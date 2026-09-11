import asyncio
from typing import (
    Annotated,
    Any,
    AsyncGenerator,
    Callable,
    Dict,
    List,
    Optional,
    TypedDict,
)
from langchain_core.messages import AIMessage, BaseMessage, SystemMessage, ToolMessage
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from . import agent_tools
from src.schemas import AgentTargetScope, Target
from src.core import settings
import time


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    target_scope: AgentTargetScope
    # Auto-maintained running knowledge base, re-injected into every turn's
    # context by _render_context_message - see build_agent_tools/_call_model.
    # Both are plain last-write-wins fields (no Annotated reducer): each
    # _call_model call always writes back the FULL merged value, not a
    # delta, so overwrite-on-write is the correct semantics here. They ride
    # along with `messages` in the same Postgres checkpoint, so they survive
    # pause/resume for free.
    enumeration: Dict[str, Dict[str, str]]
    attack_log: List[Dict[str, str]]


class AgentInterruptAction(TypedDict):
    accept: Callable[[bool], None]
    tool_calls: list[Any]


# Two-phase turn: many tool-calling chat templates only give the model a
# slot for EITHER plain text OR a tool call in one turn, never both, no
# matter what a system prompt asks for - that's a template/training
# constraint a single call can't reliably override (confirmed empirically:
# a one-time system message, then a per-turn reminder, both failed to
# produce visible reasoning across multiple real turns). Splitting into a
# plain reasoning call followed by a tool-bound call guarantees a reasoning
# line every time, and - as a secondary benefit - tends to improve decision
# quality even on models that aren't dedicated "reasoning" models, since it
# forces the same step-by-step scaffold chain-of-thought prompting relies on.
REASONING_ONLY_PROMPT = (
    "Think through the current situation before acting: what you know so "
    "far, what you're trying to find out or accomplish next, and why that "
    "is the right next step. Respond with ONLY that reasoning as 1-3 "
    "sentences of plain text - do not call a tool or take any action yet. "
    "Do not write out a command, session prompt, or transcript (e.g. "
    "`ftp> anonymous`) as if it has already run - describing what you plan "
    "to type is not the same as typing it, and nothing you write here will "
    "actually execute."
)

ACT_ON_REASONING_PROMPT = (
    "Now act on the reasoning above by calling exactly one tool. Writing a "
    "command as plain text or inside a code block does NOT run it, no "
    "matter how it's formatted - the only way to actually do anything, "
    "including sending input to an open session, is a real tool call."
)


class Agent:
    def __init__(
        self,
        model_name: str,
        checkpointer: AsyncPostgresSaver,
        project_id: str,
        target_id: str,
    ):
        self.project_id = project_id
        self.target_id = target_id
        self.checkpointer = checkpointer
        self.ollama_url = settings.ollama_url
        self.finish_summary: Optional[str] = None

        # Written to by tool calls (execute_kali_command's FACTS extraction,
        # log_attack_attempt) as they happen inside the "tools" node - tools
        # have no direct handle on graph state, so these buffer updates
        # until the next _call_model run, which folds them into the
        # checkpointed enumeration/attack_log state fields and clears the
        # buffer. Safe because the graph always routes tools -> agent
        # (never two tool-executing turns back to back), and because
        # asyncio's single-threaded event loop makes these plain
        # (non-await-ing) dict/list mutations atomic even when several tool
        # calls from one LLM turn run concurrently.
        self._pending_enumeration: Dict[str, dict] = {}
        self._pending_attack_log: List[dict] = []

        self.tools = agent_tools.build_agent_tools(
            project_id,
            target_id,
            self._mark_finished,
            self._record_enumeration,
            self._record_attack_attempt,
        )

        self.changeModel(model_name=model_name)

        self.app = self._build_graph()

    def _mark_finished(self, summary: str):
        self.finish_summary = summary

    def _record_enumeration(self, entries: Dict[str, dict]):
        self._pending_enumeration.update(entries)

    def _record_attack_attempt(self, entry: dict):
        self._pending_attack_log.append(entry)

    def _build_graph(self):
        workflow = StateGraph(AgentState)

        # Nodes
        workflow.add_node("agent", self._call_model)
        workflow.add_node("tools", ToolNode(self.tools))

        # Edges
        workflow.add_edge(START, "agent")
        workflow.add_conditional_edges("agent", self._should_continue, ["tools", END])
        workflow.add_edge("tools", "agent")

        return workflow.compile(
            checkpointer=self.checkpointer, interrupt_before=["tools"]
        )

    def _render_context_message(self, state: AgentState) -> Optional[SystemMessage]:
        """Renders the running enumeration table / attack-attempt log as one
        compact reminder, so a fact from many turns ago (or from before a
        pause/resume) doesn't depend on the model re-finding it buried in a
        long transcript - which matters more here than usual, since this
        runs on local Ollama models with comparatively weak long-context
        recall and often a small context window to begin with."""
        enumeration = state.get("enumeration") or {}
        attack_log = state.get("attack_log") or []

        if not enumeration and not attack_log:
            return None

        lines = [
            "### Known so far (auto-maintained - trust this over your own "
            "memory of earlier turns, and don't repeat work it already covers):"
        ]

        if enumeration:
            lines.append("Enumeration:")
            for port in sorted(enumeration):
                info = enumeration[port]
                detail = " ".join(
                    part for part in (info.get("service", ""), info.get("version", "")) if part
                )
                line = f"- {port}: {detail}" if detail else f"- {port}"
                if info.get("notes"):
                    line += f" ({info['notes']})"
                lines.append(line)

        if attack_log:
            lines.append("Attempted attack vectors:")
            for entry in attack_log:
                line = (
                    f"- [{entry.get('outcome', '?')}] {entry.get('target', '?')}: "
                    f"{entry.get('vector', '?')}"
                )
                if entry.get("notes"):
                    line += f" - {entry['notes']}"
                lines.append(line)

        return SystemMessage(content="\n".join(lines))

    def _call_model(self, state: AgentState):
        """Node: LLM processes the current state.

        Two calls, not one: first the plain (non-tool-bound) model states
        its reasoning as text, then the tool-bound model acts on it. Neither
        the reasoning prompt nor the reasoning response itself is persisted
        into state/checkpoint - only the final response (with the reasoning
        folded into its content) is, keeping the saved conversation the same
        shape as before."""
        messages = list(state["messages"])
        context_message = self._render_context_message(state)
        context = [context_message] if context_message else []

        reasoning_response = self.llm.invoke(
            messages + context + [SystemMessage(content=REASONING_ONLY_PROMPT)]
        )
        reasoning_text = str(reasoning_response.content).strip()

        response = self.llm_with_tools.invoke(
            messages
            + context
            + [
                AIMessage(content=reasoning_text),
                SystemMessage(content=ACT_ON_REASONING_PROMPT),
            ]
        )

        # Make sure the reasoning is visible even if the tool-calling model
        # itself returns empty content alongside its tool call, which is the
        # common case this whole two-call split exists to work around.
        if reasoning_text and not str(response.content).strip():
            response = response.model_copy(update={"content": reasoning_text})

        # Fold whatever tool calls buffered since the last turn (see
        # _record_enumeration/_record_attack_attempt) into the checkpointed
        # state fields, per-field-merging enumeration entries rather than
        # replacing them outright so a later, narrower fact about a port
        # (e.g. just a note) can't clobber an earlier service/version.
        enumeration = dict(state.get("enumeration") or {})
        for port, fact in self._pending_enumeration.items():
            merged = {**enumeration.get(port, {}), **{k: v for k, v in fact.items() if v}}
            enumeration[port] = merged
        self._pending_enumeration = {}

        attack_log = list(state.get("attack_log") or [])
        attack_log.extend(self._pending_attack_log)
        self._pending_attack_log = []

        return {"messages": [response], "enumeration": enumeration, "attack_log": attack_log}

    def _should_continue(self, state: AgentState):
        last_message = state["messages"][-1]
        if isinstance(last_message, AIMessage) and last_message.tool_calls:
            return "tools"
        return END

    def changeModel(self, model_name: str):
        self.llm = ChatOllama(model=model_name, base_url=self.ollama_url)

        # A separate instance (not reusing self.llm) so this only affects
        # the tool-calling phase, not the plain reasoning-only call above.
        # "Thinking" models (e.g. the Qwen3 family) default to wrapping a
        # <think>...</think> block into the response content even when
        # tools are bound - which both duplicates the explicit reasoning
        # call this graph already does, and, per known Ollama/Qwen3
        # tool-call parsing issues (ollama/ollama #11662, #14601), raises
        # the odds the model's tool-call JSON gets returned as plain text
        # content instead of being parsed into an actual tool call. Forcing
        # reasoning off here removes that interaction for the call that
        # actually needs a clean, structured tool call to come back.
        tool_llm = ChatOllama(model=model_name, base_url=self.ollama_url, reasoning=False)
        self.llm_with_tools = tool_llm.bind_tools(self.tools)

    # --- Execution and Interaction ---
    async def start_agent(
        self,
        target: Target,
        start_prompt: str,
        thread_id: str,
        should_interrupt: bool,
        duration_seconds: int,
        stop_event: asyncio.Event | None = None,
        run_state: dict | None = None,
    ) -> AsyncGenerator[BaseMessage | AgentInterruptAction, None]:
        config: RunnableConfig = {"configurable": {"thread_id": thread_id}}

        if stop_event is None:
            stop_event = asyncio.Event()

        if run_state is None:
            run_state = {}

        existing_state = await self.app.aget_state(config)

        if existing_state.values:
            input_data = None
        else:
            target_scope: AgentTargetScope = {
                "name": target.name,
                "ipv4": target.ipv4,
                "ipv6": target.ipv6,
                "description": target.description,
                "ports": target.ports,
            }
            input_data = {
                "messages": [("user", start_prompt)],
                "target_scope": target_scope,
            }

        time_left = duration_seconds
        run_state["time_left"] = time_left

        # The only sanctioned way for the agent to end its own run is
        # finish_task. If the model instead responds with no tool call at
        # all - a real risk especially for smaller local models, and
        # observed in practice - the graph reaches END on its own, which
        # would otherwise silently end the whole run even with time left on
        # the clock and no error logged anywhere. Nudge it back into acting
        # instead, and only actually give up after several such turns in a
        # row (protects against a truly stuck model spinning forever).
        consecutive_no_tool_calls = 0
        MAX_CONSECUTIVE_NO_TOOL_CALLS = 3
        NUDGE_MESSAGE = (
            "You did not call a tool on your last turn - every turn must "
            "end with a tool call. If you wrote out a command or session "
            "prompt as plain text or in a code block, that did NOT run it; "
            "nothing happens until you make a real tool call - if you meant "
            "to send input to an open session, call send_to_session now. "
            "Continue the assessment with a tool call, or call finish_task "
            "if it is genuinely complete."
        )

        while (
            not stop_event.is_set()
            and time_left > 0
            and self.finish_summary is None
        ):
            loop_start = time.monotonic()
            
            event_queue = asyncio.Queue()
            
            async def _stream_worker():
                try:
                    async for event in self.app.astream(
                        input_data, config=config, stream_mode="updates"
                    ):
                        await event_queue.put(event)
                except Exception as e:
                    # Without this, any failure here (bad checkpointer state,
                    # Ollama unreachable, etc.) would silently look identical
                    # to the graph reaching END - the run would just "finish"
                    # instantly with no explanation.
                    await event_queue.put(e)
                finally:
                    await event_queue.put(None)
                    
            stream_task = asyncio.get_running_loop().create_task(_stream_worker())

            try:
                while not stop_event.is_set():
                    # Race waiting for next event vs stop_event being set
                    get_event_task = asyncio.create_task(event_queue.get())
                    stop_wait_task = asyncio.create_task(stop_event.wait())
                    
                    done, pending = await asyncio.wait(
                        [get_event_task, stop_wait_task],
                        return_when=asyncio.FIRST_COMPLETED
                    )    
                    
                    for task in pending:
                        task.cancel()
                        
                    if stop_wait_task in done:
                        # User requested pause/stop mid-generation - abort 
                        stream_task.cancel()
                        return
                    
                    event = get_event_task.result()
                    if event is None:
                        break

                    if isinstance(event, BaseException):
                        raise event

                    # stream_mode="updates" yields {node_name: {"messages": [...]}} -
                    # the update is keyed by the node that produced it, not "messages"
                    # directly.
                    for node_update in event.values():
                        if not isinstance(node_update, dict):
                            continue
                        for message in node_update.get("messages", []):
                            yield message

                    if self.finish_summary is not None:
                        # finish_task just ran as part of this step - stop
                        # immediately rather than letting the unconditional
                        # tools -> agent edge run one more (wasted) LLM turn.
                        stream_task.cancel()
                        return
            finally:
                if not stream_task.done():
                    stream_task.cancel()
            
            if stop_event.is_set():
                break                
            
            input_data = None
            state = await self.app.aget_state(config)

            if state.next == ("tools",):
                consecutive_no_tool_calls = 0
                last_message: AIMessage = state.values["messages"][-1]
                tool_calls = last_message.tool_calls

                requires_interrupt = should_interrupt and any(
                    tc["name"] == agent_tools.KALI_COMMAND_TOOL_NAME
                    for tc in tool_calls
                )

                if not requires_interrupt:
                    time_left -= (time.monotonic() - loop_start)
                    run_state["time_left"] = time_left
                    input_data = None
                    continue
                else:
                    loop = asyncio.get_running_loop()
                    resume_future: asyncio.Future[bool] = loop.create_future()

                    def accept(approved: bool):
                        if not resume_future.done():
                            resume_future.set_result(approved)

                    interrupt_action: AgentInterruptAction = {
                        "accept": accept,
                        "tool_calls": tool_calls,
                    }

                    # Pause timer awaiting for user's action
                    time_left -= (time.monotonic() - loop_start)
                    run_state["time_left"] = time_left

                    yield interrupt_action

                    is_approved: bool = await resume_future

                    # Resume the clock fresh - time spent waiting for the
                    # user's decision must not count against the budget.
                    loop_start = time.monotonic()

                    if is_approved:
                        input_data = None
                    else:
                        rejection_messages = [
                            ToolMessage(
                                content="User Denied Execution. Do not attempt this specific command again. Re-evaluate your approach.",
                                tool_call_id=tc["id"],
                                name=tc["name"],
                            )
                            for tc in tool_calls
                        ]
                        await self.app.aupdate_state(
                            config, {"messages": rejection_messages}, as_node="tools"
                        )
                        input_data = None

            else:
                consecutive_no_tool_calls += 1
                if consecutive_no_tool_calls >= MAX_CONSECUTIVE_NO_TOOL_CALLS:
                    yield AIMessage(
                        content=(
                            "Stopping the run: the model did not call a "
                            f"tool for {MAX_CONSECUTIVE_NO_TOOL_CALLS} "
                            "consecutive turns."
                        )
                    )
                    break

                input_data = {"messages": [SystemMessage(content=NUDGE_MESSAGE)]}

            time_left -= (time.monotonic() - loop_start)
            run_state["time_left"] = time_left