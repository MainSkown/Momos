import asyncio
import json
import logging
import re
import uuid
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
from src.core.kali_integration import kali_registry
from src.schemas import AgentTargetScope, Target
from src.core import settings
import time

logger = logging.getLogger("momos.agent")

# Matches Qwen's own native tool-call wire syntax
# (<tool_call>{"name": ..., "arguments": {...}}</tool_call>). Ollama is
# supposed to parse this into the response's structured tool_calls, but has
# a confirmed bug (ollama/ollama #11662, #14601) where it sometimes doesn't -
# the block just falls through as plain text in .content or
# additional_kwargs['reasoning_content'] instead, and the tool call silently
# never executes. Observed in production: a real log_attack_attempt call
# lost this way, with no error and no log entry - see
# Agent._recover_leaked_tool_calls.
_LEAKED_TOOL_CALL_PATTERN = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)

# Used only when ollama_manager.get_model_capabilities couldn't be reached
# for this model (see Agent.__init__/_prepare_and_run) - a conservative
# floor, not a real default any current model actually ships with, so the
# message-trimming budget below stays tight rather than silently assuming
# a large window it hasn't actually confirmed.
DEFAULT_CONTEXT_WINDOW_FALLBACK = 4096

# _trim_messages_for_model reserves this fraction of the model's context
# window for the trimmed conversation history it sends; the rest is left
# for the per-turn context message (target scope, mode, enumeration table,
# attack log - see _render_context_message), the tools' own schemas (sent
# with every request once bound), and the model's own generation. No
# tokenizer is available for an arbitrary local Ollama model, so this is
# necessarily a rough per-message token estimate rather than an exact
# count - deliberately conservative in both constants below, since
# UNDER-trimming (context overflow silently truncating from the wrong end,
# or the request failing outright) is a much worse failure mode than
# trimming a little more eagerly than strictly necessary.
_CONTEXT_BUDGET_FRACTION = 0.5
_EST_TOKENS_PER_MESSAGE = 250
_MIN_MESSAGES_SENT_TO_MODEL = 12
_MAX_MESSAGES_SENT_TO_MODEL = 80


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
    # Current focus - "scouting" or "exploiting" (see agent_tools.py's
    # switch_mode/VALID_MODES). Mirrors Agent.mode, which is the live,
    # synchronously-updated source of truth (see Agent._set_mode) - this
    # field only exists so the value survives a pause/resume via the same
    # Postgres checkpoint as everything else.
    mode: str


class AgentInterruptAction(TypedDict):
    accept: Callable[[bool], None]
    tool_calls: list[Any]


# Previously this graph made two LLM calls per turn - a plain reasoning-only
# call, then a separate tool-bound call told to act on it - because many
# tool-calling chat templates only allow text OR a tool call in one turn,
# never both. That split turned out not to actually prevent the failure it
# was built for (the model narrating a command instead of calling a tool
# happened in EITHER phase, in production runs against Metasploitable 2),
# while doubling per-turn latency and - since the reasoning text got folded
# into persisted message content whenever the tool-call response came back
# empty - permanently bloating every future turn's context with what was
# often just decorative narration, not functional reasoning. Collapsed back
# to one call: bind tools directly with reasoning=True, and let each
# model's own template decide how (or whether) to interleave thinking and
# tool-calling, rather than hand-rolling a scaffold around it. Reasoning
# text - when the model/Ollama actually populates it - is captured from
# additional_kwargs['reasoning_content'] for logging, and deliberately
# never folded into .content, since LangChain's message serialization back
# to the provider only resends .content/.tool_calls, not additional_kwargs -
# so it stays visible in the UI without ever being replayed into the
# model's own future context. Accepted trade-off: for a model whose
# template genuinely can't produce text and a tool call together, a turn
# may now come back with a tool call and no visible reasoning at all -
# there's no second call trying to force it out. The
# consecutive_no_tool_calls/NUDGE_MESSAGE stall-recovery loop in
# start_agent() is the backstop for whenever a turn comes back with
# neither.


class Agent:
    def __init__(
        self,
        model_name: str,
        checkpointer: AsyncPostgresSaver,
        project_id: str,
        target_id: str,
        reasoning: Optional[bool] = None,
        context_window: Optional[int] = None,
    ):
        self.project_id = project_id
        self.target_id = target_id
        self.checkpointer = checkpointer
        self.ollama_url = settings.ollama_url
        self.finish_summary: Optional[str] = None

        # Best-effort per-model info from ollama_manager.get_model_capabilities
        # (see agent_service.py's _prepare_and_run, which fetches this
        # before constructing Agent) - None whenever that lookup wasn't
        # available/failed, in which case changeModel/_message_budget fall
        # back to conservative, previously-hardcoded defaults rather than
        # guessing. context_window backs the message-trimming budget below;
        # reasoning is consumed directly by changeModel.
        self.context_window = context_window or DEFAULT_CONTEXT_WINDOW_FALLBACK

        # Live, synchronously-updated source of truth for the current
        # scouting/exploiting focus (see agent_tools.py's switch_mode) -
        # read directly by report_vulnerability/log_attack_attempt's gating
        # via _get_mode, so a switch_mode call is visible to them
        # immediately rather than only after the next _call_model flush.
        # Mirrored into the checkpointed AgentState.mode field every turn
        # (see _call_model) purely so it survives a pause/resume; restored
        # from checkpoint in start_agent() when resuming.
        self.mode: str = "scouting"

        # Whether a real run()/new_session() call has happened since the
        # last switch_mode call - gates report_vulnerability/
        # log_attack_attempt alongside mode itself. Mode gating alone
        # turned out not to be enough: observed in production, the agent
        # called switch_mode("exploiting", ...) and then immediately
        # log_attack_attempt + report_vulnerability with a fully fabricated
        # CVE, exploit-db id, and CVSS score - without ever actually
        # running anything against the target in between. Same
        # synchronous-instance-attribute pattern as self.mode (see
        # _get_mode/_set_mode) and the same reasoning for why: tool calls
        # need to observe this immediately, not just after the next
        # _call_model flush.
        self._tested_since_mode_switch: bool = False

        # Written to by tool calls (log_attack_attempt, run()'s FACTS
        # extraction) as they happen inside the "tools" node - tools have no
        # direct handle on graph state, so these buffer updates until the
        # next _call_model run, which folds them into the checkpointed
        # enumeration/attack_log state fields and clears the buffer. Safe
        # because the graph always routes tools -> agent (never two
        # tool-executing turns back to back), and because asyncio's
        # single-threaded event loop makes these plain (non-await-ing)
        # dict/list mutations atomic even when several tool calls from one
        # LLM turn run concurrently.
        self._pending_enumeration: Dict[str, dict] = {}
        self._pending_attack_log: List[dict] = []

        self.tools = agent_tools.build_agent_tools(
            project_id,
            target_id,
            self._mark_finished,
            self._record_enumeration,
            self._record_attack_attempt,
            self._get_mode,
            self._set_mode,
            self._get_tested_since_mode_switch,
            self._mark_tested,
        )

        self.changeModel(model_name=model_name, reasoning=reasoning)

        self.app = self._build_graph()

    def _mark_finished(self, summary: str):
        self.finish_summary = summary

    def _record_enumeration(self, entries: Dict[str, dict]):
        self._pending_enumeration.update(entries)

    def _record_attack_attempt(self, entry: dict):
        self._pending_attack_log.append(entry)

    def _get_mode(self) -> str:
        return self.mode

    def _set_mode(self, mode: str):
        self.mode = mode
        # Fresh mode, fresh requirement to prove something was actually
        # tried in it - including re-entering "exploiting" after having
        # left it, so a vector's confirmation can't ride on testing done
        # for a different, earlier vector.
        self._tested_since_mode_switch = False

    def _get_tested_since_mode_switch(self) -> bool:
        return self._tested_since_mode_switch

    def _mark_tested(self):
        self._tested_since_mode_switch = True

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

    @staticmethod
    def _render_target_scope_reminder(target_scope: Optional[AgentTargetScope]) -> str:
        """Re-states the exact authorized address every turn, for the same
        reason mode/enumeration are re-injected below - the starting
        prompt's target scope is otherwise only ever seen once, as part of
        the very first message. Observed in production: on a target named
        after a well-known vulnerable-by-design box (e.g. "Metasploitable
        2"), a local model drifted into scanning a plausible-looking IP it
        associated with that name from its own training data instead of
        the actual one given in scope - wasting a run chasing a host that
        was never actually configured here. Re-stating the real address
        every turn gives it much less room to substitute a memorized one."""
        if not target_scope:
            return ""

        def _value(v):
            if isinstance(v, list):
                return ", ".join(str(x) for x in v) if v else "not defined"
            return str(v) if v not in (None, "") else "not defined"

        return (
            "### Authorized target - use exactly this, never a different "
            "address you recall for a target with this name:\n"
            f"- Name: {_value(target_scope.get('name'))}\n"
            f"- IPv4: {_value(target_scope.get('ipv4'))}\n"
            f"- IPv6: {_value(target_scope.get('ipv6'))}\n"
            f"- Authorized ports: {_value(target_scope.get('ports'))}"
        )

    def _render_context_message(self, state: AgentState) -> SystemMessage:
        """Renders the current scouting/exploiting mode plus the running
        enumeration table / attack-attempt log as one compact reminder,
        every turn - so neither the current focus nor a fact from many
        turns ago (or from before a pause/resume) depends on the model
        re-finding it buried in a long transcript. The one-time starting
        prompt's directives are only ever sent once, as the very first
        message of what can be a long run - re-injecting this every turn is
        far more reliable than relying on the model to remember that, which
        matters more here than usual given this runs on local Ollama models
        with comparatively weak long-context recall and often a small
        context window to begin with."""
        scope_reminder = self._render_target_scope_reminder(state.get("target_scope"))
        lines = [scope_reminder, ""] if scope_reminder else []

        mode = self.mode
        lines.append(f"### Current mode: {mode}")
        if mode == "scouting":
            lines.append(
                "Focus on enumeration - identify open ports/services and "
                "their versions. switch_mode to \"exploiting\" once you "
                "have a specific service/version and a candidate "
                "vulnerability to test."
            )
        else:
            lines.append(
                "Focus on testing the specific vector you switched here "
                "for. Before improvising your own exploit/payload (e.g. a "
                "hand-rolled one-liner), check for an existing tested "
                "approach first - e.g. searchsploit for this "
                "service/version, or the relevant tool's own checks - and "
                "follow a real match exactly. switch_mode back to "
                "\"scouting\" if you need broader enumeration first."
            )
            if not self._tested_since_mode_switch:
                lines.append(
                    "You have NOT yet run() anything against the target "
                    "since switching to exploiting mode - report_vulnerability "
                    "and log_attack_attempt will be refused until you do. "
                    "Make the real attempt first."
                )

        enumeration = state.get("enumeration") or {}
        attack_log = state.get("attack_log") or []

        if enumeration or attack_log:
            lines.append("")
            lines.append(
                "### Known so far (auto-maintained - trust this over your "
                "own memory of earlier turns, and don't repeat work it "
                "already covers):"
            )

            if enumeration:
                lines.append("Enumeration:")
                for port in sorted(enumeration):
                    info = enumeration[port]
                    detail = " ".join(
                        part
                        for part in (info.get("service", ""), info.get("version", ""))
                        if part
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

    def _recover_leaked_tool_calls(self, response: AIMessage) -> AIMessage:
        """Recovers a tool call Ollama failed to parse into
        response.tool_calls (see _LEAKED_TOOL_CALL_PATTERN above) by
        pulling it back out of .content/reasoning_content, validating it
        names one of our actual tools, and promoting it to a real
        structured tool call so the graph executes it like any other. Also
        strips the raw block from whatever field it was found in, so it
        isn't shown to the user (or the model itself, next turn) as
        garbled JSON on top of silently not running."""
        if response.tool_calls:
            return response

        valid_tool_names = {t.name for t in self.tools}
        recovered: list = []
        update: dict = {}

        for field, text in (
            ("content", str(response.content) if response.content else ""),
            ("reasoning_content", response.additional_kwargs.get("reasoning_content") or ""),
        ):
            matches = list(_LEAKED_TOOL_CALL_PATTERN.finditer(text))
            if not matches:
                continue

            cleaned = text
            for match in matches:
                try:
                    call = json.loads(match.group(1))
                except json.JSONDecodeError:
                    continue
                name = call.get("name")
                if name not in valid_tool_names:
                    continue
                recovered.append(
                    {
                        "name": name,
                        "args": call.get("arguments") or {},
                        "id": f"recovered-{uuid.uuid4()}",
                        "type": "tool_call",
                    }
                )
                cleaned = cleaned.replace(match.group(0), "").strip()

            if field == "content":
                update["content"] = cleaned
            else:
                update["additional_kwargs"] = {
                    **response.additional_kwargs,
                    "reasoning_content": cleaned,
                }

        if not recovered:
            return response

        logger.warning(
            f"Recovered {len(recovered)} tool call(s) Ollama failed to parse "
            f"natively: {[c['name'] for c in recovered]}"
        )
        update["tool_calls"] = recovered
        return response.model_copy(update=update)

    def _message_budget(self) -> int:
        """How many of the persisted conversation's messages
        _trim_messages_for_model keeps, sized off self.context_window (see
        the module-level comment above _CONTEXT_BUDGET_FRACTION for the
        reasoning behind the constants used here)."""
        usable_tokens = self.context_window * _CONTEXT_BUDGET_FRACTION
        budget = int(usable_tokens // _EST_TOKENS_PER_MESSAGE)
        return max(_MIN_MESSAGES_SENT_TO_MODEL, min(_MAX_MESSAGES_SENT_TO_MODEL, budget))

    def _trim_messages_for_model(self, messages: list[BaseMessage]) -> list[BaseMessage]:
        """Shrinks what's actually SENT to the model each turn, independent
        of what's PERSISTED - state["messages"] (and so the UI's full audit
        log via agent_service.py) keeps every message regardless; this only
        affects the invoke() input built here. Safe to drop older turns
        outright because the model's actual working memory - current mode,
        the enumeration table, the attack-attempt log - is independently
        re-synthesized into context_message every single turn (see
        _render_context_message), not reconstructed by the model re-reading
        old messages. Without this, a long-running turn count would grow
        this call's prompt without bound, which a small local model's often
        narrow (commonly 4k-8k token) context window can't absorb.

        Always keeps the very first message (the rendered starting prompt -
        target scope, tool inventory, operating directives) as a stable
        anchor, plus as many of the most recent messages as the budget
        allows. Never lets the kept "recent" window start on a bare
        ToolMessage - every backend's tool-call/tool-response linkage
        expects one to immediately follow the AIMessage(tool_calls=...) it
        answers, so an orphaned one at the very start of the window (i.e.
        missing that AIMessage, which fell on the trimmed side of the cut)
        risks a hard error from the chat template, not just confusion."""
        budget = self._message_budget()
        if len(messages) <= budget:
            return messages

        first = messages[0]
        candidate_start = max(1, len(messages) - (budget - 1))

        start = candidate_start
        while start < len(messages) and isinstance(messages[start], ToolMessage):
            start += 1

        if start >= len(messages) or start <= 1:
            # Budget too tight to safely cut anywhere (everything past the
            # candidate start is part of one giant trailing tool-call
            # exchange, or there's nothing to trim in the first place) -
            # send the untrimmed conversation rather than risk an orphaned
            # ToolMessage or trimming nothing useful.
            return messages

        recent = messages[start:]
        trimmed_count = start - 1

        notice = SystemMessage(
            content=(
                f"[{trimmed_count} earlier turn(s) omitted here to keep "
                "this prompt a manageable size - they are NOT lost: the "
                "current mode, enumeration table, and attack-attempt log "
                "shown below already reflect everything learned in them. "
                "Don't re-run something already listed there just because "
                "you can no longer see the turn that found it.]"
            )
        )
        return [first, notice] + recent

    def _call_model(self, state: AgentState):
        """Node: one LLM call per turn, tools bound directly, with
        reasoning=True (set in changeModel) so native "thinking" models can
        surface their reasoning via additional_kwargs['reasoning_content']
        - see the module-level comment above for why this replaced the
        previous two-call split. The response is persisted as-is;
        reasoning_content (when present) is read out for logging by
        agent_service.py's _message_to_log_specs, not touched here."""
        messages = list(state["messages"])
        context_message = self._render_context_message(state)

        trimmed_messages = self._trim_messages_for_model(messages)
        response = self.llm_with_tools.invoke(trimmed_messages + [context_message])
        response = self._recover_leaked_tool_calls(response)

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

        return {
            "messages": [response],
            "enumeration": enumeration,
            "attack_log": attack_log,
            "mode": self.mode,
        }

    def _should_continue(self, state: AgentState):
        last_message = state["messages"][-1]
        if isinstance(last_message, AIMessage) and last_message.tool_calls:
            return "tools"
        return END

    def changeModel(self, model_name: str, reasoning: Optional[bool] = None):
        # repeat_penalty/repeat_last_n: raised above Ollama's own defaults
        # (~1.1 / 64) because a reasoning-heavy model was observed getting
        # stuck oscillating within a single reasoning generation ("it's A -
        # no, maybe B - no, it's A" repeated many times) rather than
        # converging. These are universal anti-repetition sampling knobs,
        # not conditioned on model name/family - unlike a per-model prompt
        # branch, this is expected to help any model prone to the same
        # failure mode, not just one specific one.
        #
        # reasoning, by contrast, IS model-specific and was previously
        # hardcoded True for every model regardless of whether its own
        # chat template actually supports interleaving thinking with a
        # tool call - a non-reasoning model (e.g. a plain instruct-tuned
        # 8B) forced into reasoning=True was observed able to return
        # empty/garbled output instead of a usable response. `reasoning`
        # here comes from ollama_manager.get_model_capabilities (see
        # agent_service.py) when that lookup succeeded; None (lookup
        # unavailable/failed, or a direct changeModel call from elsewhere
        # that doesn't pass one) preserves the old default of True rather
        # than silently disabling reasoning for a model that might need it.
        use_reasoning = True if reasoning is None else reasoning
        llm = ChatOllama(
            model=model_name,
            base_url=self.ollama_url,
            reasoning=use_reasoning,
            repeat_penalty=1.3,
            repeat_last_n=256,
        )
        self.llm_with_tools = llm.bind_tools(self.tools)

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
            # Restore the live mode from the checkpoint - a fresh Agent
            # instance always starts at self.mode = "scouting" (see
            # __init__), so resuming a paused run that had switched to
            # "exploiting" needs this or it would silently reset.
            self.mode = existing_state.values.get("mode", self.mode)
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

        # Give the agent a terminal from turn one - no "open a session
        # first" step for it to forget. Best-effort: if this fails (should
        # only happen if the container isn't actually ready yet), the run
        # tool itself opens "default" defensively on its first call anyway.
        manager = await kali_registry.get_manager(self.project_id)
        if not manager.has_current_session(self.target_id):
            try:
                await manager.open_session(
                    self.target_id,
                    agent_tools.DEFAULT_SESSION_NAME,
                    agent_tools.DEFAULT_SESSION_COMMAND,
                )
            except Exception as e:
                print(f"Could not pre-open default session for {self.target_id}: {e}")

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
        MAX_CONSECUTIVE_NO_TOOL_CALLS = 5
        NUDGE_MESSAGE = (
            "You did not call a tool on your last turn - every turn must "
            "end with a tool call. If you wrote out a command or session "
            "prompt as plain text or in a code block, that did NOT run it; "
            "nothing happens until you make a real tool call - if you meant "
            "to send input to your current session, call run(input=...) "
            "now. Continue the assessment with a tool call, or call "
            "finish_task if it is genuinely complete."
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

                # execute_kali_command is commented out (see agent_tools.py)
                # - run/new_session are now the tools that actually execute
                # something in the container, so those are what
                # should_interrupt gates on instead.
                requires_interrupt = should_interrupt and any(
                    tc["name"] in (agent_tools.RUN_TOOL_NAME, agent_tools.NEW_SESSION_TOOL_NAME)
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