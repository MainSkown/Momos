"""Orchestrator role: the pipeline's own outer loop - run scouting once,
then repeatedly dispatch batches of pending attack vectors for pentesting
and request a report for anything that comes back vulnerable - never
acting on the target itself (see roles/tools/orchestrator_tools.py's own
docstring for why it has no shell/session/scanning tool at all). A
legitimate fork of agent.py's Agent, not a parametrization of it - see the
"Each role is its own file/class" decision in the implementation plan.
Only truly generic plumbing is pulled from roles/common.py; agent.py
itself is never imported from here.

Unlike every other role, "done" here is a live CONDITION on the
AttackVector board (nothing pending or testing left, and scouting has run
at least once) rather than something a dedicated finish tool sets - see
_is_done's own docstring for why the orchestrator has no finish tool at
all, unlike scouting's finish_scouting or pentesting's report_outcome."""

from typing import (
    Annotated,
    AsyncGenerator,
    Optional,
    TypedDict,
)
from langchain_core.messages import AIMessage, BaseMessage, SystemMessage
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from src.core import db_manager, settings
from src.core.agent import agent_tools
from src.schemas.attack_vector_scheme import AttackVectorStatus
from .. import common
from ..tools import orchestrator_tools

_STATUS_DISPLAY_ORDER = (
    "pending",
    "testing",
    "tested_vulnerable",
    "tested_not_vulnerable",
    "inconclusive",
)


class OrchestratorState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    # Checkpointed (not just a plain self._scouting_done attribute) so a
    # fresh OrchestratorAgent instance resuming a paused pipeline doesn't
    # forget scouting already ran, which would otherwise make _is_done
    # (and the "call run_scouting() first" reminder) wrongly behave as if
    # nothing had happened yet.
    scouting_done: bool


class OrchestratorAgent:
    def __init__(
        self,
        model_name: str,
        checkpointer: AsyncPostgresSaver,
        project_id: str,
        target_id: str,
        agent_run_id: str,
        reasoning: Optional[bool] = None,
        context_window: Optional[int] = None,
        should_interrupt: bool = False,
    ):
        self.project_id = project_id
        self.target_id = target_id
        self.agent_run_id = agent_run_id
        self.checkpointer = checkpointer
        self.context_window = context_window or common.DEFAULT_CONTEXT_WINDOW_FALLBACK
        self._scouting_done = False

        self.tools = agent_tools.build_orchestrator_agent_tools(
            project_id,
            target_id,
            agent_run_id,
            should_interrupt,
            self._mark_scouting_done,
        )

        self.changeModel(model_name=model_name, reasoning=reasoning)
        self.app = self._build_graph()

    def _mark_scouting_done(self):
        self._scouting_done = True

    def _build_graph(self):
        workflow = StateGraph(OrchestratorState)
        workflow.add_node("agent", self._call_model)
        tool_node = ToolNode(self.tools)
        workflow.add_node(
            "tools",
            common.make_guarded_tools_node(
                tool_node, orchestrator_tools.WRITER_TOOL_NAMES, orchestrator_tools.READER_TOOL_NAMES
            ),
        )
        workflow.add_edge(START, "agent")
        workflow.add_conditional_edges("agent", self._should_continue, ["tools", END])
        workflow.add_edge("tools", "agent")
        return workflow.compile(checkpointer=self.checkpointer, interrupt_before=["tools"])

    def _render_context_message(self, state: OrchestratorState) -> SystemMessage:
        # A live DB read, not state carried on OrchestratorState - unlike
        # scouting's enumeration/proposed_vectors, the real source of
        # truth here (AttackVector rows) is written by the sub-agents this
        # role spawns, not by this role's own turn, so re-deriving it
        # fresh every turn is the only way to see their results.
        vectors = db_manager.get_attack_vectors_for_target(self.target_id)
        lines = ["### Attack vector board (live - trust this over your own memory of earlier turns)"]

        if not vectors:
            lines.append("(empty - nothing proposed yet)")
        else:
            by_status: dict = {}
            for v in vectors:
                by_status.setdefault(v.status.value, []).append(v)
            for status in _STATUS_DISPLAY_ORDER:
                group = by_status.get(status)
                if not group:
                    continue
                lines.append(f"{status} ({len(group)}):")
                for v in group:
                    reported = " [reported]" if v.linked_vulnerability_id else ""
                    lines.append(f"  - {v.id}: {v.description}{reported}")

        lines.append("")
        if not self._scouting_done:
            lines.append("Call run_scouting() first - nothing has been enumerated yet.")
        else:
            lines.append(
                'Pick a batch of "pending" (or abandoned "testing", left over from an '
                "earlier interrupted run) vector ids and call dispatch_pentest_batch with "
                'them, call request_report for anything "tested_vulnerable" and not yet '
                "[reported], and stop once nothing pending/testing remains."
            )

        return SystemMessage(content="\n".join(lines))

    async def _call_model(self, state: OrchestratorState):
        messages = list(state["messages"])
        context_message = self._render_context_message(state)
        trimmed = common.trim_messages_for_model(messages, self.context_window, self.tools)
        response = await self.llm_with_tools.ainvoke(trimmed + [context_message])
        return {
            "messages": [response],
            "scouting_done": self._scouting_done,
        }

    def _should_continue(self, state: OrchestratorState):
        last_message = state["messages"][-1]
        if isinstance(last_message, AIMessage) and last_message.tool_calls:
            return "tools"
        return END

    def changeModel(self, model_name: str, reasoning: Optional[bool] = None):
        self.model_name = model_name
        use_reasoning = True if reasoning is None else reasoning
        llm = ChatOllama(
            model=model_name,
            base_url=settings.ollama_url,
            reasoning=use_reasoning,
            num_ctx=self.context_window,
        )
        self.llm_with_tools = llm.bind_tools(self.tools)

    def _is_done(self) -> bool:
        """No dedicated finish tool exists for this role (see the module
        docstring) - the orchestrator's job is inherently "keep going
        until the board says there's nothing left", not something it
        itself gets to unilaterally declare complete. Done once scouting
        has run at least once AND no AttackVector is left pending or
        testing - a lingering "testing" row counts as NOT done rather than
        finished, since (per orchestrator_tools.create_dispatch_pentest_batch_tool's
        own comment) it can only mean a sub-run was abandoned, not that
        one is still genuinely live - every dispatch_pentest_batch call
        fully awaits its whole batch before returning, so nothing can be
        truly in flight between the orchestrator's own turns."""
        if not self._scouting_done:
            return False
        vectors = db_manager.get_attack_vectors_for_target(self.target_id)
        return not any(
            v.status in (AttackVectorStatus.PENDING, AttackVectorStatus.TESTING) for v in vectors
        )

    async def start_agent(
        self,
        start_prompt: str,
        thread_id: str,
        stop_event,
        duration_seconds: Optional[int] = None,
        run_state: Optional[dict] = None,
        max_turns: Optional[int] = None,
    ) -> AsyncGenerator:
        config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
        existing_state = await self.app.aget_state(config)

        if existing_state.values:
            input_data = None
            self._scouting_done = existing_state.values.get("scouting_done", self._scouting_done)
        else:
            input_data = {
                "messages": [("user", start_prompt)],
                "scouting_done": False,
            }

        def requires_interrupt(tool_call_names) -> bool:
            # orchestrator_tools.ALWAYS_INTERRUPT_TOOL_NAMES/
            # INTERRUPT_GATED_TOOL_NAMES are both empty - none of the
            # orchestrator's own 3 tools ever need human approval at its
            # level; each sub-agent it spawns surfaces its OWN interrupt
            # need independently, keyed by its own agent_run_id (see
            # orchestrator_tools._drain_sub_agent).
            return False

        async for event in common.run_graph_loop(
            self.app,
            thread_id,
            input_data,
            stop_event,
            self.context_window,
            self._is_done,
            requires_interrupt,
            duration_seconds=duration_seconds,
            run_state=run_state,
            max_turns=max_turns,
        ):
            yield event
