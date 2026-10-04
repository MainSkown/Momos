"""Reporting role: handed one pentesting sub-agent's complete, already-
persisted transcript (resolved via AttackVector.assigned_run_id and read
with db_manager.get_agent_logs_for_run - never a hand-carried summary, see
pentesting_tools.create_report_outcome_tool's own docstring for why) and
writes exactly one report_vulnerability call from it. Unlike scouting/
pentesting, reporting never touches the target itself - no target_scope,
no Kali session, no interrupt approval is ever needed (reporting_tools.
WRITER_TOOL_NAMES is empty). A legitimate fork of agent.py's Agent, not a
parametrization of it - see the "Each role is its own file/class" decision
in the implementation plan. Only truly generic plumbing is pulled from
roles/common.py; agent.py itself is never imported from here."""

from typing import (
    Annotated,
    AsyncGenerator,
    List,
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
from src.core import settings
from src.core.agent import agent_tools
from src.schemas import AgentLog, Vulnerability
from . import common
from . import reporting_tools

# Each entry's own raw_output is already capped once at the point it was
# first stored (agent_tools._cap_raw_output, RAW_OUTPUT_MAX_CHARS=20000) -
# this is a SECOND, tighter cap specifically for the transcript rendered
# here, since a whole pentesting run can have a dozen-plus such entries and
# baking all of them in at their individual storage-time cap would still
# blow a small local model's context window on its own. Head-only (not
# head+tail like the storage-time cap) - for THIS purpose (letting
# reporting construct an accurate proof_of_concept), the command actually
# run and the start of its result matter far more than a scan's tail end.
_TRANSCRIPT_ENTRY_RAW_OUTPUT_CAP = 3000
_TRANSCRIPT_TOTAL_CAP = 40000


def _render_transcript(logs: List[AgentLog]) -> str:
    """Formats a pentesting run's full AgentLog rows into one readable
    block - every real tool call and its real (capped) raw output, in
    order. Thinking entries are skipped: they're the pentesting agent's
    own reasoning, not evidence of anything that actually happened against
    the target, and reporting's job is to write from what was actually
    done, not from what the other agent was thinking."""
    lines = []
    for log in logs:
        if log.type == "thinking":
            continue
        label = "TOOL CALL" if log.type == "tool" else "RESULT"
        header = f"[{label}: {log.tool_name}]" if log.tool_name else f"[{label}]"
        lines.append(f"{header} {log.content}")
        if log.raw_output:
            raw = log.raw_output
            if len(raw) > _TRANSCRIPT_ENTRY_RAW_OUTPUT_CAP:
                raw = raw[:_TRANSCRIPT_ENTRY_RAW_OUTPUT_CAP] + "\n[...truncated here...]"
            lines.append(f"  Real output:\n{raw}")

    transcript = "\n".join(lines) if lines else "(no log entries found for this run)"
    if len(transcript) > _TRANSCRIPT_TOTAL_CAP:
        omitted = len(transcript) - _TRANSCRIPT_TOTAL_CAP
        transcript = (
            transcript[:_TRANSCRIPT_TOTAL_CAP]
            + f"\n\n[...{omitted} characters of this transcript omitted here, too large to show in full...]"
        )
    return transcript


def _last_real_raw_output(logs: List[AgentLog]) -> Optional[str]:
    """The evidence agent_tools._verify_claim_against_evidence checks
    report_vulnerability's proof_of_concept against - reporting never
    calls run() itself, so this stands in for "the agent's own most recent
    real tool output" with the pentesting run's actual last one instead."""
    for log in reversed(logs):
        if log.raw_output:
            return log.raw_output
    return None


class ReportingState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    finish_summary: Optional[str]


class ReportingAgent:
    def __init__(
        self,
        model_name: str,
        checkpointer: AsyncPostgresSaver,
        project_id: str,
        target_id: str,
        agent_run_id: str,
        attack_vector_id: str,
        pentesting_logs: List[AgentLog],
        reasoning: Optional[bool] = None,
        context_window: Optional[int] = None,
    ):
        self.project_id = project_id
        self.target_id = target_id
        self.agent_run_id = agent_run_id
        self.attack_vector_id = attack_vector_id
        self.checkpointer = checkpointer
        self.finish_summary: Optional[str] = None
        self.created_vulnerability: Optional[Vulnerability] = None
        self.context_window = context_window or common.DEFAULT_CONTEXT_WINDOW_FALLBACK

        self.transcript_text = _render_transcript(pentesting_logs)
        self._last_raw_output = _last_real_raw_output(pentesting_logs)

        self._get_model_name = lambda: getattr(self, "model_name", "")

        self.tools = agent_tools.build_reporting_agent_tools(
            project_id,
            target_id,
            self._get_mode,
            self._has_tested,
            self._clear_tested,
            self._on_reported,
            self._get_last_raw_output,
            self._get_model_name,
        )

        self.changeModel(model_name=model_name, reasoning=reasoning)
        self.app = self._build_graph()

    def _get_mode(self) -> str:
        # Constant - reporting has no mode of its own, same trick
        # pentesting_tools.create_report_outcome_tool uses for the
        # same shared _require_tested gate.
        return "exploiting"

    def _has_tested(self) -> bool:
        # Constant True - reporting's evidence is the pentesting run's own
        # already-real transcript, not something reporting freshly tests
        # itself. The actual check that matters here is
        # _verify_claim_against_evidence (see _get_last_raw_output below),
        # not this proof-of-a-fresh-action gate.
        return True

    def _clear_tested(self):
        # No-op - reporting makes exactly one report_vulnerability call
        # per run, ever; there is no "next claim" to re-gate before.
        pass

    def _get_last_raw_output(self) -> Optional[str]:
        return self._last_raw_output

    def _on_reported(self, vulnerability: Vulnerability):
        self.created_vulnerability = vulnerability
        self.finish_summary = (
            f"Recorded vulnerability '{vulnerability.name}' "
            f"(CVSS v4.0 score {vulnerability.cvss4_score})."
        )

    def _build_graph(self):
        workflow = StateGraph(ReportingState)
        workflow.add_node("agent", self._call_model)
        tool_node = ToolNode(self.tools)
        workflow.add_node(
            "tools",
            common.make_guarded_tools_node(
                tool_node, reporting_tools.WRITER_TOOL_NAMES, reporting_tools.READER_TOOL_NAMES
            ),
        )
        workflow.add_edge(START, "agent")
        workflow.add_conditional_edges("agent", self._should_continue, ["tools", END])
        workflow.add_edge("tools", "agent")
        return workflow.compile(checkpointer=self.checkpointer, interrupt_before=["tools"])

    def _render_context_message(self, state: ReportingState) -> SystemMessage:
        return SystemMessage(
            content=(
                "### Reminder\nCall report_vulnerability exactly once, built only "
                "from the real transcript you were given at the start of this run - "
                "never add, assume, or embellish anything it doesn't actually show. "
                "If it's rejected (e.g. an invalid CVSS v4.0 vector), fix exactly "
                "what the error describes and call it again."
            )
        )

    async def _call_model(self, state: ReportingState):
        messages = list(state["messages"])
        context_message = self._render_context_message(state)
        trimmed = common.trim_messages_for_model(messages, self.context_window, self.tools)
        response = await self.llm_with_tools.ainvoke(trimmed + [context_message])
        return {
            "messages": [response],
            "finish_summary": self.finish_summary,
        }

    def _should_continue(self, state: ReportingState):
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

    async def start_agent(
        self,
        start_prompt: str,
        thread_id: str,
        stop_event,
        max_turns: int = 6,
    ) -> AsyncGenerator:
        config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
        existing_state = await self.app.aget_state(config)

        if existing_state.values:
            input_data = None
            self.finish_summary = existing_state.values.get("finish_summary", self.finish_summary)
        else:
            full_prompt = f"{start_prompt}\n\n### Pentesting run transcript\n{self.transcript_text}"
            input_data = {"messages": [("user", full_prompt)]}

        def is_done() -> bool:
            return self.finish_summary is not None

        def requires_interrupt(tool_call_names) -> bool:
            # reporting_tools.WRITER_TOOL_NAMES is empty - reporting never
            # touches the target, so no call it can make ever needs human
            # approval.
            return False

        async for event in common.run_graph_loop(
            self.app,
            thread_id,
            input_data,
            stop_event,
            self.context_window,
            is_done,
            requires_interrupt,
            max_turns=max_turns,
        ):
            yield event
