"""Scouting role: one agent-run per target, one job - thorough enumeration,
then propose_attack_vector for everything worth testing. No mode concept
(that split is now a role boundary, not something this role self-manages),
no report_vulnerability (not its job), no log_attack_attempt (it never
exploits anything). A legitimate fork of agent.py's Agent, not a
parametrization of it - see the "Each role is its own file/class" decision
in the implementation plan. Only truly generic plumbing (token trimming,
the turn-conflict guard, the stream-and-stop loop) is pulled from
roles/common.py; agent.py itself is never imported from here."""

import uuid
from typing import (
    Annotated,
    AsyncGenerator,
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
from src.core import settings
from src.core.agent import agent_tools
from src.core.kali_integration import kali_registry
from src.schemas import AgentTargetScope, Target
from . import common
from . import scouting_tools

_MAX_ENUMERATION_PROPOSED_SHOWN = 40


class ScoutingState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    target_scope: AgentTargetScope
    enumeration: Dict[str, Dict[str, str]]
    proposed_vectors: List[str]
    finish_summary: Optional[str]


class ScoutingAgent:
    def __init__(
        self,
        model_name: str,
        checkpointer: AsyncPostgresSaver,
        project_id: str,
        target_id: str,
        agent_run_id: str,
        reasoning: Optional[bool] = None,
        context_window: Optional[int] = None,
        allow_shell: bool = True,
        allow_install_packages: bool = True,
        enabled_tools: Optional[List[str]] = None,
    ):
        self.project_id = project_id
        self.target_id = target_id
        self.agent_run_id = agent_run_id
        self.checkpointer = checkpointer
        self.finish_summary: Optional[str] = None
        self.context_window = context_window or common.DEFAULT_CONTEXT_WINDOW_FALLBACK
        self.allow_shell = allow_shell

        self._current_session_name: Optional[str] = None
        self._current_session_command: Optional[str] = None
        self._at_shell_prompt: bool = True
        self._authorized_ports_override: Optional[List[int]] = None
        self._last_raw_output: Optional[str] = None
        # Monotonic - never cleared, unlike the Single Agent flow's per-
        # claim has_tested/clear_tested cycle. See
        # scouting_tools.create_propose_attack_vector_tool's own docstring
        # for why that's the right gate shape here (one scan, several
        # proposals from it - not one proposal per tool call).
        self._has_real_action: bool = False
        self._pending_enumeration: Dict[str, dict] = {}
        self._pending_proposed_vectors: List[str] = []

        self._get_model_name = lambda: getattr(self, "model_name", "")

        self.tools = scouting_tools.build_scouting_tools(
            project_id,
            target_id,
            agent_run_id,
            self._record_enumeration,
            self._mark_tested,
            self._has_tested,
            self._set_current_session,
            self._set_at_shell_prompt,
            self._set_last_raw_output,
            self._set_authorized_ports,
            self._mark_finished,
            allow_shell,
            allow_install_packages,
            enabled_tools,
        )

        self.changeModel(model_name=model_name, reasoning=reasoning)
        self.app = self._build_graph()

    def _mark_finished(self, summary: str):
        self.finish_summary = summary

    def _record_enumeration(self, entries: Dict[str, dict]):
        self._pending_enumeration.update(entries)

    def _mark_tested(self):
        self._has_real_action = True

    def _has_tested(self) -> bool:
        return self._has_real_action

    def _set_current_session(self, name: Optional[str], command: Optional[str]):
        self._current_session_name = name
        self._current_session_command = command

    def _set_at_shell_prompt(self, value: bool):
        self._at_shell_prompt = value

    def _set_last_raw_output(self, raw_output: Optional[str]):
        self._last_raw_output = raw_output

    def _set_authorized_ports(self, new_ports: List[int]):
        self._authorized_ports_override = new_ports

    async def _apply_granted_ports(self, config: RunnableConfig, new_ports: list[int]):
        current_state = await self.app.aget_state(config)
        scope = dict(current_state.values.get("target_scope") or {})
        scope["ports"] = sorted(set(scope.get("ports") or []) | set(new_ports))
        await self.app.aupdate_state(config, {"target_scope": scope})

    def _build_graph(self):
        workflow = StateGraph(ScoutingState)
        workflow.add_node("agent", self._call_model)
        tool_node = ToolNode(self.tools)
        workflow.add_node(
            "tools",
            common.make_guarded_tools_node(
                tool_node, scouting_tools.WRITER_TOOL_NAMES, scouting_tools.READER_TOOL_NAMES
            ),
        )
        workflow.add_edge(START, "agent")
        workflow.add_conditional_edges("agent", self._should_continue, ["tools", END])
        workflow.add_edge("tools", "agent")
        return workflow.compile(checkpointer=self.checkpointer, interrupt_before=["tools"])

    def _render_context_message(self, state: ScoutingState) -> SystemMessage:
        target_scope = state.get("target_scope")
        if self._authorized_ports_override is not None and target_scope:
            target_scope = {**target_scope, "ports": self._authorized_ports_override}
        scope_reminder = common.render_target_scope_reminder(target_scope)
        lines = [scope_reminder, ""] if scope_reminder else []

        lines.append(
            "### Your job: enumerate this target thoroughly, then call "
            "propose_attack_vector for every service worth testing. You "
            "do not exploit anything yourself."
        )

        if self._current_session_name is not None:
            lines.append("")
            lines.append(
                f'### Current terminal session: "{self._current_session_name}" '
                f"running `{self._current_session_command}`"
            )
            if not self._at_shell_prompt:
                lines.append(
                    "Your last output did not look like your plain shell "
                    "prompt - you may still be inside another program. "
                    "Exit it first before running further shell commands."
                )

        enumeration = state.get("enumeration") or {}
        proposed_vectors = state.get("proposed_vectors") or []
        if enumeration or proposed_vectors:
            lines.append("")
            lines.append(
                "### Known so far (auto-maintained - trust this over your "
                "own memory of earlier turns):"
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
            if proposed_vectors:
                lines.append("Attack vectors already proposed - don't repeat these:")
                shown = proposed_vectors[-_MAX_ENUMERATION_PROPOSED_SHOWN:]
                for v in shown:
                    lines.append(f"- {v}")

        return SystemMessage(content="\n".join(lines))

    async def _call_model(self, state: ScoutingState):
        messages = list(state["messages"])
        context_message = self._render_context_message(state)
        trimmed = common.trim_messages_for_model(messages, self.context_window, self.tools)
        response = await self.llm_with_tools.ainvoke(trimmed + [context_message])

        enumeration = dict(state.get("enumeration") or {})
        for port, fact in self._pending_enumeration.items():
            merged = {**enumeration.get(port, {}), **{k: v for k, v in fact.items() if v}}
            enumeration[port] = merged
        self._pending_enumeration = {}

        proposed_vectors = list(state.get("proposed_vectors") or [])
        proposed_vectors.extend(self._pending_proposed_vectors)
        self._pending_proposed_vectors = []

        return {
            "messages": [response],
            "enumeration": enumeration,
            "proposed_vectors": proposed_vectors,
            "finish_summary": self.finish_summary,
        }

    def _should_continue(self, state: ScoutingState):
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
        target: Target,
        start_prompt: str,
        thread_id: str,
        should_interrupt: bool,
        stop_event,
        max_turns: int = 40,
    ) -> AsyncGenerator:
        config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
        existing_state = await self.app.aget_state(config)

        if existing_state.values:
            input_data = None
            self.finish_summary = existing_state.values.get("finish_summary", self.finish_summary)
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

        if self.allow_shell:
            manager = await kali_registry.get_manager(self.project_id)
            if not manager.has_current_session(self.target_id, self.agent_run_id):
                try:
                    await manager.open_session(
                        self.target_id,
                        self.agent_run_id,
                        agent_tools.DEFAULT_SESSION_NAME,
                        agent_tools.DEFAULT_SESSION_COMMAND,
                    )
                except Exception as e:
                    print(f"Could not pre-open default session for {self.target_id}: {e}")
            current = manager.get_current_session(self.target_id, self.agent_run_id)
            self._set_current_session(
                current.name if current else None,
                current.command if current else None,
            )

        def is_done() -> bool:
            return self.finish_summary is not None

        def requires_interrupt(tool_call_names) -> bool:
            _, readers = common.turn_conflict(
                tool_call_names, scouting_tools.WRITER_TOOL_NAMES, scouting_tools.READER_TOOL_NAMES
            )
            if readers:
                return False
            always = bool(tool_call_names & scouting_tools.ALWAYS_INTERRUPT_TOOL_NAMES)
            return always or (
                should_interrupt
                and bool(tool_call_names & scouting_tools.INTERRUPT_GATED_TOOL_NAMES)
            )

        async def on_tool_message(message: ToolMessage, cfg: RunnableConfig):
            if message.name == agent_tools.REQUEST_PORT_ACCESS_TOOL_NAME and message.artifact:
                await self._apply_granted_ports(cfg, message.artifact)

        async for event in common.run_graph_loop(
            self.app,
            thread_id,
            input_data,
            stop_event,
            self.context_window,
            is_done,
            requires_interrupt,
            on_tool_message=on_tool_message,
            max_turns=max_turns,
        ):
            yield event
