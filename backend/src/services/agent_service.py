import asyncio
from typing import Callable, Dict, List, Optional, Tuple
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_ollama import ChatOllama
from src.core import db_manager, settings
from src.core.agent import Agent, agent_tools
from src.core.agent import agent_checkpointer
from src.core.kali_integration import kali_registry
from src.schemas.target_scheme import Target
from src.schemas.project_scheme import ProjectSettings
from src.schemas.agent_log_scheme import AgentLog, AgentLogResponse, AgentLogType
from src.schemas.agent_run_scheme import AgentRun, AgentRunResponse, AgentRunState
from src.utils.exceptions import (
    ProjectDoesNotExistException,
    TargetDoesNotExistException,
    DurationNotDefinedInTarget,
    AgentAlreadyRunningException,
)
from src.websocket import (
    ws_registry,
    WsTypes,
    AgentMessage,
    AgentInterruptRequest,
    AgentInterruptResponseMessage,
    AgentRunStatus,
    AgentRunTimer,
)

# thread_id (== target_id) -> pending interrupt's accept callback
_pending_interrupts: Dict[str, Callable[[bool], None]] = {}

# target_id -> project_id, for every target currently running an agent
_running_targets: Dict[str, str] = {}

# target_id -> the active run's stop_event, so a pause request can trigger it
_stop_events: Dict[str, asyncio.Event] = {}

# target_id -> the active run's shared time-remaining state (see Agent.start_agent)
_run_states: Dict[str, dict] = {}


async def _set_running(project_id: str, target_id: str, running: bool):
    if running:
        _running_targets[target_id] = project_id
    else:
        _running_targets.pop(target_id, None)

    await ws_registry.send_message(
        AgentRunStatus(
            type=WsTypes.AgentRunStatus,
            project_id=project_id,
            target_id=target_id,
            running=running,
        )
    )


async def _persist_run_state(
    project_id: str, target_id: str, status: AgentRunState, remaining_seconds: float
) -> AgentRun:
    run = AgentRun(
        status=status,
        remaining_seconds=max(0, int(remaining_seconds)),
        project_id=project_id,
        target_id=target_id,
    )

    loop = asyncio.get_running_loop()
    saved = await loop.run_in_executor(None, db_manager.upsert_agent_run, run)

    await ws_registry.send_message(
        AgentRunTimer(
            type=WsTypes.AgentRunTimer,
            run=AgentRunResponse.model_validate(saved),
        )
    )

    return saved


async def _on_interrupt_response(message: AgentInterruptResponseMessage):
    accept = _pending_interrupts.pop(message.target_id, None)

    if accept is None:
        print(f"No pending interrupt for target {message.target_id}. Ignoring.")
        return

    # The agent is about to resume - flip the timer back to running immediately,
    # rather than waiting for the next log message to arrive.
    run_state = _run_states.get(message.target_id, {})
    await _persist_run_state(
        message.project_id,
        message.target_id,
        AgentRunState.RUNNING,
        run_state.get("time_left", 0),
    )

    accept(message.approved)


ws_registry.add_hook(WsTypes.AgentInterruptResponse, _on_interrupt_response)


def _stringify_content(content) -> str:
    return content if isinstance(content, str) else str(content)


NOT_DEFINED = "Not defined"


def _format_prompt_value(value) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) if value else NOT_DEFINED

    if value is None or value == "":
        return NOT_DEFINED

    return str(value)


def _render_start_prompt(template: str, target: Target) -> str:
    """Replaces every {{placeholder}} in the starting prompt with the target's
    actual values - matching the placeholders documented in ProjectSettingsPage.vue."""
    replacements = {
        "{{name}}": _format_prompt_value(target.name),
        "{{description}}": _format_prompt_value(target.description),
        "{{ipv4}}": _format_prompt_value(target.ipv4),
        "{{ipv6}}": _format_prompt_value(target.ipv6),
        "{{ports}}": _format_prompt_value(target.ports),
    }

    rendered = template

    for placeholder, value in replacements.items():
        rendered = rendered.replace(placeholder, value)

    return rendered


def _render_tool_call_content(tool_name: str, args: dict) -> str:
    if tool_name == agent_tools.KALI_COMMAND_TOOL_NAME:
        return str(args.get("command", ""))

    if tool_name == agent_tools.REPORT_VULNERABILITY_TOOL_NAME:
        return str(args.get("name", ""))

    return ", ".join(f"{k}={v}" for k, v in args.items())


LOG_SUMMARY_SYSTEM_PROMPT = (
    "You are summarizing a penetration-testing agent's activity for a live "
    "status log. Rewrite the given text as a single short, clear sentence "
    "describing what the agent is doing, thinking, or found. Keep it factual "
    "and concise - no preamble, no commentary, just the summary."
)


async def _summarize_for_log(project_id: str, content: str) -> str:
    parsing_model_name = await agent_tools.get_parsing_model_name(project_id)

    if not parsing_model_name:
        # No parsing model configured for this project - fall back to raw content
        return content

    parser_llm = ChatOllama(model=parsing_model_name, base_url=settings.ollama_url)

    try:
        response = await parser_llm.ainvoke(
            [
                SystemMessage(content=LOG_SUMMARY_SYSTEM_PROMPT),
                HumanMessage(content=content),
            ]
        )
    except Exception as e:
        # A flaky/unreachable parsing model must not take down the whole
        # agent run - fall back to the raw content for this one log entry.
        print(f"Log summarization failed, using raw content: {e}")
        return content

    return str(response.content)


def _message_to_log_specs(
    message: BaseMessage,
) -> List[Tuple[AgentLogType, str, Optional[str]]]:
    """Turns one agent message into zero or more (type, content, tool_name) specs."""
    specs: List[Tuple[AgentLogType, str, Optional[str]]] = []

    if isinstance(message, AIMessage):
        content = _stringify_content(message.content)

        if content.strip():
            specs.append(("thinking", content, None))

        for tc in message.tool_calls:
            specs.append(
                ("tool", _render_tool_call_content(tc["name"], tc["args"]), tc["name"])
            )

    elif isinstance(message, ToolMessage):
        content = _stringify_content(message.content)

        if content.strip():
            specs.append(("action", content, None))

    return specs


async def _persist_and_broadcast(
    project_id: str,
    target_id: str,
    log_type: AgentLogType,
    content: str,
    tool_name: Optional[str] = None,
) -> AgentLog:
    log = AgentLog(
        type=log_type,
        content=content,
        tool_name=tool_name,
        project_id=project_id,
        target_id=target_id,
    )

    loop = asyncio.get_running_loop()
    saved = await loop.run_in_executor(None, db_manager.add_agent_log, log)

    await ws_registry.send_message(
        AgentMessage(
            type=WsTypes.AgentMessage,
            log=AgentLogResponse.model_validate(saved),
        )
    )

    return saved


class AgentService:
    @staticmethod
    def _get_owned_target(project_id: str, target_id: str) -> Target:
        project = db_manager.get_project(project_id)

        if project is None:
            raise ProjectDoesNotExistException(
                f"Tried accessing nonexistent project ({project_id})",
                project_id,
            )

        target = db_manager.get_target(target_id)

        if target is None or str(target.project_id) != str(project.id):
            raise TargetDoesNotExistException(
                f"Target {target_id} does not exist in project {project_id}", target_id
            )

        return target

    @staticmethod
    async def start_agent(project_id: str, target_id: str):
        target = AgentService._get_owned_target(project_id, target_id)

        if target_id in _running_targets:
            raise AgentAlreadyRunningException(
                f"Agent is already running for target {target_id}", target_id
            )

        if target.task_duration is None or target.task_duration == 0:
            raise DurationNotDefinedInTarget(
                f"Target {target_id} does not have defined scan duration"
            )

        # Resume from a paused run's remaining time, if one exists - otherwise
        # start fresh with the target's full configured duration.
        existing_run = db_manager.get_agent_run(target_id)

        if existing_run is not None and existing_run.status == AgentRunState.PAUSED:
            duration_seconds = existing_run.remaining_seconds
        else:
            duration_seconds = target.task_duration

        # Initiate kali manager for this project
        # TODO - Message to frontend that container init
        kali_manager = await kali_registry.get_manager(project_id)
        await kali_manager.prepare_nftables(target)
        # TODO - Message to frontend that container started

        project_settings = db_manager.get_project_settings(project_id)

        agent = Agent(
            model_name=project_settings.base_model_name,
            checkpointer=agent_checkpointer.checkpointer,
            project_id=project_id,
            target_id=target_id,
        )

        asyncio.create_task(
            AgentService._run_agent(agent, target, project_settings, duration_seconds)
        )

    @staticmethod
    async def pause_agent(project_id: str, target_id: str):
        AgentService._get_owned_target(project_id, target_id)

        stop_event = _stop_events.get(target_id)

        if stop_event is None:
            # Not currently running - nothing to pause
            return

        stop_event.set()

    @staticmethod
    def get_run(project_id: str, target_id: str) -> Optional[AgentRun]:
        AgentService._get_owned_target(project_id, target_id)

        return db_manager.get_agent_run(target_id)

    @staticmethod
    def is_project_running(project_id: str) -> bool:
        return project_id in _running_targets.values()

    @staticmethod
    async def _run_agent(
        agent: Agent,
        target: Target,
        project_settings: ProjectSettings,
        duration_seconds: int,
    ):
        project_id = str(target.project_id)
        target_id = str(target.id)

        stop_event = asyncio.Event()
        run_state: dict = {}
        _stop_events[target_id] = stop_event
        _run_states[target_id] = run_state

        await _set_running(project_id, target_id, True)
        await _persist_run_state(
            project_id, target_id, AgentRunState.RUNNING, duration_seconds
        )

        try:
            await _persist_and_broadcast(
                project_id,
                target_id,
                "action",
                f"Starting analysis on target: {target.name}",
            )

            async for event in agent.start_agent(
                target=target,
                start_prompt=_render_start_prompt(
                    project_settings.starting_prompt, target
                ),
                thread_id=target_id,
                should_interrupt=project_settings.should_interrupt,
                duration_seconds=duration_seconds,
                stop_event=stop_event,
                run_state=run_state,
            ):
                if isinstance(event, dict):
                    # AgentInterruptAction - pause and wait for approval
                    _pending_interrupts[target_id] = event["accept"]

                    await _persist_run_state(
                        project_id,
                        target_id,
                        AgentRunState.INTERRUPTED,
                        run_state.get("time_left", 0),
                    )

                    await ws_registry.send_message(
                        AgentInterruptRequest(
                            type=WsTypes.AgentInterruptRequest,
                            project_id=project_id,
                            target_id=target_id,
                            tool_calls=[
                                {"name": tc["name"], "args": tc["args"]}
                                for tc in event["tool_calls"]
                            ],
                        )
                    )
                    continue

                for log_type, content, tool_name in _message_to_log_specs(event):
                    if log_type in ("thinking", "action"):
                        content = await _summarize_for_log(project_id, content)

                    await _persist_and_broadcast(
                        project_id, target_id, log_type, content, tool_name
                    )

            # The generator exhausted normally - either the user paused it
            # (stop_event was set) or it genuinely ran out of time/finished.
            final_status = (
                AgentRunState.PAUSED if stop_event.is_set() else AgentRunState.FINISHED
            )
            await _persist_run_state(
                project_id, target_id, final_status, run_state.get("time_left", 0)
            )
        except Exception as e:
            print(f"Agent run failed for target {target_id}: {e}")
            await _persist_and_broadcast(
                project_id, target_id, "action", f"Agent run failed: {e}"
            )
            await _persist_run_state(project_id, target_id, AgentRunState.FINISHED, 0)
        finally:
            _pending_interrupts.pop(target_id, None)
            _stop_events.pop(target_id, None)
            _run_states.pop(target_id, None)
            await _set_running(project_id, target_id, False)
