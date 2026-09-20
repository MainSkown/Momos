import asyncio
from typing import Callable, Dict, List, Optional, Tuple
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    ToolMessage,
)
from src.core import db_manager, ollama_manager, settings
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
    AgentContextUsage,
    KaliCreationStageMessage,
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
    # No branch for agent_tools.KALI_COMMAND_TOOL_NAME here - that tool is
    # built but deliberately never bound in agent_tools.build_agent_tools
    # (see create_kali_tool's own docstring), so it can never actually
    # appear in a real tool call. Revive create_kali_tool's call site there
    # first if this ever needs to render its args again.
    if tool_name == agent_tools.INSTALL_PACKAGE_TOOL_NAME:
        return str(args.get("package", ""))

    if tool_name == agent_tools.ATTACK_LOG_TOOL_NAME:
        return f"[{args.get('outcome', '')}] {args.get('target', '')}: {args.get('vector', '')}"

    if tool_name == agent_tools.REPORT_VULNERABILITY_TOOL_NAME:
        severity = args.get("severity", "")
        return f"[{severity}] {args.get('name', '')}" if severity else str(args.get("name", ""))

    if tool_name == agent_tools.FINISH_TASK_TOOL_NAME:
        return str(args.get("summary", ""))

    if tool_name == agent_tools.SWITCH_MODE_TOOL_NAME:
        return f"{args.get('mode', '')}: {args.get('reason', '')}"

    if tool_name == agent_tools.RUN_TOOL_NAME:
        input_value = args.get("input")
        return str(input_value) if input_value is not None else "(checking for output)"

    if tool_name == agent_tools.NEW_SESSION_TOOL_NAME:
        return f"[{args.get('name', '')}] {args.get('command', '')}"

    if tool_name == agent_tools.SWITCH_SESSION_TOOL_NAME:
        return str(args.get("name", ""))

    if tool_name == agent_tools.CLOSE_SESSION_TOOL_NAME:
        return str(args.get("name", ""))

    if tool_name == agent_tools.LIST_SESSIONS_TOOL_NAME:
        return "(list sessions)"

    if tool_name == agent_tools.INTERRUPT_SESSION_TOOL_NAME:
        return "(Ctrl-C)"

    if tool_name == agent_tools.NMAP_SCAN_TOOL_NAME:
        extras = []
        if args.get("run_default_scripts"):
            extras.append("-sC")
        if args.get("timing"):
            extras.append(str(args["timing"]))
        suffix = f" ({', '.join(extras)})" if extras else ""
        return f"ports={args.get('ports') or 'default'}{suffix}"

    if tool_name == agent_tools.HYDRA_BRUTEFORCE_TOOL_NAME:
        user = args.get("username") or args.get("username_list", "")
        return f"{args.get('service', '')}: {user}"

    if tool_name == agent_tools.GOBUSTER_SCAN_TOOL_NAME:
        scheme = "https" if args.get("use_tls") else "http"
        return f"{scheme} port {args.get('port', 80)}"

    if tool_name in (
        agent_tools.SEARCHSPLOIT_SEARCH_TOOL_NAME,
        agent_tools.SEARCHSPLOIT_VIEW_TOOL_NAME,
    ):
        return str(args.get("query") or args.get("edb_id", ""))

    if tool_name == agent_tools.SEARCHSPLOIT_RUN_TOOL_NAME:
        edb_id = args.get("edb_id", "")
        run_args = args.get("exploit_args", "")
        return f"EDB-ID {edb_id} {run_args}".strip()

    if tool_name == agent_tools.FTP_CONNECT_TOOL_NAME:
        return str(args.get("username", ""))

    if tool_name == agent_tools.FTP_COMMAND_TOOL_NAME:
        return str(args.get("command", ""))

    if tool_name in (agent_tools.SSH_CHECK_LOGIN_TOOL_NAME, agent_tools.SSH_RUN_TOOL_NAME):
        username = args.get("username", "")
        command = args.get("command")
        return f"{username}: {command}" if command is not None else username

    if tool_name == agent_tools.TELNET_PROBE_TOOL_NAME:
        return f"port {args.get('port', '')}"

    return ", ".join(f"{k}={v}" for k, v in args.items())


def _message_to_log_specs(
    message: BaseMessage,
) -> List[Tuple[AgentLogType, str, Optional[str], Optional[str]]]:
    """Turns one agent message into zero or more (type, content, tool_name,
    raw_output) specs."""
    specs: List[Tuple[AgentLogType, str, Optional[str], Optional[str]]] = []

    if isinstance(message, AIMessage):
        # Prefer additional_kwargs['reasoning_content'] - Agent.changeModel
        # sets reasoning=True, and that's where a native "thinking" model's
        # reasoning ends up rather than in .content (see agent.py's
        # _call_model), so it doesn't get replayed into the model's own
        # future context. Fall back to .content for a model that puts
        # substantive text there directly instead (no native reasoning
        # support, template allows text alongside/instead of a tool call).
        reasoning_content = message.additional_kwargs.get("reasoning_content")
        content = (
            _stringify_content(reasoning_content)
            if reasoning_content
            else _stringify_content(message.content)
        )

        if content.strip():
            specs.append(("thinking", content, None, None))

        for tc in message.tool_calls:
            specs.append(
                ("tool", _render_tool_call_content(tc["name"], tc["args"]), tc["name"], None)
            )

    elif isinstance(message, ToolMessage):
        content = _stringify_content(message.content)

        if content.strip():
            # artifact is populated for tools using response_format=
            # "content_and_artifact" (run/new_session/switch_session, see
            # agent_tools.py) - None for every other tool, and never sent
            # back to the model either way (LangChain only resends
            # .content/.tool_calls, not .artifact).
            raw_output = getattr(message, "artifact", None)
            specs.append(("action", content, None, raw_output))

    return specs


async def _persist_and_broadcast(
    project_id: str,
    target_id: str,
    log_type: AgentLogType,
    content: str,
    tool_name: Optional[str] = None,
    raw_output: Optional[str] = None,
) -> AgentLog:
    log = AgentLog(
        type=log_type,
        content=content,
        tool_name=tool_name,
        raw_output=raw_output,
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

        # One KaliManger (and its prepare_nftables firewall scope) is shared
        # across every target in a project (kali_registry.get_manager is
        # keyed by project_id only) - prepare_nftables unconditionally tears
        # down and rebuilds that shared scope for whichever single target is
        # starting, so a second concurrent target in the same project would
        # silently cut off the first's traffic rather than actually running
        # side by side. Enforce exclusivity at the project level instead of
        # letting that race happen.
        if AgentService.is_project_running(project_id):
            raise AgentAlreadyRunningException(
                f"Another target in project {project_id} is already running "
                "an agent - only one target per project can run at a time "
                "(the Kali container and its firewall scope are shared "
                "across the whole project).",
                target_id,
            )

        if target.task_duration is None or target.task_duration == 0:
            raise DurationNotDefinedInTarget(
                f"Target {target_id} does not have defined scan duration"
            )

        # Resume from a paused run's remaining time, if one exists - otherwise
        # start fresh with the target's full configured duration.
        existing_run = db_manager.get_agent_run(target_id)
        resuming_paused_run = (
            existing_run is not None and existing_run.status == AgentRunState.PAUSED
        )
        duration_seconds = (
            existing_run.remaining_seconds if resuming_paused_run else target.task_duration
        )

        # Claim the target (and so, via is_project_running, the whole
        # project) immediately - everything above this point is a plain
        # synchronous check with no `await`, so no other coroutine can have
        # interleaved since this call started; claiming here, before the
        # `await adelete_thread(...)` below (the only await left in this
        # function), closes a real race the two exclusivity checks above
        # would otherwise still have: two concurrent start_agent() calls
        # for two different, fresh targets in the same project could both
        # pass is_project_running before either claimed anything, letting
        # both proceed to build/rebuild the shared Kali container and
        # firewall scope at once.
        _running_targets[target_id] = project_id

        if not resuming_paused_run:
            # Not resuming a paused run - clear any leftover LangGraph
            # checkpoint for this thread (from a prior finished/errored run).
            # The checkpointer persists state per thread_id independently of
            # our own AgentRunState, so without this, Agent.start_agent would
            # try to "resume" an already-completed graph: it has nothing left
            # to do, so it does nothing and looks like an instant, silent
            # completion instead of actually starting the task.
            if agent_checkpointer.checkpointer is not None:
                await agent_checkpointer.checkpointer.adelete_thread(target_id)

        project_settings = db_manager.get_project_settings(project_id)

        asyncio.create_task(
            AgentService._prepare_and_run(target, project_settings, duration_seconds)
        )

    @staticmethod
    async def _prepare_and_run(
        target: Target, project_settings: ProjectSettings, duration_seconds: int
    ):
        project_id = str(target.project_id)
        target_id = str(target.id)
        loop = asyncio.get_running_loop()

        def on_stage(stage):
            # Called from the executor thread running the container's
            # (synchronous) Docker setup - hop back onto the event loop.
            asyncio.run_coroutine_threadsafe(
                ws_registry.send_message(
                    KaliCreationStageMessage(
                        project_id=project_id,
                        type=WsTypes.KaliCreationStage,
                        stage=stage,
                    )
                ),
                loop,
            )

        # Best-effort - a model whose capabilities can't be looked up
        # (Ollama unreachable, model not actually pulled yet, ...) still
        # gets to run, just with Agent's previous hardcoded defaults
        # (reasoning=True, a conservative context-window fallback) rather
        # than failing the whole run over a lookup that's only ever an
        # optimization, never a requirement.
        reasoning: Optional[bool] = None
        context_window: Optional[int] = None
        try:
            capabilities = await ollama_manager.get_model_capabilities(
                project_settings.base_model_name
            )
            reasoning = capabilities["thinking"]
            # Clamp the model's own detected max context to this project's
            # override (if set) or the system-wide default ceiling - this
            # is the exact value Agent.changeModel later requests from
            # Ollama via num_ctx, so it must already reflect whatever cap
            # the operator/project owner wants, not just the raw detected
            # maximum (which can be very large - e.g. 256k for qwen3:8b -
            # and force an allocation the host can't actually afford).
            ceiling = project_settings.max_context_window or settings.DEFAULT_MAX_CONTEXT_WINDOW
            context_window = min(capabilities["context_window"], ceiling)
        except Exception as e:
            print(
                f"Could not fetch capabilities for model "
                f"'{project_settings.base_model_name}', using defaults: {e}"
            )

        try:
            kali_manager = await kali_registry.get_manager(project_id, on_stage=on_stage)
            await kali_manager.prepare_nftables(target)

            # ANDed here as defense-in-depth against a settings row saved
            # before project_router.py's update_project_settings validation
            # existed - install_kali_package must never be reachable
            # without shell access to actually use whatever gets installed.
            effective_allow_install = (
                project_settings.allow_shell and project_settings.allow_install_packages
            )

            agent = Agent(
                model_name=project_settings.base_model_name,
                checkpointer=agent_checkpointer.checkpointer,
                project_id=project_id,
                target_id=target_id,
                reasoning=reasoning,
                context_window=context_window,
                allow_shell=project_settings.allow_shell,
                allow_install_packages=effective_allow_install,
            )
        except Exception as e:
            # Without this, a failure preparing the container would leave the
            # target claimed in _running_targets forever with no feedback -
            # the UI would just show "starting" indefinitely.
            print(f"Could not prepare agent run for target {target_id}: {e}")
            _running_targets.pop(target_id, None)
            await _persist_and_broadcast(
                project_id, target_id, "action", f"Could not start agent: {e}"
            )
            return

        await AgentService._run_agent(agent, target, project_settings, duration_seconds)

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

        try:
            # Registration/initial persistence moved inside this try (was
            # previously before it) - a failure in _set_running/
            # _persist_run_state here used to propagate uncaught out of
            # _run_agent with no wrapping try/except, skipping the finally
            # block below entirely and leaving _running_targets[target_id]
            # (already claimed in start_agent, before this task was even
            # scheduled) permanently stuck - every subsequent start_agent()
            # call for that target would then raise
            # AgentAlreadyRunningException with no recovery short of a
            # backend restart.
            _stop_events[target_id] = stop_event
            _run_states[target_id] = run_state

            await _set_running(project_id, target_id, True)
            await _persist_run_state(
                project_id, target_id, AgentRunState.RUNNING, duration_seconds
            )

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
                if isinstance(event, dict) and event.get("kind") == "context_usage":
                    await ws_registry.send_message(
                        AgentContextUsage(
                            type=WsTypes.AgentContextUsage,
                            project_id=project_id,
                            target_id=target_id,
                            used_tokens=event["used_tokens"],
                            context_window=event["context_window"],
                        )
                    )
                    continue

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

                for log_type, content, tool_name, raw_output in _message_to_log_specs(event):
                    # Log content is shown as-is now, no summarization pass -
                    # in testing, running the agent's own deliberate
                    # reasoning (from the two-phase _call_model split) back
                    # through a separate parsing model degraded it rather
                    # than clarified it. Kali command output is already
                    # condensed by the parsing model inside the tool itself
                    # (see agent_tools.py) before it ever reaches here.

                    await _persist_and_broadcast(
                        project_id, target_id, log_type, content, tool_name, raw_output
                    )

            if agent.finish_summary:
                await _persist_and_broadcast(
                    project_id,
                    target_id,
                    "action",
                    f"Agent finished the task: {agent.finish_summary}",
                )

            # The generator exhausted normally - either the user paused it,
            # the agent decided it was done (finish_summary is set), or it
            # genuinely ran out of time.
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
            # FAILED (not FINISHED) so a crash is distinguishable in the UI
            # from a run that completed/paused/ran out of time normally,
            # and the real time_left already tracked in run_state (not a
            # hardcoded 0) - run_state defaults to {} if the failure
            # happened before the agent loop itself ever started, so
            # .get(...) still falls back to 0 sensibly in that case.
            await _persist_run_state(
                project_id,
                target_id,
                AgentRunState.FAILED,
                run_state.get("time_left", 0),
            )
        finally:
            manager = await kali_registry.get_manager_if_exists(project_id)
            if manager is not None:
                await manager.close_sessions_for_target(target_id)

            _pending_interrupts.pop(target_id, None)
            _stop_events.pop(target_id, None)
            _run_states.pop(target_id, None)
            await _set_running(project_id, target_id, False)
