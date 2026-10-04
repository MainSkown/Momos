import asyncio
from typing import Callable, Dict, List, Optional, Tuple
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    ToolMessage,
)
from src.core import db_manager, ollama_manager, settings, tool_groups
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
    ModelNotSelectedException,
    ModelNotInstalledException,
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

# agent_run_id -> pending interrupt's accept callback. Keyed by agent_run_id,
# not target_id - in single_agent mode these are always the same value (see
# Agent.__init__'s own comment on agent_run_id), so every existing call site
# that looks this up by target_id keeps finding exactly the right entry
# unchanged; a multi_agent pipeline's several concurrently-running sub-runs
# (Phase 4) will have genuinely distinct agent_run_ids instead.
_pending_interrupts: Dict[str, Callable[[bool], None]] = {}

# agent_run_id -> the tool_calls of the interrupt currently pending for that
# run, same shape as the AgentInterruptRequest websocket message sent below.
# Kept in lockstep with _pending_interrupts (set/popped together) so a
# client that reloads mid-approval (missing the one-shot websocket push) can
# still recover what it needs to render the dialog via
# AgentService.get_pending_interrupt, instead of being stuck forever with no
# way to approve/deny an "interrupted" run.
_pending_interrupt_tool_calls: Dict[str, List[dict]] = {}

# target_id -> project_id, for every target currently running an agent
# PIPELINE (one root run; in single_agent mode that's the one and only run,
# in multi_agent mode it will be the orchestrator - Phase 4). Unchanged
# meaning from before agent_run_id existed - still exactly one entry per
# running target, still what is_project_running/get_running_target read.
_running_targets: Dict[str, str] = {}

# target_id -> the set of agent_run_ids currently live under that target's
# pipeline - one entry for single_agent mode, but genuinely several once a
# multi_agent pipeline can have several sub-runs in flight at once (Phase 4).
# Populated/depopulated by _run_agent's own registration/cleanup.
# pause_agent/finish_agent fan their stop signal out across every entry
# here for a target instead of assuming there's ever just one - built now,
# even though single_agent mode never puts more than one id in a set, so
# Phase 4 doesn't need to touch either of those two methods again.
_live_runs_for_target: Dict[str, set] = {}

# agent_run_id -> the active run's stop_event, so a pause request can trigger it
_stop_events: Dict[str, asyncio.Event] = {}

# agent_run_id -> the active run's shared time-remaining state (see Agent.start_agent)
_run_states: Dict[str, dict] = {}

# agent_run_id -> True if the pending stop_event.set() should end the run as
# FINISHED (not resumable) rather than PAUSED - set by finish_agent(),
# consumed once in _run_agent's post-loop status decision.
_finish_intents: Dict[str, bool] = {}

# Process-wide cap on how many agent LLM instances may run at once, across
# every project - see config.py's GLOBAL_MAX_CONCURRENT_AGENTS. Safe to
# construct at import time (no running loop needed) - a plain counter under
# the hood until something actually awaits .acquire().
_global_agent_semaphore = asyncio.Semaphore(settings.GLOBAL_MAX_CONCURRENT_AGENTS)

# project_id -> how many slots that project currently holds. NOT a plain
# asyncio.Semaphore per project - a project's own cap
# (ProjectSettings.max_concurrent_agents) can change at runtime via the
# settings UI, and re-reading it live on every acquire (rather than baking a
# fixed size into a Semaphore constructed once, the first time that project
# ever ran) means a changed setting takes effect on the very next acquire,
# not just after a process restart.
_project_slot_counts: Dict[str, int] = {}
_project_slot_condition = asyncio.Condition()


async def _acquire_agent_slot(project_id: str, project_settings: ProjectSettings) -> None:
    """Blocks until a slot is free for this project - both this project's
    own configured allowance AND the global hardware ceiling - then holds
    both. Release with _release_agent_slot exactly once per successful
    acquire (a try/finally at the call site, gated on this having actually
    returned - see _run_agent). effective_slots = min(this project's own
    max_concurrent_agents, the global cap) - see
    GLOBAL_MAX_CONCURRENT_AGENTS's own comment in config.py for why the
    global figure always wins when the two disagree.

    All-or-nothing: if the global acquire below is cancelled (or raises)
    after the per-project slot was already counted, that count is rolled
    back before re-raising - otherwise a cancelled caller would leak a
    per-project slot forever, since _release_agent_slot is never reached
    for an acquire that didn't actually succeed."""
    effective_slots = max(
        1, min(project_settings.max_concurrent_agents, settings.GLOBAL_MAX_CONCURRENT_AGENTS)
    )
    async with _project_slot_condition:
        while _project_slot_counts.get(project_id, 0) >= effective_slots:
            await _project_slot_condition.wait()
        _project_slot_counts[project_id] = _project_slot_counts.get(project_id, 0) + 1
    try:
        # Acquired second, not first - holding the per-project slot while
        # waiting on the global one is harmless (nothing else needs THIS
        # project's slot released to make global progress elsewhere), and
        # keeping one consistent acquire order everywhere this is called
        # is what actually matters for avoiding a deadlock between the two.
        await _global_agent_semaphore.acquire()
    except BaseException:
        async with _project_slot_condition:
            _project_slot_counts[project_id] = max(0, _project_slot_counts.get(project_id, 0) - 1)
            _project_slot_condition.notify_all()
        raise


async def _release_agent_slot(project_id: str) -> None:
    _global_agent_semaphore.release()
    async with _project_slot_condition:
        _project_slot_counts[project_id] = max(0, _project_slot_counts.get(project_id, 0) - 1)
        _project_slot_condition.notify_all()


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
    # These dicts are actually keyed by agent_run_id now (see their own
    # comments) - this still works unchanged because single_agent mode's
    # agent_run_id always equals target_id. AgentInterruptResponseMessage
    # has no agent_run_id field yet to look up a multi_agent sub-run's own
    # pending interrupt by - that's Phase 6's job, alongside the rest of
    # the "queue of pending approvals" work.
    accept = _pending_interrupts.pop(message.target_id, None)
    _pending_interrupt_tool_calls.pop(message.target_id, None)

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


def _capability_note(project_settings: ProjectSettings) -> str:
    """A short corrective block appended by _render_start_prompt when this
    project's actual allow_shell/allow_install_packages settings mean some
    tool the starting prompt's own text may describe (the default
    base_starting_prompt does; a hand-edited one might too) isn't actually
    available this run - see PROMPT_AUDIT.md finding 4.2. Applied
    unconditionally on the flags themselves, not on whether the prompt is
    still the unmodified default - starting_prompt is stored per-project and
    only ever SEEDED from base_starting_prompt at project creation
    (project_settings_factory), so a template-only fix would never reach an
    already-created or hand-edited project. Empty string when both flags are
    on (today's implicit assumption, so nothing needs correcting)."""
    if not project_settings.allow_shell:
        # nmap_scan/searchsploit_search/searchsploit_view are core/always-
        # bound (tool_groups.py) regardless of enabled_tools; everything
        # else this project actually has bound is whatever
        # tool_names_for(enabled_tools) resolves to (metasploit_run
        # included only when that group is on) - listing a tool here that
        # build_agent_tools didn't actually bind would just have the model
        # call something that doesn't exist.
        available = ["nmap_scan", "searchsploit_search", "searchsploit_view"] + sorted(
            tool_groups.tool_names_for(project_settings.enabled_tools)
        )
        return (
            "\n\n### Runtime Note\n"
            "Raw terminal access is disabled for this run - `run`, "
            "`new_session`, `switch_session`, `list_sessions`, "
            "`close_session`, `interrupt_session`, and "
            "`install_kali_package` are NOT available, regardless of "
            "anything said above. Your only way to act against the target "
            "is the structured tools this project has enabled: "
            + ", ".join(f"`{name}`" for name in available)
            + " - use those for everything."
        )
    if not project_settings.allow_install_packages:
        return (
            "\n\n### Runtime Note\n"
            "Package installation is disabled for this run - "
            "`install_kali_package` is NOT available, regardless of "
            "anything said above. Work only with what's already listed as "
            "installed; you have no way to add anything else."
        )
    return ""


def _render_start_prompt(
    template: str, target: Target, project_settings: ProjectSettings
) -> str:
    """Replaces every {{placeholder}} in the starting prompt with the target's
    actual values - matching the placeholders documented in
    ProjectSettingsPage.vue - then appends a runtime capability note (see
    _capability_note) if this project's allow_shell/allow_install_packages
    settings mean some tool the prompt's own text may describe isn't
    actually available this run."""
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

    return rendered + _capability_note(project_settings)


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

    if tool_name == agent_tools.REQUEST_PORT_ACCESS_TOOL_NAME:
        return f"{args.get('port', '')}/{args.get('protocol', '')}: {args.get('reason', '')}"

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
        artifact = getattr(message, "artifact", None)
        # AgentLog.raw_output is Optional[str] - some content_and_artifact
        # tools put non-string data there instead (request_port_access's
        # artifact is a List[int] of newly-authorized ports, consumed
        # directly from message.artifact by agent.py's port-application
        # logic, never meant to be persisted/displayed as text). Passing
        # that straight through used to reach AgentLogResponse.model_validate
        # in _persist_and_broadcast and raise a pydantic ValidationError
        # there, crashing log persistence for the very turn a port grant
        # was just approved - confirmed by reproducing it directly.
        artifact_str = artifact if isinstance(artifact, str) else None

        # artifact is populated for tools using response_format=
        # "content_and_artifact" (run/new_session/switch_session, see
        # agent_tools.py) - None for every other tool, and never sent
        # back to the model either way (LangChain only resends
        # .content/.tool_calls, not .artifact). It's persisted as
        # AgentLog.raw_output but never rendered by the frontend, so in
        # every other case `content` is both what the agent sees next
        # turn AND what the user sees in the log.
        #
        # searchsploit_view is the one deliberate exception: its `content`
        # must stay the exploit's full raw source (the agent needs it
        # verbatim - see its own docstring), which is too much to dump
        # into the user-facing chat log. Its artifact holds a short,
        # parsed summary instead (see _summarize_exploit_source in
        # agent_tools.py), so here - and only here - that's what gets
        # displayed; the full source is kept as raw_output instead of
        # being discarded.
        if message.name == agent_tools.SEARCHSPLOIT_VIEW_TOOL_NAME and artifact_str:
            display_content, raw_output = artifact_str, content
        else:
            display_content, raw_output = content, artifact_str

        if display_content.strip():
            specs.append(("action", display_content, None, raw_output))

    return specs


async def _persist_and_broadcast(
    project_id: str,
    target_id: str,
    log_type: AgentLogType,
    content: str,
    tool_name: Optional[str] = None,
    raw_output: Optional[str] = None,
    agent_run_id: Optional[str] = None,
    role: Optional[str] = None,
) -> AgentLog:
    log = AgentLog(
        type=log_type,
        content=content,
        tool_name=tool_name,
        raw_output=raw_output,
        project_id=project_id,
        target_id=target_id,
        agent_run_id=agent_run_id,
        role=role,
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

        # Loaded here (a synchronous db call, no await) rather than after the
        # claim below, so an unselected model can be rejected before either
        # the target is claimed or the Kali container is provisioned -
        # parsing_model_name is intentionally allowed to be empty (see
        # project_settings_factory/agent_tools.py's own handling of it), only
        # base_model_name is actually required to run the agent at all.
        project_settings = db_manager.get_project_settings(project_id)
        if not project_settings.base_model_name:
            raise ModelNotSelectedException(
                f"Project {project_id} has no AI model selected - choose a "
                "model in project settings before starting a scan."
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

        # Blocking install check - unlike _prepare_and_run's own best-effort
        # capabilities lookup (kept as-is, for reasoning/context_window),
        # this one actually aborts the start if the model isn't installed/
        # reachable, instead of silently falling back to defaults and
        # running anyway. Done after claiming the target (claiming itself
        # must stay await-free, see the comment above) - un-claim on
        # failure so a rejected start doesn't leave the target/project stuck
        # looking busy.
        try:
            await ollama_manager.get_model_capabilities(project_settings.base_model_name)
        except Exception as e:
            _running_targets.pop(target_id, None)
            raise ModelNotInstalledException(
                f"Model '{project_settings.base_model_name}' is not "
                f"installed or reachable: {e}",
                project_settings.base_model_name,
            )

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
            # A plain dict write, safe to call directly from this executor
            # thread - see kali_user.py's identical on_stage for why. Lets a
            # client that missed the live KaliCreationStageMessage below
            # (e.g. Targets.vue refreshed mid-build) recover current
            # progress via kali_registry.get_build_status.
            kali_registry.set_build_stage(project_id, stage, target_id=target_id)

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
            kali_registry.clear_build_status(project_id)
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
                enabled_tools=project_settings.enabled_tools,
            )
        except Exception as e:
            # Without this, a failure preparing the container would leave the
            # target claimed in _running_targets forever with no feedback -
            # the UI would just show "starting" indefinitely.
            print(f"Could not prepare agent run for target {target_id}: {e}")
            _running_targets.pop(target_id, None)
            kali_registry.clear_build_status(project_id)
            await _persist_and_broadcast(
                project_id, target_id, "action", f"Could not start agent: {e}"
            )
            return

        await AgentService._run_agent(agent, target, project_settings, duration_seconds)

    @staticmethod
    async def pause_agent(project_id: str, target_id: str):
        """Signals the stop_event of every agent run currently live under
        this target's pipeline - one, in single_agent mode, but genuinely
        several once a multi_agent pipeline can have concurrent sub-runs in
        flight (Phase 4): pausing the whole pipeline must stop all of them,
        not just whichever one a caller happened to know about. See
        _live_runs_for_target's own comment for why this index exists."""
        AgentService._get_owned_target(project_id, target_id)

        for agent_run_id in list(_live_runs_for_target.get(target_id, ())):
            stop_event = _stop_events.get(agent_run_id)
            if stop_event is not None:
                stop_event.set()

    @staticmethod
    async def finish_agent(project_id: str, target_id: str):
        """Ends the run outright (FINISHED, not resumable), as opposed to
        pause_agent's PAUSED/resumable stop. Reachable from two distinct
        states, handled differently since only one of them has anything
        actually running:
        - RUNNING: signal the active loop's stop_event, same as pause_agent,
          but flagged so the post-loop status decision resolves to FINISHED
          instead of PAUSED. Only effective while the agent is actually in
          its main loop - a run parked in _pending_interrupts (awaiting
          interrupt approval, status INTERRUPTED) isn't waiting on
          stop_event at all, so this has no effect until
          _on_interrupt_response resumes it - callers should gate this the
          same way pause_agent already is (status == "running" only).
        - PAUSED: there is no active loop/stop_event at all (_run_agent's
          finally already popped it) - directly flip the persisted status
          instead. This is what lets a paused run be finished outright from
          the UI's resume button, instead of only ever being resumed.
        Any other state (no run, already FINISHED/FAILED) is a no-op.

        Fans out across every agent run currently live under this target's
        pipeline (see pause_agent's own comment on _live_runs_for_target) -
        one, in single_agent mode, but genuinely several once a
        multi_agent pipeline can have concurrent sub-runs in flight
        (Phase 4)."""
        AgentService._get_owned_target(project_id, target_id)

        live_run_ids = list(_live_runs_for_target.get(target_id, ()))
        any_signaled = False
        for agent_run_id in live_run_ids:
            stop_event = _stop_events.get(agent_run_id)
            if stop_event is not None:
                # Must be recorded before stop_event.set() - _run_agent's
                # post-loop status decision reads this once the loop wakes
                # up and exhausts, immediately after the event fires.
                _finish_intents[agent_run_id] = True
                stop_event.set()
                any_signaled = True

        if any_signaled:
            return

        existing_run = db_manager.get_agent_run(target_id)
        if existing_run is not None and existing_run.status == AgentRunState.PAUSED:
            await _persist_run_state(project_id, target_id, AgentRunState.FINISHED, 0)

    @staticmethod
    def get_run(project_id: str, target_id: str) -> Optional[AgentRun]:
        AgentService._get_owned_target(project_id, target_id)

        return db_manager.get_agent_run(target_id)

    @staticmethod
    def get_pending_interrupt(project_id: str, target_id: str) -> Optional[List[dict]]:
        """The tool_calls of the interrupt currently awaiting approval for
        target_id, or None if there isn't one - lets a client that reloaded
        mid-approval (and so missed the one-shot AgentInterruptRequest
        websocket push) recover the dialog's contents instead of being
        stuck with a run stuck as INTERRUPTED and nothing to approve/deny."""
        AgentService._get_owned_target(project_id, target_id)

        return _pending_interrupt_tool_calls.get(target_id)

    @staticmethod
    def is_project_running(project_id: str) -> bool:
        return project_id in _running_targets.values()

    @staticmethod
    def get_running_target(project_id: str) -> Optional[str]:
        """The target currently running for project_id, or None - at most
        one, since start_agent enforces one running target per project."""
        return next(
            (t for t, p in _running_targets.items() if p == project_id), None
        )

    @staticmethod
    async def _run_agent(
        agent: Agent,
        target: Target,
        project_settings: ProjectSettings,
        duration_seconds: int,
    ):
        project_id = str(target.project_id)
        target_id = str(target.id)
        # == target_id for single_agent mode (see Agent.__init__'s own
        # comment) - every dict below keyed by agent_run_id therefore keeps
        # behaving exactly as it did when it was keyed by target_id, for
        # every call site that still only knows about target_id (pause_agent,
        # get_pending_interrupt, the websocket interrupt-response hook, ...).
        # A multi_agent pipeline's sub-runs (Phase 4) will have genuinely
        # distinct ids here instead.
        agent_run_id = agent.agent_run_id
        # Hardcoded for now - every caller of _run_agent today is the
        # single_agent flow. Phase 4's roles log their own role instead,
        # most likely by generalizing this same function rather than
        # duplicating it.
        role = "single_agent"

        stop_event = asyncio.Event()
        run_state: dict = {}
        slot_acquired = False

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
            _stop_events[agent_run_id] = stop_event
            _run_states[agent_run_id] = run_state
            _live_runs_for_target.setdefault(target_id, set()).add(agent_run_id)

            # Blocks here, potentially for a while, if this project (or the
            # whole backend) is already at its concurrent-agent ceiling -
            # see _acquire_agent_slot. Deliberately AFTER the registration
            # above (so a pause/finish request issued while still queued
            # for a slot can still flip _finish_intents/set stop_event - the
            # loop below simply never got to check them yet) but BEFORE
            # _set_running/_persist_run_state (a run that's still waiting
            # for a slot hasn't actually started yet, so it shouldn't claim
            # to be RUNNING until it is).
            await _acquire_agent_slot(project_id, project_settings)
            slot_acquired = True

            await _set_running(project_id, target_id, True)
            await _persist_run_state(
                project_id, target_id, AgentRunState.RUNNING, duration_seconds
            )

            await _persist_and_broadcast(
                project_id,
                target_id,
                "action",
                f"Starting analysis on target: {target.name}",
                agent_run_id=agent_run_id,
                role=role,
            )

            async for event in agent.start_agent(
                target=target,
                start_prompt=_render_start_prompt(
                    project_settings.starting_prompt, target, project_settings
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
                    _pending_interrupts[agent_run_id] = event["accept"]
                    tool_calls = [
                        {"name": tc["name"], "args": tc["args"]}
                        for tc in event["tool_calls"]
                    ]
                    _pending_interrupt_tool_calls[agent_run_id] = tool_calls

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
                            tool_calls=tool_calls,
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
                        project_id,
                        target_id,
                        log_type,
                        content,
                        tool_name,
                        raw_output,
                        agent_run_id=agent_run_id,
                        role=role,
                    )

            if agent.finish_summary:
                await _persist_and_broadcast(
                    project_id,
                    target_id,
                    "action",
                    f"Agent finished the task: {agent.finish_summary}",
                    agent_run_id=agent_run_id,
                    role=role,
                )

            # The generator exhausted normally - either the user paused it,
            # the user held the button to finish it outright, the agent
            # decided it was done (finish_summary is set), or it genuinely
            # ran out of time. finish_agent() takes priority over the plain
            # stop_event check below - a held-to-finish stop must never be
            # reclassified as PAUSED (which would make it resumable).
            finished_by_request = _finish_intents.pop(agent_run_id, False)
            final_status = (
                AgentRunState.FINISHED
                if finished_by_request
                else (
                    AgentRunState.PAUSED if stop_event.is_set() else AgentRunState.FINISHED
                )
            )
            # A user-forced finish always zeroes remaining_seconds - it's a
            # deliberate "stop counting" action, not a natural exhaustion
            # that just happens to land near 0.
            final_remaining = 0 if finished_by_request else run_state.get("time_left", 0)
            await _persist_run_state(
                project_id, target_id, final_status, final_remaining
            )
        except Exception as e:
            print(f"Agent run failed for target {target_id}: {e}")
            await _persist_and_broadcast(
                project_id,
                target_id,
                "action",
                f"Agent run failed: {e}",
                agent_run_id=agent_run_id,
                role=role,
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
                # Scoped to just THIS run's own sessions, not every session
                # on the target - close_sessions_for_target would tear down
                # a sibling agent's sessions too, once more than one can be
                # live on the same target at once (Phase 4). Harmless no-op
                # difference for single_agent mode today, where this run is
                # always the only one.
                await manager.close_sessions_for_run(target_id, agent_run_id)

            _pending_interrupts.pop(agent_run_id, None)
            _pending_interrupt_tool_calls.pop(agent_run_id, None)
            _stop_events.pop(agent_run_id, None)
            _run_states.pop(agent_run_id, None)
            # Purely defensive - the try block above already pops this on
            # the normal-completion path. A finish request that overlaps an
            # exception/FAILED run is simply dropped, not retried.
            _finish_intents.pop(agent_run_id, None)
            live_runs = _live_runs_for_target.get(target_id)
            if live_runs is not None:
                live_runs.discard(agent_run_id)
                if not live_runs:
                    _live_runs_for_target.pop(target_id, None)
            if slot_acquired:
                await _release_agent_slot(project_id)
            await _set_running(project_id, target_id, False)
