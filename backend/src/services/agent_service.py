import asyncio
from typing import Dict, List, Optional
from src.core import db_manager, ollama_manager, settings, tool_groups
from src.core.agent import Agent
from src.core.agent import agent_checkpointer
from src.core.agent import run_registry
from src.core.agent.roles import common as roles_common
from src.core.agent.roles.agents.orchestrator_agent import OrchestratorAgent
from src.core.kali_integration import kali_registry
from src.schemas.target_scheme import Target
from src.schemas.project_scheme import (
    ProjectSettings,
    orchestrator_starting_prompt as default_orchestrator_prompt,
)
from src.schemas.agent_run_scheme import AgentRun, AgentRunState
from src.schemas.attack_vector_scheme import AttackVector
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
    AgentInterruptRequest,
    AgentInterruptResponseMessage,
    AgentRunStatus,
    AgentContextUsage,
    KaliCreationStageMessage,
)

# target_id -> project_id, for every target currently running an agent
# PIPELINE (one root run; in single_agent mode that's the one and only run,
# in multi_agent mode it's the orchestrator - Phase 5). Stays here, not in
# run_registry.py - this is the router-facing "is this target's pipeline
# running at all" contract (is_project_running/get_running_target), a
# service-layer concern distinct from run_registry's per-agent-run
# bookkeeping (which a role's own tools also need direct access to,
# without importing this module - see run_registry.py's own docstring for
# why that split exists).
_running_targets: Dict[str, str] = {}


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


async def _on_interrupt_response(message: AgentInterruptResponseMessage):
    # run_registry's dicts are keyed by agent_run_id. A client that knows
    # which sub-run it's answering (see AgentInterruptRequest.agent_run_id -
    # every multi_agent sub-run's own interrupt push now carries its real
    # one, see orchestrator_tools.py's _drain_sub_agent) should set this
    # directly, resolved below with no ambiguity. Single Agent mode's
    # existing clients never send it (its one interrupt is already fully
    # identified by target_id alone, since its agent_run_id always equals
    # target_id - see Agent.__init__'s own comment) and fall through to
    # the direct target_id lookup unchanged. Only a client that sends
    # neither a matching agent_run_id nor has a direct target_id match
    # (e.g. an older multi_agent client, from before this field existed)
    # falls back further, to the first pending interrupt found among every
    # run currently live under this target's pipeline - the same
    # best-effort AgentService.get_pending_interrupt itself uses.
    agent_run_id = message.agent_run_id or message.target_id
    accept = run_registry.pending_interrupts.pop(agent_run_id, None)
    run_registry.pending_interrupt_tool_calls.pop(agent_run_id, None)

    if accept is None:
        for candidate in run_registry.live_runs_for_target.get(message.target_id, ()):
            accept = run_registry.pending_interrupts.pop(candidate, None)
            if accept is not None:
                run_registry.pending_interrupt_tool_calls.pop(candidate, None)
                agent_run_id = candidate
                break

    if accept is None:
        print(f"No pending interrupt for target {message.target_id}. Ignoring.")
        return

    if agent_run_id == message.target_id:
        # Single Agent mode only (its agent_run_id always equals
        # target_id) - flips the UI timer back to RUNNING immediately
        # rather than waiting for the next log message to arrive. A
        # resolved multi_agent sub-run has no run_state timer entry of its
        # own to flip (see roles/common.py's run_graph_loop docstring - only
        # the orchestrator tracks one) - its own next persisted message
        # corrects its displayed status anyway.
        run_state = run_registry.run_states.get(message.target_id, {})
        await run_registry.persist_run_state(
            project_id=message.project_id,
            target_id=message.target_id,
            status=AgentRunState.RUNNING,
            remaining_seconds=run_state.get("time_left", 0),
        )

    accept(message.approved)


ws_registry.add_hook(WsTypes.AgentInterruptResponse, _on_interrupt_response)


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

        # A fixed duration is only required in "timer" mode - a target set
        # to "until_vectors_checked" can start with no task_duration (and
        # no safety_cap_duration either; that just means unbounded).
        if target.run_mode == "timer" and (
            target.task_duration is None or target.task_duration == 0
        ):
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

        multi_agent = project_settings.pipeline_mode == "multi_agent"
        # Multi Agent mode's root run is role="orchestrator" (one real
        # AgentRun row per target, upserted the same way single_agent's
        # own row is - see run_registry.persist_run_state's docstring);
        # everything below this point reads identically for both modes
        # once root_role is resolved.
        root_role = "orchestrator" if multi_agent else "single_agent"

        # Resume from a paused run's remaining time, if one exists - otherwise
        # start fresh. "timer" mode starts fresh with the target's full
        # configured duration (unchanged). "until_vectors_checked" has no
        # required duration - duration_seconds there is instead the elapsed-
        # so-far stopwatch value (0 on a fresh run; AgentRun.remaining_seconds
        # doubles as "elapsed" for this mode - see agent.py/common.py's own
        # comments), and target.safety_cap_duration (optional) is the
        # separate hard ceiling passed through below.
        existing_run = db_manager.get_agent_run(target_id, role=root_role)
        resuming_paused_run = (
            existing_run is not None and existing_run.status == AgentRunState.PAUSED
        )
        if resuming_paused_run:
            duration_seconds = existing_run.remaining_seconds
        elif target.run_mode == "until_vectors_checked":
            duration_seconds = 0
        else:
            duration_seconds = target.task_duration

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

        if not resuming_paused_run and agent_checkpointer.checkpointer is not None:
            # Not resuming a paused run - clear any leftover LangGraph
            # checkpoint for this thread (from a prior finished/errored run).
            # The checkpointer persists state per thread_id independently of
            # our own AgentRunState, so without this, start_agent would try
            # to "resume" an already-completed graph: it has nothing left to
            # do, so it does nothing and looks like an instant, silent
            # completion instead of actually starting the task.
            if multi_agent:
                # The orchestrator's thread_id is f"{target_id}:{its own
                # AgentRun.id}" (Phase 0's thread-id scheme), not target_id
                # itself - only knowable once that row exists. If
                # existing_run is None, this is this target's first-ever
                # multi_agent run and there is no checkpoint to clear yet.
                if existing_run is not None:
                    await agent_checkpointer.checkpointer.adelete_thread(
                        f"{target_id}:{existing_run.id}"
                    )
            else:
                await agent_checkpointer.checkpointer.adelete_thread(target_id)

        if not resuming_paused_run:
            # Scouting (multi_agent) / the agent's own propose_attack_vector
            # tool (single_agent) is about to start proposing vectors again
            # from scratch (the checkpoint was just cleared above), but
            # AttackVector rows aren't checkpointed - without this, leftover
            # vectors from a previous, already-finished run on this same
            # target would still look live to the new run (re-dispatched if
            # "pending" in multi_agent, re-offered to pick up in
            # single_agent, shown as stale board cards either way). Applies
            # regardless of pipeline mode or run_mode - a single_agent
            # Target can propose/resolve vectors too now. See
            # delete_attack_vectors_for_target's own docstring for why this
            # is safe: the Vulnerability rows a prior run produced are a
            # separate, untouched table.
            db_manager.delete_attack_vectors_for_target(target_id)

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

        if multi_agent:
            asyncio.create_task(
                AgentService._prepare_and_run_orchestrator(target, project_settings, duration_seconds)
            )
        else:
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
            await run_registry.persist_and_broadcast(
                project_id=project_id,
                target_id=target_id,
                log_type="action",
                content=f"Could not start agent: {e}",
            )
            return

        await AgentService._run_agent(agent, target, project_settings, duration_seconds)

    @staticmethod
    async def _prepare_and_run_orchestrator(
        target: Target, project_settings: ProjectSettings, duration_seconds: int
    ):
        """Multi Agent mode's equivalent of _prepare_and_run - same Kali/
        nftables preparation (shared once per target, not re-done per
        sub-agent: scouting/pentesting sub-agents call kali_registry.get_manager
        themselves when they open a session, which is a no-op once the
        container already exists), but constructs an OrchestratorAgent
        instead of the Single Agent flow's own Agent, and hands off to
        _run_orchestrator instead of _run_agent - their event-stream shapes
        differ too much to share one runner (see _run_orchestrator's own
        docstring)."""
        project_id = str(target.project_id)
        target_id = str(target.id)
        loop = asyncio.get_running_loop()

        def on_stage(stage):
            kali_registry.set_build_stage(project_id, stage, target_id=target_id)
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

        orchestrator_model_name = (
            project_settings.orchestrator_model_name or project_settings.base_model_name
        )
        reasoning: Optional[bool] = None
        context_window: Optional[int] = None
        try:
            capabilities = await ollama_manager.get_model_capabilities(orchestrator_model_name)
            reasoning = capabilities["thinking"]
            ceiling = project_settings.max_context_window or settings.DEFAULT_MAX_CONTEXT_WINDOW
            context_window = min(capabilities["context_window"], ceiling)
        except Exception as e:
            print(
                f"Could not fetch capabilities for model '{orchestrator_model_name}', "
                f"using defaults: {e}"
            )

        try:
            kali_manager = await kali_registry.get_manager(project_id, on_stage=on_stage)
            kali_registry.clear_build_status(project_id)
            await kali_manager.prepare_nftables(target)

            # Gets (or, on this target's first-ever multi_agent run,
            # creates) the one stable orchestrator AgentRun row for this
            # target - its real `id` IS this pipeline's root agent_run_id
            # from here on (see run_registry.start_sub_run's own docstring
            # for why that distinction matters: every sub-run's
            # parent_run_id needs a REAL AgentRun.id to point at, not an
            # arbitrary string).
            orchestrator_run = await run_registry.persist_run_state(
                project_id=project_id,
                target_id=target_id,
                status=AgentRunState.RUNNING,
                remaining_seconds=duration_seconds,
                agent_run_id=None,
                role="orchestrator",
            )
            orchestrator_agent_run_id = str(orchestrator_run.id)

            orchestrator = OrchestratorAgent(
                model_name=orchestrator_model_name,
                checkpointer=agent_checkpointer.checkpointer,
                project_id=project_id,
                target_id=target_id,
                agent_run_id=orchestrator_agent_run_id,
                reasoning=reasoning,
                context_window=context_window,
                should_interrupt=project_settings.should_interrupt,
            )
        except Exception as e:
            print(f"Could not prepare orchestrator run for target {target_id}: {e}")
            _running_targets.pop(target_id, None)
            kali_registry.clear_build_status(project_id)
            await run_registry.persist_and_broadcast(
                project_id=project_id,
                target_id=target_id,
                log_type="action",
                content=f"Could not start multi-agent pipeline: {e}",
            )
            return

        await AgentService._run_orchestrator(orchestrator, target, project_settings, duration_seconds)

    @staticmethod
    async def pause_agent(project_id: str, target_id: str):
        """Signals the stop_event of every agent run currently live under
        this target's pipeline - one, in single_agent mode, but genuinely
        several once a multi_agent pipeline can have concurrent sub-runs in
        flight: pausing the whole pipeline must stop all of them, not just
        whichever one a caller happened to know about. See
        run_registry.live_runs_for_target's own comment for why this index
        exists."""
        AgentService._get_owned_target(project_id, target_id)
        run_registry.stop_all_for_target(target_id)

    @staticmethod
    async def finish_agent(project_id: str, target_id: str):
        """Ends the run outright (FINISHED, not resumable), as opposed to
        pause_agent's PAUSED/resumable stop. Reachable from two distinct
        states, handled differently since only one of them has anything
        actually running:
        - RUNNING: signal the active loop's stop_event, same as pause_agent,
          but flagged so the post-loop status decision resolves to FINISHED
          instead of PAUSED. Only effective while the agent is actually in
          its main loop - a run parked in pending_interrupts (awaiting
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
        pipeline (see pause_agent's own comment on
        run_registry.live_runs_for_target) - one, in single_agent mode,
        but genuinely several once a multi_agent pipeline can have
        concurrent sub-runs in flight."""
        AgentService._get_owned_target(project_id, target_id)

        live_run_ids = list(run_registry.live_runs_for_target.get(target_id, ()))
        any_signaled = False
        for agent_run_id in live_run_ids:
            stop_event = run_registry.stop_events.get(agent_run_id)
            if stop_event is not None:
                # Must be recorded before stop_event.set() - _run_agent's
                # post-loop status decision reads this once the loop wakes
                # up and exhausts, immediately after the event fires.
                run_registry.finish_intents[agent_run_id] = True
                stop_event.set()
                any_signaled = True

        if any_signaled:
            return

        project_settings = db_manager.get_project_settings(project_id)
        role = "orchestrator" if project_settings.pipeline_mode == "multi_agent" else "single_agent"
        existing_run = db_manager.get_agent_run(target_id, role=role)
        if existing_run is not None and existing_run.status == AgentRunState.PAUSED:
            # agent_run_id/role must be passed through for Multi Agent mode -
            # persist_run_state defaults to upsert_agent_run's (target_id,
            # role="single_agent") lookup otherwise, which would miss this
            # orchestrator row entirely (or silently flip an unrelated
            # single_agent row instead), leaving the real paused run as
            # PAUSED forever.
            await run_registry.persist_run_state(
                project_id=project_id,
                target_id=target_id,
                status=AgentRunState.FINISHED,
                remaining_seconds=0,
                agent_run_id=str(existing_run.id),
                role=role,
            )

    @staticmethod
    def get_run(project_id: str, target_id: str) -> Optional[AgentRun]:
        AgentService._get_owned_target(project_id, target_id)

        project_settings = db_manager.get_project_settings(project_id)
        role = "orchestrator" if project_settings.pipeline_mode == "multi_agent" else "single_agent"
        return db_manager.get_agent_run(target_id, role=role)

    @staticmethod
    def get_pending_interrupt(project_id: str, target_id: str) -> Optional[List[dict]]:
        """The tool_calls of the interrupt currently awaiting approval for
        target_id, or None if there isn't one - lets a client that reloaded
        mid-approval (and so missed the one-shot AgentInterruptRequest
        websocket push) recover the dialog's contents instead of being
        stuck with a run stuck as INTERRUPTED and nothing to approve/deny.

        Single Agent mode's agent_run_id always equals target_id, so the
        direct lookup below is exact. Multi Agent mode has no single run_id
        equal to target_id - falls back to the first pending interrupt
        found among every run currently live under this target's pipeline
        (the orchestrator itself never raises one, but any
        scouting/pentesting sub-run it spawned might). Only ever surfaces
        ONE at a time even if several sub-runs happen to be interrupted
        together - kept only for Single Agent mode's existing clients
        (which only ever have one to find anyway); see get_pending_interrupts
        for the plural version a Multi Agent client should actually use."""
        AgentService._get_owned_target(project_id, target_id)

        direct = run_registry.pending_interrupt_tool_calls.get(target_id)
        if direct is not None:
            return direct

        for agent_run_id in run_registry.live_runs_for_target.get(target_id, ()):
            pending = run_registry.pending_interrupt_tool_calls.get(agent_run_id)
            if pending is not None:
                return pending
        return None

    @staticmethod
    def get_pending_interrupts(project_id: str, target_id: str) -> List[dict]:
        """Every pending interrupt currently live under this target's
        pipeline, each tagged with the real agent_run_id that raised it -
        the plural counterpart to get_pending_interrupt's single best-
        effort pick, for a Multi Agent client that can show/let a human
        approve more than one sub-run's interrupt at a time (e.g. two
        concurrent pentesting sub-runs each waiting on their own
        request_port_access approval)."""
        AgentService._get_owned_target(project_id, target_id)

        entries: List[dict] = []
        seen = set()

        direct = run_registry.pending_interrupt_tool_calls.get(target_id)
        if direct is not None:
            entries.append({"agent_run_id": target_id, "tool_calls": direct})
            seen.add(target_id)

        for agent_run_id in run_registry.live_runs_for_target.get(target_id, ()):
            if agent_run_id in seen:
                continue
            pending = run_registry.pending_interrupt_tool_calls.get(agent_run_id)
            if pending is not None:
                entries.append({"agent_run_id": agent_run_id, "tool_calls": pending})

        return entries

    @staticmethod
    def get_attack_vectors(project_id: str, target_id: str) -> List[AttackVector]:
        AgentService._get_owned_target(project_id, target_id)
        return db_manager.get_attack_vectors_for_target(target_id)

    @staticmethod
    def get_run_tree(project_id: str, target_id: str) -> List[AgentRun]:
        """Every AgentRun under this target's pipeline (every role, not
        just the root) - for a Multi Agent client to group logs by run,
        same as Single Agent mode's one-row equivalent from get_run."""
        AgentService._get_owned_target(project_id, target_id)
        return db_manager.get_agent_runs_for_target(target_id)

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
        # comment) - every run_registry dict therefore keeps behaving
        # exactly as it did when it was keyed by target_id, for every call
        # site that still only knows about target_id (pause_agent,
        # get_pending_interrupt, the websocket interrupt-response hook, ...).
        # A multi_agent pipeline's sub-runs have genuinely distinct,
        # database-backed ids here instead (see run_registry.start_sub_run).
        agent_run_id = agent.agent_run_id
        # Hardcoded for now - every caller of _run_agent today is the
        # single_agent flow.
        role = "single_agent"

        stop_event = asyncio.Event()
        run_state: dict = {}
        slot_acquired = False

        try:
            # Registration/initial persistence moved inside this try (was
            # previously before it) - a failure in _set_running/
            # persist_run_state here used to propagate uncaught out of
            # _run_agent with no wrapping try/except, skipping the finally
            # block below entirely and leaving _running_targets[target_id]
            # (already claimed in start_agent, before this task was even
            # scheduled) permanently stuck - every subsequent start_agent()
            # call for that target would then raise
            # AgentAlreadyRunningException with no recovery short of a
            # backend restart.
            run_registry.stop_events[agent_run_id] = stop_event
            run_registry.run_states[agent_run_id] = run_state
            run_registry.live_runs_for_target.setdefault(target_id, set()).add(agent_run_id)

            # Blocks here, potentially for a while, if this project (or the
            # whole backend) is already at its concurrent-agent ceiling -
            # see run_registry.acquire_agent_slot. Deliberately AFTER the
            # registration above (so a pause/finish request issued while
            # still queued for a slot can still flip finish_intents/set
            # stop_event - the loop below simply never got to check them
            # yet) but BEFORE _set_running/persist_run_state (a run that's
            # still waiting for a slot hasn't actually started yet, so it
            # shouldn't claim to be RUNNING until it is).
            await run_registry.acquire_agent_slot(
                project_id, project_settings.max_concurrent_agents
            )
            slot_acquired = True

            await _set_running(project_id, target_id, True)
            await run_registry.persist_run_state(
                project_id=project_id,
                target_id=target_id,
                status=AgentRunState.RUNNING,
                remaining_seconds=duration_seconds,
            )

            await run_registry.persist_and_broadcast(
                project_id=project_id,
                target_id=target_id,
                log_type="action",
                content=f"Starting analysis on target: {target.name}",
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
                            agent_run_id=agent_run_id,
                            role=role,
                        )
                    )
                    continue

                if isinstance(event, dict):
                    # AgentInterruptAction - pause and wait for approval
                    run_registry.pending_interrupts[agent_run_id] = event["accept"]
                    tool_calls = [
                        {"name": tc["name"], "args": tc["args"]}
                        for tc in event["tool_calls"]
                    ]
                    run_registry.pending_interrupt_tool_calls[agent_run_id] = tool_calls

                    await run_registry.persist_run_state(
                        project_id=project_id,
                        target_id=target_id,
                        status=AgentRunState.INTERRUPTED,
                        remaining_seconds=run_state.get("time_left", 0),
                    )

                    await ws_registry.send_message(
                        AgentInterruptRequest(
                            type=WsTypes.AgentInterruptRequest,
                            project_id=project_id,
                            target_id=target_id,
                            tool_calls=tool_calls,
                            agent_run_id=agent_run_id,
                        )
                    )
                    continue

                for log_type, content, tool_name, raw_output in run_registry.message_to_log_specs(
                    event
                ):
                    # Log content is shown as-is now, no summarization pass -
                    # in testing, running the agent's own deliberate
                    # reasoning (from the two-phase _call_model split) back
                    # through a separate parsing model degraded it rather
                    # than clarified it. Kali command output is already
                    # condensed by the parsing model inside the tool itself
                    # (see agent_tools.py) before it ever reaches here.

                    await run_registry.persist_and_broadcast(
                        project_id=project_id,
                        target_id=target_id,
                        log_type=log_type,
                        content=content,
                        tool_name=tool_name,
                        raw_output=raw_output,
                        agent_run_id=agent_run_id,
                        role=role,
                    )

            if agent.finish_summary:
                await run_registry.persist_and_broadcast(
                    project_id=project_id,
                    target_id=target_id,
                    log_type="action",
                    content=f"Agent finished the task: {agent.finish_summary}",
                    agent_run_id=agent_run_id,
                    role=role,
                )

            # The generator exhausted normally - either the user paused it,
            # the user held the button to finish it outright, the agent
            # decided it was done (finish_summary is set), or it genuinely
            # ran out of time. finish_agent() takes priority over the plain
            # stop_event check below - a held-to-finish stop must never be
            # reclassified as PAUSED (which would make it resumable).
            finished_by_request = run_registry.finish_intents.pop(agent_run_id, False)
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
            await run_registry.persist_run_state(
                project_id=project_id,
                target_id=target_id,
                status=final_status,
                remaining_seconds=final_remaining,
            )
        except Exception as e:
            print(f"Agent run failed for target {target_id}: {e}")
            await run_registry.persist_and_broadcast(
                project_id=project_id,
                target_id=target_id,
                log_type="action",
                content=f"Agent run failed: {e}",
                agent_run_id=agent_run_id,
                role=role,
            )
            # FAILED (not FINISHED) so a crash is distinguishable in the UI
            # from a run that completed/paused/ran out of time normally,
            # and the real time_left already tracked in run_state (not a
            # hardcoded 0) - run_state defaults to {} if the failure
            # happened before the agent loop itself ever started, so
            # .get(...) still falls back to 0 sensibly in that case.
            await run_registry.persist_run_state(
                project_id=project_id,
                target_id=target_id,
                status=AgentRunState.FAILED,
                remaining_seconds=run_state.get("time_left", 0),
            )
        finally:
            manager = await kali_registry.get_manager_if_exists(project_id)
            if manager is not None:
                # Scoped to just THIS run's own sessions, not every session
                # on the target - close_sessions_for_target would tear down
                # a sibling agent's sessions too, once more than one can be
                # live on the same target at once. Harmless no-op
                # difference for single_agent mode today, where this run is
                # always the only one.
                await manager.close_sessions_for_run(target_id, agent_run_id)

            run_registry.cleanup_sub_run(target_id, agent_run_id)
            if slot_acquired:
                await run_registry.release_agent_slot(project_id)
            await _set_running(project_id, target_id, False)

    @staticmethod
    async def _run_orchestrator(
        orchestrator: OrchestratorAgent,
        target: Target,
        project_settings: ProjectSettings,
        duration_seconds: int,
    ):
        """Multi Agent mode's equivalent of _run_agent - same registration/
        slot/status-persistence shape, adapted to OrchestratorAgent's own
        event stream and run identity. Two deliberate differences from
        _run_agent, beyond the obvious (role="orchestrator", a real
        agent_run_id instead of target_id, and OrchestratorAgent.start_agent's
        own narrower signature - no `target`/`should_interrupt`, since it
        never touches the target itself and so never needs interrupt
        approval at its own level):

        1. No acquire_agent_slot/release_agent_slot here at all. The
           concurrency cap bounds actual WORKER model calls (scouting/
           pentesting/reporting, each acquiring their own slot inside
           orchestrator_tools.py), not the orchestrator's own - its own LLM
           call always happens strictly BEFORE/AFTER a blocking tool call
           that spawns those workers, never AT THE SAME TIME as them
           (LangGraph's agent->tools->agent step is sequential, not
           concurrent). Acquiring a slot for the orchestrator's own run
           here too would deadlock the moment max_concurrent_agents=1 -
           the orchestrator would hold the only slot for its entire
           lifetime, leaving none free for the very sub-agents it's
           waiting on.
        2. No per-message persist_and_broadcast loop reading the
           orchestrator's sub-agents' own messages - those are already
           fully persisted/broadcast by orchestrator_tools.py's own
           _drain_sub_agent, synchronously, before the tool call that
           spawned them even returns. This loop only ever sees the
           orchestrator's OWN messages (role="orchestrator")."""
        project_id = str(target.project_id)
        target_id = str(target.id)
        agent_run_id = orchestrator.agent_run_id
        role = "orchestrator"

        stop_event = asyncio.Event()
        run_state: dict = {}

        try:
            run_registry.stop_events[agent_run_id] = stop_event
            run_registry.run_states[agent_run_id] = run_state
            run_registry.live_runs_for_target.setdefault(target_id, set()).add(agent_run_id)

            await _set_running(project_id, target_id, True)
            await run_registry.persist_run_state(
                project_id=project_id,
                target_id=target_id,
                status=AgentRunState.RUNNING,
                remaining_seconds=duration_seconds,
                agent_run_id=agent_run_id,
                role=role,
            )

            await run_registry.persist_and_broadcast(
                project_id=project_id,
                target_id=target_id,
                log_type="action",
                content=f"Starting multi-agent pipeline on target: {target.name}",
                agent_run_id=agent_run_id,
                role=role,
            )

            prompt_template = (
                project_settings.orchestrator_starting_prompt or ""
            ).strip() or default_orchestrator_prompt
            rendered_prompt = roles_common.render_target_prompt(prompt_template, target)

            async for event in orchestrator.start_agent(
                start_prompt=rendered_prompt,
                thread_id=f"{target_id}:{agent_run_id}",
                stop_event=stop_event,
                duration_seconds=duration_seconds,
                run_state=run_state,
                run_mode=target.run_mode,
                safety_cap=target.safety_cap_duration,
            ):
                if isinstance(event, dict) and event.get("kind") == "context_usage":
                    await ws_registry.send_message(
                        AgentContextUsage(
                            type=WsTypes.AgentContextUsage,
                            project_id=project_id,
                            target_id=target_id,
                            used_tokens=event["used_tokens"],
                            context_window=event["context_window"],
                            agent_run_id=agent_run_id,
                            role=role,
                        )
                    )
                    continue

                if isinstance(event, dict):
                    # OrchestratorAgent.start_agent's own requires_interrupt
                    # always returns False (see its own docstring) - this
                    # shape never actually occurs, kept only so an
                    # unexpected dict here can't crash this loop.
                    continue

                for log_type, content, tool_name, raw_output in run_registry.message_to_log_specs(
                    event
                ):
                    await run_registry.persist_and_broadcast(
                        project_id=project_id,
                        target_id=target_id,
                        log_type=log_type,
                        content=content,
                        tool_name=tool_name,
                        raw_output=raw_output,
                        agent_run_id=agent_run_id,
                        role=role,
                    )

            finished_by_request = run_registry.finish_intents.pop(agent_run_id, False)
            final_status = (
                AgentRunState.FINISHED
                if finished_by_request
                else (
                    AgentRunState.PAUSED if stop_event.is_set() else AgentRunState.FINISHED
                )
            )
            final_remaining = 0 if finished_by_request else run_state.get("time_left", 0)
            await run_registry.persist_run_state(
                project_id=project_id,
                target_id=target_id,
                status=final_status,
                remaining_seconds=final_remaining,
                agent_run_id=agent_run_id,
                role=role,
            )
        except Exception as e:
            print(f"Orchestrator run failed for target {target_id}: {e}")
            await run_registry.persist_and_broadcast(
                project_id=project_id,
                target_id=target_id,
                log_type="action",
                content=f"Multi-agent pipeline failed: {e}",
                agent_run_id=agent_run_id,
                role=role,
            )
            await run_registry.persist_run_state(
                project_id=project_id,
                target_id=target_id,
                status=AgentRunState.FAILED,
                remaining_seconds=run_state.get("time_left", 0),
                agent_run_id=agent_run_id,
                role=role,
            )
        finally:
            # The orchestrator itself never opens a Kali session (it never
            # touches the target - see OrchestratorAgent's own docstring),
            # so this is a harmless no-op for its own agent_run_id; any
            # sub-agent it spawned already closed its own sessions inside
            # orchestrator_tools.py's own run_one/request_report bodies.
            run_registry.cleanup_sub_run(target_id, agent_run_id)
            await _set_running(project_id, target_id, False)
