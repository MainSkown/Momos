"""Orchestrator role's own NEW tool implementations - run_scouting,
dispatch_pentest_batch, request_report, request_tool_access - the only
four tools this role has (see the tool matrix in the implementation
plan). No target-touching tool at all: the orchestrator never acts on the
target directly, only through the scouting/pentesting/reporting
sub-agents each of these spawns and awaits via run_registry's own
concurrency/run-lifecycle primitives (core/agent/run_registry.py) - never
polled, each tool call blocks until its sub-agent(s) are completely done
and returns their real result as the tool's own return value for the
orchestrator's next turn.

Each sub-agent's own interrupt requests (e.g. request_port_access) surface
through the exact same run_registry.pending_interrupts/
pending_interrupt_tool_calls registry the Single Agent flow already uses -
keyed by that sub-run's own agent_run_id, which is already a real AgentRun.id
(see run_registry.start_sub_run's own docstring), so the existing websocket
approval plumbing needs no role-specific case to resolve one."""

import asyncio
from typing import Callable, Dict, List, Optional
from langchain_core.tools import tool
from src.core import db_manager, tool_groups
from src.core.agent import agent_checkpointer, run_registry
from src.core.agent.roles import common
from src.core.kali_integration import kali_registry
from src.schemas.agent_run_scheme import AgentRunState
from src.schemas.attack_vector_scheme import AttackVectorStatus
from src.schemas.project_scheme import (
    pentesting_starting_prompt as default_pentesting_prompt,
    reporting_starting_prompt as default_reporting_prompt,
    scouting_starting_prompt as default_scouting_prompt,
)
from src.websocket import ws_registry, WsTypes, AgentInterruptRequest, AgentContextUsage

RUN_SCOUTING_TOOL_NAME = "run_scouting"
DISPATCH_PENTEST_BATCH_TOOL_NAME = "dispatch_pentest_batch"
REQUEST_REPORT_TOOL_NAME = "request_report"
REQUEST_TOOL_ACCESS_TOOL_NAME = "request_tool_access"

# dispatch_pentest_batch (and, less critically, run_scouting) write new
# AttackVector rows and move existing ones to "testing" - request_report
# READS an AttackVector's status/assigned_run_id to decide whether there's
# anything to report. Calling dispatch and request together in the same
# turn for the same vector would be a genuine ordering hazard (reporting a
# vector that's simultaneously still being tested) - see
# roles/common.py's make_guarded_tools_node docstring for why the whole
# turn is rejected outright rather than trying to out-time it.
# request_tool_access also writes to the same AttackVector row
# (extra_tool_groups) - treated as a writer for the exact same reason.
WRITER_TOOL_NAMES = {
    RUN_SCOUTING_TOOL_NAME,
    DISPATCH_PENTEST_BATCH_TOOL_NAME,
    REQUEST_TOOL_ACCESS_TOOL_NAME,
}
READER_TOOL_NAMES = {REQUEST_REPORT_TOOL_NAME}
# run_scouting/dispatch_pentest_batch/request_report never touch the
# target directly (see this module's own docstring) - only the sub-agents
# they spawn do, and each of those surfaces its OWN interrupt need through
# its own agent_run_id, independent of the orchestrator's turn. Nothing
# there ever needs human approval at the orchestrator's level.
#
# request_tool_access is the one exception: it is itself the approval
# gate for letting a vector exceed the project's own enabled_tools
# ceiling, so it always pauses regardless of should_interrupt - see its
# own factory function below.
INTERRUPT_GATED_TOOL_NAMES: set = set()
ALWAYS_INTERRUPT_TOOL_NAMES: set = {REQUEST_TOOL_ACCESS_TOOL_NAME}


def _project_enabled_group_ids(project_settings) -> set:
    """The project's own tool_groups ceiling, as a set of group ids - None
    means every default_enabled group (mirrors tool_groups.tool_names_for's
    own None-handling, but at the group-id level instead of the raw
    tool-name level, since this module works with the ids an orchestrator
    picks per-vector, not raw tool names)."""
    if project_settings.enabled_tools is None:
        return {g.id for g in tool_groups.TOOL_GROUPS if g.default_enabled}
    return set(project_settings.enabled_tools)


async def _drain_sub_agent(
    agent_events,
    project_id: str,
    target_id: str,
    agent_run_id: str,
    role: str,
    parent_run_id: Optional[str] = None,
    attack_vector_id: Optional[str] = None,
) -> None:
    """Shared consumption loop for every sub-agent this role spawns -
    persists/broadcasts every real message exactly like agent_service.py's
    own _run_agent does for the Single Agent flow, and - on an interrupt -
    registers it into run_registry's shared registry AND pushes a real
    AgentInterruptRequest over the websocket (tagged with this sub-run's
    own agent_run_id, resolved by whatever already answers the Single
    Agent flow's own pending-interrupt messages) instead of auto-approving
    or silently dropping it. `parent_run_id`/`attack_vector_id` are passed
    through to every persist_run_state call this makes for the same reason
    its callers must also pass them to their OWN persist_run_state calls -
    see this module's run_one/request_report, whose own comment on
    save_agent_run explains why omitting them would silently wipe them
    back to None on the very next status update for this row."""
    async for event in agent_events:
        if isinstance(event, dict):
            if event.get("kind") == "context_usage":
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
            if event.get("kind") == "interrupt":
                run_registry.pending_interrupts[agent_run_id] = event["accept"]
                tool_calls = [
                    {"name": tc["name"], "args": tc["args"]} for tc in event["tool_calls"]
                ]
                run_registry.pending_interrupt_tool_calls[agent_run_id] = tool_calls

                await run_registry.persist_run_state(
                    project_id=project_id,
                    target_id=target_id,
                    status=AgentRunState.INTERRUPTED,
                    remaining_seconds=0,
                    agent_run_id=agent_run_id,
                    role=role,
                    parent_run_id=parent_run_id,
                    attack_vector_id=attack_vector_id,
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
        for log_type, content, tool_name, raw_output in run_registry.message_to_log_specs(event):
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


def create_run_scouting_tool(
    project_id: str,
    target_id: str,
    orchestrator_run_id: str,
    should_interrupt: bool,
    on_scouting_done: Callable[[], None],
):
    @tool(RUN_SCOUTING_TOOL_NAME)
    async def run_scouting() -> str:
        """Runs the scouting sub-agent once against this target - full
        enumeration, then a batch of candidate attack vectors proposed.
        Call this once before dispatching any pentesting; calling it again
        later just re-enumerates (harmless, but wasteful - prefer
        dispatching against what it already found)."""
        from src.core.agent.roles.agents import scouting_agent as scouting_mod

        loop = asyncio.get_running_loop()
        target = await loop.run_in_executor(None, db_manager.get_target, target_id)
        project_settings = await loop.run_in_executor(None, db_manager.get_project_settings, project_id)

        model_name = project_settings.scouting_model_name or project_settings.base_model_name
        reasoning, context_window = await common.resolve_model_capabilities(
            model_name, project_settings.max_context_window
        )

        run = await run_registry.start_sub_run(
            project_id=project_id, target_id=target_id, role="scouting", parent_run_id=orchestrator_run_id
        )
        agent_run_id = str(run.id)
        stop_event = asyncio.Event()
        run_registry.stop_events[agent_run_id] = stop_event

        try:
            agent = scouting_mod.ScoutingAgent(
                model_name=model_name,
                checkpointer=agent_checkpointer.checkpointer,
                project_id=project_id,
                target_id=target_id,
                agent_run_id=agent_run_id,
                reasoning=reasoning,
                context_window=context_window,
                allow_shell=project_settings.allow_shell,
                allow_install_packages=project_settings.allow_install_packages,
                enabled_tools=project_settings.enabled_tools,
            )
            prompt_template = (
                project_settings.scouting_starting_prompt or ""
            ).strip() or default_scouting_prompt
            rendered_prompt = common.render_target_prompt(prompt_template, target)

            await _drain_sub_agent(
                agent.start_agent(
                    target=target,
                    start_prompt=rendered_prompt,
                    thread_id=f"{target_id}:{agent_run_id}",
                    should_interrupt=should_interrupt,
                    stop_event=stop_event,
                ),
                project_id,
                target_id,
                agent_run_id,
                "scouting",
                parent_run_id=orchestrator_run_id,
            )
        finally:
            manager = await kali_registry.get_manager_if_exists(project_id)
            if manager is not None:
                # Scoped to just THIS sub-run's own sessions, not every
                # session on the target - close_sessions_for_target would
                # tear down a sibling sub-agent's sessions too, once more
                # than one can be live on the same target at once (mirrors
                # agent_service.py's own _run_agent cleanup).
                await manager.close_sessions_for_run(target_id, agent_run_id)

            await run_registry.persist_run_state(
                project_id=project_id,
                target_id=target_id,
                status=AgentRunState.FINISHED,
                remaining_seconds=0,
                agent_run_id=agent_run_id,
                role="scouting",
                parent_run_id=orchestrator_run_id,
            )
            run_registry.cleanup_sub_run(target_id, agent_run_id)

        on_scouting_done()

        vectors = await loop.run_in_executor(None, db_manager.get_attack_vectors_for_target, target_id)
        pending_count = sum(1 for v in vectors if v.status == AttackVectorStatus.PENDING)
        return (
            f"Scouting finished: {agent.finish_summary or '(no summary given)'} "
            f"{pending_count} attack vector(s) now pending."
        )

    return run_scouting


def create_dispatch_pentest_batch_tool(
    project_id: str,
    target_id: str,
    orchestrator_run_id: str,
    should_interrupt: bool,
):
    # Captured here, before the inner tool function's own `tool_groups`
    # parameter exists - that parameter name is fixed by the tool's public
    # signature (the orchestrator LLM calls it by that name) and would
    # shadow the `src.core.tool_groups` module import for every reference
    # inside dispatch_pentest_batch/run_one, so the frozenset is pulled out
    # under its own name here instead of referencing the module directly
    # down there.
    valid_tool_group_ids = tool_groups.TOOL_GROUP_IDS

    @tool(DISPATCH_PENTEST_BATCH_TOOL_NAME)
    async def dispatch_pentest_batch(
        vector_ids: List[str], tool_groups: Optional[Dict[str, List[str]]] = None
    ) -> str:
        """Spawns one pentesting sub-agent per vector id given, runs them
        CONCURRENTLY (bounded by this project's max_concurrent_agents -
        pass as many ids as you judge reasonable to run together, the
        bound is enforced for you), waits for every one of them to finish,
        and returns each one's final outcome. Only pass ids of currently
        "pending" attack vectors from the list shown to you each turn.

        Args:
            vector_ids: One or more pending AttackVector ids to test now.
            tool_groups: Optional, keyed by vector id. Each value is a list
                of tool_groups ids (e.g. "ftp", "sqlmap") to narrow that
                vector's dispatch to - a vector id omitted from this dict
                keeps the project's own full enabled_tools. This can only
                NARROW what a vector gets, never expand it beyond the
                project's own settings - for that, call
                request_tool_access first. An unknown group id anywhere in
                this dict rejects that one vector's dispatch (others in the
                same call are unaffected).
        """
        from src.core.agent.roles.agents import pentesting_agent as pentesting_mod

        loop = asyncio.get_running_loop()
        target = await loop.run_in_executor(None, db_manager.get_target, target_id)
        project_settings = await loop.run_in_executor(None, db_manager.get_project_settings, project_id)
        max_concurrent_agents = project_settings.max_concurrent_agents
        model_name = project_settings.pentesting_model_name or project_settings.base_model_name
        prompt_template = (
            project_settings.pentesting_starting_prompt or ""
        ).strip() or default_pentesting_prompt

        project_default_ids = _project_enabled_group_ids(project_settings)
        requested_tool_groups = tool_groups or {}

        async def run_one(vector_id: str) -> str:
            vector = await loop.run_in_executor(None, db_manager.get_attack_vector, vector_id)
            if vector is None or str(vector.target_id) != str(target_id):
                return f"{vector_id}: not found - skipped."
            # TESTING is also accepted, not just PENDING - a genuinely
            # live pentesting sub-run can never appear here in the first
            # place (dispatch_pentest_batch always blocks until every
            # sub-agent it spawned is fully done before returning control
            # to the orchestrator's next turn), so a vector sitting at
            # TESTING when a NEW dispatch decision is being made is, by
            # construction, abandoned - e.g. from a pipeline paused or
            # interrupted mid-batch on a previous run. Re-dispatching it is
            # exactly the resume behavior the implementation plan calls
            # for ("any AttackVector left at status=testing with no live
            # run is treated the same as pending by the next dispatch
            # decision").
            if vector.status not in (AttackVectorStatus.PENDING, AttackVectorStatus.TESTING):
                return f"{vector_id}: not pending/testing (status={vector.status}) - skipped."

            # tool_groups only ever NARROWS the project's own ceiling - an
            # id this project doesn't enable at all is dropped, never
            # added (effective_ids below). The only way to actually exceed
            # project_default_ids is vector.extra_tool_groups, which only
            # request_tool_access is ever allowed to write to.
            requested = requested_tool_groups.get(vector_id)
            note = ""
            if requested is None:
                narrowed = project_default_ids
            else:
                unknown = [g for g in requested if g not in valid_tool_group_ids]
                if unknown:
                    # Rejected immediately - must not raise, since every
                    # vector in this batch runs concurrently under
                    # asyncio.gather and one bad id must never cancel or
                    # otherwise affect its siblings.
                    return (
                        f"{vector_id}: unknown tool group '{unknown[0]}' in "
                        "tool_groups - dispatch rejected."
                    )
                requested_ids = set(requested)
                narrowed = requested_ids & project_default_ids
                dropped = sorted(requested_ids - project_default_ids)
                if dropped:
                    note += " (note: " + ", ".join(
                        f"'{d}' not enabled for this project, ignored" for d in dropped
                    ) + ")"

            vector_extra_ids = set(vector.extra_tool_groups or [])
            effective_ids = narrowed | vector_extra_ids
            approved_extra = sorted(vector_extra_ids - narrowed)
            if approved_extra:
                note += (
                    f" (approved extra tool group(s) in use: {', '.join(approved_extra)})"
                )

            await run_registry.acquire_agent_slot(project_id, max_concurrent_agents)
            agent_run_id = None
            agent = None
            error: Optional[Exception] = None
            try:
                run = await run_registry.start_sub_run(
                    project_id=project_id,
                    target_id=target_id,
                    role="pentesting",
                    parent_run_id=orchestrator_run_id,
                    attack_vector_id=vector_id,
                )
                agent_run_id = str(run.id)
                vector.status = AttackVectorStatus.TESTING
                vector.assigned_run_id = run.id
                vector = await loop.run_in_executor(None, db_manager.update_attack_vector, vector)
                await run_registry.broadcast_attack_vector(vector)

                stop_event = asyncio.Event()
                run_registry.stop_events[agent_run_id] = stop_event

                reasoning, context_window = await common.resolve_model_capabilities(
                    model_name, project_settings.max_context_window
                )
                agent = pentesting_mod.PentestingAgent(
                    model_name=model_name,
                    checkpointer=agent_checkpointer.checkpointer,
                    project_id=project_id,
                    target_id=target_id,
                    agent_run_id=agent_run_id,
                    attack_vector_id=vector_id,
                    attack_vector_description=vector.description,
                    reasoning=reasoning,
                    context_window=context_window,
                    allow_shell=project_settings.allow_shell,
                    allow_install_packages=project_settings.allow_install_packages,
                    enabled_tools=sorted(effective_ids),
                )
                rendered_prompt = common.render_target_prompt(
                    prompt_template, target, attack_vector=vector.description
                )
                await _drain_sub_agent(
                    agent.start_agent(
                        target=target,
                        start_prompt=rendered_prompt,
                        thread_id=f"{target_id}:{agent_run_id}",
                        should_interrupt=should_interrupt,
                        stop_event=stop_event,
                    ),
                    project_id,
                    target_id,
                    agent_run_id,
                    "pentesting",
                    parent_run_id=orchestrator_run_id,
                    attack_vector_id=vector_id,
                )
            except Exception as e:
                # Caught here (not left to propagate out of run_one) so one
                # sub-agent's unexpected failure can't abandon its slot/run-
                # state cleanup below, or (since several of these run
                # concurrently under asyncio.gather) leave siblings running
                # un-awaited if this coroutine were torn down by an
                # uncaught exception instead.
                print(f"dispatch_pentest_batch: pentesting sub-run for {vector_id} failed: {e}")
                error = e
            finally:
                # persist_run_state/cleanup_sub_run are wrapped in their
                # own try/except (log and continue), NOT allowed to
                # propagate out of this finally - release_agent_slot right
                # below is this finally block's own responsibility to
                # guarantee, and a persistence failure must never be able
                # to skip it and leak the slot acquire_agent_slot already
                # granted above.
                if agent_run_id is not None:
                    try:
                        manager = await kali_registry.get_manager_if_exists(project_id)
                        if manager is not None:
                            # Scoped to just THIS sub-run's own sessions, not
                            # every session on the target - close_sessions_for_target
                            # would tear down a sibling sub-agent's sessions too,
                            # once more than one can be live on the same target at
                            # once (mirrors agent_service.py's own _run_agent
                            # cleanup).
                            await manager.close_sessions_for_run(target_id, agent_run_id)

                        await run_registry.persist_run_state(
                            project_id=project_id,
                            target_id=target_id,
                            status=AgentRunState.FINISHED,
                            remaining_seconds=0,
                            agent_run_id=agent_run_id,
                            role="pentesting",
                            parent_run_id=orchestrator_run_id,
                            attack_vector_id=vector_id,
                        )
                        run_registry.cleanup_sub_run(target_id, agent_run_id)
                    except Exception as persist_error:
                        print(
                            "dispatch_pentest_batch: failed to persist/"
                            f"clean up run state for {agent_run_id}: {persist_error}"
                        )
                await run_registry.release_agent_slot(project_id)

            if error is not None:
                return f"{vector_id}: pentesting sub-run failed before reporting an outcome: {error}"

            refreshed = await loop.run_in_executor(None, db_manager.get_attack_vector, vector_id)
            outcome = agent.outcome or {}
            summary = outcome.get("summary") or agent.finish_summary or "(no outcome reported)"
            return f"{vector_id} [{refreshed.status}]: {summary}{note}"

        # dict.fromkeys preserves first-seen order while dropping repeats -
        # the same id listed twice in one batch must dispatch exactly one
        # sub-agent for it, not two concurrent ones racing to flip the same
        # vector PENDING->TESTING.
        unique_vector_ids = list(dict.fromkeys(vector_ids))
        results = await asyncio.gather(*(run_one(vid) for vid in unique_vector_ids))
        return "\n".join(results)

    return dispatch_pentest_batch


def create_request_tool_access_tool(project_id: str, target_id: str):
    """Builds request_tool_access, bound to a specific project/target. The
    only sanctioned way for a dispatched pentesting sub-agent to use a
    tool group beyond what this project's own enabled_tools would
    otherwise allow, scoped to exactly one AttackVector via its
    extra_tool_groups (see dispatch_pentest_batch's own narrowing/clamp
    logic above - the two are two halves of the same mechanism and must
    agree on what "allowed" means).

    Deliberately NOT an automated grant, same rationale as
    create_request_port_access_tool: this always pauses for human approval
    (see this module's own ALWAYS_INTERRUPT_TOOL_NAMES, independent of
    this project's should_interrupt setting) rather than letting the
    orchestrator unilaterally expand what a vector can do. On denial,
    LangGraph's existing rejection path means this function's body never
    runs at all."""

    @tool(REQUEST_TOOL_ACCESS_TOOL_NAME)
    async def request_tool_access(vector_id: str, tool_group: str, reason: str) -> str:
        """Asks a human operator for permission to let a specific attack
        vector's future pentesting dispatches use a tool group beyond what
        this project's own settings normally allow. This ALWAYS pauses for
        human approval, regardless of this project's approval setting -
        call it BEFORE dispatching a vector whose description names a tool
        you don't currently have. Approval is scoped to this one vector
        only and persists across redispatches - it never changes the
        project's own settings.

        Args:
            vector_id: The AttackVector id this approval applies to.
            tool_group: A tool_groups id (e.g. "sqlmap", "metasploit") -
                must be a real, known id.
            reason: A short, concrete justification - what the vector's
                description suggests is needed and why.
        """
        if tool_group not in tool_groups.TOOL_GROUP_IDS:
            return f"'{tool_group}' is not a known tool group - nothing changed."

        loop = asyncio.get_running_loop()
        vector = await loop.run_in_executor(None, db_manager.get_attack_vector, vector_id)
        if vector is None or str(vector.target_id) != str(target_id):
            return f"{vector_id}: not found."

        project_settings = await loop.run_in_executor(None, db_manager.get_project_settings, project_id)
        already_allowed = _project_enabled_group_ids(project_settings) | set(vector.extra_tool_groups or [])
        if tool_group in already_allowed:
            return f"'{tool_group}' is already available for {vector_id} - no change needed."

        # By the time this line runs, a human has already approved the
        # request (see this module's own ALWAYS_INTERRUPT_TOOL_NAMES) -
        # LangGraph's rejection path on denial means this function body
        # never runs at all, same as request_port_access.
        new_extra = sorted(set(vector.extra_tool_groups or []) | {tool_group})
        vector.extra_tool_groups = new_extra
        vector = await loop.run_in_executor(None, db_manager.update_attack_vector, vector)
        await run_registry.broadcast_attack_vector(vector)

        return (
            f"Approved - '{tool_group}' is now available for {vector_id} "
            f"(reason: {reason}). This vector's extra tool groups: {', '.join(new_extra)}."
        )

    return request_tool_access


def create_request_report_tool(project_id: str, target_id: str, orchestrator_run_id: str):
    @tool(REQUEST_REPORT_TOOL_NAME)
    async def request_report(vector_id: str) -> str:
        """Spawns the reporting sub-agent for one vector that tested
        vulnerable, writing a real Vulnerability record (with a precise
        CVSS v4.0 vector) from that pentesting run's own full, real
        transcript - never from this role's own paraphrase. Only call this
        for a vector whose status is "tested_vulnerable" and that hasn't
        already been reported.

        Args:
            vector_id: The AttackVector id to write a report for.
        """
        from src.core.agent.roles.agents import reporting_agent as reporting_mod

        loop = asyncio.get_running_loop()
        vector = await loop.run_in_executor(None, db_manager.get_attack_vector, vector_id)
        if vector is None or str(vector.target_id) != str(target_id):
            return f"{vector_id}: not found."
        if vector.status != AttackVectorStatus.TESTED_VULNERABLE:
            return f"{vector_id}: status is {vector.status}, not tested_vulnerable - nothing to report."
        if vector.linked_vulnerability_id is not None:
            return f"{vector_id}: already reported (vulnerability {vector.linked_vulnerability_id})."
        if vector.assigned_run_id is None:
            return f"{vector_id}: has no assigned pentesting run to read a transcript from."

        pentesting_logs = await loop.run_in_executor(
            None, db_manager.get_agent_logs_for_run, vector.assigned_run_id
        )
        project_settings = await loop.run_in_executor(None, db_manager.get_project_settings, project_id)
        model_name = project_settings.reporting_model_name or project_settings.base_model_name
        reasoning, context_window = await common.resolve_model_capabilities(
            model_name, project_settings.max_context_window
        )

        run = await run_registry.start_sub_run(
            project_id=project_id,
            target_id=target_id,
            role="reporting",
            parent_run_id=orchestrator_run_id,
            attack_vector_id=vector_id,
        )
        agent_run_id = str(run.id)
        stop_event = asyncio.Event()
        run_registry.stop_events[agent_run_id] = stop_event

        try:
            agent = reporting_mod.ReportingAgent(
                model_name=model_name,
                checkpointer=agent_checkpointer.checkpointer,
                project_id=project_id,
                target_id=target_id,
                agent_run_id=agent_run_id,
                attack_vector_id=vector_id,
                pentesting_logs=pentesting_logs,
                reasoning=reasoning,
                context_window=context_window,
            )
            prompt = (
                project_settings.reporting_starting_prompt or ""
            ).strip() or default_reporting_prompt

            await _drain_sub_agent(
                agent.start_agent(
                    start_prompt=prompt,
                    thread_id=f"{target_id}:{agent_run_id}",
                    stop_event=stop_event,
                ),
                project_id,
                target_id,
                agent_run_id,
                "reporting",
                parent_run_id=orchestrator_run_id,
                attack_vector_id=vector_id,
            )
        finally:
            manager = await kali_registry.get_manager_if_exists(project_id)
            if manager is not None:
                # Scoped to just THIS sub-run's own sessions, not every
                # session on the target - close_sessions_for_target would
                # tear down a sibling sub-agent's sessions too, once more
                # than one can be live on the same target at once (mirrors
                # agent_service.py's own _run_agent cleanup).
                await manager.close_sessions_for_run(target_id, agent_run_id)

            await run_registry.persist_run_state(
                project_id=project_id,
                target_id=target_id,
                status=AgentRunState.FINISHED,
                remaining_seconds=0,
                agent_run_id=agent_run_id,
                role="reporting",
                parent_run_id=orchestrator_run_id,
                attack_vector_id=vector_id,
            )
            run_registry.cleanup_sub_run(target_id, agent_run_id)

        if agent.created_vulnerability is None:
            return f"{vector_id}: reporting did not produce a vulnerability within its turn limit."

        vector.linked_vulnerability_id = agent.created_vulnerability.id
        vector = await loop.run_in_executor(None, db_manager.update_attack_vector, vector)
        await run_registry.broadcast_attack_vector(vector)

        return (
            f"{vector_id}: recorded vulnerability '{agent.created_vulnerability.name}' "
            f"(CVSS v4.0 score {agent.created_vulnerability.cvss4_score})."
        )

    return request_report
