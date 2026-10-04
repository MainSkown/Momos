"""Agent-run-lifecycle primitives shared by services/agent_service.py (the
Single Agent flow) and the roles/ package (the multi-agent pipeline's own
orchestrator/scouting/pentesting/reporting sub-runs).

This lives under core/agent/, not services/, specifically so roles/*.py can
import it without creating a cycle: services/agent_service.py already
imports from core/agent (Agent, agent_tools, and now the roles package);
if these primitives lived in agent_service.py instead, a role's own tool
(e.g. dispatch_pentest_batch, which needs to acquire a concurrency slot
and persist its sub-agent's logs) would have to import back from
agent_service.py, which imports the roles package - a cycle. Nothing here
depends on FastAPI/routers/websockets beyond the plain ws_registry
message-broadcasting primitive every part of this backend already uses.

Every module-level dict here is keyed by agent_run_id - for single_agent
mode that's == target_id (see Agent.__init__'s own comment), so every
pre-existing call site that only knows target_id keeps working unchanged.
For a multi_agent sub-run, agent_run_id is the REAL AgentRun.id - the
database row's own surrogate primary key, not an arbitrary string - see
start_sub_run below for why that distinction matters (AttackVector's
discovered_by_run_id/assigned_run_id are real foreign keys to this exact
column).
"""

import asyncio
import uuid
from typing import Callable, Dict, List, Optional, Tuple
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from src.core import db_manager, settings
from src.core.agent import agent_tools
from src.schemas.agent_log_scheme import AgentLog, AgentLogResponse, AgentLogType
from src.schemas.agent_run_scheme import AgentRun, AgentRunResponse, AgentRunState
from src.websocket import ws_registry, WsTypes, AgentMessage, AgentRunTimer

# agent_run_id -> pending interrupt's accept callback. See this module's
# own docstring for why agent_run_id, not target_id.
pending_interrupts: Dict[str, Callable[[bool], None]] = {}

# agent_run_id -> the tool_calls of the interrupt currently pending for
# that run, same shape as the AgentInterruptRequest websocket message.
# Kept in lockstep with pending_interrupts.
pending_interrupt_tool_calls: Dict[str, List[dict]] = {}

# target_id -> the set of agent_run_ids currently live under that target's
# pipeline - one entry for single_agent mode, several once a multi_agent
# pipeline has concurrent sub-runs in flight. pause_agent/finish_agent
# (agent_service.py) fan their stop signal out across every entry here for
# a target instead of assuming there's ever just one.
live_runs_for_target: Dict[str, set] = {}

# agent_run_id -> the active run's stop_event, so a pause request can
# trigger it.
stop_events: Dict[str, asyncio.Event] = {}

# agent_run_id -> the active run's shared time-remaining state (only
# meaningful for a run that was given a duration_seconds budget - see
# roles/common.py's run_graph_loop. Sub-roles other than the orchestrator
# don't use this).
run_states: Dict[str, dict] = {}

# agent_run_id -> True if the pending stop_event.set() should end the run
# as FINISHED (not resumable) rather than PAUSED.
finish_intents: Dict[str, bool] = {}

# Process-wide cap on how many agent LLM instances may run at once, across
# every project - see config.py's GLOBAL_MAX_CONCURRENT_AGENTS.
_global_agent_semaphore = asyncio.Semaphore(settings.GLOBAL_MAX_CONCURRENT_AGENTS)

# project_id -> how many slots that project currently holds. NOT a plain
# asyncio.Semaphore per project - see acquire_agent_slot's own docstring
# for why a fixed-size Semaphore constructed once wouldn't reflect a
# project's max_concurrent_agents setting changing at runtime.
_project_slot_counts: Dict[str, int] = {}
_project_slot_condition = asyncio.Condition()


async def acquire_agent_slot(project_id: str, max_concurrent_agents: int) -> None:
    """Blocks until a slot is free for this project - both this project's
    own configured allowance AND the global hardware ceiling - then holds
    both. Release with release_agent_slot exactly once per successful
    acquire. effective_slots = min(max_concurrent_agents, the global cap)
    - see GLOBAL_MAX_CONCURRENT_AGENTS's own comment in config.py for why
    the global figure always wins when the two disagree.

    All-or-nothing: if the global acquire below is cancelled (or raises)
    after the per-project slot was already counted, that count is rolled
    back before re-raising - otherwise a cancelled caller would leak a
    per-project slot forever."""
    effective_slots = max(1, min(max_concurrent_agents, settings.GLOBAL_MAX_CONCURRENT_AGENTS))
    async with _project_slot_condition:
        while _project_slot_counts.get(project_id, 0) >= effective_slots:
            await _project_slot_condition.wait()
        _project_slot_counts[project_id] = _project_slot_counts.get(project_id, 0) + 1
    try:
        await _global_agent_semaphore.acquire()
    except BaseException:
        async with _project_slot_condition:
            _project_slot_counts[project_id] = max(0, _project_slot_counts.get(project_id, 0) - 1)
            _project_slot_condition.notify_all()
        raise


async def release_agent_slot(project_id: str) -> None:
    _global_agent_semaphore.release()
    async with _project_slot_condition:
        _project_slot_counts[project_id] = max(0, _project_slot_counts.get(project_id, 0) - 1)
        _project_slot_condition.notify_all()


async def persist_run_state(
    *,
    project_id: str,
    target_id: str,
    status: AgentRunState,
    remaining_seconds: float,
    agent_run_id: Optional[str] = None,
    role: str = "single_agent",
    parent_run_id: Optional[str] = None,
    attack_vector_id: Optional[str] = None,
) -> AgentRun:
    """Single_agent mode (agent_run_id=None, role="single_agent" - the
    defaults) keeps using upsert_agent_run's (target_id, role) lookup
    convenience, completely unchanged from before this function moved
    here. A multi_agent sub-run passes its own already-known agent_run_id
    (the real AgentRun.id minted by start_sub_run below) and goes through
    save_agent_run's plain merge-by-id instead - see that method's own
    docstring for why upsert_agent_run's lookup would be wrong for it
    (it would collapse multiple concurrent same-role sub-runs onto one
    row)."""
    run = AgentRun(
        id=uuid.UUID(agent_run_id) if agent_run_id else uuid.uuid4(),
        status=status,
        remaining_seconds=max(0, int(remaining_seconds)),
        project_id=project_id,
        target_id=target_id,
        role=role,
        parent_run_id=uuid.UUID(parent_run_id) if parent_run_id else None,
        attack_vector_id=uuid.UUID(attack_vector_id) if attack_vector_id else None,
    )

    loop = asyncio.get_running_loop()
    if agent_run_id is None:
        saved = await loop.run_in_executor(None, db_manager.upsert_agent_run, run)
    else:
        saved = await loop.run_in_executor(None, db_manager.save_agent_run, run)

    await ws_registry.send_message(
        AgentRunTimer(
            type=WsTypes.AgentRunTimer,
            run=AgentRunResponse.model_validate(saved),
        )
    )

    return saved


async def start_sub_run(
    *, project_id: str, target_id: str, role: str, parent_run_id: Optional[str],
    attack_vector_id: Optional[str] = None,
) -> AgentRun:
    """Mints a brand-new AgentRun row for one multi_agent sub-run (never
    an update to a previous one - unlike single_agent, a new pentesting/
    scouting/reporting run is always its own fresh row) and returns it.
    The row's own `id` IS this sub-run's agent_run_id from this point on -
    used identically for Kali session scoping (see kali_manager.py),
    every dict in this module, and as the real foreign key value written
    into AttackVector.discovered_by_run_id/assigned_run_id and
    AgentLog.agent_run_id. Unifying these (rather than inventing a
    separate string identifier) is what lets the reporting role's
    get_agent_logs_for_run(vector.assigned_run_id) actually resolve to a
    real pentesting run's transcript."""
    loop = asyncio.get_running_loop()
    run = AgentRun(
        status=AgentRunState.RUNNING,
        remaining_seconds=0,
        project_id=project_id,
        target_id=target_id,
        role=role,
        parent_run_id=uuid.UUID(parent_run_id) if parent_run_id else None,
        attack_vector_id=uuid.UUID(attack_vector_id) if attack_vector_id else None,
    )
    saved = await loop.run_in_executor(None, db_manager.add_to_database, run)

    agent_run_id = str(saved.id)
    live_runs_for_target.setdefault(target_id, set()).add(agent_run_id)

    await ws_registry.send_message(
        AgentRunTimer(type=WsTypes.AgentRunTimer, run=AgentRunResponse.model_validate(saved))
    )
    return saved


def cleanup_sub_run(target_id: str, agent_run_id: str) -> None:
    """The finally-block half of start_sub_run - pops every dict entry
    for this sub-run and removes it from its target's live set. Does NOT
    touch Kali sessions (close_sessions_for_run) or release a concurrency
    slot - those are the caller's own responsibility, since not every
    caller necessarily acquired one the same way (and a role with no
    sessions of its own, e.g. reporting, has nothing to close)."""
    pending_interrupts.pop(agent_run_id, None)
    pending_interrupt_tool_calls.pop(agent_run_id, None)
    stop_events.pop(agent_run_id, None)
    run_states.pop(agent_run_id, None)
    finish_intents.pop(agent_run_id, None)
    live_runs = live_runs_for_target.get(target_id)
    if live_runs is not None:
        live_runs.discard(agent_run_id)
        if not live_runs:
            live_runs_for_target.pop(target_id, None)


def stringify_content(content) -> str:
    return content if isinstance(content, str) else str(content)


def render_tool_call_content(tool_name: str, args: dict) -> str:
    """Same purpose as agent_service.py's own (pre-move) version, extended
    with the 4 new multi-agent pipeline tools. Kept as one function (not
    forked per role) since it's pure, stateless rendering with no
    behavioral consequence - a role simply never produces a tool_name
    this doesn't have a case for other than the ones below plus every
    legacy name already handled."""
    if tool_name == agent_tools.INSTALL_PACKAGE_TOOL_NAME:
        return str(args.get("package", ""))
    if tool_name == agent_tools.REPORT_VULNERABILITY_TOOL_NAME:
        return str(args.get("name", ""))
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
    if tool_name in (agent_tools.SWITCH_SESSION_TOOL_NAME, agent_tools.CLOSE_SESSION_TOOL_NAME):
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
    # --- Multi-agent pipeline tools ---
    if tool_name == "propose_attack_vector":
        return "; ".join(str(d) for d in args.get("descriptions", []))
    if tool_name == "report_outcome":
        return f"[{args.get('outcome', '')}] {args.get('summary', '')}"
    if tool_name == "dispatch_pentest_batch":
        return ", ".join(str(v) for v in args.get("vector_ids", []))
    if tool_name == "request_report":
        return str(args.get("vector_id", ""))
    if tool_name == "run_scouting":
        return "(run scouting)"

    return ", ".join(f"{k}={v}" for k, v in args.items())


def message_to_log_specs(
    message: BaseMessage,
) -> List[Tuple[AgentLogType, str, Optional[str], Optional[str]]]:
    """Same logic as agent_service.py's own (pre-move) version - turns one
    agent message into zero or more (type, content, tool_name,
    raw_output) specs."""
    specs: List[Tuple[AgentLogType, str, Optional[str], Optional[str]]] = []

    if isinstance(message, AIMessage):
        reasoning_content = message.additional_kwargs.get("reasoning_content")
        content = (
            stringify_content(reasoning_content)
            if reasoning_content
            else stringify_content(message.content)
        )
        if content.strip():
            specs.append(("thinking", content, None, None))
        for tc in message.tool_calls:
            specs.append(
                ("tool", render_tool_call_content(tc["name"], tc["args"]), tc["name"], None)
            )
    elif isinstance(message, ToolMessage):
        content = stringify_content(message.content)
        artifact = getattr(message, "artifact", None)
        artifact_str = artifact if isinstance(artifact, str) else None
        if message.name == agent_tools.SEARCHSPLOIT_VIEW_TOOL_NAME and artifact_str:
            display_content, raw_output = artifact_str, content
        else:
            display_content, raw_output = content, artifact_str
        if display_content.strip():
            specs.append(("action", display_content, None, raw_output))

    return specs


async def persist_and_broadcast(
    *,
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
        agent_run_id=uuid.UUID(agent_run_id) if agent_run_id else None,
        role=role,
    )

    loop = asyncio.get_running_loop()
    saved = await loop.run_in_executor(None, db_manager.add_agent_log, log)

    await ws_registry.send_message(
        AgentMessage(type=WsTypes.AgentMessage, log=AgentLogResponse.model_validate(saved))
    )

    return saved
