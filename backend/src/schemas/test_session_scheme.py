"""One TestSession row per target Start->finish (or Start->Pause, when
resumed later the SAME row keeps going - see agent_service.start_agent's
own fresh-vs-resume handling). Every AgentRun/AgentLog/AttackVector created
while a session is live is stamped with its session_id (see
run_registry.py's current_session_for_target), rather than the old
behavior of deleting AttackVector rows on every fresh start - this is what
lets History show "how did this specific test go" instead of only ever one
flat, ever-growing pile per target. Vulnerability rows are deliberately
NOT owned by a session (no vulnerability_id/session link here) - they're
durable findings that outlive the session that produced them; a vector's
own linked_vulnerability_id is the only pointer between the two."""

import uuid
from enum import Enum
from datetime import datetime, timezone
from typing import Optional
from sqlmodel import SQLModel, Field, Column, DateTime


class TestSessionOutcome(str, Enum):
    RUNNING = "running"
    PAUSED = "paused"
    # Either the user pressed Finish, or the agent/orchestrator decided on
    # its own it was done (finish_task / orchestrator is_done) - History
    # doesn't distinguish the two, since both mean "a genuine stop, not a
    # budget running out or a crash".
    FINISHED = "finished"
    # A natural (non-paused, non-finish-requested) exit where the time
    # budget or safety cap actually ran out - see agent_service.py's
    # _time_budget_exhausted, which classifies this after the fact from
    # the same run_state the agent loop itself already maintains.
    TIME_EXPIRED = "time_expired"
    FAILED = "failed"
    # Backend restarted (or crashed) while this session was RUNNING with no
    # live task left to ever end it - see
    # DatabaseManager.mark_orphaned_sessions_aborted, called once at
    # backend startup (main.py's lifespan). Named "aborted", not
    # "interrupted", to avoid colliding with AgentRunState.INTERRUPTED (a
    # live run merely waiting on tool-approval) - a wholly different,
    # mid-run status this enum never needs to represent at all. Does NOT
    # apply to a session left PAUSED across a restart - pausing has always
    # been a deliberate, resumable stopping point in this codebase (see
    # AgentRunState.PAUSED), restart or not.
    ABORTED = "aborted"


class TestSessionBase(SQLModel):
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )
    ended_at: Optional[datetime] = Field(
        default=None, sa_column=Column(DateTime(timezone=True))
    )
    # Sum of this session's running intervals (fresh-start/resume ->
    # pause/end), excluding paused time - accumulated each time the
    # session stops running (see TestSession.last_resumed_at below and
    # agent_service.py's _finalize_session).
    active_seconds: int = 0
    # Copy of target.task_duration at session start - None for a
    # "until_vectors_checked" target with no fixed duration. Captured once
    # so later edits to the target's own duration never rewrite an
    # already-started session's history.
    time_budget_seconds: Optional[int] = None
    outcome: TestSessionOutcome = TestSessionOutcome.RUNNING
    # --- Config snapshot - captured once at session start (see
    # agent_service.start_agent) so later changes to project settings
    # never rewrite an already-started session's history. ---
    pipeline_mode: str
    max_concurrent_agents: int
    base_model_name: str
    orchestrator_model_name: str
    scouting_model_name: str
    pentesting_model_name: str
    reporting_model_name: str


class TestSession(TestSessionBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    project_id: uuid.UUID = Field(foreign_key="project.id")
    target_id: uuid.UUID = Field(foreign_key="target.id")
    # Internal bookkeeping only - deliberately absent from
    # TestSessionBase/Response, so it's never exposed over the API. Holds
    # when the session's CURRENT running interval began, or None while
    # paused/ended. Set on fresh start and on resume, folded into
    # active_seconds and cleared on pause/finish/abort - see
    # agent_service.py's _finalize_session and
    # DatabaseManager.mark_orphaned_sessions_aborted.
    last_resumed_at: Optional[datetime] = Field(
        default=None, sa_column=Column(DateTime(timezone=True))
    )


class TestSessionResponse(TestSessionBase):
    id: uuid.UUID
    project_id: uuid.UUID
    target_id: uuid.UUID

    model_config = {"from_attributes": True}


class TestSessionDetailResponse(TestSessionResponse):
    # Derived at read time (see TestSessionService.get_session_detail) -
    # not stored, so these can never go stale relative to the actual
    # vector/vulnerability rows.
    vector_counts: dict[str, int]
    vulnerability_count: int


# Default/max page size for the session Logs tab's own pagination
# (DatabaseManager.get_agent_logs_for_session / TestSessionService.
# get_session_logs / session_router.py's GetTestSessionLogs) - one shared
# constant instead of the same literal repeated across all three layers.
DEFAULT_LOG_PAGE_SIZE = 200
