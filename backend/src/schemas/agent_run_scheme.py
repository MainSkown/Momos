import uuid
from enum import Enum
from datetime import datetime, timezone
from typing import Optional
from sqlmodel import SQLModel, Field, Relationship, Column, DateTime
from sqlalchemy import Index, text
from . import Target

# Plain validated strings, not a Postgres-native enum (unlike AgentRunState
# below) - role is closer to "which role module produced this row" than a
# fixed state machine, and a new role being addable later without an
# `ALTER TYPE ... ADD VALUE` migration (see AgentRunState.FAILED's own
# migration in database_manager.py for what that dance looks like) felt
# worth the trade-off of losing DB-level enforcement. Not validated at the
# schema level here - callers (agent_service.py / the roles layer) are
# expected to only ever use one of these.
AGENT_RUN_ROLES = (
    "single_agent",
    "orchestrator",
    "scouting",
    "pentesting",
    "reporting",
)


class AgentRunState(str, Enum):
    RUNNING = "running"
    PAUSED = "paused"
    INTERRUPTED = "interrupted"
    FINISHED = "finished"
    # A run that ended because something actually went wrong (an unhandled
    # exception in agent_service.py's _run_agent), as opposed to FINISHED,
    # which means the run completed/paused/ran out of time normally.
    # Without this distinction, a crash used to persist as FINISHED with
    # remaining_seconds hardcoded to 0 - indistinguishable in the UI from a
    # real run that used its full duration.
    FAILED = "failed"


class AgentRunBase(SQLModel):
    status: AgentRunState
    remaining_seconds: int
    # timezone=True is required - without it, SQLAlchemy/Postgres round-trips
    # this as a timezone-naive value, silently dropping the UTC marker. The
    # frontend then parses the resulting "no Z suffix" timestamp as local
    # time (per the JS Date spec), which threw its elapsed-time countdown
    # off by the local UTC offset.
    recorded_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )
    # Which role produced this run - see AGENT_RUN_ROLES above. Defaults to
    # "single_agent" so every existing call site that constructs an
    # AgentRun without naming a role (today's whole single-agent flow)
    # keeps working unchanged.
    role: str = "single_agent"
    # The run that spawned this one - e.g. a pentesting run's parent is the
    # orchestrator run that dispatched it. None for "single_agent" (no
    # parent concept there) and for the orchestrator's own root run.
    parent_run_id: Optional[uuid.UUID] = None
    # Which AttackVector this run is/was working on - set for pentesting
    # and reporting runs, None for single_agent/orchestrator/scouting.
    attack_vector_id: Optional[uuid.UUID] = None


class AgentRun(AgentRunBase, table=True):
    # Surrogate PK, not target_id - a target's pipeline is now a TREE of
    # runs (one orchestrator + one scouting + N pentesting + N reporting in
    # multi_agent mode), not the single row this used to be. The partial
    # unique index below preserves single_agent's old "exactly one row per
    # target" guarantee without applying that same constraint to the
    # other, inherently-plural roles. See database_manager.py's
    # upsert_agent_run/get_agent_run for how single_agent mode's call sites
    # keep working unchanged against this new shape.
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    target_id: uuid.UUID = Field(foreign_key="target.id")
    project_id: uuid.UUID = Field(foreign_key="project.id")

    target: Target = Relationship(back_populates="agent_runs")

    __table_args__ = (
        Index(
            "agentrun_single_agent_per_target",
            "target_id",
            unique=True,
            postgresql_where=text("role = 'single_agent'"),
        ),
    )


class AgentRunResponse(AgentRunBase):
    id: uuid.UUID
    target_id: uuid.UUID
    project_id: uuid.UUID

    model_config = {"from_attributes": True}
