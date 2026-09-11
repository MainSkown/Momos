import uuid
from enum import Enum
from datetime import datetime, timezone
from sqlmodel import SQLModel, Field, Relationship, Column, DateTime
from . import Target


class AgentRunState(str, Enum):
    RUNNING = "running"
    PAUSED = "paused"
    INTERRUPTED = "interrupted"
    FINISHED = "finished"


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


class AgentRun(AgentRunBase, table=True):
    # One row per target - reflects the current/latest state of that target's
    # agent run, not a historical log of every run.
    target_id: uuid.UUID = Field(foreign_key="target.id", primary_key=True)
    project_id: uuid.UUID = Field(foreign_key="project.id")

    target: Target = Relationship(back_populates="agent_run")


class AgentRunResponse(AgentRunBase):
    target_id: uuid.UUID
    project_id: uuid.UUID

    model_config = {"from_attributes": True}
