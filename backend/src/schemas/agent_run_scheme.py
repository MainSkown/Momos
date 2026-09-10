import uuid
from enum import Enum
from datetime import datetime, timezone
from sqlmodel import SQLModel, Field, Relationship
from . import Target


class AgentRunState(str, Enum):
    RUNNING = "running"
    PAUSED = "paused"
    INTERRUPTED = "interrupted"
    FINISHED = "finished"


class AgentRunBase(SQLModel):
    status: AgentRunState
    remaining_seconds: int
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


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
