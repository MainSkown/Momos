from enum import Enum
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlmodel import SQLModel, Field, Relationship, Column, DateTime
from . import Target

class AgentLogType(str, Enum):
    THINKING = "thinking"
    ACTION = "action"
    TOOL ="tool"

class AgentLogBase(SQLModel):
    type: AgentLogType
    content: str
    tool_name: Optional[str] = None


class AgentLog(AgentLogBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    # timezone=True - see the same note in agent_run_scheme.py's recorded_at;
    # without it, the DB round-trip silently drops the UTC marker and the
    # frontend can misparse the resulting timestamp as local time.
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )

    project_id: uuid.UUID = Field(foreign_key="project.id")
    target_id: uuid.UUID = Field(foreign_key="target.id")

    target: Target = Relationship(back_populates="agent_logs")


class AgentLogResponse(AgentLogBase):
    id: uuid.UUID
    created_at: datetime
    project_id: uuid.UUID
    target_id: uuid.UUID

    model_config = {"from_attributes": True}
