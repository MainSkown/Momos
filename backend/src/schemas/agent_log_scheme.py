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
    # Raw, unparsed tool output for a "tool"-adjacent "action" entry, when
    # available - populated from the ToolMessage.artifact that run()/
    # new_session()/switch_session() attach via response_format=
    # "content_and_artifact" (see agent_tools.py). Never shown to the model
    # itself (LangChain never resends a ToolMessage's artifact back into the
    # conversation) - this exists purely so a human reviewing the log can
    # see what the parsing model actually condensed `content` from, instead
    # of only ever seeing its (possibly wrong) summary. It's also exactly
    # what the reporting role reads back wholesale (see
    # get_agent_logs_for_run in database_manager.py) to write an accurate
    # proof_of_concept from a pentesting run's real transcript, not a
    # paraphrase of it.
    raw_output: Optional[str] = None
    # Which agent_run produced this entry, and which role that run was -
    # both nullable so every pre-existing single-agent-flow log row (and
    # every new single_agent-mode one, which never bothers setting these)
    # stays valid without a migration backfill. Multi-agent mode's roles
    # always set both, so the reporting role can pull exactly one
    # pentesting run's transcript (get_agent_logs_for_run) and the UI can
    # group a target's logs by role/run instead of one flat stream.
    agent_run_id: Optional[uuid.UUID] = None
    role: Optional[str] = None


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
