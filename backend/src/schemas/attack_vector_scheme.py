import uuid
from enum import Enum
from datetime import datetime, timezone
from typing import Optional
from sqlmodel import SQLModel, Field, Relationship, Column, DateTime
from . import Target


class AttackVectorStatus(str, Enum):
    PENDING = "pending"
    TESTING = "testing"
    TESTED_VULNERABLE = "tested_vulnerable"
    TESTED_NOT_VULNERABLE = "tested_not_vulnerable"
    # Also the terminal state for a vector nothing could ever test (e.g. the
    # pentesting role lacks the tool a vector needs) - reported here with
    # the reasoning rather than a separate "skipped" bin, since it's the
    # same "we don't have a verdict" shape as every other inconclusive case.
    INCONCLUSIVE = "inconclusive"


class AttackVectorBase(SQLModel):
    # A concrete, specific candidate (e.g. "vsftpd 2.3.4 on port 21 - check
    # for the known backdoor") - see scouting_starting_prompt's own
    # propose_attack_vector guidance in project_scheme.py. Not a vague
    # "check this port" note.
    description: str
    status: AttackVectorStatus = AttackVectorStatus.PENDING
    # The agent_run that proposed this vector - either the scouting run, or
    # a pentesting run that surfaced it mid-exploitation (see pentesting's
    # report_outcome new_vectors). Nullable only because this table has no
    # other legitimate way to create a row without one; never actually left
    # unset in practice.
    discovered_by_run_id: Optional[uuid.UUID] = Field(
        default=None, foreign_key="agentrun.id"
    )
    # The pentesting run currently (or most recently) assigned to test this
    # vector - set when the orchestrator dispatches it, read by the
    # reporting role (via this field, not a hand-carried argument - see
    # reporting_starting_prompt) to pull that run's full log transcript.
    assigned_run_id: Optional[uuid.UUID] = Field(
        default=None, foreign_key="agentrun.id"
    )
    # The pentesting agent's own short summary from report_outcome - for
    # the orchestrator's cheap scheduling/requeue decisions only. The real
    # evidence for writing a proof_of_concept is the assigned run's full
    # persisted log (AgentLog rows for assigned_run_id), not this field -
    # see reporting_starting_prompt in project_scheme.py.
    result_summary: Optional[str] = None
    # Set once the reporting role successfully records a Vulnerability from
    # this vector's assigned run - see report_vulnerability.
    linked_vulnerability_id: Optional[uuid.UUID] = Field(
        default=None, foreign_key="vulnerability.id"
    )


class AttackVector(AttackVectorBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    project_id: uuid.UUID = Field(foreign_key="project.id")
    target_id: uuid.UUID = Field(foreign_key="target.id")

    target: Target = Relationship(back_populates="attack_vectors")

    # timezone=True - see the same note in agent_log_scheme.py's created_at;
    # without it, the DB round-trip silently drops the UTC marker and the
    # frontend can misparse the resulting timestamp as local time.
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )


class ResponseAttackVector(AttackVectorBase):
    id: uuid.UUID
    project_id: uuid.UUID
    target_id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
