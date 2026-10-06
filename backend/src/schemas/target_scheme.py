import uuid
from typing import List, Optional, TYPE_CHECKING, Annotated, TypedDict
from sqlmodel import SQLModel, Field, Relationship, Column
from sqlalchemy import ARRAY, Integer
from pydantic import Field as PydanticField

if TYPE_CHECKING:
    from .project_scheme import Project
    from .vulnerability_scheme import Vulnerability
    from .agent_log_scheme import AgentLog
    from .agent_run_scheme import AgentRun
    from .attack_vector_scheme import AttackVector

ValidPort = Annotated[int, PydanticField(ge=1, le=65535)]


class AgentTargetScope(TypedDict):
    name: str
    ipv4: str | None
    ipv6: str | None
    description: str | None
    ports: list[int] | None


class TargetBase(SQLModel):
    name: str
    ipv4: str | None
    ipv6: str | None
    # domain: str | None
    description: str | None
    ports: List[ValidPort] | None = Field(sa_column=Column(ARRAY(Integer)))
    task_duration: int | None
    # "timer" (default): stop when task_duration elapses, like today.
    # "until_vectors_checked": run until no AttackVector for this target is
    # PENDING/TESTING, with safety_cap_duration as an optional hard ceiling.
    run_mode: str = "timer"
    safety_cap_duration: int | None = None


class Target(TargetBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    project_id: uuid.UUID = Field(foreign_key="project.id")

    project: Optional["Project"] = Relationship(back_populates="targets")
    vulnerabilities: List["Vulnerability"] = Relationship(back_populates="target")
    agent_logs: List["AgentLog"] = Relationship(back_populates="target")
    # List, not Optional[...] singular - a target's pipeline is now a TREE
    # of runs (one orchestrator + one scouting + N pentesting + N reporting
    # in multi_agent mode, still just one in single_agent mode) rather than
    # the single row this used to be. See agent_run_scheme.py.
    agent_runs: List["AgentRun"] = Relationship(back_populates="target")
    attack_vectors: List["AttackVector"] = Relationship(back_populates="target")


class ResponseTarget(TargetBase):
    id: uuid.UUID
    project_id: uuid.UUID

    model_config = {"from_attributes": True}
