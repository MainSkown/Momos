import uuid
from typing import List, Optional, TYPE_CHECKING, Annotated, TypedDict
from sqlmodel import SQLModel, Field, Relationship, Column
from sqlalchemy import ARRAY, Integer
from pydantic import Field as PydanticField

if TYPE_CHECKING:
    from .project_scheme import Project
    from .vulnerability_scheme import Vulnerability
    from .agent_log_scheme import AgentLog

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


class Target(TargetBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    project_id: uuid.UUID = Field(foreign_key="project.id")

    project: Optional["Project"] = Relationship(back_populates="targets")
    vulnerabilities: List["Vulnerability"] = Relationship(back_populates="target")
    agent_logs: List["AgentLog"] = Relationship(back_populates="target")


class ResponseTarget(TargetBase):
    id: uuid.UUID
    project_id: uuid.UUID

    model_config = {"from_attributes": True}
