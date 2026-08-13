import uuid
from typing import List, Optional, TYPE_CHECKING, Annotated
from sqlmodel import SQLModel, Field, Relationship, Column
from sqlalchemy import ARRAY, Integer
from pydantic import Field as PydanticField

if TYPE_CHECKING:
    from .project_scheme import Project

ValidPort = Annotated[int, PydanticField(ge=1, le=65535)]


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


class ResponseTarget(TargetBase):
    id: uuid.UUID
    project_id: uuid.UUID

    model_config = {"from_attributes": True}
