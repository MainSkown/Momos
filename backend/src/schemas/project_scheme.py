import uuid 
from typing import List, TYPE_CHECKING
from sqlmodel import SQLModel, Field, Relationship

if TYPE_CHECKING:
    from .target_scheme import Target

class ProjectBase(SQLModel):
    name: str

class Project(ProjectBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)

    targets: List["Target"] = Relationship(back_populates="project")

class ProjectResponse(ProjectBase):
    id: uuid.UUID
    
    model_config = {
        "from_attributes":True,
        "json_schema_extra": {
            "title": "Project"
        }
    }