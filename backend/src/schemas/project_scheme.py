import uuid 
from sqlmodel import SQLModel, Field

class ProjectBase(SQLModel):
    name: str

class Project(ProjectBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)

class ProjectResponse(ProjectBase):
    id: uuid.UUID
    
    model_config = {
        "from_attributes":True,
        "json_schema_extra": {
            "title": "Project"
        }
    }