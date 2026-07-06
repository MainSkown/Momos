from typing import List

from fastapi import APIRouter, HTTPException, status
from src.services import ProjectService
from src.schemas import ProjectResponse, ProjectBase

router = APIRouter()


@router.get(
    "/projects", response_model=List[ProjectResponse], operation_id="GetAllProjects"
)
def all_projects():
    try:
        return ProjectService.get_projects()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not return all projects",
        )


@router.post("/project", response_model=ProjectResponse, operation_id="PostProject")
def create_project(data: ProjectBase):
    try:
        return ProjectService.add_project(data.name)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not create new project",
        )
