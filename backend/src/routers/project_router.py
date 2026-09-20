from typing import List

from fastapi import APIRouter, HTTPException, status
from src.services import ProjectService
from src.schemas import (
    ProjectResponse,
    ProjectRequest,
    ProjectSettings,
    ProjectSettingsBody,
)

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
def create_project(data: ProjectRequest):
    try:
        return ProjectService.add_project(data.name, data.base_model_name, data.parsing_model_name)
    except Exception as e:
        print(f"Exception happened when creating new project", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not create new project",
        )


@router.get(
    "/project/{project_id}/settings",
    response_model=ProjectSettings,
    operation_id="GetProjectSettings",
)
def get_project_settings(project_id: str):
    try:
        return ProjectService.get_project_settings(project_id)
    except Exception as e:
        print(
            f"Exception happened when getting project {project_id} settings: ", str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not get project settings",
        )


@router.put("/project/{project_id}/settings", operation_id="UpdateProjectSettings")
def update_project_settings(project_id: str, data: ProjectSettingsBody):
    if str(data.project_id) != project_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"URL project_id ({project_id}) does not match body project_id ({data.project_id})",
        )

    if data.allow_install_packages and not data.allow_shell:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="allow_install_packages requires allow_shell to also be enabled.",
        )

    try:
        return ProjectService.update_project_settings(data)
    except Exception as e:
        print(
            f"Exception happened when updating project {project_id} settings: ", str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not update project settings",
        )


@router.delete(
    "/project/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="DeleteProject",
)
def delete_project(project_id: str):
    try:
        ProjectService.delete_project(project_id)
        return
    except Exception as e:
        print(f"Exception happened when deleting project {project_id}: ", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not delete project",
        )
