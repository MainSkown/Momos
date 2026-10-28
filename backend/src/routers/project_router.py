from typing import List

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from src.services import ProjectService, OllamaService, AgentService
from src.services.project_scope_service import ProjectScopeService
from src.schemas import (
    ProjectResponse,
    ProjectRequest,
    ProjectSettings,
    ProjectSettingsBody,
    ProjectScopeBody,
    ProjectScopeResponse,
    AuthorizationAcknowledgmentRequest,
    AuthorizationAcknowledgmentResponse,
)
from src.core import tool_groups, db_manager
from src.core.pipeline_modes import PIPELINE_MODE_IDS
from src.schemas.scope_parsing import parse_host_range, host_count
from src.utils.exceptions import ProjectDoesNotExistException

router = APIRouter()


class ProjectScopeUpdateResponse(BaseModel):
    scope: ProjectScopeResponse
    large_range_warning: bool


class AcknowledgmentStatusResponse(BaseModel):
    is_acknowledged: bool


def _require_project_exists(project_id: str) -> None:
    # ProjectScope/acknowledgment endpoints have no existence check of
    # their own the way ProjectService.get_project_settings does for
    # settings - this mirrors that same db_manager.get_project(...) is
    # None check so an unknown project_id maps to 404 here too, instead of
    # a 500 from a downstream merge/FK failure.
    if db_manager.get_project(project_id) is None:
        raise ProjectDoesNotExistException(
            f"Project does not exist: {project_id}", project_id
        )


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
        parse_host_range(data.host_range)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if not (1 <= data.port_range_start <= 65535 and 1 <= data.port_range_end <= 65535):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="port_range_start and port_range_end must each be between 1 and 65535",
        )
    if data.port_range_start > data.port_range_end:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="port_range_start must not be greater than port_range_end",
        )

    try:
        return ProjectService.add_project(
            data.name,
            data.base_model_name,
            data.parsing_model_name,
            data.host_range,
            data.port_range_start,
            data.port_range_end,
        )
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
    except ProjectDoesNotExistException as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        print(
            f"Exception happened when getting project {project_id} settings: ", str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not get project settings",
        )


@router.put("/project/{project_id}/settings", operation_id="UpdateProjectSettings")
async def update_project_settings(project_id: str, data: ProjectSettingsBody):
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

    if data.pipeline_mode not in PIPELINE_MODE_IDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown pipeline_mode: {data.pipeline_mode!r}",
        )

    # pipeline_mode can't change mid-run - a live orchestrator run (and
    # every sub-run it's spawned) assumes the mode it started under; the
    # Single Agent flow's own AgentRun row likewise assumes the opposite.
    # is_project_running is the same exclusivity check AgentService.start_agent
    # itself enforces, so this can only ever reject a change that would have
    # raced a live run either way.
    try:
        current_settings = ProjectService.get_project_settings(project_id)
    except ProjectDoesNotExistException as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    if data.pipeline_mode != current_settings.pipeline_mode and AgentService.is_project_running(
        project_id
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot change pipeline_mode while this project has a run in progress.",
        )

    if data.enabled_tools is not None:
        unknown = set(data.enabled_tools) - tool_groups.TOOL_GROUP_IDS
        if unknown:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown tool group(s): {sorted(unknown)}",
            )

    # Reject settings that point at a model that isn't actually installed -
    # without this, selecting a model and then deleting it left the project
    # silently referencing a model that no longer exists. Empty is still
    # allowed for both fields (base_model_name is enforced at run-start time
    # instead - see AgentService.start_agent - and parsing_model_name is
    # intentionally optional).
    if data.base_model_name or data.parsing_model_name:
        try:
            installed = await OllamaService.get_models_list()
        except Exception as e:
            print(f"Could not verify installed models: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not verify installed models",
            )
        installed_names = {model.name for model in installed.models}

        if data.base_model_name and data.base_model_name not in installed_names:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Model '{data.base_model_name}' is not installed.",
            )
        if data.parsing_model_name and data.parsing_model_name not in installed_names:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Model '{data.parsing_model_name}' is not installed.",
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


@router.get(
    "/project/{project_id}/scope",
    response_model=ProjectScopeResponse,
    operation_id="GetProjectScope",
)
def get_project_scope(project_id: str):
    try:
        _require_project_exists(project_id)

        scope = db_manager.get_project_scope(project_id)
        if scope is None:
            # ProjectScope is mandatory at creation time (see
            # ProjectService.add_project) - a Project row existing without
            # one means that invariant was broken somewhere, a genuine
            # server-side bug rather than a normal "not found" for a
            # client to see as a 404.
            raise RuntimeError(f"Project {project_id} exists but has no ProjectScope")

        return scope
    except ProjectDoesNotExistException as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        print(f"Exception happened when getting project {project_id} scope: ", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not get project scope",
        )


@router.put(
    "/project/{project_id}/scope",
    response_model=ProjectScopeUpdateResponse,
    operation_id="UpdateProjectScope",
)
def update_project_scope(project_id: str, data: ProjectScopeBody):
    if str(data.project_id) != project_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"URL project_id ({project_id}) does not match body project_id ({data.project_id})",
        )

    try:
        _require_project_exists(project_id)

        scope = ProjectScopeService.update_scope(
            project_id, data.host_range, data.port_range_start, data.port_range_end
        )
        large_range_warning = host_count(data.host_range) > 254
    except ProjectDoesNotExistException as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        print(f"Exception happened when updating project {project_id} scope: ", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not update project scope",
        )

    return ProjectScopeUpdateResponse(
        scope=ProjectScopeResponse.model_validate(scope),
        large_range_warning=large_range_warning,
    )


@router.post(
    "/project/{project_id}/acknowledgment",
    response_model=AuthorizationAcknowledgmentResponse,
    operation_id="SubmitAuthorizationAcknowledgment",
)
def submit_authorization_acknowledgment(
    project_id: str, data: AuthorizationAcknowledgmentRequest
):
    try:
        _require_project_exists(project_id)

        return ProjectScopeService.submit_acknowledgment(
            project_id, data.acknowledged_by, data.description
        )
    except ProjectDoesNotExistException as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        print(
            f"Exception happened when submitting acknowledgment for project {project_id}: ",
            str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not submit authorization acknowledgment",
        )


@router.get(
    "/project/{project_id}/acknowledgment/status",
    response_model=AcknowledgmentStatusResponse,
    operation_id="GetAcknowledgmentStatus",
)
def get_acknowledgment_status(project_id: str):
    try:
        _require_project_exists(project_id)

        return AcknowledgmentStatusResponse(
            is_acknowledged=ProjectScopeService.is_acknowledged(project_id)
        )
    except ProjectDoesNotExistException as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        print(
            f"Exception happened when getting acknowledgment status for project {project_id}: ",
            str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not get acknowledgment status",
        )
