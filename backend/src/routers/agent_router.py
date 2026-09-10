from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from src.core import db_manager
from src.schemas import AgentLogResponse
from src.services import AgentService
from src.utils.exceptions import (
    ProjectDoesNotExistException,
    TargetDoesNotExistException,
    DurationNotDefinedInTarget,
)

router = APIRouter()


class AgentRunningResponse(BaseModel):
    running: bool

@router.post(
    "/project/{project_id}/target/{target_id}/agent/start", operation_id="StartAgent"
)
async def start_agent(project_id: str, target_id: str):
    try:
        await AgentService.start_agent(project_id, target_id)
    except (ProjectDoesNotExistException, TargetDoesNotExistException) as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except DurationNotDefinedInTarget as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        print(f"Could not start agent: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not start agent",
        )

@router.get(
    "/project/{project_id}/agent_logs",
    response_model=list[AgentLogResponse],
    operation_id="GetProjectAgentLogs",
)
def get_project_agent_logs(project_id: str):
    try:
        return db_manager.get_all_agent_logs_in_project(project_id)
    except Exception as e:
        print(f"Could not fetch agent logs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not fetch agent logs",
        )

@router.get(
    "/project/{project_id}/agent/running",
    response_model=AgentRunningResponse,
    operation_id="IsProjectAgentRunning",
)
def is_project_agent_running(project_id: str):
    return AgentRunningResponse(running=AgentService.is_project_running(project_id))
