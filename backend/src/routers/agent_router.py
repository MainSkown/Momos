from fastapi import APIRouter, HTTPException, status
from src.services import AgentService
from src.utils.exceptions import (
    ProjectDoesNotExistException,
    TargetDoesNotExistException,
    DurationNotDefinedInTarget,
)

router = APIRouter()

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
