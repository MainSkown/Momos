from fastapi import APIRouter, HTTPException, status
from src.services import AgentService

router = APIRouter()

@router.post(
    "/project/{project_id}/agent/start", id="StartAgent4Project"
)
async def start_agent(project_id: str):
    try:
        AgentService.start_agent(project_id=project_id)
    except Exception as e:
        ... #TODO implement exception handling