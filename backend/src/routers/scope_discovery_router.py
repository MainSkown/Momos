from typing import List

from fastapi import APIRouter, HTTPException, status
from src.services import ScopeDiscoveryService
from src.schemas import DiscoveredHost
from src.utils.exceptions import ProjectDoesNotExistException

router = APIRouter()


@router.post(
    "/project/{project_id}/scope/discover",
    response_model=List[DiscoveredHost],
    operation_id="DiscoverProjectHosts",
)
async def discover_hosts(project_id: str):
    try:
        return await ScopeDiscoveryService.discover_hosts(project_id)
    except ProjectDoesNotExistException as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not run host discovery for project: {project_id}",
        )
