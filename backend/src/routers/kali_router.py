from typing import List
from fastapi import APIRouter, HTTPException, status
from src.schemas import KaliUser, KaliStatusResponse, ConsoleSessionInfo
from src.services import KaliService
router = APIRouter()

@router.get(
    "/kali_client/{client_id}", response_model=KaliUser, operation_id="KaliClientExists")
def get_kali_client(client_id: str):
    try:
        client = KaliService.get_client(client_id=client_id)
    except Exception as e:
        print(f"Kali registry error: {e}", flush=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error looking up client",
        )
        
    if client is not None:
        return client
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Client does not exist with id: {client_id}"
    )
        
@router.get(
    "/project/{project_id}/kali_client",
    response_model=KaliUser,
    operation_id="GetProjectKaliClient",
)
def get_project_kali_client(project_id: str):
    try:
        client = KaliService.get_client_for_project(project_id)
    except Exception as e:
        print(f"Kali registry error: {e}", flush=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error looking up client",
        )

    if client is not None:
        return client

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Project has no active Kali client: {project_id}",
    )

@router.get(
    "/project/{project_id}/kali_client/sessions",
    response_model=List[ConsoleSessionInfo],
    operation_id="GetConsoleSessions",
)
async def get_console_sessions(project_id: str):
    try:
        return await KaliService.list_sessions(project_id)
    except Exception as e:
        print(f"Kali registry error: {e}", flush=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error listing console sessions",
        )

@router.post("/project/{project_id}/kali_client", response_model=KaliUser, operation_id="CreateKaliUser")
async def post_kali_user(project_id: str):
    try:
        return await KaliService.create_client(project_id)
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not create client",
        )

@router.get(
    "/project/{project_id}/kali/status",
    response_model=KaliStatusResponse,
    operation_id="GetProjectKaliStatus",
)
def get_project_kali_status(project_id: str):
    try:
        return KaliService.get_status(project_id)
    except Exception as e:
        print(f"Kali registry error: {e}", flush=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not get Kali status",
        )