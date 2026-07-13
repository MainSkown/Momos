from fastapi import APIRouter, HTTPException, status
from src.schemas import KaliUser
from src.services import KaliService
router = APIRouter()

@router.get(
    "/kali_client/{client_id}", response_model=KaliUser, operation_id="KaliClientExists")
def get_kali_client(client_id: str):
    try:
        client = KaliService.get_client(client_id=client_id)
        if client is not None:
            return client
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Client does not exists with id: ${client_id}"
            )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not find client",
        )
        
@router.post("/project/{project_id}/kali_client", response_model=KaliUser, operation_id="CreateKaliUser")
def post_kali_user(project_id: str):
    try:
        return KaliService.create_client(project_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not create client",
        )