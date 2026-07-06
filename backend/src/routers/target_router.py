from typing import List

from fastapi import APIRouter, HTTPException, status
from src.services import TargetService
from src.schemas import ResponseTarget, TargetBase

router = APIRouter()


@router.get(
    "/project/{project_id}/targets",
    response_model=List[ResponseTarget],
    operation_id="GetAllTargetsInProject",
)
def get_all_targets_in_project(project_id: str):
    try:
        return TargetService.get_all_targets(project_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not return all targets for project:{project_id}",
        )


@router.post("/project/{project_id}/target", response_model=ResponseTarget, operation_id="PostTarget")
def create_target(project_id: str, data: TargetBase):
    try:
        return TargetService.add_target(data.name, project_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not create target named {data.name}",
        )
        
@router.delete("/target/{target_id}", status_code=status.HTTP_204_NO_CONTENT, operation_id="DeleteTarget")
def delete_target(target_id: str):
    try:
        TargetService.delete_target(target_id)
        return
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not delete target: {target_id}",
        )
