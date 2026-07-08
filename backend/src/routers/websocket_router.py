from fastapi import APIRouter, HTTPException, WebSocket, status
from pydantic import BaseModel
from src.websocket import ws_registry, WebSocketTrafficUnion
from typing import List

router = APIRouter()


@router.websocket("/{project_id}")
async def websocket_endpoint(project_id: str, websocket: WebSocket):
    try:
        ws_registry.connect(project_id, websocket)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not start websocket connection",
        )


class WebsocketTraffic(BaseModel):
    items: List[WebSocketTrafficUnion]


# Dummy endpoint for easy type generation between backend and frontend
@router.get(
    "/_internal/ws-types",
    response_model=WebsocketTraffic,
    tags=["_internal"],
    operation_id="wsTypes",
)
def ws_types_dummy() -> list[WebSocketTrafficUnion]:
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="This is a type generation bridge, not active API endpoint",
    )
