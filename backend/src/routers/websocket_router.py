from typing import Union

from fastapi import APIRouter, HTTPException, WebSocket, status
from pydantic import BaseModel, RootModel
from src.websocket import ws_registry, OutboundTrafficUnion, InboundTrafficUnion

router = APIRouter()


@router.websocket("/client")
async def websocket_endpoint(websocket: WebSocket):
    try:
        await ws_registry.connect(websocket)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not start websocket connection",
        )


class InboundTraffic(RootModel):
    root: InboundTrafficUnion


class OutboundTraffic(RootModel):
    root: OutboundTrafficUnion


# 2. Reference the RootModels in your schema
class WebsocketTrafficSchema(BaseModel):
    inbound_traffic: InboundTraffic
    outbound_traffic: OutboundTraffic


# Dummy endpoint for easy type generation between backend and frontend
@router.get(
    "/_internal/ws-types",
    response_model=WebsocketTrafficSchema,
    tags=["_internal"],
    operation_id="wsTypes",
)
def ws_types_dummy():
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="This is a type generation bridge, not active API endpoint",
    )
