from pydantic import BaseModel
from typing import Literal, Type, Union
from enum import Enum

# Separate registries for cleaner typing definitions
REGISTERED_INBOUND_MESSAGES: list[Type[BaseModel]] = []
REGISTERED_OUTBOUND_MESSAGES: list[Type[BaseModel]] = []

class WsTypes(str, Enum):
    WebSocketMessage = "WebSocketMessage"
    SendCommandMessage = "SendCommandMessage"
    ReceiveCommandOutputMessage = "ReceiveCommandOutputMessage"
    CreateUserKaliMessage = "CreateUserKaliMessage"
    UserKaliCreatedMessage = "UserKaliCreatedMessage"

class WebSocketMessage(BaseModel):
    type: Literal[WsTypes.WebSocketMessage]

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        
        type_annotation = cls.__annotations__.get("type")
        if type_annotation is None or WsTypes.WebSocketMessage in str(type_annotation):
            raise TypeError(
                f"Class '{cls.__name__}' must explicitly override the 'type' field"
            )

# --- Directional Base Classes ---

class InboundMessage(WebSocketMessage):
    type: Literal['InboundMessage']
    """Messages sent from CLIENT -> SERVER"""
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        REGISTERED_INBOUND_MESSAGES.append(cls)

class OutboundMessage(WebSocketMessage):
    type: Literal['OutboundMessage']
    """Messages sent from SERVER -> CLIENT"""
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        REGISTERED_OUTBOUND_MESSAGES.append(cls)

# --- Inbound Subclasses (Client Sends) ---

class SendCommandMessage(InboundMessage):
    type: Literal[WsTypes.SendCommandMessage]
    command: str
    user: Literal["root", "momos"]

class CreateUserKaliMessage(InboundMessage):
    type: Literal[WsTypes.CreateUserKaliMessage]
    project_id: str

# --- Outbound Subclasses (Server Sends) ---

class ReceiveCommandOutputMessage(OutboundMessage):
    type: Literal[WsTypes.ReceiveCommandOutputMessage]
    output: str

class UserKaliCreatedMessage(OutboundMessage):
    type: Literal[WsTypes.UserKaliCreatedMessage]
    client_id: str

# --- Union Typings ---
#! Must be at the end of this file - filled on run
InboundTrafficUnion = Union[*REGISTERED_INBOUND_MESSAGES]
OutboundTrafficUnion = Union[*REGISTERED_OUTBOUND_MESSAGES]