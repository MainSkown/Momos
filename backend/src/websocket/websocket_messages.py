from pydantic import BaseModel
from typing import Literal, Optional, Type, Union
from enum import Enum
from src.schemas import OllamaDownloadProgress

# Separate registries for cleaner typing definitions
REGISTERED_INBOUND_MESSAGES: list[Type[BaseModel]] = []
REGISTERED_OUTBOUND_MESSAGES: list[Type[BaseModel]] = []

class WsTypes(str, Enum):
    WebSocketMessage = "WebSocketMessage"
    SendCommandMessage = "SendCommandMessage"
    ReceiveCommandOutputMessage = "ReceiveCommandOutputMessage"
    CreatedKaliUserMessage = "CreatedKaliUserMessage"
    ModelPullingUpdate = "ModelPullingUpdate"
    OllamaDownloadProgress = "OllamaDownloadProgress"
    
class WebSocketMessage(BaseModel):
    type: Literal[WsTypes.WebSocketMessage]

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        
        type_annotation = cls.__annotations__.get("type")
        if type_annotation is None or WsTypes.WebSocketMessage in str(type_annotation):
            raise TypeError(
                f"Class '{cls.__name__}' must explicitly override the 'type' field"
            )
            
# --- Errors ---
class WebSocketError(BaseModel):
    code: str
    message: Optional[str]    

# --- Directional Base Classes ---

class InboundMessage(WebSocketMessage):
    type: Literal['InboundMessage']
    """Messages sent from CLIENT -> SERVER"""
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        REGISTERED_INBOUND_MESSAGES.append(cls)

class OutboundMessage(WebSocketMessage):
    type: Literal['OutboundMessage']
    error: Optional[WebSocketError] = None
    
    """Messages sent from SERVER -> CLIENT"""
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        REGISTERED_OUTBOUND_MESSAGES.append(cls)

# --- Inbound Subclasses (Client Sends) ---

class SendCommandMessage(InboundMessage):
    project_id: str
    type: Literal[WsTypes.SendCommandMessage]
    command: str
    user: Literal["root", "momos"]

# --- Outbound Subclasses (Server Sends) ---

class ReceiveCommandOutputMessage(OutboundMessage):
    project_id: str
    type: Literal[WsTypes.ReceiveCommandOutputMessage]
    output: str
    
class CreatedKaliUserMessage(OutboundMessage):
    project_id: str
    type: Literal[WsTypes.CreatedKaliUserMessage]
    client_id: str
    
class ModelPullingUpdate(OutboundMessage):
    type: Literal[WsTypes.ModelPullingUpdate]
    progress: OllamaDownloadProgress

# --- Union Typings ---
#! Must be at the end of this file - filled on run
InboundTrafficUnion = Union[*REGISTERED_INBOUND_MESSAGES]
OutboundTrafficUnion = Union[*REGISTERED_OUTBOUND_MESSAGES]