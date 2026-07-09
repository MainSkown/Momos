from pydantic import BaseModel
from typing import Literal, Type, Union
from enum import Enum

REGISTERED_WS_MESSAGES: list[Type[BaseModel]] = []

class WsTypes(str, Enum):
    "Every message type"
    WebSocketMessage = "WebSocketMessage"
    SendCommandMessage = "SendCommandMessage"
    ReceiveCommandOutputMessage = "ReceiveCommandOutputMessage"
    CreateUserKaliMessage = "CreateUserKaliMessage"

class WebSocketMessage(BaseModel):
    type: Literal[WsTypes.WebSocketMessage]

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        type_annotation = cls.__annotations__.get("type")
        # Check to ensure every new class has a different type
        if type_annotation is None or WsTypes.WebSocketMessage in str(type_annotation):
            raise TypeError(
                f"Class '{cls.__name__} must explicitly override the 'type' field'"
            )

        REGISTERED_WS_MESSAGES.append(cls)


class SendCommandMessage(WebSocketMessage):
    type: Literal[WsTypes.SendCommandMessage]
    command: str
    user: Literal["root", "momos"]


class ReceiveCommandOutputMessage(WebSocketMessage):
    type: Literal[WsTypes.ReceiveCommandOutputMessage]
    

class CreateUserKaliMessage(WebSocketMessage):
    type: Literal[WsTypes.CreateUserKaliMessage]
    project_id: str


# Must be at the end, filled on runtime
WebSocketTrafficUnion = Union[*REGISTERED_WS_MESSAGES]
