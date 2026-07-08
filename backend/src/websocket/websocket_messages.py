from pydantic import BaseModel
from typing import Literal, Type, Union

REGISTERED_WS_MESSAGES: list[Type[BaseModel]] = []


class WebSocketMessage(BaseModel):
    type: Literal["WebsocketMessage"] = "WebsocketMessage"

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        type_annotation = cls.__annotations__.get("type")
        # Check to ensure every new class has a different type
        if type_annotation is None or "WebsocketMessage" in str(type_annotation):
            raise TypeError(
                f"Class '{cls.__name__} must explicitly override the 'type' field'"
            )

        REGISTERED_WS_MESSAGES.append(cls)


class SendCommandMessage(WebSocketMessage):
    type: Literal["SendCommandMessage"] = "SendCommandMessage"

    command: str
    user: Literal["root", "momos"]


class ReceiveCommandOutputMessage(WebSocketMessage):
    type: Literal["ReceiveCommandOutputMessage"] = "ReceiveCommandOutputMessage"
    output: str


# Must be at the end, filled on runtime
WebSocketTrafficUnion = Union[*REGISTERED_WS_MESSAGES]
