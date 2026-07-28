from typing import Dict, List, Callable, Awaitable, TypeVar
from fastapi import WebSocket
from pydantic import TypeAdapter, ValidationError
from src.websocket import (
    WebSocketMessage,
    InboundTrafficUnion,
    OutboundTrafficUnion,
    WsTypes,
)
import asyncio

TMessage = TypeVar("TMessage", bound=WebSocketMessage)


class WebSocketRegistry:
    def __init__(self):
        self.active_sockets: List[WebSocket] = []

        # Global hooks { message_type: [callbacks(project_id, message)] } }
        self.hooks: Dict[
            WsTypes, List[Callable[[WebSocketMessage], Awaitable[None]]]
        ] = {}

        self.inbound_message_adapter = TypeAdapter(InboundTrafficUnion)

    def add_global_hook(
        self,
        message_type: WsTypes,
        callback: Callable[[TMessage], Awaitable[None]],
    ):
        if message_type not in self.global_hooks:
            self.hooks[message_type] = []

        self.hooks[message_type].append(callback)

    # Discontinued: changed websockets to be global
    # def add_project_hook(
    # self,
    # project_id: str,
    # message_type: WsTypes,
    # callback: Callable[[str, TMessage], Awaitable[None]],
    # ):
    #     """Register an async function to trigger for a SPECIFIC project and message type."""
    #     # Keep only one active callback per project and message type.
    #     # This prevents duplicate handlers after reconnects or page refreshes.
    #     if project_id not in self.project_hooks:
    #         self.project_hooks[project_id] = {}

    #     self.project_hooks[project_id][message_type] = [callback]

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_sockets.append(websocket)

        try:
            async for raw_data in websocket.iter_text():
                try:
                    message = self.inbound_message_adapter.validate_json(raw_data)
                    print(f"Got message: {message}")

                    # Look up global hooks
                    handlers = self.hooks.get(message.type, [])

                    for handler in handlers:                        
                        asyncio.create_task(handler(message))

                except ValidationError as e:
                    print(f"Invalid message format received: {e}")
                except Exception as e:
                    print(f"Error executing hook for: {e}")

        finally:
            print(f"Client disconnected.")
            self.disconnect(websocket)

    def disconnect(self, websocket: WebSocket):
        """Clean up the socket and optionally the hooks."""
        if websocket in self.active_sockets:
            self.active_sockets.remove(websocket)

    # def remove_hooks(self, project_id: str):
    #     """Clean up hooks if not used anymore"""
    #     if project_id in self.project_hooks:
    #         del self.project_hooks[project_id]


async def send_message(self, message: OutboundTrafficUnion):
    message_json = message.model_dump_json()

    async def _send_to_single_client(websocket):
        if not websocket:
            return

        try:
            await websocket.send_text(message_json)
        except Exception as e:
            # Safely get the client info just in case
            client_info = getattr(websocket, "client", "Unknown Client")
            print(f"Connection lost while sending to {client_info}: {e}")
            self.disconnect(websocket)

    tasks = [_send_to_single_client(ws) for ws in list(self.active_sockets)]

    if tasks:
        # Run all sends simultaneously
        await asyncio.gather(*tasks)


ws_registry = WebSocketRegistry()
