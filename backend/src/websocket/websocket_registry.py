from typing import Dict, List, Callable, Awaitable, TypeVar
from fastapi import WebSocket
from pydantic import TypeAdapter, ValidationError
from src.websocket import WebSocketMessage, InboundTrafficUnion, OutboundTrafficUnion, WsTypes
import asyncio

TMessage = TypeVar("TMessage", bound=WebSocketMessage)


class WebSocketRegistry:
    def __init__(self):
        self.active_sockets: Dict[str, WebSocket] = {}

        # Global hooks, mainly used for creating stuff { message_type: [callbacks(project_id, message)] } }
        self.global_hooks: Dict[
            WsTypes, List[Callable[[str, WebSocketMessage], Awaitable[None]]]
        ] = {}

        # Nested Dictionary: { project_id: { message_type: [callbacks(project_id, message)] } }
        self.project_hooks: Dict[
            str, Dict[WsTypes, List[Callable[[str, WebSocketMessage], Awaitable[None]]]]
        ] = {}

        self.inbound_message_adapter = TypeAdapter(InboundTrafficUnion)
        
    def add_global_hook(
        self,
        message_type: WsTypes,
        callback: Callable[[str, TMessage], Awaitable[None]]
    ):
        if message_type not in self.global_hooks:
            self.global_hooks[message_type] = []
        
        self.global_hooks[message_type].append(callback)

    def add_project_hook(
    self,
    project_id: str,
    message_type: WsTypes,
    callback: Callable[[str, TMessage], Awaitable[None]],
    ):
        """Register an async function to trigger for a SPECIFIC project and message type."""
        # Keep only one active callback per project and message type.
        # This prevents duplicate handlers after reconnects or page refreshes.
        if project_id not in self.project_hooks:
            self.project_hooks[project_id] = {}

        self.project_hooks[project_id][message_type] = [callback]

    async def connect(self, project_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_sockets[project_id] = websocket

        try:
            async for raw_data in websocket.iter_text():
                try:
                    message = self.inbound_message_adapter.validate_json(raw_data)
                    print(f"Got message: {message}")
                    
                    # Look up global hooks
                    global_handlers = self.global_hooks.get(message.type, [])
                    
                    for handler in global_handlers:
                        # We still want to know from which project the message came from
                        asyncio.create_task(handler(project_id, message))
                    

                    # Look up hooks ONLY for this specific project
                    project_hooks = self.project_hooks.get(project_id, {})
                    handlers = project_hooks.get(message.type, [])

                    for handler in handlers:
                        asyncio.create_task(handler(project_id, message))

                except ValidationError as e:
                    print(f"Invalid message format received: {e}")
                except Exception as e:
                    print(f"Error executing hook for {project_id}: {e}")

        finally:
            print(f"Client {project_id} disconnected.")
            self.disconnect(project_id)

    def disconnect(self, project_id: str):
        """Clean up the socket and optionally the hooks."""
        if project_id in self.active_sockets:
            del self.active_sockets[project_id]

    def remove_hooks(self, project_id: str):
        """Clean up hooks if not used anymore"""
        if project_id in self.project_hooks:
            del self.project_hooks[project_id]

    async def send_message(self, project_id: str, message: OutboundTrafficUnion):
        websocket = self.active_sockets.get(project_id)
        if not websocket:
            print(f"Cannot send message: No active connection for {project_id}")
            return

        try:
            await websocket.send_text(message.model_dump_json())
        except Exception as e:
            print(f"Connection lost while sending to {project_id}: {e}")
            self.disconnect(project_id)

ws_registry = WebSocketRegistry()
