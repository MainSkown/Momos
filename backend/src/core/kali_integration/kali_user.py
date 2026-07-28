import uuid
import asyncio
from typing import List
from src.websocket import (
    ws_registry,
    WsTypes,
    SendCommandMessage,
    ReceiveCommandOutputMessage,
    CreatedKaliUserMessage,
    WebSocketError,
)
from .kali_registry import kali_registry


class KaliUserRegistry:
    def __init__(self):
        self.active_users: List[KaliUser] = []
        self.pending_users: List[uuid.UUID] = (
            []
        )  # List of pending users - in process of creation

    async def create_user(self, project_id: str) -> str:
        client_id = uuid.uuid4()
        self.pending_users.append(client_id)

        asyncio.create_task(self._create_user(project_id, client_id))

        return str(client_id)

    async def _create_user(self, project_id: str, client_id: uuid.UUID):
        user = await KaliUser.create(project_id, client_id)

        self.active_users.append(user)
        self.pending_users.remove(client_id)

        message = CreatedKaliUserMessage(
            project_id=project_id,
            type=WsTypes.CreatedKaliUserMessage,
            client_id=str(client_id),
        )

        await ws_registry.send_message(message)


kali_user_registry = KaliUserRegistry()


class KaliUser:
    def __init__(self, project_id: str, client_id: uuid.UUID):
        self.project_id = project_id
        self.client_id = client_id

    @classmethod
    async def create(cls, project_id: str, client_id: uuid.UUID):
        # Check/Get the manager async
        manager = await kali_registry.get_manager(project_id)
        if not manager:
            raise RuntimeError(
                f"Could not create Kali Manager for project: {project_id}"
            )

        instance = cls(project_id, client_id)

        # Attach project-scoped hooks
        ws_registry.add_hook(
            WsTypes.SendCommandMessage, instance._send_command_hook
        )

        return instance

    async def _send_command_hook(self, message: SendCommandMessage):
        project_id = message.project_id
        
        if project_id != self.project_id:
            raise RuntimeError(
                "Tried to run command in different project, than user was created for."
            )

        manager = await kali_registry.get_manager(project_id)
        try:
            result = await manager.execute(message.command, message.user)
        except Exception as e:
            output_message = ReceiveCommandOutputMessage(
                project_id=project_id,
                type=WsTypes.ReceiveCommandOutputMessage,
                output="",
                error=WebSocketError(code="CommandError", message=str(e)),
            )
            await ws_registry.send_message(output_message)
            return

        output_message = ReceiveCommandOutputMessage(
            project_id=project_id,
            type=WsTypes.ReceiveCommandOutputMessage,
            output=result,
        )

        await ws_registry.send_message(output_message)
