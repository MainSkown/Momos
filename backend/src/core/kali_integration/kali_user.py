import uuid
from typing import List
from src.websocket import (
    ws_registry,
    WsTypes,
    CreateUserKaliMessage,
    SendCommandMessage,
    ReceiveCommandOutputMessage,
    UserKaliCreatedMessage,
)
from .kali_registry import kali_registry


class KaliUserRegistry:
    def __init__(self):
        self.active_users: List[KaliUser] = []
        
        ws_registry.add_global_hook(
            WsTypes.CreateUserKaliMessage, self._create_user_callback
        )

    async def _create_user_callback(self, project_id: str, message: CreateUserKaliMessage):
        if project_id != message.project_id:
            raise RuntimeError(
                "Tried to create user with different project id, than socket was set for."
            )

        user = await KaliUser.create(message.project_id)
        self.active_users.append(user)


kali_user_registry = KaliUserRegistry()


class KaliUser:
    def __init__(self, project_id: str, client_id: uuid.UUID):
        self.project_id = project_id
        self.client_id = client_id

    @classmethod
    async def create(cls, project_id: str):
        # Check/Get the manager async
        manager = await kali_registry.get_manager(project_id)
        if not manager:
            raise RuntimeError(
                f"Could not create Kali Manager for project: {project_id}"
            )

        client_id = uuid.uuid4()
        instance = cls(project_id, client_id)

        # Attach project-scoped hooks
        ws_registry.add_project_hook(
            project_id, WsTypes.SendCommandMessage, instance._send_command_hook
        )

        # Send the confirmation message back to the frontend
        message = UserKaliCreatedMessage(
            type=WsTypes.UserKaliCreatedMessage, client_id=client_id
        )
        await ws_registry.send_message(project_id, message)

        return instance

    async def _send_command_hook(self, project_id: str, message: SendCommandMessage):
        if project_id != self.project_id:
            raise RuntimeError(
                "Tried to run command in different project, than user was created for."
            )

        manager = await kali_registry.get_manager(project_id)
        result = await manager.execute(message.command, message.user)

        output_message = ReceiveCommandOutputMessage(
            type=WsTypes.ReceiveCommandOutputMessage, output=result
        )

        await ws_registry.send_message(self.project_id, output_message)