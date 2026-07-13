import uuid
from typing import List
from src.websocket import (
    ws_registry,
    WsTypes,
    SendCommandMessage,
    ReceiveCommandOutputMessage,
    CreatedKaliUserMessage
)
from .kali_registry import kali_registry

def _send_created_message(project_id: str, client_id: str):
    message = CreatedKaliUserMessage(
        type=WsTypes.CreatedKaliUserMessage,
        client_id=client_id
    )
    
    ws_registry.send_message(project_id, message)

class KaliUserRegistry:
    def __init__(self):
        self.active_users: List[KaliUser] = []        

    async def create_user(self, project_id: str) -> str:        
        user = await KaliUser.create(project_id)
        self.active_users.append(user)
        
        # It may take some time to create user when container has to be created
        # Sending websocket message to make sure that user a) knows even if post req was broken
        _send_created_message(project_id, user.client_id)
        
        return user.client_id

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