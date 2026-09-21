import uuid
import asyncio
import logging
from typing import Dict, List, Optional, Tuple
from src.schemas import KaliCreationStage
from src.websocket import (
    ws_registry,
    WsTypes,
    SendCommandMessage,
    ReceiveCommandOutputMessage,
    CreatedKaliUserMessage,
    KaliCreationStageMessage,
    WebSocketError,
)
from .kali_registry import kali_registry

logger = logging.getLogger("momos.kali")


class KaliUserRegistry:
    def __init__(self):
        self.active_users: List[KaliUser] = []
        self.pending_users: Dict[uuid.UUID, str] = (
            {}
        )  # client_id -> project_id, in process of creation

    async def create_user(self, project_id: str) -> str:
        client_id = uuid.uuid4()
        self.pending_users[client_id] = project_id

        asyncio.create_task(self._create_user(project_id, client_id))

        return str(client_id)

    async def _create_user(self, project_id: str, client_id: uuid.UUID):
        try:
            user = await KaliUser.create(project_id, client_id)
        except Exception as e:
            # Without this, a failure here (e.g. Docker/package install error)
            # would leave the pending entry stuck forever with no way for the
            # frontend to find out - it would just wait on a message that never
            # arrives.
            logger.error(f"Failed to create Kali client for project {project_id}: {e}")
            self.pending_users.pop(client_id, None)
            kali_registry.clear_build_status(project_id)

            await ws_registry.send_message(
                CreatedKaliUserMessage(
                    project_id=project_id,
                    type=WsTypes.CreatedKaliUserMessage,
                    client_id=str(client_id),
                    error=WebSocketError(code="KaliCreationError", message=str(e)),
                )
            )
            return

        self.active_users.append(user)
        self.pending_users.pop(client_id, None)

        message = CreatedKaliUserMessage(
            project_id=project_id,
            type=WsTypes.CreatedKaliUserMessage,
            client_id=str(client_id),
        )

        await ws_registry.send_message(message)

    def get_client_for_project(
        self, project_id: str
    ) -> Optional[Tuple[uuid.UUID, bool]]:
        """Returns (client_id, pending) for the active or pending client
        belonging to project_id, or None if it has no Kali instance."""
        active = next(
            (u for u in self.active_users if u.project_id == project_id), None
        )
        if active is not None:
            return active.client_id, False

        pending_client_id = next(
            (cid for cid, pid in self.pending_users.items() if pid == project_id),
            None,
        )
        if pending_client_id is not None:
            return pending_client_id, True

        return None


kali_user_registry = KaliUserRegistry()


class KaliUser:
    def __init__(self, project_id: str, client_id: uuid.UUID):
        self.project_id = project_id
        self.client_id = client_id

    @classmethod
    async def create(cls, project_id: str, client_id: uuid.UUID):
        loop = asyncio.get_running_loop()

        def on_stage(stage: KaliCreationStage):
            # A plain dict write, safe to call directly from this executor
            # thread (protected by the GIL like any other CPython dict
            # mutation) - unlike the websocket send below, it doesn't need
            # the event loop. Persisted so a client that missed the live
            # KaliCreationStageMessage below (e.g. a page refresh mid-build)
            # can still recover current progress via
            # kali_registry.get_build_status.
            kali_registry.set_build_stage(project_id, stage, target_id=None)

            # Called from the executor thread running the (synchronous) Docker
            # setup - hop back onto the event loop to actually send it.
            asyncio.run_coroutine_threadsafe(
                ws_registry.send_message(
                    KaliCreationStageMessage(
                        project_id=project_id,
                        type=WsTypes.KaliCreationStage,
                        stage=stage,
                    )
                ),
                loop,
            )

        # Check/Get the manager async
        manager = await kali_registry.get_manager(project_id, on_stage=on_stage)
        kali_registry.clear_build_status(project_id)
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
