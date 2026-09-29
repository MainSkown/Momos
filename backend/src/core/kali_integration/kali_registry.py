import asyncio
from dataclasses import dataclass
from typing import Callable, Dict, Optional
from src.schemas import KaliCreationStage
from src.websocket import ws_registry, WsTypes, KaliContainerActiveMessage
from src.core import db_manager, tool_groups
from .kali_manager import KaliManger


@dataclass
class KaliBuildStatus:
    stage: KaliCreationStage
    # The target whose run triggered this build, if any - None for a build
    # triggered by an explicit console connect (kali_user.py) rather than
    # an agent run (agent_service.py).
    target_id: Optional[str]


class KaliRegistry:
    def __init__(self):
        self._active_managers: Dict[str, KaliManger] = {}
        # Per-project build progress - set at the same on_stage closures
        # that already emit the live KaliCreationStageMessage (kali_user.py,
        # agent_service.py), so a client that missed those (e.g. a page
        # refresh mid-build) can still recover current progress via
        # get_build_status instead of only ever seeing "not building".
        self._build_status: Dict[str, KaliBuildStatus] = {}
        self._lock = asyncio.Lock()

    async def get_manager(
        self,
        project_id: str,
        on_stage: Optional[Callable[[KaliCreationStage], None]] = None,
    ) -> KaliManger:
        async with self._lock:
            if project_id in self._active_managers.keys():
                return self._active_managers[project_id]

            # Only reached once per project (every other call above hits
            # the cached-manager branch) - the one place that needs to know
            # which tool groups this project has enabled, so no other
            # get_manager caller needs a new parameter. A container that
            # already exists keeps whatever packages it was built with even
            # if enabled_tools changes later - by design, see
            # tool_groups.py/ProjectSettings.enabled_tools' own comments.
            loop = asyncio.get_running_loop()
            settings = await loop.run_in_executor(
                None, db_manager.get_project_settings, project_id
            )
            packages = tool_groups.packages_for_enabled_tools(
                settings.enabled_tools if settings else None
            )
            manager = KaliManger(
                container_name=f"momos-kali-worker-{project_id}", packages=packages
            )
            await manager.start(on_stage=on_stage)

            self._active_managers[project_id] = manager

        # Broadcast outside the lock (send_message doesn't need it, and
        # holding a lock across a websocket send is unnecessary). This is
        # the single chokepoint every trigger - an agent run, an explicit
        # console connect, or any Kali-using tool - goes through, unlike
        # CreatedKaliUserMessage which only fires for the console-connect
        # flow.
        await ws_registry.send_message(
            KaliContainerActiveMessage(
                project_id=project_id, type=WsTypes.KaliContainerActive
            )
        )
        return manager

    def has_manager(self, project_id: str) -> bool:
        return project_id in self._active_managers

    def set_build_stage(
        self, project_id: str, stage: KaliCreationStage, target_id: Optional[str] = None
    ) -> None:
        self._build_status[project_id] = KaliBuildStatus(stage=stage, target_id=target_id)

    def clear_build_status(self, project_id: str) -> None:
        self._build_status.pop(project_id, None)

    def get_build_status(self, project_id: str) -> Optional[KaliBuildStatus]:
        return self._build_status.get(project_id)

    async def get_manager_if_exists(self, project_id: str) -> Optional[KaliManger]:
        """Like get_manager, but never creates one - for cleanup paths (e.g.
        closing a target's sessions when its run ends) that shouldn't spin
        up a container just because a run is finishing."""
        async with self._lock:
            return self._active_managers.get(project_id)

    async def delete_manager(self, project_id: str):
        async with self._lock:
            manager = self._active_managers.pop(project_id, None)

        if manager is not None:
            await manager.stop()

    async def shutdown(self):
        async with self._lock:
            managers = list(self._active_managers.values())
            self._active_managers.clear()

        await asyncio.gather(
            *(manager.stop() for manager in managers),
            return_exceptions=True,
        )

kali_registry = KaliRegistry()