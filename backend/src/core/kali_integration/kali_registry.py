import asyncio
from typing import Callable, Dict, Optional
from src.schemas import KaliCreationStage
from .kali_manager import KaliManger

class KaliRegistry:
    def __init__(self):
        self._active_managers: Dict[str, KaliManger] = {}
        self._lock = asyncio.Lock()

    async def get_manager(
        self,
        project_id: str,
        on_stage: Optional[Callable[[KaliCreationStage], None]] = None,
    ) -> KaliManger:
        async with self._lock:
            if project_id in self._active_managers.keys():
                return self._active_managers[project_id]

            manager = KaliManger(container_name=f"momos-kali-worker-{project_id}")
            await manager.start(on_stage=on_stage)

            self._active_managers[project_id] = manager
            return manager

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