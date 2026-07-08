import asyncio
from typing import Dict
from .kali_manager import KaliManger

class KaliRegistry:
    def __init__(self):
        self._active_managers: Dict[str, KaliManger] = {}
        self._lock = asyncio.Lock()

    async def get_manager(self, project_id: str) -> KaliManger:
        async with self._lock:
            if project_id in self._active_managers:
                return self._active_managers[project_id]

            manager = KaliManger(container_name=f"momos-kali-worker-{project_id}")
            await manager.start()
            
            self._active_managers[project_id] = manager
            return manager

    async def delete_manager(self, project_id: str):
        async with self._lock:
            if project_id in self._active_managers:
                manager = self._active_managers[project_id]
                await manager.stop()
                del self._active_managers[project_id]

kali_registry = KaliRegistry()