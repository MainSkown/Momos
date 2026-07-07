import threading
from .kali_manager import KaliManger


class KaliRegistry:
    _instance = None
    _lock = threading.Lock()
    _active_managers: dict[str, KaliManger] = {}

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(KaliRegistry, cls).__new__(cls)
                    cls._instance._active_managers = {}

    async def get_manager(self, project_id: str) -> KaliManger:
        if project_id in self._active_managers:
            return self._active_managers[project_id]

        manager = KaliManger(container_name=f"momos-kali-worker-{project_id}")
        
        self._active_managers[project_id] = manager
        await manager.start()
        
        return manager

    async def delete_manager(self, project_id: str):
        if project_id in self._active_managers:
            manager = self._active_managers[project_id]
            await manager.stop()
            del self._active_managers[project_id]
