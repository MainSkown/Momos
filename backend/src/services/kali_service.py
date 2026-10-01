from typing import List
from src.schemas import KaliUser, KaliStatusResponse, ConsoleSessionInfo
from src.core.kali_integration import kali_user_registry, kali_registry


class KaliService:
    @staticmethod
    def get_client(client_id: str) -> KaliUser | None:
        client = next(
            (
                u
                for u in kali_user_registry.active_users
                if str(u.client_id) == client_id
            ),
            None,
        )
        if client is not None:
            return KaliUser(client_id=str(client.client_id))

        pending = next(
            (id for id in kali_user_registry.pending_users if str(id) == client_id),
            None,
        )
        if pending is not None:
            return KaliUser(client_id=str(pending), pending=True)

        return None

    @staticmethod
    def get_client_for_project(project_id: str) -> KaliUser | None:
        result = kali_user_registry.get_client_for_project(project_id)
        if result is None:
            return None

        client_id, pending = result
        return KaliUser(client_id=str(client_id), pending=pending)

    @staticmethod
    async def create_client(project_id: str) -> KaliUser:
        client_id = await kali_user_registry.create_user(project_id)
        return KaliUser(client_id=client_id)

    @staticmethod
    async def list_sessions(project_id: str) -> List[ConsoleSessionInfo]:
        """Live console-session state for reload recovery - KaliManger.
        sessions is the only source of truth (in-memory, same as the
        agent's own sessions - nothing here is persisted to the DB), so
        this is a live read, not a query. Empty (not an error) whenever
        the project has no active console client at all."""
        user = kali_user_registry.get_active_user_for_project(project_id)
        if user is None:
            return []
        sessions = await user.list_sessions()
        return [ConsoleSessionInfo(name=s.name, user=s.user) for s in sessions]

    @staticmethod
    def get_status(project_id: str) -> KaliStatusResponse:
        build_status = kali_registry.get_build_status(project_id)
        return KaliStatusResponse(
            active=kali_registry.has_manager(project_id),
            building=build_status is not None,
            stage=build_status.stage if build_status else None,
            target_id=build_status.target_id if build_status else None,
        )
