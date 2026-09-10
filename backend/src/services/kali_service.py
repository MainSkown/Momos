from src.schemas import KaliUser
from src.core.kali_integration import kali_user_registry


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
