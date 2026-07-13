from src.schemas import KaliUser
from src.core.kali_integration import kali_user_registry
import asyncio


class KaliService:
    @staticmethod
    def get_client(client_id: str) -> KaliUser | None:
        client = next(
            (u for u in kali_user_registry.active_users if u.client_id == client_id),
            None,
        )
        
        if client is not None:
            return KaliUser(client_id=client.client_id)
        else:
            return None
        
    @staticmethod
    async def create_client(project_id: str) -> KaliUser:
        client_id = await kali_user_registry.create_user(project_id)
        return KaliUser(client_id)
