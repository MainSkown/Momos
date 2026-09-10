from pydantic import BaseModel
from typing import Optional
from enum import Enum

class KaliUser(BaseModel):
    client_id: str
    pending: Optional[bool] = None


class KaliCreationStage(str, Enum):
    """Stages the Kali worker container goes through on first creation for a
    project. Reported over websocket so the frontend can show real progress
    instead of a generic "connecting" message during the (often multi-minute)
    package installation."""

    checking_container = "checking_container"
    starting_container = "starting_container"
    updating_packages = "updating_packages"
    installing_packages = "installing_packages"
    creating_user = "creating_user"

    def __str__(self) -> str:
        return self.value