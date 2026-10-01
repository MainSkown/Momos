from pydantic import BaseModel
from typing import Literal, Optional
from enum import Enum

class KaliUser(BaseModel):
    client_id: str
    pending: Optional[bool] = None


class ConsoleSessionInfo(BaseModel):
    """One active User Console session - see kali_user.py's
    CONSOLE_TARGET_ID/create_session. name carries the "root-"/"momos-"
    prefix create_session assigns (e.g. "root-1") to stay unique within
    the shared console namespace, and is also what SendCommandMessage.
    session/CloseConsoleSessionMessage.session expect - the frontend
    strips the prefix itself before using it as the tab label."""

    name: str
    user: Literal["root", "momos"]


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
    verifying_setup = "verifying_setup"

    def __str__(self) -> str:
        return self.value


class KaliStatusResponse(BaseModel):
    """Current Kali container state for a project - active reflects the
    real container-level registry (KaliRegistry), not just the client/
    session-level concept KaliUser/GetProjectKaliClient track, so it stays
    accurate regardless of whether the container was started by an
    explicit console connect or by an agent run."""

    active: bool
    building: bool
    stage: Optional[KaliCreationStage] = None
    target_id: Optional[str] = None