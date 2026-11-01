from typing import Optional

from pydantic import BaseModel
from sqlalchemy import Column, LargeBinary
from sqlmodel import SQLModel, Field


class OllamaConnectionSettingsBase(SQLModel):
    mode: str = "local"
    remote_url: str = ""
    remote_api_key_encrypted: Optional[bytes] = Field(default=None, sa_column=Column(LargeBinary))


class OllamaConnectionSettings(OllamaConnectionSettingsBase, table=True):
    # Singleton row - same reasoning as UserSettings.id; see
    # database_manager.py's get_ollama_connection_settings.
    id: int = Field(default=1, primary_key=True)


def ollama_connection_settings_factory() -> OllamaConnectionSettings:
    return OllamaConnectionSettings(
        mode="local",
        remote_url="",
        remote_api_key_encrypted=None,
    )


class OllamaConnectionPublic(BaseModel):
    # Never a remote_api_key* field - GET must never return the key itself,
    # only whether one is stored (see the Milestone 3 plan's Scope note 2).
    mode: str
    remote_url: str
    has_remote_api_key: bool


class OllamaConnectionUpdate(BaseModel):
    mode: str
    remote_url: str = ""
    remote_api_key: Optional[str] = None


class OllamaConnectionTestRequest(BaseModel):
    remote_url: str
    remote_api_key: Optional[str] = None


class OllamaConnectionTestResult(BaseModel):
    reachable: bool
    latency_ms: Optional[float] = None
    error: Optional[str] = None
