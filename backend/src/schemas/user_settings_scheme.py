from sqlmodel import SQLModel, Field

from src.core.config import settings

ACCENT_COLOR_PRESETS = {"red", "blue", "green", "purple", "orange"}


class UserSettingsBase(SQLModel):
    notify_agent_finished: bool = False
    notify_vulnerability_found: bool = False
    notify_agent_paused: bool = False
    notify_agent_error: bool = False
    accent_color: str = "red"
    global_max_concurrent_agents: int = 1


class UserSettings(UserSettingsBase, table=True):
    # Singleton row - this is a single-user local app with no auth/account
    # concept, so there is deliberately only ever one row, pinned to a
    # fixed id rather than letting SQLModel default to a fresh uuid per
    # insert (which would make "the" row ambiguous the moment a second one
    # existed). See database_manager.py's get_user_settings for the
    # lazy-create-if-missing read that enforces there's ever only one.
    id: int = Field(default=1, primary_key=True)


def user_settings_factory() -> UserSettings:
    # global_max_concurrent_agents seeds from the current .env value so a
    # fresh install behaves exactly as it does today until someone changes
    # it in Settings - see run_registry.py's _global_agent_semaphore and
    # config.py's GLOBAL_MAX_CONCURRENT_AGENTS for the value this used to
    # be the ONLY source of truth for.
    return UserSettings(
        notify_agent_finished=False,
        notify_vulnerability_found=False,
        notify_agent_paused=False,
        notify_agent_error=False,
        accent_color="red",
        global_max_concurrent_agents=settings.GLOBAL_MAX_CONCURRENT_AGENTS,
    )
