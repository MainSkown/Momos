from src.schemas.user_settings_scheme import UserSettings
from src.core.database_manager import db_manager


class UserSettingsService:
    @staticmethod
    def get_user_settings() -> UserSettings:
        return db_manager.get_user_settings()

    @staticmethod
    def update_user_settings(data: UserSettings) -> UserSettings:
        user_settings = UserSettings(**data.model_dump())
        return db_manager.update_user_settings(user_settings)
