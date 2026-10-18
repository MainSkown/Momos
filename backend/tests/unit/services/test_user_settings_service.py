import pytest

from src.schemas.user_settings_scheme import UserSettings
from src.services.user_settings_service import UserSettingsService


@pytest.fixture
def service_db(monkeypatch, fake_db_manager):
    monkeypatch.setattr("src.services.user_settings_service.db_manager", fake_db_manager)
    return fake_db_manager


def test_get_user_settings_delegates_to_db_manager(service_db):
    expected = UserSettings(accent_color="blue")
    service_db.get_user_settings.return_value = expected

    result = UserSettingsService.get_user_settings()

    service_db.get_user_settings.assert_called_once_with()
    assert result is expected


def test_update_user_settings_forwards_a_user_settings_instance(service_db):
    service_db.update_user_settings.side_effect = lambda settings: settings
    data = UserSettings(accent_color="blue", global_max_concurrent_agents=4)

    UserSettingsService.update_user_settings(data)

    forwarded = service_db.update_user_settings.call_args.args[0]
    assert isinstance(forwarded, UserSettings)
    assert forwarded.model_dump() == data.model_dump()


def test_update_user_settings_returns_what_db_manager_returns(service_db):
    saved = UserSettings(accent_color="green")
    service_db.update_user_settings.return_value = saved
    data = UserSettings(accent_color="blue")

    result = UserSettingsService.update_user_settings(data)

    assert result is saved
