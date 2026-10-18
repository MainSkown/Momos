from src.schemas.user_settings_scheme import user_settings_factory


def test_factory_defaults_every_notification_flag_to_false():
    settings = user_settings_factory()

    assert settings.notify_agent_finished is False
    assert settings.notify_vulnerability_found is False
    assert settings.notify_agent_paused is False
    assert settings.notify_agent_error is False


def test_factory_defaults_accent_color_to_red():
    assert user_settings_factory().accent_color == "red"


def test_factory_reads_global_max_concurrent_agents_from_live_settings(monkeypatch):
    monkeypatch.setattr(
        "src.schemas.user_settings_scheme.settings.GLOBAL_MAX_CONCURRENT_AGENTS", 4
    )

    assert user_settings_factory().global_max_concurrent_agents == 4


def test_factory_matches_current_config_value_when_unpatched():
    from src.core.config import settings as live_settings

    assert (
        user_settings_factory().global_max_concurrent_agents
        == live_settings.GLOBAL_MAX_CONCURRENT_AGENTS
    )
