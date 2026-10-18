"""user_settings_router.py - GET/PUT over the singleton UserSettings row.
Mirrors test_project_router.py's style: TestClient(app) with
UserSettingsService mocked at the router's own call site via importlib
(the src.routers package re-export shadows the real submodule - see
test_project_router.py's own docstring for why a plain `from src.routers
import user_settings_router` would silently bind to the wrong object)."""

import importlib

from unittest.mock import MagicMock

from src.schemas import UserSettings

user_settings_router = importlib.import_module("src.routers.user_settings_router")


def user_settings_row(**overrides):
    fields = {
        "id": 1,
        "notify_agent_finished": False,
        "notify_vulnerability_found": False,
        "notify_agent_paused": False,
        "notify_agent_error": False,
        "accent_color": "red",
        "global_max_concurrent_agents": 1,
    }
    fields.update(overrides)
    return UserSettings(**fields)


def valid_put_body(**overrides):
    body = {
        "notify_agent_finished": True,
        "notify_vulnerability_found": False,
        "notify_agent_paused": False,
        "notify_agent_error": True,
        "accent_color": "blue",
        "global_max_concurrent_agents": 3,
    }
    body.update(overrides)
    return body


def test_get_user_settings_happy_path(api_client, monkeypatch):
    monkeypatch.setattr(
        user_settings_router.UserSettingsService,
        "get_user_settings",
        MagicMock(return_value=user_settings_row()),
    )
    response = api_client.get("/api/user-settings")
    assert response.status_code == 200
    assert response.json()["accent_color"] == "red"


def test_get_user_settings_error_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        user_settings_router.UserSettingsService,
        "get_user_settings",
        MagicMock(side_effect=RuntimeError("db down")),
    )
    response = api_client.get("/api/user-settings")
    assert response.status_code == 500


def test_update_user_settings_unknown_accent_color_returns_400(api_client, monkeypatch):
    mock_update = MagicMock()
    monkeypatch.setattr(
        user_settings_router.UserSettingsService, "update_user_settings", mock_update
    )
    response = api_client.put(
        "/api/user-settings", json=valid_put_body(accent_color="magenta")
    )
    assert response.status_code == 400
    mock_update.assert_not_called()


def test_update_user_settings_zero_concurrent_agents_returns_400(api_client, monkeypatch):
    mock_update = MagicMock()
    monkeypatch.setattr(
        user_settings_router.UserSettingsService, "update_user_settings", mock_update
    )
    response = api_client.put(
        "/api/user-settings", json=valid_put_body(global_max_concurrent_agents=0)
    )
    assert response.status_code == 400
    mock_update.assert_not_called()


def test_update_user_settings_negative_concurrent_agents_returns_400(api_client, monkeypatch):
    mock_update = MagicMock()
    monkeypatch.setattr(
        user_settings_router.UserSettingsService, "update_user_settings", mock_update
    )
    response = api_client.put(
        "/api/user-settings", json=valid_put_body(global_max_concurrent_agents=-3)
    )
    assert response.status_code == 400
    mock_update.assert_not_called()


def test_update_user_settings_happy_path(api_client, monkeypatch):
    mock_update = MagicMock(return_value=user_settings_row(accent_color="blue"))
    monkeypatch.setattr(
        user_settings_router.UserSettingsService, "update_user_settings", mock_update
    )
    body = valid_put_body()
    response = api_client.put("/api/user-settings", json=body)
    assert response.status_code == 200
    assert response.json()["accent_color"] == "blue"

    mock_update.assert_called_once()
    (called_with,) = mock_update.call_args.args
    assert called_with.accent_color == "blue"
    assert called_with.global_max_concurrent_agents == 3


def test_update_user_settings_service_error_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        user_settings_router.UserSettingsService,
        "update_user_settings",
        MagicMock(side_effect=RuntimeError("db write failed")),
    )
    response = api_client.put("/api/user-settings", json=valid_put_body())
    assert response.status_code == 500
