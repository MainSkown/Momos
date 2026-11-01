"""connection_router.py - see docs/plans/milestone-3-remote-ollama-connection.md's
O3 section. ConnectionService is mocked at the router's own call site; the
exception->status mapping is what these tests pin down."""

import importlib
from unittest.mock import AsyncMock

from src.schemas import OllamaConnectionPublic, OllamaConnectionTestResult
from src.utils.exceptions import (
    ConnectionSwitchBlockedException,
    EncryptionKeyMissingException,
)

connection_router = importlib.import_module("src.routers.connection_router")
ConnectionService = connection_router.ConnectionService

LOCAL_CONNECTION = OllamaConnectionPublic(
    mode="local", remote_url="", has_remote_api_key=False
)
REMOTE_CONNECTION = OllamaConnectionPublic(
    mode="remote", remote_url="https://ollama.example.com", has_remote_api_key=True
)
UPDATE_BODY = {"mode": "remote", "remote_url": "https://ollama.example.com", "remote_api_key": "sk-test"}


def test_get_connection_returns_service_result(api_client, monkeypatch):
    monkeypatch.setattr(ConnectionService, "get_connection", lambda: REMOTE_CONNECTION)
    response = api_client.get("/api/ollama/connection")
    assert response.status_code == 200
    assert response.json() == REMOTE_CONNECTION.model_dump()


def test_put_connection_returns_saved_connection(api_client, monkeypatch):
    mock_save = AsyncMock(return_value=REMOTE_CONNECTION)
    monkeypatch.setattr(ConnectionService, "save_connection", mock_save)
    response = api_client.put("/api/ollama/connection", json=UPDATE_BODY)
    assert response.status_code == 200
    assert response.json() == REMOTE_CONNECTION.model_dump()
    passed_update = mock_save.call_args.args[0]
    assert passed_update.mode == "remote"
    assert passed_update.remote_api_key == "sk-test"


def test_put_connection_value_error_returns_400(api_client, monkeypatch):
    monkeypatch.setattr(
        ConnectionService,
        "save_connection",
        AsyncMock(side_effect=ValueError("remote_url is required when mode is 'remote'.")),
    )
    response = api_client.put("/api/ollama/connection", json=UPDATE_BODY)
    assert response.status_code == 400
    assert "remote_url is required" in response.json()["detail"]


def test_put_connection_encryption_key_missing_returns_500_naming_env_var(api_client, monkeypatch):
    monkeypatch.setattr(
        ConnectionService,
        "save_connection",
        AsyncMock(side_effect=EncryptionKeyMissingException("APP_ENCRYPTION_KEY is not set")),
    )
    response = api_client.put("/api/ollama/connection", json=UPDATE_BODY)
    assert response.status_code == 500
    assert "APP_ENCRYPTION_KEY" in response.json()["detail"]


def test_put_connection_switch_blocked_returns_409_with_running_count(api_client, monkeypatch):
    monkeypatch.setattr(
        ConnectionService,
        "save_connection",
        AsyncMock(
            side_effect=ConnectionSwitchBlockedException(
                "Cannot switch connection while agents are running.", running_count=3
            )
        ),
    )
    response = api_client.put("/api/ollama/connection", json=UPDATE_BODY)
    assert response.status_code == 409
    assert "3" in response.json()["detail"]


def test_post_connection_test_returns_reachable_result(api_client, monkeypatch):
    result = OllamaConnectionTestResult(reachable=True, latency_ms=42.5)
    monkeypatch.setattr(ConnectionService, "test_connection", AsyncMock(return_value=result))
    response = api_client.post(
        "/api/ollama/connection/test",
        json={"remote_url": "https://ollama.example.com", "remote_api_key": "sk-test"},
    )
    assert response.status_code == 200
    assert response.json() == {"reachable": True, "latency_ms": 42.5, "error": None}


def test_post_connection_test_unreachable_is_still_200(api_client, monkeypatch):
    result = OllamaConnectionTestResult(
        reachable=False, error="connection refused or host unreachable"
    )
    mock_test = AsyncMock(return_value=result)
    monkeypatch.setattr(ConnectionService, "test_connection", mock_test)
    response = api_client.post(
        "/api/ollama/connection/test", json={"remote_url": "https://down.example.com"}
    )
    assert response.status_code == 200
    assert response.json()["reachable"] is False
    mock_test.assert_awaited_once_with("https://down.example.com", None)
