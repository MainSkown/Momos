"""scope_discovery_router.py - POST /project/{project_id}/scope/discover.
Mirrors target_router.py's own exception-to-status-code test convention:
drive TestClient(app) with ScopeDiscoveryService mocked at the router's
own call site, never a real Docker/Kali container."""

import importlib
import uuid
from unittest.mock import AsyncMock

from src.schemas.project_scheme import DiscoveredHost
from src.utils.exceptions import ProjectDoesNotExistException

scope_discovery_router = importlib.import_module("src.routers.scope_discovery_router")

PROJECT_ID = str(uuid.uuid4())


def test_discover_hosts_happy_path(api_client, monkeypatch):
    monkeypatch.setattr(
        scope_discovery_router.ScopeDiscoveryService,
        "discover_hosts",
        AsyncMock(
            return_value=[
                DiscoveredHost(host="10.0.0.1", in_scope=True),
                DiscoveredHost(host="10.0.0.9", in_scope=False),
            ]
        ),
    )

    response = api_client.post(f"/api/project/{PROJECT_ID}/scope/discover")

    assert response.status_code == 200
    assert response.json() == [
        {"host": "10.0.0.1", "in_scope": True},
        {"host": "10.0.0.9", "in_scope": False},
    ]


def test_discover_hosts_empty_result_is_an_empty_list_not_an_error(api_client, monkeypatch):
    monkeypatch.setattr(
        scope_discovery_router.ScopeDiscoveryService,
        "discover_hosts",
        AsyncMock(return_value=[]),
    )

    response = api_client.post(f"/api/project/{PROJECT_ID}/scope/discover")

    assert response.status_code == 200
    assert response.json() == []


def test_discover_hosts_unknown_project_returns_404(api_client, monkeypatch):
    monkeypatch.setattr(
        scope_discovery_router.ScopeDiscoveryService,
        "discover_hosts",
        AsyncMock(
            side_effect=ProjectDoesNotExistException(
                f"Project does not exist: {PROJECT_ID}", PROJECT_ID
            )
        ),
    )

    response = api_client.post(f"/api/project/{PROJECT_ID}/scope/discover")

    assert response.status_code == 404


def test_discover_hosts_kali_execution_failure_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        scope_discovery_router.ScopeDiscoveryService,
        "discover_hosts",
        AsyncMock(side_effect=RuntimeError("nmap exited with status 1")),
    )

    response = api_client.post(f"/api/project/{PROJECT_ID}/scope/discover")

    assert response.status_code == 500


def test_discover_hosts_unexpected_error_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        scope_discovery_router.ScopeDiscoveryService,
        "discover_hosts",
        AsyncMock(side_effect=Exception("boom")),
    )

    response = api_client.post(f"/api/project/{PROJECT_ID}/scope/discover")

    assert response.status_code == 500
