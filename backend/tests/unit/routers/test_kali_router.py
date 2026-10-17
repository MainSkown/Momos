"""kali_router.py - see docs/testing-crawler-reports/routers.md's
kali_router.py section. This router is the "reference pattern" the report
names for the None/not-None -> 404/200 mapping (no typed exceptions
involved here, just a None check), so these tests mostly confirm that
pattern holds across all four read endpoints, plus the one write endpoint
(post_kali_user) which has no typed exception at all and always maps any
failure to a flat 500."""

import importlib
import uuid
from unittest.mock import AsyncMock, MagicMock

kali_router = importlib.import_module("src.routers.kali_router")

PROJECT_ID = str(uuid.uuid4())
CLIENT_ID = str(uuid.uuid4())


def test_get_kali_client_not_found_returns_404(api_client, monkeypatch):
    monkeypatch.setattr(
        kali_router.KaliService, "get_client", MagicMock(return_value=None)
    )
    response = api_client.get(f"/api/kali_client/{CLIENT_ID}")
    assert response.status_code == 404


def test_get_kali_client_active_returns_200_pending_false(api_client, monkeypatch):
    monkeypatch.setattr(
        kali_router.KaliService,
        "get_client",
        MagicMock(return_value={"client_id": CLIENT_ID, "pending": None}),
    )
    response = api_client.get(f"/api/kali_client/{CLIENT_ID}")
    assert response.status_code == 200
    assert response.json()["pending"] is None


def test_get_kali_client_pending_returns_200_pending_true(api_client, monkeypatch):
    monkeypatch.setattr(
        kali_router.KaliService,
        "get_client",
        MagicMock(return_value={"client_id": CLIENT_ID, "pending": True}),
    )
    response = api_client.get(f"/api/kali_client/{CLIENT_ID}")
    assert response.status_code == 200
    assert response.json()["pending"] is True


def test_get_kali_client_registry_error_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        kali_router.KaliService,
        "get_client",
        MagicMock(side_effect=RuntimeError("registry exploded")),
    )
    response = api_client.get(f"/api/kali_client/{CLIENT_ID}")
    assert response.status_code == 500


def test_get_project_kali_client_not_found_returns_404(api_client, monkeypatch):
    monkeypatch.setattr(
        kali_router.KaliService,
        "get_client_for_project",
        MagicMock(return_value=None),
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/kali_client")
    assert response.status_code == 404


def test_get_project_kali_client_found_returns_200(api_client, monkeypatch):
    monkeypatch.setattr(
        kali_router.KaliService,
        "get_client_for_project",
        MagicMock(return_value={"client_id": CLIENT_ID, "pending": False}),
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/kali_client")
    assert response.status_code == 200


def test_get_project_kali_client_error_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        kali_router.KaliService,
        "get_client_for_project",
        MagicMock(side_effect=RuntimeError("registry exploded")),
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/kali_client")
    assert response.status_code == 500


def test_get_console_sessions_no_active_user_returns_empty_list(api_client, monkeypatch):
    monkeypatch.setattr(
        kali_router.KaliService, "list_sessions", AsyncMock(return_value=[])
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/kali_client/sessions")
    assert response.status_code == 200
    assert response.json() == []


def test_get_console_sessions_happy_path_maps_name_and_user(api_client, monkeypatch):
    monkeypatch.setattr(
        kali_router.KaliService,
        "list_sessions",
        AsyncMock(return_value=[{"name": "root-1", "user": "root"}]),
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/kali_client/sessions")
    assert response.status_code == 200
    assert response.json() == [{"name": "root-1", "user": "root"}]


def test_get_console_sessions_error_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        kali_router.KaliService,
        "list_sessions",
        AsyncMock(side_effect=RuntimeError("registry exploded")),
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/kali_client/sessions")
    assert response.status_code == 500


def test_post_kali_user_happy_path(api_client, monkeypatch):
    mock_create = AsyncMock(return_value={"client_id": CLIENT_ID, "pending": True})
    monkeypatch.setattr(kali_router.KaliService, "create_client", mock_create)
    response = api_client.post(f"/api/project/{PROJECT_ID}/kali_client")
    assert response.status_code == 200
    assert response.json()["client_id"] == CLIENT_ID
    mock_create.assert_called_once_with(PROJECT_ID)


def test_post_kali_user_error_returns_500_no_typed_exception(api_client, monkeypatch):
    """Confirmed (routers.md): create_client has no typed exception at
    all, so any failure - container build error, registry error, anything
    - always maps to the same flat 500 "Could not create client"."""
    monkeypatch.setattr(
        kali_router.KaliService,
        "create_client",
        AsyncMock(side_effect=RuntimeError("docker build failed")),
    )
    response = api_client.post(f"/api/project/{PROJECT_ID}/kali_client")
    assert response.status_code == 500
    assert response.json()["detail"] == "Could not create client"


def test_get_project_kali_status_idle_never_404s(api_client, monkeypatch):
    monkeypatch.setattr(
        kali_router.KaliService,
        "get_status",
        MagicMock(
            return_value={
                "active": False,
                "building": False,
                "stage": None,
                "target_id": None,
            }
        ),
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/kali/status")
    assert response.status_code == 200
    assert response.json() == {
        "active": False,
        "building": False,
        "stage": None,
        "target_id": None,
    }


def test_get_project_kali_status_building(api_client, monkeypatch):
    monkeypatch.setattr(
        kali_router.KaliService,
        "get_status",
        MagicMock(
            return_value={
                "active": False,
                "building": True,
                "stage": "installing_packages",
                "target_id": str(uuid.uuid4()),
            }
        ),
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/kali/status")
    assert response.status_code == 200
    body = response.json()
    assert body["building"] is True
    assert body["stage"] == "installing_packages"


def test_get_project_kali_status_error_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        kali_router.KaliService,
        "get_status",
        MagicMock(side_effect=RuntimeError("registry exploded")),
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/kali/status")
    assert response.status_code == 500
