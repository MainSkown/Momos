"""target_router.py - see docs/testing-crawler-reports/routers.md's
target_router.py section for the gaps these tests exercise: POST's
malformed project_id/unknown-project paths and PUT's bad-IPv4/IPv6/
missing-target paths now map to 400/404 via typed exceptions
(InvalidProjectIdException, ProjectDoesNotExistException,
InvalidTargetDataException, TargetDoesNotExistException) instead of
falling through to the router's generic Exception -> 500 handler."""

import importlib
import uuid
from unittest.mock import MagicMock

target_router = importlib.import_module("src.routers.target_router")

PROJECT_ID = str(uuid.uuid4())
TARGET_ID = str(uuid.uuid4())


def target_body(**overrides):
    body = {
        "name": "t1",
        "ipv4": "10.0.0.5",
        "ipv6": None,
        "description": "a target",
        "ports": [80, 443],
        "task_duration": 60,
    }
    body.update(overrides)
    return body


def target_response(**overrides):
    body = target_body()
    body.update(
        {
            "id": TARGET_ID,
            "project_id": PROJECT_ID,
        }
    )
    body.update(overrides)
    return body


def test_get_all_targets_happy_path(api_client, monkeypatch):
    monkeypatch.setattr(
        target_router.TargetService,
        "get_all_targets",
        MagicMock(return_value=[target_response()]),
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/targets")
    assert response.status_code == 200
    assert response.json()[0]["id"] == TARGET_ID


def test_get_all_targets_error_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        target_router.TargetService,
        "get_all_targets",
        MagicMock(side_effect=RuntimeError("db down")),
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/targets")
    assert response.status_code == 500


def test_get_all_targets_unknown_project_returns_empty_list(api_client, monkeypatch):
    """Pin (routers.md): an unknown project_id is never distinguished from
    a project with zero targets - both return []."""
    monkeypatch.setattr(
        target_router.TargetService, "get_all_targets", MagicMock(return_value=[])
    )
    response = api_client.get(f"/api/project/{uuid.uuid4()}/targets")
    assert response.status_code == 200
    assert response.json() == []


def test_create_target_happy_path(api_client, monkeypatch):
    """Fixed: the router used to call add_target("t1", PROJECT_ID) and drop
    every other field of the request body - it now forwards all of them."""
    mock_add = MagicMock(return_value=target_response())
    monkeypatch.setattr(target_router.TargetService, "add_target", mock_add)
    response = api_client.post(
        f"/api/project/{PROJECT_ID}/target", json=target_body()
    )
    assert response.status_code == 200
    assert response.json()["id"] == TARGET_ID
    mock_add.assert_called_once_with(
        "t1",
        PROJECT_ID,
        ipv4="10.0.0.5",
        ipv6=None,
        description="a target",
        ports=[80, 443],
        task_duration=60,
    )


def test_create_target_unknown_project_returns_404(api_client, monkeypatch):
    """Fixed (routers.md confirmed gap): TargetService.add_target now
    raises ProjectDoesNotExistException for an unknown project_id, which
    the router maps to 404 instead of the generic 500."""
    unknown_project_id = str(uuid.uuid4())
    monkeypatch.setattr(
        target_router.TargetService,
        "add_target",
        MagicMock(
            side_effect=target_router.ProjectDoesNotExistException(
                f"Project does not exist: {unknown_project_id}", unknown_project_id
            )
        ),
    )
    response = api_client.post(
        f"/api/project/{unknown_project_id}/target", json=target_body()
    )
    assert response.status_code == 404


def test_create_target_malformed_project_id_returns_400(api_client, monkeypatch):
    """Fixed (routers.md confirmed gap): uuid.UUID(project_id) raising
    ValueError for a malformed id is now wrapped by TargetService.add_target
    into InvalidProjectIdException, which the router maps to 400."""
    monkeypatch.setattr(
        target_router.TargetService,
        "add_target",
        MagicMock(
            side_effect=target_router.InvalidProjectIdException(
                "Malformed project_id: not-a-uuid", "not-a-uuid"
            )
        ),
    )
    response = api_client.post(
        "/api/project/not-a-uuid/target", json=target_body()
    )
    assert response.status_code == 400


def test_delete_target_unknown_id_returns_204(api_client, monkeypatch):
    """Pin (routers.md): delete_target never checks existence first."""
    monkeypatch.setattr(
        target_router.TargetService, "delete_target", MagicMock(return_value=None)
    )
    response = api_client.delete(f"/api/target/{uuid.uuid4()}")
    assert response.status_code == 204


def test_delete_target_error_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        target_router.TargetService,
        "delete_target",
        MagicMock(side_effect=RuntimeError("boom")),
    )
    response = api_client.delete(f"/api/target/{TARGET_ID}")
    assert response.status_code == 500


def test_update_target_happy_path(api_client, monkeypatch):
    mock_update = MagicMock(return_value=None)
    monkeypatch.setattr(target_router.TargetService, "update_target", mock_update)
    response = api_client.put(f"/api/target/{TARGET_ID}", json=target_body())
    assert response.status_code == 200
    mock_update.assert_called_once()


def test_update_target_bad_ipv4_returns_400(api_client, monkeypatch):
    """Fixed (routers.md confirmed gap): a bad IPv4 now raises
    InvalidTargetDataException, which the router maps to 400 instead of
    the generic 500."""
    monkeypatch.setattr(
        target_router.TargetService,
        "update_target",
        MagicMock(
            side_effect=target_router.InvalidTargetDataException(
                "'999.999.999.999' is not a valid IPv4"
            )
        ),
    )
    response = api_client.put(f"/api/target/{TARGET_ID}", json=target_body())
    assert response.status_code == 400


def test_update_target_bad_ipv6_returns_400(api_client, monkeypatch):
    monkeypatch.setattr(
        target_router.TargetService,
        "update_target",
        MagicMock(
            side_effect=target_router.InvalidTargetDataException(
                "'not-an-ipv6' is not a valid IPv6"
            )
        ),
    )
    response = api_client.put(f"/api/target/{TARGET_ID}", json=target_body())
    assert response.status_code == 400


def test_update_target_missing_target_returns_404(api_client, monkeypatch):
    """Fixed (routers.md confirmed gap): "Target does not exist" now
    raises TargetDoesNotExistException, which the router maps to 404
    instead of the generic 500."""
    monkeypatch.setattr(
        target_router.TargetService,
        "update_target",
        MagicMock(
            side_effect=target_router.TargetDoesNotExistException(
                f"Target does not exist: {TARGET_ID}", TARGET_ID
            )
        ),
    )
    response = api_client.put(f"/api/target/{TARGET_ID}", json=target_body())
    assert response.status_code == 404
