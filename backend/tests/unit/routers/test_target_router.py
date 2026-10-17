"""target_router.py - see docs/testing-crawler-reports/routers.md's
target_router.py section for the confirmed gaps these tests pin: POST's
malformed project_id/unknown-project paths and PUT's bad-IPv4/IPv6/
missing-target paths all fall through to the generic 500 the router
catches everything with, instead of the 400/404 a typed exception would
let it return."""

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
    mock_add = MagicMock(return_value=target_response())
    monkeypatch.setattr(target_router.TargetService, "add_target", mock_add)
    response = api_client.post(
        f"/api/project/{PROJECT_ID}/target", json=target_body()
    )
    assert response.status_code == 200
    assert response.json()["id"] == TARGET_ID
    mock_add.assert_called_once_with("t1", PROJECT_ID)


def test_create_target_unknown_project_is_still_500(api_client, monkeypatch):
    """Confirmed gap (routers.md): an FK violation for an unknown
    project_id surfaces as a generic Exception, mapped to 500 rather than
    404."""
    monkeypatch.setattr(
        target_router.TargetService,
        "add_target",
        MagicMock(side_effect=RuntimeError("FK violation: unknown project")),
    )
    response = api_client.post(
        f"/api/project/{uuid.uuid4()}/target", json=target_body()
    )
    assert response.status_code == 500


def test_create_target_malformed_project_id_is_still_500(api_client, monkeypatch):
    """Confirmed gap (routers.md): uuid.UUID(project_id) raising ValueError
    for a malformed id is caught by the same catch-all and mapped to 500,
    not a 400/422."""
    monkeypatch.setattr(
        target_router.TargetService,
        "add_target",
        MagicMock(side_effect=ValueError("badly formed hexadecimal UUID string")),
    )
    response = api_client.post(
        "/api/project/not-a-uuid/target", json=target_body()
    )
    assert response.status_code == 500


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


def test_update_target_bad_ipv4_is_still_500(api_client, monkeypatch):
    """Confirmed gap (routers.md): a bad-IPv4 ValueError from the service
    is caught by the router's generic Exception handler and mapped to
    500, not the 400 the plan says it should be."""
    monkeypatch.setattr(
        target_router.TargetService,
        "update_target",
        MagicMock(side_effect=ValueError("'999.999.999.999' is not a valid IPv4")),
    )
    response = api_client.put(f"/api/target/{TARGET_ID}", json=target_body())
    assert response.status_code == 500


def test_update_target_bad_ipv6_is_still_500(api_client, monkeypatch):
    monkeypatch.setattr(
        target_router.TargetService,
        "update_target",
        MagicMock(side_effect=ValueError("'not-an-ipv6' is not a valid IPv6")),
    )
    response = api_client.put(f"/api/target/{TARGET_ID}", json=target_body())
    assert response.status_code == 500


def test_update_target_missing_target_is_still_500(api_client, monkeypatch):
    """Confirmed gap (routers.md): "Target does not exist" ValueError is
    caught by the same catch-all and mapped to 500, not the 404 the plan
    says it should be."""
    monkeypatch.setattr(
        target_router.TargetService,
        "update_target",
        MagicMock(side_effect=ValueError(f"Target does not exist: {TARGET_ID}")),
    )
    response = api_client.put(f"/api/target/{TARGET_ID}", json=target_body())
    assert response.status_code == 500
