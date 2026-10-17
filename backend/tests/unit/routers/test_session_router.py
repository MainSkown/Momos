"""session_router.py - see docs/testing-crawler-reports/routers.md's
session_router.py section. Named (with agent_router) as the reference
pattern for typed-exception mapping: SessionDoesNotExistException -> 404
on every read endpoint, and SessionIsRunningException -> 409 on delete."""

import importlib
import uuid
from unittest.mock import MagicMock

from src.utils.exceptions import SessionDoesNotExistException, SessionIsRunningException

session_router = importlib.import_module("src.routers.session_router")

PROJECT_ID = str(uuid.uuid4())
SESSION_ID = str(uuid.uuid4())
TARGET_ID = str(uuid.uuid4())


def session_response(**overrides):
    body = {
        "id": SESSION_ID,
        "project_id": PROJECT_ID,
        "target_id": TARGET_ID,
        "started_at": "2026-01-01T00:00:00Z",
        "ended_at": None,
        "active_seconds": 0,
        "time_budget_seconds": 3600,
        "outcome": "running",
        "pipeline_mode": "single_agent",
        "max_concurrent_agents": 1,
        "base_model_name": "llama3:8b",
        "orchestrator_model_name": "",
        "scouting_model_name": "",
        "pentesting_model_name": "",
        "reporting_model_name": "",
    }
    body.update(overrides)
    return body


def session_detail_response(**overrides):
    body = session_response()
    body.update({"vector_counts": {}, "vulnerability_count": 0})
    body.update(overrides)
    return body


def test_get_project_test_sessions_happy_path(api_client, monkeypatch):
    monkeypatch.setattr(
        session_router.TestSessionService,
        "get_sessions_for_project",
        MagicMock(return_value=[session_response()]),
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/sessions")
    assert response.status_code == 200
    assert response.json()[0]["id"] == SESSION_ID


def test_get_project_test_sessions_unknown_project_returns_empty_list(
    api_client, monkeypatch
):
    monkeypatch.setattr(
        session_router.TestSessionService,
        "get_sessions_for_project",
        MagicMock(return_value=[]),
    )
    response = api_client.get(f"/api/project/{uuid.uuid4()}/sessions")
    assert response.status_code == 200
    assert response.json() == []


def test_get_project_test_sessions_error_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        session_router.TestSessionService,
        "get_sessions_for_project",
        MagicMock(side_effect=RuntimeError("db down")),
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/sessions")
    assert response.status_code == 500


def test_get_test_session_happy_path(api_client, monkeypatch):
    monkeypatch.setattr(
        session_router.TestSessionService,
        "get_session_detail",
        MagicMock(return_value=session_detail_response(vector_counts={"pending": 2})),
    )
    response = api_client.get(f"/api/session/{SESSION_ID}")
    assert response.status_code == 200
    assert response.json()["vector_counts"] == {"pending": 2}


def test_get_test_session_missing_maps_to_404(api_client, monkeypatch):
    monkeypatch.setattr(
        session_router.TestSessionService,
        "get_session_detail",
        MagicMock(
            side_effect=SessionDoesNotExistException(
                f"Session does not exist: {SESSION_ID}", SESSION_ID
            )
        ),
    )
    response = api_client.get(f"/api/session/{SESSION_ID}")
    assert response.status_code == 404
    assert response.json()["detail"] == f"Session does not exist: {SESSION_ID}"


def test_get_test_session_generic_error_maps_to_500(api_client, monkeypatch):
    monkeypatch.setattr(
        session_router.TestSessionService,
        "get_session_detail",
        MagicMock(side_effect=RuntimeError("boom")),
    )
    response = api_client.get(f"/api/session/{SESSION_ID}")
    assert response.status_code == 500


def test_get_session_attack_vectors_happy_path(api_client, monkeypatch):
    monkeypatch.setattr(
        session_router.TestSessionService,
        "get_session_attack_vectors",
        MagicMock(return_value=[]),
    )
    response = api_client.get(f"/api/session/{SESSION_ID}/attack_vectors")
    assert response.status_code == 200
    assert response.json() == []


def test_get_session_attack_vectors_missing_maps_to_404(api_client, monkeypatch):
    monkeypatch.setattr(
        session_router.TestSessionService,
        "get_session_attack_vectors",
        MagicMock(
            side_effect=SessionDoesNotExistException("gone", SESSION_ID)
        ),
    )
    response = api_client.get(f"/api/session/{SESSION_ID}/attack_vectors")
    assert response.status_code == 404


def test_get_session_attack_vectors_generic_error_maps_to_500(api_client, monkeypatch):
    monkeypatch.setattr(
        session_router.TestSessionService,
        "get_session_attack_vectors",
        MagicMock(side_effect=RuntimeError("boom")),
    )
    response = api_client.get(f"/api/session/{SESSION_ID}/attack_vectors")
    assert response.status_code == 500


def test_get_session_runs_happy_path_converts_tuples(api_client, monkeypatch):
    run_id = uuid.uuid4()
    monkeypatch.setattr(
        session_router.TestSessionService,
        "get_session_runs",
        MagicMock(return_value=[(run_id, "pentesting")]),
    )
    response = api_client.get(f"/api/session/{SESSION_ID}/runs")
    assert response.status_code == 200
    assert response.json() == [{"agent_run_id": str(run_id), "role": "pentesting"}]


def test_get_session_runs_missing_maps_to_404(api_client, monkeypatch):
    monkeypatch.setattr(
        session_router.TestSessionService,
        "get_session_runs",
        MagicMock(side_effect=SessionDoesNotExistException("gone", SESSION_ID)),
    )
    response = api_client.get(f"/api/session/{SESSION_ID}/runs")
    assert response.status_code == 404


def test_get_session_runs_generic_error_maps_to_500(api_client, monkeypatch):
    monkeypatch.setattr(
        session_router.TestSessionService,
        "get_session_runs",
        MagicMock(side_effect=RuntimeError("boom")),
    )
    response = api_client.get(f"/api/session/{SESSION_ID}/runs")
    assert response.status_code == 500


def test_get_session_logs_happy_path_with_from_end_offset(api_client, monkeypatch):
    mock_get_logs = MagicMock(return_value=([], 5, 3))
    monkeypatch.setattr(
        session_router.TestSessionService, "get_session_logs", mock_get_logs
    )
    response = api_client.get(f"/api/session/{SESSION_ID}/logs?from_end=true")
    assert response.status_code == 200
    body = response.json()
    assert body == {"items": [], "total": 5, "offset": 3}
    assert mock_get_logs.call_args.kwargs["from_end"] is True


def test_get_session_logs_missing_maps_to_404(api_client, monkeypatch):
    monkeypatch.setattr(
        session_router.TestSessionService,
        "get_session_logs",
        MagicMock(side_effect=SessionDoesNotExistException("gone", SESSION_ID)),
    )
    response = api_client.get(f"/api/session/{SESSION_ID}/logs")
    assert response.status_code == 404


def test_get_session_logs_generic_error_maps_to_500(api_client, monkeypatch):
    monkeypatch.setattr(
        session_router.TestSessionService,
        "get_session_logs",
        MagicMock(side_effect=RuntimeError("boom")),
    )
    response = api_client.get(f"/api/session/{SESSION_ID}/logs")
    assert response.status_code == 500


def test_delete_test_session_happy_path(api_client, monkeypatch):
    monkeypatch.setattr(
        session_router.TestSessionService, "delete_session", MagicMock(return_value=None)
    )
    response = api_client.delete(f"/api/session/{SESSION_ID}")
    assert response.status_code == 204


def test_delete_test_session_missing_maps_to_404(api_client, monkeypatch):
    monkeypatch.setattr(
        session_router.TestSessionService,
        "delete_session",
        MagicMock(side_effect=SessionDoesNotExistException("gone", SESSION_ID)),
    )
    response = api_client.delete(f"/api/session/{SESSION_ID}")
    assert response.status_code == 404


def test_delete_test_session_running_maps_to_409(api_client, monkeypatch):
    monkeypatch.setattr(
        session_router.TestSessionService,
        "delete_session",
        MagicMock(
            side_effect=SessionIsRunningException(
                f"Cannot delete a running session: {SESSION_ID}", SESSION_ID
            )
        ),
    )
    response = api_client.delete(f"/api/session/{SESSION_ID}")
    assert response.status_code == 409
    assert (
        response.json()["detail"]
        == f"Cannot delete a running session: {SESSION_ID}"
    )


def test_delete_test_session_generic_error_maps_to_500(api_client, monkeypatch):
    monkeypatch.setattr(
        session_router.TestSessionService,
        "delete_session",
        MagicMock(side_effect=RuntimeError("boom")),
    )
    response = api_client.delete(f"/api/session/{SESSION_ID}")
    assert response.status_code == 500
