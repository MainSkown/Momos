"""agent_router.py - see docs/testing-crawler-reports/routers.md's
agent_router.py section. This router is named as a reference pattern
(all seven typed exceptions mapped correctly) - these tests confirm that
holds for every endpoint that declares the mapping, not just start_agent."""

import importlib
import uuid
from unittest.mock import AsyncMock, MagicMock

from src.utils.exceptions import (
    AgentAlreadyRunningException,
    DurationNotDefinedInTarget,
    ModelNotInstalledException,
    ModelNotSelectedException,
    ProjectDoesNotExistException,
    ScopeNotAcknowledgedException,
    TargetDoesNotExistException,
)

agent_router = importlib.import_module("src.routers.agent_router")

PROJECT_ID = str(uuid.uuid4())
TARGET_ID = str(uuid.uuid4())
START_URL = f"/api/project/{PROJECT_ID}/target/{TARGET_ID}/agent/start"
PAUSE_URL = f"/api/project/{PROJECT_ID}/target/{TARGET_ID}/agent/pause"
FINISH_URL = f"/api/project/{PROJECT_ID}/target/{TARGET_ID}/agent/finish"
RUN_URL = f"/api/project/{PROJECT_ID}/target/{TARGET_ID}/agent/run"
PENDING_INTERRUPT_URL = (
    f"/api/project/{PROJECT_ID}/target/{TARGET_ID}/agent/pending_interrupt"
)
PENDING_INTERRUPTS_URL = (
    f"/api/project/{PROJECT_ID}/target/{TARGET_ID}/agent/pending_interrupts"
)
RUN_TREE_URL = f"/api/project/{PROJECT_ID}/target/{TARGET_ID}/agent/run_tree"
ATTACK_VECTORS_URL = f"/api/project/{PROJECT_ID}/target/{TARGET_ID}/attack_vectors"


# --- start_agent: all six typed exceptions ---


def test_start_agent_happy_path(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService, "start_agent", AsyncMock(return_value=None)
    )
    response = api_client.post(START_URL)
    assert response.status_code == 200


def test_start_agent_project_does_not_exist_maps_to_404(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "start_agent",
        AsyncMock(
            side_effect=ProjectDoesNotExistException("no such project", PROJECT_ID)
        ),
    )
    response = api_client.post(START_URL)
    assert response.status_code == 404
    assert response.json()["detail"] == "no such project"


def test_start_agent_target_does_not_exist_maps_to_404(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "start_agent",
        AsyncMock(
            side_effect=TargetDoesNotExistException("no such target", TARGET_ID)
        ),
    )
    response = api_client.post(START_URL)
    assert response.status_code == 404
    assert response.json()["detail"] == "no such target"


def test_start_agent_duration_not_defined_maps_to_400(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "start_agent",
        AsyncMock(side_effect=DurationNotDefinedInTarget("no duration set")),
    )
    response = api_client.post(START_URL)
    assert response.status_code == 400
    assert response.json()["detail"] == "no duration set"


def test_start_agent_model_not_selected_maps_to_400(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "start_agent",
        AsyncMock(side_effect=ModelNotSelectedException("no model selected")),
    )
    response = api_client.post(START_URL)
    assert response.status_code == 400
    assert response.json()["detail"] == "no model selected"


def test_start_agent_model_not_installed_maps_to_400(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "start_agent",
        AsyncMock(
            side_effect=ModelNotInstalledException("model gone", "llama3:8b")
        ),
    )
    response = api_client.post(START_URL)
    assert response.status_code == 400
    assert response.json()["detail"] == "model gone"


def test_start_agent_scope_not_acknowledged_maps_to_400(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "start_agent",
        AsyncMock(
            side_effect=ScopeNotAcknowledgedException("scope not acknowledged")
        ),
    )
    response = api_client.post(START_URL)
    assert response.status_code == 400
    assert response.json()["detail"] == "scope not acknowledged"


def test_start_agent_already_running_maps_to_409(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "start_agent",
        AsyncMock(
            side_effect=AgentAlreadyRunningException("already running", TARGET_ID)
        ),
    )
    response = api_client.post(START_URL)
    assert response.status_code == 409
    assert response.json()["detail"] == "already running"


def test_start_agent_generic_error_maps_to_500(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "start_agent",
        AsyncMock(side_effect=RuntimeError("something unrelated broke")),
    )
    response = api_client.post(START_URL)
    assert response.status_code == 500


# --- pause_agent: owned-target check only ---


def test_pause_agent_happy_path(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService, "pause_agent", AsyncMock(return_value=None)
    )
    response = api_client.post(PAUSE_URL)
    assert response.status_code == 200


def test_pause_agent_not_running_is_still_200_not_409(api_client, monkeypatch):
    """Pin (routers.md): pausing a non-running target is a no-op, not a
    conflict - AgentService.pause_agent returning normally (no exception)
    always yields 200."""
    monkeypatch.setattr(
        agent_router.AgentService, "pause_agent", AsyncMock(return_value=None)
    )
    response = api_client.post(PAUSE_URL)
    assert response.status_code == 200


def test_pause_agent_unknown_target_maps_to_404(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "pause_agent",
        AsyncMock(
            side_effect=TargetDoesNotExistException("no such target", TARGET_ID)
        ),
    )
    response = api_client.post(PAUSE_URL)
    assert response.status_code == 404


def test_pause_agent_generic_error_maps_to_500(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "pause_agent",
        AsyncMock(side_effect=RuntimeError("boom")),
    )
    response = api_client.post(PAUSE_URL)
    assert response.status_code == 500


# --- finish_agent: same shape as pause_agent ---


def test_finish_agent_happy_path(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService, "finish_agent", AsyncMock(return_value=None)
    )
    response = api_client.post(FINISH_URL)
    assert response.status_code == 200


def test_finish_agent_unknown_project_maps_to_404(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "finish_agent",
        AsyncMock(
            side_effect=ProjectDoesNotExistException("no such project", PROJECT_ID)
        ),
    )
    response = api_client.post(FINISH_URL)
    assert response.status_code == 404


def test_finish_agent_generic_error_maps_to_500(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "finish_agent",
        AsyncMock(side_effect=RuntimeError("boom")),
    )
    response = api_client.post(FINISH_URL)
    assert response.status_code == 500


# --- get_project_agent_logs: straight to db_manager, no AgentService ---


def test_get_project_agent_logs_happy_path(api_client, monkeypatch):
    fake_db_manager = MagicMock()
    fake_db_manager.get_all_agent_logs_in_project.return_value = []
    monkeypatch.setattr(agent_router, "db_manager", fake_db_manager)
    response = api_client.get(f"/api/project/{PROJECT_ID}/agent_logs")
    assert response.status_code == 200
    assert response.json() == []


def test_get_project_agent_logs_unknown_project_returns_empty_list(
    api_client, monkeypatch
):
    """Pin (routers.md): an unknown project_id is indistinguishable from a
    project with zero logs."""
    fake_db_manager = MagicMock()
    fake_db_manager.get_all_agent_logs_in_project.return_value = []
    monkeypatch.setattr(agent_router, "db_manager", fake_db_manager)
    response = api_client.get(f"/api/project/{uuid.uuid4()}/agent_logs")
    assert response.status_code == 200
    assert response.json() == []


def test_get_project_agent_logs_error_returns_500(api_client, monkeypatch):
    fake_db_manager = MagicMock()
    fake_db_manager.get_all_agent_logs_in_project.side_effect = RuntimeError("db down")
    monkeypatch.setattr(agent_router, "db_manager", fake_db_manager)
    response = api_client.get(f"/api/project/{PROJECT_ID}/agent_logs")
    assert response.status_code == 500


# --- is_project_agent_running: no try at all ---


def test_is_project_agent_running_false_when_idle(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService, "is_project_running", MagicMock(return_value=False)
    )
    monkeypatch.setattr(
        agent_router.AgentService, "get_running_target", MagicMock(return_value=None)
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/agent/running")
    assert response.status_code == 200
    assert response.json() == {"running": False, "target_id": None}


def test_is_project_agent_running_true_with_target(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService, "is_project_running", MagicMock(return_value=True)
    )
    monkeypatch.setattr(
        agent_router.AgentService,
        "get_running_target",
        MagicMock(return_value=TARGET_ID),
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/agent/running")
    assert response.status_code == 200
    assert response.json() == {"running": True, "target_id": TARGET_ID}


# --- get_target_agent_run ---


def test_get_target_agent_run_no_run_returns_null(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService, "get_run", MagicMock(return_value=None)
    )
    response = api_client.get(RUN_URL)
    assert response.status_code == 200
    assert response.json() is None


def test_get_target_agent_run_happy_path(api_client, monkeypatch):
    run = {
        "id": str(uuid.uuid4()),
        "target_id": TARGET_ID,
        "project_id": PROJECT_ID,
        "status": "running",
        "remaining_seconds": 42,
        "recorded_at": "2026-01-01T00:00:00Z",
        "role": "single_agent",
        "parent_run_id": None,
        "attack_vector_id": None,
        "session_id": None,
    }
    monkeypatch.setattr(
        agent_router.AgentService, "get_run", MagicMock(return_value=run)
    )
    response = api_client.get(RUN_URL)
    assert response.status_code == 200
    assert response.json()["remaining_seconds"] == 42


def test_get_target_agent_run_unknown_target_maps_to_404(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "get_run",
        MagicMock(side_effect=TargetDoesNotExistException("no such target", TARGET_ID)),
    )
    response = api_client.get(RUN_URL)
    assert response.status_code == 404


def test_get_target_agent_run_generic_error_maps_to_500(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService, "get_run", MagicMock(side_effect=RuntimeError("x"))
    )
    response = api_client.get(RUN_URL)
    assert response.status_code == 500


# --- get_target_pending_interrupt ---


def test_get_pending_interrupt_none_returns_null(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService, "get_pending_interrupt", MagicMock(return_value=None)
    )
    response = api_client.get(PENDING_INTERRUPT_URL)
    assert response.status_code == 200
    assert response.json() is None


def test_get_pending_interrupt_list_returns_tool_calls(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "get_pending_interrupt",
        MagicMock(return_value=[{"name": "nmap_scan", "args": {}}]),
    )
    response = api_client.get(PENDING_INTERRUPT_URL)
    assert response.status_code == 200
    assert response.json() == {"tool_calls": [{"name": "nmap_scan", "args": {}}]}


def test_get_pending_interrupt_unknown_project_maps_to_404(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "get_pending_interrupt",
        MagicMock(
            side_effect=ProjectDoesNotExistException("no such project", PROJECT_ID)
        ),
    )
    response = api_client.get(PENDING_INTERRUPT_URL)
    assert response.status_code == 404


def test_get_pending_interrupt_generic_error_maps_to_500(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "get_pending_interrupt",
        MagicMock(side_effect=RuntimeError("x")),
    )
    response = api_client.get(PENDING_INTERRUPT_URL)
    assert response.status_code == 500


# --- get_target_pending_interrupts (plural) ---


def test_get_pending_interrupts_empty(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService, "get_pending_interrupts", MagicMock(return_value=[])
    )
    response = api_client.get(PENDING_INTERRUPTS_URL)
    assert response.status_code == 200
    assert response.json() == []


def test_get_pending_interrupts_preserves_agent_run_id(api_client, monkeypatch):
    run_id = str(uuid.uuid4())
    monkeypatch.setattr(
        agent_router.AgentService,
        "get_pending_interrupts",
        MagicMock(
            return_value=[{"agent_run_id": run_id, "tool_calls": [{"name": "run"}]}]
        ),
    )
    response = api_client.get(PENDING_INTERRUPTS_URL)
    assert response.status_code == 200
    assert response.json()[0]["agent_run_id"] == run_id


def test_get_pending_interrupts_unknown_target_maps_to_404(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "get_pending_interrupts",
        MagicMock(side_effect=TargetDoesNotExistException("gone", TARGET_ID)),
    )
    response = api_client.get(PENDING_INTERRUPTS_URL)
    assert response.status_code == 404


def test_get_pending_interrupts_generic_error_maps_to_500(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "get_pending_interrupts",
        MagicMock(side_effect=RuntimeError("x")),
    )
    response = api_client.get(PENDING_INTERRUPTS_URL)
    assert response.status_code == 500


# --- get_target_agent_run_tree ---


def test_get_run_tree_happy_path(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService, "get_run_tree", MagicMock(return_value=[])
    )
    response = api_client.get(RUN_TREE_URL)
    assert response.status_code == 200
    assert response.json() == []


def test_get_run_tree_unknown_target_maps_to_404(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "get_run_tree",
        MagicMock(side_effect=TargetDoesNotExistException("gone", TARGET_ID)),
    )
    response = api_client.get(RUN_TREE_URL)
    assert response.status_code == 404


def test_get_run_tree_generic_error_maps_to_500(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService, "get_run_tree", MagicMock(side_effect=RuntimeError("x"))
    )
    response = api_client.get(RUN_TREE_URL)
    assert response.status_code == 500


# --- get_target_attack_vectors ---


def test_get_attack_vectors_happy_path(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService, "get_attack_vectors", MagicMock(return_value=[])
    )
    response = api_client.get(ATTACK_VECTORS_URL)
    assert response.status_code == 200
    assert response.json() == []


def test_get_attack_vectors_unknown_project_maps_to_404(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "get_attack_vectors",
        MagicMock(
            side_effect=ProjectDoesNotExistException("no such project", PROJECT_ID)
        ),
    )
    response = api_client.get(ATTACK_VECTORS_URL)
    assert response.status_code == 404


def test_get_attack_vectors_generic_error_maps_to_500(api_client, monkeypatch):
    monkeypatch.setattr(
        agent_router.AgentService,
        "get_attack_vectors",
        MagicMock(side_effect=RuntimeError("x")),
    )
    response = api_client.get(ATTACK_VECTORS_URL)
    assert response.status_code == 500
