"""project_router.py - see docs/testing-crawler-reports/routers.md's
project_router.py section for the gaps these tests exercise: GET/PUT
settings now map an unknown project to 404 via
ProjectService.get_project_settings raising ProjectDoesNotExistException,
instead of falling through to the generic 500. PUT's pre-check call to
get_project_settings is now wrapped in its own try/except for that typed
exception - but only for that typed exception: a genuinely different
failure there (anything not ProjectDoesNotExistException) still isn't
caught by anything in the handler, so it remains a bare, detail-less
FastAPI 500 (see test_update_settings_precheck_failure_is_bare_500)."""

import importlib
import uuid
from unittest.mock import AsyncMock, MagicMock

from fastapi.testclient import TestClient

from main import app
from src.schemas import ProjectSettings

# `src.routers.project_router` as a module ATTRIBUTE lookup (`from
# src.routers import project_router`) resolves to the router INSTANCE
# re-exported under that same name by src/routers/__init__.py, not the
# submodule that actually holds ProjectService/AgentService/OllamaService.
# Only importlib reaches the real module object - see
# tests/integration/api/conftest.py's docstring for the same gotcha.
project_router = importlib.import_module("src.routers.project_router")

PROJECT_ID = str(uuid.uuid4())


def settings_body(**overrides):
    body = {
        "project_id": PROJECT_ID,
        "should_interrupt": False,
        "starting_prompt": "go",
        "base_model_name": "",
        "parsing_model_name": "",
        "pipeline_mode": "single_agent",
        "max_concurrent_agents": 1,
        "allow_shell": True,
        "allow_install_packages": True,
    }
    body.update(overrides)
    return body


def settings_response(**overrides):
    """The router accesses attributes on this (current_settings.
    pipeline_mode), so it must be a real object, not a dict - ProjectSettings
    is a table=True model, so direct construction skips strict Pydantic
    validation (see schemas.md's crawler finding) the same way Target's did
    in target_router.py's update_target, which is exactly what lets this
    stand in without a real DB row behind it."""
    settings = settings_body()
    settings.update(overrides)
    settings["project_id"] = uuid.UUID(settings["project_id"])
    return ProjectSettings(**settings)


def test_all_projects_happy_path(api_client, monkeypatch):
    monkeypatch.setattr(
        project_router.ProjectService,
        "get_projects",
        MagicMock(return_value=[{"id": PROJECT_ID, "name": "p1"}]),
    )
    response = api_client.get("/api/projects")
    assert response.status_code == 200
    assert response.json() == [{"id": PROJECT_ID, "name": "p1"}]


def test_all_projects_error_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        project_router.ProjectService,
        "get_projects",
        MagicMock(side_effect=RuntimeError("db down")),
    )
    response = api_client.get("/api/projects")
    assert response.status_code == 500


def test_create_project_happy_path(api_client, monkeypatch):
    mock_add = MagicMock(return_value={"id": PROJECT_ID, "name": "new"})
    monkeypatch.setattr(project_router.ProjectService, "add_project", mock_add)
    response = api_client.post(
        "/api/project",
        json={"name": "new", "base_model_name": "m1", "parsing_model_name": "m2"},
    )
    assert response.status_code == 200
    assert response.json() == {"id": PROJECT_ID, "name": "new"}
    mock_add.assert_called_once_with("new", "m1", "m2")


def test_create_project_error_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        project_router.ProjectService,
        "add_project",
        MagicMock(side_effect=RuntimeError("boom")),
    )
    response = api_client.post(
        "/api/project",
        json={"name": "new", "base_model_name": "m1", "parsing_model_name": "m2"},
    )
    assert response.status_code == 500


def test_get_project_settings_happy_path(api_client, monkeypatch):
    monkeypatch.setattr(
        project_router.ProjectService,
        "get_project_settings",
        MagicMock(return_value=settings_response()),
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/settings")
    assert response.status_code == 200


def test_get_project_settings_unknown_project_returns_404(api_client, monkeypatch):
    """Fixed (routers.md confirmed gap): ProjectService.get_project_settings
    now raises ProjectDoesNotExistException for an unknown project, which
    the router maps to 404 instead of the generic 500."""
    monkeypatch.setattr(
        project_router.ProjectService,
        "get_project_settings",
        MagicMock(
            side_effect=project_router.ProjectDoesNotExistException(
                f"Project does not exist: {PROJECT_ID}", PROJECT_ID
            )
        ),
    )
    response = api_client.get(f"/api/project/{PROJECT_ID}/settings")
    assert response.status_code == 404


def test_update_settings_url_body_id_mismatch_returns_400(api_client):
    other_id = str(uuid.uuid4())
    response = api_client.put(
        f"/api/project/{other_id}/settings", json=settings_body()
    )
    assert response.status_code == 400


def test_update_settings_install_packages_without_shell_returns_400(api_client):
    response = api_client.put(
        f"/api/project/{PROJECT_ID}/settings",
        json=settings_body(allow_shell=False, allow_install_packages=True),
    )
    assert response.status_code == 400


def test_update_settings_unknown_pipeline_mode_returns_400(api_client):
    response = api_client.put(
        f"/api/project/{PROJECT_ID}/settings",
        json=settings_body(pipeline_mode="not_a_real_mode"),
    )
    assert response.status_code == 400


def test_update_settings_pipeline_mode_change_while_running_returns_400(
    api_client, monkeypatch
):
    monkeypatch.setattr(
        project_router.ProjectService,
        "get_project_settings",
        MagicMock(return_value=settings_response(pipeline_mode="single_agent")),
    )
    monkeypatch.setattr(
        project_router.AgentService, "is_project_running", MagicMock(return_value=True)
    )
    response = api_client.put(
        f"/api/project/{PROJECT_ID}/settings",
        json=settings_body(pipeline_mode="multi_agent"),
    )
    assert response.status_code == 400


def test_update_settings_pipeline_mode_change_while_idle_is_ok(api_client, monkeypatch):
    monkeypatch.setattr(
        project_router.ProjectService,
        "get_project_settings",
        MagicMock(return_value=settings_response(pipeline_mode="single_agent")),
    )
    monkeypatch.setattr(
        project_router.AgentService, "is_project_running", MagicMock(return_value=False)
    )
    monkeypatch.setattr(
        project_router.ProjectService,
        "update_project_settings",
        MagicMock(return_value=None),
    )
    response = api_client.put(
        f"/api/project/{PROJECT_ID}/settings",
        json=settings_body(pipeline_mode="multi_agent"),
    )
    assert response.status_code == 200


def test_update_settings_unknown_tool_group_returns_400(api_client, monkeypatch):
    monkeypatch.setattr(
        project_router.ProjectService,
        "get_project_settings",
        MagicMock(return_value=settings_response()),
    )
    monkeypatch.setattr(
        project_router.AgentService, "is_project_running", MagicMock(return_value=False)
    )
    response = api_client.put(
        f"/api/project/{PROJECT_ID}/settings",
        json=settings_body(enabled_tools=["definitely_not_a_real_group"]),
    )
    assert response.status_code == 400


def test_update_settings_model_not_installed_returns_400(api_client, monkeypatch):
    monkeypatch.setattr(
        project_router.ProjectService,
        "get_project_settings",
        MagicMock(return_value=settings_response()),
    )
    monkeypatch.setattr(
        project_router.AgentService, "is_project_running", MagicMock(return_value=False)
    )
    installed = MagicMock()
    installed.models = []
    monkeypatch.setattr(
        project_router.OllamaService,
        "get_models_list",
        AsyncMock(return_value=installed),
    )
    response = api_client.put(
        f"/api/project/{PROJECT_ID}/settings",
        json=settings_body(base_model_name="not-installed"),
    )
    assert response.status_code == 400


def test_update_settings_model_check_failure_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        project_router.ProjectService,
        "get_project_settings",
        MagicMock(return_value=settings_response()),
    )
    monkeypatch.setattr(
        project_router.AgentService, "is_project_running", MagicMock(return_value=False)
    )
    monkeypatch.setattr(
        project_router.OllamaService,
        "get_models_list",
        AsyncMock(side_effect=RuntimeError("ollama unreachable")),
    )
    response = api_client.put(
        f"/api/project/{PROJECT_ID}/settings",
        json=settings_body(base_model_name="any-model"),
    )
    assert response.status_code == 500
    assert response.json()["detail"] == "Could not verify installed models"


def test_update_settings_update_failure_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        project_router.ProjectService,
        "get_project_settings",
        MagicMock(return_value=settings_response()),
    )
    monkeypatch.setattr(
        project_router.AgentService, "is_project_running", MagicMock(return_value=False)
    )
    monkeypatch.setattr(
        project_router.ProjectService,
        "update_project_settings",
        MagicMock(side_effect=RuntimeError("db write failed")),
    )
    response = api_client.put(
        f"/api/project/{PROJECT_ID}/settings", json=settings_body()
    )
    assert response.status_code == 500


def test_update_settings_happy_path(api_client, monkeypatch):
    monkeypatch.setattr(
        project_router.ProjectService,
        "get_project_settings",
        MagicMock(return_value=settings_response()),
    )
    monkeypatch.setattr(
        project_router.AgentService, "is_project_running", MagicMock(return_value=False)
    )
    monkeypatch.setattr(
        project_router.ProjectService,
        "update_project_settings",
        MagicMock(return_value=settings_response()),
    )
    response = api_client.put(
        f"/api/project/{PROJECT_ID}/settings", json=settings_body()
    )
    assert response.status_code == 200


def test_update_settings_unknown_project_returns_404(api_client, monkeypatch):
    """Fixed (routers.md confirmed gap): the pre-check call to
    get_project_settings now has its own try/except for
    ProjectDoesNotExistException specifically, so an unknown project_id
    maps to 404 instead of falling through to a bare 500."""
    monkeypatch.setattr(
        project_router.ProjectService,
        "get_project_settings",
        MagicMock(
            side_effect=project_router.ProjectDoesNotExistException(
                f"Project does not exist: {PROJECT_ID}", PROJECT_ID
            )
        ),
    )
    response = api_client.put(
        f"/api/project/{PROJECT_ID}/settings",
        json=settings_body(pipeline_mode="multi_agent"),
    )
    assert response.status_code == 404


def test_update_settings_precheck_failure_is_bare_500(monkeypatch):
    """Pin (routers.md): the pre-check's new try/except only catches
    ProjectDoesNotExistException (see test_update_settings_unknown_project_
    returns_404) - it is not a broad catch-all. A genuinely different
    failure there (anything else the service might raise) is still an
    unhandled exception that Starlette's own default error handler turns
    into a bare 500 with no JSON "detail" - never the router's own
    HTTPException(detail=...)."""
    monkeypatch.setattr(
        project_router.ProjectService,
        "get_project_settings",
        MagicMock(side_effect=RuntimeError("db connection lost")),
    )
    client = TestClient(app, raise_server_exceptions=False)
    response = client.put(
        f"/api/project/{PROJECT_ID}/settings",
        json=settings_body(pipeline_mode="multi_agent"),
    )
    assert response.status_code == 500
    assert response.headers["content-type"] != "application/json"


def test_delete_project_unknown_id_returns_204(api_client, monkeypatch):
    """Pin (routers.md): delete_project never checks existence first, so
    deleting an id that was never there still reports success."""
    monkeypatch.setattr(
        project_router.ProjectService, "delete_project", MagicMock(return_value=None)
    )
    response = api_client.delete(f"/api/project/{uuid.uuid4()}")
    assert response.status_code == 204


def test_delete_project_error_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        project_router.ProjectService,
        "delete_project",
        MagicMock(side_effect=RuntimeError("boom")),
    )
    response = api_client.delete(f"/api/project/{PROJECT_ID}")
    assert response.status_code == 500
