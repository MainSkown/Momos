"""ollama_router.py - see docs/testing-crawler-reports/routers.md's
ollama_router.py section. Confirmed gap: download_model raising ValueError
for an already-queued/downloading OR an already-downloaded model both
map to the router's generic 500, not the 409 the plan says they should
be."""

import importlib
from unittest.mock import AsyncMock, MagicMock

from fastapi.testclient import TestClient

from main import app

ollama_router = importlib.import_module("src.routers.ollama_router")

MODEL_NAME = "llama3:8b"


def model_data(**overrides):
    body = {
        "family": "llama",
        "name": MODEL_NAME,
        "parameters_size_b": 8.0,
        "thinking": False,
        "context_window": 8192,
        "size_gb": 4.5,
    }
    body.update(overrides)
    return body


def test_get_models_list_happy_path(api_client, monkeypatch):
    monkeypatch.setattr(
        ollama_router.OllamaService,
        "get_models_list",
        AsyncMock(return_value={"models": [model_data()]}),
    )
    response = api_client.get("/api/ollama/models")
    assert response.status_code == 200
    assert response.json()["models"][0]["name"] == MODEL_NAME


def test_get_models_list_error_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        ollama_router.OllamaService,
        "get_models_list",
        AsyncMock(side_effect=RuntimeError("ollama unreachable")),
    )
    response = api_client.get("/api/ollama/models")
    assert response.status_code == 500


def test_post_model_happy_path_returns_202(api_client, monkeypatch):
    mock_download = AsyncMock(return_value=None)
    monkeypatch.setattr(ollama_router.OllamaService, "download_model", mock_download)
    response = api_client.post("/api/ollama/model", json={"model_name": MODEL_NAME})
    assert response.status_code == 202
    assert response.json() == {
        "status": "pending",
        "message": f"Download initiated for {MODEL_NAME}",
    }
    mock_download.assert_called_once_with(MODEL_NAME)


def test_post_model_already_queued_is_still_500(api_client, monkeypatch):
    """Confirmed gap (routers.md): should be 409, is actually 500."""
    monkeypatch.setattr(
        ollama_router.OllamaService,
        "download_model",
        AsyncMock(side_effect=ValueError(f"{MODEL_NAME} is already queued")),
    )
    response = api_client.post("/api/ollama/model", json={"model_name": MODEL_NAME})
    assert response.status_code == 500


def test_post_model_already_downloaded_is_still_500(api_client, monkeypatch):
    """Confirmed gap (routers.md): should be 409, is actually 500."""
    monkeypatch.setattr(
        ollama_router.OllamaService,
        "download_model",
        AsyncMock(side_effect=ValueError(f"{MODEL_NAME} is already downloaded")),
    )
    response = api_client.post("/api/ollama/model", json={"model_name": MODEL_NAME})
    assert response.status_code == 500


def test_delete_model_happy_path(api_client, monkeypatch):
    mock_delete = AsyncMock(return_value=None)
    monkeypatch.setattr(ollama_router.OllamaService, "delete_model", mock_delete)
    response = api_client.request(
        "DELETE", "/api/ollama/model", json={"model_name": MODEL_NAME}
    )
    assert response.status_code == 200
    mock_delete.assert_called_once_with(MODEL_NAME)


def test_delete_model_error_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        ollama_router.OllamaService,
        "delete_model",
        AsyncMock(side_effect=RuntimeError("ollama delete failed")),
    )
    response = api_client.request(
        "DELETE", "/api/ollama/model", json={"model_name": MODEL_NAME}
    )
    assert response.status_code == 500


def test_get_downloadable_models_happy_path(api_client):
    # api_client's fixture already sets app.state.ollama_models = [] -
    # mirroring what main.py's real (skipped-in-tests) lifespan would.
    response = api_client.get("/api/ollama/downloadable_models")
    assert response.status_code == 200
    assert response.json() == {"models": []}


def test_get_downloadable_models_without_lifespan_state_is_unhandled_500():
    """Testability blocker confirmed (routers.md): the route reads
    request.app.state.ollama_models with no try/except of its own and no
    default - skip the real lifespan (as every router-unit test here
    does) without setting the state by hand, and this isn't a clean
    HTTPException(500) at all, it's an unhandled AttributeError that
    Starlette's own default error handler turns into a bare 500."""
    # main.app is a process-wide singleton (every test imports the SAME
    # object) - another test's api_client fixture may have already set
    # app.state.ollama_models, so that has to be undone here rather than
    # relied on to simply never have happened.
    if hasattr(app.state, "ollama_models"):
        del app.state.ollama_models
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/api/ollama/downloadable_models")
    assert response.status_code == 500
    assert response.headers["content-type"] != "application/json"


def test_get_download_queue_details_shape(api_client, monkeypatch):
    monkeypatch.setattr(
        ollama_router.OllamaService,
        "get_download_queue",
        MagicMock(return_value={"current": MODEL_NAME, "queue": ["other-model"]}),
    )
    response = api_client.get("/api/ollama/download_queue")
    assert response.status_code == 200
    assert response.json() == {"current": MODEL_NAME, "queue": ["other-model"]}
