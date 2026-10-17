"""§1.4b: ollama_router through the real app - ollama_router ->
OllamaService -> ollama_manager, with ollama's own AsyncClient faked only
at fake_ollama_client (the .client attribute ollama_manager was
constructed with). See docs/testing-plan.md §1.4b."""

import time

from ollama import ListResponse, ShowResponse
from ollama._types import ModelDetails


def _create_project(client, base_model_name=""):
    return client.post(
        "/api/project",
        json={
            "name": "Ollama Target",
            "base_model_name": base_model_name,
            "parsing_model_name": "",
        },
    ).json()


def _set_base_model(client, fake_ollama_client, project_id, model_name):
    # update_project_settings (project_router.py) rejects a base_model_name
    # that isn't in the real installed-models list - scripted here via the
    # same fake_ollama_client boundary every other call in this file uses.
    fake_ollama_client.list.return_value = ListResponse(
        models=[
            ListResponse.Model(
                model=model_name,
                size=1,
                details=ModelDetails(family="qwen", parameter_size="8B"),
            )
        ]
    )
    fake_ollama_client.show.return_value = ShowResponse(model_info={}, capabilities=[])

    current = client.get(f"/api/project/{project_id}/settings").json()
    current["base_model_name"] = model_name
    current["project_id"] = project_id
    response = client.put(f"/api/project/{project_id}/settings", json=current)
    assert response.status_code == 200


def test_get_models_list_reflects_the_real_ollama_manager_pipeline(
    api_integration_client, fake_ollama_client
):
    fake_ollama_client.list.return_value = ListResponse(
        models=[
            ListResponse.Model(
                model="llama3:8b",
                size=4_000_000_000,
                details=ModelDetails(family="llama", parameter_size="8B"),
            )
        ]
    )
    fake_ollama_client.show.return_value = ShowResponse(model_info={}, capabilities=[])

    response = api_integration_client.get("/api/ollama/models")
    assert response.status_code == 200

    models = response.json()["models"]
    assert len(models) == 1
    assert models[0]["name"] == "llama3:8b"
    assert models[0]["family"] == "llama"
    assert models[0]["parameters_size_b"] == 8.0
    assert models[0]["size_gb"] == round(4_000_000_000 / (1024**3), 2)


def test_download_model_runs_the_real_queue_and_worker_against_the_fake_client(
    api_integration_client, fake_ollama_client
):
    # download_model's own "already downloaded?" check calls
    # get_models_list first - an empty catalog here is what makes the new
    # model's download actually proceed.
    fake_ollama_client.list.return_value = ListResponse(models=[])

    pulled: list[str] = []

    async def fake_pull(model_name, stream=True):
        pulled.append(model_name)

        async def _progress_stream():
            yield type("P", (), {"status": "pulling", "completed": 50, "total": 100})()
            yield type("P", (), {"status": "success", "completed": 100, "total": 100})()

        return _progress_stream()

    fake_ollama_client.pull = fake_pull

    response = api_integration_client.post(
        "/api/ollama/model", json={"model_name": "qwen3:8b"}
    )
    assert response.status_code == 202

    deadline = time.monotonic() + 5
    queue = None
    while time.monotonic() < deadline:
        queue = api_integration_client.get("/api/ollama/download_queue").json()
        if queue["current"] is None and not queue["queue"]:
            break
        time.sleep(0.05)

    assert queue is not None
    assert queue["current"] is None
    assert queue["queue"] == []
    # The real OllamaManager.pull_model actually reached the fake client's
    # own pull() with the model name the router was given - not just that
    # the queue drained.
    assert pulled == ["qwen3:8b"]


def test_delete_model_success_clears_the_real_project_setting(
    api_integration_client, pg_container, fake_ollama_client
):
    project = _create_project(api_integration_client)
    _set_base_model(api_integration_client, fake_ollama_client, project["id"], "qwen3:8b")

    fake_ollama_client.delete.return_value = None

    # httpx's Client.delete() has no `json=` kwarg (DELETE-with-a-body is
    # unusual enough that the convenience method omits it) - .request()
    # is the plain way to send one.
    response = api_integration_client.request(
        "DELETE", "/api/ollama/model", json={"model_name": "qwen3:8b"}
    )
    assert response.status_code == 200

    settings = pg_container.get_project_settings(project["id"], create_new=False)
    assert settings.base_model_name == ""


def test_delete_model_failure_does_not_clear_the_real_project_setting(
    api_integration_client, pg_container, fake_ollama_client
):
    """delete_model must not call clear_model_references (a real DB write)
    when the Ollama-side delete itself failed - see ollama_service.py's
    own comment and docs/testing-plan.md's §1.4b entry for this router."""
    project = _create_project(api_integration_client)
    _set_base_model(api_integration_client, fake_ollama_client, project["id"], "qwen3:8b")

    fake_ollama_client.delete.side_effect = Exception("ollama unreachable")

    response = api_integration_client.request(
        "DELETE", "/api/ollama/model", json={"model_name": "qwen3:8b"}
    )
    assert response.status_code == 500

    settings = pg_container.get_project_settings(project["id"], create_new=False)
    assert settings.base_model_name == "qwen3:8b"
