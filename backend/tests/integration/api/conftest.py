"""§1.4b API-integration fixture - a real FastAPI app, real HTTP, real
Postgres (pg_container), nothing else mocked. See docs/testing-plan.md
§1.4b and the module docstring on tests/integration/conftest.py for why
this tier exists on top of the mocked router/service unit tests."""

import importlib
from unittest.mock import MagicMock

import anyio.from_thread
import docker.errors
import pytest
from fastapi.testclient import TestClient

from main import app

# `src.routers.agent_router`/`src.core.kali_integration.kali_registry` as a
# dotted path - whether written as `import a.b.c as x` or resolved by
# monkeypatch.setattr's own string form - is a package-ATTRIBUTE lookup on
# `src.routers`/`src.core.kali_integration`, and both of those packages
# shadow the submodule with an instance re-exported under the exact same
# name (`from .agent_router import router as agent_router`, `from
# .kali_registry import kali_registry`). Only an explicit sys.modules
# lookup (importlib.import_module, which returns the module itself, not a
# package attribute) reaches the actual module object that holds the
# `db_manager` name these fixtures need to patch.
agent_router_module = importlib.import_module("src.routers.agent_router")
kali_registry_module = importlib.import_module("src.core.kali_integration.kali_registry")


@pytest.fixture
def api_integration_client(pg_container, monkeypatch):
    """A plain TestClient(app) - deliberately NOT entered as a context
    manager. Doing so would run main.py's real lifespan, which connects to
    the production .env Postgres host via setup_checkpointer() (unreachable
    here) and writes a real models.schema.json to disk via
    export_json_schema() - neither of which project/target/vulnerability/
    session routes need.

    db_manager is imported by name into each service module at import
    time, so patching src.core.database_manager.db_manager itself would
    have no effect on any of them - each module below must be patched
    individually (see tests/conftest.py's fake_db_manager docstring for the
    same rule applied to the unit tier). The first four cover the plain
    CRUD routers; the rest were only discovered necessary once the kali/
    ollama/agent/websocket suites started driving the REAL registry/graph
    code underneath those routers (not just the router/service layer) -
    kali_registry.py, run_registry.py and agent.py each do their own
    `from src.core import db_manager` too, independently of
    agent_service.py's own import of the same name."""
    monkeypatch.setattr("src.services.project_service.db_manager", pg_container)
    monkeypatch.setattr("src.services.target_service.db_manager", pg_container)
    monkeypatch.setattr("src.services.test_session_service.db_manager", pg_container)
    monkeypatch.setattr("src.services.vulnerability_service.db_manager", pg_container)
    monkeypatch.setattr("src.services.ollama_service.db_manager", pg_container)
    monkeypatch.setattr("src.services.agent_service.db_manager", pg_container)
    monkeypatch.setattr(agent_router_module, "db_manager", pg_container)
    monkeypatch.setattr(kali_registry_module, "db_manager", pg_container)
    monkeypatch.setattr("src.core.agent.run_registry.db_manager", pg_container)
    monkeypatch.setattr("src.core.agent.agent.db_manager", pg_container)

    client = TestClient(app)
    # GetDownloadableModels (ollama_router.py) reads
    # request.app.state.ollama_models, only ever set by main.py's real
    # lifespan - deliberately not run above. An empty list is enough for
    # every test in this tier; none needs a non-empty downloadable-models
    # catalog.
    client.app.state.ollama_models = []

    # TestClient.portal (anyio's BlockingPortal, the thread+event-loop that
    # actually runs the ASGI app) is normally only set by __enter__ - used
    # as a plain, non-context-managed client (see this fixture's own
    # docstring for why), every single .get()/.post() call instead opens
    # and tears down its OWN brand new portal/thread just for that one
    # call (see starlette.testclient.TestClient._portal_factory). A route
    # handler's fire-and-forget asyncio.create_task(...) (kali_user_
    # registry.create_user's background container build, agent_service.
    # start_agent's background _prepare_and_run) is scheduled on THAT
    # call's own throwaway loop, which is destroyed the instant the
    # response is sent - the task never runs again, no matter how long a
    # later call polls for it. Pinning one persistent portal here (without
    # touching wait_startup/wait_shutdown/the lifespan task __enter__ also
    # starts - this replicates only the "keep one event loop alive" half)
    # lets every request in a test share the same loop, the same way a
    # real deployed server's one long-lived loop would.
    with anyio.from_thread.start_blocking_portal(**client.async_backend) as portal:
        client.portal = portal
        yield client
        client.portal = None


@pytest.fixture
def kali_container_ready(fake_docker_client):
    """Scripts fake_docker_client so KaliManger._create_container (kali_
    manager.py) succeeds end-to-end through the REAL provisioning code -
    no existing container found, a freshly "run" one, every apt-get/setup/
    verification exec_run call inside it exiting 0 - shared by every test
    that drives the real kali_registry -> KaliManger flow: kali_client
    creation (test_kali_api.py) and the agent's own Kali container
    provisioning (test_agent_api.py), both of which go through
    KaliRegistry.get_manager -> KaliManger.start the exact same way."""
    container = MagicMock()
    container.exec_run.return_value = MagicMock(exit_code=0, output=b"")
    fake_docker_client.containers.get.side_effect = docker.errors.NotFound("not found")
    fake_docker_client.containers.run.return_value = container
    return container
