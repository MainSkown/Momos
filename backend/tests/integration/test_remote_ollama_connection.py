"""T1 live suite (docs/plans/milestone-3-remote-ollama-connection.md's T1
section) - this subtask *is* the test, no separate test for the test. A
real, ephemeral `ollama/ollama` container (tests/integration/ollama_live/
conftest.py's `live_ollama_url`) exercises `ConnectionService.
test_connection`/`save_connection` + `OllamaManager.reconfigure` end-to-end
at the real network level - the one thing Part T's intro says a mocked
`ollama.AsyncClient` can't prove. Per CLAUDE.md rule 2 ("pick the cheapest
test that would actually fail"), failure-*reason* differentiation (timeout
vs. refused vs. 401) stays a mocked unit test (O2's
tests/unit/services/test_connection_service.py) - a real local Ollama
container can't be made to time out or reject on 401 on demand without
this test becoming flaky or slow.

Excluded from the default suite by the `live_tools` marker below (see
pyproject.toml's addopts) - run explicitly with:
    uv run pytest tests/integration/ollama_live/ \
        tests/integration/test_remote_ollama_connection.py -m live_tools -v

`live_ollama_url` lives in a sibling directory's conftest.py
(ollama_live/), not an ancestor of this file, so pytest's normal
directory-scoped conftest discovery never finds it on its own. Importing
the fixture function directly (rather than `pytest_plugins`, which pytest
rejects once ollama_live/ is itself passed as a collection path - it's
already auto-loaded as a conftest plugin by then, and re-importing it by
dotted path collides with that) is the standard way to pull a fixture into
a module outside its own defining package."""

import asyncio

import pytest

from src.core.agent import run_registry
from src.core.ollama_manager import ollama_manager
from src.schemas.ollama_connection_scheme import OllamaConnectionUpdate
from src.services.connection_service import ConnectionService
from tests.integration.ollama_live.conftest import live_ollama_url  # noqa: F401

pytestmark = pytest.mark.live_tools


@pytest.fixture(autouse=True)
def _reset_run_registry_slots():
    """Same reset test_connection_service.py's unit tests already apply -
    save_connection's run_exclusively_if_idle guard reads this module-level
    state, and it must start clean regardless of what else ran earlier in
    the session."""
    run_registry._project_slot_counts.clear()
    run_registry._global_slot_count = 0
    run_registry._project_slot_condition = asyncio.Condition()
    yield


@pytest.fixture
def real_db_manager(pg_container, monkeypatch):
    """connection_service.py imports `db_manager` by name
    (`from src.core import db_manager, ...`), so the patch target is that
    module's own reference - same convention tests/integration/api/
    conftest.py's api_integration_client fixture already uses for every
    other service."""
    monkeypatch.setattr("src.services.connection_service.db_manager", pg_container)
    return pg_container


@pytest.fixture
def restore_ollama_manager():
    """`ollama_manager` is a real module-level singleton, not something
    this suite mocks (the whole point of T1 is driving it for real) - so
    save_connection's reconfigure() call below mutates genuinely global
    state for the rest of the pytest session. Captures and restores it
    after this file's tests run, so a later test in the same session (were
    one ever added) doesn't inherit a client pointed at an already-torn-
    down container."""
    original_base_url = ollama_manager.base_url
    original_headers = ollama_manager.headers
    original_client = ollama_manager.client
    yield
    ollama_manager.base_url = original_base_url
    ollama_manager.headers = original_headers
    ollama_manager.client = original_client


async def test_test_connection_against_the_live_container_is_reachable_with_bounded_latency(
    live_ollama_url,
):
    result = await ConnectionService.test_connection(live_ollama_url, api_key=None)

    assert result.reachable is True
    assert result.error is None
    assert result.latency_ms is not None
    assert result.latency_ms < 5000


async def test_save_connection_then_list_models_reaches_the_real_container_end_to_end(
    live_ollama_url, real_db_manager, restore_ollama_manager
):
    await ConnectionService.save_connection(
        OllamaConnectionUpdate(mode="remote", remote_url=live_ollama_url)
    )

    assert ollama_manager.base_url == live_ollama_url

    models = await ollama_manager.list_models()

    assert models.models == []


async def test_test_connection_against_a_closed_port_reports_connection_refused():
    result = await ConnectionService.test_connection("http://127.0.0.1:1", api_key=None)

    assert result.reachable is False
    assert "connection refused" in result.error
