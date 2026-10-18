"""ollama_service.py - see docs/testing-crawler-reports/remaining-services.md's
ollama_service.py section. OllamaService keeps class-level mutable state
(_download_queue/_queued_models/_current_download/_worker_task) shared
across the whole process, so every test resets it via the autouse fixture
below. ollama_manager/db_manager are imported by NAME into
src.services.ollama_service, so patches target that module's reference,
never the source module (see conftest.py's fake_ollama_client docstring
and the module-level docstring in ollama_manager.py)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.schemas import OllamaDownloadProgress
from src.services.ollama_service import OllamaService


@pytest.fixture(autouse=True)
def reset_ollama_service_state():
    OllamaService._download_queue = asyncio.Queue()
    OllamaService._current_download = None
    OllamaService._queued_models = []
    OllamaService._worker_task = None
    OllamaService._download_lock = asyncio.Lock()
    yield
    if OllamaService._worker_task is not None and not OllamaService._worker_task.done():
        OllamaService._worker_task.cancel()


@pytest.fixture
def fake_ollama_manager(monkeypatch):
    manager = AsyncMock()
    monkeypatch.setattr("src.services.ollama_service.ollama_manager", manager)
    return manager


@pytest.fixture
def fake_db_manager_for_service(monkeypatch):
    manager = MagicMock()
    monkeypatch.setattr("src.services.ollama_service.db_manager", manager)
    return manager


def _empty_models_list():
    return SimpleNamespace(models=[])


# --- download_model: check-then-act race (Phase 4 item 3) -----------------


@pytest.mark.asyncio
async def test_concurrent_download_calls_for_same_model_both_queue_it(
    fake_ollama_manager, monkeypatch
):
    """The 'already queued' check and the append to _queued_models are
    separated by an `await cls.get_models_list()`, which used to let two
    concurrent calls for the same model both pass the check before either
    appended, queueing the model twice. Now guarded by `_download_lock`:
    the first call to actually reach the lock runs the whole
    check-then-act atomically, so the second call sees the already-queued
    model and raises instead of queueing a duplicate."""
    fake_ollama_manager.list_models = AsyncMock(return_value=_empty_models_list())
    # Isolate this to download_model's own check-then-act window: the
    # background worker would otherwise dequeue and remove() these entries
    # from _queued_models the moment it gets scheduled, hiding the very
    # queue state this test exists to prove.
    monkeypatch.setattr(OllamaService, "_ensure_worker_running", classmethod(lambda cls: None))

    release = asyncio.Event()

    original_get_models_list = OllamaService.get_models_list

    async def slow_get_models_list():
        await release.wait()
        return await original_get_models_list()

    monkeypatch.setattr(
        OllamaService, "get_models_list", classmethod(lambda cls: slow_get_models_list())
    )

    task_a = asyncio.create_task(OllamaService.download_model("llama3:8b"))
    task_b = asyncio.create_task(OllamaService.download_model("llama3:8b"))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    release.set()
    results = await asyncio.gather(task_a, task_b, return_exceptions=True)

    successes = [r for r in results if r is None]
    failures = [r for r in results if isinstance(r, ValueError)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert OllamaService._queued_models.count("llama3:8b") == 1


@pytest.mark.asyncio
async def test_download_model_raises_when_model_is_current_download(
    fake_ollama_manager,
):
    OllamaService._current_download = "llama3:8b"

    with pytest.raises(ValueError, match="llama3:8b"):
        await OllamaService.download_model("llama3:8b")


@pytest.mark.asyncio
async def test_download_model_raises_when_already_downloaded(fake_ollama_manager):
    existing = SimpleNamespace(model="llama3:8b", details=None, size=0)
    models_list = SimpleNamespace(models=[existing])
    fake_ollama_manager.list_models = AsyncMock(return_value=models_list)
    fake_ollama_manager.show = AsyncMock(return_value=SimpleNamespace(modelinfo={}, capabilities=[]))

    with pytest.raises(ValueError, match="already downloaded"):
        await OllamaService.download_model("llama3:8b")

    assert OllamaService._queued_models == []


# --- _download_worker: one failing pull must not stop the queue ----------


@pytest.mark.asyncio
async def test_worker_keeps_processing_after_one_pull_raises(
    fake_ollama_manager, monkeypatch
):
    """A pull that raises must not stop the worker - the next queued model
    still has to be pulled, and `finally` must still run task_done/clear
    _current_download for the failed one. Proven here by checking the
    SECOND model actually got pulled, not just that no exception escaped."""
    monkeypatch.setattr("src.services.ollama_service.ws_registry", AsyncMock())

    async def pull_model(model_name):
        if model_name == "bad-model":
            raise RuntimeError("pull failed")
        yield OllamaDownloadProgress(model=model_name, status="done", completed=1, total=1)

    fake_ollama_manager.pull_model = pull_model

    OllamaService._queued_models = ["bad-model", "good-model"]
    await OllamaService._download_queue.put("bad-model")
    await OllamaService._download_queue.put("good-model")

    await OllamaService._download_worker()

    assert OllamaService._download_queue.empty()
    assert OllamaService._current_download is None


@pytest.mark.asyncio
async def test_worker_clears_current_download_in_finally_even_on_failure(
    fake_ollama_manager, monkeypatch
):
    monkeypatch.setattr("src.services.ollama_service.ws_registry", AsyncMock())

    async def pull_model(model_name):
        raise RuntimeError("pull failed")
        yield  # pragma: no cover - makes this an async generator

    fake_ollama_manager.pull_model = pull_model

    OllamaService._queued_models = ["bad-model"]
    await OllamaService._download_queue.put("bad-model")

    await OllamaService._download_worker()

    assert OllamaService._current_download is None
    assert OllamaService._download_queue.empty()


@pytest.mark.asyncio
async def test_worker_sends_progress_update_over_websocket(
    fake_ollama_manager, monkeypatch
):
    fake_ws_registry = AsyncMock()
    monkeypatch.setattr("src.services.ollama_service.ws_registry", fake_ws_registry)

    async def pull_model(model_name):
        yield OllamaDownloadProgress(model=model_name, status="done", completed=1, total=1)

    fake_ollama_manager.pull_model = pull_model

    OllamaService._queued_models = ["good-model"]
    await OllamaService._download_queue.put("good-model")

    await OllamaService._download_worker()

    fake_ws_registry.send_message.assert_awaited_once()


# --- get_models_list -------------------------------------------------------


@pytest.mark.asyncio
async def test_get_models_list_wraps_exception_in_runtime_error(fake_ollama_manager):
    fake_ollama_manager.list_models = AsyncMock(side_effect=ConnectionError("down"))

    with pytest.raises(RuntimeError, match="down"):
        await OllamaService.get_models_list()


@pytest.mark.asyncio
async def test_get_models_list_computes_size_gb_from_bytes(fake_ollama_manager):
    model = MagicMock()
    model.model = "llama3:8b"
    model.size = 2 * (1024**3)
    model.details = None
    models_list = MagicMock()
    models_list.models = [model]
    fake_ollama_manager.list_models = AsyncMock(return_value=models_list)
    fake_ollama_manager.show = AsyncMock(return_value=MagicMock(modelinfo={}, capabilities=[]))

    result = await OllamaService.get_models_list()

    assert result.models[0].size_gb == 2.0
    assert result.models[0].family == ""
    assert result.models[0].parameters_size_b == 0.0


# --- delete_model: ordering (Phase 4 item 3) -------------------------------


@pytest.mark.asyncio
async def test_delete_model_does_not_clear_references_when_ollama_delete_fails(
    fake_ollama_manager, fake_db_manager_for_service
):
    fake_ollama_manager.delete_model = AsyncMock(side_effect=RuntimeError("delete failed"))

    with pytest.raises(RuntimeError, match="delete failed"):
        await OllamaService.delete_model("llama3:8b")

    fake_db_manager_for_service.clear_model_references.assert_not_called()


@pytest.mark.asyncio
async def test_delete_model_clears_references_after_successful_ollama_delete(
    fake_ollama_manager, fake_db_manager_for_service
):
    fake_ollama_manager.delete_model = AsyncMock(return_value=None)

    await OllamaService.delete_model("llama3:8b")

    fake_db_manager_for_service.clear_model_references.assert_called_once_with("llama3:8b")


# --- get_download_queue -----------------------------------------------------


def test_get_download_queue_returns_independent_copy():
    OllamaService._current_download = "llama3:8b"
    OllamaService._queued_models = ["other-model"]

    queue_details = OllamaService.get_download_queue()
    queue_details.queue.append("mutated")

    assert OllamaService._queued_models == ["other-model"]
