"""KaliRegistry tests (backend/src/core/kali_integration/kali_registry.py).
Module-level singletons (KaliManger, db_manager) are bound by name into this
module at import time, so every patch below targets
src.core.kali_integration.kali_registry's own reference to them - patching
the source module would have no effect here (see docs/testing-plan.md
§1.3/§1.4's testability-blocker notes)."""

import asyncio
import importlib

import pytest

from src.core.kali_integration.kali_registry import KaliRegistry

# src/core/kali_integration/__init__.py does `from .kali_registry import
# kali_registry`, which overwrites the PACKAGE's own "kali_registry"
# attribute with the singleton instance - `import
# src.core.kali_integration.kali_registry as x` would silently bind x to
# that instance instead of the actual submodule. importlib.import_module
# goes through sys.modules directly and sidesteps that shadowing.
kali_registry_module = importlib.import_module(
    "src.core.kali_integration.kali_registry"
)


class _BlockingManager:
    """Stands in for KaliManger - records whether start() has begun and lets
    the test control exactly when it finishes, without any real Docker
    build."""

    def __init__(self):
        self.began = asyncio.Event()
        self.release = asyncio.Event()

    async def start(self, on_stage=None):
        self.began.set()
        await self.release.wait()


@pytest.fixture
def registry(monkeypatch):
    monkeypatch.setattr(kali_registry_module.db_manager, "get_project_settings", lambda pid: None)
    return KaliRegistry()


# --- Bug 5: get_manager holds its lock across the entire container build ---


async def test_get_manager_if_exists_for_an_unrelated_project_does_not_block_during_a_build(
    registry, monkeypatch
):
    blocking_manager = _BlockingManager()
    monkeypatch.setattr(
        kali_registry_module, "KaliManger", lambda **kwargs: blocking_manager
    )

    build_task = asyncio.create_task(registry.get_manager("project-a"))
    await asyncio.wait_for(blocking_manager.began.wait(), timeout=1)

    # project-a's build is genuinely still in flight - the registry's own
    # lock must already be released (it only ever guards the dict check/
    # insert, not the build itself), so an UNRELATED project's
    # get_manager_if_exists call resolves immediately instead of waiting
    # behind it.
    assert not registry._lock.locked()

    second_task = asyncio.create_task(registry.get_manager_if_exists("project-b"))
    manager_b = await asyncio.wait_for(second_task, timeout=1)
    assert manager_b is None

    blocking_manager.release.set()
    manager_a = await build_task
    assert manager_a is blocking_manager


async def test_delete_manager_for_unrelated_project_does_not_block_during_a_build(
    registry, monkeypatch
):
    blocking_manager = _BlockingManager()
    monkeypatch.setattr(
        kali_registry_module, "KaliManger", lambda **kwargs: blocking_manager
    )

    build_task = asyncio.create_task(registry.get_manager("project-a"))
    await asyncio.wait_for(blocking_manager.began.wait(), timeout=1)

    delete_task = asyncio.create_task(registry.delete_manager("project-b"))
    await asyncio.wait_for(delete_task, timeout=1)

    blocking_manager.release.set()
    await build_task


# --- Standard lifecycle coverage --------------------------------------------


async def test_concurrent_get_manager_calls_construct_exactly_once(registry, monkeypatch):
    construction_count = 0

    class FastManager:
        async def start(self, on_stage=None):
            return None

    def factory(**kwargs):
        nonlocal construction_count
        construction_count += 1
        return FastManager()

    monkeypatch.setattr(kali_registry_module, "KaliManger", factory)

    managers = await asyncio.gather(*(registry.get_manager("project-a") for _ in range(10)))

    assert construction_count == 1
    assert all(m is managers[0] for m in managers)


async def test_failed_start_caches_nothing_and_a_retry_builds_fresh(registry, monkeypatch):
    attempts = []

    class SometimesFailingManager:
        def __init__(self):
            attempts.append(self)

        async def start(self, on_stage=None):
            if len(attempts) == 1:
                raise RuntimeError("docker build failed")

    monkeypatch.setattr(
        kali_registry_module, "KaliManger", lambda **kwargs: SometimesFailingManager()
    )

    with pytest.raises(RuntimeError, match="docker build failed"):
        await registry.get_manager("project-a")

    assert registry.has_manager("project-a") is False

    manager = await registry.get_manager("project-a")
    assert registry.has_manager("project-a") is True
    assert manager is attempts[1]


async def test_get_manager_if_exists_never_constructs_a_manager(registry, monkeypatch):
    def factory(**kwargs):
        raise AssertionError("get_manager_if_exists must never construct a manager")

    monkeypatch.setattr(kali_registry_module, "KaliManger", factory)

    result = await registry.get_manager_if_exists("unknown-project")

    assert result is None


async def test_delete_manager_pops_and_stops_the_manager_exactly_once(registry, monkeypatch):
    class FastManager:
        def __init__(self):
            self.stop_calls = 0

        async def start(self, on_stage=None):
            return None

        async def stop(self):
            self.stop_calls += 1

    monkeypatch.setattr(kali_registry_module, "KaliManger", lambda **kwargs: FastManager())

    manager = await registry.get_manager("project-a")
    await registry.delete_manager("project-a")

    assert manager.stop_calls == 1
    assert registry.has_manager("project-a") is False


async def test_delete_manager_for_missing_project_is_a_no_op(registry):
    await registry.delete_manager("never-existed")
    assert registry.has_manager("never-existed") is False


async def test_shutdown_stops_every_manager_even_if_one_raises(registry, monkeypatch):
    class RaisingManager:
        async def start(self, on_stage=None):
            return None

        async def stop(self):
            raise RuntimeError("stop failed")

    class FineManager:
        def __init__(self):
            self.stopped = False

        async def start(self, on_stage=None):
            return None

        async def stop(self):
            self.stopped = True

    remaining = ["raising", "fine"]
    objects = {"raising": RaisingManager(), "fine": FineManager()}

    def factory(**kwargs):
        return objects[remaining.pop(0)]

    monkeypatch.setattr(kali_registry_module, "KaliManger", factory)
    await registry.get_manager("project-raising")
    await registry.get_manager("project-fine")

    await registry.shutdown()

    assert objects["fine"].stopped is True
    assert registry.has_manager("project-raising") is False
    assert registry.has_manager("project-fine") is False


def test_build_status_set_get_clear_round_trip(registry):
    from src.schemas import KaliCreationStage

    assert registry.get_build_status("project-a") is None

    registry.set_build_stage("project-a", KaliCreationStage.installing_packages, target_id="t1")
    status = registry.get_build_status("project-a")
    assert status.stage == KaliCreationStage.installing_packages
    assert status.target_id == "t1"

    registry.clear_build_status("project-a")
    assert registry.get_build_status("project-a") is None


def test_clear_build_status_on_missing_project_is_a_no_op(registry):
    registry.clear_build_status("never-set")
