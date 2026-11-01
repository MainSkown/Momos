"""Unit tests for run_registry.run_exclusively_if_idle - the atomic
switch-guard Milestone 3's connection_service.save_connection relies on
(docs/plans/milestone-3-remote-ollama-connection.md, O2). Separate file
from test_run_registry.py so this one function's own autouse reset fixture
doesn't get lost among that file's much larger surface area.
"""

import asyncio
from unittest.mock import AsyncMock

import pytest

from src.core.agent import run_registry
from src.utils.exceptions import ConnectionSwitchBlockedException


@pytest.fixture(autouse=True)
def _reset_run_registry_slots():
    run_registry._project_slot_counts.clear()
    run_registry._global_slot_count = 0
    run_registry._project_slot_condition = asyncio.Condition()
    yield


async def test_runs_the_action_and_returns_its_result_when_no_slots_are_held():
    action = AsyncMock(return_value="saved")

    result = await run_registry.run_exclusively_if_idle(action)

    assert result == "saved"
    action.assert_awaited_once()


async def test_raises_connection_switch_blocked_and_never_calls_action_when_a_slot_is_held():
    run_registry._global_slot_count = 2
    action = AsyncMock(return_value="saved")

    with pytest.raises(ConnectionSwitchBlockedException) as exc_info:
        await run_registry.run_exclusively_if_idle(action)

    assert exc_info.value.running_count == 2
    action.assert_not_awaited()


async def test_holds_the_lock_across_the_action_so_a_concurrent_acquire_waits_for_it():
    """The whole point of run_exclusively_if_idle over a plain "check, then
    separately write": no acquire_agent_slot call may interleave between
    the idle-check and the action completing. Proven here by starting a
    slow action and showing a concurrent acquire_agent_slot call stays
    blocked until that action - not just the check - has finished."""
    monkeypatch_cap = AsyncMock(return_value=5)
    run_registry._current_global_cap = monkeypatch_cap
    release = asyncio.Event()

    async def slow_action():
        await release.wait()
        return "done"

    guarded_task = asyncio.create_task(run_registry.run_exclusively_if_idle(slow_action))
    await asyncio.sleep(0.05)

    acquire_task = asyncio.create_task(run_registry.acquire_agent_slot("p1", 5))
    await asyncio.sleep(0.05)
    assert not acquire_task.done()

    release.set()
    assert await asyncio.wait_for(guarded_task, timeout=1) == "done"
    await asyncio.wait_for(acquire_task, timeout=1)
    await run_registry.release_agent_slot("p1")


async def test_a_slot_acquired_before_the_call_is_detected_even_though_the_condition_was_free():
    """_global_slot_count, not the condition's own lock state, is the thing
    being checked - a slot already held (and then released, as a real
    acquire_agent_slot/release_agent_slot pair would do) must still be
    visible as 'currently running' for as long as it's held."""
    run_registry._current_global_cap = AsyncMock(return_value=5)
    await run_registry.acquire_agent_slot("p1", 5)

    with pytest.raises(ConnectionSwitchBlockedException):
        await run_registry.run_exclusively_if_idle(AsyncMock())

    await run_registry.release_agent_slot("p1")
