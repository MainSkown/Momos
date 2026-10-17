"""Unit tests for backend/src/core/agent/run_registry.py.

See docs/testing-plan.md's "Agent / orchestration layer" bullet under
§1.4 and docs/testing-crawler-reports/agent-core-files.md's run_registry.py
section. Named bug under test here: release_agent_slot clamps the
per-project count at 0 but releases the GLOBAL semaphore unconditionally,
so calling it more times than a slot was acquired permanently raises the
global concurrency cap above GLOBAL_MAX_CONCURRENT_AGENTS - see
test_release_agent_slot_called_twice_permanently_raises_the_global_cap.

Module-level mutable globals (pending_interrupts, live_runs_for_target,
_project_slot_counts, _global_agent_semaphore, ...) have no reset
function (see agent-core-files.md's own testability-blockers section) -
_reset_run_registry_globals clears/rebuilds them before every test here.
"""

import asyncio
import uuid
from unittest.mock import AsyncMock

import pytest

from src.core.agent import run_registry
from src.schemas.agent_run_scheme import AgentRun, AgentRunState


@pytest.fixture(autouse=True)
def _reset_run_registry_globals():
    run_registry.pending_interrupts.clear()
    run_registry.pending_interrupt_tool_calls.clear()
    run_registry.live_runs_for_target.clear()
    run_registry.stop_events.clear()
    run_registry.run_states.clear()
    run_registry.finish_intents.clear()
    run_registry.current_session_for_target.clear()
    run_registry._project_slot_counts.clear()
    run_registry._global_agent_semaphore = asyncio.Semaphore(
        run_registry.settings.GLOBAL_MAX_CONCURRENT_AGENTS
    )
    run_registry._project_slot_condition = asyncio.Condition()
    yield


def _set_global_cap(monkeypatch, value: int):
    monkeypatch.setattr(run_registry.settings, "GLOBAL_MAX_CONCURRENT_AGENTS", value)
    monkeypatch.setattr(run_registry, "_global_agent_semaphore", asyncio.Semaphore(value))


class TestAcquireAndReleaseAgentSlot:
    async def test_a_second_caller_for_the_same_project_blocks_until_release(self, monkeypatch):
        _set_global_cap(monkeypatch, 5)
        await run_registry.acquire_agent_slot("proj1", 1)

        task = asyncio.create_task(run_registry.acquire_agent_slot("proj1", 1))
        await asyncio.sleep(0.05)
        assert not task.done()

        await run_registry.release_agent_slot("proj1")
        await asyncio.wait_for(task, timeout=1)
        await run_registry.release_agent_slot("proj1")

    async def test_the_global_cap_blocks_a_third_project_even_with_room_per_project(
        self, monkeypatch
    ):
        _set_global_cap(monkeypatch, 2)
        await run_registry.acquire_agent_slot("p1", 5)
        await run_registry.acquire_agent_slot("p2", 5)

        task = asyncio.create_task(run_registry.acquire_agent_slot("p3", 5))
        await asyncio.sleep(0.05)
        assert not task.done()

        await run_registry.release_agent_slot("p1")
        await asyncio.wait_for(task, timeout=1)
        await run_registry.release_agent_slot("p2")
        await run_registry.release_agent_slot("p3")

    async def test_cancelling_while_waiting_on_the_global_semaphore_rolls_back_the_project_slot(
        self, monkeypatch
    ):
        _set_global_cap(monkeypatch, 1)
        await run_registry.acquire_agent_slot("p1", 5)

        task = asyncio.create_task(run_registry.acquire_agent_slot("p2", 5))
        await asyncio.sleep(0.05)
        assert run_registry._project_slot_counts["p2"] == 1

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert run_registry._project_slot_counts.get("p2", 0) == 0
        await run_registry.release_agent_slot("p1")

    async def test_max_concurrent_agents_zero_clamps_to_one_slot_not_zero(self, monkeypatch):
        _set_global_cap(monkeypatch, 5)
        await run_registry.acquire_agent_slot("p1", 0)

        task = asyncio.create_task(run_registry.acquire_agent_slot("p1", 0))
        await asyncio.sleep(0.05)
        assert not task.done()

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await run_registry.release_agent_slot("p1")

    async def test_release_agent_slot_called_twice_permanently_raises_the_global_cap(
        self, monkeypatch
    ):
        """Confirms agent-core-files.md's finding 5: a double release
        leaves the global semaphore holding MORE available slots than
        GLOBAL_MAX_CONCURRENT_AGENTS ever allowed - release_agent_slot
        clamps _project_slot_counts with max(0, ...) but calls
        _global_agent_semaphore.release() unconditionally on every call,
        with no matching guard."""
        _set_global_cap(monkeypatch, 1)
        await run_registry.acquire_agent_slot("p1", 1)

        await run_registry.release_agent_slot("p1")
        await run_registry.release_agent_slot("p1")

        assert run_registry._project_slot_counts.get("p1", 0) == 0
        assert run_registry._global_agent_semaphore._value == 2
        assert run_registry._global_agent_semaphore._value > 1


class TestPersistRunState:
    @pytest.fixture(autouse=True)
    def _patch_dependencies(self, monkeypatch, fake_db_manager):
        self.fake_db_manager = fake_db_manager
        self.fake_ws_registry = AsyncMock()
        monkeypatch.setattr(run_registry, "db_manager", fake_db_manager)
        monkeypatch.setattr(run_registry, "ws_registry", self.fake_ws_registry)

    def _agent_run(self, **overrides):
        defaults = dict(
            id=uuid.uuid4(),
            status=AgentRunState.RUNNING,
            remaining_seconds=0,
            project_id=uuid.uuid4(),
            target_id=uuid.uuid4(),
            role="single_agent",
        )
        defaults.update(overrides)
        return AgentRun(**defaults)

    async def test_agent_run_id_none_routes_to_upsert_not_save(self):
        saved = self._agent_run()
        self.fake_db_manager.upsert_agent_run.return_value = saved

        result = await run_registry.persist_run_state(
            project_id=str(saved.project_id),
            target_id=str(saved.target_id),
            status=AgentRunState.RUNNING,
            remaining_seconds=10,
        )

        self.fake_db_manager.upsert_agent_run.assert_called_once()
        self.fake_db_manager.save_agent_run.assert_not_called()
        assert result is saved
        self.fake_ws_registry.send_message.assert_called_once()

    async def test_a_supplied_agent_run_id_routes_to_save_not_upsert(self):
        saved = self._agent_run()
        self.fake_db_manager.save_agent_run.return_value = saved

        result = await run_registry.persist_run_state(
            project_id=str(saved.project_id),
            target_id=str(saved.target_id),
            status=AgentRunState.RUNNING,
            remaining_seconds=10,
            agent_run_id=str(saved.id),
        )

        self.fake_db_manager.save_agent_run.assert_called_once()
        self.fake_db_manager.upsert_agent_run.assert_not_called()
        assert result is saved

    async def test_the_current_session_for_the_target_is_stamped_onto_the_row(self):
        target_id = str(uuid.uuid4())
        session_id = str(uuid.uuid4())
        run_registry.current_session_for_target[target_id] = session_id
        self.fake_db_manager.upsert_agent_run.side_effect = lambda run: run

        saved = await run_registry.persist_run_state(
            project_id=str(uuid.uuid4()),
            target_id=target_id,
            status=AgentRunState.RUNNING,
            remaining_seconds=10,
        )

        assert str(saved.session_id) == session_id

    async def test_negative_remaining_seconds_is_clamped_to_zero(self):
        self.fake_db_manager.upsert_agent_run.side_effect = lambda run: run

        saved = await run_registry.persist_run_state(
            project_id=str(uuid.uuid4()),
            target_id=str(uuid.uuid4()),
            status=AgentRunState.RUNNING,
            remaining_seconds=-5.9,
        )

        assert saved.remaining_seconds == 0

    async def test_an_invalid_agent_run_id_raises_before_any_database_call(self):
        with pytest.raises(ValueError):
            await run_registry.persist_run_state(
                project_id=str(uuid.uuid4()),
                target_id=str(uuid.uuid4()),
                status=AgentRunState.RUNNING,
                remaining_seconds=10,
                agent_run_id="not-a-uuid",
            )
        self.fake_db_manager.save_agent_run.assert_not_called()
        self.fake_db_manager.upsert_agent_run.assert_not_called()


class TestStartSubRun:
    @pytest.fixture(autouse=True)
    def _patch_dependencies(self, monkeypatch, fake_db_manager):
        self.fake_db_manager = fake_db_manager
        self.fake_ws_registry = AsyncMock()
        monkeypatch.setattr(run_registry, "db_manager", fake_db_manager)
        monkeypatch.setattr(run_registry, "ws_registry", self.fake_ws_registry)

    async def test_registers_the_new_run_id_in_the_targets_live_set(self):
        target_id = str(uuid.uuid4())
        saved = AgentRun(
            id=uuid.uuid4(),
            status=AgentRunState.RUNNING,
            remaining_seconds=0,
            project_id=uuid.uuid4(),
            target_id=uuid.UUID(target_id),
            role="scouting",
        )
        self.fake_db_manager.add_to_database.return_value = saved

        result = await run_registry.start_sub_run(
            project_id=str(saved.project_id),
            target_id=target_id,
            role="scouting",
            parent_run_id=None,
        )

        assert str(result.id) in run_registry.live_runs_for_target[target_id]


class TestCleanupSubRun:
    def test_is_idempotent_for_an_unknown_run_or_target(self):
        run_registry.cleanup_sub_run("no-such-target", "no-such-run")
        run_registry.cleanup_sub_run("no-such-target", "no-such-run")

    def test_removes_the_target_key_once_the_last_run_is_gone(self):
        target_id, run_id = "t1", "r1"
        run_registry.live_runs_for_target[target_id] = {run_id}

        run_registry.cleanup_sub_run(target_id, run_id)

        assert target_id not in run_registry.live_runs_for_target

    def test_keeps_the_target_key_while_a_sibling_run_remains(self):
        target_id = "t1"
        run_registry.live_runs_for_target[target_id] = {"r1", "r2"}

        run_registry.cleanup_sub_run(target_id, "r1")

        assert run_registry.live_runs_for_target[target_id] == {"r2"}

    def test_pops_every_other_per_run_dict_entry_too(self):
        target_id, run_id = "t1", "r1"
        run_registry.live_runs_for_target[target_id] = {run_id}
        run_registry.pending_interrupts[run_id] = lambda approved: None
        run_registry.stop_events[run_id] = asyncio.Event()
        run_registry.run_states[run_id] = {"time_left": 5}
        run_registry.finish_intents[run_id] = True

        run_registry.cleanup_sub_run(target_id, run_id)

        assert run_id not in run_registry.pending_interrupts
        assert run_id not in run_registry.stop_events
        assert run_id not in run_registry.run_states
        assert run_id not in run_registry.finish_intents


class TestStopSignalFanout:
    def test_stop_all_for_target_sets_every_live_runs_stop_event(self):
        target_id = "t1"
        a, b = asyncio.Event(), asyncio.Event()
        run_registry.live_runs_for_target[target_id] = {"a", "b"}
        run_registry.stop_events["a"] = a
        run_registry.stop_events["b"] = b

        run_registry.stop_all_for_target(target_id)

        assert a.is_set() and b.is_set()

    def test_stop_other_runs_for_target_skips_the_callers_own_event_by_identity(self):
        target_id = "t1"
        own = asyncio.Event()
        sibling = asyncio.Event()
        run_registry.live_runs_for_target[target_id] = {"own", "sibling"}
        run_registry.stop_events["own"] = own
        run_registry.stop_events["sibling"] = sibling

        run_registry.stop_other_runs_for_target(target_id, own)

        assert not own.is_set()
        assert sibling.is_set()

    def test_stop_other_runs_for_target_uses_identity_not_equality(self):
        """Two distinct asyncio.Event() instances are never == equal (no
        __eq__ override), so this only guards against a regression that
        swaps `is not` for `!=` and happens to still work by luck."""
        target_id = "t1"
        own = asyncio.Event()
        look_alike = asyncio.Event()
        run_registry.live_runs_for_target[target_id] = {"own", "look_alike"}
        run_registry.stop_events["own"] = own
        run_registry.stop_events["look_alike"] = look_alike

        run_registry.stop_other_runs_for_target(target_id, own)

        assert look_alike.is_set()
        assert not own.is_set()


class TestRenderToolCallContent:
    def test_nmap_scan_shows_ports_and_script_flag(self):
        content = run_registry.render_tool_call_content(
            "nmap_scan", {"ports": "21,80", "run_default_scripts": True}
        )
        assert content == "ports=21,80 (-sC)"

    def test_nmap_scan_with_no_ports_shows_default(self):
        content = run_registry.render_tool_call_content("nmap_scan", {})
        assert content == "ports=default"

    def test_hydra_bruteforce_falls_back_to_username_list(self):
        content = run_registry.render_tool_call_content(
            "hydra_bruteforce", {"service": "ftp", "username_list": "/wordlists/users.txt"}
        )
        assert content == "ftp: /wordlists/users.txt"

    def test_report_outcome_shows_outcome_and_summary(self):
        content = run_registry.render_tool_call_content(
            "report_outcome", {"outcome": "vulnerable", "summary": "anon ftp login"}
        )
        assert content == "[vulnerable] anon ftp login"

    def test_unknown_tool_name_falls_back_to_a_key_value_join(self):
        content = run_registry.render_tool_call_content("some_future_tool", {"a": 1, "b": "x"})
        assert content == "a=1, b=x"


class TestMessageToLogSpecs:
    def test_ai_message_reasoning_content_is_shown_instead_of_visible_content(self):
        from langchain_core.messages import AIMessage

        message = AIMessage(
            content="visible narration",
            additional_kwargs={"reasoning_content": "the actual reasoning"},
        )

        specs = run_registry.message_to_log_specs(message)

        assert specs == [("thinking", "the actual reasoning", None, None)]

    def test_ai_message_with_n_tool_calls_produces_n_tool_specs(self):
        from langchain_core.messages import AIMessage

        message = AIMessage(
            content="",
            tool_calls=[
                {"name": "nmap_scan", "args": {}, "id": "1"},
                {"name": "list_sessions", "args": {}, "id": "2"},
            ],
        )

        specs = run_registry.message_to_log_specs(message)

        assert [s[2] for s in specs] == ["nmap_scan", "list_sessions"]

    def test_searchsploit_view_swaps_display_and_raw_output(self):
        from langchain_core.messages import ToolMessage

        message = ToolMessage(
            content="full raw exploit source",
            name="searchsploit_view",
            tool_call_id="1",
            artifact="short parsed summary",
        )

        specs = run_registry.message_to_log_specs(message)

        assert specs == [("action", "short parsed summary", None, "full raw exploit source")]

    def test_other_tool_message_keeps_content_as_display_and_artifact_as_raw(self):
        from langchain_core.messages import ToolMessage

        message = ToolMessage(
            content="Found 1 open port(s)",
            name="nmap_scan",
            tool_call_id="1",
            artifact="21/tcp open ftp",
        )

        specs = run_registry.message_to_log_specs(message)

        assert specs == [("action", "Found 1 open port(s)", None, "21/tcp open ftp")]
