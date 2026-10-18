"""§1.4a tier 1 (docs/testing-plan.md) - real open_session/run/
switch_session/close_session/idle-sweep-timeout behavior, exercised through
the unmodified real create_terminal_tools factory and kali_session.py/
kali_manager.py code, against `generic_container` (a real, plain `alpine`
container - see backend/tests/integration/conftest.py). No pentest tools,
no Postgres, no Ollama/LLM: every command used below is a plain shell
builtin, deliberately never one of agent_tools.py's _NETWORK_FACING_
BINARIES, so _maybe_condense's own network-facing gate skips the
parsing-model path entirely and this tier never touches db_manager/Ollama -
exactly the "no test may require a real LLM" rule this whole suite is
built around.

Only `agent_tools.kali_registry.get_manager` is replaced (same pattern the
unit tests in test_agent_tool_factories.py already use for a fake manager) -
everything below it (KaliManger, KaliSession, create_terminal_tools' own
helpers) is the real, unmodified production code."""

import asyncio

import pytest

from src.core.agent import agent_tools
from src.core.agent.agent_tools import (
    CLOSE_SESSION_TOOL_NAME,
    LIST_SESSIONS_TOOL_NAME,
    NEW_SESSION_TOOL_NAME,
    RUN_TOOL_NAME,
    SWITCH_SESSION_TOOL_NAME,
    create_terminal_tools,
)
from src.core.kali_integration import kali_manager as kali_manager_module
from src.core.kali_integration.kali_manager import KaliManger

PROJECT_ID = "test-project-tier1"
TARGET_ID = "test-target-tier1"
AGENT_RUN_ID = "test-run-tier1"


def _tools_by_name(tools) -> dict:
    return {t.name: t for t in tools}


async def _invoke(tool, **args):
    return await tool.ainvoke(
        {"name": tool.name, "args": args, "id": "test-call", "type": "tool_call"}
    )


@pytest.fixture(scope="module")
def manager(generic_container):
    """ONE real KaliManger for the whole module, wired directly onto the
    shared `generic_container` - deliberately NOT via manager.start()
    (which would run _configure_container's apt-get/dpkg-based setup,
    irrelevant and unavailable on a plain Alpine image).

    Deliberately module-scoped, not per-test: KaliManger.__del__ (kali_
    manager.py) stops `self.container` as a safety net whenever a manager
    instance is garbage-collected - a real production behavior, not a test
    artifact. A fresh KaliManger per test pointed at this SHARED,
    session-scoped container was tried first and confirmed (via `docker
    events`) to stop the shared container the moment each test's own
    instance got garbage-collected after that test's teardown - long
    before the later tests in this file ever ran. One manager for the
    module's whole lifetime, matching generic_container's own lifetime,
    means __del__ never fires until everything here is already done.
    Per-test isolation is instead handled by the autouse
    `_clean_sessions` fixture below, which resets this manager's session
    state before/after each test.

    create_terminal_tools' own tools reach this manager through
    kali_registry.get_manager, so that's the one thing patched here -
    mirrors kali_exec/the fake-manager fixtures in tests/unit/agent/
    test_agent_tool_factories.py, just with a real container and real
    docker client underneath instead of a mock. Patched by hand (save/
    restore) rather than via the `monkeypatch` fixture - `monkeypatch` is
    function-scoped, and a module-scoped fixture can't depend on it."""
    instance = KaliManger(container_name=generic_container.name, packages=())
    instance.container = generic_container

    async def _get_manager(project_id, on_stage=None):
        return instance

    original_get_manager = agent_tools.kali_registry.get_manager
    agent_tools.kali_registry.get_manager = _get_manager
    yield instance
    agent_tools.kali_registry.get_manager = original_get_manager


@pytest.fixture(autouse=True)
async def _clean_sessions(manager):
    """Resets the shared module-scoped manager's session state before AND
    after every test, so tests stay isolated from each other despite
    sharing one manager/container - see `manager`'s own docstring for why
    it can't just be a fresh instance per test."""

    async def _reset():
        await manager.close_all_sessions()
        if manager._session_sweep_task is not None:
            manager._session_sweep_task.cancel()
            # Clear the reference too (matching KaliManger.stop()'s own
            # pattern), not just cancel it - pytest-asyncio gives each
            # test its own event loop, and a left-behind reference to an
            # already-cancelled task gets `.cancel()`-ed AGAIN by a later
            # test's reset, on a loop that doesn't own it - which raises
            # `RuntimeError: Event loop is closed` instead of being the
            # harmless no-op it looks like.
            manager._session_sweep_task = None
        manager.session_closed_notifier = None

    await _reset()
    yield
    await _reset()


@pytest.fixture
def terminal_tools(manager):
    calls = {
        "on_enumeration": [],
        "mark_tested": [],
        "on_session_change": [],
        "on_prompt_state_change": [],
        "on_raw_output": [],
    }
    tools = create_terminal_tools(
        PROJECT_ID,
        TARGET_ID,
        AGENT_RUN_ID,
        lambda d: calls["on_enumeration"].append(d),
        lambda: calls["mark_tested"].append(True),
        lambda name, command: calls["on_session_change"].append((name, command)),
        lambda is_open: calls["on_prompt_state_change"].append(is_open),
        lambda output: calls["on_raw_output"].append(output),
    )
    return _tools_by_name(tools), calls


@pytest.mark.live_tools
@pytest.mark.timeout(90)
class TestKaliSessionLifecycle:
    async def test_run_auto_opens_default_session_and_executes_real_command(
        self, terminal_tools
    ):
        """No session is open yet - run()'s own _resolve_current_session
        must transparently open the "default" bash session (real
        open_session/_open_session_sync, a real docker exec_create against
        generic_container) before sending the command."""
        tools, calls = terminal_tools

        result = await _invoke(
            tools[RUN_TOOL_NAME], input="echo hello-from-tier1", wait_seconds=3
        )

        assert "hello-from-tier1" in result.artifact
        assert calls["on_session_change"] == [("default", "/bin/bash")]

    async def test_new_session_switch_session_and_close_session_real_lifecycle(
        self, terminal_tools, manager
    ):
        tools, calls = terminal_tools

        # Opening "default" implicitly via run(), then a second real session.
        await _invoke(tools[RUN_TOOL_NAME], input="echo in-default", wait_seconds=3)

        opened = await _invoke(
            tools[NEW_SESSION_TOOL_NAME], name="second", command="/bin/bash"
        )
        assert "Session 'second' opened and is now current." in opened.content

        in_second = await _invoke(
            tools[RUN_TOOL_NAME], input="echo in-second-session", wait_seconds=3
        )
        assert "in-second-session" in in_second.artifact

        listed = await _invoke(tools[LIST_SESSIONS_TOOL_NAME])
        assert "default" in listed.content
        assert "second (current)" in listed.content

        switched = await _invoke(tools[SWITCH_SESSION_TOOL_NAME], name="default")
        assert "Switched to session 'default'." in switched.content

        back_in_default = await _invoke(
            tools[RUN_TOOL_NAME], input="pwd", wait_seconds=3
        )
        assert "/home/momos" in back_in_default.artifact

        closed = await _invoke(tools[CLOSE_SESSION_TOOL_NAME], name="second")
        assert "Session 'second' closed." in closed.content

        # Real registry state, not just the tool's own claim.
        remaining = await manager.list_sessions(TARGET_ID, AGENT_RUN_ID)
        assert [s.name for s in remaining] == ["default"]

        close_again = await _invoke(tools[CLOSE_SESSION_TOOL_NAME], name="second")
        assert "No such session 'second'" in close_again.content

    async def test_close_session_unknown_name_reports_nothing_to_close(
        self, terminal_tools
    ):
        tools, _ = terminal_tools
        result = await _invoke(tools[CLOSE_SESSION_TOOL_NAME], name="never-opened")
        assert "No such session 'never-opened'" in result.content


@pytest.mark.live_tools
@pytest.mark.timeout(60)
async def test_idle_sweep_really_closes_a_quiet_session(
    terminal_tools, manager, monkeypatch
):
    """Real idle-sweep behavior from kali_manager.py's own
    _sweep_idle_sessions background task - SESSION_IDLE_TIMEOUT_SECONDS/
    SESSION_SWEEP_INTERVAL_SECONDS are patched down from their 20-minute/
    60-second production defaults so this can run in a handful of real
    seconds, without touching kali_manager.py itself: both names are bound
    into kali_manager's own module namespace via `from .kali_session import
    ...`, so the patch target is kali_manager_module (the consuming
    module), not kali_session - same "patch the consumer, not the source"
    rule docs/testing-plan.md §1.3 already documents project-wide."""
    monkeypatch.setattr(kali_manager_module, "SESSION_IDLE_TIMEOUT_SECONDS", 2)
    monkeypatch.setattr(kali_manager_module, "SESSION_SWEEP_INTERVAL_SECONDS", 1)

    tools, _ = terminal_tools
    notified = []

    async def _notifier(target_id, name):
        notified.append((target_id, name))

    manager.session_closed_notifier = _notifier

    await _invoke(tools[RUN_TOOL_NAME], input="echo still-alive", wait_seconds=3)

    # Past the patched idle timeout plus at least one sweep interval, with
    # margin - the session must not be touched again in the meantime, or
    # last_activity resets and the sweep never fires.
    await asyncio.sleep(5)

    remaining = await manager.list_sessions(TARGET_ID, AGENT_RUN_ID)
    assert remaining == []
    assert notified == [(TARGET_ID, "default")]

    # The agent-facing tool layer must see the same reality, not just
    # internal manager state.
    result = await _invoke(tools[CLOSE_SESSION_TOOL_NAME], name="default")
    assert "No such session 'default'" in result.content
