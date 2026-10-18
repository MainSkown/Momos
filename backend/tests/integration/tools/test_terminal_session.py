"""§1.4a tier 2 (docs/testing-plan.md) - the same real open_session/run/
switch_session/close_session machinery test_kali_session.py already proves
for tier 1 (against a bare `generic_container`), now exercised through the
unmodified real create_terminal_tools factory against `live_kali_session`/
`pentest_tools_image` instead - proving the interactive terminal-session
plumbing also works end-to-end against the real attacker image, with
actual tools installed, not just a plain shell.

Two things are replaced, same "patch the consumer, not the source" pattern
as tier-1's own `manager` fixture:
- `agent_tools.kali_registry.get_manager`, so the real tool factory reaches
  `live_kali_session`'s manager/container.
- `agent_tools._get_project_settings`, so run()'s own `_maybe_condense`
  doesn't route a network-facing command's (e.g. nmap's) real output
  through `_parse_output` - which would otherwise need a real project row/
  parsing-model config from `db_manager`, a real Postgres dependency this
  tier deliberately has none of. This is exactly why tier-1's own test file
  never uses a _NETWORK_FACING_BINARIES command at all; stubbing this one
  lookup to "no parsing model configured" (its own normal, supported
  fallback - see `_parse_output`) lets this file use a real one instead,
  while everything else (the real session, the real nmap exec) stays
  completely unmodified.

Everything here is real Docker exec against a real container - nothing
about KaliManger/KaliSession/create_terminal_tools is faked."""

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


def _tools_by_name(tools) -> dict:
    return {t.name: t for t in tools}


async def _invoke(tool, **args):
    return await tool.ainvoke(
        {"name": tool.name, "args": args, "id": "test-call", "type": "tool_call"}
    )


@pytest.fixture
def terminal_tools(live_kali_session, monkeypatch, http_target):
    async def _get_manager(project_id, on_stage=None):
        return live_kali_session.manager

    async def _no_parsing_model_configured(project_id):
        return None

    monkeypatch.setattr(agent_tools.kali_registry, "get_manager", _get_manager)
    monkeypatch.setattr(agent_tools, "_get_project_settings", _no_parsing_model_configured)

    calls = {
        "on_enumeration": [],
        "mark_tested": [],
        "on_session_change": [],
        "on_prompt_state_change": [],
        "on_raw_output": [],
    }
    tools = create_terminal_tools(
        live_kali_session.project_id,
        live_kali_session.target_id,
        live_kali_session.agent_run_id,
        lambda d: calls["on_enumeration"].append(d),
        lambda: calls["mark_tested"].append(True),
        lambda name, command: calls["on_session_change"].append((name, command)),
        lambda is_open: calls["on_prompt_state_change"].append(is_open),
        lambda output: calls["on_raw_output"].append(output),
    )
    return _tools_by_name(tools), calls


@pytest.mark.live_tools
@pytest.mark.timeout(120)
async def test_run_executes_real_nmap_interactively_against_http_target(terminal_tools):
    """The free-text interactive pathway specifically - nmap typed into the
    session via run(), not nmap_scan's one-shot tier-1 tool - must relay
    the real scan's own real findings (port 80, the real nginx version
    string) back through the session unmodified."""
    tools, _ = terminal_tools

    result = await _invoke(
        tools[RUN_TOOL_NAME], input="nmap -Pn -sV http-target", wait_seconds=20
    )

    assert "80/tcp open" in result.artifact
    assert "nginx" in result.artifact


@pytest.mark.live_tools
@pytest.mark.timeout(90)
async def test_new_session_switch_session_and_close_session_real_lifecycle(
    terminal_tools, live_kali_session
):
    """Session switch/close against the real attacker image - mirrors tier-
    1's own TestKaliSessionLifecycle.
    test_new_session_switch_session_and_close_session_real_lifecycle, now
    proving the same registry/session-pointer mechanics hold against
    pentest_tools_image rather than plain alpine."""
    tools, calls = terminal_tools
    manager = live_kali_session.manager
    target_id = live_kali_session.target_id
    agent_run_id = live_kali_session.agent_run_id

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

    closed = await _invoke(tools[CLOSE_SESSION_TOOL_NAME], name="second")
    assert "Session 'second' closed." in closed.content

    remaining = await manager.list_sessions(target_id, agent_run_id)
    assert [s.name for s in remaining] == ["default"]

    close_again = await _invoke(tools[CLOSE_SESSION_TOOL_NAME], name="second")
    assert "No such session 'second'" in close_again.content
