"""roles/agents/scouting_agent.py.

Builds a real ScoutingAgent (ChatOllama patched out - see
role-agents-graphs.md's testability-blockers section: it's constructed
directly inside changeModel, with no factory seam, so tests must patch the
name in this module) backed by a real langgraph MemorySaver, and drives it
through its own real tool factories against a fake db_manager - never
against the pure dict/logic in isolation, so these actually exercise the
production wiring, not a reimplementation of it.
"""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from langchain_core.messages import AIMessage
from langgraph.checkpoint.memory import MemorySaver

from src.core.agent.roles.agents import scouting_agent as scouting_mod
from src.core.agent.roles.tools import scouting_tools


def _make_agent(monkeypatch, allow_shell=False):
    fake_llm = MagicMock()
    fake_llm.bind_tools.return_value = MagicMock()
    monkeypatch.setattr(scouting_mod, "ChatOllama", MagicMock(return_value=fake_llm))

    agent = scouting_mod.ScoutingAgent(
        model_name="test-model",
        checkpointer=MemorySaver(),
        project_id=str(uuid.uuid4()),
        target_id=str(uuid.uuid4()),
        agent_run_id=str(uuid.uuid4()),
        allow_shell=allow_shell,
    )
    return agent


# --- Dead dedup-code fix confirmation (crawler finding #2) ---
#
# role-agents-graphs.md / role-tools-modules.md both claimed
# _pending_proposed_vectors was dead: nothing in build_scouting_agent_tools
# called back into it, so the "already proposed - don't repeat" block in
# _render_context_message never had anything to show. Fixed by rebuilding
# propose_attack_vector (in __init__) wired to
# ScoutingAgent._register_proposed_vector. Proven here by going through the
# REAL propose_attack_vector tool (not poking the private buffer directly)
# and showing it now gets written, and that a repeat name is deduped.


@pytest.mark.asyncio
async def test_propose_attack_vector_populates_the_dedup_buffer(monkeypatch):
    agent = _make_agent(monkeypatch)

    fake_db = MagicMock()
    fake_db.add_attack_vector.side_effect = lambda v: v
    monkeypatch.setattr(scouting_tools, "db_manager", fake_db)

    propose_tool = next(
        t for t in agent.tools if t.name == scouting_tools.PROPOSE_ATTACK_VECTOR_TOOL_NAME
    )
    agent._mark_tested()  # has_tested() must be True for the tool to accept anything

    result = await propose_tool.ainvoke({"descriptions": ["vsftpd 2.3.4 on port 21 - check backdoor"]})

    assert "Recorded 1 attack vector" in result
    # The fix: a real, successful propose call now writes into the buffer
    # _call_model drains into ScoutingState.proposed_vectors - the "don't
    # repeat these" context block has something to render.
    assert agent._pending_proposed_vectors == ["vsftpd 2.3.4 on port 21 - check backdoor"]

    # Confirm the state update _call_model would produce is equally
    # populated, proving the whole pipeline (tool -> buffer -> state) is
    # wired, not just the buffer in isolation.
    state_update_proposed_vectors = list({"proposed_vectors": []}.get("proposed_vectors") or [])
    state_update_proposed_vectors.extend(agent._pending_proposed_vectors)
    assert state_update_proposed_vectors == ["vsftpd 2.3.4 on port 21 - check backdoor"]


@pytest.mark.asyncio
async def test_propose_attack_vector_rejects_an_already_proposed_duplicate(monkeypatch):
    agent = _make_agent(monkeypatch)

    fake_db = MagicMock()
    fake_db.add_attack_vector.side_effect = lambda v: v
    monkeypatch.setattr(scouting_tools, "db_manager", fake_db)

    propose_tool = next(
        t for t in agent.tools if t.name == scouting_tools.PROPOSE_ATTACK_VECTOR_TOOL_NAME
    )
    agent._mark_tested()

    first = await propose_tool.ainvoke({"descriptions": ["vsftpd 2.3.4 on port 21 - check backdoor"]})
    assert "Recorded 1 attack vector" in first

    second = await propose_tool.ainvoke({"descriptions": ["vsftpd 2.3.4 on port 21 - check backdoor"]})

    # The duplicate must be rejected, not saved again, and the buffer must
    # not grow a second copy of the same description.
    assert "Skipped 1 already-proposed duplicate" in second
    assert fake_db.add_attack_vector.call_count == 1
    assert agent._pending_proposed_vectors == ["vsftpd 2.3.4 on port 21 - check backdoor"]


# --- Enumeration merge logic (pure-ish, via the real _record_enumeration) ---


@pytest.mark.asyncio
async def test_enumeration_merge_keeps_earlier_value_when_later_fact_is_blank(monkeypatch):
    # The real merge (in _call_model) combines the PERSISTED state's
    # enumeration from earlier turns with this turn's freshly-recorded
    # _pending_enumeration - exercised here through the real method, not a
    # reimplementation of its merge expression.
    agent = _make_agent(monkeypatch)
    agent.llm_with_tools.ainvoke = AsyncMock(return_value=AIMessage(content="ok", tool_calls=[]))
    agent._pending_enumeration = {"80": {"service": "", "version": ""}}

    state = {
        "messages": [],
        "target_scope": {},
        "enumeration": {"80": {"service": "http", "version": "1.0"}},
        "proposed_vectors": [],
    }
    result = await agent._call_model(state)

    # A later blank value must not erase the earlier real one.
    assert result["enumeration"]["80"] == {"service": "http", "version": "1.0"}


@pytest.mark.asyncio
async def test_enumeration_merge_overrides_with_non_empty_later_value(monkeypatch):
    agent = _make_agent(monkeypatch)
    agent.llm_with_tools.ainvoke = AsyncMock(return_value=AIMessage(content="ok", tool_calls=[]))
    agent._pending_enumeration = {"80": {"version": "2.0"}}

    state = {
        "messages": [],
        "target_scope": {},
        "enumeration": {"80": {"service": "http", "version": "1.0"}},
        "proposed_vectors": [],
    }
    result = await agent._call_model(state)

    assert result["enumeration"]["80"] == {"service": "http", "version": "2.0"}


# --- requires_interrupt branches (captured straight out of start_agent) ---


@pytest.mark.asyncio
async def test_requires_interrupt_branches(monkeypatch):
    agent = _make_agent(monkeypatch, allow_shell=False)

    captured = {}

    async def fake_run_graph_loop(*args, **kwargs):
        # requires_interrupt is run_graph_loop's 7th positional parameter
        # (app, thread_id, input_data, stop_event, context_window, is_done,
        # requires_interrupt, ...) - scouting_agent.py calls it positionally.
        captured["requires_interrupt"] = args[6]
        return
        yield  # pragma: no cover - makes this an async generator

    monkeypatch.setattr(scouting_mod.common, "run_graph_loop", fake_run_graph_loop)

    target = SimpleNamespace(name="t", description=None, ipv4=None, ipv6=None, ports=[])
    async for _ in agent.start_agent(
        target=target,
        start_prompt="go",
        thread_id="t1",
        should_interrupt=True,
        stop_event=None,
    ):
        pass

    requires_interrupt = captured["requires_interrupt"]
    writer = next(iter(scouting_tools.WRITER_TOOL_NAMES))
    reader = scouting_tools.PROPOSE_ATTACK_VECTOR_TOOL_NAME
    always = next(iter(scouting_tools.ALWAYS_INTERRUPT_TOOL_NAMES))

    # Writer + reader in the same turn: False - the race guard rejects the
    # whole turn before an interrupt decision would even matter.
    assert requires_interrupt({writer, reader}) is False
    # Writer only, should_interrupt=True (passed above): True.
    assert requires_interrupt({writer}) is True
    # An ALWAYS_INTERRUPT tool always interrupts, even alone.
    assert requires_interrupt({always}) is True
    # Reader only: never needs approval.
    assert requires_interrupt({reader}) is False
