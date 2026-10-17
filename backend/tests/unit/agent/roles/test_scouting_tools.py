"""roles/tools/scouting_tools.py - propose_attack_vector/finish_scouting."""

import uuid
from unittest.mock import MagicMock

import pytest

from src.core.agent.roles.tools import scouting_tools


@pytest.fixture
def ids():
    return {
        "project_id": str(uuid.uuid4()),
        "target_id": str(uuid.uuid4()),
        "agent_run_id": str(uuid.uuid4()),
    }


async def _noop_async(*args, **kwargs):
    return None


def _wire_db(monkeypatch):
    fake_db = MagicMock()
    fake_db.add_attack_vector.side_effect = lambda v: v
    monkeypatch.setattr(scouting_tools, "db_manager", fake_db)
    monkeypatch.setattr(scouting_tools.run_registry, "broadcast_attack_vector", _noop_async)
    return fake_db


@pytest.mark.asyncio
async def test_propose_attack_vector_rejected_before_any_real_tool_call(monkeypatch, ids):
    # Crawler finding #4: propose_attack_vector is gated on has_tested() -
    # calling it before a single real tool call happened this run must be
    # rejected outright, and must never touch the DB.
    fake_db = _wire_db(monkeypatch)
    tool = scouting_tools.create_propose_attack_vector_tool(
        ids["project_id"], ids["target_id"], ids["agent_run_id"], has_tested=lambda: False
    )

    result = await tool.ainvoke({"descriptions": ["vsftpd 2.3.4 - check known backdoor"]})

    assert "haven't actually run anything" in result
    fake_db.add_attack_vector.assert_not_called()


@pytest.mark.asyncio
async def test_propose_attack_vector_allowed_after_a_real_tool_call(monkeypatch, ids):
    fake_db = _wire_db(monkeypatch)
    tool = scouting_tools.create_propose_attack_vector_tool(
        ids["project_id"], ids["target_id"], ids["agent_run_id"], has_tested=lambda: True
    )

    result = await tool.ainvoke({"descriptions": ["vsftpd 2.3.4 - check known backdoor"]})

    assert "Recorded 1 attack vector" in result
    fake_db.add_attack_vector.assert_called_once()


@pytest.mark.asyncio
async def test_propose_attack_vector_whitespace_only_list_rejected(monkeypatch, ids):
    fake_db = _wire_db(monkeypatch)
    tool = scouting_tools.create_propose_attack_vector_tool(
        ids["project_id"], ids["target_id"], ids["agent_run_id"], has_tested=lambda: True
    )

    result = await tool.ainvoke({"descriptions": ["   ", ""]})

    assert "cannot be empty" in result
    fake_db.add_attack_vector.assert_not_called()


@pytest.mark.asyncio
async def test_propose_attack_vector_mixed_list_saves_only_non_empty(monkeypatch, ids):
    fake_db = _wire_db(monkeypatch)
    tool = scouting_tools.create_propose_attack_vector_tool(
        ids["project_id"], ids["target_id"], ids["agent_run_id"], has_tested=lambda: True
    )

    result = await tool.ainvoke({"descriptions": ["  ", "real vector A", "   real vector B  "]})

    assert "Recorded 2 attack vector" in result
    assert fake_db.add_attack_vector.call_count == 2
    saved_descriptions = [c.args[0].description for c in fake_db.add_attack_vector.call_args_list]
    assert saved_descriptions == ["real vector A", "real vector B"]


@pytest.mark.asyncio
async def test_finish_scouting_calls_on_finish_exactly_once():
    calls = []
    tool = scouting_tools.create_finish_scouting_tool(on_finish=lambda s: calls.append(s))

    result = await tool.ainvoke({"summary": "enumerated everything"})

    assert calls == ["enumerated everything"]
    assert "Ending the run now" in result
