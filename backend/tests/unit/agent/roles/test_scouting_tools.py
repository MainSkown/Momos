"""agent_tools/roles/scouting_tools.py - propose_attack_vector/finish_scouting."""

import uuid
from unittest.mock import MagicMock

import pytest

from src.core.agent import agent_tools
from src.core.agent.agent_tools.roles import scouting_tools


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
async def test_propose_attack_vector_without_register_proposed_never_dedupes(monkeypatch, ids):
    # register_proposed is optional (defaults to None) - a caller that
    # doesn't pass it (e.g. this test, or any other direct caller of the
    # tool factory) gets the old no-dedup behavior unchanged.
    fake_db = _wire_db(monkeypatch)
    tool = scouting_tools.create_propose_attack_vector_tool(
        ids["project_id"], ids["target_id"], ids["agent_run_id"], has_tested=lambda: True
    )

    await tool.ainvoke({"descriptions": ["same vector"]})
    result = await tool.ainvoke({"descriptions": ["same vector"]})

    assert "Recorded 1 attack vector" in result
    assert fake_db.add_attack_vector.call_count == 2


@pytest.mark.asyncio
async def test_propose_attack_vector_register_proposed_rejects_duplicate(monkeypatch, ids):
    # The real dedup wiring, exercised directly against the tool factory's
    # own register_proposed parameter - ScoutingAgent._register_proposed_vector
    # is one real implementation of this callable, but the tool's own
    # check/skip/report logic is what's pinned here.
    fake_db = _wire_db(monkeypatch)
    seen = set()

    def register_proposed(description: str) -> bool:
        if description in seen:
            return False
        seen.add(description)
        return True

    tool = scouting_tools.create_propose_attack_vector_tool(
        ids["project_id"],
        ids["target_id"],
        ids["agent_run_id"],
        has_tested=lambda: True,
        register_proposed=register_proposed,
    )

    first = await tool.ainvoke({"descriptions": ["vsftpd 2.3.4 - check known backdoor"]})
    second = await tool.ainvoke({"descriptions": ["vsftpd 2.3.4 - check known backdoor"]})

    assert "Recorded 1 attack vector" in first
    assert "Recorded 1 attack vector" not in second
    assert "Skipped 1 already-proposed duplicate" in second
    fake_db.add_attack_vector.assert_called_once()


@pytest.mark.asyncio
async def test_finish_scouting_calls_on_finish_exactly_once():
    calls = []
    tool = scouting_tools.create_finish_scouting_tool(on_finish=lambda s: calls.append(s))

    result = await tool.ainvoke({"summary": "enumerated everything"})

    assert calls == ["enumerated everything"]
    assert "Ending the run now" in result


def test_scouting_allowed_pentest_tool_names_is_exact_set():
    assert scouting_tools.ALLOWED_PENTEST_TOOL_NAMES == {
        agent_tools.NMAP_SCAN_TOOL_NAME,
        agent_tools.GOBUSTER_SCAN_TOOL_NAME,
        agent_tools.SEARCHSPLOIT_SEARCH_TOOL_NAME,
        agent_tools.SEARCHSPLOIT_VIEW_TOOL_NAME,
        agent_tools.NIKTO_SCAN_TOOL_NAME,
        agent_tools.WHATWEB_SCAN_TOOL_NAME,
        agent_tools.SMB_ENUM_TOOL_NAME,
        agent_tools.SNMP_ENUM_TOOL_NAME,
        agent_tools.TESTSSL_SCAN_TOOL_NAME,
        agent_tools.WPSCAN_ENUM_TOOL_NAME,
        agent_tools.DNS_RECON_TOOL_NAME,
        agent_tools.PACKET_CAPTURE_TOOL_NAME,
    }


def test_scouting_writer_tool_names_includes_the_new_target_touching_tools():
    # nikto_scan/whatweb_scan/smb_enum/snmp_enum all send real traffic to
    # the target, same as nmap_scan/gobuster_scan - they must be writers
    # (and therefore interrupt-gated, since INTERRUPT_GATED_TOOL_NAMES is
    # just an alias of this set) or make_guarded_tools_node's write/read
    # race guard silently stops covering them.
    assert agent_tools.NIKTO_SCAN_TOOL_NAME in scouting_tools.WRITER_TOOL_NAMES
    assert agent_tools.WHATWEB_SCAN_TOOL_NAME in scouting_tools.WRITER_TOOL_NAMES
    assert agent_tools.SMB_ENUM_TOOL_NAME in scouting_tools.WRITER_TOOL_NAMES
    assert agent_tools.SNMP_ENUM_TOOL_NAME in scouting_tools.WRITER_TOOL_NAMES
    assert scouting_tools.INTERRUPT_GATED_TOOL_NAMES is scouting_tools.WRITER_TOOL_NAMES


def test_scouting_writer_tool_names_includes_the_new_recon_tools():
    # Hand-enumerated set, not a union with ALLOWED_PENTEST_TOOL_NAMES - a new
    # target-touching tool added only to the allowed set silently escapes the
    # race guard and interrupt gating.
    new_recon_writers = {
        agent_tools.TESTSSL_SCAN_TOOL_NAME,
        agent_tools.WPSCAN_ENUM_TOOL_NAME,
        agent_tools.DNS_RECON_TOOL_NAME,
        agent_tools.PACKET_CAPTURE_TOOL_NAME,
    }
    assert new_recon_writers <= scouting_tools.WRITER_TOOL_NAMES
