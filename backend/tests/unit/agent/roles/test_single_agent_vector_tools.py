"""roles/tools/single_agent_vector_tools.py - start_attack_vector/
report_outcome for the Single Agent flow. report_outcome here resolves
"whichever vector is current" with NO attack_vector_id argument (unlike
pentesting_tools' own version, which takes one explicitly) - a silent
wrong-vector resolution would misattribute a result, so that's the one to
get exactly right below."""

import uuid
from unittest.mock import MagicMock

import pytest

from src.core.agent.roles.tools import single_agent_vector_tools as sa_tools
from src.schemas.attack_vector_scheme import AttackVectorStatus


@pytest.fixture
def ids():
    return {
        "project_id": str(uuid.uuid4()),
        "target_id": str(uuid.uuid4()),
        "agent_run_id": str(uuid.uuid4()),
    }


async def _noop_async(*args, **kwargs):
    return None


def _wire_db(monkeypatch, vector=None):
    fake_db = MagicMock()
    fake_db.get_attack_vector.return_value = vector
    fake_db.update_attack_vector.side_effect = lambda v: v
    fake_db.add_attack_vector.side_effect = lambda v: v
    monkeypatch.setattr(sa_tools, "db_manager", fake_db)
    monkeypatch.setattr(sa_tools.run_registry, "broadcast_attack_vector", _noop_async)
    return fake_db


def _vector(ids, status=AttackVectorStatus.PENDING):
    return MagicMock(id="v-1", target_id=ids["target_id"], status=status)


class _CurrentVector:
    """Minimal stand-in for the agent's own get/set/clear closures - the
    exact 3 callables start_attack_vector/report_outcome are built with."""

    def __init__(self):
        self.current_id = None
        self.tested = False

    def get(self):
        return self.current_id

    def set(self, value):
        self.current_id = value

    def has_tested(self):
        return self.tested

    def clear_tested(self):
        self.tested = False


# --- start_attack_vector ---


@pytest.mark.asyncio
async def test_start_attack_vector_happy_path_selects_and_clears_tested(monkeypatch, ids):
    vector = _vector(ids)
    fake_db = _wire_db(monkeypatch, vector)
    current = _CurrentVector()
    current.tested = True  # should be cleared by a fresh selection
    tool = sa_tools.create_start_attack_vector_tool(
        ids["target_id"], current.get, current.set, current.clear_tested
    )

    result = await tool.ainvoke({"attack_vector_id": "v-1"})

    assert "Selected v-1" in result
    fake_db.update_attack_vector.assert_called_once()
    assert fake_db.update_attack_vector.call_args[0][0].status == AttackVectorStatus.TESTING
    assert current.current_id == "v-1"
    assert current.tested is False


@pytest.mark.asyncio
async def test_start_attack_vector_rejected_when_one_already_selected(monkeypatch, ids):
    fake_db = _wire_db(monkeypatch, vector=None)
    current = _CurrentVector()
    current.current_id = "already-selected"
    tool = sa_tools.create_start_attack_vector_tool(
        ids["target_id"], current.get, current.set, current.clear_tested
    )

    result = await tool.ainvoke({"attack_vector_id": "v-1"})

    assert "already selected" in result
    fake_db.get_attack_vector.assert_not_called()


@pytest.mark.asyncio
async def test_start_attack_vector_rejected_for_unknown_id(monkeypatch, ids):
    fake_db = _wire_db(monkeypatch, vector=None)
    current = _CurrentVector()
    tool = sa_tools.create_start_attack_vector_tool(
        ids["target_id"], current.get, current.set, current.clear_tested
    )

    result = await tool.ainvoke({"attack_vector_id": "nope"})

    assert "not found" in result
    assert current.current_id is None


@pytest.mark.asyncio
async def test_start_attack_vector_rejected_when_not_pending(monkeypatch, ids):
    vector = _vector(ids, status=AttackVectorStatus.TESTING)
    _wire_db(monkeypatch, vector)
    current = _CurrentVector()
    tool = sa_tools.create_start_attack_vector_tool(
        ids["target_id"], current.get, current.set, current.clear_tested
    )

    result = await tool.ainvoke({"attack_vector_id": "v-1"})

    assert "not pending" in result
    assert current.current_id is None


# --- report_outcome: resolving "whichever vector is current" ---


@pytest.mark.asyncio
async def test_report_outcome_resolves_to_the_actual_current_vector(monkeypatch, ids):
    vector = _vector(ids, status=AttackVectorStatus.TESTING)
    fake_db = _wire_db(monkeypatch, vector)
    current = _CurrentVector()
    current.current_id = "v-1"
    current.tested = True
    tool = sa_tools.create_report_outcome_tool(
        ids["project_id"],
        ids["target_id"],
        ids["agent_run_id"],
        current.get,
        current.set,
        current.has_tested,
        current.clear_tested,
    )

    result = await tool.ainvoke({"outcome": "vulnerable", "summary": "confirmed", "new_vectors": []})

    assert "Recorded outcome for v-1" in result
    fake_db.get_attack_vector.assert_called_once_with("v-1")
    updated = fake_db.update_attack_vector.call_args[0][0]
    assert updated.status == AttackVectorStatus.TESTED_VULNERABLE
    # Resolved and then cleared - ready for the next vector.
    assert current.current_id is None
    assert current.tested is False


@pytest.mark.asyncio
async def test_report_outcome_errors_cleanly_when_no_vector_is_current(monkeypatch, ids):
    fake_db = _wire_db(monkeypatch, vector=None)
    current = _CurrentVector()  # current_id stays None

    tool = sa_tools.create_report_outcome_tool(
        ids["project_id"],
        ids["target_id"],
        ids["agent_run_id"],
        current.get,
        current.set,
        current.has_tested,
        current.clear_tested,
    )

    result = await tool.ainvoke({"outcome": "vulnerable", "summary": "confirmed", "new_vectors": []})

    assert "No attack vector currently selected" in result
    fake_db.get_attack_vector.assert_not_called()
    fake_db.update_attack_vector.assert_not_called()


@pytest.mark.asyncio
async def test_report_outcome_rejected_without_a_real_action_since_selection(monkeypatch, ids):
    vector = _vector(ids, status=AttackVectorStatus.TESTING)
    fake_db = _wire_db(monkeypatch, vector)
    current = _CurrentVector()
    current.current_id = "v-1"
    current.tested = False  # nothing run since start_attack_vector

    tool = sa_tools.create_report_outcome_tool(
        ids["project_id"],
        ids["target_id"],
        ids["agent_run_id"],
        current.get,
        current.set,
        current.has_tested,
        current.clear_tested,
    )

    result = await tool.ainvoke({"outcome": "vulnerable", "summary": "confirmed", "new_vectors": []})

    assert "haven't actually run anything" in result
    fake_db.update_attack_vector.assert_not_called()
    # The selection itself must survive a rejection - it must still be
    # resolvable once the agent actually runs something.
    assert current.current_id == "v-1"


# --- Confirms the documented verification gap (crawler finding) ---


@pytest.mark.asyncio
async def test_report_outcome_accepts_vulnerable_claim_with_no_evidence_check_at_all(
    monkeypatch, ids
):
    # single_agent_vector_tools.create_report_outcome_tool's own docstring
    # claims "same resolution logic as pentesting_tools" - but unlike
    # pentesting's version, this one never calls
    # agent_tools._verify_claim_against_evidence at all. Confirmed here:
    # a "vulnerable" outcome is accepted with no evidence check, which is
    # the real discrepancy role-tools-modules.md flags (not a passing
    # requirement - a gap worth fixing, recorded as such).
    vector = _vector(ids, status=AttackVectorStatus.TESTING)
    _wire_db(monkeypatch, vector)
    current = _CurrentVector()
    current.current_id = "v-1"
    current.tested = True

    tool = sa_tools.create_report_outcome_tool(
        ids["project_id"],
        ids["target_id"],
        ids["agent_run_id"],
        current.get,
        current.set,
        current.has_tested,
        current.clear_tested,
    )

    # No get_last_raw_output / evidence parameter exists on this tool's
    # signature at all - there is nothing to even feed it.
    import inspect

    assert "get_last_raw_output" not in inspect.signature(
        sa_tools.create_report_outcome_tool
    ).parameters

    result = await tool.ainvoke(
        {"outcome": "vulnerable", "summary": "pure fabrication, no real evidence", "new_vectors": []}
    )

    assert "Recorded outcome for v-1: vulnerable" in result
