"""roles/agents/orchestrator_agent.py - the pipeline's outer loop. _is_done
and _render_context_message both read the live AttackVector board via
db_manager (module-level import, patched per-module per conftest.py's
project-wide rule), never from checkpointed state."""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from langgraph.checkpoint.memory import MemorySaver

from src.core.agent.roles.agents import orchestrator_agent as orch_mod
from src.schemas.attack_vector_scheme import AttackVectorStatus


def _vector(status, linked=None, description="desc", vid=None):
    return MagicMock(
        id=vid or str(uuid.uuid4()),
        status=status,
        linked_vulnerability_id=linked,
        description=description,
    )


def _make_agent(monkeypatch):
    fake_llm = MagicMock()
    fake_llm.bind_tools.return_value = MagicMock()
    monkeypatch.setattr(orch_mod, "ChatOllama", MagicMock(return_value=fake_llm))

    fake_db = MagicMock()
    monkeypatch.setattr(orch_mod, "db_manager", fake_db)

    agent = orch_mod.OrchestratorAgent(
        model_name="test-model",
        checkpointer=MemorySaver(),
        project_id=str(uuid.uuid4()),
        target_id=str(uuid.uuid4()),
        agent_run_id=str(uuid.uuid4()),
    )
    return agent, fake_db


# --- _is_done ---


def test_is_done_false_before_scouting_has_ever_run(monkeypatch):
    agent, fake_db = _make_agent(monkeypatch)
    fake_db.get_attack_vectors_for_target.return_value = []
    assert agent._is_done() is False
    # Must not even need to read the board - scouting_done gates first.
    fake_db.get_attack_vectors_for_target.assert_not_called()


def test_is_done_false_with_a_pending_vector(monkeypatch):
    agent, fake_db = _make_agent(monkeypatch)
    agent._mark_scouting_done()
    fake_db.get_attack_vectors_for_target.return_value = [_vector(AttackVectorStatus.PENDING)]
    assert agent._is_done() is False


def test_is_done_false_with_a_lingering_testing_vector(monkeypatch):
    agent, fake_db = _make_agent(monkeypatch)
    agent._mark_scouting_done()
    fake_db.get_attack_vectors_for_target.return_value = [_vector(AttackVectorStatus.TESTING)]
    assert agent._is_done() is False


def test_is_done_false_when_vulnerable_vector_not_yet_reported(monkeypatch):
    agent, fake_db = _make_agent(monkeypatch)
    agent._mark_scouting_done()
    fake_db.get_attack_vectors_for_target.return_value = [
        _vector(AttackVectorStatus.TESTED_VULNERABLE, linked=None)
    ]
    assert agent._is_done() is False


def test_is_done_true_once_every_vulnerable_vector_is_reported(monkeypatch):
    agent, fake_db = _make_agent(monkeypatch)
    agent._mark_scouting_done()
    fake_db.get_attack_vectors_for_target.return_value = [
        _vector(AttackVectorStatus.TESTED_VULNERABLE, linked=str(uuid.uuid4())),
        _vector(AttackVectorStatus.TESTED_NOT_VULNERABLE),
        _vector(AttackVectorStatus.INCONCLUSIVE),
    ]
    assert agent._is_done() is True


def test_is_done_true_on_empty_board_once_scouting_ran(monkeypatch):
    agent, fake_db = _make_agent(monkeypatch)
    agent._mark_scouting_done()
    fake_db.get_attack_vectors_for_target.return_value = []
    assert agent._is_done() is True


# --- _render_context_message ---


def test_render_context_message_empty_board(monkeypatch):
    agent, fake_db = _make_agent(monkeypatch)
    fake_db.get_attack_vectors_for_target.return_value = []
    message = agent._render_context_message({"messages": []})
    assert "(empty - nothing proposed yet)" in message.content


def test_render_context_message_prompts_for_scouting_first(monkeypatch):
    agent, fake_db = _make_agent(monkeypatch)
    fake_db.get_attack_vectors_for_target.return_value = []
    message = agent._render_context_message({"messages": []})
    assert "Call run_scouting() first" in message.content
    assert "dispatch_pentest_batch" not in message.content


def test_render_context_message_after_scouting_shows_dispatch_instruction(monkeypatch):
    agent, fake_db = _make_agent(monkeypatch)
    agent._mark_scouting_done()
    fake_db.get_attack_vectors_for_target.return_value = []
    message = agent._render_context_message({"messages": []})
    assert "dispatch_pentest_batch" in message.content
    assert "Call run_scouting() first" not in message.content


def test_render_context_message_tags_reported_vectors(monkeypatch):
    agent, fake_db = _make_agent(monkeypatch)
    agent._mark_scouting_done()
    reported = _vector(AttackVectorStatus.TESTED_VULNERABLE, linked=str(uuid.uuid4()), vid="v1")
    unreported = _vector(AttackVectorStatus.PENDING, vid="v2")
    fake_db.get_attack_vectors_for_target.return_value = [reported, unreported]

    message = agent._render_context_message({"messages": []})

    lines = message.content.splitlines()
    reported_line = next(l for l in lines if "v1" in l)
    unreported_line = next(l for l in lines if "v2" in l)
    assert "[reported]" in reported_line
    assert "[reported]" not in unreported_line


# --- start_agent wires check_done_mid_turn=False (the orchestrator's own
# documented exception to run_graph_loop's default - the key contract
# that lets it see a dispatch_pentest_batch/run_scouting result and react
# to it, e.g. call request_report, within the SAME astream() call) ---


@pytest.mark.asyncio
async def test_start_agent_passes_check_done_mid_turn_false(monkeypatch):
    agent, fake_db = _make_agent(monkeypatch)
    fake_db.get_attack_vectors_for_target.return_value = []

    captured = {}

    async def fake_run_graph_loop(*args, **kwargs):
        captured["check_done_mid_turn"] = kwargs.get("check_done_mid_turn")
        captured["requires_interrupt"] = args[6]
        return
        yield  # pragma: no cover

    monkeypatch.setattr(orch_mod.common, "run_graph_loop", fake_run_graph_loop)

    stop_event = AsyncMock()
    async for _ in agent.start_agent(start_prompt="go", thread_id="t1", stop_event=stop_event):
        pass

    assert captured["check_done_mid_turn"] is False
    # run_scouting/dispatch_pentest_batch/request_report never need human
    # approval at the orchestrator's own level (each sub-agent surfaces
    # its own interrupt independently).
    assert captured["requires_interrupt"]({"run_scouting", "request_report"}) is False
    # request_tool_access is the one orchestrator tool that always must
    # (orchestrator_tools.ALWAYS_INTERRUPT_TOOL_NAMES) - this is the gate
    # the whole request_tool_access feature depends on actually firing.
    assert captured["requires_interrupt"]({"request_tool_access"}) is True
