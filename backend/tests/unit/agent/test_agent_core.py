"""Unit tests for backend/src/core/agent/agent.py's own logic.

See docs/testing-plan.md's "Agent / orchestration layer" bullet under
§1.4 and docs/testing-crawler-reports/agent-core-files.md. Named bug
under test here: resuming a run whose checkpoint is paused right before
the "tools" node (awaiting human approval for a gated tool call) can run
that tool for real without ever re-surfacing the approval prompt - see
TestApprovalBypassOnResume.

Pure state-tracking methods (_record_enumeration, _mark_vulnerability_reported,
_recover_leaked_tool_calls, _trim_messages_for_model, ...) are exercised
directly against a minimally-constructed Agent instance - build_agent_tools
runs for real (it has no I/O at construction time - see agent-tools.md's
own testability-blocker #11), so Agent() itself needs ChatOllama and
kali_registry.get_manager patched even for tests that never call
start_agent.
"""

import asyncio
import uuid
from typing import Any, List
from unittest.mock import MagicMock

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, SystemMessage, ToolMessage
from langgraph.checkpoint.memory import InMemorySaver
from pydantic import Field

from src.core.agent import agent as agent_module
from src.core.agent.agent import Agent, _mode_gate_conflict
from src.core.database_manager import DatabaseManager
from src.schemas import Target


class ScriptedLLM(BaseChatModel):
    """A bind_tools-capable fake chat model - FakeListChatModel (the
    shared fake_llm fixture) raises NotImplementedError from bind_tools,
    which changeModel always calls, so Agent construction needs this
    instead. Each ainvoke call consumes the next scripted response."""

    responses: List[Any] = Field(default_factory=list)
    calls: List[Any] = Field(default_factory=list)

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        raise NotImplementedError

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        from langchain_core.outputs import ChatGeneration, ChatResult

        self.calls.append(messages)
        response = self.responses[len(self.calls) - 1]
        return ChatResult(generations=[ChatGeneration(message=response)])

    @property
    def _llm_type(self):
        return "scripted"


class FakeSessionManager:
    """Same minimal session-surface fake used by
    test_agent_tool_factories.py's guided/terminal-tool tests - see that
    file's module docstring for why a real KaliManager isn't used here."""

    def __init__(self):
        self.current_name = None
        self.opened_sessions: list = []
        self.run_in_current_session_calls: list = []
        self.run_in_current_session_responses: list = []

    def has_current_session(self, target_id, agent_run_id):
        return self.current_name is not None

    async def open_session(self, target_id, agent_run_id, name, command):
        self.opened_sessions.append((name, command))
        self.current_name = name

    def get_current_session(self, target_id, agent_run_id):
        if self.current_name is None:
            return None
        return SimpleSession(self.current_name)

    async def run_in_current_session(self, target_id, agent_run_id, input, wait_seconds):
        self.run_in_current_session_calls.append((input, wait_seconds))
        outcome = self.run_in_current_session_responses.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    async def promote_stuck_session(self, *args, **kwargs):
        return None


class SimpleSession:
    def __init__(self, name):
        self.name = name
        self.command = "/bin/bash"
        self.at_shell_prompt = True
        self.confusion_streak = 0


def _make_target(**overrides) -> Target:
    defaults = dict(
        name="test-target",
        project_id=uuid.uuid4(),
        ipv4="10.0.0.5",
        ipv6=None,
        description=None,
        ports=[21, 80],
        task_duration=None,
    )
    defaults.update(overrides)
    return Target(**defaults)


@pytest.fixture
def fake_db_manager():
    db = MagicMock(spec=DatabaseManager)
    db.get_attack_vectors_for_target.return_value = []
    return db


def _build_agent(monkeypatch, llm, session_manager, fake_db_manager, checkpointer, **overrides):
    monkeypatch.setattr(agent_module, "ChatOllama", lambda **_: llm)
    monkeypatch.setattr(agent_module, "db_manager", fake_db_manager)

    async def _get_manager(project_id, on_stage=None):
        return session_manager

    monkeypatch.setattr(agent_module.kali_registry, "get_manager", _get_manager)

    kwargs = dict(
        model_name="test-model",
        checkpointer=checkpointer,
        project_id="proj1",
        target_id="target1",
        agent_run_id="run1",
    )
    kwargs.update(overrides)
    return Agent(**kwargs)


class TestApprovalBypassOnResume:
    """agent-core-files.md's top finding, now fixed: agent.py's comment
    claims a run paused while awaiting approval re-surfaces that approval
    on resume, but resuming used to always feed input_data=None straight
    into self.app.astream() at the top of the loop. Against langgraph
    1.2.12 (see backend/pyproject.toml), a static interrupt_before=
    ["tools"] checkpoint resumes by streaming with input=None - documented
    langgraph behavior, not a guess - so this directly re-entered and ran
    "tools" for the pending gated call, without ever going through the
    requires_interrupt check that used to (only) guard a tool call
    discovered mid-loop within the SAME start_agent() call.

    Fix: start_agent now checks existing_state.next == ("tools",) when
    resuming a checkpoint with values - if so, it re-derives
    requires_interrupt against the pending tool call (the exact same
    computation the loop body already does for a pause discovered
    mid-loop) and, when it's required, yields the SAME interrupt action a
    fresh pause would yield instead of streaming straight through."""

    async def test_resuming_a_run_paused_before_a_gated_tool_requires_re_approval(
        self, monkeypatch, fake_db_manager
    ):
        checkpointer = InMemorySaver()
        session_manager = FakeSessionManager()
        llm = ScriptedLLM(
            responses=[
                AIMessage(
                    content="",
                    tool_calls=[{"name": "run", "args": {"input": "whoami"}, "id": "call-1"}],
                )
            ]
        )
        target = _make_target()

        agent1 = _build_agent(monkeypatch, llm, session_manager, fake_db_manager, checkpointer)
        agen1 = agent1.start_agent(
            target=target,
            start_prompt="start",
            thread_id="thread1",
            should_interrupt=True,
            duration_seconds=300,
        )
        ai_message = await agen1.__anext__()
        assert isinstance(ai_message, AIMessage)
        assert ai_message.tool_calls[0]["name"] == "run"
        interrupt_action = await agen1.__anext__()
        assert interrupt_action["kind"] == "interrupt"
        assert interrupt_action["tool_calls"][0]["name"] == "run"
        assert session_manager.run_in_current_session_calls == []
        # Simulates a crash/restart while the approval prompt was still
        # showing - nobody ever calls interrupt_action["accept"]. The
        # extra sleeps let the already-cancelled background stream task
        # actually unwind before the test (and its event loop) ends.
        await agen1.aclose()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        session_manager.run_in_current_session_responses = ["whoami output: momos"]
        agent2 = _build_agent(monkeypatch, llm, session_manager, fake_db_manager, checkpointer)
        agen2 = agent2.start_agent(
            target=target,
            start_prompt="start",
            thread_id="thread1",
            should_interrupt=True,
            duration_seconds=300,
        )
        resumed_event = await agen2.__anext__()

        # The fix: resuming re-surfaces the SAME interrupt action a fresh
        # pause would yield - the tool must NOT have run yet.
        assert resumed_event["kind"] == "interrupt"
        assert resumed_event["tool_calls"][0]["name"] == "run"
        assert session_manager.run_in_current_session_calls == []

        # Approving now (the re-surfaced prompt) does let the pending call
        # proceed - this isn't a dead end, just a re-gated one.
        resumed_event["accept"](True)
        ran_tool_message = await agen2.__anext__()
        await agen2.aclose()

        assert isinstance(ran_tool_message, ToolMessage)
        assert ran_tool_message.name == "run"
        assert session_manager.run_in_current_session_calls == [("whoami", 8)]


class TestModeGateConflict:
    def test_a_writer_and_reader_in_the_same_turn_conflict(self):
        writers, readers = _mode_gate_conflict({"run", "report_vulnerability"})
        assert writers == {"run"}
        assert readers == {"report_vulnerability"}

    def test_no_conflict_returns_an_empty_reader_set(self):
        writers, readers = _mode_gate_conflict({"run", "list_sessions"})
        assert readers == set()


class TestRecordEnumeration:
    def test_a_second_call_for_the_same_port_wipes_the_firsts_fields(self, monkeypatch, fake_db_manager):
        """agent-core-files.md's finding 3 (Suspect 3): _record_enumeration
        is a plain dict.update, which replaces "21"'s whole value rather
        than merging field-by-field - the field-preserving fold (the `if v`
        filter merge) only happens later, once per turn, inside
        _call_model. Two _record_enumeration calls for the same port
        within one tools turn lose the first call's fields entirely."""
        checkpointer = InMemorySaver()
        agent = _build_agent(
            monkeypatch, ScriptedLLM(responses=[]), FakeSessionManager(), fake_db_manager, checkpointer
        )

        agent._record_enumeration({"21": {"service": "ftp"}})
        agent._record_enumeration({"21": {"version": "vsftpd 2.3.4"}})

        assert agent._pending_enumeration == {"21": {"version": "vsftpd 2.3.4"}}


class TestVulnerabilityClaimTracking:
    def test_unrelated_vulnerability_reported_clears_an_outstanding_different_claim(
        self, monkeypatch, fake_db_manager
    ):
        """agent-core-files.md's finding 4: _mark_vulnerability_reported
        pops an ARBITRARY element from the outstanding-claims set, so a
        report for an unrelated finding can incorrectly clear someone
        else's still-unresolved claim."""
        checkpointer = InMemorySaver()
        agent = _build_agent(
            monkeypatch, ScriptedLLM(responses=[]), FakeSessionManager(), fake_db_manager, checkpointer
        )

        agent._record_attack_attempt(
            {"target": "10.0.0.5", "vector": "anon ftp login", "outcome": "vulnerable"}
        )
        assert agent._get_unresolved_vulnerable_claims_count() == 1

        agent._mark_vulnerability_reported(vulnerability=None)

        assert agent._get_unresolved_vulnerable_claims_count() == 0

    def test_retracting_with_not_vulnerable_clears_the_same_claim(self, monkeypatch, fake_db_manager):
        checkpointer = InMemorySaver()
        agent = _build_agent(
            monkeypatch, ScriptedLLM(responses=[]), FakeSessionManager(), fake_db_manager, checkpointer
        )

        agent._record_attack_attempt(
            {"target": "10.0.0.5", "vector": "anon ftp login", "outcome": "vulnerable"}
        )
        agent._record_attack_attempt(
            {"target": "10.0.0.5", "vector": "anon ftp login", "outcome": "not_vulnerable"}
        )

        assert agent._get_unresolved_vulnerable_claims_count() == 0

    def test_identical_claim_logged_twice_counts_once(self, monkeypatch, fake_db_manager):
        checkpointer = InMemorySaver()
        agent = _build_agent(
            monkeypatch, ScriptedLLM(responses=[]), FakeSessionManager(), fake_db_manager, checkpointer
        )

        for _ in range(3):
            agent._record_attack_attempt(
                {"target": "10.0.0.5", "vector": "  Anon FTP Login  ", "outcome": "vulnerable"}
            )

        assert agent._get_unresolved_vulnerable_claims_count() == 1


class TestRecoverLeakedToolCalls:
    def test_valid_leaked_block_in_content_is_promoted_and_stripped(self, monkeypatch, fake_db_manager):
        checkpointer = InMemorySaver()
        agent = _build_agent(
            monkeypatch, ScriptedLLM(responses=[]), FakeSessionManager(), fake_db_manager, checkpointer
        )
        tool_name = agent.tools[0].name
        response = AIMessage(
            content=(
                f'<tool_call>{{"name": "{tool_name}", "arguments": {{}}}}</tool_call>'
            )
        )

        recovered = agent._recover_leaked_tool_calls(response)

        assert len(recovered.tool_calls) == 1
        assert recovered.tool_calls[0]["name"] == tool_name
        assert "<tool_call>" not in recovered.content

    def test_unknown_tool_name_is_not_promoted_and_is_replaced_with_a_placeholder(
        self, monkeypatch, fake_db_manager
    ):
        checkpointer = InMemorySaver()
        agent = _build_agent(
            monkeypatch, ScriptedLLM(responses=[]), FakeSessionManager(), fake_db_manager, checkpointer
        )
        response = AIMessage(
            content='<tool_call>{"name": "not_a_real_tool", "arguments": {}}</tool_call>'
        )

        recovered = agent._recover_leaked_tool_calls(response)

        assert recovered.tool_calls == []
        assert "[malformed tool call removed]" in recovered.content

    def test_malformed_json_is_replaced_with_a_placeholder_not_promoted(
        self, monkeypatch, fake_db_manager
    ):
        checkpointer = InMemorySaver()
        agent = _build_agent(
            monkeypatch, ScriptedLLM(responses=[]), FakeSessionManager(), fake_db_manager, checkpointer
        )
        response = AIMessage(content="<tool_call>{not valid json}</tool_call>")

        recovered = agent._recover_leaked_tool_calls(response)

        assert recovered.tool_calls == []
        assert "[malformed tool call removed]" in recovered.content

    def test_a_response_with_real_tool_calls_already_set_is_returned_unchanged(
        self, monkeypatch, fake_db_manager
    ):
        checkpointer = InMemorySaver()
        agent = _build_agent(
            monkeypatch, ScriptedLLM(responses=[]), FakeSessionManager(), fake_db_manager, checkpointer
        )
        response = AIMessage(
            content="<tool_call>{\"name\": \"run\", \"arguments\": {}}</tool_call>",
            tool_calls=[{"name": "list_sessions", "args": {}, "id": "1"}],
        )

        recovered = agent._recover_leaked_tool_calls(response)

        assert recovered is response


class TestTrimMessagesForModel:
    def test_within_budget_returns_the_same_list_object(self, monkeypatch, fake_db_manager):
        checkpointer = InMemorySaver()
        agent = _build_agent(
            monkeypatch, ScriptedLLM(responses=[]), FakeSessionManager(), fake_db_manager, checkpointer
        )
        messages = [SystemMessage(content="start")]

        assert agent._trim_messages_for_model(messages) is messages

    def test_kept_window_never_starts_on_a_bare_tool_message(self, monkeypatch, fake_db_manager):
        checkpointer = InMemorySaver()
        agent = _build_agent(
            monkeypatch, ScriptedLLM(responses=[]), FakeSessionManager(), fake_db_manager, checkpointer
        )
        agent._cached_fixed_overhead_tokens = 0
        agent.context_window = 100000
        monkeypatch.setattr(agent_module, "_MAX_MESSAGES_SENT_TO_MODEL", 4)

        messages = [SystemMessage(content="start")]
        for i in range(10):
            messages.append(AIMessage(content="", tool_calls=[{"name": "run", "args": {}, "id": str(i)}]))
            messages.append(ToolMessage(content="ok", tool_call_id=str(i), name="run"))

        trimmed = agent._trim_messages_for_model(messages)

        # trimmed is always [first, notice] + recent - trimmed[1] is the
        # inserted SystemMessage notice itself, never a ToolMessage by
        # construction regardless of whether the skip-forward logic below
        # actually works. The real claim this test is named for lives at
        # trimmed[2] (recent[0]), the kept window's own first message.
        assert trimmed[0] is messages[0]
        assert not isinstance(trimmed[2], ToolMessage)
