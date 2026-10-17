"""roles/common.py - the plumbing shared by every pipeline role.

Covers the pure helpers (turn_conflict, trim_messages_for_model,
render_target_prompt, render_target_scope_reminder, resolve_model_capabilities)
and the two pieces of real behavior that need a fake dependency:
make_guarded_tools_node (a fake ToolNode) and run_graph_loop (a fake
compiled graph) - see docs/testing-crawler-reports/role-agents-graphs.md's
top finding, confirmed below in test_run_graph_loop_check_done_mid_turn_*.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from langchain_core.messages import AIMessage, SystemMessage, ToolMessage

from src.core.agent.roles import common


# --- turn_conflict ---


def test_turn_conflict_writer_only_has_no_readers():
    writers, readers = common.turn_conflict({"run"}, {"run"}, {"report_outcome"})
    assert writers == {"run"}
    assert readers == set()


def test_turn_conflict_reader_only_has_no_writers():
    writers, readers = common.turn_conflict({"report_outcome"}, {"run"}, {"report_outcome"})
    assert writers == set()
    assert readers == set()


def test_turn_conflict_empty_input():
    assert common.turn_conflict(set(), {"run"}, {"report_outcome"}) == (set(), set())


def test_turn_conflict_mixed_turn_returns_both():
    writers, readers = common.turn_conflict(
        {"run", "report_outcome"}, {"run"}, {"report_outcome"}
    )
    assert writers == {"run"}
    assert readers == {"report_outcome"}


def test_turn_conflict_name_in_both_sets_conflicts_with_itself():
    # A tool misclassified into both sets: a lone call still produces a
    # non-empty writers AND readers set, so the whole turn is rejected -
    # pins the failure mode so a classification bug is caught by a test,
    # not by it rejecting its own turn in production.
    writers, readers = common.turn_conflict({"weird"}, {"weird"}, {"weird"})
    assert writers == {"weird"}
    assert readers == {"weird"}


# --- trim_messages_for_model ---


def _msg(i, cls=SystemMessage):
    return cls(content=f"m{i}")


def test_trim_messages_returns_identical_list_when_under_budget():
    messages = [_msg(0), _msg(1), _msg(2)]
    # context_window large enough that budget >> len(messages)
    result = common.trim_messages_for_model(messages, context_window=100_000, tools=[])
    assert result is messages


def test_trim_messages_empty_list_returned_as_is():
    assert common.trim_messages_for_model([], context_window=1000, tools=[]) == []


def test_trim_messages_drops_oldest_and_keeps_first_plus_notice():
    # context_window=2050, first message "first" (5 chars), tools=[] ->
    # fixed_overhead=1, budget=int((2050-1)*0.5//250)=4. 5 messages is
    # over that budget, and candidate_start (5-(4-1)=2) lands on the
    # first of a run of ToolMessages - exercising the "advance past an
    # orphaned ToolMessage run" branch explicitly.
    first = _msg("first")
    filler = _msg("a")
    tool_1 = ToolMessage(content="t1", tool_call_id="1", name="run")
    tool_2 = ToolMessage(content="t2", tool_call_id="2", name="run")
    tail_ai = AIMessage(content="final")
    messages = [first, filler, tool_1, tool_2, tail_ai]

    result = common.trim_messages_for_model(messages, context_window=2050, tools=[])

    assert result[0] is first
    assert isinstance(result[1], SystemMessage)
    assert "omitted" in result[1].content
    # The kept window must never start on an orphaned ToolMessage - both
    # tool_1 and tool_2 must be skipped, leaving only the final AIMessage.
    assert result[2:] == [tail_ai]


def test_trim_messages_all_but_first_are_tool_messages_keeps_only_notice():
    first = _msg("first")
    tool_msgs = [ToolMessage(content=f"t{i}", tool_call_id=str(i), name="run") for i in range(10)]
    messages = [first] + tool_msgs

    result = common.trim_messages_for_model(messages, context_window=250, tools=[])

    assert result[0] is first
    assert len(result) == 2
    assert isinstance(result[1], SystemMessage)


def test_trim_messages_single_huge_first_message_is_unchanged():
    # A one-element history (just the starting prompt, before any agent
    # turn) always satisfies len(messages) <= budget (budget clamps to at
    # least 1), regardless of how large that single message's content is
    # - the budget is a message COUNT, not a char-length check. This pins
    # the silent-truncation risk the crawler report flags: a starting
    # prompt that alone exceeds context_window is never trimmed here, and
    # Ollama will truncate its start instead, without warning.
    first = SystemMessage(content="x" * 50_000)
    messages = [first]
    result = common.trim_messages_for_model(messages, context_window=10, tools=[])
    assert result is messages


# --- render_target_prompt ---


def test_render_target_prompt_substitutes_every_placeholder():
    target = SimpleNamespace(
        name="box", description="a test box", ipv4="10.0.0.1", ipv6=None, ports=[22, 80]
    )
    template = "{{name}}|{{description}}|{{ipv4}}|{{ipv6}}|{{ports}}|{{attack_vector}}"
    result = common.render_target_prompt(template, target)
    assert result == "box|a test box|10.0.0.1|Not defined|22, 80|{{attack_vector}}"


def test_render_target_prompt_attack_vector_substituted_when_given():
    target = SimpleNamespace(name="box", description=None, ipv4=None, ipv6=None, ports=[])
    result = common.render_target_prompt("vector: {{attack_vector}}", target, attack_vector="XSS")
    assert result == "vector: XSS"


def test_render_target_prompt_empty_ports_is_not_defined():
    target = SimpleNamespace(name="box", description=None, ipv4=None, ipv6=None, ports=[])
    result = common.render_target_prompt("{{ports}}", target)
    assert result == "Not defined"


# --- render_target_scope_reminder ---


def test_render_target_scope_reminder_empty_scope_is_blank():
    assert common.render_target_scope_reminder(None) == ""
    assert common.render_target_scope_reminder({}) == ""


def test_render_target_scope_reminder_empty_ports_list_is_not_defined():
    scope = {"name": "box", "ipv4": "1.2.3.4", "ipv6": None, "ports": []}
    reminder = common.render_target_scope_reminder(scope)
    assert "Authorized ports: not defined" in reminder


def test_render_target_scope_reminder_integer_zero_port_renders_as_0():
    # 0 is a legitimate (if odd) falsy-looking value that must still
    # render as "0", not be treated as "not defined" like None/"" are.
    scope = {"name": "box", "ipv4": None, "ipv6": None, "ports": 0}
    reminder = common.render_target_scope_reminder(scope)
    assert "Authorized ports: 0" in reminder


# --- resolve_model_capabilities ---


@pytest.mark.asyncio
async def test_resolve_model_capabilities_success_clamps_to_ceiling(monkeypatch):
    monkeypatch.setattr(
        common.ollama_manager,
        "get_model_capabilities",
        AsyncMock(return_value={"thinking": True, "context_window": 999_999}),
    )
    monkeypatch.setattr(common.core_settings, "DEFAULT_MAX_CONTEXT_WINDOW", 4096)

    reasoning, context_window = await common.resolve_model_capabilities("m", None)

    assert reasoning is True
    assert context_window == 4096


@pytest.mark.asyncio
async def test_resolve_model_capabilities_failure_falls_back(monkeypatch):
    async def raise_lookup(model_name):
        raise RuntimeError("no such model")

    monkeypatch.setattr(common.ollama_manager, "get_model_capabilities", raise_lookup)

    reasoning, context_window = await common.resolve_model_capabilities("m", None)

    assert reasoning is None
    assert context_window == common.DEFAULT_CONTEXT_WINDOW_FALLBACK


# --- make_guarded_tools_node ---


class _FakeToolNode:
    def __init__(self):
        self.ainvoke = AsyncMock(return_value={"messages": ["ok"]})


def _ai_message_with_calls(*names_and_ids):
    return AIMessage(
        content="",
        tool_calls=[{"name": n, "id": i, "args": {}} for n, i in names_and_ids],
    )


@pytest.mark.asyncio
async def test_guarded_tools_node_rejects_mixed_writer_reader_turn():
    tool_node = _FakeToolNode()
    guarded = common.make_guarded_tools_node(tool_node, {"run"}, {"report_outcome"})
    state = {
        "messages": [_ai_message_with_calls(("run", "1"), ("report_outcome", "2"))]
    }

    result = await guarded(state, {})

    tool_node.ainvoke.assert_not_called()
    messages = result["messages"]
    assert len(messages) == 2
    ids = {m.tool_call_id for m in messages}
    assert ids == {"1", "2"}
    for m in messages:
        assert isinstance(m, ToolMessage)
        assert "run" in m.content and "report_outcome" in m.content


@pytest.mark.asyncio
async def test_guarded_tools_node_allows_writer_only_turn():
    tool_node = _FakeToolNode()
    guarded = common.make_guarded_tools_node(tool_node, {"run"}, {"report_outcome"})
    state = {"messages": [_ai_message_with_calls(("run", "1"))]}

    result = await guarded(state, {"configurable": {}})

    tool_node.ainvoke.assert_awaited_once_with(state, {"configurable": {}})
    assert result == {"messages": ["ok"]}


@pytest.mark.asyncio
async def test_guarded_tools_node_converts_dispatch_exception_to_tool_message():
    tool_node = _FakeToolNode()
    tool_node.ainvoke.side_effect = TypeError("bad args")
    guarded = common.make_guarded_tools_node(tool_node, {"run"}, {"report_outcome"})
    state = {"messages": [_ai_message_with_calls(("run", "1"))]}

    result = await guarded(state, {})

    messages = result["messages"]
    assert len(messages) == 1
    assert "Tool call failed" in messages[0].content


# --- run_graph_loop: the check_done_mid_turn stale-checkpoint bug ---
#
# docs/testing-crawler-reports/role-agents-graphs.md's top finding:
# pentesting/scouting/reporting all call run_graph_loop with its default
# check_done_mid_turn=True, so the loop can return as soon as the TOOLS
# node's update makes is_done() true - before the AGENT node (the only
# place that writes finish_summary/scouting_done into the checkpoint) is
# ever even streamed. The two tests below drive the exact same fake graph
# through both branches of the flag and show the agent-node message is
# dropped only when check_done_mid_turn=True - confirming the bug is real,
# not just a prediction from reading the code.


class _FakeState:
    def __init__(self, next_=()):
        self.next = next_
        self.values = {}


def _make_fake_app(done_flag: dict):
    """A minimal stand-in for a compiled LangGraph app: one astream() call
    per turn, yielding a tools-node update (simulating the tool having
    already run for real and flipped done_flag, exactly like a role's own
    on_outcome_reported/finish_scouting callback does synchronously inside
    the tool call, before the ToolNode's own state update is even streamed
    back) followed by an agent-node update (the one that would persist
    that result into the checkpoint)."""

    class FakeApp:
        async def astream(self, input_data, config, stream_mode):
            done_flag["done"] = True
            yield {
                "tools": {
                    "messages": [
                        ToolMessage(content="outcome recorded", tool_call_id="1", name="report_outcome")
                    ]
                }
            }
            yield {"agent": {"messages": [AIMessage(content="turn complete", tool_calls=[])]}}

        async def aget_state(self, config):
            return _FakeState(next_=())

        async def aupdate_state(self, config, values, as_node=None):
            pass

    return FakeApp()


@pytest.mark.asyncio
async def test_run_graph_loop_check_done_mid_turn_true_drops_the_agent_node_message():
    import asyncio

    done_flag = {"done": False}
    app = _make_fake_app(done_flag)
    stop_event = asyncio.Event()

    received = []
    async for event in common.run_graph_loop(
        app,
        "thread-1",
        {"messages": []},
        stop_event,
        context_window=4096,
        is_done=lambda: done_flag["done"],
        requires_interrupt=lambda names: False,
        check_done_mid_turn=True,  # the default every sub-role actually uses
    ):
        received.append(event)

    # Only the ToolMessage was ever seen - the agent-node AIMessage that
    # would have checkpointed finish_summary/scouting_done never streamed.
    assert len(received) == 1
    assert isinstance(received[0], ToolMessage)


@pytest.mark.asyncio
async def test_run_graph_loop_check_done_mid_turn_false_lets_the_agent_node_run():
    import asyncio

    done_flag = {"done": False}
    app = _make_fake_app(done_flag)
    stop_event = asyncio.Event()

    received = []
    async for event in common.run_graph_loop(
        app,
        "thread-1",
        {"messages": []},
        stop_event,
        context_window=4096,
        is_done=lambda: done_flag["done"],
        requires_interrupt=lambda names: False,
        check_done_mid_turn=False,  # what the orchestrator explicitly passes instead
    ):
        received.append(event)

    # Both the tools-node ToolMessage AND the agent-node AIMessage made it
    # out - the checkpointing node actually got to run this time.
    assert len(received) == 2
    assert isinstance(received[0], ToolMessage)
    assert isinstance(received[1], AIMessage)
