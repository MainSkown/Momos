"""agent_tools/roles/orchestrator_tools.py - run_scouting/dispatch_pentest_batch/
request_report, _drain_sub_agent, and the writer/reader ordering hazard
the module's own docstring says roles/common.py's guarded-tools-node must
reject outright. Sub-agents (ScoutingAgent/PentestingAgent/ReportingAgent)
are replaced with lightweight fakes throughout - their OWN internals are
covered by test_scouting_agent.py/test_pentesting_agent.py/
test_reporting_agent.py; this file is about orchestrator_tools' own
dispatch/state-machine/concurrency logic, which needs no Docker/Kali/
pgvector at all (pure DB-state + sub-agent-orchestration glue, per
docs/testing-plan.md)."""

import asyncio
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from langgraph.prebuilt import ToolNode

from src.core.agent.roles import common
from src.core.agent.roles.agents import pentesting_agent, reporting_agent, scouting_agent
from src.core.agent.agent_tools.roles import orchestrator_tools
from src.schemas.agent_run_scheme import AgentRunState
from src.schemas.attack_vector_scheme import AttackVectorStatus


@pytest.fixture
def ids():
    return {
        "project_id": str(uuid.uuid4()),
        "target_id": str(uuid.uuid4()),
        "orchestrator_run_id": str(uuid.uuid4()),
    }


async def _noop_async(*args, **kwargs):
    return None


class _FakeSubAgent:
    """Stands in for ScoutingAgent/PentestingAgent/ReportingAgent -
    start_agent is an empty async generator (nothing to drain), with
    whatever result attributes the real one would have set by the time
    its run finished."""

    instances = []

    def __init__(self, *args, **kwargs):
        self.finish_summary = "done"
        self.outcome = {"outcome": "vulnerable", "summary": "ok", "new_vectors": []}
        self.created_vulnerability = None
        self.kwargs = kwargs
        _FakeSubAgent.instances.append(self)

    async def start_agent(self, *args, **kwargs):
        return
        yield  # pragma: no cover - makes this an async generator


@pytest.fixture(autouse=True)
def _reset_fake_sub_agent():
    _FakeSubAgent.instances = []
    yield
    _FakeSubAgent.instances = []


def _wire_common_mocks(monkeypatch, ids, project_settings=None):
    fake_db = MagicMock()
    fake_db.get_target.return_value = SimpleNamespace(
        name="t", description=None, ipv4=None, ipv6=None, ports=[]
    )
    fake_db.get_project_settings.return_value = project_settings or MagicMock(
        scouting_model_name="m",
        base_model_name="m",
        pentesting_model_name="m",
        reporting_model_name="m",
        max_context_window=None,
        max_concurrent_agents=5,
        allow_shell=False,
        allow_install_packages=False,
        enabled_tools=None,
        scouting_starting_prompt="",
        pentesting_starting_prompt="",
        reporting_starting_prompt="",
    )
    monkeypatch.setattr(orchestrator_tools, "db_manager", fake_db)

    monkeypatch.setattr(orchestrator_tools.run_registry, "broadcast_attack_vector", _noop_async)
    monkeypatch.setattr(
        orchestrator_tools.run_registry, "persist_run_state", AsyncMock(return_value=MagicMock(id=uuid.uuid4()))
    )
    monkeypatch.setattr(
        orchestrator_tools.run_registry,
        "start_sub_run",
        AsyncMock(return_value=MagicMock(id=uuid.uuid4())),
    )
    monkeypatch.setattr(orchestrator_tools.run_registry, "cleanup_sub_run", MagicMock())
    monkeypatch.setattr(orchestrator_tools.run_registry, "acquire_agent_slot", AsyncMock())
    monkeypatch.setattr(orchestrator_tools.run_registry, "release_agent_slot", AsyncMock())
    monkeypatch.setattr(common, "resolve_model_capabilities", AsyncMock(return_value=(None, 2048)))

    monkeypatch.setattr(scouting_agent, "ScoutingAgent", _FakeSubAgent)
    monkeypatch.setattr(pentesting_agent, "PentestingAgent", _FakeSubAgent)
    monkeypatch.setattr(reporting_agent, "ReportingAgent", _FakeSubAgent)

    return fake_db


# --- Crawler finding #6: the dispatch/request_report ordering hazard ---
# The module's own docstring says mixing dispatch_pentest_batch/run_scouting
# (writers) with request_report (reader) in one turn is "a genuine ordering
# hazard" meant to be rejected outright by roles/common.py's
# guarded-tools-node - not something orchestrator_tools enforces itself.


@pytest.mark.asyncio
async def test_guarded_tools_node_rejects_dispatch_and_request_report_in_same_turn(
    monkeypatch, ids
):
    fake_db = _wire_common_mocks(monkeypatch, ids)

    tools = [
        orchestrator_tools.create_run_scouting_tool(
            ids["project_id"], ids["target_id"], ids["orchestrator_run_id"], False, lambda: None
        ),
        orchestrator_tools.create_dispatch_pentest_batch_tool(
            ids["project_id"], ids["target_id"], ids["orchestrator_run_id"], False
        ),
        orchestrator_tools.create_request_report_tool(
            ids["project_id"], ids["target_id"], ids["orchestrator_run_id"]
        ),
    ]
    tool_node = ToolNode(tools)
    tool_node.ainvoke = AsyncMock(side_effect=AssertionError("tool_node must never run for a rejected turn"))
    guarded = common.make_guarded_tools_node(
        tool_node, orchestrator_tools.WRITER_TOOL_NAMES, orchestrator_tools.READER_TOOL_NAMES
    )

    from langchain_core.messages import AIMessage

    state = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": orchestrator_tools.DISPATCH_PENTEST_BATCH_TOOL_NAME,
                        "id": "1",
                        "args": {"vector_ids": ["v-1"]},
                    },
                    {
                        "name": orchestrator_tools.REQUEST_REPORT_TOOL_NAME,
                        "id": "2",
                        "args": {"vector_id": "v-1"},
                    },
                ],
            )
        ]
    }

    result = await guarded(state, {})

    # Neither call actually ran - no DB read for either tool's own logic.
    fake_db.get_attack_vector.assert_not_called()
    messages = result["messages"]
    assert len(messages) == 2
    for m in messages:
        assert "Rejected" in m.content


# --- _drain_sub_agent ---


@pytest.mark.asyncio
async def test_drain_sub_agent_persists_interrupt_and_sends_request(monkeypatch, ids):
    sent_messages = []
    monkeypatch.setattr(
        orchestrator_tools.ws_registry, "send_message", AsyncMock(side_effect=lambda m: sent_messages.append(m))
    )
    persist_calls = []
    monkeypatch.setattr(
        orchestrator_tools.run_registry,
        "persist_run_state",
        AsyncMock(side_effect=lambda **kw: persist_calls.append(kw)),
    )

    async def accept(approved):
        pass

    async def events():
        yield {"kind": "interrupt", "accept": accept, "tool_calls": [{"name": "run", "args": {}, "id": "1"}]}

    await orchestrator_tools._drain_sub_agent(
        events(), ids["project_id"], ids["target_id"], "run-1", "pentesting"
    )

    assert orchestrator_tools.run_registry.pending_interrupts["run-1"] is accept
    assert persist_calls[0]["status"] == AgentRunState.INTERRUPTED
    assert len(sent_messages) == 1
    assert sent_messages[0].agent_run_id == "run-1"

    orchestrator_tools.run_registry.pending_interrupts.pop("run-1", None)
    orchestrator_tools.run_registry.pending_interrupt_tool_calls.pop("run-1", None)


@pytest.mark.asyncio
async def test_drain_sub_agent_context_usage_sent_but_not_persisted(monkeypatch, ids):
    sent_messages = []
    monkeypatch.setattr(
        orchestrator_tools.ws_registry, "send_message", AsyncMock(side_effect=lambda m: sent_messages.append(m))
    )
    persist_and_broadcast = AsyncMock()
    monkeypatch.setattr(orchestrator_tools.run_registry, "persist_and_broadcast", persist_and_broadcast)

    async def events():
        yield {"kind": "context_usage", "used_tokens": 10, "context_window": 2048}

    await orchestrator_tools._drain_sub_agent(
        events(), ids["project_id"], ids["target_id"], "run-1", "pentesting"
    )

    assert len(sent_messages) == 1
    persist_and_broadcast.assert_not_called()


@pytest.mark.asyncio
async def test_drain_sub_agent_persists_real_messages(monkeypatch, ids):
    from langchain_core.messages import AIMessage

    persisted = []
    monkeypatch.setattr(
        orchestrator_tools.run_registry,
        "persist_and_broadcast",
        AsyncMock(side_effect=lambda **kw: persisted.append(kw)),
    )

    async def events():
        yield AIMessage(content="thinking about it", tool_calls=[])

    await orchestrator_tools._drain_sub_agent(
        events(), ids["project_id"], ids["target_id"], "run-1", "pentesting"
    )

    assert len(persisted) == 1
    assert persisted[0]["agent_run_id"] == "run-1"
    assert persisted[0]["role"] == "pentesting"


# --- dispatch_pentest_batch: duplicate vector id in one call (fixed) ---


@pytest.mark.asyncio
async def test_dispatch_pentest_batch_duplicate_id_runs_the_sub_agent_once(monkeypatch, ids):
    # role-tools-modules.md's finding: the same vector id passed twice in
    # one call used to have both coroutines read PENDING before either
    # wrote TESTING, so the pentest ran twice on one vector. Fixed by
    # deduping vector_ids (dict.fromkeys, order-preserving) before
    # dispatching - confirmed here with a fake get_attack_vector that
    # would return a FRESH "still pending" vector on every call (what both
    # concurrent reads would have seen pre-fix), showing only one sub-agent
    # is ever constructed for the id now.
    fake_db = _wire_common_mocks(monkeypatch, ids)
    fake_db.get_attack_vector.side_effect = lambda vid: MagicMock(
        id=vid, target_id=ids["target_id"], status=AttackVectorStatus.PENDING, description="d"
    )
    fake_db.update_attack_vector.side_effect = lambda v: v

    tool = orchestrator_tools.create_dispatch_pentest_batch_tool(
        ids["project_id"], ids["target_id"], ids["orchestrator_run_id"], False
    )

    result = await tool.ainvoke({"vector_ids": ["dup-vector", "dup-vector"]})

    # Exactly one sub-agent construction for the deduped id.
    assert len(_FakeSubAgent.instances) == 1
    assert orchestrator_tools.run_registry.start_sub_run.await_count == 1
    # And exactly one result line, not two.
    assert result.count("dup-vector") == 1


# --- dispatch_pentest_batch: slot leak if persist_run_state raises (fixed) ---


@pytest.mark.asyncio
async def test_dispatch_pentest_batch_releases_slot_even_if_persist_run_state_raises(
    monkeypatch, ids
):
    fake_db = _wire_common_mocks(monkeypatch, ids)
    fake_db.get_attack_vector.return_value = MagicMock(
        id="v-1", target_id=ids["target_id"], status=AttackVectorStatus.PENDING, description="d"
    )
    fake_db.update_attack_vector.side_effect = lambda v: v

    monkeypatch.setattr(
        orchestrator_tools.run_registry, "persist_run_state", AsyncMock(side_effect=RuntimeError("db down"))
    )

    tool = orchestrator_tools.create_dispatch_pentest_batch_tool(
        ids["project_id"], ids["target_id"], ids["orchestrator_run_id"], False
    )

    # persist_run_state's failure is logged and swallowed inside the
    # finally block, not left to propagate - the tool call completes
    # normally.
    result = await tool.ainvoke({"vector_ids": ["v-1"]})

    # acquire ran, and - the fix - release_agent_slot ran too, even though
    # persist_run_state raised in the same finally block. No slot leak.
    orchestrator_tools.run_registry.acquire_agent_slot.assert_awaited_once()
    orchestrator_tools.run_registry.release_agent_slot.assert_awaited_once()
    assert "v-1" in result


# --- request_report: each guard checked in order ---


@pytest.mark.asyncio
async def test_request_report_not_found_or_wrong_target(monkeypatch, ids):
    fake_db = _wire_common_mocks(monkeypatch, ids)
    fake_db.get_attack_vector.return_value = None
    tool = orchestrator_tools.create_request_report_tool(
        ids["project_id"], ids["target_id"], ids["orchestrator_run_id"]
    )
    result = await tool.ainvoke({"vector_id": "missing"})
    assert "not found" in result


@pytest.mark.asyncio
async def test_request_report_rejects_wrong_status(monkeypatch, ids):
    fake_db = _wire_common_mocks(monkeypatch, ids)
    fake_db.get_attack_vector.return_value = MagicMock(
        target_id=ids["target_id"],
        status=AttackVectorStatus.PENDING,
        linked_vulnerability_id=None,
        assigned_run_id=str(uuid.uuid4()),
    )
    tool = orchestrator_tools.create_request_report_tool(
        ids["project_id"], ids["target_id"], ids["orchestrator_run_id"]
    )
    result = await tool.ainvoke({"vector_id": "v-1"})
    assert "not tested_vulnerable" in result


@pytest.mark.asyncio
async def test_request_report_rejects_already_reported(monkeypatch, ids):
    fake_db = _wire_common_mocks(monkeypatch, ids)
    fake_db.get_attack_vector.return_value = MagicMock(
        target_id=ids["target_id"],
        status=AttackVectorStatus.TESTED_VULNERABLE,
        linked_vulnerability_id=str(uuid.uuid4()),
        assigned_run_id=str(uuid.uuid4()),
    )
    tool = orchestrator_tools.create_request_report_tool(
        ids["project_id"], ids["target_id"], ids["orchestrator_run_id"]
    )
    result = await tool.ainvoke({"vector_id": "v-1"})
    assert "already reported" in result


@pytest.mark.asyncio
async def test_request_report_rejects_no_assigned_run(monkeypatch, ids):
    fake_db = _wire_common_mocks(monkeypatch, ids)
    fake_db.get_attack_vector.return_value = MagicMock(
        target_id=ids["target_id"],
        status=AttackVectorStatus.TESTED_VULNERABLE,
        linked_vulnerability_id=None,
        assigned_run_id=None,
    )
    tool = orchestrator_tools.create_request_report_tool(
        ids["project_id"], ids["target_id"], ids["orchestrator_run_id"]
    )
    result = await tool.ainvoke({"vector_id": "v-1"})
    assert "no assigned pentesting run" in result


@pytest.mark.asyncio
async def test_request_report_status_mismatch_takes_precedence_over_existing_link(monkeypatch, ids):
    # A vector that is BOTH the wrong status AND already linked must be
    # rejected for the status reason, not silently treated as reported.
    fake_db = _wire_common_mocks(monkeypatch, ids)
    fake_db.get_attack_vector.return_value = MagicMock(
        target_id=ids["target_id"],
        status=AttackVectorStatus.PENDING,
        linked_vulnerability_id=str(uuid.uuid4()),
        assigned_run_id=str(uuid.uuid4()),
    )
    tool = orchestrator_tools.create_request_report_tool(
        ids["project_id"], ids["target_id"], ids["orchestrator_run_id"]
    )
    result = await tool.ainvoke({"vector_id": "v-1"})
    assert "not tested_vulnerable" in result


# --- run_scouting: model fallback and pending-count summary ---


@pytest.mark.asyncio
async def test_run_scouting_falls_back_to_base_model_when_scouting_model_unset(monkeypatch, ids):
    settings = MagicMock(
        scouting_model_name="",
        base_model_name="base-model",
        max_context_window=None,
        allow_shell=False,
        allow_install_packages=False,
        enabled_tools=None,
        scouting_starting_prompt="",
    )
    fake_db = _wire_common_mocks(monkeypatch, ids, project_settings=settings)
    fake_db.get_attack_vectors_for_target.return_value = []

    tool = orchestrator_tools.create_run_scouting_tool(
        ids["project_id"], ids["target_id"], ids["orchestrator_run_id"], False, lambda: None
    )
    await tool.ainvoke({})

    # The fake agent doesn't record its own constructor kwargs, so assert
    # via resolve_model_capabilities's own recorded call instead.
    called_model = common.resolve_model_capabilities.await_args.args[0]
    assert called_model == "base-model"


@pytest.mark.asyncio
async def test_run_scouting_reports_total_pending_count_after_run(monkeypatch, ids):
    fake_db = _wire_common_mocks(monkeypatch, ids)
    fake_db.get_attack_vectors_for_target.return_value = [
        MagicMock(status=AttackVectorStatus.PENDING),
        MagicMock(status=AttackVectorStatus.PENDING),
        MagicMock(status=AttackVectorStatus.TESTING),
    ]

    on_scouting_done = MagicMock()
    tool = orchestrator_tools.create_run_scouting_tool(
        ids["project_id"], ids["target_id"], ids["orchestrator_run_id"], False, on_scouting_done
    )
    result = await tool.ainvoke({})

    on_scouting_done.assert_called_once()
    assert "2 attack vector(s) now pending" in result


# --- dispatch_pentest_batch: tool_groups narrowing is a ceiling, never an
# expansion path - B2's actual enforcement mechanism (see
# orchestrator_tools.py's module docstring and _project_enabled_group_ids). ---


def _pending_vector(vector_id, target_id, extra_tool_groups=None):
    return MagicMock(
        id=vector_id,
        target_id=target_id,
        status=AttackVectorStatus.PENDING,
        description="d",
        extra_tool_groups=extra_tool_groups,
    )


@pytest.mark.asyncio
async def test_dispatch_pentest_batch_tool_groups_narrows_below_project_default(monkeypatch, ids):
    # Project allows every default-enabled group (enabled_tools=None), but
    # this one vector is narrowed down to just "ftp" via tool_groups.
    fake_db = _wire_common_mocks(monkeypatch, ids)
    fake_db.get_attack_vector.return_value = _pending_vector("v-1", ids["target_id"])
    fake_db.update_attack_vector.side_effect = lambda v: v

    tool = orchestrator_tools.create_dispatch_pentest_batch_tool(
        ids["project_id"], ids["target_id"], ids["orchestrator_run_id"], False
    )
    await tool.ainvoke({"vector_ids": ["v-1"], "tool_groups": {"v-1": ["ftp"]}})

    assert len(_FakeSubAgent.instances) == 1
    assert _FakeSubAgent.instances[0].kwargs["enabled_tools"] == ["ftp"]


@pytest.mark.asyncio
async def test_dispatch_pentest_batch_tool_groups_never_expands_past_project_default(
    monkeypatch, ids
):
    # The project's own enabled_tools is explicitly just "ftp" - asking for
    # "metasploit" too via tool_groups must NOT add it. This is the test to
    # break-and-watch-go-red per CLAUDE.md 2.1.
    settings = MagicMock(
        scouting_model_name="m",
        base_model_name="m",
        pentesting_model_name="m",
        reporting_model_name="m",
        max_context_window=None,
        max_concurrent_agents=5,
        allow_shell=False,
        allow_install_packages=False,
        enabled_tools=["ftp"],
        scouting_starting_prompt="",
        pentesting_starting_prompt="",
        reporting_starting_prompt="",
    )
    fake_db = _wire_common_mocks(monkeypatch, ids, project_settings=settings)
    fake_db.get_attack_vector.return_value = _pending_vector("v-1", ids["target_id"])
    fake_db.update_attack_vector.side_effect = lambda v: v

    tool = orchestrator_tools.create_dispatch_pentest_batch_tool(
        ids["project_id"], ids["target_id"], ids["orchestrator_run_id"], False
    )
    result = await tool.ainvoke(
        {"vector_ids": ["v-1"], "tool_groups": {"v-1": ["ftp", "metasploit"]}}
    )

    assert _FakeSubAgent.instances[0].kwargs["enabled_tools"] == ["ftp"]
    assert "metasploit" not in _FakeSubAgent.instances[0].kwargs["enabled_tools"]
    # The drop is surfaced to the orchestrator, not swallowed silently.
    assert "metasploit" in result
    assert "ignored" in result


@pytest.mark.asyncio
async def test_dispatch_pentest_batch_unknown_group_id_rejects_only_that_vector(monkeypatch, ids):
    target_id = ids["target_id"]
    vectors = {
        "v-1": _pending_vector("v-1", target_id),
        "v-2": _pending_vector("v-2", target_id),
    }
    fake_db = _wire_common_mocks(monkeypatch, ids)
    fake_db.get_attack_vector.side_effect = lambda vid: vectors[vid]
    fake_db.update_attack_vector.side_effect = lambda v: v

    tool = orchestrator_tools.create_dispatch_pentest_batch_tool(
        ids["project_id"], ids["target_id"], ids["orchestrator_run_id"], False
    )
    result = await tool.ainvoke(
        {"vector_ids": ["v-1", "v-2"], "tool_groups": {"v-1": ["not-a-real-id"]}}
    )

    v1_line = next(line for line in result.splitlines() if line.startswith("v-1"))
    v2_line = next(line for line in result.splitlines() if line.startswith("v-2"))
    assert "not-a-real-id" in v1_line
    assert "rejected" in v1_line

    # Only one sub-agent was ever constructed, and it's v-2's - the bad id
    # for v-1 never spawned anything, and v-1's rejection didn't cancel or
    # otherwise affect v-2 running concurrently under asyncio.gather.
    assert len(_FakeSubAgent.instances) == 1
    assert _FakeSubAgent.instances[0].kwargs["attack_vector_id"] == "v-2"
    assert "v-2" in v2_line


# --- request_tool_access: the only expansion path, always human-gated ---


@pytest.mark.asyncio
async def test_request_tool_access_approves_and_dispatch_later_picks_it_up(monkeypatch, ids):
    target_id = ids["target_id"]
    vector = _pending_vector("v-1", target_id)
    fake_db = _wire_common_mocks(monkeypatch, ids)
    fake_db.get_attack_vector.return_value = vector
    fake_db.update_attack_vector.side_effect = lambda v: v

    access_tool = orchestrator_tools.create_request_tool_access_tool(
        ids["project_id"], ids["target_id"]
    )
    approval_result = await access_tool.ainvoke(
        {"vector_id": "v-1", "tool_group": "metasploit", "reason": "needs msf exploit"}
    )

    assert "Approved" in approval_result
    fake_db.update_attack_vector.assert_called_once()
    persisted_vector = fake_db.update_attack_vector.call_args.args[0]
    assert persisted_vector.extra_tool_groups == ["metasploit"]

    # Simulate the persisted state: the same vector object now carries the
    # approved group, same as a fresh get_attack_vector would return after
    # a real commit. The project's own enabled_tools never changed.
    vector.extra_tool_groups = ["metasploit"]

    dispatch_tool = orchestrator_tools.create_dispatch_pentest_batch_tool(
        ids["project_id"], ids["target_id"], ids["orchestrator_run_id"], False
    )
    await dispatch_tool.ainvoke({"vector_ids": ["v-1"]})

    assert "metasploit" in _FakeSubAgent.instances[0].kwargs["enabled_tools"]


@pytest.mark.asyncio
async def test_request_tool_access_already_available_is_a_no_op(monkeypatch, ids):
    fake_db = _wire_common_mocks(monkeypatch, ids)
    fake_db.get_attack_vector.return_value = _pending_vector("v-1", ids["target_id"])

    access_tool = orchestrator_tools.create_request_tool_access_tool(
        ids["project_id"], ids["target_id"]
    )
    # "ftp" is already default_enabled for a project with enabled_tools=None.
    result = await access_tool.ainvoke(
        {"vector_id": "v-1", "tool_group": "ftp", "reason": "just in case"}
    )

    assert "already available" in result
    fake_db.update_attack_vector.assert_not_called()


@pytest.mark.asyncio
async def test_request_tool_access_rejects_unknown_group(monkeypatch, ids):
    fake_db = _wire_common_mocks(monkeypatch, ids)

    access_tool = orchestrator_tools.create_request_tool_access_tool(
        ids["project_id"], ids["target_id"]
    )
    result = await access_tool.ainvoke(
        {"vector_id": "v-1", "tool_group": "not-a-real-id", "reason": "because"}
    )

    assert "not a known tool group" in result
    fake_db.get_attack_vector.assert_not_called()
    fake_db.update_attack_vector.assert_not_called()


def test_request_tool_access_is_always_interrupt_gated():
    assert (
        orchestrator_tools.REQUEST_TOOL_ACCESS_TOOL_NAME
        in orchestrator_tools.ALWAYS_INTERRUPT_TOOL_NAMES
    )


def test_build_orchestrator_agent_tools_returns_four_tools_including_request_tool_access(ids):
    from src.core.agent.agent_tools.builders import build_orchestrator_agent_tools

    tools = build_orchestrator_agent_tools(
        ids["project_id"], ids["target_id"], ids["orchestrator_run_id"], False, lambda: None
    )

    assert len(tools) == 4
    tool_names = {t.name for t in tools}
    assert orchestrator_tools.REQUEST_TOOL_ACCESS_TOOL_NAME in tool_names
