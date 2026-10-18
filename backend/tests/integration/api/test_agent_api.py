"""§1.4b: agent_router through the real app - agent_router -> AgentService
-> run_registry -> agent_checkpointer/Agent, with Docker and the LLM faked
only at their one real boundary each (fake_docker_client/kali_container_
ready, and ChatOllama patched below). See docs/testing-plan.md §1.4b.

Deliberately scaled back from a full turn-by-turn graph exercise (see the
module docstring on agent_checkpointer_ready and this file's own comments)
- the required, non-negotiable proof is just: start_agent creates a real
RUNNING AgentRun row, and pause/finish_agent change that row's real,
persisted state. Driving the graph through an actual tool call/approval
cycle would need far more exact message-shape scripting against LangGraph
internals than this narrow tier is meant to pay for - see
docs/testing-plan.md §1.4b's own "narrower and non-negotiable" framing.
"""

import asyncio
import time

import pytest
from langchain_core.messages import AIMessage
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from src.core.agent import agent_checkpointer
from src.schemas.agent_run_scheme import AgentRunState
from ollama import ListResponse, ShowResponse
from ollama._types import ModelDetails


class _GateAwareModel:
    """Stands in for agent.py's Agent.changeModel's `ChatOllama(...).
    bind_tools(self.tools)` - the one real call site that would otherwise
    reach a live Ollama server (see agent-core-files.md's own "Hardwired
    LLM construction" testability blocker). `.ainvoke` blocks on `gate`
    until the test releases it, so the run can be caught deterministically
    while it's genuinely live (registered in run_registry, RUNNING in the
    real DB, actually suspended on this exact call) rather than racing a
    real LLM call's timing to land a pause/finish before it would
    otherwise finish on its own."""

    def __init__(self, gate: asyncio.Event):
        self._gate = gate

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, *args, **kwargs):
        await self._gate.wait()
        return AIMessage(content="no further action", tool_calls=[])


@pytest.fixture
async def agent_checkpointer_ready(postgres_dsn, monkeypatch):
    """Validated recipe from the task brief - a real AsyncPostgresSaver
    against the same Postgres testcontainer pg_container itself uses.
    agent_service.py reads agent_checkpointer.checkpointer as a module
    attribute lookup at each call site, so patching this one name is
    enough - no per-consuming-module patching needed, unlike db_manager."""
    pool = AsyncConnectionPool(
        conninfo=postgres_dsn,
        max_size=5,
        kwargs={"autocommit": True, "prepare_threshold": 0, "row_factory": dict_row},
        open=False,
    )
    await pool.open()
    checkpointer = AsyncPostgresSaver(pool)
    await checkpointer.setup()
    monkeypatch.setattr(agent_checkpointer, "checkpointer", checkpointer)
    yield checkpointer
    await pool.close()


@pytest.fixture
def agent_gate(monkeypatch):
    """Patches src.core.agent.agent.ChatOllama itself (per the task brief's
    LLM-boundary recipe) to _GateAwareModel, gated on a fresh asyncio.Event
    - yields that event so a test can release it, or just leave it closed
    and let pause/finish interrupt the suspended call instead (see
    agent.py's start_agent streaming loop: asyncio.wait races the next
    stream event against stop_event, so a pause/finish signal is noticed
    even while the "agent" node's own LLM call is still suspended)."""
    gate = asyncio.Event()
    monkeypatch.setattr(
        "src.core.agent.agent.ChatOllama", lambda **kwargs: _GateAwareModel(gate)
    )
    return gate


def _create_project_and_target(client, fake_ollama_client, model_name="qwen3:8b"):
    # update_project_settings (project_router.py) rejects a base_model_name
    # that isn't in the real installed-models list; start_agent's own
    # blocking install check (AgentService.start_agent) re-verifies the
    # same thing via ollama_manager.get_model_capabilities - both read
    # through this same fake_ollama_client boundary.
    fake_ollama_client.list.return_value = ListResponse(
        models=[
            ListResponse.Model(
                model=model_name,
                size=1,
                details=ModelDetails(family="qwen", parameter_size="8B"),
            )
        ]
    )
    fake_ollama_client.show.return_value = ShowResponse(model_info={}, capabilities=[])

    project = client.post(
        "/api/project",
        json={"name": "Agent Target", "base_model_name": "", "parsing_model_name": ""},
    ).json()

    # single_agent mode - project_settings_factory defaults new projects to
    # "multi_agent" (the OrchestratorAgent pipeline), which is a
    # substantially bigger surface than this narrow tier is meant to
    # cover; single_agent is what Agent/_run_agent (the code this test
    # actually targets) runs.
    settings = client.get(f"/api/project/{project['id']}/settings").json()
    settings["project_id"] = project["id"]
    settings["pipeline_mode"] = "single_agent"
    settings["base_model_name"] = model_name
    response = client.put(f"/api/project/{project['id']}/settings", json=settings)
    assert response.status_code == 200

    target = client.post(
        f"/api/project/{project['id']}/target",
        json={
            "name": "agent-target",
            "ipv4": None,
            "ipv6": None,
            "description": None,
            "ports": None,
            "task_duration": 60,
        },
    ).json()

    # add_target (TargetService.add_target) only ever uses data.name - the
    # POST body's task_duration is ignored, same gap test_target_api.py's
    # own PUT test already pins. run_mode defaults to "timer", which
    # start_agent rejects outright without a real task_duration - a PUT is
    # the only way to actually set it. update_target (target_router.py)
    # returns no body (status 200, empty) - keep the original POST's dict.
    # ports=[] (not None) - TargetService.update_target iterates
    # target.ports unconditionally (`all(1 <= port <= 65535 for port in
    # target.ports)`), which raises TypeError on a None list; a real gap,
    # out of scope for this test file, that ports=[] sidesteps.
    put_response = client.put(
        f"/api/target/{target['id']}",
        json={
            "name": "agent-target",
            "ipv4": None,
            "ipv6": None,
            "description": None,
            "ports": [],
            "task_duration": 60,
        },
    )
    assert put_response.status_code == 200

    return project, target


def _poll(predicate, timeout_seconds=5.0, interval=0.05):
    deadline = time.monotonic() + timeout_seconds
    result = None
    while time.monotonic() < deadline:
        result = predicate()
        if result is not None:
            return result
        time.sleep(interval)
    return result


def test_start_agent_creates_a_real_running_agent_run_row(
    api_integration_client,
    pg_container,
    kali_container_ready,
    fake_ollama_client,
    agent_checkpointer_ready,
    agent_gate,
):
    project, target = _create_project_and_target(api_integration_client, fake_ollama_client)

    response = api_integration_client.post(
        f"/api/project/{project['id']}/target/{target['id']}/agent/start"
    )
    assert response.status_code == 200

    run = _poll(lambda: pg_container.get_agent_run(target["id"], role="single_agent"))

    assert run is not None
    assert run.status == AgentRunState.RUNNING
    assert str(run.target_id) == target["id"]
    assert str(run.project_id) == project["id"]

    # Let the gated LLM call return and the run wind down on its own,
    # rather than leaving a suspended background task hanging past the
    # end of the test.
    agent_gate.set()


def test_pause_agent_changes_the_real_agent_run_row_to_paused(
    api_integration_client,
    pg_container,
    kali_container_ready,
    fake_ollama_client,
    agent_checkpointer_ready,
    agent_gate,
):
    project, target = _create_project_and_target(api_integration_client, fake_ollama_client)

    start_response = api_integration_client.post(
        f"/api/project/{project['id']}/target/{target['id']}/agent/start"
    )
    assert start_response.status_code == 200

    run = _poll(lambda: pg_container.get_agent_run(target["id"], role="single_agent"))
    assert run is not None and run.status == AgentRunState.RUNNING

    # The run is now genuinely live (registered in run_registry, RUNNING
    # in the real DB) and suspended on agent_gate inside its one real LLM
    # call - pause_agent's stop_event.set() races the stream loop's own
    # asyncio.wait and is noticed without needing that call to ever return.
    pause_response = api_integration_client.post(
        f"/api/project/{project['id']}/target/{target['id']}/agent/pause"
    )
    assert pause_response.status_code == 200

    paused_run = _poll(
        lambda: (
            run
            if (run := pg_container.get_agent_run(target["id"], role="single_agent"))
            and run.status != AgentRunState.RUNNING
            else None
        )
    )
    assert paused_run is not None
    assert paused_run.status == AgentRunState.PAUSED

    agent_gate.set()


def test_finish_agent_changes_the_real_agent_run_row_to_finished(
    api_integration_client,
    pg_container,
    kali_container_ready,
    fake_ollama_client,
    agent_checkpointer_ready,
    agent_gate,
):
    project, target = _create_project_and_target(api_integration_client, fake_ollama_client)

    start_response = api_integration_client.post(
        f"/api/project/{project['id']}/target/{target['id']}/agent/start"
    )
    assert start_response.status_code == 200

    run = _poll(lambda: pg_container.get_agent_run(target["id"], role="single_agent"))
    assert run is not None and run.status == AgentRunState.RUNNING

    finish_response = api_integration_client.post(
        f"/api/project/{project['id']}/target/{target['id']}/agent/finish"
    )
    assert finish_response.status_code == 200

    finished_run = _poll(
        lambda: (
            run
            if (run := pg_container.get_agent_run(target["id"], role="single_agent"))
            and run.status != AgentRunState.RUNNING
            else None
        )
    )
    assert finished_run is not None
    assert finished_run.status == AgentRunState.FINISHED

    # Real TestSession state, not just the AgentRun row - _finalize_session
    # is the other half of finish_agent's real-DB contract.
    session = pg_container.get_latest_session_for_target(target["id"])
    assert session is not None
    assert session.outcome.value == "finished"

    agent_gate.set()
