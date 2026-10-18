"""§1.4a tier 2 (docs/testing-plan.md) - nmap_scan against http_target
through the real, unmodified create_pentest_tools factory. Follows
test_kali_session.py's own reference pattern (a real KaliManger wired onto
a fixture container without .start()) via tools/conftest.py's
live_kali_session, which already provides that wiring for this whole tier.

Every assertion here checks nmap's own real output against http_target
(a seeded open port 80, and port 81 - nothing listens there) through
_parse_nmap_output's real regex, not a recorded/mocked string."""

import uuid

import pytest

from src.core.agent import agent_tools
from src.core.agent.agent_tools import NMAP_SCAN_TOOL_NAME, create_pentest_tools
from src.schemas import Target

pytestmark = pytest.mark.live_tools


def _make_target(**overrides) -> Target:
    defaults = dict(
        name="nmap-test-target",
        project_id=uuid.uuid4(),
        ipv4="http-target",
        ipv6=None,
        description=None,
        ports=[80, 81],
        task_duration=None,
    )
    defaults.update(overrides)
    return Target(**defaults)


async def _invoke(tool, **args):
    return await tool.ainvoke(
        {"name": tool.name, "args": args, "id": "test-call", "type": "tool_call"}
    )


@pytest.fixture
def pentest_tools(monkeypatch, fake_db_manager, live_kali_session, http_target):
    fake_db_manager.get_target.return_value = _make_target()
    monkeypatch.setattr(agent_tools, "db_manager", fake_db_manager)

    async def _get_manager(project_id, on_stage=None):
        return live_kali_session.manager

    monkeypatch.setattr(agent_tools.kali_registry, "get_manager", _get_manager)

    calls = {"on_enumeration": [], "mark_tested": [], "on_raw_output": []}
    tools = create_pentest_tools(
        live_kali_session.project_id,
        live_kali_session.target_id,
        lambda d: calls["on_enumeration"].append(d),
        lambda: calls["mark_tested"].append(True),
        lambda output: calls["on_raw_output"].append(output),
    )
    return {t.name: t for t in tools}, calls


@pytest.mark.timeout(60)
async def test_nmap_scan_reports_the_open_port_and_excludes_the_closed_one(pentest_tools):
    tools, calls = pentest_tools

    result = await _invoke(tools[NMAP_SCAN_TOOL_NAME], ports="80,81")

    # Structured result: only the real open port, with an http-ish service.
    # Keyed "80/tcp", not bare "80" - _parse_nmap_output keys by
    # port/protocol so a tcp/udp pair on the same port number never
    # collides into one entry.
    assert "Found 1 open port(s): 80/tcp" in result.content
    assert calls["on_enumeration"], "nmap_scan never reported findings to the enumeration table"
    entries = calls["on_enumeration"][0]
    assert set(entries) == {"80/tcp"}
    assert entries["80/tcp"]["service"] == "http"
    assert calls["mark_tested"] == [True]

    # Raw artifact: nmap's own real port table, port 81 explicitly closed.
    assert "80/tcp open" in result.artifact
    assert "81/tcp closed" in result.artifact
    assert "81/tcp open" not in result.artifact


@pytest.mark.timeout(30)
async def test_nmap_scan_refuses_an_out_of_scope_port_without_ever_calling_nmap(
    pentest_tools, monkeypatch, live_kali_session
):
    tools, calls = pentest_tools
    executed_commands = []
    real_execute = live_kali_session.manager.execute

    async def _spy_execute(command, *args, **kwargs):
        executed_commands.append(command)
        return await real_execute(command, *args, **kwargs)

    monkeypatch.setattr(live_kali_session.manager, "execute", _spy_execute)

    result = await _invoke(tools[NMAP_SCAN_TOOL_NAME], ports="9999")

    assert "outside this target's authorized scope" in result.content
    assert executed_commands == []
    assert calls["mark_tested"] == []
