"""§1.4a tier 2 (docs/testing-plan.md) - metasploit_run against the real
pentest-tools image's own msfconsole.

Safety scope is locked in by the plan itself and is NON-NEGOTIABLE: the
only module this file may ever construct, reference, or run is
`auxiliary/scanner/portscan/tcp`, against `http_target` - one safe,
non-exploitative module, deliberately scoped away from anything under
`exploit/`, `payload/`, or `post/`, even as a negative/rejection test. See
docs/testing-plan.md §1.4a's own explicit decision before touching this
file.

`metasploit_run` (agent_tools.py) takes RHOSTS/RPORT entirely inside its
free-text `commands` string - no `target_id` resolution happens inside the
tool at all (confirmed by reading its body: it never calls
`_get_target_info`/`_get_target_host`), so `http_target`'s container name
is supplied directly in the command string here, with no monkeypatching
needed for target resolution. The only thing replaced is
`agent_tools.kali_registry.get_manager` (same pattern test_kali_session.py's
tier-1 `manager` fixture already uses) - everything below it (KaliManger.
execute, the real msfconsole process) is real, unmodified production code
against a real target container. Also unlike run()'s interactive pathway,
metasploit_run never calls `_maybe_condense`/`_parse_output` at all, so
this test touches no database and no Ollama either."""

import pytest

from src.core.agent import agent_tools
from src.core.agent.agent_tools import METASPLOIT_RUN_TOOL_NAME, create_pentest_tools


def _tools_by_name(tools) -> dict:
    return {t.name: t for t in tools}


async def _invoke(tool, **args):
    return await tool.ainvoke(
        {"name": tool.name, "args": args, "id": "test-call", "type": "tool_call"}
    )


@pytest.fixture
def pentest_tools(live_kali_session, monkeypatch, http_target):
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
    return _tools_by_name(tools), calls


@pytest.mark.live_tools
@pytest.mark.timeout(300)
async def test_metasploit_run_portscan_finds_real_open_port(pentest_tools):
    """The one module this tier is allowed to run - auxiliary/scanner/
    portscan/tcp - against http_target's real nginx. Asserts on the
    module's own "[+] <ip> - <ip>:<port> - TCP OPEN" result line for port
    80 (confirmed empirically against this exact image/module), which is
    robust to msfconsole's startup banner/database-not-connected noise
    since it's a late, distinctive line format the module itself prints -
    and that port 81 (requested but never seeded) is NOT reported open, so
    this can't pass on a vacuous "found something" match."""
    tools, _ = pentest_tools

    result = await _invoke(
        tools[METASPLOIT_RUN_TOOL_NAME],
        commands=(
            "use auxiliary/scanner/portscan/tcp; "
            "set RHOSTS http-target; "
            "set PORTS 80,81; "
            "run"
        ),
    )

    assert ":80 - TCP OPEN" in result.artifact
    assert ":81 - TCP OPEN" not in result.artifact
