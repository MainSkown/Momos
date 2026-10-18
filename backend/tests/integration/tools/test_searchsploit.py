"""§1.4a tier 2 (docs/testing-plan.md) - searchsploit_search/view/run
against the real exploitdb mirror bundled in pentest_tools_image, through
the real, unmodified create_pentest_tools factory - same live_kali_session
wiring as test_nmap.py/test_gobuster.py.

Assertions are pinned to EDB-ID 49757 (vsftpd 2.3.4 - Backdoor Command
Execution) and its Metasploit-module twin, EDB-ID 17491 (vsftpd 2.3.4 -
Backdoor Command Execution (Metasploit)) - both long-stable, permanent
exploit-db IDs (49757 is the same one the task's own Stage A smoke test
already confirmed; 17491 is the exact ID agent_tools.py's own
_METASPLOIT_MODULE_MARKERS comment cites as an observed-in-production
Metasploit module) - never a live search-ranking string, so this suite
doesn't rot as the exploitdb database updates. EDB-ID 20 (a plain-text
advisory with no runnable interpreter) pins searchsploit_run's
unsupported-extension branch the same way.

searchsploit_run is deliberately never exercised past routing/validation -
no real exploit payload is ever executed, even against our own disposable
http_target (docs/testing-plan.md §1.4a's explicit, conservative scoping,
matching how this tier also limits metasploit_run elsewhere).

SEARCHSPLOIT_EXPLOITDB_PREFIX note: pentest-tools.Dockerfile git-clones
exploitdb to /opt/exploitdb (simplest on this Alpine-based test image),
while production's real Kali image gets it from the kalilinux apt package,
which installs to /usr/share/exploitdb/ - the path agent_tools.py's
constant is hard-coded for. That's a property of which image is running,
not a behavior difference to paper over at the filesystem level, so it's
patched here the same way test_kali_session.py patches
SESSION_IDLE_TIMEOUT_SECONDS: on the consuming module, for this test
module only."""

import uuid

import pytest

from src.core.agent import agent_tools
from src.core.agent.agent_tools import (
    SEARCHSPLOIT_RUN_TOOL_NAME,
    SEARCHSPLOIT_SEARCH_TOOL_NAME,
    SEARCHSPLOIT_VIEW_TOOL_NAME,
    create_pentest_tools,
)
from src.schemas import Target

pytestmark = pytest.mark.live_tools

VSFTPD_SCRIPT_EDB_ID = "49757"
VSFTPD_METASPLOIT_MODULE_EDB_ID = "17491"
TEXT_ADVISORY_EDB_ID = "20"


def _make_target(**overrides) -> Target:
    defaults = dict(
        name="searchsploit-test-target",
        project_id=uuid.uuid4(),
        ipv4="http-target",
        ipv6=None,
        description=None,
        ports=[80],
        task_duration=None,
    )
    defaults.update(overrides)
    return Target(**defaults)


async def _invoke(tool, **args):
    return await tool.ainvoke(
        {"name": tool.name, "args": args, "id": "test-call", "type": "tool_call"}
    )


@pytest.fixture(autouse=True)
def _exploitdb_path_matches_this_test_image(monkeypatch):
    monkeypatch.setattr(agent_tools, "SEARCHSPLOIT_EXPLOITDB_PREFIX", "/opt/exploitdb/")


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


@pytest.mark.timeout(30)
async def test_searchsploit_search_finds_the_pinned_stable_exploit(pentest_tools):
    tools, _ = pentest_tools

    result = await _invoke(tools[SEARCHSPLOIT_SEARCH_TOOL_NAME], query="vsftpd 2.3.4")

    assert (
        f"{VSFTPD_SCRIPT_EDB_ID}: vsftpd 2.3.4 - Backdoor Command Execution"
        in result.content
    )


@pytest.mark.timeout(30)
async def test_searchsploit_search_handles_a_genuinely_not_found_query(pentest_tools):
    tools, _ = pentest_tools

    result = await _invoke(
        tools[SEARCHSPLOIT_SEARCH_TOOL_NAME],
        query="momos-test-definitely-not-a-real-exploit-xyz",
    )

    assert result.content == "No matching exploits found."


@pytest.mark.timeout(30)
async def test_searchsploit_view_returns_the_real_exploit_source(pentest_tools):
    tools, calls = pentest_tools

    result = await _invoke(
        tools[SEARCHSPLOIT_VIEW_TOOL_NAME], edb_id=VSFTPD_SCRIPT_EDB_ID
    )

    assert (
        "# Exploit Title: vsftpd 2.3.4 - Backdoor Command Execution"
        in result.content
    )
    assert "Exploit Title: vsftpd 2.3.4 - Backdoor Command Execution" in result.artifact
    assert calls["mark_tested"] == [True]


@pytest.mark.timeout(15)
async def test_searchsploit_run_rejects_an_invalid_edb_id_before_any_real_lookup(
    pentest_tools, monkeypatch, live_kali_session
):
    tools, calls = pentest_tools
    executed_commands = []
    real_execute = live_kali_session.manager.execute

    async def _spy_execute(command, *args, **kwargs):
        executed_commands.append(command)
        return await real_execute(command, *args, **kwargs)

    monkeypatch.setattr(live_kali_session.manager, "execute", _spy_execute)

    result = await _invoke(
        tools[SEARCHSPLOIT_RUN_TOOL_NAME], edb_id="not-a-number"
    )

    assert "Invalid edb_id" in result.content
    assert executed_commands == []
    assert calls["mark_tested"] == []


@pytest.mark.timeout(30)
async def test_searchsploit_run_routes_a_metasploit_module_to_metasploit_run_instead(
    pentest_tools, monkeypatch, live_kali_session
):
    """EDB-ID 17491 is a real Metasploit-framework module (require
    'msf/core', class ... < Msf::Exploit::Remote) mirrored as a plain .rb
    file - searchsploit_run must recognize this from its content and
    refuse to run it with a bare ruby interpreter, never actually
    attempting to execute it."""
    tools, calls = pentest_tools
    executed_commands = []
    real_execute = live_kali_session.manager.execute

    async def _spy_execute(command, *args, **kwargs):
        executed_commands.append(command)
        return await real_execute(command, *args, **kwargs)

    monkeypatch.setattr(live_kali_session.manager, "execute", _spy_execute)

    result = await _invoke(
        tools[SEARCHSPLOIT_RUN_TOOL_NAME], edb_id=VSFTPD_METASPLOIT_MODULE_EDB_ID
    )

    assert "Metasploit-framework module" in result.content
    assert "metasploit_run" in result.content
    assert not any("ruby" in cmd for cmd in executed_commands)
    assert calls["mark_tested"] == [True]


@pytest.mark.timeout(30)
async def test_searchsploit_run_rejects_an_unsupported_file_extension(
    pentest_tools, monkeypatch, live_kali_session
):
    """EDB-ID 20 is a plain-text advisory (.txt) - no interpreter exists
    for it in _SEARCHSPLOIT_INTERPRETER_BY_EXTENSION, so searchsploit_run
    must refuse it without ever trying to execute anything."""
    tools, calls = pentest_tools
    executed_commands = []
    real_execute = live_kali_session.manager.execute

    async def _spy_execute(command, *args, **kwargs):
        executed_commands.append(command)
        return await real_execute(command, *args, **kwargs)

    monkeypatch.setattr(live_kali_session.manager, "execute", _spy_execute)

    result = await _invoke(
        tools[SEARCHSPLOIT_RUN_TOOL_NAME], edb_id=TEXT_ADVISORY_EDB_ID
    )

    assert "Don't know how to run a '.txt' file" in result.content
    assert not any(
        cmd.strip().startswith(("python3 ", "perl ", "ruby ", "bash "))
        for cmd in executed_commands
    )
    assert calls["mark_tested"] == [True]
