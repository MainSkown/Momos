"""§1.4a tier 2 (docs/testing-plan.md) - gobuster_scan against http_target
through the real, unmodified create_pentest_tools factory - same
live_kali_session/http_target wiring as test_nmap.py, see that file's own
docstring and test_kali_session.py for the pattern this is built on.

http_target's seeded tree (backend/tests/docker/http-target/site/) has
admin/, backup/, login/, images/ and deliberately no fifth path - gobuster
is pointed at a small, test-local wordlist (built here, not the
nonexistent default DEFAULT_GOBUSTER_WORDLIST - this image has no
/usr/share/wordlists at all, see pentest-tools.Dockerfile) containing
those four names plus one that was never seeded, so a false positive is
exactly as checkable as a miss."""

import base64
import uuid

import pytest

from src.core.agent import agent_tools
from src.core.agent.agent_tools import GOBUSTER_SCAN_TOOL_NAME, create_pentest_tools
from src.schemas import Target

pytestmark = pytest.mark.live_tools

SEEDED_PATHS = ("admin", "backup", "login", "images")
UNSEEDED_PATH = "momos-test-definitely-not-seeded"
WORDLIST_PATH = "/tmp/momos-test-gobuster-wordlist.txt"


def _make_target(**overrides) -> Target:
    defaults = dict(
        name="gobuster-test-target",
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


@pytest.fixture
async def gobuster_wordlist(live_kali_session):
    """Writes a small, fixed wordlist directly into the pentest-tools
    container - the same base64-pipe technique agent_tools.py's own
    write_local_file tool uses, so no shell-quoting of the word list is
    needed. Removed again after the test - this is this test's own
    artifact, not one of the session-scoped fixtures'."""
    content = "\n".join((*SEEDED_PATHS, UNSEEDED_PATH)) + "\n"
    encoded = base64.b64encode(content.encode()).decode()
    await live_kali_session.manager.execute(
        f"echo {encoded} | base64 -d > {WORDLIST_PATH}", timeout_seconds=10
    )
    yield WORDLIST_PATH
    await live_kali_session.manager.execute(f"rm -f {WORDLIST_PATH}", timeout_seconds=10)


@pytest.mark.timeout(90)
async def test_gobuster_scan_real_run_finds_seeded_paths_and_not_the_unseeded_one(
    pentest_tools, gobuster_wordlist
):
    """Proves gobuster's own real behavior against the real target,
    independent of gobuster_scan's own output parsing (see the xfail test
    below for that) - the raw artifact is gobuster's unmodified stdout."""
    tools, _ = pentest_tools

    result = await _invoke(
        tools[GOBUSTER_SCAN_TOOL_NAME], port=80, wordlist=gobuster_wordlist
    )

    for path in SEEDED_PATHS:
        assert f"/{path} " in result.artifact
    assert UNSEEDED_PATH not in result.artifact


@pytest.mark.timeout(90)
async def test_gobuster_scan_structured_result_reports_all_seeded_paths(
    pentest_tools, gobuster_wordlist
):
    tools, calls = pentest_tools

    result = await _invoke(
        tools[GOBUSTER_SCAN_TOOL_NAME], port=80, wordlist=gobuster_wordlist
    )

    assert f"Found {len(SEEDED_PATHS)} path(s)." in result.content
    assert calls["on_enumeration"], "gobuster_scan never reported findings to the enumeration table"
    notes = calls["on_enumeration"][0]["80"]["notes"]
    for path in SEEDED_PATHS:
        assert f"/{path}" in notes
    assert UNSEEDED_PATH not in notes
