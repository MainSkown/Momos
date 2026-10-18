"""§1.4a tier 2 (docs/testing-plan.md) - hydra_bruteforce
(create_pentest_tools, backend/src/core/agent/agent_tools.py) against
`ssh_target`'s and `ftp_target`'s shared seeded weak test account
(username "momos-test", password "momos-test-weak-pw" - see
backend/tests/docker/ssh-target.Dockerfile / ftp-target.Dockerfile).

hydra_bruteforce's own Literal["ftp", "ssh", "telnet", "mysql", "smtp",
"pop3"] confirms ftp IS a supported service mode, so both pairs below run
against real services, not just ssh - matching docs/testing-plan.md
§1.4a's "ssh_target's AND ftp_target's seeded weak account" wording.

Each service gets one positive case (a small wordlist that DOES contain
the real password, mixed with wrong guesses) and one separate negative
case (a wordlist that does NOT contain it) - a false positive on the
negative case would be exactly the kind of bug this tier exists to catch
(docs/testing-plan.md's own "never just 'the call didn't throw'" rule)."""

import uuid

import pytest

from src.core.agent import agent_tools
from src.core.agent.agent_tools import HYDRA_BRUTEFORCE_TOOL_NAME, create_pentest_tools
from src.schemas import Target

USERNAME = "momos-test"
PASSWORD = "momos-test-weak-pw"
POS_WORDLIST_PATH = "/tmp/hydra-test-passwords-pos.txt"
NEG_WORDLIST_PATH = "/tmp/hydra-test-passwords-neg.txt"


def _make_target(host: str, port: int) -> Target:
    return Target(
        name="hydra-probe-target",
        project_id=uuid.uuid4(),
        ipv4=host,
        ipv6=None,
        description=None,
        ports=[port],
        task_duration=None,
    )


def _tools_by_name(tools) -> dict:
    return {t.name: t for t in tools}


async def _invoke(tool, **args):
    return await tool.ainvoke(
        {"name": tool.name, "args": args, "id": "test-call", "type": "tool_call"}
    )


@pytest.fixture(scope="module")
async def hydra_wordlists(live_kali_session):
    """Writes two small, fixed wordlists into the real Kali container once
    per module (plain files, no tool involved in creating them - hydra's
    own password_list argument just needs them to already exist on disk,
    exactly like a real operator would have prepared them beforehand)."""
    manager = live_kali_session.manager
    await manager.execute(
        f"printf '%s\\n' wrong-guess-one {PASSWORD} wrong-guess-two > {POS_WORDLIST_PATH}"
    )
    await manager.execute(
        f"printf '%s\\n' wrong-guess-one wrong-guess-two wrong-guess-three > {NEG_WORDLIST_PATH}"
    )
    yield POS_WORDLIST_PATH, NEG_WORDLIST_PATH
    await manager.execute(f"rm -f {POS_WORDLIST_PATH} {NEG_WORDLIST_PATH}")


@pytest.fixture
def hydra_tools_factory(live_kali_session, ssh_target, ftp_target, monkeypatch):
    """Returns a function(host, port) -> {tool_name: tool}, built fresh
    per call against whichever target host/port this test needs -
    kali_registry.get_manager is patched once per test (restored by
    `monkeypatch`), db_manager.get_target per `_build` call. Depends
    directly on both `ssh_target`/`ftp_target` (not just
    live_kali_session) so both real containers actually exist and are
    attached to docker_network before any hydra run tries to resolve
    their hostnames."""

    async def _get_manager(project_id, on_stage=None):
        return live_kali_session.manager

    monkeypatch.setattr(agent_tools.kali_registry, "get_manager", _get_manager)

    def _build(host: str, port: int) -> dict:
        monkeypatch.setattr(
            agent_tools.db_manager, "get_target", lambda target_id: _make_target(host, port)
        )
        tools = create_pentest_tools(
            live_kali_session.project_id,
            live_kali_session.target_id,
            lambda d: None,
            lambda: None,
            lambda output: None,
        )
        return _tools_by_name(tools)

    return _build


@pytest.mark.live_tools
@pytest.mark.timeout(120)
class TestHydraAgainstSshTarget:
    async def test_positive_wordlist_finds_the_real_password(
        self, hydra_tools_factory, hydra_wordlists
    ):
        pos_path, _neg_path = hydra_wordlists
        tools = hydra_tools_factory("ssh-target", 22)

        result = await _invoke(
            tools[HYDRA_BRUTEFORCE_TOOL_NAME],
            service="ssh",
            username=USERNAME,
            password_list=pos_path,
        )

        assert result.content.startswith("Valid credentials found!")
        assert f"login: {USERNAME}" in result.artifact
        assert f"password: {PASSWORD}" in result.artifact

    async def test_negative_wordlist_reports_no_match_not_a_false_positive(
        self, hydra_tools_factory, hydra_wordlists
    ):
        _pos_path, neg_path = hydra_wordlists
        tools = hydra_tools_factory("ssh-target", 22)

        result = await _invoke(
            tools[HYDRA_BRUTEFORCE_TOOL_NAME],
            service="ssh",
            username=USERNAME,
            password_list=neg_path,
        )

        assert result.content.startswith("No valid credentials found.")
        assert "Valid credentials found" not in result.content


@pytest.mark.live_tools
@pytest.mark.timeout(120)
class TestHydraAgainstFtpTarget:
    async def test_positive_wordlist_finds_the_real_password(
        self, hydra_tools_factory, hydra_wordlists
    ):
        pos_path, _neg_path = hydra_wordlists
        tools = hydra_tools_factory("ftp-target", 21)

        result = await _invoke(
            tools[HYDRA_BRUTEFORCE_TOOL_NAME],
            service="ftp",
            username=USERNAME,
            password_list=pos_path,
        )

        assert result.content.startswith("Valid credentials found!")
        assert f"login: {USERNAME}" in result.artifact
        assert f"password: {PASSWORD}" in result.artifact

    async def test_negative_wordlist_reports_no_match_not_a_false_positive(
        self, hydra_tools_factory, hydra_wordlists
    ):
        _pos_path, neg_path = hydra_wordlists
        tools = hydra_tools_factory("ftp-target", 21)

        result = await _invoke(
            tools[HYDRA_BRUTEFORCE_TOOL_NAME],
            service="ftp",
            username=USERNAME,
            password_list=neg_path,
        )

        assert result.content.startswith("No valid credentials found.")
        assert "Valid credentials found" not in result.content
