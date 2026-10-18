"""§1.4a tier 2 (docs/testing-plan.md) - ftp_connect/ftp_command
(create_guided_session_tools, backend/src/core/agent/agent_tools.py)
against `ftp_target`'s real vsftpd, its seeded weak test account and its
seeded fixed file tree (backend/tests/docker/ftp-target.Dockerfile):
username "momos-test", password "momos-test-weak-pw", with the server
chrooted into the account's home dir so the FTP-visible root contains
"public/readme.txt" and "public/docs/notes.txt".

Only kali_registry.get_manager and db_manager.get_target are patched (the
same "patch the consumer" seam as test_ssh_probe.py/test_kali_session.py)
- create_guided_session_tools itself runs completely unmodified against
live_kali_session's real KaliManger/container."""

import asyncio
import uuid

import pytest

from src.core.agent import agent_tools
from src.core.agent.agent_tools import (
    FTP_COMMAND_TOOL_NAME,
    FTP_CONNECT_TOOL_NAME,
    create_guided_session_tools,
)
from src.schemas import Target

FTP_USERNAME = "momos-test"
FTP_PASSWORD = "momos-test-weak-pw"
README_CONTENT = "momos ftp smoke-test file\n"
NOTES_CONTENT = "nested fixed file for recursive listing tests\n"


def _make_ftp_target() -> Target:
    return Target(
        name="ftp-probe-target",
        project_id=uuid.uuid4(),
        ipv4="ftp-target",
        ipv6=None,
        description=None,
        ports=[21],
        task_duration=None,
    )


def _tools_by_name(tools) -> dict:
    return {t.name: t for t in tools}


async def _invoke(tool, **args):
    return await tool.ainvoke(
        {"name": tool.name, "args": args, "id": "test-call", "type": "tool_call"}
    )


async def _invoke_ftp_connect(tool, **args):
    """Like _invoke, but retries ftp_connect's own documented "unclear"
    outcome - confirmed reproducible when this file runs right after
    test_hydra.py's FTP brute-force in the same session: the real
    vsftpd on ftp-target replies to the login attempt slower than usual
    for a few seconds right after fielding hydra's burst of connections,
    so the real 530/230 reply doesn't arrive within ftp_connect's own
    SESSION_OPEN_READ_SECONDS (3s) window and it correctly falls back to
    "Login outcome unclear from the response" (agent_tools.py's own
    documented third outcome, not a false positive/negative). ftp_connect
    itself documents that retrying is the right move here ("Only retry
    this tool if the previous call actually failed... it's safe to call
    again"), and _ftp_logged_in is never set True on an unclear outcome,
    so retrying is safe - a real "Login successful."/"Login failed." is
    never retried or masked, only this specific inconclusive case is."""
    result = None
    for attempt in range(5):
        result = await _invoke(tool, **args)
        if not result.content.startswith("Login outcome unclear"):
            return result
        await asyncio.sleep(2)
    return result


@pytest.fixture
def ftp_env(live_kali_session, ftp_target, monkeypatch):
    """Returns (tools_by_name, manager) - `manager` is live_kali_session's
    own real KaliManger, exposed so tests can verify a `get`'s downloaded
    file by exec'ing a real `cat` in the container directly, independent
    of what ftp_command itself claims. Depends directly on `ftp_target`
    (not just live_kali_session) so the real vsftpd container actually
    exists and is attached to docker_network before any tool call tries
    to resolve its hostname."""

    async def _get_manager(project_id, on_stage=None):
        return live_kali_session.manager

    monkeypatch.setattr(agent_tools.kali_registry, "get_manager", _get_manager)
    monkeypatch.setattr(agent_tools.db_manager, "get_target", lambda target_id: _make_ftp_target())
    # See test_ssh_probe.py's ssh_tools fixture for why this is needed -
    # ftp_command's _send_and_condense classifies by the ftp session's own
    # command text (e.g. "ls", "get readme.txt"), none of which is in
    # _NETWORK_FACING_BINARIES, so this is defensive rather than currently
    # load-bearing here - but cheap insurance against the same real-DB/
    # fake-project-id crash if that ever changes.
    monkeypatch.setattr(agent_tools.db_manager, "get_project_settings", lambda project_id: None)

    tools = create_guided_session_tools(
        live_kali_session.project_id,
        live_kali_session.target_id,
        live_kali_session.agent_run_id,
        lambda d: None,
        lambda: None,
        lambda name, command: None,
        lambda is_open: None,
        lambda output: None,
    )
    return _tools_by_name(tools), live_kali_session.manager


@pytest.fixture(autouse=True)
async def _close_ftp_session_after_test(live_kali_session):
    """ftp_connect refuses to open a second 'ftp' session - each test in
    this file gets a clean slate by closing whatever the previous test
    left open (directly via the manager, not through a tool, since the
    tests below need a FRESH login each time to exercise ftp_connect
    itself, not "already connected")."""
    yield
    try:
        await live_kali_session.manager.close_session(
            live_kali_session.target_id, live_kali_session.agent_run_id, "ftp"
        )
    except Exception:
        pass


@pytest.mark.live_tools
@pytest.mark.timeout(60)
class TestFtpConnect:
    async def test_correct_credentials_log_in_successfully(self, ftp_env):
        tools, _manager = ftp_env
        result = await _invoke_ftp_connect(
            tools[FTP_CONNECT_TOOL_NAME], username=FTP_USERNAME, password=FTP_PASSWORD
        )
        assert result.content.startswith("Login successful.")

    async def test_wrong_password_is_rejected_not_a_false_positive(self, ftp_env):
        tools, _manager = ftp_env
        result = await _invoke_ftp_connect(
            tools[FTP_CONNECT_TOOL_NAME],
            username=FTP_USERNAME,
            password="definitely-not-the-real-password",
        )
        assert result.content.startswith("Login failed.")


@pytest.mark.live_tools
@pytest.mark.timeout(90)
class TestFtpCommand:
    async def test_ls_lists_the_real_seeded_directory_tree(self, ftp_env):
        tools, _manager = ftp_env
        connect = await _invoke_ftp_connect(
            tools[FTP_CONNECT_TOOL_NAME], username=FTP_USERNAME, password=FTP_PASSWORD
        )
        assert connect.content.startswith("Login successful.")

        root_listing = await _invoke(tools[FTP_COMMAND_TOOL_NAME], command="ls")
        assert "public" in root_listing.content

        public_listing = await _invoke(tools[FTP_COMMAND_TOOL_NAME], command="ls public")
        assert "readme.txt" in public_listing.content
        assert "docs" in public_listing.content

        docs_listing = await _invoke(tools[FTP_COMMAND_TOOL_NAME], command="ls public/docs")
        assert "notes.txt" in docs_listing.content

    async def test_get_downloads_the_exact_seeded_file_content(self, ftp_env):
        tools, manager = ftp_env
        connect = await _invoke_ftp_connect(
            tools[FTP_CONNECT_TOOL_NAME], username=FTP_USERNAME, password=FTP_PASSWORD
        )
        assert connect.content.startswith("Login successful.")

        cd_result = await _invoke(tools[FTP_COMMAND_TOOL_NAME], command="cd public")
        assert "250" in cd_result.artifact or "directory" in cd_result.content.lower()

        get_result = await _invoke(tools[FTP_COMMAND_TOOL_NAME], command="get readme.txt")
        assert "226" in get_result.artifact or "complete" in get_result.content.lower()

        # The real behavior, not the tool's own claim - a real downloaded
        # file, with the real seeded content, sitting in the real
        # container's momos home dir (the session's own workdir).
        ok, downloaded = True, None
        try:
            downloaded = await manager.execute("cat /home/momos/readme.txt", timeout_seconds=10)
        except RuntimeError as e:
            ok = False
            downloaded = str(e)
        assert ok, f"download did not land on disk: {downloaded}"
        assert downloaded == README_CONTENT

        nested_cd = await _invoke(tools[FTP_COMMAND_TOOL_NAME], command="cd docs")
        assert "250" in nested_cd.artifact or "directory" in nested_cd.content.lower()
        await _invoke(tools[FTP_COMMAND_TOOL_NAME], command="get notes.txt")
        nested_downloaded = await manager.execute("cat /home/momos/notes.txt", timeout_seconds=10)
        assert nested_downloaded == NOTES_CONTENT


@pytest.mark.live_tools
@pytest.mark.timeout(60)
async def test_active_mode_fallback_is_detected_against_the_real_server(
    ftp_env, live_kali_session
):
    """Proves _ftp_active_mode_fallback (agent_tools.py) actually engages
    against a real vsftpd, not just the pure-unit regex test elsewhere.

    Forcing it through ftp_connect's own passive-toggle path isn't
    reachable here: this test topology (pentest-tools and ftp-target
    sharing one unfirewalled Docker bridge network, no NAT) is exactly
    the condition active mode needs to actually succeed, so a session
    that's genuinely left in active mode would just work rather than
    fail the way it does in production (where the agent's sandbox can't
    receive the target's inbound PORT callback at all) - see this
    function's own real result below, which confirms that directly.

    Instead this uses `quote` (one of the few ftp_command-allowed
    commands that can reach the raw protocol) to send a PORT command
    vsftpd is guaranteed to reject regardless of network topology: RFC
    959 PORT syntax accepted, but vsftpd's own anti-bounce-attack check
    (port_promiscuous=NO, the default - see ftp-target.Dockerfile, which
    never sets it) rejects any PORT whose IP doesn't match this control
    connection's own peer address. That is a real "500 Illegal PORT
    command." from the real server - exactly the string
    _ftp_active_mode_fallback's regex is looking for - not a simulated
    one."""
    tools, manager = ftp_env
    connect = await _invoke_ftp_connect(
        tools[FTP_CONNECT_TOOL_NAME], username=FTP_USERNAME, password=FTP_PASSWORD
    )
    assert connect.content.startswith("Login successful.")

    forced = await _invoke(tools[FTP_COMMAND_TOOL_NAME], command="quote port 1,2,3,4,5,6")
    assert "Illegal PORT command" in forced.artifact
    assert "fell back to ACTIVE-mode FTP" in forced.content

    # Confirms the session was actually marked for a passive-mode retry -
    # real internal state changed by the real detection, not just the
    # returned message text.
    current_session = manager.get_current_session(
        live_kali_session.target_id, live_kali_session.agent_run_id
    )
    assert current_session.ftp_passive is False
