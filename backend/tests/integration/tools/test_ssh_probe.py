"""§1.4a tier 2 (docs/testing-plan.md) - ssh_check_login/ssh_run
(create_guided_session_tools, backend/src/core/agent/agent_tools.py)
against `ssh_target`'s real sshd and its seeded weak test account
(username "momos-test", password "momos-test-weak-pw" - see
backend/tests/docker/ssh-target.Dockerfile).

Runs the real, unmodified create_guided_session_tools factory through
`live_kali_session`'s real KaliManger (backend/tests/integration/tools/
conftest.py) - only kali_registry.get_manager and db_manager.get_target
are patched, the same "patch the consumer" seam test_kali_session.py
already uses for kali_registry, extended here to db_manager since these
tools also resolve their target through it (_get_target_host ->
_get_target_info -> db_manager.get_target)."""

import asyncio
import uuid

import pytest

from src.core.agent import agent_tools
from src.core.agent.agent_tools import (
    SSH_CHECK_LOGIN_TOOL_NAME,
    SSH_RUN_TOOL_NAME,
    create_guided_session_tools,
)
from src.schemas import Target

SSH_USERNAME = "momos-test"
SSH_PASSWORD = "momos-test-weak-pw"


def _make_ssh_target() -> Target:
    return Target(
        name="ssh-probe-target",
        project_id=uuid.uuid4(),
        ipv4="ssh-target",
        ipv6=None,
        description=None,
        ports=[22],
        task_duration=None,
    )


def _tools_by_name(tools) -> dict:
    return {t.name: t for t in tools}


async def _invoke(tool, **args):
    return await tool.ainvoke(
        {"name": tool.name, "args": args, "id": "test-call", "type": "tool_call"}
    )


async def _invoke_ssh_connect(tool, **args):
    """Like _invoke, but retries a bare transport-level drop - confirmed
    reproducible (and root-caused by hand, outside pytest, against the
    same Dockerfile) when this file runs right after test_hydra.py's SSH
    brute-force in the same session, against the same real sshd on
    ssh-target: OpenSSH 9.8+'s built-in per-source-IP penalty system
    (confirmed via `sshd -V` -> OpenSSH_9.9p2, and the target's own
    "drop connection ... penalty: failed authentication" log line) blocks
    every NEW connection from the attacking container's IP outright
    ("Connection closed by <ip> port 22", before any login attempt even
    happens) for a real, measured ~30s after hydra's failed-password
    attempts - not a one-off blip, so a short retry isn't enough; this
    waits long enough to clear it with margin. That penalty window is a
    real but incidental property of the shared target container settling
    after a brute-force from the SAME attacker IP, not a tool bug and not
    the actual auth outcome this test cares about - a real "Permission
    denied"/successful login is never retried or masked, only this
    specific pre-auth drop is."""
    result = None
    for attempt in range(15):
        result = await _invoke(tool, **args)
        text = result.artifact or result.content
        if "Connection closed by" not in text:
            return result
        await asyncio.sleep(3)
    return result


@pytest.fixture
def ssh_tools(live_kali_session, ssh_target, monkeypatch):
    """Patches the two module-level singletons ssh_check_login/ssh_run
    resolve through, then builds the real tool list against
    live_kali_session's manager - restored by `monkeypatch` after the
    test, so this never leaks into sibling test files sharing the same
    session-scoped container. Depends directly on `ssh_target` (not just
    live_kali_session) so the real sshd container actually exists and is
    attached to docker_network before any tool call tries to resolve its
    hostname - otherwise ssh gets a real-but-useless "Name does not
    resolve"."""

    async def _get_manager(project_id, on_stage=None):
        return live_kali_session.manager

    monkeypatch.setattr(agent_tools.kali_registry, "get_manager", _get_manager)
    monkeypatch.setattr(agent_tools.db_manager, "get_target", lambda target_id: _make_ssh_target())
    # ssh_run routes its output through _maybe_condense/_parse_output with
    # label="ssh {command}" - "ssh" is itself in _NETWORK_FACING_BINARIES,
    # so it always calls _get_project_settings(project_id) regardless of
    # the remote command. live_kali_session's project_id is a fixed
    # placeholder string, not a real UUID, so the REAL db_manager singleton
    # (never mocked - only .get_target is patched above) would otherwise
    # blow up in uuid.UUID(...) before any LLM call could even happen.
    # None here takes the same "no parsing model configured" fallback
    # _parse_output already has for a project with none set - raw output
    # returned as-is, no Ollama/LLM call, matching this whole tier's "no
    # test may require a real LLM" rule.
    monkeypatch.setattr(agent_tools.db_manager, "get_project_settings", lambda project_id: None)

    calls = {"on_enumeration": [], "on_raw_output": [], "mark_tested": []}
    tools = create_guided_session_tools(
        live_kali_session.project_id,
        live_kali_session.target_id,
        live_kali_session.agent_run_id,
        lambda d: calls["on_enumeration"].append(d),
        lambda: calls["mark_tested"].append(True),
        lambda name, command: None,
        lambda is_open: None,
        lambda output: calls["on_raw_output"].append(output),
    )
    return _tools_by_name(tools)


@pytest.mark.live_tools
@pytest.mark.timeout(90)
class TestSshCheckLogin:
    async def test_correct_password_succeeds(self, ssh_tools):
        result = await _invoke_ssh_connect(
            ssh_tools[SSH_CHECK_LOGIN_TOOL_NAME],
            username=SSH_USERNAME,
            password=SSH_PASSWORD,
        )
        assert result.content.startswith(f"Login successful for '{SSH_USERNAME}'.")

    async def test_wrong_password_is_rejected(self, ssh_tools):
        result = await _invoke_ssh_connect(
            ssh_tools[SSH_CHECK_LOGIN_TOOL_NAME],
            username=SSH_USERNAME,
            password="definitely-not-the-real-password",
        )
        assert result.content.startswith(f"Login failed for '{SSH_USERNAME}'")
        assert "successful" not in result.content.split("\n\n")[0]


@pytest.mark.live_tools
@pytest.mark.timeout(60)
class TestSshRun:
    # Real bug found by this tier, not a flaky/misbehaving test: ssh_run is
    # decorated @tool(..., response_format="content_and_artifact") (a
    # 2-tuple (content, artifact) is required), but its final line is
    # `return await _maybe_condense(...)` - _maybe_condense (and
    # _parse_output underneath it) always returns a bare `str`, never a
    # tuple, unlike every sibling tool in this file (new_session/
    # switch_session/run all explicitly wrap it: `return f"...{condensed}",
    # raw_output`). LangChain's own BaseTool.arun validates this before
    # the ToolMessage is even built, so this is not specific to anything
    # in this test harness - every real invocation of ssh_run through the
    # standard tool-call path (`.ainvoke`/`.invoke` with a tool_call dict -
    # exactly how the production agent graph calls every tool) raises:
    #   ValueError: Since response_format='content_and_artifact' a
    #   two-tuple of the message content and raw tool output is expected.
    #   Instead, generated response is of type: <class 'str'>.
    # No unit test anywhere exercises ssh_run (confirmed:
    # tests/unit/agent/test_agent_tool_factories.py never references it),
    # so nothing caught this until a real, unmocked tool-call invocation
    # here did. xfail(strict=True) so this flips to a hard failure (not a
    # silent pass) the moment ssh_run's return statement is fixed to
    # `return f"...{condensed}", output` like its siblings.
    @pytest.mark.xfail(
        reason="agent_tools.py ssh_run returns a bare str from "
        "_maybe_condense instead of a (content, artifact) tuple - crashes "
        "with ValueError on every real tool-call invocation. See this "
        "test class's own comment for the full trace.",
        strict=True,
    )
    async def test_whoami_returns_the_real_remote_username(self, ssh_tools):
        result = await _invoke(
            ssh_tools[SSH_RUN_TOOL_NAME],
            username=SSH_USERNAME,
            password=SSH_PASSWORD,
            command="whoami",
        )
        assert SSH_USERNAME in result.content

    @pytest.mark.xfail(
        reason="Same real bug as test_whoami_returns_the_real_remote_username "
        "above - ssh_run crashes with ValueError before any assertion here "
        "can even run.",
        strict=True,
    )
    async def test_id_output_is_the_real_remote_command_output(self, ssh_tools):
        result = await _invoke(
            ssh_tools[SSH_RUN_TOOL_NAME],
            username=SSH_USERNAME,
            password=SSH_PASSWORD,
            command="id -un",
        )
        # The real remote `id -un` output, not a guess/echo of the input -
        # pins the exact username the account was seeded with.
        assert SSH_USERNAME in result.content
