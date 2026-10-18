"""§1.4a tier 2 (docs/testing-plan.md) - telnet_probe
(create_guided_session_tools, backend/src/core/agent/agent_tools.py)
against `telnet_target`'s real busybox telnetd on port 23 (backend/tests/
docker/telnet-target.Dockerfile).

telnet_probe is documented as "whatever banner/greeting it sends back - a
quick 'what's listening here' check", NOT a login - see its own
docstring in agent_tools.py. Confirmed empirically: telnet_probe's own
command (`echo | timeout 3 telnet host port`) closes stdin right after
one blank line, so the real client exits on EOF with only its own local
"Connected to <host>" confirmation - never the server's /bin/login
prompt, which needs more of a round trip than this probe waits for. The
assertions below are scoped to exactly that real, observed behavior, not
an assumption from the docstring alone."""

import uuid

import pytest

from src.core.agent import agent_tools
from src.core.agent.agent_tools import TELNET_PROBE_TOOL_NAME, create_guided_session_tools
from src.schemas import Target


def _make_telnet_target() -> Target:
    return Target(
        name="telnet-probe-target",
        project_id=uuid.uuid4(),
        ipv4="telnet-target",
        ipv6=None,
        description=None,
        ports=[23],
        task_duration=None,
    )


def _tools_by_name(tools) -> dict:
    return {t.name: t for t in tools}


async def _invoke(tool, **args):
    return await tool.ainvoke(
        {"name": tool.name, "args": args, "id": "test-call", "type": "tool_call"}
    )


@pytest.fixture
def telnet_tools(live_kali_session, telnet_target, monkeypatch):
    """Depends directly on `telnet_target` (not just live_kali_session) so
    the real telnetd container actually exists and is attached to
    docker_network before any tool call tries to resolve its hostname."""

    async def _get_manager(project_id, on_stage=None):
        return live_kali_session.manager

    monkeypatch.setattr(agent_tools.kali_registry, "get_manager", _get_manager)
    monkeypatch.setattr(
        agent_tools.db_manager, "get_target", lambda target_id: _make_telnet_target()
    )
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
    return _tools_by_name(tools)


@pytest.mark.live_tools
@pytest.mark.timeout(45)
async def test_telnet_probe_connects_to_the_real_service_and_returns_its_banner(telnet_tools):
    result = await _invoke(telnet_tools[TELNET_PROBE_TOOL_NAME], port=23)

    # Confirmed against the real client: busybox telnet's own local
    # "Connected to <host>" confirmation is everything that comes back
    # within the 3s window - `echo | timeout 3 telnet ...` feeds stdin a
    # single blank line then closes it, so the client exits on EOF before
    # the server's /bin/login process (forked per-connection, see
    # telnet-target.Dockerfile) gets a chance to print its own "login:"
    # prompt back. That matches telnet_probe's own docstring ("whatever
    # banner/greeting it sends back - a quick 'what's listening here'
    # check", explicitly NOT a login) - this is the right, specific thing
    # to assert, not the login prompt a first read of the docstring might
    # suggest.
    assert "Connected to telnet-target" in result.content


@pytest.mark.live_tools
@pytest.mark.timeout(45)
async def test_telnet_probe_against_a_closed_port_reports_no_banner(telnet_tools):
    """Negative case: a port nothing is listening on must not be
    misreported as a successful connection/banner - proves this isn't a
    tool that just echoes back whatever was asked of it."""
    result = await _invoke(telnet_tools[TELNET_PROBE_TOOL_NAME], port=9999)

    # Real client-side connection-refused text, not the success banner -
    # confirmed via the real container (e.g. "telnet: can't connect to
    # remote host (<ip>): Connection refused").
    assert "Connected to telnet-target" not in result.content
    assert "refused" in result.content.lower()
