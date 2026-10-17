"""Tool-factory unit tests for backend/src/core/agent/agent_tools.py.

Scope: the 6 tool factories build_agent_tools assembles directly -
create_kali_tool, create_pentest_tools, create_guided_session_tools,
create_vulnerability_tool, create_terminal_tools, create_file_tools - see
docs/testing-plan.md's "Agent / orchestration layer" bullet under §1.4 and
the matching sections of docs/testing-crawler-reports/agent-tools.md. The
pure helpers underneath them (_safe_shell_word, _parse_nmap_output, ...)
are covered by test_agent_tools_helpers.py, not here.

build_agent_tools itself and the build_*_agent_tools role gatherers are
out of scope: every factory below is called directly with hand-built
callbacks, never through build_agent_tools - that keeps roles/ (a
different, parallel task's scope) out of the import graph entirely.

Two fixtures provide the two kinds of fake "Kali" a factory needs:
- `kali_exec` - a real KaliManger whose container is fake_docker_client's
  own containers.run() return value, for every tool that goes through
  _execute_one_shot (Tier 1 pentest tools, ssh/telnet, file tools,
  create_kali_tool) - their shell commands are checked against this
  container's recorded exec_run calls.
- `fake_session_manager` - a hand-written stand-in for KaliManger's
  session surface (list_sessions/open_session/run_in_current_session/...),
  for ftp_connect/ftp_command and the terminal tools - these drive a real
  socket-backed KaliSession in production, which is kali_manager.py's own
  test scope, not agent_tools'.
"""

import asyncio
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cvss import CVSS4
from pydantic import ValidationError

from src.core.agent import agent_tools
from src.core.agent.agent_tools import (
    FTP_COMMAND_TOOL_NAME,
    FTP_CONNECT_TOOL_NAME,
    GOBUSTER_SCAN_TOOL_NAME,
    HYDRA_BRUTEFORCE_TOOL_NAME,
    KALI_COMMAND_TOOL_NAME,
    NEW_SESSION_TOOL_NAME,
    NMAP_SCAN_TOOL_NAME,
    RUN_TOOL_NAME,
    SWITCH_SESSION_TOOL_NAME,
    WRITE_LOCAL_FILE_TOOL_NAME,
    create_file_tools,
    create_guided_session_tools,
    create_kali_tool,
    create_pentest_tools,
    create_terminal_tools,
    create_vulnerability_tool,
)
from src.core.kali_integration.kali_manager import KaliManger
from src.core.kali_integration.kali_session import KaliSession, KaliSessionError
from src.schemas import Target


def _make_target(**overrides) -> Target:
    defaults = dict(
        name="test-target",
        project_id=uuid.uuid4(),
        ipv4="10.0.0.5",
        ipv6=None,
        description=None,
        ports=[21, 80],
        task_duration=None,
    )
    defaults.update(overrides)
    return Target(**defaults)


async def _invoke(tool, **args):
    return await tool.ainvoke(
        {"name": tool.name, "args": args, "id": "test-call", "type": "tool_call"}
    )


def _tools_by_name(tools) -> dict:
    return {t.name: t for t in tools}


@pytest.fixture
def kali_exec(fake_docker_client, monkeypatch):
    container = MagicMock()
    container.exec_run.return_value = SimpleNamespace(exit_code=0, output=b"")
    fake_docker_client.containers.run.return_value = container
    manager = KaliManger(container_name="test-kali", packages=())
    manager.container = fake_docker_client.containers.run.return_value

    async def _get_manager(project_id, on_stage=None):
        return manager

    monkeypatch.setattr(agent_tools.kali_registry, "get_manager", _get_manager)
    return container


@pytest.fixture
def patched_db_manager(monkeypatch, fake_db_manager):
    monkeypatch.setattr(agent_tools, "db_manager", fake_db_manager)
    return fake_db_manager


class FakeSessionManager:
    """See this module's own docstring for why ftp/terminal tools get a
    hand-written fake here instead of a real KaliManger+fake_docker_client -
    their actual I/O is a socket-backed session, not a docker exec call."""

    def __init__(self):
        self.sessions: dict[str, KaliSession] = {}
        self.current_name: str | None = None
        self.run_in_current_session_responses: list = []
        self.run_in_current_session_calls: list = []
        self.promote_return: str | None = None
        self.command_lock = asyncio.Lock()

    def has_current_session(self, target_id, agent_run_id):
        return self.current_name is not None

    async def open_session(self, target_id, agent_run_id, name, command):
        self.sessions[name] = KaliSession(
            name=name,
            command=command,
            target_id=target_id,
            agent_run_id=agent_run_id,
            exec_id="x",
            sock=None,
            user="momos",
        )
        self.current_name = name

    def get_current_session(self, target_id, agent_run_id):
        return self.sessions.get(self.current_name)

    def get_current_session_name(self, target_id, agent_run_id):
        return self.current_name

    async def run_in_current_session(self, target_id, agent_run_id, input, wait_seconds):
        self.run_in_current_session_calls.append((input, wait_seconds))
        outcome = self.run_in_current_session_responses.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    async def promote_stuck_session(self, target_id, agent_run_id, default_name, default_command):
        return self.promote_return

    async def list_sessions(self, target_id, agent_run_id):
        return [s for s in self.sessions.values() if not s.closed]

    async def switch_session(self, target_id, agent_run_id, name):
        session = self.sessions.get(name)
        if session is None or session.closed:
            raise KaliSessionError(f"No such session '{name}'.")
        self.current_name = name

    async def close_session(self, target_id, agent_run_id, name):
        session = self.sessions.get(name)
        if session is None or session.closed:
            return False
        session.closed = True
        if self.current_name == name:
            remaining = [n for n, s in self.sessions.items() if not s.closed]
            self.current_name = remaining[0] if remaining else None
        return True

    async def interrupt_session(self, target_id, agent_run_id):
        return self.run_in_current_session_responses.pop(0)


@pytest.fixture
def fake_session_manager(monkeypatch):
    manager = FakeSessionManager()

    async def _get_manager(project_id, on_stage=None):
        return manager

    monkeypatch.setattr(agent_tools.kali_registry, "get_manager", _get_manager)
    return manager


class TestCreateKaliTool:
    """Not wired into build_agent_tools (see the factory's own docstring -
    kept intact, commented out at its one call site), but still a real,
    independently reachable tool factory."""

    async def test_empty_output_short_circuits_before_any_parsing(self, kali_exec):
        on_enumeration = MagicMock()
        tool = create_kali_tool("proj1", on_enumeration)
        assert tool.name == KALI_COMMAND_TOOL_NAME

        result = await _invoke(tool, command="true")

        assert result.content == "(command produced no output)"
        on_enumeration.assert_not_called()
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"]
        assert cmd == ["/bin/bash", "-c", "timeout --kill-after=5 120 true"]

    async def test_missing_required_command_is_rejected_before_any_execution(self, kali_exec):
        tool = create_kali_tool("proj1", MagicMock())

        with pytest.raises(ValidationError):
            await _invoke(tool)

        kali_exec.exec_run.assert_not_called()


class TestCreatePentestTools:
    def _build(self, **callbacks):
        defaults = dict(
            on_enumeration=MagicMock(),
            mark_tested=MagicMock(),
            on_raw_output=MagicMock(),
        )
        defaults.update(callbacks)
        tools = create_pentest_tools(
            "proj1",
            "target1",
            defaults["on_enumeration"],
            defaults["mark_tested"],
            defaults["on_raw_output"],
        )
        return _tools_by_name(tools), defaults

    async def test_nmap_scan_builds_the_expected_command_and_parses_open_ports(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ports=[21, 80])
        kali_exec.exec_run.return_value = SimpleNamespace(
            exit_code=0, output=b"21/tcp open  ftp     vsftpd 2.3.4\n"
        )
        tools, cb = self._build()

        result = await _invoke(tools[NMAP_SCAN_TOOL_NAME], ports="21")

        assert "Found 1 open port(s): 21" in result.content
        assert result.artifact == "21/tcp open  ftp     vsftpd 2.3.4\n"
        cb["on_enumeration"].assert_called_once_with(
            {"21": {"service": "ftp", "version": "vsftpd 2.3.4", "notes": ""}}
        )
        cb["mark_tested"].assert_called_once()
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"]
        assert cmd == [
            "/bin/bash",
            "-c",
            "timeout --kill-after=5 240 nmap -Pn -sV -p 21 10.0.0.5",
        ]

    async def test_nmap_scan_refuses_an_out_of_scope_port_without_executing_anything(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ports=[21, 80])
        tools, cb = self._build()

        result = await _invoke(tools[NMAP_SCAN_TOOL_NAME], ports="22")

        assert "outside this target's authorized scope" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_hydra_bruteforce_missing_required_service_is_rejected(self, kali_exec):
        tools, _ = self._build()

        with pytest.raises(ValidationError):
            await _invoke(tools[HYDRA_BRUTEFORCE_TOOL_NAME])

        kali_exec.exec_run.assert_not_called()

    async def test_hydra_bruteforce_rejects_both_username_and_username_list_given(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target()
        tools, cb = self._build()

        result = await _invoke(
            tools[HYDRA_BRUTEFORCE_TOOL_NAME],
            service="ftp",
            username="anonymous",
            username_list="/x",
            password="",
        )

        assert "only one of `username`/`username_list`" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_gobuster_scan_rejects_malformed_extensions_without_ever_running_gobuster(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target()
        tools, cb = self._build()

        result = await _invoke(tools[GOBUSTER_SCAN_TOOL_NAME], extensions="php;id")

        assert "Invalid `extensions`" in result.content
        cb["mark_tested"].assert_not_called()
        assert all(
            "gobuster" not in call.kwargs["cmd"][-1]
            for call in kali_exec.exec_run.call_args_list
        )


class TestCreateGuidedSessionTools:
    def _build(self, **callbacks):
        defaults = dict(
            on_enumeration=MagicMock(),
            mark_tested=MagicMock(),
            on_session_change=MagicMock(),
            on_prompt_state_change=MagicMock(),
            on_raw_output=MagicMock(),
        )
        defaults.update(callbacks)
        tools = create_guided_session_tools(
            "proj1",
            "target1",
            "run1",
            defaults["on_enumeration"],
            defaults["mark_tested"],
            defaults["on_session_change"],
            defaults["on_prompt_state_change"],
            defaults["on_raw_output"],
        )
        return _tools_by_name(tools), defaults

    async def test_ftp_command_sends_an_allowed_command_to_the_already_open_session(
        self, fake_session_manager
    ):
        fake_session_manager.sessions["ftp"] = KaliSession(
            name="ftp",
            command="ftp -n 10.0.0.5",
            target_id="target1",
            agent_run_id="run1",
            exec_id="x",
            sock=None,
            user="momos",
        )
        fake_session_manager.current_name = "ftp"
        fake_session_manager.run_in_current_session_responses = ["226 Transfer complete"]
        tools, _ = self._build()

        result = await _invoke(tools[FTP_COMMAND_TOOL_NAME], command="ls")

        assert fake_session_manager.run_in_current_session_calls == [("ls", 20)]
        assert result.artifact == "226 Transfer complete"

    async def test_ftp_command_rejects_a_disallowed_command_before_touching_the_session(
        self, fake_session_manager
    ):
        tools, _ = self._build()

        result = await _invoke(tools[FTP_COMMAND_TOOL_NAME], command="user anonymous")

        assert "not an accepted ftp command" in result.content
        assert fake_session_manager.run_in_current_session_calls == []

    async def test_ftp_command_missing_required_argument_is_rejected(self, fake_session_manager):
        tools, _ = self._build()

        with pytest.raises(ValidationError):
            await _invoke(tools[FTP_COMMAND_TOOL_NAME])

    async def test_ftp_connect_rejects_a_newline_in_username_before_any_session_work(
        self, fake_session_manager
    ):
        tools, _ = self._build()

        result = await _invoke(tools[FTP_CONNECT_TOOL_NAME], username="a\nb")

        assert "cannot contain newlines" in result.content
        assert fake_session_manager.sessions == {}


class TestCreateTerminalTools:
    def _build(self, **callbacks):
        defaults = dict(
            on_enumeration=MagicMock(),
            mark_tested=MagicMock(),
            on_session_change=MagicMock(),
            on_prompt_state_change=MagicMock(),
            on_raw_output=MagicMock(),
        )
        defaults.update(callbacks)
        tools = create_terminal_tools(
            "proj1",
            "target1",
            "run1",
            defaults["on_enumeration"],
            defaults["mark_tested"],
            defaults["on_session_change"],
            defaults["on_prompt_state_change"],
            defaults["on_raw_output"],
        )
        return _tools_by_name(tools), defaults

    async def test_run_sends_input_to_the_current_session_and_marks_tested(
        self, fake_session_manager
    ):
        fake_session_manager.sessions["default"] = KaliSession(
            name="default",
            command="/bin/bash",
            target_id="target1",
            agent_run_id="run1",
            exec_id="x",
            sock=None,
            user="momos",
        )
        fake_session_manager.current_name = "default"
        fake_session_manager.run_in_current_session_responses = ["total 0"]
        tools, cb = self._build()

        result = await _invoke(tools[RUN_TOOL_NAME], input="ls -la")

        assert fake_session_manager.run_in_current_session_calls == [("ls -la", 8)]
        cb["mark_tested"].assert_called_once()
        assert result.artifact == "total 0"

    async def test_new_session_missing_required_name_is_rejected(self, fake_session_manager):
        tools, _ = self._build()

        with pytest.raises(ValidationError):
            await _invoke(tools[NEW_SESSION_TOOL_NAME])

        assert fake_session_manager.sessions == {}

    async def test_switch_session_to_a_missing_name_hints_list_sessions(
        self, fake_session_manager
    ):
        tools, _ = self._build()

        result = await _invoke(tools[SWITCH_SESSION_TOOL_NAME], name="nope")

        assert "list_sessions" in result.content


class TestCreateFileTools:
    async def test_write_local_file_writes_base64_encoded_content(self, kali_exec):
        tools = _tools_by_name(create_file_tools("proj1"))

        result = await _invoke(tools[WRITE_LOCAL_FILE_TOOL_NAME], content="hello", filename="x.txt")

        assert "Wrote 5 bytes to /tmp/momos-files/" in result.content
        assert result.content.rstrip().endswith("-x.txt")
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert "base64 -d" in cmd

    async def test_write_local_file_never_interpolates_content_raw_into_the_shell_command(
        self, kali_exec
    ):
        tools = _tools_by_name(create_file_tools("proj1"))
        payload = "$(touch /tmp/INJECTED)"

        await _invoke(tools[WRITE_LOCAL_FILE_TOOL_NAME], content=payload)

        cmd = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert payload not in cmd

    async def test_write_local_file_rejects_content_over_the_byte_limit(self, kali_exec):
        tools = _tools_by_name(create_file_tools("proj1"))
        oversized = "x" * (agent_tools.WRITE_LOCAL_FILE_MAX_BYTES + 1)

        result = await _invoke(tools[WRITE_LOCAL_FILE_TOOL_NAME], content=oversized)

        assert "over the" in result.content
        kali_exec.exec_run.assert_not_called()

    async def test_write_local_file_missing_required_content_is_rejected(self, kali_exec):
        tools = _tools_by_name(create_file_tools("proj1"))

        with pytest.raises(ValidationError):
            await _invoke(tools[WRITE_LOCAL_FILE_TOOL_NAME])

        kali_exec.exec_run.assert_not_called()


class TestCreateVulnerabilityTool:
    def _build(self, **overrides):
        defaults = dict(
            get_mode=lambda: "exploiting",
            has_tested=lambda: True,
            clear_tested=MagicMock(),
            on_reported=MagicMock(),
            get_last_raw_output=lambda: "230 Login successful.",
            get_model_name=lambda: "test-model",
        )
        defaults.update(overrides)
        tool = create_vulnerability_tool(
            "proj1",
            "target1",
            defaults["get_mode"],
            defaults["has_tested"],
            defaults["clear_tested"],
            defaults["on_reported"],
            defaults["get_last_raw_output"],
            defaults["get_model_name"],
        )
        return tool, defaults

    async def test_reports_a_vulnerability_with_the_score_derived_from_its_vector(
        self, patched_db_manager
    ):
        patched_db_manager.get_project_settings.return_value = SimpleNamespace(
            parsing_model_name=None
        )
        saved_holder = {}

        def _capture(vulnerability):
            saved_holder["vuln"] = vulnerability
            return vulnerability

        patched_db_manager.add_vulnerability.side_effect = _capture
        tool, cb = self._build()

        result = await _invoke(
            tool,
            name="Anonymous FTP",
            proof_of_concept="ftp login as anonymous",
            cvss4_vector=agent_tools.CVSS4_EXAMPLE_VECTOR,
        )

        expected_score = CVSS4(agent_tools.CVSS4_EXAMPLE_VECTOR).base_score
        assert "Recorded vulnerability 'Anonymous FTP'" in result.content
        assert f"CVSS v4.0 score: {expected_score}" in result.content
        assert saved_holder["vuln"].cvss4_score == expected_score
        cb["clear_tested"].assert_called_once()
        cb["on_reported"].assert_called_once_with(saved_holder["vuln"])

    async def test_gate_rejects_a_claim_made_outside_exploiting_mode(self, patched_db_manager):
        tool, cb = self._build(get_mode=lambda: "scouting")

        result = await _invoke(
            tool,
            name="x",
            proof_of_concept="y",
            cvss4_vector=agent_tools.CVSS4_EXAMPLE_VECTOR,
        )

        assert "Not in exploiting mode" in result.content
        cb["on_reported"].assert_not_called()
        patched_db_manager.add_vulnerability.assert_not_called()

    async def test_invalid_cvss4_vector_is_rejected_with_the_metric_reference(
        self, patched_db_manager
    ):
        tool, cb = self._build()

        result = await _invoke(
            tool,
            name="x",
            proof_of_concept="y",
            cvss4_vector="CVSS:3.1/S:U/C:H/I:H/A:H",
        )

        assert agent_tools.CVSS4_METRIC_REFERENCE in result.content
        cb["on_reported"].assert_not_called()

    async def test_missing_required_name_is_rejected_before_the_gate_even_runs(
        self, patched_db_manager
    ):
        tool, _ = self._build(
            get_mode=MagicMock(side_effect=AssertionError("gate should not run yet"))
        )

        with pytest.raises(ValidationError):
            await _invoke(
                tool, proof_of_concept="y", cvss4_vector=agent_tools.CVSS4_EXAMPLE_VECTOR
            )
