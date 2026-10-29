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
import inspect
import shlex
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cvss import CVSS4
from pydantic import ValidationError

from src.core.agent import agent_tools
from src.core.agent.agent_tools import (
    DNS_RECON_TOOL_NAME,
    CRACK_HASHES_TOOL_NAME,
    COMMIX_RUN_TOOL_NAME,
    DOWNLOAD_FILE_TOOL_NAME,
    FTP_COMMAND_TOOL_NAME,
    FTP_CONNECT_TOOL_NAME,
    GOBUSTER_SCAN_TOOL_NAME,
    HYDRA_BRUTEFORCE_TOOL_NAME,
    IMPACKET_EXEC_TOOL_NAME,
    IMPACKET_KERBEROAST_TOOL_NAME,
    KALI_COMMAND_TOOL_NAME,
    MYSQL_CONNECT_TOOL_NAME,
    MYSQL_QUERY_TOOL_NAME,
    NETEXEC_RUN_TOOL_NAME,
    NEW_SESSION_TOOL_NAME,
    NIKTO_SCAN_TOOL_NAME,
    NMAP_SCAN_TOOL_NAME,
    PACKET_CAPTURE_TOOL_NAME,
    RESPONDER_READ_TOOL_NAME,
    RESPONDER_START_TOOL_NAME,
    RESPONDER_STOP_TOOL_NAME,
    RUN_PYTHON_SCRIPT_TOOL_NAME,
    RUN_TOOL_NAME,
    SMB_ENUM_TOOL_NAME,
    SNMP_ENUM_TOOL_NAME,
    SQLMAP_RUN_TOOL_NAME,
    SSH_RUN_TOOL_NAME,
    SWITCH_SESSION_TOOL_NAME,
    TESTSSL_SCAN_TOOL_NAME,
    WHATWEB_SCAN_TOOL_NAME,
    WPSCAN_ENUM_TOOL_NAME,
    LOCAL_FILES_DIR,
    WRITE_LOCAL_FILE_TOOL_NAME,
    create_file_tools,
    create_guided_session_tools,
    create_kali_tool,
    build_agent_tools,
    build_pentesting_agent_tools,
    build_scouting_agent_tools,
    create_pentest_tools,
    create_scripting_tools,
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

        assert "Found 1 open port(s): 21/tcp" in result.content
        assert result.artifact == "21/tcp open  ftp     vsftpd 2.3.4\n"
        # Keyed by "port/protocol", not bare port number (finding 4) - "21"
        # alone would collide a tcp and udp result on the same port number.
        cb["on_enumeration"].assert_called_once_with(
            {"21/tcp": {"service": "ftp", "version": "vsftpd 2.3.4", "notes": ""}}
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

    async def test_gobuster_scan_reports_its_findings_even_when_gobuster_itself_exits_nonzero(
        self, kali_exec, patched_db_manager
    ):
        """Real gobuster can exit non-zero (e.g. it tripped its own error
        threshold against a flaky target) after already producing a fully
        valid, parseable scan - CI caught this: a live run found every
        seeded path but still came back with `artifact=None` because that
        exit code was mistaken for an _execute_one_shot/docker-exec
        failure. gobuster's own verdict on a completed scan isn't that
        (same reasoning as ssh_run_command's `; true`, see its comment)."""
        patched_db_manager.get_target.return_value = _make_target()
        gobuster_output = "\r\x1b[2K/admin (Status: 301) [Size: 169]\n"
        kali_exec.exec_run.side_effect = [
            SimpleNamespace(exit_code=0, output=b""),  # wordlist existence check
            SimpleNamespace(exit_code=1, output=gobuster_output.encode()),
        ]
        tools, cb = self._build()

        result = await _invoke(
            tools[GOBUSTER_SCAN_TOOL_NAME], wordlist="/tmp/wordlist.txt"
        )

        assert result.artifact is not None
        assert "/admin" in result.artifact
        cb["mark_tested"].assert_called_once()

    async def test_nikto_scan_builds_the_expected_command(self, kali_exec, patched_db_manager):
        patched_db_manager.get_target.return_value = _make_target(ports=[80])
        nikto_output = "+ Server leaks inodes via ETags\n"
        kali_exec.exec_run.return_value = SimpleNamespace(
            exit_code=0, output=nikto_output.encode()
        )
        tools, cb = self._build()

        result = await _invoke(tools[NIKTO_SCAN_TOOL_NAME], port=80)

        assert result.content == nikto_output
        assert result.artifact == nikto_output
        cb["mark_tested"].assert_called_once()
        cb["on_raw_output"].assert_called_once_with(nikto_output)
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"]
        assert cmd == [
            "/bin/bash",
            "-c",
            "timeout --kill-after=5 300 nikto -h 10.0.0.5 -p 80",
        ]

    async def test_nikto_scan_refuses_an_out_of_scope_port_without_executing_anything(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ports=[21, 80])
        tools, cb = self._build()

        result = await _invoke(tools[NIKTO_SCAN_TOOL_NAME], port=8080)

        assert "outside this target's authorized scope" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_whatweb_scan_builds_the_expected_command_and_populates_enumeration(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ports=[80])
        whatweb_output = "http://10.0.0.5 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ]\n"
        kali_exec.exec_run.return_value = SimpleNamespace(
            exit_code=0, output=whatweb_output.encode()
        )
        tools, cb = self._build()

        result = await _invoke(tools[WHATWEB_SCAN_TOOL_NAME], port=80)

        assert result.content == whatweb_output
        assert result.artifact == whatweb_output
        cb["mark_tested"].assert_called_once()
        cb["on_raw_output"].assert_called_once_with(whatweb_output)
        cb["on_enumeration"].assert_called_once_with(
            {"80": {"service": "http", "version": "", "notes": "Apache[2.4.41]; Country[RESERVED]"}}
        )
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"]
        assert cmd == [
            "/bin/bash",
            "-c",
            "timeout --kill-after=5 60 whatweb http://10.0.0.5:80/",
        ]

    async def test_whatweb_scan_refuses_an_out_of_scope_port_without_executing_anything(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ports=[21, 80])
        tools, cb = self._build()

        result = await _invoke(tools[WHATWEB_SCAN_TOOL_NAME], port=8080)

        assert "outside this target's authorized scope" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()
        cb["on_enumeration"].assert_not_called()

    async def test_smb_enum_builds_the_expected_command(self, kali_exec, patched_db_manager):
        patched_db_manager.get_target.return_value = _make_target(ports=[445])
        smb_output = "\tSharename       Type      Comment\n\tpublic          Disk\n"
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=0, output=smb_output.encode())
        tools, cb = self._build()

        result = await _invoke(tools[SMB_ENUM_TOOL_NAME], port=445)

        assert result.content == smb_output
        assert result.artifact == smb_output
        cb["mark_tested"].assert_called_once()
        cb["on_raw_output"].assert_called_once_with(smb_output)
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"]
        assert cmd == [
            "/bin/bash",
            "-c",
            "timeout --kill-after=5 30 smbclient -L //10.0.0.5 -N -p 445",
        ]

    async def test_smb_enum_refuses_an_out_of_scope_port_without_executing_anything(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ports=[21, 80])
        tools, cb = self._build()

        result = await _invoke(tools[SMB_ENUM_TOOL_NAME], port=445)

        assert "outside this target's authorized scope" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_snmp_enum_builds_the_expected_command(self, kali_exec, patched_db_manager):
        patched_db_manager.get_target.return_value = _make_target(ports=[161])
        snmp_output = "SNMPv2-MIB::sysDescr.0 = STRING: Linux target\n"
        kali_exec.exec_run.return_value = SimpleNamespace(
            exit_code=0, output=snmp_output.encode()
        )
        tools, cb = self._build()

        result = await _invoke(tools[SNMP_ENUM_TOOL_NAME], community="public", port=161)

        assert result.content == snmp_output
        assert result.artifact == snmp_output
        cb["mark_tested"].assert_called_once()
        cb["on_raw_output"].assert_called_once_with(snmp_output)
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"]
        assert cmd == [
            "/bin/bash",
            "-c",
            "timeout --kill-after=5 60 snmpwalk -v2c -c public 10.0.0.5:161",
        ]

    async def test_snmp_enum_refuses_an_out_of_scope_port_without_executing_anything(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ports=[21, 80])
        tools, cb = self._build()

        result = await _invoke(tools[SNMP_ENUM_TOOL_NAME], port=162)

        assert "outside this target's authorized scope" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_sqlmap_run_builds_the_expected_command(self, kali_exec, patched_db_manager):
        patched_db_manager.get_target.return_value = _make_target(ports=[80])
        sqlmap_output = "sqlmap identified the following injection point(s)\n"
        kali_exec.exec_run.return_value = SimpleNamespace(
            exit_code=0, output=sqlmap_output.encode()
        )
        tools, cb = self._build()

        result = await _invoke(tools[SQLMAP_RUN_TOOL_NAME], path="/login.php", port=80)

        assert result.content == sqlmap_output
        assert result.artifact == sqlmap_output
        cb["mark_tested"].assert_called_once()
        cb["on_raw_output"].assert_called_once_with(sqlmap_output)
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"]
        assert cmd == [
            "/bin/bash",
            "-c",
            "timeout --kill-after=5 300 sqlmap --batch -u http://10.0.0.5:80/login.php",
        ]

    async def test_sqlmap_run_refuses_an_out_of_scope_port_without_executing_anything(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ports=[21, 80])
        tools, cb = self._build()

        result = await _invoke(tools[SQLMAP_RUN_TOOL_NAME], path="/x", port=443)

        assert "outside this target's authorized scope" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_sqlmap_run_includes_param_and_data_flags_when_given(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ports=[80])
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=0, output=b"sqlmap output\n")
        tools, cb = self._build()

        await _invoke(
            tools[SQLMAP_RUN_TOOL_NAME],
            path="/login.php",
            port=80,
            param="id",
            data="username=admin&password=test",
        )

        cmd = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert "-p id" in cmd
        assert "--data 'username=admin&password=test'" in cmd

    async def test_sqlmap_run_never_sends_a_caller_supplied_host_only_this_targets_own_host(
        self, kali_exec, patched_db_manager
    ):
        """Even a `path` that looks like a full URL pointing at a
        different host must only ever contribute its own path component -
        the URL sqlmap actually receives always targets this run's own
        target host, never anything the caller embeds in `path`. Verified
        by temporarily making the URL construction naive/free-form (e.g.
        f"{scheme}://{host}:{port}/{path}") - that change makes this test
        go red, since the naive URL would still embed "evil.example.com"
        and would not equal the expected same-host URL (CLAUDE.md 2.1)."""
        patched_db_manager.get_target.return_value = _make_target(ports=[80])
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=0, output=b"sqlmap output\n")
        tools, cb = self._build()

        await _invoke(tools[SQLMAP_RUN_TOOL_NAME], path="http://evil.example.com/x", port=80)

        command = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert "evil.example.com" not in command
        assert "http://10.0.0.5:80/x" in command

    async def test_testssl_scan_builds_the_expected_command(self, kali_exec, patched_db_manager):
        patched_db_manager.get_target.return_value = _make_target(ports=[443])
        testssl_output = "Testing server preferences\n"
        kali_exec.exec_run.return_value = SimpleNamespace(
            exit_code=0, output=testssl_output.encode()
        )
        tools, cb = self._build()

        result = await _invoke(tools[TESTSSL_SCAN_TOOL_NAME], port=443)

        assert result.content == testssl_output
        assert result.artifact == testssl_output
        cb["mark_tested"].assert_called_once()
        cb["on_raw_output"].assert_called_once_with(testssl_output)
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"]
        assert cmd == [
            "/bin/bash",
            "-c",
            "timeout --kill-after=5 240 testssl --warnings off 10.0.0.5:443",
        ]

    async def test_testssl_scan_includes_the_starttls_flag_when_given(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ports=None)
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=0, output=b"ok\n")
        tools, cb = self._build()

        await _invoke(tools[TESTSSL_SCAN_TOOL_NAME], port=25, starttls="smtp")

        cmd = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert "--starttls smtp" in cmd
        assert "10.0.0.5:25" in cmd

    async def test_testssl_scan_rejects_an_invalid_starttls_value_without_executing_anything(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ports=None)
        tools, cb = self._build()

        result = await _invoke(tools[TESTSSL_SCAN_TOOL_NAME], starttls="smtp;id")

        assert "Invalid `starttls`" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_testssl_scan_refuses_an_out_of_scope_port_without_executing_anything(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ports=[21, 80])
        tools, cb = self._build()

        result = await _invoke(tools[TESTSSL_SCAN_TOOL_NAME], port=443)

        assert "outside this target's authorized scope" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_wpscan_enum_builds_the_expected_command(self, kali_exec, patched_db_manager):
        patched_db_manager.get_target.return_value = _make_target(ports=[80])
        wpscan_output = "[+] WordPress version 6.1 identified\n"
        kali_exec.exec_run.return_value = SimpleNamespace(
            exit_code=0, output=wpscan_output.encode()
        )
        tools, cb = self._build()

        result = await _invoke(tools[WPSCAN_ENUM_TOOL_NAME])

        assert result.content == wpscan_output
        assert result.artifact == wpscan_output
        cb["mark_tested"].assert_called_once()
        cb["on_raw_output"].assert_called_once_with(wpscan_output)
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"]
        assert cmd == [
            "/bin/bash",
            "-c",
            "timeout --kill-after=5 180 wpscan --url http://10.0.0.5:80/ "
            "--enumerate vp,vt,u --no-update",
        ]

    async def test_wpscan_enum_never_sends_a_caller_supplied_host_only_this_targets_own_host(
        self, kali_exec, patched_db_manager
    ):
        """Mirrors test_sqlmap_run_never_sends_a_caller_supplied_host_...
        above - verified by temporarily making the URL construction naive/
        free-form; that change makes this test go red since the naive URL
        would still embed "evil.example.com" (CLAUDE.md 2.1)."""
        patched_db_manager.get_target.return_value = _make_target(ports=[80])
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=0, output=b"ok\n")
        tools, cb = self._build()

        await _invoke(tools[WPSCAN_ENUM_TOOL_NAME], path="http://evil.example.com/wp")

        command = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert "evil.example.com" not in command
        assert "http://10.0.0.5:80/wp" in command

    async def test_wpscan_enum_refuses_an_out_of_scope_port_without_executing_anything(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ports=[21, 80])
        tools, cb = self._build()

        result = await _invoke(tools[WPSCAN_ENUM_TOOL_NAME], port=443)

        assert "outside this target's authorized scope" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_dns_recon_omitted_nameserver_resolves_to_this_runs_own_target(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ipv4="10.0.0.5")
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=0, output=b"std results\n")
        tools, cb = self._build()

        result = await _invoke(tools[DNS_RECON_TOOL_NAME], domain="example.com")

        assert result.content == "std results\n"
        cb["mark_tested"].assert_called_once()
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"]
        assert cmd == [
            "/bin/bash",
            "-c",
            "timeout --kill-after=5 120 dnsrecon -d example.com -n 10.0.0.5 -t std",
        ]

    async def test_dns_recon_axfr_mode_passes_the_axfr_flag_to_dnsrecon(
        self, kali_exec, patched_db_manager
    ):
        """Verified by breaking it: temporarily hardcoding `-t std`
        regardless of `mode` makes this test go red (CLAUDE.md 2.1)."""
        patched_db_manager.get_target.return_value = _make_target(ipv4="10.0.0.5")
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=0, output=b"axfr results\n")
        tools, cb = self._build()

        await _invoke(
            tools[DNS_RECON_TOOL_NAME],
            domain="example.com",
            nameserver="ns1.example.com",
            mode="axfr",
        )

        cmd = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert "-t axfr" in cmd
        assert "-n ns1.example.com" in cmd

    async def test_dns_recon_rejects_an_invalid_mode_outright(self, kali_exec):
        tools, _ = self._build()

        with pytest.raises(ValidationError):
            await _invoke(tools[DNS_RECON_TOOL_NAME], domain="example.com", mode="brute")

        kali_exec.exec_run.assert_not_called()

    async def test_dns_recon_rejects_an_invalid_domain_without_executing_anything(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ipv4="10.0.0.5")
        tools, cb = self._build()

        result = await _invoke(tools[DNS_RECON_TOOL_NAME], domain="example.com; id")

        assert "Invalid `domain`" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_packet_capture_builds_the_expected_command(self, kali_exec, patched_db_manager):
        patched_db_manager.get_target.return_value = _make_target(ipv4="10.0.0.5")
        capture_output = "5 packets captured\n"
        kali_exec.exec_run.return_value = SimpleNamespace(
            exit_code=0, output=capture_output.encode()
        )
        tools, cb = self._build()

        result = await _invoke(tools[PACKET_CAPTURE_TOOL_NAME], duration_seconds=10)

        assert result.content == capture_output
        cb["mark_tested"].assert_called_once()
        cb["on_raw_output"].assert_called_once_with(capture_output)
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"]
        assert cmd == [
            "/bin/bash",
            "-c",
            "timeout --kill-after=5 25 timeout 10 tshark -i any -f 'host 10.0.0.5' "
            "-a duration:10",
        ]

    async def test_packet_capture_includes_max_packets_flag_when_given(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ipv4="10.0.0.5")
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=0, output=b"ok\n")
        tools, cb = self._build()

        await _invoke(tools[PACKET_CAPTURE_TOOL_NAME], duration_seconds=10, max_packets=50)

        cmd = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert "-c 50" in cmd

    async def test_packet_capture_filter_always_pins_the_target_host_regardless_of_input(
        self, kali_exec, patched_db_manager
    ):
        """The one property that keeps a capture inside the authorized
        scope: the BPF filter sent to tshark is always "host <target ip>",
        never anything caller-influenced. Verified by breaking it:
        temporarily building the filter from an extra free-form argument
        (or dropping the host entirely) makes this test go red (CLAUDE.md
        2.1) - there is no argument on this tool that should be able to
        change the filter at all."""
        patched_db_manager.get_target.return_value = _make_target(ipv4="10.0.0.5")
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=0, output=b"ok\n")
        tools, cb = self._build()

        await _invoke(tools[PACKET_CAPTURE_TOOL_NAME], duration_seconds=5, max_packets=1)

        cmd = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert "host 10.0.0.5" in cmd

    async def test_packet_capture_rejects_a_duration_above_the_cap_without_executing_anything(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ipv4="10.0.0.5")
        tools, cb = self._build()

        result = await _invoke(tools[PACKET_CAPTURE_TOOL_NAME], duration_seconds=121)

        assert "must be at most" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_netexec_run_builds_the_expected_command_with_password(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target()
        nxc_output = "SMB  10.0.0.5  445  HOST  [+] domain\\user:pass\n"
        kali_exec.exec_run.return_value = SimpleNamespace(
            exit_code=0, output=nxc_output.encode()
        )
        tools, cb = self._build()

        result = await _invoke(
            tools[NETEXEC_RUN_TOOL_NAME],
            protocol="smb",
            username="user",
            password="pass",
        )

        assert result.content == nxc_output
        assert result.artifact == nxc_output
        cb["mark_tested"].assert_called_once()
        cb["on_raw_output"].assert_called_once_with(nxc_output)
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"]
        assert cmd == [
            "/bin/bash",
            "-c",
            "timeout --kill-after=5 180 nxc smb 10.0.0.5 -u user -p pass",
        ]

    async def test_netexec_run_uses_hash_flag_and_includes_command_when_given(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target()
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=0, output=b"ok\n")
        tools, cb = self._build()

        await _invoke(
            tools[NETEXEC_RUN_TOOL_NAME],
            protocol="winrm",
            username="user",
            ntlm_hash="aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
            command="whoami",
        )

        cmd = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert "nxc winrm 10.0.0.5 -u user" in cmd
        assert "-H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c" in cmd
        assert "-x whoami" in cmd

    async def test_netexec_run_rejects_both_password_and_hash_given(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target()
        tools, cb = self._build()

        result = await _invoke(
            tools[NETEXEC_RUN_TOOL_NAME],
            protocol="smb",
            username="user",
            password="pass",
            ntlm_hash="8846f7eaee8fb117ad06bdd830b7586c",
        )

        assert "exactly one of" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_netexec_run_rejects_neither_password_nor_hash_given(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target()
        tools, cb = self._build()

        result = await _invoke(
            tools[NETEXEC_RUN_TOOL_NAME], protocol="smb", username="user"
        )

        assert "exactly one of" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_netexec_run_rejects_an_unknown_protocol_outright(self, kali_exec):
        tools, _ = self._build()

        with pytest.raises(ValidationError):
            await _invoke(
                tools[NETEXEC_RUN_TOOL_NAME],
                protocol="rdp",
                username="user",
                password="pass",
            )

        kali_exec.exec_run.assert_not_called()

    async def test_impacket_kerberoast_builds_the_expected_command(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target()
        spn_output = "$krb5tgs$23$*user$DOMAIN$...\n"
        kali_exec.exec_run.return_value = SimpleNamespace(
            exit_code=0, output=spn_output.encode()
        )
        tools, cb = self._build()

        result = await _invoke(
            tools[IMPACKET_KERBEROAST_TOOL_NAME],
            username="svc_user",
            password="svc_pass",
            domain="example.com",
        )

        assert result.content == spn_output
        assert result.artifact == spn_output
        cb["mark_tested"].assert_called_once()
        cb["on_raw_output"].assert_called_once_with(spn_output)
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        # GetUserSPNs' positional target is "domain[/username[:password]]" -
        # it has no "@host" syntax at all (unlike wmiexec/psexec/
        # secretsdump); the actual target host must go through its own
        # -dc-ip flag, confirmed against a real impacket-GetUserSPNs -h
        # and a real connection attempt (an "@host"-appended target silently
        # falls back to resolving the domain name via DNS instead of
        # reaching the given host at all).
        assert "impacket-GetUserSPNs -request -dc-ip 10.0.0.5 example.com/svc_user:svc_pass" in cmd

    async def test_impacket_kerberoast_has_no_free_target_argument(self):
        """Per the plan's own correction: this tool is scoped to this
        run's own target host like everything else in this file - there
        is no `target` parameter at all to accept a caller-supplied host."""
        tools, _ = TestCreatePentestTools()._build()
        sig = inspect.signature(tools[IMPACKET_KERBEROAST_TOOL_NAME].coroutine)
        assert "target" not in sig.parameters

    async def test_impacket_kerberoast_rejects_an_invalid_domain_without_executing_anything(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target()
        tools, cb = self._build()

        result = await _invoke(
            tools[IMPACKET_KERBEROAST_TOOL_NAME],
            username="svc_user",
            password="svc_pass",
            domain="example.com; id",
        )

        assert "Invalid `domain`" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_impacket_exec_wmiexec_builds_the_expected_command_with_password(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target()
        exec_output = "[*] Executing command\nadministrator\n"
        kali_exec.exec_run.return_value = SimpleNamespace(
            exit_code=0, output=exec_output.encode()
        )
        tools, cb = self._build()

        result = await _invoke(
            tools[IMPACKET_EXEC_TOOL_NAME],
            username="admin",
            password_or_hash="s3cret",
            command="whoami",
            method="wmiexec",
        )

        assert result.content == exec_output
        cb["mark_tested"].assert_called_once()
        cb["on_raw_output"].assert_called_once_with(exec_output)
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert "impacket-wmiexec admin:s3cret@10.0.0.5 whoami" in cmd

    async def test_impacket_exec_detects_an_ntlm_hash_and_uses_the_hashes_flag(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target()
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=0, output=b"ok\n")
        tools, cb = self._build()

        await _invoke(
            tools[IMPACKET_EXEC_TOOL_NAME],
            username="admin",
            password_or_hash="8846f7eaee8fb117ad06bdd830b7586c",
            command="whoami",
            method="psexec",
        )

        cmd = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert "-hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c" in cmd
        assert cmd.endswith("admin@10.0.0.5 whoami")
        assert "impacket-psexec" in cmd

    async def test_impacket_exec_secretsdump_rejects_a_given_command(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target()
        tools, cb = self._build()

        result = await _invoke(
            tools[IMPACKET_EXEC_TOOL_NAME],
            username="admin",
            password_or_hash="s3cret",
            command="whoami",
            method="secretsdump",
        )

        assert "has no remote command" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_impacket_exec_secretsdump_builds_the_expected_command(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target()
        dump_output = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:...\n"
        kali_exec.exec_run.return_value = SimpleNamespace(
            exit_code=0, output=dump_output.encode()
        )
        tools, cb = self._build()

        result = await _invoke(
            tools[IMPACKET_EXEC_TOOL_NAME],
            username="admin",
            password_or_hash="s3cret",
            command=None,
            method="secretsdump",
        )

        assert result.content == dump_output
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert cmd.endswith("impacket-secretsdump admin:s3cret@10.0.0.5")

    async def test_impacket_exec_has_no_free_target_argument(self):
        tools, _ = TestCreatePentestTools()._build()
        sig = inspect.signature(tools[IMPACKET_EXEC_TOOL_NAME].coroutine)
        assert "target" not in sig.parameters

    async def test_impacket_exec_rejects_an_unknown_method_outright(self, kali_exec):
        tools, _ = self._build()

        with pytest.raises(ValidationError):
            await _invoke(
                tools[IMPACKET_EXEC_TOOL_NAME],
                username="admin",
                password_or_hash="s3cret",
                command="whoami",
                method="smbexec",
            )

        kali_exec.exec_run.assert_not_called()

    async def test_crack_hashes_builds_the_expected_command(
        self, kali_exec, patched_db_manager
    ):
        hashcat_output = "5f4dcc3b5aa765d61d8327deb882cf99:password\n"
        kali_exec.exec_run.side_effect = [
            SimpleNamespace(exit_code=0, output=b""),  # wordlist existence check
            SimpleNamespace(exit_code=0, output=hashcat_output.encode()),
        ]
        tools, cb = self._build()
        hash_file = f"{LOCAL_FILES_DIR}/abc123-hashes.txt"

        result = await _invoke(
            tools[CRACK_HASHES_TOOL_NAME],
            hash_file=hash_file,
            hash_mode="0",
            wordlist="/usr/share/wordlists/rockyou.txt",
        )

        assert result.content == hashcat_output
        cb["mark_tested"].assert_called_once()
        cb["on_raw_output"].assert_called_once_with(hashcat_output)
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"]
        assert cmd == [
            "/bin/bash",
            "-c",
            "timeout --kill-after=5 300 hashcat -m 0 -a 0 "
            f"{hash_file} /usr/share/wordlists/rockyou.txt",
        ]

    async def test_crack_hashes_rejects_a_hash_file_outside_local_files_dir(
        self, kali_exec, patched_db_manager
    ):
        """The one property that keeps this tool from reading arbitrary
        sandbox files: `hash_file` must resolve under LOCAL_FILES_DIR.
        Verified by breaking it: temporarily removing the containment
        check makes this test go red, since "/etc/passwd" would otherwise
        be accepted outright (CLAUDE.md 2.1)."""
        tools, cb = self._build()

        result = await _invoke(
            tools[CRACK_HASHES_TOOL_NAME], hash_file="/etc/passwd", hash_mode="0"
        )

        assert "must be" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_crack_hashes_rejects_a_traversal_attempt_out_of_local_files_dir(
        self, kali_exec, patched_db_manager
    ):
        """A path that starts with LOCAL_FILES_DIR as a raw string but
        normalizes outside it via ".." must still be rejected - a naive
        startswith() check on the unnormalized string would wrongly accept
        this."""
        tools, cb = self._build()

        result = await _invoke(
            tools[CRACK_HASHES_TOOL_NAME],
            hash_file=f"{LOCAL_FILES_DIR}/../../etc/passwd",
            hash_mode="0",
        )

        assert "must be" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_crack_hashes_rejects_a_non_digit_hash_mode(
        self, kali_exec, patched_db_manager
    ):
        tools, cb = self._build()

        result = await _invoke(
            tools[CRACK_HASHES_TOOL_NAME],
            hash_file=f"{LOCAL_FILES_DIR}/abc-hashes.txt",
            hash_mode="1000; id",
        )

        assert "Invalid `hash_mode`" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_crack_hashes_rejects_a_runtime_above_the_cap(
        self, kali_exec, patched_db_manager
    ):
        tools, cb = self._build()

        result = await _invoke(
            tools[CRACK_HASHES_TOOL_NAME],
            hash_file=f"{LOCAL_FILES_DIR}/abc-hashes.txt",
            hash_mode="0",
            max_runtime_seconds=601,
        )

        assert "must be at most" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()

    async def test_crack_hashes_rejects_a_nonexistent_wordlist_without_running_hashcat(
        self, kali_exec, patched_db_manager
    ):
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=1, output=b"")
        tools, cb = self._build()

        result = await _invoke(
            tools[CRACK_HASHES_TOOL_NAME],
            hash_file=f"{LOCAL_FILES_DIR}/abc-hashes.txt",
            hash_mode="0",
            wordlist="/tmp/does-not-exist.txt",
        )

        assert "does not exist" in result.content
        cb["mark_tested"].assert_not_called()
        assert all(
            "hashcat" not in call.kwargs["cmd"][-1]
            for call in kali_exec.exec_run.call_args_list
        )

    async def test_commix_run_builds_the_expected_command(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ports=[80])
        commix_output = "[!] No parameter(s) found for testing.\n"
        kali_exec.exec_run.return_value = SimpleNamespace(
            exit_code=0, output=commix_output.encode()
        )
        tools, cb = self._build()

        result = await _invoke(tools[COMMIX_RUN_TOOL_NAME], url="/vuln.php", port=80)

        assert result.content == commix_output
        assert result.artifact == commix_output
        cb["mark_tested"].assert_called_once()
        cb["on_raw_output"].assert_called_once_with(commix_output)
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"]
        assert cmd == [
            "/bin/bash",
            "-c",
            "timeout --kill-after=5 300 commix --batch -u http://10.0.0.5:80/vuln.php",
        ]

    async def test_commix_run_includes_data_and_param_flags_when_given(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ports=[80])
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=0, output=b"ok\n")
        tools, cb = self._build()

        await _invoke(
            tools[COMMIX_RUN_TOOL_NAME],
            url="/vuln.php",
            port=80,
            data="cmd=ls",
            param="cmd",
        )

        cmd = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert "-d cmd=ls" in cmd
        assert "-p cmd" in cmd

    async def test_commix_run_never_sends_a_caller_supplied_host_only_this_targets_own_host(
        self, kali_exec, patched_db_manager
    ):
        """Mirrors test_sqlmap_run_never_sends_a_caller_supplied_host_...
        above - verified by temporarily making the URL construction naive/
        free-form; that change makes this test go red since the naive URL
        would still embed "evil.example.com" (CLAUDE.md 2.1)."""
        patched_db_manager.get_target.return_value = _make_target(ports=[80])
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=0, output=b"ok\n")
        tools, cb = self._build()

        await _invoke(tools[COMMIX_RUN_TOOL_NAME], url="http://evil.example.com/vuln.php")

        command = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert "evil.example.com" not in command
        assert "http://10.0.0.5:80/vuln.php" in command

    async def test_commix_run_refuses_an_out_of_scope_port_without_executing_anything(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ports=[21, 80])
        tools, cb = self._build()

        result = await _invoke(tools[COMMIX_RUN_TOOL_NAME], url="/x", port=443)

        assert "outside this target's authorized scope" in result.content
        kali_exec.exec_run.assert_not_called()
        cb["mark_tested"].assert_not_called()


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

    async def test_mysql_connect_rejects_a_newline_in_username_before_any_session_work(
        self, fake_session_manager
    ):
        tools, _ = self._build()

        result = await _invoke(
            tools[MYSQL_CONNECT_TOOL_NAME], username="a\nb", password="x"
        )

        assert "cannot contain newlines" in result.content
        assert fake_session_manager.sessions == {}

    async def test_mysql_connect_opens_a_fresh_session_and_reports_connection_failure_normally(
        self, fake_session_manager, patched_db_manager
    ):
        """The spec's own edge case: a target with nothing actually
        listening on the MySQL port. The real client exits immediately with
        a connection-error message rather than hanging or raising - this
        pins that mysql_connect surfaces that as normal, readable failure
        output instead of letting an exception escape."""
        patched_db_manager.get_target.return_value = _make_target(ipv4="10.0.0.5")
        # mysql is network-facing (see _NETWORK_FACING_BINARIES), so the
        # fresh-connect path's own command text would otherwise reach
        # _parse_output's real ChatOllama/Ollama call - same reasoning as
        # TestSshRun's own comment on this fixture.
        patched_db_manager.get_project_settings.return_value = None
        fake_session_manager.run_in_current_session_responses = [
            "ERROR 2002 (HY000): Can't connect to MySQL server on "
            "'10.0.0.5:3306' (111)\n"
        ]
        tools, cb = self._build()

        result = await _invoke(
            tools[MYSQL_CONNECT_TOOL_NAME], username="root", password="toor"
        )

        assert result.content.startswith("Connection failed.")
        assert "ERROR 2002" in result.artifact
        cb["mark_tested"].assert_called_once()
        assert "mysql" in fake_session_manager.sessions
        assert fake_session_manager.sessions["mysql"].command.startswith("mysql -h 10.0.0.5")

    async def test_mysql_connect_reuses_an_already_open_session(
        self, fake_session_manager, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target(ipv4="10.0.0.5")
        fake_session_manager.sessions["mysql"] = KaliSession(
            name="mysql",
            command="mysql -h 10.0.0.5 -u root -ptoor --connect-timeout=10",
            target_id="target1",
            agent_run_id="run1",
            exec_id="x",
            sock=None,
            user="momos",
        )
        fake_session_manager.current_name = "mysql"
        fake_session_manager.run_in_current_session_responses = [
            "+---+\n| 1 |\n+---+\n| 1 |\n+---+\n"
        ]
        tools, cb = self._build()

        result = await _invoke(
            tools[MYSQL_CONNECT_TOOL_NAME], username="root", password="toor"
        )

        assert "Already connected" in result.content
        assert fake_session_manager.run_in_current_session_calls == [("SELECT 1;", 20)]
        cb["mark_tested"].assert_called_once()

    async def test_mysql_query_sends_sql_to_the_already_open_session(
        self, fake_session_manager
    ):
        fake_session_manager.sessions["mysql"] = KaliSession(
            name="mysql",
            command="mysql -h 10.0.0.5 -u root -ptoor --connect-timeout=10",
            target_id="target1",
            agent_run_id="run1",
            exec_id="x",
            sock=None,
            user="momos",
        )
        fake_session_manager.current_name = "mysql"
        fake_session_manager.run_in_current_session_responses = [
            "+----------+\n| version()|\n+----------+\n| 8.0.30   |\n+----------+\n"
        ]
        tools, cb = self._build()

        result = await _invoke(tools[MYSQL_QUERY_TOOL_NAME], sql="SELECT version();")

        assert fake_session_manager.run_in_current_session_calls == [
            ("SELECT version();", 20)
        ]
        assert "8.0.30" in result.artifact
        cb["mark_tested"].assert_called_once()

    async def test_mysql_query_rejects_a_newline_before_touching_the_session(
        self, fake_session_manager
    ):
        tools, _ = self._build()

        result = await _invoke(tools[MYSQL_QUERY_TOOL_NAME], sql="SELECT 1;\nSELECT 2;")

        assert "cannot contain newlines" in result.content
        assert fake_session_manager.run_in_current_session_calls == []

    async def test_mysql_query_missing_required_argument_is_rejected(
        self, fake_session_manager
    ):
        tools, _ = self._build()

        with pytest.raises(ValidationError):
            await _invoke(tools[MYSQL_QUERY_TOOL_NAME])

    async def test_mysql_query_with_no_session_open_is_rejected(self, fake_session_manager):
        tools, _ = self._build()

        result = await _invoke(tools[MYSQL_QUERY_TOOL_NAME], sql="SELECT 1;")

        assert "No MySQL session is currently open" in result.content
        assert fake_session_manager.run_in_current_session_calls == []

    async def test_responder_start_opens_a_background_session_without_blocking_on_a_read(
        self, fake_session_manager
    ):
        """Unlike mysql_connect's own initial read, responder_start must
        not wait on run_in_current_session at all - responder runs
        indefinitely, so there's nothing to usefully wait for at launch
        time (see responder_start's own docstring)."""
        tools, cb = self._build()

        result = await _invoke(tools[RESPONDER_START_TOOL_NAME])

        assert fake_session_manager.sessions["responder"].command == "responder -I eth0"
        assert fake_session_manager.current_name == "responder"
        assert fake_session_manager.run_in_current_session_calls == []
        cb["mark_tested"].assert_called_once()
        cb["on_session_change"].assert_called_once_with("responder", "responder -I eth0")
        assert result.artifact is None

    async def test_responder_start_with_custom_interface_builds_the_expected_command(
        self, fake_session_manager
    ):
        tools, _ = self._build()

        await _invoke(tools[RESPONDER_START_TOOL_NAME], interface="eth1")

        assert fake_session_manager.sessions["responder"].command == "responder -I eth1"

    async def test_responder_start_rejects_a_newline_in_interface_before_touching_the_session(
        self, fake_session_manager
    ):
        tools, _ = self._build()

        result = await _invoke(tools[RESPONDER_START_TOOL_NAME], interface="eth0\nrm -rf /")

        assert "cannot contain newlines" in result.content
        assert fake_session_manager.sessions == {}

    async def test_responder_start_refuses_to_reopen_an_already_running_session(
        self, fake_session_manager
    ):
        fake_session_manager.sessions["responder"] = KaliSession(
            name="responder",
            command="responder -I eth0",
            target_id="target1",
            agent_run_id="run1",
            exec_id="x",
            sock=None,
            user="momos",
        )
        fake_session_manager.current_name = "responder"
        tools, cb = self._build()

        result = await _invoke(tools[RESPONDER_START_TOOL_NAME], interface="eth1")

        assert "already running" in result.content
        # Still the original command - the existing session was never
        # replaced by this call.
        assert fake_session_manager.sessions["responder"].command == "responder -I eth0"
        cb["mark_tested"].assert_not_called()

    async def test_responder_read_polls_the_open_session_for_captured_output(
        self, fake_session_manager
    ):
        fake_session_manager.sessions["responder"] = KaliSession(
            name="responder",
            command="responder -I eth0",
            target_id="target1",
            agent_run_id="run1",
            exec_id="x",
            sock=None,
            user="momos",
        )
        fake_session_manager.current_name = "responder"
        captured = (
            "[LLMNR] Poisoned answer sent to 10.0.0.9\n"
            "[SMB] NTLMv2-SSP Hash captured: WORKSTATION::...\n"
        )
        fake_session_manager.run_in_current_session_responses = [captured]
        tools, cb = self._build()

        result = await _invoke(tools[RESPONDER_READ_TOOL_NAME])

        assert fake_session_manager.run_in_current_session_calls == [(None, 8)]
        assert "NTLMv2-SSP Hash captured" in result.artifact
        cb["on_raw_output"].assert_called_once_with(captured)

    async def test_responder_read_switches_to_the_responder_session_if_not_current(
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
        fake_session_manager.sessions["responder"] = KaliSession(
            name="responder",
            command="responder -I eth0",
            target_id="target1",
            agent_run_id="run1",
            exec_id="x",
            sock=None,
            user="momos",
        )
        fake_session_manager.current_name = "ftp"
        fake_session_manager.run_in_current_session_responses = [""]
        tools, _ = self._build()

        await _invoke(tools[RESPONDER_READ_TOOL_NAME])

        assert fake_session_manager.current_name == "responder"

    async def test_responder_read_with_no_session_open_is_rejected(self, fake_session_manager):
        tools, cb = self._build()

        result = await _invoke(tools[RESPONDER_READ_TOOL_NAME])

        assert "No responder session is open" in result.content
        assert fake_session_manager.run_in_current_session_calls == []
        cb["on_raw_output"].assert_not_called()

    async def test_responder_stop_closes_an_open_session(self, fake_session_manager):
        fake_session_manager.sessions["responder"] = KaliSession(
            name="responder",
            command="responder -I eth0",
            target_id="target1",
            agent_run_id="run1",
            exec_id="x",
            sock=None,
            user="momos",
        )
        fake_session_manager.current_name = "responder"
        tools, _ = self._build()

        result = await _invoke(tools[RESPONDER_STOP_TOOL_NAME])

        assert "stopped" in result.content.lower()
        assert fake_session_manager.sessions["responder"].closed is True

    async def test_responder_stop_with_no_session_open_reports_nothing_to_stop(
        self, fake_session_manager
    ):
        tools, _ = self._build()

        result = await _invoke(tools[RESPONDER_STOP_TOOL_NAME])

        assert "No responder session" in result.content


class TestSshRun:
    """Finding 6, now fixed: ssh_run is decorated @tool(...,
    response_format="content_and_artifact") (a 2-tuple is required), but
    used to `return await _maybe_condense(...)` directly - _maybe_condense
    returns a bare str, never a tuple - which crashed every real invocation
    with a ValueError raised by LangChain's own BaseTool.arun before the
    ToolMessage was even built (see the fix removing the xfail markers in
    tests/integration/tools/test_ssh_probe.py). This pins the fixed return
    shape at the unit level, without any Docker/live sshd needed - unlike
    ssh_check_login, nothing here exercised ssh_run's return shape at all
    before this test existed."""

    async def test_returns_a_content_artifact_tuple_not_a_bare_string(
        self, kali_exec, patched_db_manager
    ):
        patched_db_manager.get_target.return_value = _make_target()
        # No parsing model configured - _parse_output's own "fall back to
        # raw output" path, so this never needs a real/fake LLM.
        patched_db_manager.get_project_settings.return_value = None
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=0, output=b"root\n")
        tools = _tools_by_name(
            create_guided_session_tools(
                "proj1", "target1", "run1", MagicMock(), MagicMock(), MagicMock(),
                MagicMock(), MagicMock(),
            )
        )

        result = await _invoke(
            tools[SSH_RUN_TOOL_NAME], username="u", password="p", command="whoami"
        )

        assert result.content == "root\n"
        assert result.artifact == "root\n"


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

    async def test_download_file_fetches_url_and_returns_its_path(self, kali_exec):
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=0, output=b"1234")
        tools = _tools_by_name(create_file_tools("proj1"))

        result = await _invoke(
            tools[DOWNLOAD_FILE_TOOL_NAME],
            url="http://10.0.0.5/backup.zip",
            filename="backup.zip",
        )

        assert "Downloaded 1234 bytes from http://10.0.0.5/backup.zip to /tmp/momos-files/" in (
            result.content
        )
        assert result.content.rstrip().endswith("-backup.zip")
        cmd = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert "curl" in cmd
        assert "http://10.0.0.5/backup.zip" in cmd
        assert "--max-filesize" in cmd

    async def test_download_file_shell_quotes_the_url_so_it_cant_break_out_of_the_command(
        self, kali_exec
    ):
        kali_exec.exec_run.return_value = SimpleNamespace(exit_code=0, output=b"1")
        tools = _tools_by_name(create_file_tools("proj1"))
        url = "http://10.0.0.5/$(touch /tmp/INJECTED)"

        await _invoke(tools[DOWNLOAD_FILE_TOOL_NAME], url=url)

        cmd = kali_exec.exec_run.call_args.kwargs["cmd"][-1]
        assert shlex.quote(url) in cmd

    async def test_download_file_rejects_a_non_http_url(self, kali_exec):
        tools = _tools_by_name(create_file_tools("proj1"))

        result = await _invoke(tools[DOWNLOAD_FILE_TOOL_NAME], url="file:///etc/passwd")

        assert "only http:// and https:// URLs are supported" in result.content
        kali_exec.exec_run.assert_not_called()

    async def test_download_file_missing_required_url_is_rejected(self, kali_exec):
        tools = _tools_by_name(create_file_tools("proj1"))

        with pytest.raises(ValidationError):
            await _invoke(tools[DOWNLOAD_FILE_TOOL_NAME])

        kali_exec.exec_run.assert_not_called()


class TestCreateScriptingTools:
    async def test_run_python_script_returns_the_scripts_output_and_marks_tested(self, kali_exec):
        kali_exec.exec_run.side_effect = [
            SimpleNamespace(exit_code=0, output=b""),
            SimpleNamespace(exit_code=0, output=b"hello from python\n"),
        ]
        mark_tested = MagicMock()
        on_raw_output = MagicMock()
        tools = _tools_by_name(
            create_scripting_tools("proj1", on_raw_output=on_raw_output, mark_tested=mark_tested)
        )

        result = await _invoke(tools[RUN_PYTHON_SCRIPT_TOOL_NAME], code="print('hello from python')")

        assert "hello from python" in result.content
        mark_tested.assert_called_once_with()
        on_raw_output.assert_called_once_with("hello from python\n")
        write_cmd, run_cmd = [call.kwargs["cmd"][-1] for call in kali_exec.exec_run.call_args_list]
        assert "base64 -d" in write_cmd
        assert "python3 " in run_cmd

    async def test_run_python_script_never_interpolates_code_raw_into_the_shell_command(
        self, kali_exec
    ):
        tools = _tools_by_name(
            create_scripting_tools("proj1", on_raw_output=MagicMock(), mark_tested=MagicMock())
        )
        payload = "print('$(touch /tmp/INJECTED)')"

        await _invoke(tools[RUN_PYTHON_SCRIPT_TOOL_NAME], code=payload)

        for call in kali_exec.exec_run.call_args_list:
            assert payload not in call.kwargs["cmd"][-1]

    async def test_failing_script_still_returns_its_output_and_marks_tested(self, kali_exec):
        kali_exec.exec_run.side_effect = [
            SimpleNamespace(exit_code=0, output=b""),
            SimpleNamespace(exit_code=1, output=b"Traceback: boom"),
        ]
        mark_tested = MagicMock()
        on_raw_output = MagicMock()
        tools = _tools_by_name(
            create_scripting_tools("proj1", on_raw_output=on_raw_output, mark_tested=mark_tested)
        )

        result = await _invoke(tools[RUN_PYTHON_SCRIPT_TOOL_NAME], code="raise SystemExit(1)")

        assert "Traceback: boom" in result.content
        mark_tested.assert_called_once_with()
        # A failure's error text must never be recorded as real evidence -
        # on_raw_output feeds _last_raw_output, which claim verification
        # checks a reported outcome against (see every other Tier-1 tool's
        # own "mark_tested() then return early on failure, before
        # on_raw_output" convention - e.g. nikto_scan/sqlmap_run).
        on_raw_output.assert_not_called()

    async def test_failed_write_step_skips_the_run_and_does_not_mark_tested(self, kali_exec):
        kali_exec.exec_run.side_effect = [SimpleNamespace(exit_code=1, output=b"no space left")]
        mark_tested = MagicMock()
        tools = _tools_by_name(
            create_scripting_tools("proj1", on_raw_output=MagicMock(), mark_tested=mark_tested)
        )

        result = await _invoke(tools[RUN_PYTHON_SCRIPT_TOOL_NAME], code="print(1)")

        assert "no space left" in result.content
        assert kali_exec.exec_run.call_count == 1
        mark_tested.assert_not_called()


class TestScriptingGateIsIndependentOfShell:
    @pytest.mark.parametrize("allow_shell", [True, False])
    @pytest.mark.parametrize(
        ("builder", "builder_overrides"),
        [
            (agent_tools.build_agent_tools, {}),
            (agent_tools.build_scouting_agent_tools, {}),
            (agent_tools.build_pentesting_agent_tools, {"attack_vector_id": "vec1"}),
        ],
        ids=["single_agent", "scouting", "pentesting"],
    )
    def test_run_python_script_is_present_only_when_scripting_group_is_enabled(
        self, builder, builder_overrides, allow_shell
    ):
        def names_for(enabled_tools):
            kwargs = _builder_kwargs(
                builder,
                allow_shell=allow_shell,
                allow_install_packages=False,
                enabled_tools=enabled_tools,
                **builder_overrides,
            )
            return {t.name for t in builder(**kwargs)}

        assert RUN_PYTHON_SCRIPT_TOOL_NAME in names_for(["scripting"])
        assert RUN_PYTHON_SCRIPT_TOOL_NAME not in names_for(None)


def _builder_kwargs(builder, **overrides) -> dict:
    kwargs = {name: MagicMock() for name in inspect.signature(builder).parameters}
    kwargs.update(project_id="proj1", target_id="target1", agent_run_id="run1")
    kwargs.update(overrides)
    return kwargs


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
            str(uuid.uuid4()),
            str(uuid.uuid4()),
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
