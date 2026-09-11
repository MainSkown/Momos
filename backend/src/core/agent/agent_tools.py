import asyncio
import re
from typing import Callable, Dict, List
from pydantic import BaseModel, Field, ValidationError
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama
from src.core import db_manager, settings
from src.core.kali_integration import kali_registry
from src.core.kali_integration.kali_manager import KALI_USERS
from src.core.kali_integration.kali_session import KaliSessionError
from src.schemas import Vulnerability, VulnerabilityBase

KALI_COMMAND_TOOL_NAME = "execute_kali_command"
REPORT_VULNERABILITY_TOOL_NAME = "report_vulnerability"
FINISH_TASK_TOOL_NAME = "finish_task"
OPEN_SESSION_TOOL_NAME = "open_session"
SEND_TO_SESSION_TOOL_NAME = "send_to_session"
READ_SESSION_TOOL_NAME = "read_session"
CLOSE_SESSION_TOOL_NAME = "close_session"
LIST_SESSIONS_TOOL_NAME = "list_sessions"
INSTALL_PACKAGE_TOOL_NAME = "install_kali_package"
ATTACK_LOG_TOOL_NAME = "log_attack_attempt"

ATTACK_OUTCOMES = {"vulnerable", "not_vulnerable", "inconclusive"}

# Debian package-name policy: lowercase letters, digits, '+', '-', '.', must
# start with an alphanumeric. Enforced strictly here (not just relying on
# apt's own error) because this string is interpolated straight into a root
# shell command - anything looser would open command injection.
PACKAGE_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")

# Package installs can be slow (large tools, dependency resolution) - longer
# than the default one-shot command timeout.
PACKAGE_INSTALL_TIMEOUT_SECONDS = 300

# How long open_session waits for the command's initial output (a banner,
# a prompt) before returning - kept short since most either respond
# immediately or not at all until something is sent.
SESSION_OPEN_READ_SECONDS = 3

PARSER_SYSTEM_PROMPT = (
    "You are a data-extraction assistant supporting a penetration-testing agent. "
    "You are given the exact shell command that was run inside a Kali Linux "
    "container and its raw output.\n\n"
    "In 'summary', condense the output to only the information relevant to a "
    "security assessment: open ports, service names/versions, discovered "
    "hosts, vulnerabilities, file paths, credentials, and other actionable "
    "findings. Remove repetitive noise, banners, and formatting clutter. If "
    "the command failed or produced an error, clearly state the failure and "
    "its cause. Plain, concise text only - no commentary or suggestions.\n\n"
    "In 'facts', list any specific network ports this output identifies a "
    "service name and/or version for, one entry per port in the exact "
    "'<number>/tcp' or '<number>/udp' form. Leave it empty if none were "
    "found - never invent one."
)


class _PortFact(BaseModel):
    port: str = Field(description="e.g. '80/tcp' or '53/udp'")
    service: str = ""
    version: str = ""
    notes: str = ""


class _ParsedCommandOutput(BaseModel):
    """Structured result of condensing one Kali command's raw output.

    Used as the schema for parser_llm.with_structured_output() - Ollama
    constrains decoding to this JSON shape directly, which is far more
    reliable than asking a (often small, local) model to self-format an
    extra marker line inside free text and then regex it back out; that
    approach was tried and broke in practice (wrong casing, non-array
    formatting, trailing prose after the marker)."""

    summary: str
    facts: List[_PortFact] = Field(default_factory=list)


async def get_parsing_model_name(project_id: str) -> str | None:
    loop = asyncio.get_running_loop()
    project_settings = await loop.run_in_executor(
        None, db_manager.get_project_settings, project_id
    )

    return project_settings.parsing_model_name if project_settings else None


async def _parse_output(
    project_id: str,
    command: str,
    raw_output: str,
    on_enumeration: Callable[[dict], None],
) -> str:
    parsing_model_name = await get_parsing_model_name(project_id)

    if not parsing_model_name:
        # No parsing model configured for this project - fall back to raw output
        return raw_output

    parser_llm = ChatOllama(model=parsing_model_name, base_url=settings.ollama_url)
    structured_llm = parser_llm.with_structured_output(_ParsedCommandOutput)

    try:
        result = await structured_llm.ainvoke(
            [
                SystemMessage(content=PARSER_SYSTEM_PROMPT),
                HumanMessage(content=f"Command: {command}\n\nOutput:\n{raw_output}"),
            ]
        )
    except Exception as e:
        # Don't lose a real command result just because the parsing model
        # hiccuped (or doesn't support structured output) - give the agent
        # the raw output instead.
        print(f"Output parsing failed, using raw output: {e}")
        return raw_output

    entries: Dict[str, dict] = {}
    for fact in result.facts:
        port = fact.port.strip()
        if not port:
            continue
        entries[port] = {
            "service": fact.service,
            "version": fact.version,
            "notes": fact.notes,
        }
    if entries:
        on_enumeration(entries)

    return result.summary or raw_output


async def _run_kali_command(
    project_id: str, command: str, on_enumeration: Callable[[dict], None]
) -> str:
    manager = await kali_registry.get_manager(project_id)

    # Serialize the whole command (docker exec + its parsing call) so that
    # several kali-command tool calls issued in the same LLM turn don't all
    # hit Docker and the local parsing model at once.
    async with manager.command_lock:
        try:
            raw_output = await manager.execute(command)
        except RuntimeError as e:
            raw_output = str(e)

        if not raw_output.strip():
            return "(command produced no output)"

        return await _parse_output(project_id, command, raw_output, on_enumeration)


async def _install_kali_package(project_id: str, package: str) -> str:
    if not PACKAGE_NAME_PATTERN.match(package):
        return (
            f"Invalid package name '{package}'. Only a single, bare apt "
            "package name is allowed - lowercase letters, digits, '+', '-', "
            "'.', starting with a letter or digit. No flags, paths, spaces, "
            "or shell operators."
        )

    manager = await kali_registry.get_manager(project_id)

    # Shares command_lock with execute_kali_command - an apt-get invocation
    # holds dpkg's lock for its whole run, so a concurrent one-shot command
    # (or another install) would fail against it anyway.
    async with manager.command_lock:
        try:
            output = await manager.execute(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y "
                f"--no-install-recommends {package}",
                user=KALI_USERS.root,
                timeout_seconds=PACKAGE_INSTALL_TIMEOUT_SECONDS,
            )
        except RuntimeError as e:
            return f"Failed to install package '{package}': {e}"

    return f"Package '{package}' installed successfully.\n\n{output.strip()}"


def create_install_package_tool(project_id: str):
    """Builds an install_kali_package tool bound to a specific project's Kali container."""

    @tool(INSTALL_PACKAGE_TOOL_NAME)
    async def install_kali_package(package: str) -> str:
        """Installs a single apt package inside the Kali container (runs as
        root, equivalent to `apt install <package>`). Use this when a tool
        you need isn't already installed. Only a bare package name is
        accepted - no flags, paths, spaces, or shell operators (e.g.
        "hydra", not "hydra; rm -rf /" or "-y hydra"). Installing can take a
        while for larger packages.

        Args:
            package: The exact apt package name to install, e.g. "hydra" or
                "metasploit-framework".
        """
        return await _install_kali_package(project_id, package)

    return install_kali_package


def create_kali_tool(project_id: str, on_enumeration: Callable[[dict], None]):
    """Builds an execute_kali_command tool bound to a specific project's Kali container."""

    @tool(KALI_COMMAND_TOOL_NAME)
    async def execute_kali_command(command: str) -> str:
        """Executes a command in the Kali Linux container and returns a condensed
        summary of its output. Use this for anything that runs to completion
        on its own (nmap, curl, gobuster, cat, ls, ...) - note that every
        call is a fresh, independent process with no memory of previous
        calls. For anything interactive or stateful that needs to stay open
        and be driven turn by turn - nc/telnet holding a connection open, or
        listening for an incoming connection - use open_session instead."""
        return await _run_kali_command(project_id, command, on_enumeration)

    return execute_kali_command


async def _save_vulnerability(vulnerability: Vulnerability) -> Vulnerability:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, db_manager.add_vulnerability, vulnerability)


def create_vulnerability_tool(project_id: str, target_id: str):
    """Builds a report_vulnerability tool bound to a specific project/target."""

    @tool(REPORT_VULNERABILITY_TOOL_NAME)
    async def report_vulnerability(
        name: str, cvss4_vector: str, proof_of_concept: str
    ) -> str:
        """Records a confirmed vulnerability found on the current target. Only
        call this once a finding has actually been verified - not for suspected
        or untested issues.

        Args:
            name: A short, descriptive name for the vulnerability.
            cvss4_vector: A valid CVSS v4.0 vector string, e.g.
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N".
                Its severity score is derived automatically - do not include one.
            proof_of_concept: Step-by-step instructions describing exactly how to
                verify or exploit the vulnerability, in enough detail to reproduce it.
        """
        try:
            # SQLModel table models don't run Pydantic validators on
            # construction - validate through the plain base model first,
            # then build the table row from the already-validated data.
            validated = VulnerabilityBase(
                name=name,
                cvss4_vector=cvss4_vector,
                proof_of_concept=proof_of_concept,
            )
        except ValidationError as e:
            return f"Could not record vulnerability, fix the input and try again: {e}"

        vulnerability = Vulnerability(
            name=validated.name,
            cvss4_vector=validated.cvss4_vector,
            cvss4_score=validated.cvss4_score,
            proof_of_concept=validated.proof_of_concept,
            found_in=target_id,
            related_to_project=project_id,
        )

        saved = await _save_vulnerability(vulnerability)

        return (
            f"Recorded vulnerability '{saved.name}' "
            f"(CVSS v4.0 score: {saved.cvss4_score})."
        )

    return report_vulnerability


def create_finish_task_tool(on_finish: Callable[[str], None]):
    """Builds a finish_task tool that lets the agent end its own run early,
    once it considers the assessment complete."""

    @tool(FINISH_TASK_TOOL_NAME)
    async def finish_task(summary: str) -> str:
        """Call this once the assessment is complete - all reachable findings
        have been reported and there is nothing productive left to
        investigate. This ends the run immediately, even if time remains,
        and cannot be undone.

        Args:
            summary: A short summary of what was accomplished and why the
                task is considered complete.
        """
        on_finish(summary)
        return "Task marked as finished. Ending the run now."

    return finish_task


def create_attack_log_tool(on_attempt: Callable[[dict], None]):
    """Builds a log_attack_attempt tool - the agent's own working-memory
    audit trail of what it has tried against the target and whether it
    worked. Deliberately separate from report_vulnerability: this is a
    lightweight note (including failed/inconclusive attempts, so the agent
    doesn't re-try or re-imagine the same thing later), not the formal,
    CVSS-scored record of a confirmed finding."""

    @tool(ATTACK_LOG_TOOL_NAME)
    async def log_attack_attempt(
        target: str, vector: str, outcome: str, notes: str = ""
    ) -> str:
        """Records one attempted attack/exploitation vector against a
        specific port or service, and its outcome. Call this ONLY right
        after the actual attempt - a real execute_kali_command or
        send_to_session call whose result you have actually seen. Never
        call this for something you only planned or described in your
        reasoning without a matching tool call actually running it first -
        "inconclusive" must mean "I tried it and the result was unclear",
        not "I thought about trying it". If you have not actually run the
        command yet, run it now instead of logging anything. A logged
        failure keeps you (and future turns) from repeating or
        hallucinating the same attempt again. This is separate from
        report_vulnerability: a genuinely confirmed vulnerability still
        needs its own report_vulnerability call with a CVSS vector for the
        formal record.

        Args:
            target: The port/service or host the attempt was against, e.g.
                "21/tcp (vsftpd 2.3.4)".
            vector: What was tried, e.g. "exploit-db 49757 (vsftpd 2.3.4
                backdoor)" or a short description of the manual technique.
            outcome: One of "vulnerable", "not_vulnerable", or "inconclusive".
            notes: Any short additional context - error messages, why it
                failed, what would be needed to confirm it, etc.
        """
        normalized = outcome.strip().lower()
        if normalized not in ATTACK_OUTCOMES:
            return (
                f"Invalid outcome '{outcome}'. Use one of: "
                f"{', '.join(sorted(ATTACK_OUTCOMES))}."
            )

        on_attempt(
            {"target": target, "vector": vector, "outcome": normalized, "notes": notes}
        )
        return f"Logged attack attempt against '{target}' ({normalized})."

    return log_attack_attempt


def create_session_tools(project_id: str, target_id: str) -> list:
    """Builds the interactive-session tool set (open/send/read/close/list),
    bound to a project's Kali container and the target whose run opened
    them, so ending that run closes only its own sessions.

    Deliberately does NOT use manager.command_lock (a long-lived session
    must never block the one-shot execute_kali_command path, or vice versa)
    and does NOT run output through the parsing/summarization model the way
    execute_kali_command does - that output is a finished, complete result,
    while session output is exploratory/partial by nature (a banner, a
    half-formed prompt), and summarizing it risks dropping exactly the
    bytes the agent needs to decide its next move."""

    @tool(OPEN_SESSION_TOOL_NAME)
    async def open_session(command: str) -> str:
        """Starts a persistent, interactive session running `command` inside
        the Kali container, and returns a session_id for use with
        send_to_session / read_session / close_session, along with any
        output the command produces in the first few seconds (a banner or
        prompt).

        Use this ONLY for commands that are interactive or stateful and
        would hang - or lose their state - under the normal one-shot
        execute_kali_command, whose every call runs in a fresh, independent
        process: e.g. `nc <host> <port>` or `telnet <host> <port>` to hold a
        connection open and exchange data turn by turn, `nc -lvnp <port>` to
        listen for an incoming connection such as a reverse shell, or `ftp
        <host>` to log in and browse a remote filesystem (e.g. testing an
        anonymous FTP login: open_session("ftp <host>"), then
        send_to_session with "anonymous" as the username when prompted, then
        send_to_session again with an empty string as the password). For
        anything that runs to completion on its own (nmap, gobuster, curl,
        cat, ls, ...), use execute_kali_command instead - it is simpler and
        its output is automatically condensed for you.

        Always call close_session when you're done with a session - open
        sessions count against a per-project limit, so leaving them open
        can prevent opening new ones.

        Args:
            command: The shell command to run persistently, e.g.
                "nc 10.0.0.5 4444", "nc -lvnp 4444", or "ftp 10.0.0.5".
        """
        manager = await kali_registry.get_manager(project_id)
        try:
            session = await manager.open_session(command, target_id=target_id)
            initial_output = await manager.read_session(
                session.session_id, read_window=SESSION_OPEN_READ_SECONDS
            )
        except KaliSessionError as e:
            return str(e)
        return f"Session opened: {session.session_id}\n\n{initial_output}"

    @tool(SEND_TO_SESSION_TOOL_NAME)
    async def send_to_session(session_id: str, input: str, wait_seconds: int = 5) -> str:
        """Sends one line of input to an open session (as if typed and
        followed by Enter), and returns whatever output accumulates within
        `wait_seconds` afterward. There is no reliable way to know when a
        program has finished responding, so this only waits briefly by
        default - if you expect a slower response, pass a larger
        wait_seconds (up to 30), or call read_session again afterward to
        pick up anything that arrived later.

        Args:
            session_id: The id returned by open_session.
            input: The line to send, without a trailing newline.
            wait_seconds: How long to wait for output after sending, 1-30
                (default 5). Use a larger value only when you specifically
                expect a slow response.
        """
        manager = await kali_registry.get_manager(project_id)
        try:
            return await manager.write_to_session(
                session_id, input, read_window=wait_seconds
            )
        except KaliSessionError as e:
            return str(e)

    @tool(READ_SESSION_TOOL_NAME)
    async def read_session(session_id: str, wait_seconds: int = 5) -> str:
        """Reads whatever output has accumulated on an open session WITHOUT
        sending anything. Use this to check on a session after waiting (for
        example, polling an `nc -lvnp` listener for an incoming connection)
        or to pick up delayed output after a previous send_to_session. This
        call only waits up to `wait_seconds` and then returns whatever
        arrived (or a message saying nothing arrived) - it never blocks for
        a long time, so for a listener you expect to take a while, call this
        repeatedly rather than expecting one call to wait for the whole
        thing.

        Args:
            session_id: The id returned by open_session.
            wait_seconds: How long to wait for new output before giving up
                for this call, 1-30 (default 5).
        """
        manager = await kali_registry.get_manager(project_id)
        try:
            return await manager.read_session(session_id, read_window=wait_seconds)
        except KaliSessionError as e:
            return str(e)

    @tool(CLOSE_SESSION_TOOL_NAME)
    async def close_session(session_id: str) -> str:
        """Closes an open interactive session and frees its slot against
        the per-project session limit. Always close a session once you're
        done with it, or once it turns out to be unnecessary."""
        manager = await kali_registry.get_manager(project_id)
        await manager.close_session(session_id)
        return f"Session {session_id} closed."

    @tool(LIST_SESSIONS_TOOL_NAME)
    async def list_sessions() -> str:
        """Lists your currently open interactive sessions (id and the
        command each is running). Use this if you've lost track of which
        sessions are still open - for example before opening a new one, if
        you're unsure whether you're near the concurrent-session limit."""
        manager = await kali_registry.get_manager(project_id)
        sessions = await manager.list_sessions(target_id=target_id)
        if not sessions:
            return "No open sessions."
        return "\n".join(f"{s.session_id}: {s.command}" for s in sessions)

    return [open_session, send_to_session, read_session, close_session, list_sessions]


def build_agent_tools(
    project_id: str,
    target_id: str,
    on_finish: Callable[[str], None],
    on_enumeration: Callable[[dict], None],
    on_attempt: Callable[[dict], None],
) -> list:
    return [
        create_kali_tool(project_id, on_enumeration),
        create_install_package_tool(project_id),
        *create_session_tools(project_id, target_id),
        create_vulnerability_tool(project_id, target_id),
        create_attack_log_tool(on_attempt),
        create_finish_task_tool(on_finish),
    ]
