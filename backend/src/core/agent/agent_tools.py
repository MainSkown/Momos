import asyncio
from typing import Callable
from pydantic import ValidationError
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama
from src.core import db_manager, settings
from src.core.kali_integration import kali_registry
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

# How long open_session waits for the command's initial output (a banner,
# a prompt) before returning - kept short since most either respond
# immediately or not at all until something is sent.
SESSION_OPEN_READ_SECONDS = 3

PARSER_SYSTEM_PROMPT = (
    "You are a data-extraction assistant supporting a penetration-testing agent. "
    "You are given the exact shell command that was run inside a Kali Linux "
    "container and its raw output. Extract and condense only the information "
    "relevant to a security assessment: open ports, service names/versions, "
    "discovered hosts, vulnerabilities, file paths, credentials, and other "
    "actionable findings. Remove repetitive noise, banners, and formatting "
    "clutter. If the command failed or produced an error, clearly state the "
    "failure and its cause. Respond with plain, concise text only - no "
    "commentary or suggestions."
)


async def get_parsing_model_name(project_id: str) -> str | None:
    loop = asyncio.get_running_loop()
    project_settings = await loop.run_in_executor(
        None, db_manager.get_project_settings, project_id
    )

    return project_settings.parsing_model_name if project_settings else None


async def _parse_output(project_id: str, command: str, raw_output: str) -> str:
    parsing_model_name = await get_parsing_model_name(project_id)

    if not parsing_model_name:
        # No parsing model configured for this project - fall back to raw output
        return raw_output

    parser_llm = ChatOllama(model=parsing_model_name, base_url=settings.ollama_url)

    try:
        response = await parser_llm.ainvoke(
            [
                SystemMessage(content=PARSER_SYSTEM_PROMPT),
                HumanMessage(content=f"Command: {command}\n\nOutput:\n{raw_output}"),
            ]
        )
    except Exception as e:
        # Don't lose a real command result just because the parsing model
        # hiccuped - give the agent the raw output instead.
        print(f"Output parsing failed, using raw output: {e}")
        return raw_output

    return str(response.content)


async def _run_kali_command(project_id: str, command: str) -> str:
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

        return await _parse_output(project_id, command, raw_output)


def create_kali_tool(project_id: str):
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
        return await _run_kali_command(project_id, command)

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
        connection open and exchange data turn by turn, or `nc -lvnp <port>`
        to listen for an incoming connection such as a reverse shell. For
        anything that runs to completion on its own (nmap, gobuster, curl,
        cat, ls, ...), use execute_kali_command instead - it is simpler and
        its output is automatically condensed for you.

        Always call close_session when you're done with a session - open
        sessions count against a per-project limit, so leaving them open
        can prevent opening new ones.

        Args:
            command: The shell command to run persistently, e.g.
                "nc 10.0.0.5 4444" or "nc -lvnp 4444".
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
    project_id: str, target_id: str, on_finish: Callable[[str], None]
) -> list:
    return [
        create_kali_tool(project_id),
        *create_session_tools(project_id, target_id),
        create_vulnerability_tool(project_id, target_id),
        create_finish_task_tool(on_finish),
    ]
