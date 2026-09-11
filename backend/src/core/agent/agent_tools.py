import asyncio
import re
from typing import Callable, Dict, List, Optional
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
RUN_TOOL_NAME = "run"
NEW_SESSION_TOOL_NAME = "new_session"
SWITCH_SESSION_TOOL_NAME = "switch_session"
CLOSE_SESSION_TOOL_NAME = "close_session"
LIST_SESSIONS_TOOL_NAME = "list_sessions"
INTERRUPT_SESSION_TOOL_NAME = "interrupt_session"
INSTALL_PACKAGE_TOOL_NAME = "install_kali_package"
ATTACK_LOG_TOOL_NAME = "log_attack_attempt"
SWITCH_MODE_TOOL_NAME = "switch_mode"

ATTACK_OUTCOMES = {"vulnerable", "not_vulnerable", "inconclusive"}
VALID_MODES = {"scouting", "exploiting"}

# Name of the session auto-opened by Agent.start_agent before the first
# turn, and re-opened by run() as a defensive fallback if every session
# ever ends up closed.
DEFAULT_SESSION_NAME = "default"
DEFAULT_SESSION_COMMAND = "/bin/bash"

# Debian package-name policy: lowercase letters, digits, '+', '-', '.', must
# start with an alphanumeric. Enforced strictly here (not just relying on
# apt's own error) because this string is interpolated straight into a root
# shell command - anything looser would open command injection.
PACKAGE_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")

# Package installs can be slow (large tools, dependency resolution) - longer
# than the default one-shot command timeout.
PACKAGE_INSTALL_TIMEOUT_SECONDS = 300

# How long new_session waits for the command's initial output (a banner,
# a prompt) before returning - kept short since most either respond
# immediately or not at all until something is sent.
SESSION_OPEN_READ_SECONDS = 3

# Below this, run() always returns raw output unmodified - keeps small
# interactive exchanges (banners, short replies) fast and byte-exact. Above
# it, output gets condensed the same way execute_kali_command's output
# always used to (see _maybe_condense).
CONDENSE_THRESHOLD_CHARS = 1500
# Only a genuine, still-unanswered credential prompt should block
# condensation regardless of length - NOT an ordinary shell prompt (which
# also ends in $/#/> with no trailing newline, but reappears after every
# single completed command in the persistent session model).
_CREDENTIAL_PROMPT_PATTERN = re.compile(
    r"(username|login|password|passphrase)\s*:\s*$", re.IGNORECASE
)

PARSER_SYSTEM_PROMPT = (
    "You are a data-extraction assistant supporting a penetration-testing agent. "
    "You are given the exact input sent to a Kali Linux terminal session and "
    "its raw output.\n\n"
    "In 'summary', condense the output to only the information relevant to a "
    "security assessment: open ports, service names/versions, discovered "
    "hosts, vulnerabilities, file paths, credentials, and other actionable "
    "findings. Remove repetitive noise, banners, and formatting clutter. "
    "Quote any credentials, paths, or flags VERBATIM - never paraphrase or "
    "approximate them. If the command failed or produced an error, clearly "
    "state the failure and its cause. Plain, concise text only - no "
    "commentary or suggestions.\n\n"
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


def _looks_like_open_prompt(raw_output: str) -> bool:
    """True only if the output looks like it ends on an unanswered
    credential prompt (username/login/password/passphrase) - condensing
    that risks paraphrasing away exactly the text the agent still needs
    verbatim, regardless of length.

    Deliberately does NOT trigger on "ends without a trailing newline" or
    "ends in :/$/>/#" alone - every run() call against the persistent
    default bash session ends that way (that's just what a shell prompt
    looks like, reappearing after every single completed command), so a
    broader check here would silently disable condensation for ordinary
    terminal output entirely, which is what happened before this was
    narrowed to only the specific credential-prompt case."""
    return bool(_CREDENTIAL_PROMPT_PATTERN.search(raw_output[-80:]))


async def _maybe_condense(
    project_id: str,
    label: str,
    raw_output: str,
    on_enumeration: Callable[[dict], None],
) -> str:
    if len(raw_output) <= CONDENSE_THRESHOLD_CHARS or _looks_like_open_prompt(raw_output):
        return raw_output
    return await _parse_output(project_id, label, raw_output, on_enumeration)


async def _install_kali_package(project_id: str, package: str) -> str:
    if not PACKAGE_NAME_PATTERN.match(package):
        return (
            f"Invalid package name '{package}'. Only a single, bare apt "
            "package name is allowed - lowercase letters, digits, '+', '-', "
            "'.', starting with a letter or digit. No flags, paths, spaces, "
            "or shell operators."
        )

    manager = await kali_registry.get_manager(project_id)

    # Shares command_lock with the (now commented-out) one-shot execute
    # path - an apt-get invocation holds dpkg's lock for its whole run, so
    # a concurrent install would fail against it anyway.
    async with manager.command_lock:
        try:
            # `env VAR=val cmd` rather than a bare `VAR=val cmd` prefix -
            # execute() wraps this in `timeout <secs> <command>`, and
            # `timeout` execs its next token directly (no shell), so a
            # leading VAR=val there isn't treated as an env assignment, it's
            # passed straight to timeout as the (nonexistent) command to
            # run, failing with exit 127. `env` is a real binary timeout can
            # exec, and it sets the var before exec'ing apt-get itself.
            output = await manager.execute(
                "env DEBIAN_FRONTEND=noninteractive apt-get install -y "
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


async def _run_kali_command(
    project_id: str, command: str, on_enumeration: Callable[[dict], None]
) -> str:
    """Retained but unused by build_agent_tools (see create_kali_tool) -
    the underlying one-shot exec path, kept intact rather than deleted in
    case the terminal/session-only model doesn't pan out."""
    manager = await kali_registry.get_manager(project_id)

    async with manager.command_lock:
        try:
            raw_output = await manager.execute(command)
        except RuntimeError as e:
            raw_output = str(e)

        if not raw_output.strip():
            return "(command produced no output)"

        return await _parse_output(project_id, command, raw_output, on_enumeration)


def create_kali_tool(project_id: str, on_enumeration: Callable[[dict], None]):
    """Builds an execute_kali_command tool bound to a specific project's
    Kali container. NOT wired into build_agent_tools right now - having
    both this one-shot path and the session tools as two ways to "run
    something" is exactly what made the agent unreliably pick between them
    (see the terminal-tools redesign). Kept intact, commented out at the
    call site, so it's a one-line change to bring back."""

    @tool(KALI_COMMAND_TOOL_NAME)
    async def execute_kali_command(command: str) -> str:
        """Executes a command in the Kali Linux container and returns a condensed
        summary of its output. Use this for anything that runs to completion
        on its own (nmap, curl, gobuster, cat, ls, ...) - note that every
        call is a fresh, independent process with no memory of previous
        calls. For anything interactive or stateful that needs to stay open
        and be driven turn by turn, use the session tools instead."""
        return await _run_kali_command(project_id, command, on_enumeration)

    return execute_kali_command


async def _save_vulnerability(vulnerability: Vulnerability) -> Vulnerability:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, db_manager.add_vulnerability, vulnerability)


CVSS4_EXAMPLE_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

# Repeated verbatim in both the tool's own error message (so a failed
# attempt gets a strong, concrete correction signal every retry, not just
# the raw pydantic-cvss error text) and the docstring below - observed in
# production: a model repeatedly substituted CVSS v3.x metric names (a bare
# "S"/"C"/"I"/"A") for v4.0's actual ones despite a correct example already
# sitting right there in the docstring, so the error path needed the same
# reference restated, not just a pointer back to instructions already
# proven not to be enough on their own.
CVSS4_METRIC_REFERENCE = (
    "CVSS v4.0 base metrics use exactly these 11 keys, in this order: "
    "AV (N/A/L/P), AC (L/H), AT (N/P), PR (N/L/H), UI (N/P/A), "
    "VC/VI/VA (H/L/N - impact on the VULNERABLE system), "
    "SC/SI/SA (H/L/N - impact on a SUBSEQUENT system, or N/N/N if none). "
    "There is no separate Scope (S) metric and no bare C/I/A metrics in "
    "v4.0 - those are CVSS v3.x names, replaced by the VC/VI/VA + SC/SI/SA "
    "pairs above. Do not mix v3 and v4 metric names."
)


def create_vulnerability_tool(
    project_id: str, target_id: str, get_mode: Callable[[], str]
):
    """Builds a report_vulnerability tool bound to a specific project/target."""

    @tool(REPORT_VULNERABILITY_TOOL_NAME)
    async def report_vulnerability(
        name: str, cvss4_vector: str, proof_of_concept: str
    ) -> str:
        """Records a confirmed vulnerability found on the current target. Only
        call this once a finding has actually been verified - not for suspected
        or untested issues. Only works while in "exploiting" mode - call
        switch_mode("exploiting", ...) first if you haven't already.

        Args:
            name: A short, descriptive name for the vulnerability.
            cvss4_vector: A valid CVSS v4.0 vector string, e.g.
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N".
                Its severity score is derived automatically - do not include
                one. CVSS v4.0 uses different base metric names than v3.x -
                VC/VI/VA and SC/SI/SA, not a bare C/I/A or a Scope (S)
                metric. If a previous attempt was rejected, the error
                message repeats this reference - follow it exactly rather
                than guessing again.
            proof_of_concept: Step-by-step instructions describing exactly how to
                verify or exploit the vulnerability, in enough detail to reproduce it.
        """
        if get_mode() != "exploiting":
            return (
                "Not in exploiting mode - call switch_mode(\"exploiting\", "
                "<reason>) first. report_vulnerability is only for a finding "
                "you have already reproduced while actively testing a "
                "specific vector, not while scouting."
            )

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
            # Only cvss4_vector is realistically ever wrong here (name/
            # proof_of_concept have no format to get wrong) - repeat the
            # metric reference and a concrete example every time, not just
            # the raw pydantic-cvss error text, since that alone was
            # observed not being enough to stop repeated wrong guesses.
            return (
                f"Could not record vulnerability, fix the input and try again: {e}\n\n"
                f"{CVSS4_METRIC_REFERENCE}\n"
                f"Example of a valid vector: {CVSS4_EXAMPLE_VECTOR}"
            )

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


def create_attack_log_tool(
    on_attempt: Callable[[dict], None], get_mode: Callable[[], str]
):
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
        after the actual attempt - a real run() call whose result you have
        actually seen. Never call this for something you only planned or
        described in your reasoning without a matching tool call actually
        running it first - "inconclusive" must mean "I tried it and the
        result was unclear", not "I thought about trying it". If you have
        not actually run the command yet, run it now instead of logging
        anything. Only works while in "exploiting" mode - call
        switch_mode("exploiting", ...) first if you haven't already. A
        logged failure keeps you (and future turns) from repeating or
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
        if get_mode() != "exploiting":
            return (
                "Not in exploiting mode - call switch_mode(\"exploiting\", "
                "<reason>) first. log_attack_attempt is only for a vector "
                "you are actively testing, not while scouting."
            )

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


def create_switch_mode_tool(on_mode_change: Callable[[str], None]):
    """Builds the switch_mode tool that toggles the agent's own working
    focus between scouting and exploiting - see agent.py's
    _render_context_message for how the current mode is re-shown every
    turn, and create_vulnerability_tool/create_attack_log_tool for the
    gating this enables."""

    @tool(SWITCH_MODE_TOOL_NAME)
    async def switch_mode(mode: str, reason: str) -> str:
        """Switches your current focus between "scouting" (broad
        enumeration/recon) and "exploiting" (testing one specific attack
        vector). Freely bidirectional - switch back and forth as many times
        as you like: scout broadly, switch to exploiting to test a specific
        finding, switch back to scouting if that didn't pan out, and so on.
        report_vulnerability and log_attack_attempt only work while in
        "exploiting" mode.

        Args:
            mode: Either "scouting" or "exploiting".
            reason: A short reason for the switch, e.g. "found FTP 21/tcp
                running vsftpd 2.3.4, want to test the known backdoor" or
                "vsftpd backdoor didn't pan out, going back to enumerate the
                remaining ports".
        """
        normalized = mode.strip().lower()
        if normalized not in VALID_MODES:
            return f"Invalid mode '{mode}'. Use one of: {', '.join(sorted(VALID_MODES))}."

        on_mode_change(normalized)
        return f"Switched to {normalized} mode: {reason}"

    return switch_mode


def create_terminal_tools(
    project_id: str, target_id: str, on_enumeration: Callable[[dict], None]
) -> list:
    """Builds the terminal-style tool set (run/new_session/switch_session/
    list_sessions/close_session/interrupt_session), bound to a project's
    Kali container and the target whose run opened them, so ending that run
    closes only its own sessions.

    One session is always "current" for this target - Agent.start_agent
    opens a "default" bash session before the first turn, and run() itself
    defensively re-opens one if every session somehow ends up closed. This
    replaces the old execute_kali_command + open/send/read/close/list
    session tools: having two ways to "run something" and, within sessions,
    two ways to "interact" (send vs read) was the actual source of the
    agent unreliably picking the wrong one - collapsing to one verb (run)
    for "do something" removes that choice entirely.

    Deliberately does NOT use manager.command_lock (a long-lived session
    must never block install_kali_package, or vice versa)."""

    @tool(RUN_TOOL_NAME)
    async def run(input: Optional[str] = None, wait_seconds: int = 5) -> str:
        """Runs something in your current terminal session - the one tool
        for actually doing anything (recon commands, interactive login
        exchanges, everything). If `input` is given, it's sent (as if typed
        and followed by Enter) to the current session first; either way,
        this then waits up to `wait_seconds` and returns whatever output
        appeared. Omit `input` to just check for new output without sending
        anything (e.g. polling something slow-running).

        You always have a current session ready to use - no setup needed.
        Use new_session/switch_session if you want a second terminal (e.g.
        to keep a listener running while continuing recon elsewhere in
        another session).

        Examples:
        - One-shot recon: run("nmap -p 21,25,53 -sV 10.0.0.5")
        - Anonymous FTP login, after run("ftp 10.0.0.5") has connected you
          to the ftp> prompt: run("anonymous") to send the username, then
          run("") to send an empty password when prompted.
        - Checking on a long-running command without sending anything:
          run(wait_seconds=15) with no input.

        Args:
            input: The line to send, without a trailing newline. Omit
                (leave as None) to only check for output.
            wait_seconds: How long to wait for output, 1-30 (default 5).
                Use a larger value for a command you expect to take a while.
        """
        manager = await kali_registry.get_manager(project_id)

        if not manager.has_current_session(target_id):
            # Defensive fallback - should only happen if every session got
            # closed without a new one being opened. start_agent() already
            # opens "default" before the first turn.
            try:
                await manager.open_session(
                    target_id, DEFAULT_SESSION_NAME, DEFAULT_SESSION_COMMAND
                )
            except KaliSessionError as e:
                return str(e)

        try:
            raw_output = await manager.run_in_current_session(
                target_id, input, read_window=wait_seconds
            )
        except KaliSessionError as e:
            return str(e)

        label = input if input is not None else "(checking for new output)"
        return await _maybe_condense(project_id, label, raw_output, on_enumeration)

    @tool(NEW_SESSION_TOOL_NAME)
    async def new_session(name: str, command: str = DEFAULT_SESSION_COMMAND) -> str:
        """Opens a new named terminal session and makes it your current
        session (run() will act on it from now on, until you switch_session
        elsewhere). Omit `command` for a plain shell; pass another
        interactive command (e.g. "ftp 10.0.0.5") to start there instead.
        Reverse-shell listeners are not a supported use of this yet.

        Only open a second session when you specifically need two terminals
        active at once - for one thing at a time, just use run() in your
        current session instead of opening a new one.

        Args:
            name: A short name for this session, e.g. "ftp" or "recon2".
            command: The shell command to run, default a plain bash shell.
        """
        manager = await kali_registry.get_manager(project_id)
        try:
            await manager.open_session(target_id, name, command)
            initial_output = await manager.run_in_current_session(
                target_id, None, read_window=SESSION_OPEN_READ_SECONDS
            )
        except KaliSessionError as e:
            return str(e)
        return f"Session '{name}' opened and is now current.\n\n{initial_output}"

    @tool(SWITCH_SESSION_TOOL_NAME)
    async def switch_session(name: str) -> str:
        """Makes an already-open session current, so run() acts on it
        instead. Use list_sessions if you've lost track of what's open."""
        manager = await kali_registry.get_manager(project_id)
        try:
            await manager.switch_session(target_id, name)
        except KaliSessionError as e:
            return str(e)
        return f"Switched to session '{name}'."

    @tool(LIST_SESSIONS_TOOL_NAME)
    async def list_sessions() -> str:
        """Lists your open terminal sessions (name and the command each is
        running), marking which one is current."""
        manager = await kali_registry.get_manager(project_id)
        sessions = await manager.list_sessions(target_id=target_id)
        if not sessions:
            return "No open sessions."
        current = manager.get_current_session_name(target_id)
        return "\n".join(
            f"{s.name}{' (current)' if s.name == current else ''}: {s.command}"
            for s in sessions
        )

    @tool(CLOSE_SESSION_TOOL_NAME)
    async def close_session(name: str) -> str:
        """Closes a session. If it was your current one, another open
        session (if any) automatically becomes current. Close a session
        once you're done with it - a small number can be open at once."""
        manager = await kali_registry.get_manager(project_id)
        await manager.close_session(target_id, name)
        return f"Session '{name}' closed."

    @tool(INTERRUPT_SESSION_TOOL_NAME)
    async def interrupt_session() -> str:
        """Sends Ctrl-C to your current session, to recover from a hung or
        unwanted foreground command (e.g. one you forgot would block, or a
        long scan you want to abandon). Returns whatever output that
        produces (usually "^C" plus a fresh prompt)."""
        manager = await kali_registry.get_manager(project_id)
        try:
            return await manager.interrupt_session(target_id)
        except KaliSessionError as e:
            return str(e)

    return [run, new_session, switch_session, list_sessions, close_session, interrupt_session]


def build_agent_tools(
    project_id: str,
    target_id: str,
    on_finish: Callable[[str], None],
    on_enumeration: Callable[[dict], None],
    on_attempt: Callable[[dict], None],
    get_mode: Callable[[], str],
    on_mode_change: Callable[[str], None],
) -> list:
    return [
        # create_kali_tool(project_id, on_enumeration),  # commented out, not
        # deleted - see create_kali_tool's docstring. The terminal tools
        # below are the agent's only way to run commands now.
        create_install_package_tool(project_id),
        *create_terminal_tools(project_id, target_id, on_enumeration),
        create_switch_mode_tool(on_mode_change),
        create_vulnerability_tool(project_id, target_id, get_mode),
        create_attack_log_tool(on_attempt, get_mode),
        create_finish_task_tool(on_finish),
    ]
