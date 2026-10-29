"""Terminal-style tool set (run/new_session/switch_session/list_sessions/
close_session/interrupt_session). See create_terminal_tools."""

import os
import re
import shlex
from typing import Callable, Dict, List, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from pydantic import BaseModel

from src.core import settings
from src.core.kali_integration import kali_registry
from src.core.kali_integration.kali_manager import KALI_USERS, KaliManger
from src.core.kali_integration.kali_session import KaliSessionError

from .common import (
    DEFAULT_SESSION_COMMAND,
    SESSION_OPEN_READ_SECONDS,
    _extract_binary_name,
    _find_binary_token,
    _get_parsing_model_num_ctx,
    _maybe_condense,
    _resolve_current_session,
    _send_and_condense,
    _package,
)

RUN_TOOL_NAME = "run"
NEW_SESSION_TOOL_NAME = "new_session"
SWITCH_SESSION_TOOL_NAME = "switch_session"
CLOSE_SESSION_TOOL_NAME = "close_session"
LIST_SESSIONS_TOOL_NAME = "list_sessions"
INTERRUPT_SESSION_TOOL_NAME = "interrupt_session"

# A junior model - especially at 8B scale - regularly gets a real CLI
# tool's own flag/argument syntax wrong (wrong flag spelling, wrong
# argument order, a flag that doesn't exist in this tool's version, ...).
# This is deliberately narrow to the SHELL/ARGUMENT-PARSING layer
# complaining about how it was invoked, not the target/service refusing
# the connection - "Connection refused"/"No route to host"/"Connection
# timed out" must NOT trigger this, since a man page can't fix a
# network-level failure and offering one there would be actively
# misleading. See _maybe_help_with_usage below.
_USAGE_ERROR_PATTERN = re.compile(
    r"command not found"
    r"|(?:invalid|unrecognized|unknown)\s+option"
    r"|invalid\s+argument"
    r"|usage:\s"
    r"|missing\s+(?:required\s+)?(?:operand|argument)"
    r"|try\s+['\"].*--help"
    r"|requires?\s+an?\s+argument",
    re.IGNORECASE,
)

# Only a plain shell prompt is something _extract_binary_name's parsing of
# `input` as a shell command line actually makes sense for - once the
# current session is INSIDE another interactive program (ftp, msfconsole,
# ...), `input` is a line typed at THAT program's own prompt, not a Kali
# shell command, and "man <first word>" would be fetching documentation
# for something that was never actually invoked as a standalone command.
_USAGE_HELP_ELIGIBLE_SESSION_COMMANDS = {DEFAULT_SESSION_COMMAND}

# Kept short - this is a quick, best-effort lookup running alongside the
# agent's regular turn, not a scan; man/--help/-h all answer near-instantly
# once the package itself is installed.
USAGE_HELP_TIMEOUT_SECONDS = 15

# Man pages can run to tens of thousands of characters (nmap's is a good
# example) - far more than a small local parsing model needs to fix one
# invocation, and more than its context window may comfortably hold
# alongside the failed command/output. Truncating from the top keeps
# NAME/SYNOPSIS (and usually the start of OPTIONS), which is what actually
# answers "what's the right flag/argument shape" - deep per-flag detail
# further down matters far less for this than for reading the whole page.
USAGE_REFERENCE_MAX_CHARS = 8000

# Escape/overstrike cleanup for `man` output read back over a non-tty exec
# (no pager) - equivalent to what `col -bx` does, done in Python instead of
# depending on the `bsdmainutils`/`util-linux` package (not guaranteed to
# be installed) providing that binary inside the container.
_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_OVERSTRIKE_PATTERN = re.compile(r".\x08")

USAGE_HELP_SYSTEM_PROMPT = (
    "You are a command-line syntax assistant supporting an autonomous "
    "penetration-testing agent working in a Kali Linux shell. The agent "
    "ran one command and it looks like the tool itself rejected the "
    "command line - wrong flag, wrong argument order, or a similar syntax "
    "mistake - not a network or target-side failure. You are given the "
    "exact command it ran, the output that came back, and a reference "
    "(a man page or --help/-h output) for that specific tool.\n\n"
    "Your ONLY job is to fix the command's SYNTAX so it runs the way the "
    "agent already intended - correct flag spelling, correct argument "
    "order/form, correct quoting. Do not change what the agent is trying "
    "to do, do not suggest a different tool, and do not suggest what "
    "target, service, or vulnerability to investigate or which one to try "
    "next - that is entirely the agent's own decision, not yours. If the "
    "reference doesn't let you tell what a valid corrected command would "
    "be, leave 'corrected_command' empty rather than guessing.\n\n"
    "In 'corrected_command', give ONE concrete, directly runnable corrected "
    "command line (empty string if you can't determine one). In "
    "'explanation', one short sentence on what was wrong with the "
    "original - syntax only, not strategy."
)


class _UsageSuggestion(BaseModel):
    corrected_command: str = ""
    explanation: str = ""


# nmap's default host-discovery probes (a ping-scan-style pass before the
# actual port scan) go to a handful of common ports (80, 443, ICMP, ...)
# that this environment's nftables rules almost never authorize for a given
# target (see kali_manager.py's prepare_nftables) - without -Pn, those
# probes are unconditionally blocked ("Operation not permitted"/"Offending
# packet" noise) and the scan is left incomplete. This isn't a judgment
# call worth asking the agent to remember every time - the starting prompt
# already says "always include -Pn", but a model deep into a long run
# doesn't reliably keep re-applying a one-time instruction from turn one
# (observed in production: exactly this failure). -Pn is correct here
# essentially unconditionally, so add it automatically rather than relying
# on the agent to.
_NMAP_PN_INJECTED_NOTE = (
    "[Note: -Pn was added to this nmap command automatically - "
    "host-discovery probes to ports outside what's authorized for this "
    "target are always blocked in this environment, so -Pn (skip host "
    "discovery, scan directly) is effectively required for every nmap "
    "invocation here.]"
)


def _inject_pn_into_one_statement(statement: str) -> tuple[str, bool]:
    """Applies _maybe_inject_nmap_pn's rewrite to a single ";"-delimited
    statement - only the segment before a pipe, if any, since anything
    piped into another command is left untouched. Returns (statement,
    False) unchanged for anything that doesn't parse, doesn't invoke nmap,
    or already has -Pn."""
    segments = statement.split("|", 1)
    try:
        tokens = shlex.split(segments[0])
    except ValueError:
        return statement, False

    index = _find_binary_token(tokens)
    if index is None or os.path.basename(tokens[index]) != "nmap":
        return statement, False
    if "-Pn" in tokens:
        return statement, False

    new_tokens = tokens[: index + 1] + ["-Pn"] + tokens[index + 1 :]
    rewritten_first_segment = shlex.join(new_tokens)
    return "|".join([rewritten_first_segment] + segments[1:]), True


def _maybe_inject_nmap_pn(command: str) -> tuple[str, bool]:
    """If `command` invokes nmap without an explicit -Pn, inserts one right
    after the nmap token (past any sudo/env/timeout prefix - see
    _find_binary_token) and returns (rewritten command, True). Returns the
    original command unchanged (and False) for anything that doesn't parse,
    doesn't invoke nmap, or already has -Pn. `command` is first split on
    ";" so every semicolon-chained statement is considered on its own
    (e.g. "nmap x; nmap y" gets -Pn injected into both) - within each
    statement, only the segment before a pipe, if any, is rewritten, since
    anything piped into another command is left untouched."""
    statements = command.split(";")
    rewritten_statements = []
    changed_any = False
    for statement in statements:
        rewritten, changed = _inject_pn_into_one_statement(statement)
        rewritten_statements.append(rewritten)
        changed_any = changed_any or changed
    return ";".join(rewritten_statements), changed_any


def _clean_man_output(text: str) -> str:
    text = _ANSI_ESCAPE_PATTERN.sub("", text)
    text = _OVERSTRIKE_PATTERN.sub("", text)
    return text


async def _fetch_usage_reference(manager: "KaliManger", binary: str) -> Optional[str]:
    """One-shot, isolated lookup of a tool's own usage documentation -
    never touches the agent's interactive session (uses manager.execute(),
    the same one-shot exec path as install_kali_package, not
    run_in_current_session), so this can't itself leave stray output
    sitting in whatever session the agent is mid-command in. Tries `man`
    first, falling back to --help/-h for tools that don't ship a man page
    at all (common for smaller/newer utilities)."""
    for candidate_command, is_man in (
        (f"MANWIDTH=100 man {binary} 2>&1", True),
        (f"{binary} --help 2>&1", False),
        (f"{binary} -h 2>&1", False),
    ):
        try:
            output = await manager.execute(
                candidate_command,
                user=KALI_USERS.momos,
                timeout_seconds=USAGE_HELP_TIMEOUT_SECONDS,
            )
        except RuntimeError:
            # Nonzero exit (e.g. "No manual entry for X", or --help itself
            # exiting non-zero as some tools do) - try the next fallback
            # rather than giving up on the first miss.
            continue

        if is_man and "no manual entry" in output.lower():
            continue

        cleaned = _clean_man_output(output).strip()
        if cleaned:
            return cleaned[:USAGE_REFERENCE_MAX_CHARS]

    return None


async def _suggest_command_fix(
    project_id: str, command: str, output: str, reference: str
) -> Optional[str]:
    """Asks the project's configured parsing model to propose a corrected
    invocation for a command that looks like it hit a syntax/usage error,
    given that tool's own man page/--help text. Returns None (never raises)
    on any failure - this is a best-effort assist layered on top of the
    regular tool result, not something that should ever break run() itself
    if the parsing model is unavailable or misbehaves."""
    # _package()._get_project_settings (not a bare call into common.py) -
    # see common._package's own docstring: keeps a test's
    # monkeypatch.setattr(agent_tools, "_get_project_settings", ...)
    # reaching this call after the split into submodules.
    project_settings = await _package()._get_project_settings(project_id)
    parsing_model_name = project_settings.parsing_model_name if project_settings else None
    if not parsing_model_name:
        return None

    num_ctx = await _get_parsing_model_num_ctx(parsing_model_name, project_settings)
    parser_llm = ChatOllama(
        model=parsing_model_name, base_url=settings.ollama_url, num_ctx=num_ctx
    )
    structured_llm = parser_llm.with_structured_output(_UsageSuggestion)

    try:
        result = await structured_llm.ainvoke(
            [
                SystemMessage(content=USAGE_HELP_SYSTEM_PROMPT),
                HumanMessage(
                    content=(
                        f"Command attempted:\n{command}\n\n"
                        f"Output/error:\n{output}\n\n"
                        f"Reference (man/--help) for this tool:\n{reference}"
                    )
                ),
            ]
        )
    except Exception as e:
        print(f"Usage-help suggestion failed, skipping: {e}")
        return None

    corrected = result.corrected_command.strip()
    if not corrected:
        return None

    note = f"Suggested corrected command: {corrected}"
    if result.explanation.strip():
        note += f" ({result.explanation.strip()})"
    return note


def create_terminal_tools(
    project_id: str,
    target_id: str,
    agent_run_id: str,
    on_enumeration: Callable[[dict], None],
    mark_tested: Callable[[], None],
    on_session_change: Callable[[Optional[str], Optional[str]], None],
    on_prompt_state_change: Callable[[bool], None],
    on_raw_output: Callable[[str], None],
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

    # Per-run cache of a binary's man/--help text, keyed by binary name -
    # shared by every call to _maybe_help_with_usage below. A man page is
    # static reference material, so there's no reason to re-fetch it from
    # the container every time the agent mis-invokes the same tool again
    # in a different way; only the parsing-model suggestion (which depends
    # on the specific failed command) is ever redone.
    _usage_reference_cache: Dict[str, Optional[str]] = {}

    async def _maybe_help_with_usage(command: str, raw_output: str) -> Optional[str]:
        """Best-effort syntax-fix suggestion for a command that looks like
        it hit a CLI usage/argument-parsing error (see _USAGE_ERROR_PATTERN)
        - fetches that tool's own man page/--help (cached per binary) and
        asks the parsing model to propose a corrected invocation. Returns
        None whenever it can't help or anything along the way fails; never
        raises, since this rides along with the regular tool result and
        must never be the reason a real run() call fails."""
        if not _USAGE_ERROR_PATTERN.search(raw_output):
            return None

        try:
            manager = await kali_registry.get_manager(project_id)
            current_name = manager.get_current_session_name(target_id, agent_run_id)
            sessions = await manager.list_sessions(target_id, agent_run_id)
            current = next((s for s in sessions if s.name == current_name), None)
            if (
                current is None
                or current.command not in _USAGE_HELP_ELIGIBLE_SESSION_COMMANDS
                or not current.at_shell_prompt
            ):
                # Not a plain shell prompt (e.g. mid-way through ftp/
                # msfconsole) - `command` isn't a Kali shell command line
                # here, so "man <first word>" wouldn't mean anything.
                # current.command alone isn't enough to catch this: it only
                # changes via new_session, so an interactive program
                # launched as a plain run() input (e.g. run("ftp <host>"))
                # never updates it - at_shell_prompt (updated from the
                # session's own live output, see kali_manager.py's
                # _looks_like_shell_prompt) is what actually detects that
                # case.
                return None

            binary = _extract_binary_name(command)
            if not binary:
                return None

            if binary in _usage_reference_cache:
                reference = _usage_reference_cache[binary]
            else:
                reference = await _fetch_usage_reference(manager, binary)
                _usage_reference_cache[binary] = reference

            if not reference:
                return None

            return await _suggest_command_fix(project_id, command, raw_output, reference)
        except Exception as e:
            print(f"Usage-help lookup failed, skipping: {e}")
            return None

    @tool(RUN_TOOL_NAME, response_format="content_and_artifact")
    async def run(input: Optional[str] = None, wait_seconds: int = 8) -> str:
        """Runs something in your current terminal session - the one tool
        for actually doing anything (recon commands, interactive login
        exchanges, everything). If `input` is given, it's sent (as if typed
        and followed by Enter) to the current session first; either way,
        this then waits for `wait_seconds` of continuous quiet in the
        session before returning everything that appeared - never a
        partial, still-in-progress read. Omit `input` to just wait for new
        output without sending anything (e.g. picking up more from
        something already running in the background in another session).

        Omitting `input` never sends anything, no matter what you just
        said you were about to run - it only waits on whatever is already
        happening in the session (which, on an otherwise-idle session, is
        nothing at all, and this will simply time out empty). If you have
        decided on a command to run, put it directly in `input` on THIS
        call - do not call run() with no input first "to check", planning
        to send the actual command on a later turn.

        You always have a current session ready to use - no setup needed.
        Use new_session/switch_session if you want a second terminal (e.g.
        to keep a listener running while continuing recon elsewhere in
        another session). Do NOT background a command in your CURRENT
        session (e.g. "nmap ... &") to try to get the same effect - its
        output arrives on the same connection as everything else you send
        afterward, with no way to tell it apart from a later, unrelated
        run() call's own output. Open a second session with new_session
        instead whenever you want something running in parallel. Likewise,
        run("/bin/bash") or re-running any other shell binary inside your
        current session does NOT give you a fresh terminal - it just types
        that program's name at whatever prompt you're currently at; use
        new_session for an actual second terminal.

        If a command you send at your plain shell prompt looks like it
        failed on its own syntax (wrong flag, wrong argument form, ...),
        the result may include a line starting "Suggested corrected
        command:" - that's looked up from the tool's own documentation for
        you; it only ever fixes how a command is written, never what to
        run or why, which stays entirely your own call.

        Since this always waits out the FULL `wait_seconds` of quiet before
        returning, set it based on the longest pause the command might take
        while it's still working, not just its typical total runtime - a
        command can print a little (a banner, a warning) and then go quiet
        for real seconds while it keeps computing before printing its
        actual result. Too short a `wait_seconds` is what returns a
        partial result; when in doubt, prefer a larger value over a
        smaller one. Only fall back to a follow-up run() with no input if
        a command outlasts even a generous wait_seconds. Only use
        interrupt_session once a follow-up wait still shows nothing at all
        - not just because one call is taking a while.

        Examples:
        - One-shot recon: run("nmap -Pn -sV <target>") - the `-Pn` skips
          host-discovery probes to ports outside what's authorized here,
          which would otherwise be blocked and print irrelevant permission
          errors.
        - A scan expected to have long internal pauses: run("nmap -Pn -p- -sV <target>", wait_seconds=120)
        - Driving an interactive program one line at a time, after
          run("python3") has dropped you at its ">>>" prompt: run("print(1+1)")
          sends that single line and returns its output, exactly as if typed.
          An interactive network client works the same way - connect with
          one run() call, then send each subsequent line as its own call.

        Args:
            input: The line to send, without a trailing newline. Omit
                (leave as None) to only wait for output.
            wait_seconds: How long the session must stay completely quiet
                before its output is considered complete, 1-1800 (default
                8). The call always waits this long, even for a command
                that finishes sooner - set it based on the longest pause
                the command might have mid-run, not just how long it
                usually takes overall.
        """
        manager = await kali_registry.get_manager(project_id)

        try:
            current_session, session_was_replaced = await _resolve_current_session(
                manager, target_id, agent_run_id, on_session_change
            )
        except KaliSessionError as e:
            return str(e), None

        # -Pn is effectively required for every nmap invocation in this
        # environment (see _maybe_inject_nmap_pn's own comment) - rather
        # than relying on the agent to keep re-applying the starting
        # prompt's one-time "always include -Pn" instruction over a long
        # run, add it automatically whenever it's missing. Only makes sense
        # to parse `input` as a shell command line at all when the current
        # session is a plain shell - inside another interactive program
        # (ftp, msfconsole, ...) it's a line typed at THAT program's own
        # prompt, not a Kali shell command.
        nmap_pn_injected = False
        if (
            input is not None
            and current_session is not None
            and current_session.command == DEFAULT_SESSION_COMMAND
            and current_session.at_shell_prompt
        ):
            input, nmap_pn_injected = _maybe_inject_nmap_pn(input)

        condensed, raw_output = await _send_and_condense(
            manager,
            project_id,
            target_id,
            agent_run_id,
            current_session,
            input,
            wait_seconds,
            on_enumeration,
            mark_tested,
            on_session_change,
            on_prompt_state_change,
            on_raw_output,
            session_was_replaced=session_was_replaced,
        )
        if raw_output is None:
            return condensed, None

        # Detection runs against the RAW output, before condensation may
        # paraphrase away the exact wording the regex looks for - only
        # matters when input was actually sent (a bare poll never invoked
        # a command in the first place).
        if input is not None:
            usage_note = await _maybe_help_with_usage(input, raw_output)
            if usage_note:
                condensed = f"{condensed}\n\n{usage_note}"

        if nmap_pn_injected:
            condensed = f"{_NMAP_PN_INJECTED_NOTE}\n\n{condensed}"

        return condensed, raw_output

    @tool(NEW_SESSION_TOOL_NAME, response_format="content_and_artifact")
    async def new_session(name: str, command: str = DEFAULT_SESSION_COMMAND) -> str:
        """Opens a new named terminal session and makes it your current
        session (run() will act on it from now on, until you switch_session
        elsewhere). Omit `command` for a plain shell; pass another
        interactive command (e.g. "ftp <target>", "msfconsole -q") to start
        there instead. Reverse-shell listeners are not a supported use of
        this yet.

        Once `command` is an interactive program, you are AT ITS OWN PROMPT
        from the very next run() call onward - send exactly what you would
        type into that program directly, one command per run() call, not
        the program's own launch command again (e.g. after
        new_session("msf", "msfconsole -q"), send run("use <module>"), then
        run("set RHOSTS <target>"), then run("run") - never another
        "msfconsole ..." into that same session, which most such programs
        refuse or mishandle as
        an attempt to nest themselves). Also don't assume chaining several
        of the program's own commands with ";" on one line works the way it
        does in bash - many interactive programs (msfconsole included) only
        support that for their own one-shot startup flag, not for lines
        typed at their prompt afterward; when unsure, send one command per
        run() call.

        Some interactive programs' own prompts ask for a bare VALUE, not a
        protocol command - ftp is the clearest example: its "Name
        (host:...):" prompt wants just the username itself (e.g.
        "anonymous"), and its "Password:" prompt wants just the password
        itself (which can be empty - just send nothing after the prompt,
        or a dummy value like an email address), NOT the literal words
        "USER anonymous" or "PASS" - the client already constructs those
        actual protocol commands itself from what you type. Typing "USER
        anonymous" at the Name prompt sends a literal username of "USER
        anonymous" to the server, not "anonymous" - a real, observed cause
        of an anonymous-login test failing that had nothing to do with the
        target actually blocking it. If you want to send the raw protocol
        commands yourself instead (e.g. against a plain socket via
        telnet/nc), that's a different situation - there, typing "USER
        anonymous" IS correct, because there's no client wrapping your
        input.

        Only open a second session when you specifically need two terminals
        active at once - for one thing at a time, just use run() in your
        current session instead of opening a new one.

        Args:
            name: A short name for this session, e.g. "ftp" or "recon2".
            command: The shell command to run, default a plain bash shell.
        """
        manager = await kali_registry.get_manager(project_id)
        try:
            await manager.open_session(target_id, agent_run_id, name, command)
            initial_output = await manager.run_in_current_session(
                target_id, agent_run_id, None, wait_seconds=SESSION_OPEN_READ_SECONDS
            )
        except KaliSessionError as e:
            return str(e), None

        # Opening a session launches `command` for real against the
        # container - counts as testing the same way run()'s mark_tested
        # does when input is actually sent (see the comment there). Matches
        # what Agent.__init__'s own comment on _tested_since_claim already
        # documents as the intended gate ("a real run()/new_session()
        # call") - this was previously never implemented.
        mark_tested()
        on_session_change(name, command)
        on_raw_output(initial_output)

        condensed = await _maybe_condense(
            project_id,
            command,
            initial_output,
            on_enumeration,
            session_command=command,
        )
        return f"Session '{name}' opened and is now current.\n\n{condensed}", initial_output

    @tool(SWITCH_SESSION_TOOL_NAME, response_format="content_and_artifact")
    async def switch_session(name: str) -> str:
        """Makes an already-open session current, so run() acts on it
        instead, and shows whatever that session has produced since you were
        last on it (or since it opened, if you've never checked). Use
        list_sessions if you've lost track of what's open."""
        manager = await kali_registry.get_manager(project_id)
        try:
            await manager.switch_session(target_id, agent_run_id, name)
        except KaliSessionError as e:
            return f"{e} Use list_sessions to see what's currently open.", None
        current = manager.get_current_session(target_id, agent_run_id)
        if current is None:
            return f"Switched to session '{name}'.", None

        on_session_change(current.name, current.command)

        # Show what's actually happening in the session being switched to,
        # not just confirm the pointer moved - the same "did this actually
        # work" ambiguity F4 addresses for new_session applies here too,
        # e.g. switching back to a quiet `nc` session with no way to tell
        # whether it's still alive.
        try:
            initial_output = await manager.run_in_current_session(
                target_id, agent_run_id, None, wait_seconds=SESSION_OPEN_READ_SECONDS
            )
        except KaliSessionError as e:
            return f"Switched to session '{name}'.\n\n{e}", None
        on_raw_output(initial_output)
        condensed = await _maybe_condense(
            project_id,
            current.command,
            initial_output,
            on_enumeration,
            session_command=current.command,
        )
        return f"Switched to session '{name}'.\n\n{condensed}", initial_output

    @tool(LIST_SESSIONS_TOOL_NAME)
    async def list_sessions() -> str:
        """Lists your open terminal sessions (name and the command each is
        running), marking which one is current."""
        manager = await kali_registry.get_manager(project_id)
        sessions = await manager.list_sessions(target_id, agent_run_id)
        if not sessions:
            return "No open sessions."
        current = manager.get_current_session_name(target_id, agent_run_id)
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
        # Deliberately NOT force=True (unlike the console's own close) -
        # LangGraph's ToolNode runs a turn's tool calls concurrently
        # (asyncio.gather - see agent.py's own comment on this), so a turn
        # that calls both interrupt_session() and close_session() on the
        # same session would otherwise race: force-closing could sever the
        # socket out from under interrupt_session's own still-in-flight
        # read instead of letting it finish first, as the safe-wait
        # default always has.
        existed = await manager.close_session(target_id, agent_run_id, name)
        if not existed:
            return (
                f"No such session '{name}' - nothing to close (it may "
                "already be closed, idle-timed-out, or never existed)."
            )
        current = manager.get_current_session(target_id, agent_run_id)
        on_session_change(
            current.name if current else None, current.command if current else None
        )
        return f"Session '{name}' closed."

    @tool(INTERRUPT_SESSION_TOOL_NAME)
    async def interrupt_session() -> str:
        """Sends Ctrl-C to your current session, to recover from a
        genuinely hung or unwanted foreground command (e.g. one you forgot
        would block, or a long scan you deliberately want to abandon).
        Returns whatever output that produces (usually "^C" plus a fresh
        prompt).

        run() itself already waits for a command to actually finish rather
        than returning early, so reach for this only once a follow-up
        run() with no input still shows no progress at all - not just
        because a command is taking a while."""
        manager = await kali_registry.get_manager(project_id)
        try:
            raw_output = await manager.interrupt_session(target_id, agent_run_id)
        except KaliSessionError as e:
            return str(e)
        return await _maybe_condense(
            project_id, "(sending Ctrl-C)", raw_output, on_enumeration
        )

    return [run, new_session, switch_session, list_sessions, close_session, interrupt_session]
