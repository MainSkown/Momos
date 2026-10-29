"""Tier 2: guided wrappers around the three interactive protocols the agent
needs most often (ftp/ssh/telnet). See create_guided_session_tools."""

import re
import shlex
from typing import Callable, Dict, Optional

from langchain_core.tools import tool

from src.core.kali_integration import kali_registry
from src.core.kali_integration.kali_manager import KaliManger
from src.core.kali_integration.kali_session import KaliSessionError

from .common import (
    SESSION_OPEN_READ_SECONDS,
    _execute_one_shot,
    _get_target_host,
    _maybe_condense,
    _send_and_condense,
)

FTP_CONNECT_TOOL_NAME = "ftp_connect"
FTP_COMMAND_TOOL_NAME = "ftp_command"
SSH_CHECK_LOGIN_TOOL_NAME = "ssh_check_login"
SSH_RUN_TOOL_NAME = "ssh_run"
TELNET_PROBE_TOOL_NAME = "telnet_probe"

# How long ftp_command waits for a command's real output - deliberately
# longer than common's SESSION_OPEN_READ_SECONDS (which is for a
# banner/prompt, not an actual command result - ls/get/put can
# legitimately take a while). Session-io's own prompt-reappearance
# early-exit (ftp's "ftp> " - see kali_manager's _EXTRA_READY_PATTERNS)
# still returns well before this on an ordinary successful command; this
# is the ceiling for a slow one, not the typical wait.
FTP_COMMAND_READ_SECONDS = 20
SSH_CHECK_LOGIN_TIMEOUT_SECONDS = 20
SSH_RUN_TIMEOUT_SECONDS = 60
TELNET_PROBE_TIMEOUT_SECONDS = 15

FTP_SESSION_NAME = "ftp"

# "150 ..." (data connection opening) with no "226 .../425 .../426 ..."
# (transfer complete/failed) anywhere after it means the data connection
# itself never resolved within the wait window - real output (a listing,
# a file) would only ever arrive over that connection, so this is
# specifically the "data channel stalled" case (e.g. an active-mode PORT
# whose callback can't reach this sandbox), not a genuinely empty result.
# Line-anchored on the reply code, same reasoning as ftp_connect's own
# "^230[ -]" check below - a bare \b150\b could match inside unrelated
# text (a file named "150", a byte count).
_FTP_DATA_OPEN_PATTERN = re.compile(r"(?m)^150[ -]")
_FTP_DATA_DONE_PATTERN = re.compile(r"(?m)^(226|425|426)[ -]")


def _ftp_data_connection_stalled(raw_output: str) -> bool:
    return bool(_FTP_DATA_OPEN_PATTERN.search(raw_output)) and not _FTP_DATA_DONE_PATTERN.search(
        raw_output
    )


# The classic ftp client's own local (no server round-trip) confirmation of
# the "passive" toggle - "Passive mode on." exactly, printed the instant the
# client processes the command. Used to verify _send_ftp_passive actually
# took effect before trusting KaliSession.ftp_passive = True, rather than
# assuming it always works.
_FTP_PASSIVE_CONFIRMED_PATTERN = re.compile(r"Passive mode on", re.IGNORECASE)

# Observed in production on a session that HAD been toggled passive
# (ftp_passive True, confirmed on) but still fell back to an active-mode
# PORT for an individual data-connection command - the server rejected the
# PORT ("500 Illegal PORT command.") and/or the client failed to bind its
# own local data socket for it ("Can't bind for data connection..."). This
# is a different failure than _ftp_data_connection_stalled above (that one
# never even gets an initial "150" reply) - here the client is unmistakably
# back in active mode for this one transfer, despite the session-level
# toggle. Root cause not fully confirmed (client-specific PASV/EPSV
# fallback behavior against this target could not be verified without a
# live client) - detecting the symptom is what actually matters here, since
# the raw output otherwise just looks like meaningless noise to the agent.
_FTP_ACTIVE_FALLBACK_PATTERN = re.compile(
    r"Illegal PORT command|Can.?t bind for data connection", re.IGNORECASE
)


def _ftp_active_mode_fallback(raw_output: str) -> bool:
    return bool(_FTP_ACTIVE_FALLBACK_PATTERN.search(raw_output))


# The classic ftp client's own real command set (from its `?`/`help`
# listing), trimmed to what's actually useful/safe for ftp_command to send
# - checked BEFORE anything reaches the session, so a typo/hallucinated
# command gets an immediate, structured correction instead of round-
# tripping to the real ftp process for its own bare "?Invalid command"
# (observed in production: the model would then just retry more garbage
# against that same unhelpful reply, looping instead of self-correcting).
# Deliberately excludes, by category, from the full real command set:
# - Session lifecycle ("open", "close", "bye", "disconnect"): handled by
#   ftp_connect/close_session, not this tool - sending these here would
#   tear down or repoint the connection those tools are managing.
# - Login ("user"): ftp_connect's own job - re-sending it mid-session is
#   already documented above (see ftp_connect) to get a real but
#   misleading "530 Can't change from guest user" reply.
# - "passive": _send_ftp_passive already toggles this exactly once per
#   session (see _send_ftp_passive's own docstring) - it's a TOGGLE, not a
#   setting, so the model sending it again would flip the session back to active
#   mode and reintroduce the exact data-connection hang that fix exists to
#   prevent.
# - Everything that would have the same effect indirectly ("sendport"
#   forces active-mode PORT explicitly; "epsv4"/"ipany"/"ipv4"/"ipv6"
#   change the address-family/EPSV negotiation the passive-mode fix's
#   227/229 reply parsing depends on) - excluded for the same reason as
#   "passive" itself.
# - Local shell/macro escape hatches ("$", "macdef"): "$" invokes a
#   locally-defined macro, "macdef" defines one (multi-line, which
#   ftp_command's own newline check already refuses anyway) - no
#   legitimate use here and an unnecessary shell-adjacent risk.
# - Legacy protocol-tuning knobs essentially never needed against a real
#   target ("mode", "form", "struct", "ntrans", "tenex", "sunique",
#   "runique", "proxy", and ftp's own "nmap" - a filename-mapping-template
#   command from the 1980s, NOT the network scanner, kept out partly to
#   avoid any confusion with the real nmap_scan tool).
# - Interactive/display-only toggles with no value to a non-interactive
#   caller that only reads final text output ("bell", "case", "cr",
#   "hash", "verbose", "debug", "trace", "glob", "reset", "umask", "?",
#   and "image", a redundant alias of "binary").
# "quote" is deliberately KEPT as the escape hatch for any real FTP
# protocol verb not covered by a named command above.
_FTP_ALLOWED_COMMANDS = frozenset(
    {
        # Navigation/listing
        "cd", "cdup", "pwd", "ls", "dir", "mls", "mdir", "nlist", "lcd", "lpwd",
        # Transfer
        "get", "mget", "put", "mput", "append", "recv", "send",
        # Remote file operations
        "mkdir", "rmdir", "delete", "mdelete", "rename", "chmod",
        # Metadata/recon
        "size", "modtime", "status", "rstatus", "rhelp", "help", "idle",
        # Transfer type
        "ascii", "binary", "type",
        # Auth/server passthrough
        "account", "site", "quote",
        # Transfer control
        "restart",
        # Suppresses mget/mput's per-file y/n confirmation, which this
        # tool has no way to answer - without turning this off first, a
        # multi-file mget/mput would sit waiting on a prompt forever.
        "prompt",
    }
)


async def _ensure_ftp_session(
    manager: KaliManger, target_id: str, agent_run_id: str, host: str, on_session_change
):
    """Opens target_id/agent_run_id's 'ftp' session if it doesn't exist yet
    (running `ftp -n {host}` - -n suppresses ftp's own immediate auto-login
    prompt, since login is driven explicitly via the `user` command in
    ftp_connect below, not the interactive Name:/Password: exchange), or
    switches to it if it already exists - either way, returns the
    now-current KaliSession for it, plus whether this call itself opened a
    brand-new session (vs. reusing an already-open, possibly already-
    authenticated one - see ftp_connect's _ftp_logged_in tracking)."""
    command = f"ftp -n {host}"
    sessions = await manager.list_sessions(target_id, agent_run_id)
    existing = next((s for s in sessions if s.name == FTP_SESSION_NAME and not s.closed), None)
    freshly_opened = existing is None
    if existing is None:
        await manager.open_session(target_id, agent_run_id, FTP_SESSION_NAME, command)
    elif manager.get_current_session_name(target_id, agent_run_id) != FTP_SESSION_NAME:
        await manager.switch_session(target_id, agent_run_id, FTP_SESSION_NAME)
    on_session_change(FTP_SESSION_NAME, command)
    return manager.get_current_session(target_id, agent_run_id), freshly_opened


async def _send_ftp_passive(
    manager: KaliManger,
    project_id: str,
    target_id: str,
    agent_run_id: str,
    current_session,
    on_enumeration: Callable[[dict], None],
    mark_tested: Callable[[], None],
    on_session_change: Callable[[Optional[str], Optional[str]], None],
    on_prompt_state_change: Callable[[bool], None],
    on_raw_output: Callable[[str], None],
) -> tuple:
    """Toggles the classic ftp client into passive mode - called exactly
    once, right after a freshly opened FTP session and before login (see
    ftp_connect). The client defaults to ACTIVE mode (PORT), which makes
    the TARGET open a brand-new inbound connection back into this sandbox
    for every data-connection command (ls, get, put, ...); that callback
    has nowhere to land here, so the command just hangs until
    ftp_command's own read window gives up, returning little more than
    its own echoed input (confirmed in production). Passive mode instead
    has the client open the data connection itself, matching how curl's
    own FTP support already behaves in this codebase.

    "passive" is ftp's own interactive TOGGLE command, not a persisted
    setting - sending it a second time on an already-passive session
    would switch it back to active, so this must only ever be called once
    per freshly opened session, never on an already-open one."""
    return await _send_and_condense(
        manager,
        project_id,
        target_id,
        agent_run_id,
        current_session,
        "passive",
        SESSION_OPEN_READ_SECONDS,
        on_enumeration,
        mark_tested,
        on_session_change,
        on_prompt_state_change,
        on_raw_output,
    )


def create_guided_session_tools(
    project_id: str,
    target_id: str,
    agent_run_id: str,
    on_enumeration: Callable[[dict], None],
    mark_tested: Callable[[], None],
    on_session_change: Callable[[Optional[str], Optional[str]], None],
    on_prompt_state_change: Callable[[bool], None],
    on_raw_output: Callable[[str], None],
) -> list:
    """Tier 2: guided wrappers around the three interactive protocols the
    agent needs most often (ftp/ssh/telnet), for when it doesn't know -
    or keeps getting wrong - the underlying client's own syntax (observed
    in production: typing the raw USER/PASS wire-protocol commands into
    ftp's interactive Name:/Password: prompts, which want bare values).
    Unlike Tier 1, ftp_connect/ftp_command use the real session machinery
    (common._resolve_current_session/_send_and_condense - the same helpers
    run() itself uses), so they get the exact same stuck-session confusion
    detection and auto-recovery for free."""

    # Per-target FTP login state, closure-scoped (fresh per Agent/run, so
    # it can never leak across independent test runs the way a module-level
    # dict would). Lets ftp_connect tell "already logged in, this re-auth
    # attempt is pointless" apart from "actually failed" - see ftp_connect's
    # own comment for the production bug this fixes.
    _ftp_logged_in: Dict[str, bool] = {}

    @tool(FTP_CONNECT_TOOL_NAME, response_format="content_and_artifact")
    async def ftp_connect(username: str = "anonymous", password: str = "") -> str:
        """Connects to this run's target's FTP service and logs in -
        handles ftp's own login sequence for you, so there's no need to
        figure out its interactive Name:/Password: prompts or type raw
        protocol commands (USER/PASS) yourself; just give the credentials
        to try. Only call this once per set of credentials - once it
        reports a successful login, the session is already open and
        authenticated, so use ftp_command for everything else (ls, get,
        pwd, cd, ...) instead of calling this again. Only retry this tool
        if the previous call actually failed (login failed, connection
        dropped), you need to try different credentials, or an
        ftp_command result explicitly told you to (e.g. after an
        active-mode fallback) - it's safe to call again on an already-open
        session, it just confirms that rather than re-authenticating.

        Args:
            username: FTP username to try. Defaults to "anonymous".
            password: Password to try. Defaults to blank (the
                anonymous-FTP convention).
        """
        if "\n" in username or "\r" in username or "\n" in password or "\r" in password:
            return "Username/password cannot contain newlines.", None

        host, error = await _get_target_host(target_id)
        if error:
            return error, None

        manager = await kali_registry.get_manager(project_id)
        try:
            current_session, freshly_opened = await _ensure_ftp_session(
                manager, target_id, agent_run_id, host, on_session_change
            )
        except KaliSessionError as e:
            return str(e), None

        # Checked independently of freshly_opened - see KaliSession.ftp_passive's
        # own comment. A session can be "not freshly opened" (this run just
        # found it already there) while still never having been toggled
        # passive itself (opened by an earlier run, before this fix, or by
        # a version of ftp_connect that predates it) - gating on
        # freshly_opened alone left exactly that session stuck in ftp's
        # active mode forever.
        passive_raw = ""
        if not current_session.ftp_passive:
            passive_condensed, passive_raw = await _send_ftp_passive(
                manager,
                project_id,
                target_id,
                agent_run_id,
                current_session,
                on_enumeration,
                mark_tested,
                on_session_change,
                on_prompt_state_change,
                on_raw_output,
            )
            if passive_raw is None:
                return passive_condensed, None
            current_session = manager.get_current_session(target_id, agent_run_id)
            # Only trust the toggle if the client's own local confirmation
            # ("Passive mode on.") actually came back - previously this was
            # set unconditionally, which papered over the toggle silently
            # not landing and left ftp_passive stuck True forever (nothing
            # else ever retries it once set, so every future data-connection
            # command on this session would keep hitting active mode with
            # no way to recover short of closing the session outright).
            current_session.ftp_passive = bool(
                _FTP_PASSIVE_CONFIRMED_PATTERN.search(passive_raw)
            )

        if freshly_opened:
            _ftp_logged_in[target_id] = False
        elif _ftp_logged_in.get(target_id):
            # Don't just trust the cached flag - observed in production: the
            # target's own idle timeout closes the control connection
            # ("421 Timeout") without the wrapper session ever closing (the
            # ftp CLI process stays alive, just replying "Not connected."
            # to everything), so _ftp_logged_in silently went stale. Without
            # this probe, every later ftp_connect call kept claiming
            # "already connected" forever while every ftp_command kept
            # getting "Not connected." - a dead end with no way to recover.
            # A cheap read-only command (not `user` - see below) is enough
            # to tell a live session from a dead one.
            probe_condensed, probe_raw = await _send_and_condense(
                manager,
                project_id,
                target_id,
                agent_run_id,
                current_session,
                "pwd",
                FTP_COMMAND_READ_SECONDS,
                on_enumeration,
                mark_tested,
                on_session_change,
                on_prompt_state_change,
                on_raw_output,
            )
            if probe_raw is not None and "Not connected." not in probe_raw:
                return (
                    "Already connected and logged in on this FTP session - "
                    "no need to reconnect. Use ftp_command for anything "
                    "else (ls, get, pwd, cd, ...).",
                    None,
                )
            # The session is actually dead - fall through to the normal
            # login flow below. Re-sending `user` into an already-
            # authenticated (but still alive) session gets a real but
            # misleading "530 Can't change from guest user" - vsftpd
            # correctly refusing re-authentication mid-session, which the
            # (correct) reply-code regex below reads as "Login failed" even
            # though the session is fine - that's exactly why this branch
            # only reaches `user` after confirming the session is dead, not
            # unconditionally.
            _ftp_logged_in[target_id] = False

        # Sent as two separate lines, mirroring exactly what a human typing
        # at ftp's own interactive Name:/Password: prompts would send - NOT
        # "user <name> <password>" on one line. A blank password
        # interpolated into one line contributes no second token at all
        # (observed in production: the anonymous-FTP case left the session
        # sitting unanswered at its own "Password:" sub-prompt, since
        # nothing was ever sent for it).
        condensed, raw_output = await _send_and_condense(
            manager,
            project_id,
            target_id,
            agent_run_id,
            current_session,
            f"user {username}",
            SESSION_OPEN_READ_SECONDS,
            on_enumeration,
            mark_tested,
            on_session_change,
            on_prompt_state_change,
            on_raw_output,
        )
        if raw_output is None:
            return condensed, None

        # "Not connected." is ftp's own client-side reply to `user` when
        # there is no actual control connection to send it over - observed
        # in production on a session _ensure_ftp_session reused that had
        # gone dead (sessions aren't closed between agent runs, only
        # "default" is touched at run start - see Agent.start_agent), which
        # then stayed broken for the rest of every subsequent run against
        # this target, since nothing else ever re-opens it. One automatic
        # close+reopen+retry here, rather than reporting a dead session as
        # just another "unclear" login outcome.
        if "Not connected." in raw_output:
            await manager.close_session(target_id, agent_run_id, FTP_SESSION_NAME)
            try:
                current_session, _ = await _ensure_ftp_session(
                    manager, target_id, agent_run_id, host, on_session_change
                )
            except KaliSessionError as e:
                return str(e), None
            _ftp_logged_in[target_id] = False
            passive_condensed, passive_raw = await _send_ftp_passive(
                manager,
                project_id,
                target_id,
                agent_run_id,
                current_session,
                on_enumeration,
                mark_tested,
                on_session_change,
                on_prompt_state_change,
                on_raw_output,
            )
            if passive_raw is None:
                return passive_condensed, None
            current_session = manager.get_current_session(target_id, agent_run_id)
            current_session.ftp_passive = bool(
                _FTP_PASSIVE_CONFIRMED_PATTERN.search(passive_raw)
            )
            condensed, raw_output = await _send_and_condense(
                manager,
                project_id,
                target_id,
                agent_run_id,
                current_session,
                f"user {username}",
                SESSION_OPEN_READ_SECONDS,
                on_enumeration,
                mark_tested,
                on_session_change,
                on_prompt_state_change,
                on_raw_output,
            )
            if raw_output is None:
                return condensed, None
            if "Not connected." in raw_output:
                return (
                    "Could not establish an FTP control connection to this "
                    "target even after reopening the session - the service "
                    "may be down or unreachable right now rather than a "
                    "stale-session issue. Re-check with nmap_scan before "
                    "retrying.",
                    raw_output,
                )

        # Only sent if the ftp session is still the current one - a
        # confusion-streak promotion triggered by the line above (unlikely
        # this early, but possible if the session was already stuck from an
        # earlier attempt) would otherwise send the password into whatever
        # session became current instead.
        if manager.get_current_session_name(target_id, agent_run_id) == FTP_SESSION_NAME:
            current_session = manager.get_current_session(target_id, agent_run_id)
            condensed2, raw_output2 = await _send_and_condense(
                manager,
                project_id,
                target_id,
                agent_run_id,
                current_session,
                password,
                SESSION_OPEN_READ_SECONDS,
                on_enumeration,
                mark_tested,
                on_session_change,
                on_prompt_state_change,
                on_raw_output,
            )
            if raw_output2 is not None:
                condensed = f"{condensed}\n{condensed2}"
                raw_output = f"{raw_output}\n{raw_output2}"

        # Line-anchored, real FTP reply-code format ("CODE text" or
        # "CODE-text" at the START of a line) - NOT a bare \b23\d\b
        # anywhere in the text. Observed in production: that looser form
        # matched "235" inside the target's own IP address
        # (192.168.0.235, echoed back in "Connected to ...") and reported
        # a successful login before the password had even been sent.
        if re.search(r"(?m)^230[ -]", raw_output):
            prefix = "Login successful."
            _ftp_logged_in[target_id] = True
        elif re.search(r"(?m)^5\d\d[ -]", raw_output):
            prefix = "Login failed."
            _ftp_logged_in[target_id] = False
        else:
            prefix = "Login outcome unclear from the response - check the raw output below."

        if not current_session.ftp_passive:
            prefix = (
                f"{prefix} Passive mode could not be confirmed for this "
                "session - data-connection commands (ls, get, ...) may "
                "fall back to active mode and fail; a later ftp_command "
                "hitting 'Illegal PORT command'/'Can't bind for data "
                "connection' means this needs another ftp_connect."
            )

        # Appended purely for visibility/debugging (never affects the
        # login-outcome classification above, which only looks at the
        # user/password exchange) - passive_raw was previously discarded
        # entirely, leaving no way to tell after the fact whether the
        # client's own "Passive mode on." confirmation ever actually came
        # back.
        if passive_raw:
            raw_output = f"{passive_raw}\n{raw_output}"

        return f"{prefix}\n\n{condensed}", raw_output

    @tool(FTP_COMMAND_TOOL_NAME, response_format="content_and_artifact")
    async def ftp_command(command: str) -> str:
        """Sends one command to your already-open, already-authenticated
        FTP session (ls, get, pwd, cd, binary, ...) - call ftp_connect
        first if you haven't yet, but once it reports a successful login
        you are already logged in and should use this tool for every
        further command instead of calling ftp_connect again. Not gated
        by shell access: ftp's own command grammar can't reach outside
        the already-open connection to the target.

        Only a fixed set of real ftp commands is accepted - navigation
        (cd, cdup, pwd, ls, dir, mls, mdir, nlist, lcd, lpwd), transfer
        (get, mget, put, mput, append, recv, send), remote file operations
        (mkdir, rmdir, delete, mdelete, rename, chmod), recon/metadata
        (size, modtime, status, rstatus, rhelp, help, idle), transfer type
        (ascii, binary, type), account/site, quote (raw protocol escape
        hatch), restart, and prompt. Login (user) and passive mode are
        already handled for you (by ftp_connect and automatically,
        respectively) - do not send those, or "open"/"close"/"bye" (use
        ftp_connect/close_session instead), yourself. Anything not on this
        list is rejected immediately, before touching the connection.

        Args:
            command: The ftp command to send, e.g. "ls" or "get file.txt".
        """
        if "\n" in command or "\r" in command:
            return "Command cannot contain newlines - send one command at a time.", None

        stripped = command.strip()
        first_word = stripped.split(None, 1)[0].lower() if stripped else ""
        if first_word not in _FTP_ALLOWED_COMMANDS:
            return (
                f"'{first_word or command}' is not an accepted ftp command for "
                "this tool - it was rejected before touching the connection, "
                "so nothing was sent. Allowed commands: "
                f"{', '.join(sorted(_FTP_ALLOWED_COMMANDS))}. Login is handled "
                "by ftp_connect (not 'user' here), and passive mode is already "
                "set automatically - don't send either of those yourself."
            ), None

        manager = await kali_registry.get_manager(project_id)
        sessions = await manager.list_sessions(target_id, agent_run_id)
        existing = next((s for s in sessions if s.name == FTP_SESSION_NAME and not s.closed), None)
        if existing is None:
            return "No FTP session is currently open - call ftp_connect first.", None
        if manager.get_current_session_name(target_id, agent_run_id) != FTP_SESSION_NAME:
            try:
                await manager.switch_session(target_id, agent_run_id, FTP_SESSION_NAME)
            except KaliSessionError as e:
                return str(e), None
        current_session = manager.get_current_session(target_id, agent_run_id)

        condensed, raw_output = await _send_and_condense(
            manager,
            project_id,
            target_id,
            agent_run_id,
            current_session,
            command,
            FTP_COMMAND_READ_SECONDS,
            on_enumeration,
            mark_tested,
            on_session_change,
            on_prompt_state_change,
            on_raw_output,
        )
        if raw_output is not None and _ftp_data_connection_stalled(raw_output):
            condensed = (
                "[The FTP data connection for this command never completed - "
                "the server acknowledged it ('150 ...') but no transfer-"
                "complete/failed reply ('226'/'425'/'426') came back within "
                "the wait window. This is NOT confirmation of an empty "
                "result - it looks like the data connection itself couldn't "
                "be established (e.g. an active-mode callback this sandbox "
                "can't receive, or a firewalled passive-mode port). Retrying "
                "the same command is unlikely to help on its own.]\n\n"
                + condensed
            )
        elif raw_output is not None and _ftp_active_mode_fallback(raw_output):
            # Marks the session for a fresh passive-mode retry - the next
            # ftp_connect call will re-send "passive" (see its own
            # `if not current_session.ftp_passive:` check) instead of
            # trusting the toggle that evidently isn't holding for every
            # data-connection command on this session.
            current_session.ftp_passive = False
            condensed = (
                "[This command fell back to ACTIVE-mode FTP (the client "
                "tried to open its own inbound-callback data connection) "
                "even though passive mode was supposed to already be on "
                "for this session - it isn't reliably sticking for every "
                "data-connection command against this server. Call "
                "ftp_connect again (it will re-toggle passive mode) before "
                "retrying this command.]\n\n"
                + condensed
            )
        return condensed, raw_output

    @tool(SSH_CHECK_LOGIN_TOOL_NAME, response_format="content_and_artifact")
    async def ssh_check_login(username: str, password: str) -> str:
        """Tries exactly one username/password pair against this run's
        target's SSH service and reports success or failure - use this to
        confirm a single candidate credential (e.g. found elsewhere); for
        trying many candidates at once use
        hydra_bruteforce(service="ssh", ...) instead.

        Args:
            username: SSH username to try.
            password: SSH password to try.
        """
        host, error = await _get_target_host(target_id)
        if error:
            return error, None

        command = (
            f"sshpass -p {shlex.quote(password)} ssh -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=10 {shlex.quote(username)}@{host} exit"
        )
        ok, output = await _execute_one_shot(project_id, command, SSH_CHECK_LOGIN_TIMEOUT_SECONDS)
        mark_tested()
        on_raw_output(output)
        if ok:
            return f"Login successful for '{username}'.\n\n{output}", output
        return f"Login failed for '{username}' (or a connection error).\n\n{output}", output

    @tool(SSH_RUN_TOOL_NAME, response_format="content_and_artifact")
    async def ssh_run(username: str, password: str, command: str) -> str:
        """Logs into this run's target over SSH and runs exactly one
        command, returning its output. If login itself fails, that shows
        up in the output text (e.g. "Permission denied") rather than as a
        separate error - there's no persistent shell here, just one
        authenticated command per call.

        Args:
            username: SSH username.
            password: SSH password.
            command: The single command to run on the target, e.g.
                "cat /etc/passwd".
        """
        host, error = await _get_target_host(target_id)
        if error:
            return error, None

        # `; true` so the REMOTE command's own exit code (a normal,
        # informative outcome - e.g. "Permission denied" from a
        # permissions probe - not a failure of this tool) never gets
        # mistaken for a local exec failure by _execute_one_shot.
        shell_command = (
            f"sshpass -p {shlex.quote(password)} ssh -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=10 {shlex.quote(username)}@{host} "
            f"{shlex.quote(command)} ; true"
        )
        ok, output = await _execute_one_shot(project_id, shell_command, SSH_RUN_TIMEOUT_SECONDS)
        mark_tested()
        if not ok:
            return output, None
        on_raw_output(output)
        condensed = await _maybe_condense(project_id, f"ssh {command}", output, on_enumeration)
        return condensed, output

    @tool(TELNET_PROBE_TOOL_NAME, response_format="content_and_artifact")
    async def telnet_probe(port: int) -> str:
        """Connects briefly to `port` on this run's target and returns
        whatever banner/greeting it sends back - a quick "what's
        listening here" check. For an actual interactive telnet login
        session, use new_session/run() instead (if allow_shell is
        enabled) - a login prompt's exact format is specific to whatever
        service is running, with no generic shortcut this tool can offer.

        Args:
            port: Port to probe.
        """
        host, error = await _get_target_host(target_id)
        if error:
            return error, None

        # Nested `bash -c '...'`, not a bare `(...)` subshell - _execute_one_shot
        # (via KaliManger.execute's timeout_seconds) prepends its own
        # `timeout --kill-after=5 {N} ` in front of this whole string before
        # handing it to the outer bash -c, and `timeout N (subshell)` is a
        # bash syntax error (confirmed in production: every single
        # telnet_probe call failed with "syntax error near unexpected token
        # '('"). Wrapping in a nested `bash -c` avoids a bare `(` at the top
        # level entirely. `|| true` (inside the nested shell) for the same
        # reason as ssh_run above - telnet only exits on its own once the
        # inner `timeout 3` kills it, which otherwise looks like a local
        # exec failure.
        command = f"bash -c 'echo | timeout 3 telnet {host} {port} || true'"
        ok, output = await _execute_one_shot(project_id, command, TELNET_PROBE_TIMEOUT_SECONDS)
        mark_tested()
        if not ok:
            return output, None
        on_raw_output(output)
        return output, output

    return [ftp_connect, ftp_command, ssh_check_login, ssh_run, telnet_probe]
