import asyncio
import socket as socket_module
import time
from dataclasses import dataclass, field
from typing import Final, Optional

DEFAULT_READ_WINDOW_SECONDS: Final = 5
# Raised well past a short interactive exchange - this is the hard ceiling
# on the idle-quiet duration a single read can be asked to wait for. A
# command can legitimately print a little (a banner, a permission warning
# from an out-of-scope probe, ...), then go quiet for several real seconds
# while it keeps working, before printing its actual result - nmap against
# a narrow authorized-port range is a concrete example (see
# agent_tools.py's run() docstring). A short "stop once ANY quiet gap is
# seen" heuristic was tried here and reliably cut such commands off after
# their first pause, before their real output - the trailing result then
# only surfaced later, prepended to whatever the NEXT call happened to
# send. There's no way to tell "quiet because still working" apart from
# "quiet because actually done" without understanding the specific
# command, so the only correct fix is to require the FULL requested
# quiet-window, uninterrupted, before concluding a command is done - which
# means that window has to be large enough to outlast a slow command's
# internal pauses, not just its total runtime.
MAX_READ_WINDOW_SECONDS: Final = 1800
# Resets on any read/write, not on data arriving - guards abandoned
# sessions, not targets that are just slow to connect back.
SESSION_IDLE_TIMEOUT_SECONDS: Final = 20 * 60
SESSION_SWEEP_INTERVAL_SECONDS: Final = 60
# Per-target, not per-project - each agent run only ever manages its own
# target's sessions (see KaliManger._session_key).
MAX_SESSIONS_PER_TARGET: Final = 5
SOCKET_RECV_CHUNK_BYTES: Final = 4096
SOCKET_WRITE_TIMEOUT_SECONDS: Final = 10


# Substituted whenever a session read genuinely produced nothing within
# its wait window - named so agent_tools.py can recognize and skip it
# rather than spending a parsing-model call summarizing a fixed string.
NO_OUTPUT_MESSAGE: Final = "(no output within the wait window)"


class KaliSessionError(RuntimeError):
    """Session-level problem that must reach the agent as a clear tool
    result (unknown name, already closed, process exited) rather than a
    hang or silent empty string."""


@dataclass
class KaliSession:
    # Human-readable and agent-chosen (e.g. "default", "ftp") rather than a
    # UUID - unique per target, not globally, so two different targets in
    # the same project can each have their own "default" session. See
    # KaliManger._session_key for how that's namespaced internally.
    name: str
    command: str
    target_id: str
    exec_id: str
    sock: socket_module.socket
    user: str
    # Guards this session's socket I/O only - deliberately separate from
    # KaliManger.command_lock (one-shot execute() calls) and from
    # KaliManger.sessions_lock (dict membership), so a long read on one
    # session never blocks another session or a one-shot command.
    io_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    created_at: float = field(default_factory=time.monotonic)
    last_activity: float = field(default_factory=time.monotonic)
    closed: bool = False
    close_reason: Optional[str] = None
    # Best-effort guess at whether this session's last output ended at a
    # plain shell prompt vs. some other program's prompt (ftp, mysql, an
    # interpreter, ...) - only meaningfully tracked for the default
    # (plain-shell-launched) session; see KaliManger._session_io and
    # agent_tools.py's _looks_like_shell_prompt. Defaults True since a
    # freshly opened session starts at its own shell/program prompt.
    at_shell_prompt: bool = True
    # Consecutive turns the CURRENT program (active_program) has responded
    # with its own "I don't understand that" rejection to input that
    # doesn't belong there - see KaliManger._check_confusion/_session_io.
    # Deliberately NOT just "at_shell_prompt is False": that's also the
    # correct, expected, persistent state for a genuinely productive
    # multi-turn interactive session (a real ftp login flow, a msfconsole
    # module being driven, ...) and promoting on that alone was confirmed
    # in production to sever a session the agent was about to correctly
    # continue. Reset to 0 whenever at_shell_prompt becomes True again, or
    # on a fresh shell->program transition (the launch turn itself is
    # never punished).
    confusion_streak: int = 0
    # Leading token (lowercased, path-stripped) of whatever command caused
    # the most recent shell->non-shell transition, e.g. "ftp", "mysql",
    # "msfconsole" - used to look up which rejection signatures in
    # KaliManger._CONFUSION_SIGNATURES apply. None for an uncurated/unknown
    # program (including any real reverse or foreign shell) - these
    # deliberately get no content-based confusion detection at all.
    active_program: Optional[str] = None
    # Whether agent_tools.py's _send_ftp_passive has already toggled this
    # exact ftp session into passive mode - lives on the session object
    # itself (not a per-run/per-Agent closure) specifically because ftp
    # sessions persist across agent runs/pause-resumes (see
    # KaliManger._ensure_ftp_session's docstring), while a fresh run's
    # closure-scoped state (e.g. ftp_connect's _ftp_logged_in) resets every
    # time. "freshly_opened" only ever meant "did this run's ftp_connect
    # call find an existing process" - it says nothing about whether THIS
    # session was ever toggled passive, so gating the passive-mode send on
    # it left a session opened before that fix (or in an earlier run)
    # permanently stuck in ftp's default active mode across every later
    # run that reuses it, silently reintroducing the exact data-connection
    # hang the passive-mode fix exists to prevent. Checking this flag
    # directly instead - independent of freshly_opened/session age - means
    # ANY still-open, still-active-mode session gets caught and fixed the
    # next time ftp_connect touches it, exactly once, ever, per session.
    ftp_passive: bool = False
