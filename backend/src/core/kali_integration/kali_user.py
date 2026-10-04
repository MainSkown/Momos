import re
import uuid
import asyncio
import logging
from typing import Dict, List, Optional, Tuple
from src.schemas import KaliCreationStage
from src.websocket import (
    ws_registry,
    WsTypes,
    SendCommandMessage,
    ReceiveCommandOutputMessage,
    CreateConsoleSessionMessage,
    ConsoleSessionCreatedMessage,
    CloseConsoleSessionMessage,
    ConsoleSessionClosedMessage,
    CreatedKaliUserMessage,
    KaliCreationStageMessage,
    WebSocketError,
)
from .kali_manager import KALI_USERS, _ANSI_ESCAPE_PATTERN
from .kali_session import KaliSession, KaliSessionError
from .kali_registry import kali_registry

logger = logging.getLogger("momos.kali")

# OSC (Operating System Command) sequences - window-title sets
# ("\x1b]0;root@host: /\x07"), terminated by BEL or ESC \ (ST). Not
# covered by kali_manager.py's _ANSI_ESCAPE_PATTERN, which only matches
# CSI sequences ("\x1b[...letter" - colors, cursor moves, the
# bracketed-paste-mode toggles around every prompt). Both patterns exist
# in kali_manager.py/here purely to strip control sequences for DISPLAY -
# neither is applied to the raw text that KaliManger itself returns/
# stores, which _looks_like_shell_prompt's own local `cleaned` copy
# already relies on (see its comment).
_OSC_SEQUENCE_PATTERN = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")

# Kali's default root PS1 renders as TWO physical lines - this is the top
# one ("┌──(root㉿<host>)-[<cwd>]"); _SHELL_PROMPT_LINE_PATTERN below
# matches the bottom one ("└─# "). Neither is a terminal escape sequence
# (no ESC byte involved) - _ANSI_ESCAPE_PATTERN only ever strips the SGR
# color codes wrapped AROUND these literal box-drawing/"user㉿host"
# characters, never the characters themselves, so they need their own
# pattern to strip for display.
_KALI_PROMPT_TOP_LINE_PATTERN = re.compile(r"^[ \t]*┌──\(.*\)-\[.*\][ \t]*$", re.MULTILINE)

# A full prompt line - either Kali's decorated bottom line ("└─#"/"└─$")
# or any KALI_USERS member's plain bash prompt ("root@host:~$ ",
# "momos@host:~$ ") - with whatever trails it on the same line. A session
# echoes the just-typed command back on the SAME line as the prompt that
# was showing when it was typed (ordinary PTY echo), and the line left
# behind once a command finishes is just the next, now-empty prompt -
# stripping the WHOLE line covers both: the console already knows what
# was sent (it's the command the user just typed), so echoing it back a
# second time would be pure noise, not real output.
_SHELL_PROMPT_LINE_PATTERN = re.compile(
    rf"^[ \t]*(?:└─[#$]|(?:{'|'.join(re.escape(str(u)) for u in KALI_USERS)})@\S+?:.*?[$#])[ \t]*.*$",
    re.MULTILINE,
)


def _strip_echoed_command(text: str, sent_command: str) -> str:
    """_SHELL_PROMPT_LINE_PATTERN above only catches an echoed command
    bundled onto the SAME line as its prompt (e.g. "└─# ls") - true right
    after a session opens, while its startup banner/prompt is still
    sitting unread (see create_session's drain comment). For every command
    after that, the prompt that preceded THIS one was already consumed by
    the PREVIOUS call's own read (which waits through the prompt
    reappearing plus its grace period before returning - see
    kali_manager.py's _session_io_sync) - so what the PTY echoes back here
    is just the bare typed text, "ls" with no prompt attached at all,
    landing as this read's own first line with nothing for
    _SHELL_PROMPT_LINE_PATTERN to match against. Confirmed in production:
    without this, every command after the first showed its own name as a
    stray leading line. The one piece of information that reliably
    identifies that line - a prompt-pattern match can't, since it's not a
    prompt - is the exact text this caller knows it just sent."""
    sent = sent_command.strip()
    if not sent:
        return text
    first_line, separator, rest = text.partition("\n")
    if first_line.strip() == sent:
        return rest if separator else ""
    return text


def _strip_terminal_control_sequences(text: str, sent_command: Optional[str] = None) -> str:
    """A console session is a genuine persistent, interactive PTY (unlike
    the old one-shot `manager.execute()` path this replaced) - so it gets
    real interactive-shell behavior from bash: SGR color codes, the
    bracketed-paste-mode toggle sent around every prompt, (for Kali's
    heavily-decorated root prompt specifically) an OSC window-title set,
    and - the bulk of the actual noise - its own prompt lines, echoed back
    around every command. Nothing in KaliManger strips any of this before
    returning output - the agent's own condensing/parsing pipeline
    apparently tolerates it well enough that it was never surfaced there,
    but a human looking at literal text in the console needs just the
    command's own output, not the shell's half of the conversation around
    it. Confirmed against a real "ls" on Kali's default root prompt -
    without the prompt-line stripping below, its output was bracketed by
    its own two-line prompt twice over (once left over from the session's
    never-drained startup banner - see create_session - once as the
    command's own fresh prompt reappearing after)."""
    # The PTY sends real CRLF line endings - left in place, a line the
    # prompt patterns below don't match (ordinary command output) would
    # keep its trailing "\r" (the patterns' own "$"/".*$" only treat "\n"
    # as the line boundary, matching plain `.`'s own behavior of excluding
    # "\n" but not "\r"), leaving a stray character on every line.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _ANSI_ESCAPE_PATTERN.sub("", text)
    text = _OSC_SEQUENCE_PATTERN.sub("", text)
    text = _KALI_PROMPT_TOP_LINE_PATTERN.sub("", text)
    text = _SHELL_PROMPT_LINE_PATTERN.sub("", text)
    if sent_command is not None:
        text = _strip_echoed_command(text, sent_command)
    # The substitutions above leave the newlines that used to separate
    # prompt lines from real output behind as blank lines - collapse runs
    # of them and drop what's left at either end, so the frontend shows
    # just the command's own output, not a stack of blank lines where its
    # prompt noise used to be.
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip("\n")

# Synthetic session namespace every console session opens under, for every
# project - KaliManger's session machinery (built for the agent) namespaces
# sessions by target_id purely for uniqueness/bulk-close, with no other
# logic depending on it being a real Target row (confirmed by reading
# every session method - the actual Docker/user/network scoping comes from
# the KaliManger instance itself, already one-per-project). A console
# session isn't tied to any one target, so it gets this fixed string
# instead - never collides with a real Target.id (those are UUIDs), and
# keeps close_sessions_for_target (called when an *agent* run ends) from
# ever touching console sessions, since it's a completely different key.
CONSOLE_TARGET_ID = "console"
# Fixed sentinel for the "owning agent run" dimension KaliManger's session
# keying now has (see kali_manager.py's _session_key/_owner_key, added for
# concurrent agent-run isolation) - a console session has no agent run at
# all, so it gets its own fixed value here, the same way CONSOLE_TARGET_ID
# itself is a fixed sentinel on the target_id axis. Deliberately the same
# literal as CONSOLE_TARGET_ID (not a second distinct string) - there's no
# meaningful difference between the two axes for the console, and reusing
# it avoids introducing a second magic constant that would always have to
# be kept in sync with the first.
CONSOLE_AGENT_RUN_ID = CONSOLE_TARGET_ID
# Same literal as agent_tools.py's DEFAULT_SESSION_COMMAND - can't import
# it directly, agent_tools.py imports FROM kali_integration, not the
# reverse (would cycle).
CONSOLE_SESSION_COMMAND = "/bin/bash"
# Same literal and reasoning as agent_tools.py's SESSION_OPEN_READ_SECONDS -
# see create_session's drain read below.
CONSOLE_SESSION_OPEN_READ_SECONDS = 3


class KaliUserRegistry:
    def __init__(self):
        self.active_users: List[KaliUser] = []
        self.pending_users: Dict[uuid.UUID, str] = (
            {}
        )  # client_id -> project_id, in process of creation

    async def create_user(self, project_id: str) -> str:
        client_id = uuid.uuid4()
        self.pending_users[client_id] = project_id

        asyncio.create_task(self._create_user(project_id, client_id))

        return str(client_id)

    async def _create_user(self, project_id: str, client_id: uuid.UUID):
        try:
            user = await KaliUser.create(project_id, client_id)
        except Exception as e:
            # Without this, a failure here (e.g. Docker/package install error)
            # would leave the pending entry stuck forever with no way for the
            # frontend to find out - it would just wait on a message that never
            # arrives.
            logger.error(f"Failed to create Kali client for project {project_id}: {e}")
            self.pending_users.pop(client_id, None)
            kali_registry.clear_build_status(project_id)

            await ws_registry.send_message(
                CreatedKaliUserMessage(
                    project_id=project_id,
                    type=WsTypes.CreatedKaliUserMessage,
                    client_id=str(client_id),
                    error=WebSocketError(code="KaliCreationError", message=str(e)),
                )
            )
            return

        self.active_users.append(user)
        self.pending_users.pop(client_id, None)

        message = CreatedKaliUserMessage(
            project_id=project_id,
            type=WsTypes.CreatedKaliUserMessage,
            client_id=str(client_id),
        )

        await ws_registry.send_message(message)

    def get_client_for_project(
        self, project_id: str
    ) -> Optional[Tuple[uuid.UUID, bool]]:
        """Returns (client_id, pending) for the active or pending client
        belonging to project_id, or None if it has no Kali instance."""
        active = self.get_active_user_for_project(project_id)
        if active is not None:
            return active.client_id, False

        pending_client_id = next(
            (cid for cid, pid in self.pending_users.items() if pid == project_id),
            None,
        )
        if pending_client_id is not None:
            return pending_client_id, True

        return None

    def get_active_user_for_project(self, project_id: str) -> Optional["KaliUser"]:
        """Like get_client_for_project, but returns the actual KaliUser
        instance (not just its client_id) - needed by anything that wants
        to call a method on it (e.g. KaliService.list_sessions), not just
        report whether one exists."""
        return next(
            (u for u in self.active_users if u.project_id == project_id), None
        )


kali_user_registry = KaliUserRegistry()


class KaliUser:
    def __init__(self, project_id: str, client_id: uuid.UUID):
        self.project_id = project_id
        self.client_id = client_id

    @classmethod
    async def create(cls, project_id: str, client_id: uuid.UUID):
        loop = asyncio.get_running_loop()

        def on_stage(stage: KaliCreationStage):
            # A plain dict write, safe to call directly from this executor
            # thread (protected by the GIL like any other CPython dict
            # mutation) - unlike the websocket send below, it doesn't need
            # the event loop. Persisted so a client that missed the live
            # KaliCreationStageMessage below (e.g. a page refresh mid-build)
            # can still recover current progress via
            # kali_registry.get_build_status.
            kali_registry.set_build_stage(project_id, stage, target_id=None)

            # Called from the executor thread running the (synchronous) Docker
            # setup - hop back onto the event loop to actually send it.
            asyncio.run_coroutine_threadsafe(
                ws_registry.send_message(
                    KaliCreationStageMessage(
                        project_id=project_id,
                        type=WsTypes.KaliCreationStage,
                        stage=stage,
                    )
                ),
                loop,
            )

        # Check/Get the manager async
        manager = await kali_registry.get_manager(project_id, on_stage=on_stage)
        kali_registry.clear_build_status(project_id)
        if not manager:
            raise RuntimeError(
                f"Could not create Kali Manager for project: {project_id}"
            )

        instance = cls(project_id, client_id)

        # Attach project-scoped hooks
        ws_registry.add_hook(
            WsTypes.SendCommandMessage, instance._send_command_hook
        )
        ws_registry.add_hook(
            WsTypes.CreateConsoleSessionMessage, instance._create_session_hook
        )
        ws_registry.add_hook(
            WsTypes.CloseConsoleSessionMessage, instance._close_session_hook
        )
        # Lets the manager's idle sweep tell the frontend when it closes a
        # console session on its own (see KaliManger.session_closed_
        # notifier) - without this, an idle-timed-out tab stayed open in
        # the UI with no way to know its session was already gone.
        manager.session_closed_notifier = instance._notify_session_closed

        return instance

    def _check_project(self, project_id: str) -> None:
        if project_id != self.project_id:
            raise RuntimeError(
                "Tried to act on a different project than this user was created for."
            )

    async def _notify_session_closed(self, target_id: str, name: str) -> None:
        if target_id != CONSOLE_TARGET_ID:
            # Not a console session (e.g. an agent session the idle sweep
            # also just closed) - nothing on this side cares.
            return
        await ws_registry.send_message(
            ConsoleSessionClosedMessage(
                project_id=self.project_id,
                type=WsTypes.ConsoleSessionClosedMessage,
                session=name,
            )
        )

    async def create_session(self, user: KALI_USERS) -> KaliSession:
        """Opens a new console session as `user`, auto-numbered ("1", "2",
        ...) independently per user - root's and momos's own sessions are
        numbered from 1 separately, not sharing one counter - since both
        live in the same CONSOLE_TARGET_ID namespace (open_session rejects
        a name collision within a namespace, and this repo deliberately
        keeps one shared namespace/cap for the console rather than a
        second one per user - see CONSOLE_TARGET_ID's own comment), the
        actual session name carries a "root-"/"momos-" prefix to stay
        unique; the frontend strips it back off for display, since it
        already knows which user each session belongs to. Numbers are
        never reused for the life of this project's container (closing
        "root-2" doesn't make the next new root session reuse "2") -
        manager.next_session_number is a standalone counter, not derived
        from which sessions currently happen to be open, so a tab's number
        always identifies the same session for as long as either exists,
        even across a close that's still unwinding."""
        manager = await kali_registry.get_manager(self.project_id)
        next_number = await manager.next_session_number(CONSOLE_TARGET_ID, str(user))
        name = f"{user}-{next_number}"
        session = await manager.open_session(
            CONSOLE_TARGET_ID, CONSOLE_AGENT_RUN_ID, name, CONSOLE_SESSION_COMMAND, user
        )
        try:
            # Drain the shell's own startup banner/prompt before handing
            # the session back - nothing has read from it yet, so it's
            # still sitting unread in the socket buffer and would
            # otherwise get glommed onto the very first real command's own
            # output (confirmed in production: a session's first command
            # showed its own prompt TWICE - once from this never-drained
            # banner, once from the command's own fresh prompt afterward).
            # Mirrors agent_tools.py's new_session tool, which does the
            # exact same bare poll immediately after opening, for the same
            # reason - discarded here rather than shown, since
            # _strip_terminal_control_sequences would reduce it to nothing
            # but blank lines anyway.
            await manager.run_in_session(
                CONSOLE_TARGET_ID,
                CONSOLE_AGENT_RUN_ID,
                name,
                None,
                wait_seconds=CONSOLE_SESSION_OPEN_READ_SECONDS,
            )
        except Exception:
            # open_session above already succeeded and registered this
            # session - if the drain itself then fails, the caller sees
            # an exception and reports creation as failed, but without
            # this the session would otherwise live on, invisible (never
            # handed to the frontend), still occupying a
            # MAX_SESSIONS_PER_TARGET slot, until it resurfaces
            # unexplained on a later page reload's list_sessions call.
            # force=True - see kali_manager.py's close_session for why
            # (usually a no-op here too: _session_io's own EOFError/
            # OSError handling already cleans up a session that died
            # mid-drain before this exception even reaches here - this is
            # just the backstop for whatever that doesn't cover).
            await manager.close_session(
                CONSOLE_TARGET_ID, CONSOLE_AGENT_RUN_ID, name, force=True
            )
            raise
        return session

    async def close_session(self, name: str) -> bool:
        manager = await kali_registry.get_manager(self.project_id)
        # force=True - see kali_manager.py's close_session for why this
        # explicit close/exit request must not wait.
        return await manager.close_session(
            CONSOLE_TARGET_ID, CONSOLE_AGENT_RUN_ID, name, force=True
        )

    async def list_sessions(self) -> List[KaliSession]:
        manager = await kali_registry.get_manager(self.project_id)
        return await manager.list_sessions(CONSOLE_TARGET_ID, CONSOLE_AGENT_RUN_ID)

    async def _create_session_hook(self, message: CreateConsoleSessionMessage):
        project_id = message.project_id
        self._check_project(project_id)

        try:
            session = await self.create_session(KALI_USERS(message.user))
        except KaliSessionError as e:
            await ws_registry.send_message(
                ConsoleSessionCreatedMessage(
                    project_id=project_id,
                    type=WsTypes.ConsoleSessionCreatedMessage,
                    session="",
                    user=message.user,
                    error=WebSocketError(code="SessionError", message=str(e)),
                )
            )
            return

        await ws_registry.send_message(
            ConsoleSessionCreatedMessage(
                project_id=project_id,
                type=WsTypes.ConsoleSessionCreatedMessage,
                session=session.name,
                user=message.user,
            )
        )

    async def _close_session_hook(self, message: CloseConsoleSessionMessage):
        project_id = message.project_id
        self._check_project(project_id)

        await self.close_session(message.session)
        await ws_registry.send_message(
            ConsoleSessionClosedMessage(
                project_id=project_id,
                type=WsTypes.ConsoleSessionClosedMessage,
                session=message.session,
            )
        )

    async def _send_command_hook(self, message: SendCommandMessage):
        project_id = message.project_id
        self._check_project(project_id)

        # Typing "exit" closes the session the same way its own close
        # button does, instead of being sent through to the shell - the
        # underlying process would exit either way (that's what "exit"
        # does to a shell), but closing the session directly also tears
        # down the exec/socket and tells the frontend to drop the tab,
        # rather than leaving a dead session behind that every later
        # command in that tab would just error against.
        if message.command.strip() == "exit":
            await self.close_session(message.session)
            await ws_registry.send_message(
                ConsoleSessionClosedMessage(
                    project_id=project_id,
                    type=WsTypes.ConsoleSessionClosedMessage,
                    session=message.session,
                )
            )
            return

        manager = await kali_registry.get_manager(project_id)
        try:
            result = await manager.run_in_session(
                CONSOLE_TARGET_ID, CONSOLE_AGENT_RUN_ID, message.session, message.command
            )
        except Exception as e:
            output_message = ReceiveCommandOutputMessage(
                project_id=project_id,
                type=WsTypes.ReceiveCommandOutputMessage,
                output="",
                session=message.session,
                error=WebSocketError(code="CommandError", message=str(e)),
            )
            await ws_registry.send_message(output_message)
            return

        output_message = ReceiveCommandOutputMessage(
            project_id=project_id,
            type=WsTypes.ReceiveCommandOutputMessage,
            output=_strip_terminal_control_sequences(result, sent_command=message.command),
            session=message.session,
        )

        await ws_registry.send_message(output_message)
