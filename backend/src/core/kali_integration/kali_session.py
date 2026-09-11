import asyncio
import socket as socket_module
import time
from dataclasses import dataclass, field
from typing import Final, Optional

DEFAULT_READ_WINDOW_SECONDS: Final = 5
MAX_READ_WINDOW_SECONDS: Final = 30
# Resets on any read/write, not on data arriving - guards abandoned
# sessions, not targets that are just slow to connect back.
SESSION_IDLE_TIMEOUT_SECONDS: Final = 20 * 60
SESSION_SWEEP_INTERVAL_SECONDS: Final = 60
MAX_SESSIONS_PER_PROJECT: Final = 5
SOCKET_RECV_CHUNK_BYTES: Final = 4096
SOCKET_WRITE_TIMEOUT_SECONDS: Final = 10


class KaliSessionError(RuntimeError):
    """Session-level problem that must reach the agent as a clear tool
    result (unknown id, already closed, process exited) rather than a hang
    or silent empty string."""


@dataclass
class KaliSession:
    session_id: str
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
