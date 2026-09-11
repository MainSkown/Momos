import docker
import asyncio
import socket as socket_module
import time
import uuid
from docker.errors import DockerException
import logging
from typing import Callable, Dict, Final, List, Optional, Sequence
from src.schemas import Target, KaliCreationStage
from enum import Enum
from .kali_session import (
    KaliSession,
    KaliSessionError,
    DEFAULT_READ_WINDOW_SECONDS,
    MAX_READ_WINDOW_SECONDS,
    MAX_SESSIONS_PER_PROJECT,
    SESSION_IDLE_TIMEOUT_SECONDS,
    SESSION_SWEEP_INTERVAL_SECONDS,
    SOCKET_RECV_CHUNK_BYTES,
    SOCKET_WRITE_TIMEOUT_SECONDS,
)

logger = logging.getLogger("momos.kali")


class KALI_USERS(str, Enum):
    momos = "momos"
    root = "root"

    def __str__(self) -> str:
        return self.value


MOMOS_USER: Final = KALI_USERS.momos


# IANA protocol numbers, used with "meta l4proto" instead of protocol names -
# name resolution depends on the container's /etc/protocols contents (e.g. it
# lists "ipv6-icmp", not "icmpv6"), so numbers are the portable choice. nft's
# own docs also recommend "meta l4proto" over "ip6 nexthdr" for IPv6, since
# nexthdr only reflects the immediate next header and misses extension headers.
L4PROTO_TCP: Final = 6
L4PROTO_UDP: Final = 17
L4PROTO_ICMP: Final = 1
L4PROTO_ICMPV6: Final = 58

# Published up front so a future "start listening" (reverse-shell) tool has
# somewhere reachable from the LAN to bind to - Docker's own port publishing
# is a scoped, host-managed NAT rule (the same mechanism docker-compose.yml
# already uses for the backend/dashboard's own ports), not custom code
# touching the host firewall directly.
# NOTE: this range is currently shared globally across every project's Kali
# container - only one project's container can bind it at a time. Fine while
# no listening tool exists yet; revisit (e.g. per-project ranges) once one does.
REVERSE_SHELL_PORT_RANGE: Final[range] = range(4444, 4449)

# Applied to every command run via execute() (agent tool calls and console
# commands both go through it). Without this, a command that never
# terminates on its own - nc/telnet opening an interactive session, an
# unexpected prompt, anything waiting on stdin - hangs the exec call
# forever, and everything queued behind it via command_lock along with it.
DEFAULT_COMMAND_TIMEOUT_SECONDS: Final = 120

DEFAULT_KALI_PACKAGES: Final[tuple[str, ...]] = (
    #"kali-linux-headless", # downloads too long
    "wordlists",
    "curl",
    "wget",
    "nmap",
    "netcat-openbsd",
    "nftables",
    "gobuster",
    "nikto",
    "exploitdb",
    "iputils-ping",
    "bind9-dnsutils",
    "whois",
    "smbclient",
    "whatweb",
    "hydra",
    "sqlmap",
    "telnet",
    "traceroute",
    "ftp",
    "openssh-client",
)

# Anything else the agent needs on top of this baseline is installed on
# demand via the install_kali_package tool (agent_tools.py) - kept this list
# short and curated rather than reaching back for kali-linux-headless, since
# dropping that metapackage is what made container startup fast again.


class KaliManger:
    def __init__(
        self,
        container_name: str = "momos-kali-worker",
        packages: Sequence[str] | None = None,
    ):
        self.container_name = container_name
        self.container = None
        self.packages = (
            tuple(packages) if packages is not None else DEFAULT_KALI_PACKAGES
        )
        # LangGraph's ToolNode runs every tool call from one LLM turn
        # concurrently (asyncio.gather) - without this, an agent requesting
        # several kali commands in one turn would fire that many simultaneous
        # docker exec calls (each potentially a heavy tool like nmap) plus
        # that many simultaneous local-LLM parsing calls, all at once.
        self.command_lock = asyncio.Lock()

        # Persistent interactive sessions (nc/telnet, eventually a
        # reverse-shell listener) - deliberately independent of
        # command_lock above, since a long-lived session must never block
        # one-shot execute() calls or vice versa. This lock only guards
        # dict membership; each KaliSession has its own io_lock for its
        # actual socket I/O.
        self.sessions: Dict[str, KaliSession] = {}
        self.sessions_lock = asyncio.Lock()
        self._session_sweep_task: Optional[asyncio.Task] = None

        try:
            self.client = docker.from_env()
        except DockerException as e:
            logger.error(f"Could not connect to Docker: {e}")
            raise RuntimeError("Docker daemon is not available")

    async def start(
        self, on_stage: Optional[Callable[[KaliCreationStage], None]] = None
    ):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._create_container, on_stage)
        print(f"Successfully created Kali container: {self.container_name}", flush=True)

    def _report(
        self, on_stage: Optional[Callable[[KaliCreationStage], None]], stage: KaliCreationStage
    ):
        if on_stage is not None:
            on_stage(stage)

    def _create_container(
        self, on_stage: Optional[Callable[[KaliCreationStage], None]] = None
    ):
        # Check if a container with the same name already exists and, if so,
        # whether it's actually usable as-is - re-downloading and
        # reinstalling every package on every reuse (e.g. every backend
        # restart during dev) is slow and unnecessary if it's already there.
        self._report(on_stage, KaliCreationStage.checking_container)
        existing_container = None
        try:
            existing_container = self.client.containers.get(self.container_name)
        except docker.errors.NotFound:
            pass

        if existing_container is not None:
            if existing_container.status != "running":
                try:
                    existing_container.start()
                    existing_container.reload()
                except Exception as e:
                    print(
                        f"Could not restart existing container {self.container_name}: {e}",
                        flush=True,
                    )
                    existing_container = None

            if existing_container is not None and existing_container.status == "running":
                self.container = existing_container

                if self._is_configured_correctly():
                    print(
                        f"Reusing already-configured container: {self.container_name}",
                        flush=True,
                    )
                    return

                print(
                    f"Container {self.container_name} exists but isn't correctly "
                    "configured - rebuilding.",
                    flush=True,
                )

            self.container = None
            existing_container.remove(force=True)

        print("Starting container")
        self._report(on_stage, KaliCreationStage.starting_container)
        self.container = self.client.containers.run(
            image="kalilinux/kali-rolling:latest",
            name=self.container_name,
            detach=True,
            tty=True,
            remove=True,
            cap_add=["NET_ADMIN", "NET_RAW"],
            ports={f"{port}/tcp": port for port in REVERSE_SHELL_PORT_RANGE},
        )

        self._configure_container(on_stage)

        self._report(on_stage, KaliCreationStage.verifying_setup)
        if not self._is_configured_correctly():
            raise RuntimeError(
                f"Kali container {self.container_name} failed post-setup verification"
            )

    def _configure_container(
        self, on_stage: Optional[Callable[[KaliCreationStage], None]] = None
    ):
        print("Updating and downloading packages")
        self._report(on_stage, KaliCreationStage.updating_packages)
        self._exec_in_container("apt-get update")

        self._report(on_stage, KaliCreationStage.installing_packages)
        self._exec_in_container(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "
            + " ".join(self.packages)
        )
        print("Setting up momos user")
        self._report(on_stage, KaliCreationStage.creating_user)

        self._exec_in_container(
            f"id -u {MOMOS_USER} >/dev/null 2>&1 || useradd --system -s /bin/bash {MOMOS_USER}"
        )

        # Make sure the home directory exists and belongs to momos
        self._exec_in_container(
            f"install -d -o {MOMOS_USER} -g {MOMOS_USER} /home/{MOMOS_USER}"
        )

    def _is_configured_correctly(self) -> bool:
        """Checks that the container has every required package installed,
        a working nftables setup, and the momos user - used both to decide
        whether an existing container can be reused, and as a final sanity
        check right after a fresh setup.

        The nftables check only confirms the binary/kernel support actually
        works (can list the ruleset) - it deliberately does NOT check for
        any specific target's rules, since there's no target in scope here
        and none would be reliable anyway: prepare_nftables() unconditionally
        tears down and rebuilds the target-scoped rules on every agent start,
        whether the container was just reused or freshly built. So stale or
        wrong target rules can't persist regardless of what this finds."""
        try:
            # Deliberately NOT redirected to /dev/null - dpkg/id/nft's own
            # output on failure (e.g. "package 'X' is not installed") is
            # exactly what makes a failure here diagnosable, and
            # _exec_in_container already captures it into the RuntimeError.
            self._exec_in_container(f"dpkg -s {' '.join(self.packages)}")
            self._exec_in_container(f"id -u {MOMOS_USER}")
            self._exec_in_container("nft list ruleset")
        except RuntimeError as e:
            print(f"Kali container configuration check failed: {e}", flush=True)
            return False

        return True

    def _exec_in_container(
        self, command: str, user: str = "root", timeout_seconds: Optional[int] = None
    ):
        if timeout_seconds is not None:
            # Anything that opens an interactive session and waits on stdin
            # (nc without -z, telnet, an ftp/ssh client, ...) would otherwise
            # hang this call forever - and everything serialized behind it
            # via command_lock along with it. `timeout` runs entirely inside
            # the container's own process tree, so it reliably kills the
            # actual hung process regardless of what it's doing.
            command = f"timeout --kill-after=5 {timeout_seconds} {command}"

        shell_cmd = ["/bin/bash", "-c", command]

        if self.container is None:
            raise RuntimeError("Container is not running")

        result = self.container.exec_run(
            cmd=shell_cmd, user=user, workdir="/home/momos" if user == "momos" else "/"
        )
        exit_code = result.exit_code
        output = (
            result.output.decode(errors="replace")
            if isinstance(result.output, (bytes, bytearray))
            else str(result.output)
        )

        # `timeout` exits 124 if it had to send SIGTERM, or 137 if the
        # command ignored that and needed SIGKILL after the grace period.
        if timeout_seconds is not None and exit_code in (124, 137):
            raise RuntimeError(
                f"Command timed out after {timeout_seconds}s and was terminated: {shell_cmd}\n{output}"
            )

        if exit_code != 0:
            raise RuntimeError(
                f"Command failed with exit code {exit_code}: {shell_cmd}\n{output}"
            )

        return output

    # --- Persistent interactive sessions ---
    # For commands that need to stay open and be driven turn by turn
    # (nc/telnet holding a connection, eventually a reverse-shell listener)
    # rather than run once to completion. See kali_session.py for the
    # KaliSession dataclass and tunables.

    def _open_session_sync(
        self, command: str, user: KALI_USERS
    ) -> tuple[str, socket_module.socket]:
        if self.container is None:
            raise RuntimeError("Container is not running")

        exec_id = self.client.api.exec_create(
            self.container.id,
            ["/bin/bash", "-c", command],
            stdin=True,
            tty=True,
            stdout=True,
            stderr=True,
            user=str(user),
            workdir="/home/momos" if user == KALI_USERS.momos else "/",
        )["Id"]

        # exec_start(socket=True) returns a socket.SocketIO wrapper, not a
        # raw socket - its .write() is a single non-retrying send() and it
        # has no .recv()/.settimeout(). The actually-usable raw socket is
        # the wrapper's private ._sock. This is a docker-py internal, not a
        # stable public API - confirmed against the version pinned in
        # poetry.lock; re-verify if that pin is ever bumped.
        wrapper = self.client.api.exec_start(exec_id, socket=True, tty=True)
        return exec_id, wrapper._sock

    async def open_session(
        self, command: str, target_id: str, user: KALI_USERS = KALI_USERS.momos
    ) -> KaliSession:
        async with self.sessions_lock:
            if len(self.sessions) >= MAX_SESSIONS_PER_PROJECT:
                raise KaliSessionError(
                    f"Too many open sessions ({MAX_SESSIONS_PER_PROJECT} max) - "
                    "close an existing one with close_session before opening another."
                )

        loop = asyncio.get_running_loop()
        exec_id, raw_sock = await loop.run_in_executor(
            None, self._open_session_sync, command, user
        )

        session = KaliSession(
            session_id=str(uuid.uuid4()),
            command=command,
            target_id=target_id,
            exec_id=exec_id,
            sock=raw_sock,
            user=str(user),
        )

        async with self.sessions_lock:
            self.sessions[session.session_id] = session

        self._ensure_session_sweep_running()
        return session

    def _session_io_sync(
        self,
        sock: socket_module.socket,
        data: Optional[bytes],
        read_window: float,
    ) -> str:
        """Runs in the executor thread. Optionally writes `data`, then
        drains whatever arrives until `read_window` seconds pass with no
        new data, or the peer closes (the session's process exited)."""
        if data is not None:
            sock.settimeout(SOCKET_WRITE_TIMEOUT_SECONDS)
            sock.sendall(data)

        sock.settimeout(read_window)
        chunks = bytearray()
        try:
            while True:
                chunk = sock.recv(SOCKET_RECV_CHUNK_BYTES)
                if not chunk:
                    raise EOFError("session process exited")
                chunks.extend(chunk)
        except socket_module.timeout:
            pass  # Expected: no more output within the window.

        return chunks.decode(errors="replace")

    async def write_to_session(
        self,
        session_id: str,
        data: str,
        read_window: float = DEFAULT_READ_WINDOW_SECONDS,
    ) -> str:
        # tty=True means the program on the other end expects a line
        # terminator to treat this as "Enter was pressed".
        return await self._session_io(session_id, (data + "\n").encode(), read_window)

    async def read_session(
        self, session_id: str, read_window: float = DEFAULT_READ_WINDOW_SECONDS
    ) -> str:
        return await self._session_io(session_id, None, read_window)

    async def _session_io(
        self, session_id: str, data: Optional[bytes], read_window: float
    ) -> str:
        session = self.sessions.get(session_id)
        if session is None:
            raise KaliSessionError(
                f"No such session '{session_id}' - it may have already been "
                "closed (explicitly, by an idle timeout, or because its "
                "process exited)."
            )
        if session.closed:
            raise KaliSessionError(
                f"Session '{session_id}' is closed: {session.close_reason}"
            )

        read_window = max(0.5, min(read_window, MAX_READ_WINDOW_SECONDS))
        loop = asyncio.get_running_loop()

        async with session.io_lock:
            try:
                output = await loop.run_in_executor(
                    None, self._session_io_sync, session.sock, data, read_window
                )
            except EOFError:
                exit_info = await loop.run_in_executor(
                    None, self.client.api.exec_inspect, session.exec_id
                )
                # NOT _close_session() - it re-acquires session.io_lock,
                # which we're already holding here, which would deadlock.
                await self._remove_from_registry(session)
                await self._close_session_locked(
                    session,
                    reason=f"process exited (exit code {exit_info.get('ExitCode')})",
                )
                raise KaliSessionError(
                    f"Session '{session_id}' process exited "
                    f"(exit code {exit_info.get('ExitCode')}). The session is now closed."
                )
            except OSError as e:
                await self._remove_from_registry(session)
                await self._close_session_locked(session, reason=f"socket error: {e}")
                raise KaliSessionError(
                    f"Session '{session_id}' hit a socket error and was closed: {e}"
                )

        session.last_activity = time.monotonic()
        return output if output else "(no output within the read window)"

    async def close_session(self, session_id: str) -> None:
        session = self.sessions.get(session_id)
        if session is not None:
            await self._close_session(session, reason="closed by agent")

    async def _remove_from_registry(self, session: KaliSession) -> None:
        async with self.sessions_lock:
            self.sessions.pop(session.session_id, None)

    async def _close_session_locked(self, session: KaliSession, reason: str) -> None:
        """Actually closes the socket. Caller must already hold
        session.io_lock - use _close_session() instead unless you're already
        inside a block that holds it (e.g. _session_io's except handlers)."""
        if session.closed:
            return
        session.closed = True
        session.close_reason = reason
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, session.sock.close)

    async def _close_session(self, session: KaliSession, reason: str) -> None:
        await self._remove_from_registry(session)
        # Wait out any in-flight read/write on this session rather than
        # closing the socket out from under it.
        async with session.io_lock:
            await self._close_session_locked(session, reason)

    async def close_sessions_for_target(self, target_id: str) -> None:
        async with self.sessions_lock:
            to_close = [
                s for s in self.sessions.values() if s.target_id == target_id
            ]
        for session in to_close:
            await self._close_session(session, reason="agent run ended")

    async def close_all_sessions(self) -> None:
        async with self.sessions_lock:
            to_close = list(self.sessions.values())
        for session in to_close:
            await self._close_session(session, reason="container stopped")

    async def list_sessions(self, target_id: str) -> List[KaliSession]:
        async with self.sessions_lock:
            return [s for s in self.sessions.values() if s.target_id == target_id]

    def _ensure_session_sweep_running(self):
        if self._session_sweep_task is None or self._session_sweep_task.done():
            self._session_sweep_task = asyncio.get_running_loop().create_task(
                self._sweep_idle_sessions()
            )

    async def _sweep_idle_sessions(self):
        try:
            while True:
                await asyncio.sleep(SESSION_SWEEP_INTERVAL_SECONDS)
                async with self.sessions_lock:
                    if not self.sessions:
                        # Nothing left to watch - the next open_session()
                        # restarts this sweep.
                        return
                    now = time.monotonic()
                    idle = [
                        s
                        for s in self.sessions.values()
                        if now - s.last_activity > SESSION_IDLE_TIMEOUT_SECONDS
                    ]
                for session in idle:
                    logger.info(
                        f"Closing idle kali session {session.session_id} "
                        f"({session.command!r})"
                    )
                    await self._close_session(session, reason="idle timeout")
        except asyncio.CancelledError:
            pass

    async def prepare_nftables(self, target: Target):
        # Reset only our own tables - NOT "nft flush ruleset". This container
        # has its own network namespace (not host-networked), so these nft
        # commands can only ever affect its own isolated firewall state - but
        # scoping to just our tables instead of a blanket flush is still the
        # right habit, in case that ever changes.
        # "destroy" doesn't fail if the table doesn't exist yet.
        await self.execute("nft destroy table ip MOMOS_IPv4", user=KALI_USERS.root)
        await self.execute("nft destroy table ip6 MOMOS_IPv6", user=KALI_USERS.root)

        # Create IPv4 table
        await self.execute("nft add table ip MOMOS_IPv4", user=KALI_USERS.root)

        # Create output chain
        await self.execute(
            "nft 'add chain ip MOMOS_IPv4 OUTPUT { type filter hook output priority 0; policy accept; }'",
            user=KALI_USERS.root,
        )

        # Allow traffic to comeback
        await self.execute(
            "nft add rule ip MOMOS_IPv4 OUTPUT meta skuid momos ct state established,related accept",
            user=KALI_USERS.root,
        )

        # Ports string - it's empty if ports are not defined or sets what port can be access (everything else will be blocked)
        ports_str = ""
        if target.ports is not None and len(target.ports) > 0:
            ports_str = f" dport {{ {', '.join(map(str,target.ports))} }}"

        if target.ipv4 is not None:
            # Allow rule for outgoing traffic to target
            for protocol, l4proto in [("tcp", L4PROTO_TCP), ("udp", L4PROTO_UDP)]:
                # "tcp"/"udp" alone isn't valid nft syntax - it must be followed
                # by a field (dport, etc). With no ports defined, match the
                # protocol itself via its numeric "meta l4proto" instead.
                protocol_match = (
                    f"{protocol}{ports_str}" if ports_str else f"meta l4proto {l4proto}"
                )
                await self.execute(
                    f"nft add rule ip MOMOS_IPv4 OUTPUT meta skuid momos ip daddr {target.ipv4} {protocol_match} accept",
                    user=KALI_USERS.root,
                )

            await self.execute(
                f"nft add rule ip MOMOS_IPv4 OUTPUT meta skuid momos ip daddr {target.ipv4} meta l4proto {L4PROTO_ICMP} accept",
                user=KALI_USERS.root,
            )

        # Allow DNS resolution to any resolver - without this, any tool that
        # does a lookup (nmap's reverse-DNS, curl/wget by hostname, etc.)
        # gets its query silently dropped (not rejected) since the resolver
        # isn't the target IP, and hangs until the tool's own DNS timeout
        # expires instead of failing fast.
        await self.execute(
            "nft add rule ip MOMOS_IPv4 OUTPUT meta skuid momos udp dport 53 accept",
            user=KALI_USERS.root,
        )
        await self.execute(
            "nft add rule ip MOMOS_IPv4 OUTPUT meta skuid momos tcp dport 53 accept",
            user=KALI_USERS.root,
        )

        # Drop all traffic that's not going to target
        await self.execute(
            "nft add rule ip MOMOS_IPv4 OUTPUT meta skuid momos drop",
            user=KALI_USERS.root,
        )

        # Prepare IPv6 table
        await self.execute("nft add table ip6 MOMOS_IPv6", user=KALI_USERS.root)

        # Create output chain
        await self.execute(
            "nft 'add chain ip6 MOMOS_IPv6 OUTPUT { type filter hook output priority 0; policy accept; }'",
            user=KALI_USERS.root,
        )

        # Allow traffic to comeback
        await self.execute(
            "nft add rule ip6 MOMOS_IPv6 OUTPUT meta skuid momos ct state established,related accept",
            user=KALI_USERS.root,
        )

        if target.ipv6 is not None:
            # Allow tcp and udp for ipv6
            for protocol, l4proto in [("tcp", L4PROTO_TCP), ("udp", L4PROTO_UDP)]:
                # Same "tcp"/"udp" alone isn't valid nft syntax fix as above.
                # "meta l4proto" (not "ip6 nexthdr") is used deliberately here -
                # nft's own docs warn that nexthdr only reflects the immediate
                # next header and misses the real upper-layer protocol when
                # extension headers are present.
                protocol_match = (
                    f"{protocol}{ports_str}" if ports_str else f"meta l4proto {l4proto}"
                )
                await self.execute(
                    f"nft add rule ip6 MOMOS_IPv6 OUTPUT meta skuid momos ip6 daddr {target.ipv6} {protocol_match} accept",
                    user=KALI_USERS.root,
                )

            # Allow icmpv6
            await self.execute(
                f"nft add rule ip6 MOMOS_IPv6 OUTPUT meta skuid momos ip6 daddr {target.ipv6} meta l4proto {L4PROTO_ICMPV6} accept",
                user=KALI_USERS.root,
            )

        # Allow DNS resolution to any resolver - same reasoning as the ipv4
        # table above.
        await self.execute(
            "nft add rule ip6 MOMOS_IPv6 OUTPUT meta skuid momos udp dport 53 accept",
            user=KALI_USERS.root,
        )
        await self.execute(
            "nft add rule ip6 MOMOS_IPv6 OUTPUT meta skuid momos tcp dport 53 accept",
            user=KALI_USERS.root,
        )

        # Drop all traffic that's not going to target
        await self.execute(
            "nft add rule ip6 MOMOS_IPv6 OUTPUT meta skuid momos drop",
            user=KALI_USERS.root,
        )

    async def execute(
        self,
        command: str,
        user: KALI_USERS = KALI_USERS.momos,
        timeout_seconds: int = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    ) -> str:
        loop = asyncio.get_running_loop()

        return await loop.run_in_executor(
            None, self._exec_in_container, command, user, timeout_seconds
        )

    async def stop(self):
        if self._session_sweep_task is not None:
            self._session_sweep_task.cancel()
            self._session_sweep_task = None
        await self.close_all_sessions()

        if self.container:
            logger.info(f"Closing Kali container: {self.container_name}")
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self.container.stop)
            self.container = None

    def __del__(self):
        if self.container:
            try:
                self.container.stop()
            except Exception:
                pass
