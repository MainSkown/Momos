import docker
import asyncio
import base64
import os
import re
import socket as socket_module
import time
from docker.errors import DockerException
import logging
from typing import Awaitable, Callable, Dict, Final, List, Optional, Sequence
from src.schemas import Target, KaliCreationStage
from enum import Enum
from .kali_session import (
    KaliSession,
    KaliSessionError,
    DEFAULT_READ_WINDOW_SECONDS,
    MAX_READ_WINDOW_SECONDS,
    MAX_SESSIONS_PER_TARGET,
    NO_OUTPUT_MESSAGE,
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

# Detects whether a session's latest output ended at its own plain shell
# prompt (e.g. "momos@bd30a780249c:~$ " or "root@bd30a780249c:~# ") rather
# than some other program's prompt (ftp's "ftp> ", mysql's "mysql> ", a
# Python ">>> ", msfconsole's "msf6 > ", ...). Confirmed against a real
# leaked prompt in production - see KaliManger._session_io's use of this.
# Terminal escape sequences (bracketed-paste toggles, colors, ...) are
# stripped first since a tty=True exec can emit them around the prompt.
# Built from every KALI_USERS member (not just momos) - the User Console's
# root sessions need their own "root@...#" prompt recognized too, or a
# root session's read-window early-exit never fires and every command
# silently pays the full wait_seconds instead of returning as soon as the
# prompt reappears.
#
# Also matches Kali's own decorated root prompt's bottom line ("└─# "/
# "└─$ ") directly, rather than relying on the plain "user@host:path$"
# alternative above - root's default PS1 in this image renders as TWO
# physical lines ("┌──(root㉿<host>)-[<cwd>]" then "└─# "), and that
# bottom line never contains "root@" at all (it uses "㉿", not a literal
# "@", on the line above). Confirmed in production: without this, a root
# session's early-exit never fired and every root command silently paid
# the full wait_seconds, even a near-instant one like "ls".
_ANSI_ESCAPE_PATTERN: Final = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
_SHELL_PROMPT_PATTERN: Final = re.compile(
    rf"(?:(?:{'|'.join(re.escape(str(u)) for u in KALI_USERS)})@\S+:.*[$#]|└─[#$])\s*$"
)


def _looks_like_shell_prompt(output: str) -> bool:
    cleaned = _ANSI_ESCAPE_PATTERN.sub("", output)
    return bool(_SHELL_PROMPT_PATTERN.search(cleaned.strip()))


def _leading_token(text: str) -> str:
    """First whitespace-separated word of `text`, path-stripped and
    lowercased - e.g. "/usr/bin/msfconsole -q" -> "msfconsole". Used both
    to tag which program a session just launched (KaliSession.
    active_program) and to correlate a dynamic rejection message back to
    what was actually sent this turn (see _check_confusion)."""
    first = text.strip().split(None, 1)
    return os.path.basename(first[0]).lower() if first else ""


# Program name (as produced by _leading_token on the command that launched
# it) -> regexes matching THAT program's own "I don't understand that"
# rejection of unrecognized input. A pattern with a capture group is
# dynamic - see _check_confusion - it only counts as confusion if the
# captured token matches what was actually sent this turn, not just
# because rejection-shaped text appears somewhere in the output.
#
# Deliberately closed/curated, with NO generic fallback for an unknown/
# uncurated program (this includes every real reverse or foreign shell,
# since those are launched the same way - plain input to run() - and so
# are otherwise indistinguishable from "some program we don't recognize").
# A generic "command not found"/"No such file or directory" fallback was
# designed, then deliberately rejected: it collides with completely
# ordinary, on-topic environment facts a real shell legitimately reports -
# a missing binary during a routine TTY-upgrade attempt
# (`python3 -c '...'` -> "bash: python3: command not found" is a true,
# useful answer, not confusion), or literal log content containing the
# phrase "No such file" from a target's own web server logs. Only
# programs with a genuinely foreign grammar (ftp/mysql/msfconsole/a REPL)
# can produce an unambiguous "that wasn't valid input to me" signal by
# construction - a real shell command line is always valid input to a
# shell, so a shell can never produce this signal in the first place.
_CONFUSION_SIGNATURES: Final[Dict[str, List["re.Pattern"]]] = {
    "ftp": [
        re.compile(r"\?Invalid command", re.IGNORECASE),
        re.compile(r"\?Ambiguous command", re.IGNORECASE),
    ],
    "mysql": [
        re.compile(r"ERROR 1064"),
        re.compile(r"You have an error in your SQL syntax"),
    ],
    "msfconsole": [re.compile(r"\[-\]\s*Unknown command:\s*(\S+)")],
    "python3": [
        re.compile(r"SyntaxError"),
        re.compile(r"NameError: name '([^']+)' is not defined"),
    ],
    "python": [
        re.compile(r"SyntaxError"),
        re.compile(r"NameError: name '([^']+)' is not defined"),
    ],
}


def _check_confusion(active_program: Optional[str], output: str, sent_token: str) -> bool:
    for pattern in _CONFUSION_SIGNATURES.get(active_program or "", []):
        match = pattern.search(output)
        if not match:
            continue
        if pattern.groups == 0:
            return True
        if os.path.basename(match.group(1)).lower() == sent_token:
            return True
    return False


# Only the last few dozen characters of a (possibly huge, e.g. full-port
# nmap) accumulated buffer can ever match _SHELL_PROMPT_PATTERN's own $
# anchor - checking only this tail on every chunk keeps the early-exit
# check in _session_io_sync cheap regardless of how much output has piled
# up, rather than re-decoding/re-matching the whole buffer every time.
_PROMPT_TAIL_CHECK_BYTES: Final = 256

# Once the session's own shell prompt reappears, the foreground command has
# genuinely finished and returned control - see _session_io_sync's early-exit
# comment. Still wait this much longer (rather than returning the instant
# it's seen) in case a little more output is still trailing right behind it.
_PROMPT_REAPPEAR_GRACE_SECONDS: Final = 2.0
# Same idea, but for the User Console specifically (see run_in_session) -
# a human typing commands one at a time expects near-instant feedback like
# a real terminal, where _PROMPT_REAPPEAR_GRACE_SECONDS's 2s floor on every
# single command reads as sluggish. The agent's own calls (run_in_current_
# session/interrupt_session) deliberately keep the longer default instead -
# its commands are often scan-like and can legitimately trail a little more
# output right behind the prompt, which the agent's parsing pipeline needs
# intact; a human watching the screen can just press Enter again if a
# command is still genuinely finishing up.
_CONSOLE_PROMPT_REAPPEAR_GRACE_SECONDS: Final = 0.3

# Same early-exit idea as _SHELL_PROMPT_PATTERN, but for interactive
# programs whose OWN prompt never matches the plain bash pattern (ftp's
# "ftp> ", confirmed against a real PTY session - it prints with no
# trailing newline, same as a shell prompt does). Keyed by _leading_token
# of the session's launch command - see _EXTRA_READY_PATTERNS/_session_io.
# Deliberately as narrow as _CONFUSION_SIGNATURES: a wrong match here would
# cut a still-running command's wait short, so only programs whose prompt
# text is unambiguous and confirmed get an entry.
_FTP_PROMPT_PATTERN: Final = re.compile(r"(?:^|\n)ftp>\s*$")
_EXTRA_READY_PATTERNS: Final[Dict[str, "re.Pattern"]] = {"ftp": _FTP_PROMPT_PATTERN}


def _looks_ready(output: str, extra_pattern: Optional["re.Pattern"]) -> bool:
    """Like _looks_like_shell_prompt, but also accepts `extra_pattern`
    (e.g. ftp's own "ftp> ") as an early-exit signal - see
    _EXTRA_READY_PATTERNS."""
    cleaned = _ANSI_ESCAPE_PATTERN.sub("", output).strip()
    if _SHELL_PROMPT_PATTERN.search(cleaned):
        return True
    return extra_pattern is not None and bool(extra_pattern.search(cleaned))


# IANA protocol numbers, used with "meta l4proto" instead of protocol names -
# name resolution depends on the container's /etc/protocols contents (e.g. it
# lists "ipv6-icmp", not "icmpv6"), so numbers are the portable choice. nft's
# own docs also recommend "meta l4proto" over "ip6 nexthdr" for IPv6, since
# nexthdr only reflects the immediate next header and misses extension headers.
L4PROTO_TCP: Final = 6
L4PROTO_UDP: Final = 17
L4PROTO_ICMP: Final = 1
L4PROTO_ICMPV6: Final = 58

# FTP's control channel negotiates the DATA channel's address/port inline in
# its own protocol (PORT/PASV/EPSV replies) - a plain per-target dport
# allowlist has no way to know about that port in advance, so without this,
# a passive-mode data connection to the random high port the server just
# assigned gets silently dropped by prepare_nftables's final "drop"
# rule, indistinguishable from an empty directory (confirmed in production:
# "ls" against a real vsftpd target got exactly as far as "227 Entering
# Passive Mode (...)" and then nothing - the client's next packet, to that
# announced port, never got a reply). The standard nftables fix is a "ct
# helper" object bound to the control channel's own traffic (tcp/21): the
# kernel's conntrack FTP ALG then inspects that connection's PORT/PASV
# replies itself and marks the resulting data connection "related", which
# the OUTPUT chain's existing "ct state established,related accept" rule
# already allows - no need to parse FTP replies or maintain the allowlist
# dynamically in this codebase at all.
FTP_CONTROL_PORT: Final = 21

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
    # Provides setcap/getcap - needed to grant nmap raw-socket capabilities
    # for the unprivileged momos user, see _configure_container.
    "libcap2-bin",
    # Pulled in solely for its bundled /usr/share/wordlists/dirb/common.txt
    # (~4.6k entries) - agent_tools.py's gobuster_scan needs a small,
    # ready-to-use wordlist by default; "wordlists" above only ships
    # rockyou.txt.gz (needs a manual gunzip, and far too large for a
    # bounded automated scan).
    "dirb",
    # Non-interactive SSH password auth from a one-shot command - needed by
    # agent_tools.py's ssh_check_login/ssh_run. openssh-client above only
    # provides the ssh binary itself, not this.
    "sshpass",
    # Provides `rev` - searchsploit's own `-p`/`-m` (path resolution/mirror)
    # shells out to it internally and fails outright without it ("rev:
    # command not found"), which broke agent_tools.py's searchsploit_view/
    # searchsploit_run entirely (both resolve a path via `searchsploit -p`
    # first). Not present in this base image by default - `rev` moved out
    # of the base system into this package after the bsdmainutils split.
    "bsdextrautils",
    # Large (~518MB download, pulls in a full postgresql server, ruby,
    # mingw toolchains, ...) - the same category of cost that got
    # kali-linux-headless dropped above. Added anyway despite that,
    # specifically so the agent doesn't have to install_kali_package it
    # (and wait through that same download) on every single run that ends
    # up needing it - observed in production repeatedly reaching for
    # msfconsole once past initial recon. Revisit if container startup
    # time becomes a problem again.
    # "metasploit-framework",
)

# Granted to this binary (via setcap, in _configure_container) so nmap's
# default SYN/raw-socket scans work for the unprivileged `momos` user.
# Deliberately NOT solved by running agent commands as root instead - the
# target-scope nftables rules in prepare_nftables() are all keyed to
# `meta skuid momos`, so root traffic would bypass that firewall entirely.
NMAP_BINARY_PATH: Final = "/usr/bin/nmap"

# The "wordlists" package (see DEFAULT_KALI_PACKAGES) only ships this
# gzipped - unzipped once in _configure_container so agent_tools.py's
# hydra_bruteforce/gobuster_scan can point straight at the plain-text
# path without the agent having to gunzip it itself first.
ROCKYOU_WORDLIST_GZ_PATH: Final = "/usr/share/wordlists/rockyou.txt.gz"
ROCKYOU_WORDLIST_PATH: Final = "/usr/share/wordlists/rockyou.txt"

# Debian's python3 always has this on sys.path regardless of the exact
# python3.X minor version installed (unlike a version-specific site-
# packages dir) - the standard location for a hand-installed pure-Python
# module system-wide.
TELNETLIB_SHIM_PATH: Final = "/usr/lib/python3/dist-packages/telnetlib.py"

# telnetlib was removed from Python's standard library in 3.13 (PEP 594) -
# this image's python3 is new enough that it's simply gone, which broke
# agent_tools.py's searchsploit_run outright on one of the most common
# exploit-db scripts (vsftpd 2.3.4's backdoor, EDB-ID 49757, does `from
# telnetlib import Telnet`) with "ModuleNotFoundError: No module named
# 'telnetlib'". There is no PyPI package that actually provides this
# (verified against a real failure: "ERROR: No matching distribution found
# for telnetlib") - this is a minimal, from-scratch, independently-tested
# reimplementation of the small subset of the original Telnet class
# exploit-db scripts actually use (connect/write/read_until/read_all/
# read_some/close), written directly over `socket` rather than
# reproducing the original's much larger IAC option-negotiation/interact()
# machinery - not needed for the common case (a raw shell backdoor or a
# protocol trick over a plain control connection, neither of which
# actually negotiate telnet options). Deployed as a real file (not paged
# through a limited apt/pip install) via base64 (see _configure_container)
# specifically to avoid any shell-quoting risk from embedding this much
# Python source directly in a `bash -c` command string.
_TELNETLIB_SHIM_SOURCE = '''"""Minimal drop-in replacement for the stdlib telnetlib module removed in
Python 3.13 (PEP 594) - see kali_manager.py's TELNETLIB_SHIM_PATH for why
this exists instead of an actual PyPI package."""
import socket
import time
from typing import Optional

DEFAULT_TIMEOUT = 30


class Telnet:
    def __init__(self, host: Optional[str] = None, port: int = 0, timeout: float = DEFAULT_TIMEOUT):
        self.sock: Optional[socket.socket] = None
        self.timeout = timeout
        self._buffer = b""
        if host is not None:
            self.open(host, port, timeout)

    def open(self, host: str, port: int = 0, timeout: float = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.sock = socket.create_connection((host, port or 23), timeout=timeout)
        self._buffer = b""

    def write(self, buffer: bytes):
        if self.sock is None:
            raise OSError("Telnet: not connected")
        self.sock.sendall(buffer)

    def read_some(self) -> bytes:
        if self._buffer:
            data, self._buffer = self._buffer, b""
            return data
        try:
            data = self.sock.recv(4096)
        except socket.timeout:
            return b""
        return data

    def read_until(self, match: bytes, timeout: Optional[float] = None) -> bytes:
        deadline = None if timeout is None else time.monotonic() + timeout
        data = self._buffer
        self._buffer = b""
        while match not in data:
            remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
            if remaining == 0.0:
                break
            self.sock.settimeout(remaining if remaining is not None else self.timeout)
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        if match in data:
            idx = data.index(match) + len(match)
            data, self._buffer = data[:idx], data[idx:]
        return data

    def read_all(self) -> bytes:
        data = self._buffer
        self._buffer = b""
        self.sock.settimeout(None)
        while True:
            try:
                chunk = self.sock.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            data += chunk
        return data

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
'''

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

        # Persistent interactive sessions (a default bash shell plus any
        # named sessions the agent opens) - deliberately independent of
        # command_lock above, since a long-lived session must never block
        # one-shot execute() calls or vice versa. This lock only guards
        # dict membership; each KaliSession has its own io_lock for its
        # actual socket I/O. Keyed by _session_key(target_id, agent_run_id,
        # name), not by name alone - one manager is shared across every
        # target in a project (and, within one target, across every
        # concurrently-running agent on it - see agent_run_id's own
        # comment on KaliSession), so names (e.g. "default") are only
        # unique per (target, owning agent run).
        self.sessions: Dict[str, KaliSession] = {}
        self.sessions_lock = asyncio.Lock()
        # _owner_key(target_id, agent_run_id) -> name of THAT owner's
        # current session (the one run()/interrupt_session() act on unless
        # the agent switch_session's elsewhere first). Per-owner, not just
        # per-target, so two concurrently-running agents on the same target
        # each have their own independent "current" pointer and can never
        # see or move each other's.
        self.current_session: Dict[str, str] = {}
        # (target_id, agent_run_id, name) triples currently being opened -
        # validated (name not colliding FOR THIS OWNER, target under
        # MAX_SESSIONS_PER_TARGET) but not yet in `sessions` because the
        # slow docker exec_create/exec_start hasn't finished. Guarded by
        # sessions_lock, same as `sessions` itself - see open_session's
        # TOCTOU fix.
        self._pending_sessions: set[tuple[str, str, str]] = set()
        self._session_sweep_task: Optional[asyncio.Task] = None
        # Monotonic (target_id, user) -> next session number to hand out -
        # see next_session_number. Lives here (not derived from `sessions`
        # at call time) specifically so a number is never reused: `sessions`
        # also doubles as "currently open" state, and a name freed by a
        # close that's still unwinding (see _close_session's own comment -
        # _remove_from_registry runs before the socket is actually closed)
        # could otherwise be handed out again to a brand-new, unrelated
        # session while the old one's last read is still in flight.
        self._session_numbers: Dict[str, int] = {}
        # Optional async hook, set by whoever owns this manager's project-
        # level identity (kali_user.py) - called with (target_id, name)
        # whenever the idle sweep below closes a session on its own
        # initiative, not in response to an explicit close_session call.
        # None by default: an agent-driven session needs no such
        # notification (nothing agent-side listens for one), only the
        # console does, to keep a tab from silently going stale in the UI.
        self.session_closed_notifier: Optional[Callable[[str, str], Awaitable[None]]] = None

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
            "DEBIAN_FRONTEND=noninteractive apt-get install -y "
            + " ".join(self.packages)
        )
        print("Unzipping rockyou.txt wordlist")
        self._exec_in_container(
            f"[ -f {ROCKYOU_WORDLIST_PATH} ] || gunzip -k {ROCKYOU_WORDLIST_GZ_PATH}"
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

        # nmap's own postinst normally sets these capabilities itself, but
        # that step silently no-ops if libcap2-bin wasn't present yet when
        # it ran - set them explicitly and unconditionally so nmap's
        # raw-socket scans (SYN scan, OS detection, ...) work for the
        # unprivileged momos user rather than failing with "Couldn't open a
        # raw socket. Operation not permitted".
        self._exec_in_container(f"setcap cap_net_raw,cap_net_admin+eip {NMAP_BINARY_PATH}")

        # See TELNETLIB_SHIM_PATH/_TELNETLIB_SHIM_SOURCE's own comments for
        # why this is a hand-written file, not a package install - base64
        # avoids any shell-quoting risk from embedding this much Python
        # source directly in a `bash -c` command string.
        encoded_shim = base64.b64encode(_TELNETLIB_SHIM_SOURCE.encode()).decode()
        self._exec_in_container(f"echo {encoded_shim} | base64 -d > {TELNETLIB_SHIM_PATH}")

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
            self._exec_in_container(f"getcap {NMAP_BINARY_PATH} | grep -q cap_net_raw")
            self._exec_in_container("python3 -c 'import telnetlib'")
            self._exec_in_container(f"test -f {ROCKYOU_WORDLIST_PATH}")
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
    # A terminal-style model: every target has a "current" session (a
    # default bash shell, auto-opened by Agent.start_agent before the first
    # turn) that run()/interrupt_session() act on, plus any additional named
    # sessions the agent opens and switches between. Replaces the old
    # one-shot execute_kali_command + session_id-keyed tool set - see
    # kali_session.py for the KaliSession dataclass and tunables.

    def _session_key(self, target_id: str, agent_run_id: str, name: str) -> str:
        # Sessions are named by the agent (e.g. "default", "ftp") and only
        # need to be unique per (target, owning agent run) - one manager is
        # shared across every target in a project, AND, within one target,
        # across every concurrently-running agent on it (see
        # KaliSession.agent_run_id), so the dict key namespaces by both.
        return f"{target_id}::{agent_run_id}::{name}"

    def _owner_key(self, target_id: str, agent_run_id: str) -> str:
        # Key into self.current_session - one independent "current session"
        # pointer per (target, owning agent run), so concurrent agents on
        # the same target can never see or move each other's.
        return f"{target_id}::{agent_run_id}"

    def _session_number_key(self, target_id: str, user: str) -> str:
        # Deliberately its OWN key shape, not _session_key reused - this
        # counter is scoped to (target_id, OS user), an axis that has
        # nothing to do with agent_run_id (the console's auto-numbered
        # tabs, the only caller, has no agent run at all). Keeping this
        # decoupled means widening _session_key for session ownership can
        # never silently change what this counter is keyed by.
        return f"{target_id}::{user}"

    async def next_session_number(self, target_id: str, user: str) -> int:
        """Hands out the next number for an auto-numbered session (the
        User Console's "root-1", "root-2", ... - see kali_user.py's
        create_session), scoped to (target_id, user) so root's and momos's
        own numbers count independently. Deliberately a standalone counter
        rather than `max(existing session suffixes) + 1` computed from
        `list_sessions` at call time - that version raced with a session
        being closed (see _close_session: the name is freed from `sessions`
        before the socket is actually closed) and could hand out an
        already-in-use number to a brand-new, unrelated session while the
        old one's last read was still unwinding. This only ever increments,
        for as long as this manager (i.e. this project's container) is
        tracked in-process - a number is never handed out twice."""
        key = self._session_number_key(target_id, user)
        async with self.sessions_lock:
            next_number = self._session_numbers.get(key, 0) + 1
            self._session_numbers[key] = next_number
            return next_number

    def _get_session(self, target_id: str, agent_run_id: str, name: str) -> KaliSession:
        session = self.sessions.get(self._session_key(target_id, agent_run_id, name))
        if session is None:
            raise KaliSessionError(
                f"No such session '{name}' - it may have already been closed "
                "(explicitly, by an idle timeout, or because its process exited)."
            )
        if session.closed:
            raise KaliSessionError(f"Session '{name}' is closed: {session.close_reason}")
        return session

    def _get_current_session(self, target_id: str, agent_run_id: str) -> KaliSession:
        name = self.current_session.get(self._owner_key(target_id, agent_run_id))
        if name is None:
            raise KaliSessionError(
                "No current session for this target - open one with new_session."
            )
        return self._get_session(target_id, agent_run_id, name)

    def has_current_session(self, target_id: str, agent_run_id: str) -> bool:
        return self._owner_key(target_id, agent_run_id) in self.current_session

    def get_current_session_name(self, target_id: str, agent_run_id: str) -> Optional[str]:
        return self.current_session.get(self._owner_key(target_id, agent_run_id))

    def get_current_session(
        self, target_id: str, agent_run_id: str
    ) -> Optional[KaliSession]:
        """Non-raising counterpart to _get_current_session - returns None
        (rather than raising) whenever there's no current session, or it's
        somehow missing/closed, so a caller that just wants to know "what's
        current, if anything" (e.g. agent.py's session-identity reminder, or
        a tool wrapper reporting the session it just switched to) doesn't
        need to handle KaliSessionError for what isn't really an error case
        for it."""
        name = self.current_session.get(self._owner_key(target_id, agent_run_id))
        if name is None:
            return None
        session = self.sessions.get(self._session_key(target_id, agent_run_id, name))
        if session is None or session.closed:
            return None
        return session

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
        # uv.lock; re-verify if that pin is ever bumped.
        wrapper = self.client.api.exec_start(exec_id, socket=True, tty=True)
        return exec_id, wrapper._sock

    async def open_session(
        self,
        target_id: str,
        agent_run_id: str,
        name: str,
        command: str,
        user: KALI_USERS = KALI_USERS.momos,
    ) -> KaliSession:
        key = self._session_key(target_id, agent_run_id, name)
        async with self.sessions_lock:
            if (
                (key in self.sessions and not self.sessions[key].closed)
                or (target_id, agent_run_id, name) in self._pending_sessions
            ):
                raise KaliSessionError(
                    f"A session named '{name}' is already open - close it "
                    "first, or switch_session to it instead of opening another."
                )
            # Deliberately summed across every owner of this target (not
            # just agent_run_id) - this is a shared-container resource cap,
            # not a per-agent-run one; several concurrently-running agents
            # on the same target still share one MAX_SESSIONS_PER_TARGET
            # budget.
            open_for_target = sum(
                1 for s in self.sessions.values() if s.target_id == target_id
            ) + sum(1 for (t, _, _) in self._pending_sessions if t == target_id)
            if open_for_target >= MAX_SESSIONS_PER_TARGET:
                raise KaliSessionError(
                    f"Too many open sessions ({MAX_SESSIONS_PER_TARGET} max) - "
                    "close an existing one with close_session before opening another."
                )
            # Reserve this (target_id, agent_run_id, name) for the duration
            # of the slow exec below, still inside the same locked section
            # as the checks above - a concurrent open_session for the same
            # name (ToolNode runs a turn's tool calls concurrently) now sees
            # the reservation and fails validation immediately, instead of
            # both calls passing the check here and one silently clobbering
            # the other's `sessions` entry once the exec finishes.
            self._pending_sessions.add((target_id, agent_run_id, name))

        try:
            loop = asyncio.get_running_loop()
            exec_id, raw_sock = await loop.run_in_executor(
                None, self._open_session_sync, command, user
            )
        except Exception:
            async with self.sessions_lock:
                self._pending_sessions.discard((target_id, agent_run_id, name))
            raise

        session = KaliSession(
            name=name,
            command=command,
            target_id=target_id,
            agent_run_id=agent_run_id,
            exec_id=exec_id,
            sock=raw_sock,
            user=str(user),
            # Tagged from the launch command itself, not just inferred later
            # from typed input - new_session's own first read is a bare poll
            # (data=None), which the _session_io transition logic can't tag
            # from. Harmless for the default "/bin/bash" launch: "bash" is
            # never a key in _CONFUSION_SIGNATURES.
            active_program=_leading_token(command),
        )

        async with self.sessions_lock:
            self.sessions[key] = session
            self.current_session[self._owner_key(target_id, agent_run_id)] = name
            self._pending_sessions.discard((target_id, agent_run_id, name))

        self._ensure_session_sweep_running()
        return session

    def _session_io_sync(
        self,
        sock: socket_module.socket,
        data: Optional[bytes],
        wait_seconds: float,
        extra_ready_pattern: Optional["re.Pattern"] = None,
        prompt_reappear_grace_seconds: float = _PROMPT_REAPPEAR_GRACE_SECONDS,
    ) -> str:
        """Runs in the executor thread. Optionally writes `data`, then
        drains whatever arrives until `wait_seconds` pass with NO new data
        at all, the session's own shell prompt (or `extra_ready_pattern`,
        for a curated non-shell program - see _EXTRA_READY_PATTERNS)
        reappears (see below), or the peer closes (the session's process
        exited).

        Deliberately not a short "stop at the first quiet gap" heuristic -
        a command can print a little (a banner, a warning) and then
        legitimately go quiet for real seconds while it keeps working
        before printing its actual result, and there is no way to tell
        that apart from "actually finished" purely from a pause in output.
        A shorter settle-based cutoff was tried and reliably returned early
        in exactly that case (see MAX_READ_WINDOW_SECONDS's comment),
        silently truncating the result.

        The one signal that IS safe to short-circuit on is the session's
        own shell prompt (_looks_like_shell_prompt) reappearing: bash only
        ever reprints it once it has genuinely reclaimed the terminal from
        the foreground process, so a still-running command cannot produce
        this the way a mid-command pause could - unlike the quiet-gap
        heuristic above, this isn't a guess about timing, it's the shell
        itself reporting "I'm ready for the next command." Without this,
        callers are pushed (by run()'s own docstring) toward generous
        `wait_seconds` for anything scan-like "just in case" it pauses
        internally - and a command that actually finishes in a few seconds
        then sits idle for the rest of that generous window for no reason,
        which measured live cost ~95% of a real nmap call's wall-clock
        time. `wait_seconds` remains the hard ceiling either way - this
        only ever shortens the wait once the prompt is back, never removes
        it or returns a partial result while the command could plausibly
        still be running."""
        if data is not None:
            sock.settimeout(SOCKET_WRITE_TIMEOUT_SECONDS)
            sock.sendall(data)

        # Each recv() below gets its own fresh timeout (Python's
        # socket.settimeout applies per blocking call, not as a shared
        # countdown) - so this is a resetting idle timer, not a fixed total
        # budget: any new chunk pushes the deadline back out by the full
        # window again, exactly like the original single-settimeout(wait_
        # seconds)-before-the-loop version this replaced. The only change
        # is *which* window gets applied next: the normal full wait_seconds
        # after ordinary output, or the short grace window once the tail
        # looks like the shell prompt reappearing.
        chunks = bytearray()
        next_timeout = wait_seconds
        # The terminal always echoes back the CURRENT prompt plus the
        # just-typed line before the command actually runs (ordinary TTY
        # echo) - _looks_like_shell_prompt cannot tell that apart from a
        # genuinely-finished command's new prompt, so checking against it
        # immediately would make nearly every call that sends input return
        # right after the echo, before the real command has even started.
        # Confirmed in production: this exact bug truncated a real nmap
        # scan down to its first banner line. Only start checking once real
        # output has begun arriving - i.e. after the first newline
        # following the send, since the echoed input+Enter always ends
        # with one before anything the command itself prints. A bare poll
        # (no data sent) has no such echo to wait out, so it's eligible to
        # check from the very first byte.
        prompt_check_armed = data is None
        try:
            while True:
                sock.settimeout(next_timeout)
                chunk = sock.recv(SOCKET_RECV_CHUNK_BYTES)
                if not chunk:
                    raise EOFError("session process exited")
                chunks.extend(chunk)

                if not prompt_check_armed and b"\n" in chunk:
                    # Arms within the SAME chunk that ends the input echo,
                    # rather than only from the next one - otherwise a fast
                    # command whose entire echo+output+new-prompt arrives
                    # in one recv() would still wait out a full unnecessary
                    # cycle before this check is even attempted.
                    prompt_check_armed = True

                if not prompt_check_armed:
                    next_timeout = wait_seconds
                    continue

                tail = chunks[-_PROMPT_TAIL_CHECK_BYTES:].decode(errors="replace")
                if _looks_ready(tail, extra_ready_pattern):
                    next_timeout = prompt_reappear_grace_seconds
                else:
                    # Either ordinary output, or more data arrived right
                    # after what looked like a prompt (a false match inside
                    # real output, or a background flush) - either way,
                    # back to waiting the normal generous amount.
                    next_timeout = wait_seconds
        except socket_module.timeout:
            pass  # Expected: no more output within the window.

        return chunks.decode(errors="replace")

    async def run_in_current_session(
        self,
        target_id: str,
        agent_run_id: str,
        input: Optional[str],
        wait_seconds: float = DEFAULT_READ_WINDOW_SECONDS,
    ) -> str:
        # tty=True means the program on the other end expects a line
        # terminator to treat this as "Enter was pressed".
        data = (input + "\n").encode() if input is not None else None
        session = self._get_current_session(target_id, agent_run_id)
        return await self._session_io(session, data, wait_seconds)

    async def run_in_session(
        self,
        target_id: str,
        agent_run_id: str,
        name: str,
        input: Optional[str],
        wait_seconds: float = DEFAULT_READ_WINDOW_SECONDS,
    ) -> str:
        """Like run_in_current_session, but resolves the session by NAME
        directly instead of through current_session's "whatever's current
        for this target_id" pointer - for a caller (the User Console) that
        can have several sessions open and visible at once, where sending
        a command to one must never depend on, or silently change, which
        session another one would resume into. current_session is a
        single-focus affordance that only makes sense for a caller (the
        agent) that's only ever "in" one session at a time - this
        deliberately bypasses it rather than switch_session-ing first.

        Also uses the shorter _CONSOLE_PROMPT_REAPPEAR_GRACE_SECONDS once
        the prompt reappears - this is the only caller driven by a human
        watching the screen in real time rather than an agent's own
        tool-call loop, so it's also the only one worth trading away a
        little trailing-output margin for a snappier feel."""
        data = (input + "\n").encode() if input is not None else None
        session = self._get_session(target_id, agent_run_id, name)
        return await self._session_io(
            session,
            data,
            wait_seconds,
            prompt_reappear_grace_seconds=_CONSOLE_PROMPT_REAPPEAR_GRACE_SECONDS,
        )

    def _write_to_session_sync(self, sock: socket_module.socket, data: bytes) -> None:
        sock.settimeout(SOCKET_WRITE_TIMEOUT_SECONDS)
        sock.sendall(data)

    async def interrupt_session(self, target_id: str, agent_run_id: str) -> str:
        """Sends Ctrl-C to the current session's foreground process, and
        reads back whatever it produces in response (e.g. "^C" echoed plus
        a fresh shell prompt) - the replacement for the automatic `timeout`
        wrapper execute_kali_command used to have, now that everything runs
        inside a persistent session instead of a one-shot exec call.

        If the session's own io_lock is already held - a foreground
        command's read is still blocked waiting for output, exactly the
        situation this tool exists to recover from - this does NOT wait for
        that lock: a socket WRITE is safe to issue while another thread has
        a read in flight on the same socket (only two concurrent READS
        would actually race), so the Ctrl-C byte is sent directly and this
        returns immediately, letting the already-blocked read pick up
        whatever the interrupt produces within its own still-open wait
        window. Going through the normal locked path here instead would
        just queue this call up behind the exact same stuck read it's
        meant to recover from, defeating the one documented escape hatch
        for that scenario."""
        session = self._get_current_session(target_id, agent_run_id)

        if session.io_lock.locked():
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None, self._write_to_session_sync, session.sock, b"\x03"
            )
            return (
                "Sent Ctrl-C while a previous read on this session was still "
                "in progress - its output (including anything caused by "
                "this interrupt) will appear in that call's result, or your "
                "next run() call."
            )

        return await self._session_io(session, b"\x03", DEFAULT_READ_WINDOW_SECONDS)

    async def _session_io(
        self,
        session: KaliSession,
        data: Optional[bytes],
        wait_seconds: float,
        prompt_reappear_grace_seconds: float = _PROMPT_REAPPEAR_GRACE_SECONDS,
    ) -> str:
        wait_seconds = max(0.5, min(wait_seconds, MAX_READ_WINDOW_SECONDS))
        loop = asyncio.get_running_loop()
        extra_ready_pattern = _EXTRA_READY_PATTERNS.get(_leading_token(session.command))

        async with session.io_lock:
            try:
                output = await loop.run_in_executor(
                    None,
                    self._session_io_sync,
                    session.sock,
                    data,
                    wait_seconds,
                    extra_ready_pattern,
                    prompt_reappear_grace_seconds,
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
                    f"Session '{session.name}' process exited "
                    f"(exit code {exit_info.get('ExitCode')}). The session is now closed."
                )
            except OSError as e:
                await self._remove_from_registry(session)
                await self._close_session_locked(session, reason=f"socket error: {e}")
                raise KaliSessionError(
                    f"Session '{session.name}' hit a socket error and was closed: {e}"
                )

        if output:
            # Only meaningful for a plain-shell-launched session (a session
            # opened via new_session with a genuinely different command,
            # e.g. "msfconsole", simply never matches this pattern either -
            # harmless, since callers only ever check at_shell_prompt
            # alongside session.command == DEFAULT_SESSION_COMMAND anyway).
            prev_at_shell_prompt = session.at_shell_prompt
            prev_had_prior_io = session.had_prior_io
            session.at_shell_prompt = _looks_like_shell_prompt(output)
            session.had_prior_io = True
            sent_text = data.decode(errors="replace") if data is not None else None

            if session.at_shell_prompt:
                # Back home - nothing left to track.
                session.confusion_streak = 0
                session.active_program = None
            elif prev_at_shell_prompt:
                # Fresh transition (just launched ftp/telnet/nc/msfconsole/
                # ...) - never punish the launch turn itself, only what
                # happens after (see _CONFUSION_SIGNATURES's own comment).
                if sent_text and prev_had_prior_io:
                    session.active_program = _leading_token(sent_text)
                # else: a bare poll caused/observed this transition (e.g.
                # new_session's own initial read, right after open_session
                # already tagged active_program from the launch command),
                # OR this is a directly-launched non-bash session's (ftp/
                # telnet/msfconsole/...) very first _session_io call ever -
                # either way active_program is already correctly set from
                # the launch command by open_session, so don't clobber it
                # with whatever was just sent INTO that already-running
                # program (see KaliSession.had_prior_io).
                session.confusion_streak = 0
            elif sent_text is not None and session.active_program in _CONFUSION_SIGNATURES:
                # Already inside a KNOWN, curated program and still not
                # home - only these have a real foreign grammar distinct
                # from a genuine on-topic answer (even a rejection like
                # "530 Login incorrect" is on-topic and must never count).
                if _check_confusion(session.active_program, output, _leading_token(sent_text)):
                    session.confusion_streak += 1
                else:
                    session.confusion_streak = 0
            # else: a bare poll (sent_text is None) while already stuck, or
            # an UNCURATED active_program (includes any real reverse/
            # foreign shell) - leave confusion_streak unchanged. Uncurated
            # programs deliberately never accumulate a streak from output
            # content at all - see _CONFUSION_SIGNATURES's own comment for
            # why a generic fallback was tried and rejected. These rely
            # solely on the existing SESSION_IDLE_TIMEOUT_SECONDS sweep
            # instead - a known, accepted gap, not a silent new one.

        session.last_activity = time.monotonic()
        return output if output else NO_OUTPUT_MESSAGE

    async def promote_stuck_session(
        self, target_id: str, agent_run_id: str, default_name: str, default_command: str
    ) -> Optional[str]:
        """If target_id's CURRENT session - whatever it's named, whether
        that's the plain default one or one opened via new_session (e.g.
        "ftptest") - has racked up 2+ consecutive turns of its own active
        program rejecting input as unrecognized (session.confusion_streak
        >= 2 - see _check_confusion/_session_io), gets target_id back onto
        a working "default" shell session. If the stuck session IS the
        default one, it's renamed to a fresh, uniquely named session first -
        its live connection/socket is untouched, so switch_session can
        still reach it - and a brand-new plain "default" session is opened
        in its place. If the stuck session has its own distinct name, it's
        left exactly where it is (already reachable via switch_session/
        list_sessions) and "default" is simply made current instead -
        reusing an existing separate "default" session if target_id already
        has one, or opening a fresh one if not. Returns the name of the
        session that was left/renamed as stuck, or None if there was
        nothing to promote.

        Exists because a purely textual reminder telling the agent it might
        still be stuck inside another program (ftp, telnet, ...) turned out
        to be easy to ignore in practice - confirmed in production, an
        agent spent ~20 of a 30-minute run retrying unrelated shell
        commands against a session it never escaped, despite that reminder
        firing every single turn. This fixes it mechanically instead:
        whatever the next run() call is, it lands in a working shell
        either way.

        Deliberately gated on confusion_streak, NOT merely
        "not at shell prompt" - that first version was tried and reverted:
        "not at shell prompt" is also the correct, persistent state for a
        genuinely productive multi-turn interactive session (a real ftp
        login flow, a msfconsole module being driven, ...), and confirmed
        in production to sever a session the agent was about to correctly
        continue (a plain nc connect got promoted away before the agent
        could send its natural follow-up). confusion_streak instead only
        counts turns where the CURRENT program's own output said it didn't
        understand the input - see _CONFUSION_SIGNATURES's own comment for
        the full reasoning (including why an unrecognized/uncurated
        program, e.g. any real reverse shell, gets none of this and relies
        on the existing idle-timeout sweep instead)."""
        owner_key = self._owner_key(target_id, agent_run_id)
        async with self.sessions_lock:
            current_name = self.current_session.get(owner_key)
            if current_name is None:
                return None
            session = self.sessions.get(
                self._session_key(target_id, agent_run_id, current_name)
            )
            if session is None or session.closed or session.confusion_streak < 2:
                return None

            stuck_name = current_name
            if current_name == default_name:
                # Renaming "default" out from under itself, so the fresh
                # replacement below has a clear name to occupy.
                n = 1
                while self._session_key(target_id, agent_run_id, f"recovered-{n}") in self.sessions:
                    n += 1
                stuck_name = f"recovered-{n}"
                session.name = stuck_name
                del self.sessions[self._session_key(target_id, agent_run_id, current_name)]
                self.sessions[self._session_key(target_id, agent_run_id, stuck_name)] = session
            # else: already has its own distinct name (e.g. "ftptest") -
            # leave it exactly where it is, just stop it being current.

            session.confusion_streak = 0

            existing_default = self.sessions.get(
                self._session_key(target_id, agent_run_id, default_name)
            )
            reuse_existing_default = (
                existing_default is not None and not existing_default.closed
            )
            if reuse_existing_default:
                self.current_session[owner_key] = default_name

        if not reuse_existing_default:
            # Outside the lock - open_session's own slow exec_create needs
            # to run unlocked (see its own comments), and it re-acquires
            # sessions_lock itself for the actual registration.
            await self.open_session(target_id, agent_run_id, default_name, default_command)

        return stuck_name

    async def switch_session(self, target_id: str, agent_run_id: str, name: str) -> None:
        # Raises KaliSessionError if unknown/closed - validated before
        # actually switching, so a bad name leaves the current pointer alone.
        self._get_session(target_id, agent_run_id, name)
        async with self.sessions_lock:
            self.current_session[self._owner_key(target_id, agent_run_id)] = name

    async def _reassign_current_after_close(
        self, target_id: str, agent_run_id: str, name: str
    ) -> None:
        """If `name` was target_id's current session, falls back to any
        other still-open session for that target, or clears the pointer if
        none remain - the terminal tools layer (agent_tools.py) re-opens
        "default" on the next run() call rather than kali_manager deciding
        that policy itself. Shared by close_session and the idle sweep
        below - the sweep previously cleared the pointer unconditionally
        even when another session was alive and untouched, which could
        make a later new_session("default", ...)/run()'s defensive re-open
        fail on a stale name collision instead of actually falling back.

        Filters the fallback by agent_run_id too, not just target_id - or
        this owner's pointer could get reassigned to a SIBLING concurrently-
        running agent's session on the same target, which that sibling
        never opened this pointer for and may itself switch_session away
        from at any time."""
        owner_key = self._owner_key(target_id, agent_run_id)
        async with self.sessions_lock:
            if self.current_session.get(owner_key) != name:
                return
            remaining = [
                s.name
                for s in self.sessions.values()
                if s.target_id == target_id
                and s.agent_run_id == agent_run_id
                and not s.closed
            ]
            if remaining:
                self.current_session[owner_key] = remaining[0]
            else:
                self.current_session.pop(owner_key, None)

    async def close_session(
        self, target_id: str, agent_run_id: str, name: str, force: bool = False
    ) -> bool:
        """Closes a session by name. Returns True if a session with that
        name actually existed and was closed, False if there was nothing to
        close (already gone - explicitly, idle-swept, or its process
        exited) - callers should report this accurately rather than always
        claiming success.

        `force` controls what happens if a foreground command is currently
        blocking a read on this exact session (see _close_session) - it
        only ever makes sense for an explicit, single-session "close THIS
        one, now" request (the console's own close/exit, or the agent's
        own close_session tool), where blocking until that read's own
        wait_seconds elapses would defeat the point of asking to close it
        at all. Left False (the original, safe-wait behavior) for every
        other caller here - bulk/background cleanup (agent run ending,
        container stopping, the idle sweep) has no such urgency, and
        forcibly severing a session's socket while a legitimate, still-
        progressing command is mid-read is worse than just waiting for it."""
        session = self.sessions.get(self._session_key(target_id, agent_run_id, name))
        if session is None:
            return False
        await self._close_session(session, reason="closed by agent", force=force)
        await self._reassign_current_after_close(target_id, agent_run_id, name)
        return True

    async def _remove_from_registry(self, session: KaliSession) -> None:
        async with self.sessions_lock:
            self.sessions.pop(
                self._session_key(session.target_id, session.agent_run_id, session.name),
                None,
            )

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

    def _force_close_socket_sync(self, session: KaliSession, reason: str) -> None:
        """Like _close_session_locked, but doesn't wait for (or hold)
        session.io_lock first - see _close_session's own comment for why.
        Runs in the executor thread, same as the normal close - socket.
        close() itself is a fast, non-blocking syscall, but routing it
        through the same executor as every other socket op here keeps
        this consistent rather than a special case."""
        if session.closed:
            return
        session.closed = True
        session.close_reason = reason
        session.sock.close()

    async def _close_session(
        self, session: KaliSession, reason: str, force: bool = False
    ) -> None:
        await self._remove_from_registry(session)
        if force and session.io_lock.locked():
            # A foreground command that never exits AND has gone quiet
            # (a `nc -lvp` listener sitting idle waiting for a connection
            # is the concrete case this was reported against) can hold a
            # run_in_session call - and its io_lock - for as long as its
            # own wait_seconds allows, up to MAX_READ_WINDOW_SECONDS.
            # Waiting for that lock here (the normal path below) would
            # make closing/exiting the session - the one thing meant to
            # always work, even on a stuck session - queue up behind the
            # exact read it's meant to escape, locking the user out of
            # their own "exit" for as long as that read is still open.
            # Instead, close the socket directly, unlocked - the same
            # underlying guarantee interrupt_session's own lock-busy
            # branch already relies on for a plain write: closing a
            # socket out from under another thread's blocking recv() make
            # that recv() return/raise right away, and _session_io's own
            # EOFError/OSError handling (already written for exactly this
            # shape of failure) takes it from there - it'll see
            # session.closed already True below and no-op its own close
            # attempt rather than double-closing or overwriting this
            # close_reason.
            #
            # Gated on `force` (only close_session's explicit single-
            # session callers pass it) rather than applying whenever the
            # lock happens to be held - close_sessions_for_target/
            # close_all_sessions/the idle sweep below all call this
            # unforced, and a session they're closing can legitimately
            # still be mid-read on a perfectly normal, still-progressing
            # command; those callers are fine waiting for it, same as
            # they always have, rather than severing it out from under
            # itself just because the timing happened to overlap.
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None, self._force_close_socket_sync, session, reason
            )
        else:
            async with session.io_lock:
                await self._close_session_locked(session, reason)

    async def close_sessions_for_target(self, target_id: str) -> None:
        """Closes EVERY session on this target, regardless of which agent
        run owns it. Still used as-is where that's genuinely the intent
        (the container itself going away, or a caller that predates
        per-run ownership) - but a single concurrent agent run ending must
        use close_sessions_for_run below instead, or it would tear down
        every OTHER still-running agent's sessions on this same target too."""
        async with self.sessions_lock:
            to_close = [
                s for s in self.sessions.values() if s.target_id == target_id
            ]
            owner_prefix = f"{target_id}::"
        for session in to_close:
            await self._close_session(session, reason="agent run ended")
        async with self.sessions_lock:
            for owner_key in [
                k for k in self.current_session if k.startswith(owner_prefix)
            ]:
                del self.current_session[owner_key]

    async def close_sessions_for_run(self, target_id: str, agent_run_id: str) -> None:
        """Like close_sessions_for_target, but scoped to exactly one owning
        agent run - what a single pentesting/scouting/... sub-run's own
        cleanup must call once more than one agent can be live on the same
        target at once, so ending it never touches a sibling run's
        sessions."""
        async with self.sessions_lock:
            to_close = [
                s
                for s in self.sessions.values()
                if s.target_id == target_id and s.agent_run_id == agent_run_id
            ]
        for session in to_close:
            await self._close_session(session, reason="agent run ended")
        async with self.sessions_lock:
            self.current_session.pop(self._owner_key(target_id, agent_run_id), None)

    async def close_all_sessions(self) -> None:
        async with self.sessions_lock:
            to_close = list(self.sessions.values())
        for session in to_close:
            await self._close_session(session, reason="container stopped")
        async with self.sessions_lock:
            self.current_session.clear()

    async def list_sessions(self, target_id: str, agent_run_id: str) -> List[KaliSession]:
        async with self.sessions_lock:
            return [
                s
                for s in self.sessions.values()
                if s.target_id == target_id and s.agent_run_id == agent_run_id
            ]

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
                        # A session blocked in a single call is never idle,
                        # no matter how long that call has been running - a
                        # run() call can now legitimately block for up to
                        # MAX_READ_WINDOW_SECONDS waiting on a slow command,
                        # which can exceed SESSION_IDLE_TIMEOUT_SECONDS, and
                        # last_activity alone can't tell "no one has touched
                        # this in a while" apart from "someone is actively
                        # waiting on this right now".
                        if not s.io_lock.locked()
                        and now - s.last_activity > SESSION_IDLE_TIMEOUT_SECONDS
                    ]
                for session in idle:
                    logger.info(
                        f"Closing idle kali session '{session.name}' "
                        f"({session.command!r})"
                    )
                    await self._close_session(session, reason="idle timeout")
                    await self._reassign_current_after_close(
                        session.target_id, session.agent_run_id, session.name
                    )
                    # Unlike an explicit close_session call, nothing else
                    # tells a caller this happened - without this, a
                    # console tab for an idle-swept session stayed open
                    # in the UI forever (the backend session was long
                    # gone), only ever surfacing as an error on the next
                    # command sent to it.
                    if self.session_closed_notifier is not None:
                        await self.session_closed_notifier(
                            session.target_id, session.name
                        )
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

        # FTP conntrack helper - see FTP_CONTROL_PORT's own comment. Binding
        # it to the control channel here, before the established/related
        # rule below, means the kernel starts tracking that connection's
        # PORT/PASV replies from its very first packet.
        await self.execute(
            "nft 'add ct helper ip MOMOS_IPv4 ftp-helper { type \"ftp\" protocol tcp; }'",
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
            await self.execute(
                f"nft add rule ip MOMOS_IPv4 OUTPUT meta skuid momos ip daddr {target.ipv4} "
                f"tcp dport {FTP_CONTROL_PORT} ct helper set \"ftp-helper\"",
                user=KALI_USERS.root,
            )

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

        # FTP conntrack helper - same reasoning as the IPv4 table above.
        await self.execute(
            "nft 'add ct helper ip6 MOMOS_IPv6 ftp-helper { type \"ftp\" protocol tcp; }'",
            user=KALI_USERS.root,
        )

        # Allow traffic to comeback
        await self.execute(
            "nft add rule ip6 MOMOS_IPv6 OUTPUT meta skuid momos ct state established,related accept",
            user=KALI_USERS.root,
        )

        if target.ipv6 is not None:
            await self.execute(
                f"nft add rule ip6 MOMOS_IPv6 OUTPUT meta skuid momos ip6 daddr {target.ipv6} "
                f"tcp dport {FTP_CONTROL_PORT} ct helper set \"ftp-helper\"",
                user=KALI_USERS.root,
            )

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
