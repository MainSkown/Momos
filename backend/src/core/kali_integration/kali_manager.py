import docker
import asyncio
from docker.errors import DockerException
import logging
from typing import Final, Sequence
from src.schemas import Target
from enum import Enum

logger = logging.getLogger("momos.kali")


class KALI_USERS(Enum):
    momos = "momos"
    root = "root"


MOMOS_USER: Final = KALI_USERS.momos


DEFAULT_KALI_PACKAGES: Final[tuple[str, ...]] = (
    "kali-linux-headless",
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
    "dnsutils",
)


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

        try:
            self.client = docker.from_env()
        except DockerException as e:
            logger.error(f"Could not connect to Docker: {e}")
            raise RuntimeError("Docker daemon is not available")

    async def start(self):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._create_container)
        print(f"Successfully created Kali container: {self.container_name}", flush=True)

    def _create_container(self):
        # Check if container with same name exist
        try:
            old_container = self.client.containers.get(self.container_name)
            print(
                f"Container {self.container_name} already exists. Removing.", flush=True
            )
            # Removing because it can have not completed the initializing
            old_container.remove(force=True)
        except docker.errors.NotFound:
            pass

        print("Starting container")
        self.container = self.client.containers.run(
            image="kalilinux/kali-rolling:latest",
            name=self.container_name,
            detach=True,
            tty=True,
            network_mode="host",
            remove=True,
        )

        self._configure_container()

    def _configure_container(self):
        print("Updating and downloading packages")
        self._exec_in_container("apt-get update")
        self._exec_in_container(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "
            + " ".join(self.packages)
        )
        print("Setting up momos user")

        # Create momos user without sudo permissions
        self._exec_in_container(
            f"id -u {MOMOS_USER} >/dev/null 2>&1 || useradd -s /bin/bash {MOMOS_USER}"
        )

        # Make sure the home directory exists and belongs to momos
        self._exec_in_container(
            f"install -d -o {MOMOS_USER} -g {MOMOS_USER} /home/{MOMOS_USER}"
        )

    def _exec_in_container(self, command: str, user: str = "root"):
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

        if exit_code != 0:
            raise RuntimeError(
                f"Command failed with exit code {exit_code}: {shell_cmd}\n{output}"
            )

        return output

    async def prepare_nftables(self, target: Target):
        # Flush ruleset
        await self.execute("nft flush ruleset", user=KALI_USERS.root)

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
            for protocol in ["tcp", "udp"]:
                # No space - if ports are none to not break the command
                await self.execute(
                    f"nft add rule ip MOMOS_IPv4 OUTPUT meta skuid momos ip daddr {target.ipv4} {protocol}{ports_str} accept",
                    user=KALI_USERS.root,
                )

            await self.execute(
                f"nft add rule ip MOMOS_IPv4 OUTPUT meta skuid momos ip daddr {target.ipv4} icmp accept",
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
            for protocol in ["tcp", "udp"]:
                # No space - if ports are none to not break the command
                await self.execute(
                    f"nft add rule ip6 MOMOS_IPv6 OUTPUT meta skuid momos ip6 daddr {target.ipv6} {protocol}{ports_str} accept",
                    user=KALI_USERS.root,
                )

            # Allow icmpv6
            await self.execute(
                f"nft add rule ip6 MOMOS_IPv6 OUTPUT meta skuid momos ip6 daddr {target.ipv6} icmpv6 accept",
                user=KALI_USERS.root,
            )

        # Drop all traffic that's not going to target
        await self.execute(
            "nft add rule ip6 MOMOS_IPv6 OUTPUT meta skuid momos drop",
            user=KALI_USERS.root,
        )

    async def execute(self, command: str, user: KALI_USERS = KALI_USERS.momos) -> str:
        loop = asyncio.get_running_loop()

        return await loop.run_in_executor(None, self._exec_in_container, command, user)

    async def stop(self):
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
