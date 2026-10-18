"""§1.4a tier 2 fixtures (docs/testing-plan.md) - the real pentest-tools
image, a dedicated Docker network, the four seeded target containers, and
a real KaliManger pointed at the pentest-tools image instead of
production's kalilinux/kali-rolling. Building these out is this stage's
whole job; the actual per-tool tests (test_nmap.py, test_hydra.py, ...)
are a LATER stage's job and deliberately don't exist yet - see this
backend's testing-plan task notes.

Every fixture here is session-scoped and marked implicitly `live_tools` by
virtue of only ever being requested by `live_tools`-marked tests - pytest
never instantiates a fixture a deselected test doesn't request, so the
fast default suite (`-m 'not live_tools'`, the addopts default) never
touches Docker because of anything in this file."""

import uuid
from dataclasses import dataclass
from pathlib import Path

import docker
import docker.errors
import pytest

from src.core.kali_integration.kali_manager import KaliManger

DOCKER_DIR = Path(__file__).resolve().parents[2] / "docker"


def _remove_image(client, tag: str) -> None:
    try:
        client.images.remove(tag, force=True)
    except docker.errors.ImageNotFound:
        pass


def _stop_and_remove_container(container) -> None:
    try:
        container.stop(timeout=5)
    except docker.errors.NotFound:
        pass
    try:
        container.remove(force=True)
    except docker.errors.NotFound:
        pass


@pytest.fixture(scope="session")
def _docker_client():
    return docker.from_env()


@pytest.fixture(scope="session")
def docker_network(_docker_client):
    """A dedicated bridge network for this test session only, so the
    pentest-tools container and each target container resolve each other
    by plain container name - unique per session (a uuid suffix) so two
    concurrent test runs, or a run right after a previous one that didn't
    clean up, never collide on network name."""
    name = f"momos-test-tools-{uuid.uuid4().hex[:8]}"
    network = _docker_client.networks.create(name, driver="bridge")
    yield network
    try:
        network.remove()
    except docker.errors.NotFound:
        pass


@pytest.fixture(scope="session")
def pentest_tools_image(_docker_client):
    """Builds backend/tests/docker/pentest-tools.Dockerfile once per
    session - the "attacker" image every tier-2 test (and live_kali_session
    below) runs against. See that Dockerfile's own comments for what's in
    it and why; see docs/testing-plan.md §1.4a for the full tool list this
    was verified against."""
    tag = f"momos-test-pentest-tools:{uuid.uuid4().hex[:8]}"
    image, _logs = _docker_client.images.build(
        path=str(DOCKER_DIR),
        dockerfile="pentest-tools.Dockerfile",
        tag=tag,
        rm=True,
    )
    yield tag
    _remove_image(_docker_client, tag)


def _build_and_run_target(
    docker_client,
    docker_network,
    *,
    dockerfile_path: str,
    build_context: str,
    container_name: str,
):
    """Shared build+run for the four target fixtures below - each target
    Dockerfile is built once per session and run as a container with a
    FIXED name on `docker_network` (so e.g. `ssh-target` is addressable by
    that literal hostname from the pentest-tools container), with NO ports
    published to the host - target containers only ever talk to the
    pentest-tools container over the dedicated docker_network, never
    reachable from outside Docker at all. This is a safety requirement
    (docs/testing-plan.md §1.4a), not an oversight."""
    tag = f"momos-test-{container_name}:{uuid.uuid4().hex[:8]}"
    docker_client.images.build(
        path=build_context,
        dockerfile=dockerfile_path,
        tag=tag,
        rm=True,
    )
    container = docker_client.containers.run(
        tag,
        name=container_name,
        detach=True,
        network=docker_network.name,
        ports={},
    )
    return tag, container


@pytest.fixture(scope="session")
def http_target(_docker_client, docker_network):
    """nginx:alpine seeded with a small, fixed set of paths (and at least
    one deliberately-absent path) - see backend/tests/docker/http-target/
    for the exact seeded tree. Addressable as `http-target` on
    docker_network."""
    tag, container = _build_and_run_target(
        _docker_client,
        docker_network,
        dockerfile_path="Dockerfile",
        build_context=str(DOCKER_DIR / "http-target"),
        container_name="http-target",
    )
    yield container
    _stop_and_remove_container(container)
    _remove_image(_docker_client, tag)


@pytest.fixture(scope="session")
def ssh_target(_docker_client, docker_network):
    """Minimal sshd with one seeded weak test account - see
    backend/tests/docker/ssh-target.Dockerfile. Addressable as
    `ssh-target` on docker_network."""
    tag, container = _build_and_run_target(
        _docker_client,
        docker_network,
        dockerfile_path="ssh-target.Dockerfile",
        build_context=str(DOCKER_DIR),
        container_name="ssh-target",
    )
    yield container
    _stop_and_remove_container(container)
    _remove_image(_docker_client, tag)


@pytest.fixture(scope="session")
def ftp_target(_docker_client, docker_network):
    """Minimal vsftpd with one seeded weak test account and a small fixed
    file tree - see backend/tests/docker/ftp-target.Dockerfile.
    Addressable as `ftp-target` on docker_network."""
    tag, container = _build_and_run_target(
        _docker_client,
        docker_network,
        dockerfile_path="ftp-target.Dockerfile",
        build_context=str(DOCKER_DIR),
        container_name="ftp-target",
    )
    yield container
    _stop_and_remove_container(container)
    _remove_image(_docker_client, tag)


@pytest.fixture(scope="session")
def telnet_target(_docker_client, docker_network):
    """Minimal busybox telnetd with the same seeded weak test account - see
    backend/tests/docker/telnet-target.Dockerfile. Addressable as
    `telnet-target` on docker_network."""
    tag, container = _build_and_run_target(
        _docker_client,
        docker_network,
        dockerfile_path="telnet-target.Dockerfile",
        build_context=str(DOCKER_DIR),
        container_name="telnet-target",
    )
    yield container
    _stop_and_remove_container(container)
    _remove_image(_docker_client, tag)


@dataclass
class LiveKaliSession:
    """What a tier-2 test actually needs to call the real
    create_pentest_tools/create_guided_session_tools/create_terminal_tools
    factories unmodified against live_kali_session's container - see that
    fixture's own docstring for why this is a small data holder rather
    than, say, an already-opened KaliSession: Tier-1/2 pentest tools
    (nmap_scan, hydra_bruteforce, ...) run through KaliManger.execute's
    one-shot exec, not a session at all, so pre-opening one here would be
    presuming a need only some tier-2 tests (the guided-session/terminal
    ones) actually have."""

    manager: KaliManger
    project_id: str
    target_id: str
    agent_run_id: str


@pytest.fixture(scope="session")
def live_kali_session(_docker_client, docker_network, pentest_tools_image):
    """A real KaliManger pointed at pentest_tools_image on docker_network,
    so create_pentest_tools/create_guided_session_tools/create_terminal_
    tools (backend/src/core/agent/agent_tools.py) run completely
    unmodified end-to-end against it.

    Deliberately does NOT call KaliManger.start()/_create_container -
    _configure_container unconditionally runs apt-get/dpkg-based setup
    (DEFAULT_KALI_PACKAGES, useradd, setcap, ...) that assumes a Debian
    image; pentest_tools_image is Alpine-based (see pentest-tools.
    Dockerfile) and already has every tool this tier needs pre-baked in,
    so that setup would both fail (no apt-get on Alpine) and be pointless
    (nothing left to configure). Instead, the container is created
    directly via the docker SDK here (mirroring what _create_container
    itself does: detach=True, tty=True, the same cap_add) and wired onto
    `manager.container` by hand - the exact same pattern
    generic_container/test_kali_session.py's `manager` fixture already
    uses for tier 1, for the same underlying reason.

    Network attachment: `network=docker_network.name` is passed directly
    on this fixture's own `containers.run()` call, rather than extending
    KaliManger._create_container with a new network parameter (mirroring
    the existing `image` seam) or calling `docker_network.connect()`
    after the fact. This is the least invasive of the three options -
    since container creation already happens here, not inside
    KaliManger, attaching the network at creation time needs no change to
    kali_manager.py at all, unlike a new constructor parameter, and no
    extra post-creation API call, unlike connect()."""
    container_name = f"momos-test-kali-{uuid.uuid4().hex[:8]}"
    container = _docker_client.containers.run(
        pentest_tools_image,
        name=container_name,
        detach=True,
        tty=True,
        network=docker_network.name,
        cap_add=["NET_ADMIN", "NET_RAW"],
    )

    manager = KaliManger(container_name=container_name, image=pentest_tools_image, packages=())
    manager.container = container

    yield LiveKaliSession(
        manager=manager,
        project_id="test-project-tools-tier",
        target_id="test-target-tools-tier",
        agent_run_id="test-run-tools-tier",
    )

    import asyncio

    asyncio.run(manager.close_all_sessions())
    if manager._session_sweep_task is not None:
        manager._session_sweep_task.cancel()
    manager.container = None  # avoid KaliManger.__del__ stopping it twice
    _stop_and_remove_container(container)
