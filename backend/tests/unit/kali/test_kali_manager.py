"""Lifecycle/registry-logic tests for KaliManger (backend/src/core/kali_integration/
kali_manager.py) - the constructor-level `image` seam is already covered by
test_kali_manager_image_seam.py. Everything here scripts fake_docker_client's
returned MagicMock per-test and asserts against its RECORDED CALLS and
against real state transitions on the manager, never a mock's own scripted
return value alone (CLAUDE.md §2.1). See docs/testing-plan.md §1.4 and the
two kali crawler reports for the bug-hunting targets this pins down."""

import socket as socket_module
import threading
from unittest.mock import MagicMock

import docker.errors
import pytest

from src.core.kali_integration.kali_manager import KaliManger
from src.core.kali_integration.kali_session import KaliSessionError, MAX_SESSIONS_PER_TARGET
from src.schemas import Target


@pytest.fixture
async def manager(fake_docker_client):
    instance = KaliManger()
    yield instance
    if instance._session_sweep_task is not None:
        instance._session_sweep_task.cancel()


def _ok_exec_run(*_args, **_kwargs):
    return MagicMock(exit_code=0, output=b"")


# --- Bug 1: failed start() on an exited/stopped existing container ---------


def test_failed_restart_of_existing_container_crashes_instead_of_rebuilding(
    manager, fake_docker_client
):
    """docs/testing-plan.md's crawler report suspects _create_container falls
    through to `existing_container.remove(force=True)` on a None reference
    when the restart attempt fails. Confirmed by reading the source: the
    except block sets `existing_container = None`, and the `if existing_container
    is not None and existing_container.status == "running"` guard correctly
    short-circuits (no AttributeError there), but the code unconditionally
    falls through afterwards to `existing_container.remove(force=True)` with
    no further None-check - that line is where the AttributeError actually
    fires, not a clean rebuild."""
    existing = fake_docker_client.containers.get.return_value
    existing.status = "exited"
    existing.start.side_effect = docker.errors.APIError("container could not restart")

    with pytest.raises(AttributeError):
        manager._create_container(on_stage=None)

    existing.start.assert_called_once()
    fake_docker_client.containers.run.assert_not_called()


# --- Reuse / rebuild fast paths ---------------------------------------------


def test_running_and_configured_container_is_reused_without_rebuilding(
    manager, fake_docker_client
):
    existing = fake_docker_client.containers.get.return_value
    existing.status = "running"
    existing.exec_run.side_effect = _ok_exec_run

    manager._create_container(on_stage=None)

    assert manager.container is existing
    fake_docker_client.containers.run.assert_not_called()
    existing.remove.assert_not_called()


def test_running_but_misconfigured_container_is_removed_then_rebuilt(
    manager, fake_docker_client
):
    existing = fake_docker_client.containers.get.return_value
    existing.status = "running"
    # Every _is_configured_correctly check fails -> container is rebuilt.
    existing.exec_run.return_value = MagicMock(exit_code=1, output=b"not configured")

    new_container = fake_docker_client.containers.run.return_value
    new_container.exec_run.side_effect = _ok_exec_run

    manager._create_container(on_stage=None)

    existing.remove.assert_called_once_with(force=True)
    fake_docker_client.containers.run.assert_called_once()
    _, kwargs = fake_docker_client.containers.run.call_args
    assert kwargs["name"] == manager.container_name
    assert manager.container is new_container


def test_fresh_build_configure_failure_leaves_container_set_and_stops_at_first_failure(
    manager, fake_docker_client
):
    """Bug-hunting target: _configure_container must stop at the first
    failing step, and the half-configured container must NOT be cleaned up
    - the next start() detects it via _is_configured_correctly instead."""
    fake_docker_client.containers.get.side_effect = docker.errors.NotFound("none yet")
    new_container = fake_docker_client.containers.run.return_value
    ok = MagicMock(exit_code=0, output=b"")
    failing = MagicMock(
        exit_code=100, output=b"could not install package"
    )
    # apt-get update succeeds, apt-get install fails.
    new_container.exec_run.side_effect = [ok, failing]

    with pytest.raises(RuntimeError, match="exit code 100"):
        manager._create_container(on_stage=None)

    assert manager.container is new_container
    new_container.remove.assert_not_called()
    assert new_container.exec_run.call_count == 2


def test_post_setup_verification_failure_raises(manager, fake_docker_client):
    fake_docker_client.containers.get.side_effect = docker.errors.NotFound("none yet")
    new_container = fake_docker_client.containers.run.return_value
    ok = MagicMock(exit_code=0, output=b"")
    # Every _configure_container exec succeeds, but every _is_configured_correctly
    # check (run right after) fails.
    check_fail = MagicMock(exit_code=1, output=b"missing")
    configure_substrings = (
        "apt-get update", "apt-get install", "gunzip", "useradd",
        "install -d", "setcap", "base64 -d",
    )

    def exec_run(cmd, **kwargs):
        joined = " ".join(cmd) if isinstance(cmd, list) else cmd
        if any(s in joined for s in configure_substrings):
            return ok
        return check_fail

    new_container.exec_run.side_effect = exec_run

    with pytest.raises(RuntimeError, match="failed post-setup verification"):
        manager._create_container(on_stage=None)


# --- Bug 2: prepare_nftables fails open, not closed -------------------------


async def test_prepare_nftables_fails_open_when_a_rule_after_the_output_chain_fails(
    manager, monkeypatch
):
    """The OUTPUT chain is created with `policy accept`, and the final
    per-family `drop` rule is what actually locks egress down - everything
    in between is a separate, un-transacted execute() call. Confirmed via
    the real command sequence: if ANY call after the chain is created (here,
    the ftp-helper ct object, which is call #3 of the ipv4 sequence) raises,
    prepare_nftables aborts and propagates the exception - the drop rule
    for ipv4 (and the entire ipv6 table) never gets added, while the accept
    policy from the already-created chain stays in effect. That's fail-open,
    not fail-closed."""
    recorded_commands = []

    async def fake_execute(command, user=None, timeout_seconds=120):
        recorded_commands.append(command)
        if "ct helper" in command and "ip MOMOS_IPv4" in command:
            raise RuntimeError("nft: Operation not supported")
        return ""

    monkeypatch.setattr(manager, "execute", fake_execute)
    target = Target(
        name="t", ipv4="10.0.0.5", ipv6=None, description=None, ports=[80], task_duration=None
    )

    with pytest.raises(RuntimeError, match="Operation not supported"):
        await manager.prepare_nftables(target)

    assert any("add chain ip MOMOS_IPv4 OUTPUT" in c and "policy accept" in c for c in recorded_commands)
    assert not any("OUTPUT meta skuid momos drop" in c for c in recorded_commands)


async def test_prepare_nftables_happy_path_installs_the_drop_rule_last_per_family(manager, monkeypatch):
    recorded_commands = []

    async def fake_execute(command, user=None, timeout_seconds=120):
        recorded_commands.append(command)
        return ""

    monkeypatch.setattr(manager, "execute", fake_execute)
    target = Target(
        name="t", ipv4="10.0.0.5", ipv6="fe80::1", description=None, ports=[80, 443],
        task_duration=None,
    )

    await manager.prepare_nftables(target)

    ipv4_commands = [c for c in recorded_commands if "MOMOS_IPv4" in c]
    ipv6_commands = [c for c in recorded_commands if "MOMOS_IPv6" in c]
    assert ipv4_commands[-1].endswith("OUTPUT meta skuid momos drop")
    assert ipv6_commands[-1].endswith("OUTPUT meta skuid momos drop")


# --- Bug 3: _remove_from_registry pops by key, no identity check -----------


async def test_remove_from_registry_pops_by_key_with_no_identity_check(manager):
    """Confirmed real race: a slow cleanup for session A (e.g. its
    _session_io's EOFError/OSError handler calling _remove_from_registry
    after a long-blocked read finally returns) can delete a DIFFERENT,
    newly-opened session B that reused the same (target_id, agent_run_id,
    name) key in the meantime. _remove_from_registry only pops by key, with
    no check that the entry it's removing is still the same object it was
    asked to remove."""
    key = manager._session_key("target-1", "run-1", "default")

    session_a = _make_session(name="default", target_id="target-1", agent_run_id="run-1")
    manager.sessions[key] = session_a

    # Session A is replaced in the registry by a brand-new session B that
    # reused the exact same key - exactly what open_session's own reservation
    # mechanism is meant to prevent for a concurrent *open*, but says nothing
    # about a *stale cleanup* racing a session that already closed and reopened.
    session_b = _make_session(name="default", target_id="target-1", agent_run_id="run-1")
    manager.sessions[key] = session_b

    # A's own (now-stale) cleanup finally runs.
    await manager._remove_from_registry(session_a)

    assert key not in manager.sessions, (
        "confirmed bug: A's stale cleanup deleted B's live registry entry "
        "instead of leaving it alone"
    )


def _make_session(name, target_id, agent_run_id):
    from src.core.kali_integration.kali_session import KaliSession

    return KaliSession(
        name=name,
        command="/bin/bash",
        target_id=target_id,
        agent_run_id=agent_run_id,
        exec_id="exec-x",
        sock=socket_module.socketpair()[0],
        user="momos",
    )


# --- Standard lifecycle: open / run / switch / close ------------------------


async def test_open_switch_close_lifecycle_and_current_pointer_reassignment(manager, monkeypatch):
    pairs = [socket_module.socketpair() for _ in range(2)]
    client_socks = iter(sock for _, sock in pairs)

    def fake_open_sync(command, user):
        return (f"exec-{id(command)}", next(client_socks))

    monkeypatch.setattr(manager, "_open_session_sync", fake_open_sync)

    await manager.open_session("target-1", "run-1", "default", "/bin/bash")
    assert manager.get_current_session_name("target-1", "run-1") == "default"

    await manager.open_session("target-1", "run-1", "second", "/bin/bash")
    assert manager.get_current_session_name("target-1", "run-1") == "second"

    await manager.switch_session("target-1", "run-1", "default")
    assert manager.get_current_session_name("target-1", "run-1") == "default"

    closed = await manager.close_session("target-1", "run-1", "default")
    assert closed is True
    # Removed from the registry exactly once - gone, not resurrected.
    assert manager._session_key("target-1", "run-1", "default") not in manager.sessions
    # Fallback picks the only other still-open session for this owner.
    assert manager.get_current_session_name("target-1", "run-1") == "second"

    closed_again = await manager.close_session("target-1", "run-1", "default")
    assert closed_again is False

    for _, sock in pairs:
        sock.close()


async def test_open_session_rejects_duplicate_name_for_the_same_owner(manager, monkeypatch):
    server, client = socket_module.socketpair()
    monkeypatch.setattr(manager, "_open_session_sync", lambda command, user: ("exec-1", client))

    await manager.open_session("target-1", "run-1", "default", "/bin/bash")

    with pytest.raises(KaliSessionError, match="already open"):
        await manager.open_session("target-1", "run-1", "default", "/bin/bash")

    server.close()


async def test_open_session_enforces_per_target_cap_across_owners(manager, monkeypatch):
    pairs = [socket_module.socketpair() for _ in range(MAX_SESSIONS_PER_TARGET + 1)]
    client_socks = iter(sock for _, sock in pairs)
    monkeypatch.setattr(
        manager, "_open_session_sync", lambda command, user: (f"exec-{id(command)}", next(client_socks))
    )

    for i in range(MAX_SESSIONS_PER_TARGET):
        await manager.open_session("target-1", f"run-{i}", f"session-{i}", "/bin/bash")

    with pytest.raises(KaliSessionError, match="Too many open sessions"):
        await manager.open_session(
            "target-1", "run-overflow", "overflow", "/bin/bash"
        )

    for _, sock in pairs:
        sock.close()


async def test_run_in_current_session_real_socket_roundtrip_with_idle_window(manager, monkeypatch):
    """LS tier (no Docker): a real socket pair stands in for the exec socket,
    proving the actual read-window/send logic, not just a scripted return
    value."""
    server, client = socket_module.socketpair()
    monkeypatch.setattr(manager, "_open_session_sync", lambda command, user: ("exec-1", client))
    await manager.open_session("target-1", "run-1", "default", "/bin/bash")

    def peer():
        sent = server.recv(4096)
        assert sent == b"echo hi\n"
        server.sendall(b"hi\n")

    t = threading.Thread(target=peer)
    t.start()
    output = await manager.run_in_current_session(
        "target-1", "run-1", "echo hi", wait_seconds=0.3
    )
    t.join(timeout=2)

    assert "hi" in output
    server.close()


async def test_interrupt_session_while_io_lock_held_writes_directly_without_waiting(
    manager, monkeypatch
):
    server, client = socket_module.socketpair()
    monkeypatch.setattr(manager, "_open_session_sync", lambda command, user: ("exec-1", client))
    session = await manager.open_session("target-1", "run-1", "default", "/bin/bash")

    async with session.io_lock:
        result = await manager.interrupt_session("target-1", "run-1")

    assert "previous read on this session was still" in result
    assert server.recv(4096) == b"\x03"
    server.close()


async def test_exec_in_container_timeout_raises_timed_out_error(manager, fake_docker_client):
    manager.container = fake_docker_client.containers.run.return_value
    manager.container.exec_run.return_value = MagicMock(exit_code=124, output=b"")

    with pytest.raises(RuntimeError, match="timed out"):
        manager._exec_in_container("sleep 999", timeout_seconds=5)

    _, kwargs = manager.container.exec_run.call_args
    assert kwargs["cmd"][:2] == ["/bin/bash", "-c"]
    assert kwargs["cmd"][2].startswith("timeout --kill-after=5 5 ")
