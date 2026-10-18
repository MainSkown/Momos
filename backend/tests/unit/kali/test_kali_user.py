"""KaliUser/KaliUserRegistry tests (backend/src/core/kali_integration/kali_user.py).
kali_user.py binds `ws_registry` and `kali_registry` by name at import time
(`from src.websocket import ws_registry` / `from .kali_registry import
kali_registry`), so every patch below targets THIS module's own reference
to them, not the source modules (see docs/testing-plan.md §1.3's
project-wide note on this)."""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.kali_integration import kali_user as kali_user_module
from src.core.kali_integration.kali_user import (
    KaliUser,
    KaliUserRegistry,
    _strip_echoed_command,
    _strip_terminal_control_sequences,
)
from src.websocket.websocket_registry import WebSocketRegistry


@pytest.fixture
def fresh_ws_registry(monkeypatch):
    registry = WebSocketRegistry()
    monkeypatch.setattr(kali_user_module, "ws_registry", registry)
    return registry


@pytest.fixture
def fake_manager():
    manager = MagicMock()
    manager.session_closed_notifier = None
    return manager


@pytest.fixture
def fake_kali_registry(monkeypatch, fake_manager):
    fake = MagicMock()
    fake.get_manager = AsyncMock(return_value=fake_manager)
    fake.clear_build_status = MagicMock()
    fake.set_build_stage = MagicMock()
    monkeypatch.setattr(kali_user_module, "kali_registry", fake)
    return fake


# --- Bug 4: create_user has no dedupe, every hook gets registered twice ----


async def test_create_user_called_twice_registers_every_websocket_hook_once(
    fresh_ws_registry, fake_kali_registry
):
    """_create_user must check for an existing active/pending user for the
    same project and skip creating a second one - otherwise two calls would
    each run KaliUser.create, and EACH call does three ws_registry.add_hook
    calls on a brand-new KaliUser instance (add_hook's own de-dupe check
    compares bound methods, and two different instances' bound methods
    never compare equal, so nothing would collapse the duplicates). A
    double-created user means every console command could execute twice."""
    registry = KaliUserRegistry()

    await registry._create_user("project-a", uuid.uuid4())
    await registry._create_user("project-a", uuid.uuid4())

    assert len(registry.active_users) == 1
    from src.websocket import WsTypes

    assert len(fresh_ws_registry.hooks[WsTypes.SendCommandMessage]) == 1
    assert len(fresh_ws_registry.hooks[WsTypes.CreateConsoleSessionMessage]) == 1
    assert len(fresh_ws_registry.hooks[WsTypes.CloseConsoleSessionMessage]) == 1


async def test_create_user_failure_leaves_no_pending_residue(
    fresh_ws_registry, fake_kali_registry
):
    fake_kali_registry.get_manager.side_effect = RuntimeError("docker build failed")
    registry = KaliUserRegistry()
    client_id = uuid.uuid4()
    # Must actually be pending before the call, same as the success-path
    # sibling test - otherwise "not in pending_users" afterward is true
    # regardless of whether the failure path's own pop() ever runs.
    registry.pending_users[client_id] = "project-a"

    await registry._create_user("project-a", client_id)

    assert client_id not in registry.pending_users
    assert registry.active_users == []
    fake_kali_registry.clear_build_status.assert_called_once_with("project-a")


async def test_create_user_success_appends_active_and_clears_pending(
    fresh_ws_registry, fake_kali_registry
):
    registry = KaliUserRegistry()
    client_id = uuid.uuid4()
    registry.pending_users[client_id] = "project-a"

    await registry._create_user("project-a", client_id)

    assert client_id not in registry.pending_users
    assert len(registry.active_users) == 1
    assert registry.active_users[0].project_id == "project-a"


# --- get_client_for_project / get_active_user_for_project -------------------


def test_active_user_takes_precedence_over_pending_for_the_same_project():
    registry = KaliUserRegistry()
    active_client_id = uuid.uuid4()
    registry.active_users.append(KaliUser("project-a", active_client_id))
    registry.pending_users[uuid.uuid4()] = "project-a"

    client_id, pending = registry.get_client_for_project("project-a")

    assert client_id == active_client_id
    assert pending is False


def test_unknown_project_returns_none():
    registry = KaliUserRegistry()
    assert registry.get_client_for_project("unknown") is None


def test_pending_only_project_reports_pending_true():
    registry = KaliUserRegistry()
    pending_client_id = uuid.uuid4()
    registry.pending_users[pending_client_id] = "project-a"

    client_id, pending = registry.get_client_for_project("project-a")

    assert client_id == pending_client_id
    assert pending is True


# --- KaliUser._check_project --------------------------------------------


def test_check_project_raises_on_mismatched_project_id():
    user = KaliUser("project-a", uuid.uuid4())
    with pytest.raises(RuntimeError, match="different project"):
        user._check_project("project-b")


def test_check_project_accepts_matching_project_id():
    user = KaliUser("project-a", uuid.uuid4())
    user._check_project("project-a")  # must not raise


# --- KaliUser._notify_session_closed ----------------------------------------


async def test_notify_session_closed_ignores_non_console_targets(fresh_ws_registry):
    user = KaliUser("project-a", uuid.uuid4())
    sent = []
    fresh_ws_registry.send_message = AsyncMock(side_effect=lambda m: sent.append(m))

    await user._notify_session_closed("some-real-target-uuid", "default")

    assert sent == []


async def test_notify_session_closed_sends_for_console_target(fresh_ws_registry):
    from src.core.kali_integration.kali_user import CONSOLE_TARGET_ID

    user = KaliUser("project-a", uuid.uuid4())
    sent = []
    fresh_ws_registry.send_message = AsyncMock(side_effect=lambda m: sent.append(m))

    await user._notify_session_closed(CONSOLE_TARGET_ID, "root-1")

    assert len(sent) == 1
    assert sent[0].session == "root-1"


# --- _strip_echoed_command (pure) -------------------------------------------


@pytest.mark.parametrize(
    "text, sent, expected",
    [
        ("ls\n", "ls", ""),
        ("ls\nfile1\nfile2\n", "ls", "file1\nfile2\n"),
        ("ls -la\n", "ls", "ls -la\n"),  # only CONTAINS the command - must not strip
        ("  ls  \nfile\n", "  ls  ", "file\n"),
        ("some output\n", "", "some output\n"),
    ],
)
def test_strip_echoed_command(text, sent, expected):
    assert _strip_echoed_command(text, sent) == expected


# --- _strip_terminal_control_sequences (pure) -------------------------------


def test_strip_terminal_control_sequences_normalizes_crlf():
    assert _strip_terminal_control_sequences("a\r\nb\r\n") == "a\nb"


def test_strip_terminal_control_sequences_strips_osc_sequence():
    text = "before\x1b]0;window title\x07after"
    assert _strip_terminal_control_sequences(text) == "beforeafter"


def test_strip_terminal_control_sequences_removes_prompt_lines():
    text = "root@host:~# ls\nfile.txt\nroot@host:~# "
    result = _strip_terminal_control_sequences(text, sent_command="ls")
    assert result == "file.txt"


def test_strip_terminal_control_sequences_keeps_non_prompt_root_at_lines():
    text = "root@host is alive\n"
    result = _strip_terminal_control_sequences(text)
    assert "root@host is alive" in result


def test_strip_terminal_control_sequences_is_idempotent():
    text = "root@host:~# ls\nfile.txt\nroot@host:~# "
    once = _strip_terminal_control_sequences(text, sent_command="ls")
    twice = _strip_terminal_control_sequences(once)
    assert once == twice
