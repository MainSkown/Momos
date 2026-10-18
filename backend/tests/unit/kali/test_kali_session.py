"""KaliSession dataclass tests (backend/src/core/kali_integration/kali_session.py).
Most of the session lifecycle logic (open/close/idle-sweep/confusion
tracking) actually lives in KaliManger, not here - see test_kali_manager.py
for that. This file only exercises what kali_session.py itself defines:
the dataclass's own defaults/independence and KaliSessionError's identity."""

import socket as socket_module
import time

from src.core.kali_integration.kali_session import KaliSession, KaliSessionError


def _new_session(**overrides):
    defaults = dict(
        name="default",
        command="/bin/bash",
        target_id="target-1",
        agent_run_id="run-1",
        exec_id="exec-1",
        sock=socket_module.socketpair()[0],
        user="momos",
    )
    defaults.update(overrides)
    return KaliSession(**defaults)


def test_each_session_gets_its_own_independent_io_lock():
    a = _new_session()
    b = _new_session()
    assert a.io_lock is not b.io_lock


def test_created_at_and_last_activity_start_equal_and_non_decreasing():
    first = _new_session()
    time.sleep(0.01)
    second = _new_session()

    # created_at/last_activity are two separate time.monotonic() calls in
    # the dataclass's own field defaults, not one shared value - close
    # enough to be indistinguishable from "equal" for anything that cares
    # (the idle-timeout sweep), but not bit-identical.
    assert abs(first.last_activity - first.created_at) < 0.01
    assert second.created_at >= first.created_at


def test_state_defaults_reflect_a_freshly_opened_shell():
    session = _new_session()

    assert session.at_shell_prompt is True
    assert session.confusion_streak == 0
    assert session.active_program is None
    assert session.had_prior_io is False
    assert session.ftp_passive is False
    assert session.closed is False
    assert session.close_reason is None


def test_kali_session_error_is_a_runtime_error():
    assert issubclass(KaliSessionError, RuntimeError)
    err = KaliSessionError("boom")
    assert isinstance(err, RuntimeError)
