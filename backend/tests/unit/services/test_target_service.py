import uuid

import pytest

from src.schemas.target_scheme import Target
from src.services.target_service import TargetService


@pytest.fixture
def patched_db(fake_db_manager, monkeypatch):
    monkeypatch.setattr("src.services.target_service.db_manager", fake_db_manager)
    return fake_db_manager


def make_target(**overrides):
    defaults = dict(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        name="target",
        ipv4=None,
        ipv6=None,
        description=None,
        ports=[1, 2],
        task_duration=None,
    )
    defaults.update(overrides)
    return Target(**defaults)


# --- Port range boundaries (0 / 1 / 65535 / 65536) ---------------------


def test_update_target_rejects_port_zero(patched_db):
    target = make_target(ports=[0])

    with pytest.raises(ValueError):
        TargetService.update_target(target)

    patched_db.get_target.assert_not_called()
    patched_db.update_target.assert_not_called()


def test_update_target_accepts_port_one(patched_db):
    target = make_target(ports=[1])
    patched_db.get_target.return_value = target

    TargetService.update_target(target)

    patched_db.update_target.assert_called_once_with(target)


def test_update_target_accepts_port_65535(patched_db):
    target = make_target(ports=[65535])
    patched_db.get_target.return_value = target

    TargetService.update_target(target)

    patched_db.update_target.assert_called_once_with(target)


def test_update_target_rejects_port_65536(patched_db):
    target = make_target(ports=[65536])

    with pytest.raises(ValueError):
        TargetService.update_target(target)

    patched_db.update_target.assert_not_called()


def test_update_target_accepts_empty_ports_list(patched_db):
    target = make_target(ports=[])
    patched_db.get_target.return_value = target

    TargetService.update_target(target)

    patched_db.update_target.assert_called_once_with(target)


def test_update_target_with_ports_none_raises_typeerror_not_valueerror(patched_db):
    """Pins the REAL current behavior, not the intended one. `update_target`
    does `all(1 <= port <= 65535 for port in target.ports)`, which iterates
    `target.ports` directly - with `ports=None` that raises TypeError from
    the generator before the intended ValueError("All ports must be
    between 1 and 65535") path is ever reached.

    docs/testing-crawler-reports/remaining-services.md flags this as
    "likely a real bug": callers (e.g. the router) that catch ValueError to
    return a 4xx will instead hit an uncaught TypeError / 500 for a
    None-ports payload. This test should be updated (not just deleted) if
    that's ever fixed to raise ValueError instead.
    """
    target = make_target(ports=None)

    with pytest.raises(TypeError):
        TargetService.update_target(target)


# --- IPv4 / IPv6 validation ---------------------------------------------


def test_update_target_accepts_valid_ipv4(patched_db):
    target = make_target(ipv4="192.168.1.1")
    patched_db.get_target.return_value = target

    TargetService.update_target(target)

    patched_db.update_target.assert_called_once_with(target)


def test_update_target_rejects_malformed_ipv4(patched_db):
    target = make_target(ipv4="not-an-ip")

    with pytest.raises(ValueError):
        TargetService.update_target(target)

    patched_db.update_target.assert_not_called()


def test_update_target_rejects_ipv6_value_in_ipv4_field(patched_db):
    target = make_target(ipv4="::1")

    with pytest.raises(ValueError):
        TargetService.update_target(target)

    patched_db.update_target.assert_not_called()


def test_update_target_accepts_valid_ipv6(patched_db):
    target = make_target(ipv6="::1")
    patched_db.get_target.return_value = target

    TargetService.update_target(target)

    patched_db.update_target.assert_called_once_with(target)


def test_update_target_rejects_malformed_ipv6(patched_db):
    target = make_target(ipv6="not-an-ip")

    with pytest.raises(ValueError):
        TargetService.update_target(target)

    patched_db.update_target.assert_not_called()


def test_update_target_rejects_ipv4_value_in_ipv6_field(patched_db):
    target = make_target(ipv6="192.168.1.1")

    with pytest.raises(ValueError):
        TargetService.update_target(target)

    patched_db.update_target.assert_not_called()


# --- Validation ordering / existence check ------------------------------


def test_update_target_validates_ports_before_checking_existence(patched_db):
    target = make_target(ports=[99999])

    with pytest.raises(ValueError, match="ports"):
        TargetService.update_target(target)

    patched_db.get_target.assert_not_called()


def test_update_target_raises_when_target_missing(patched_db):
    target = make_target()
    patched_db.get_target.return_value = None

    with pytest.raises(ValueError, match="does not exist"):
        TargetService.update_target(target)

    patched_db.update_target.assert_not_called()
