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


def test_update_target_with_ports_none_raises_valueerror(patched_db):
    """`update_target` used to do `all(1 <= port <= 65535 for port in
    target.ports)`, which iterated `target.ports` directly - with
    `ports=None` that raised a TypeError from the generator before the
    intended ValueError("All ports must be between 1 and 65535") path was
    ever reached, so callers that catch ValueError to return a 4xx hit an
    uncaught TypeError / 500 instead. Fixed: `None` ports now takes the
    same ValueError path as an out-of-range port, consistently.
    """
    target = make_target(ports=None)

    with pytest.raises(ValueError, match="ports"):
        TargetService.update_target(target)

    patched_db.get_target.assert_not_called()
    patched_db.update_target.assert_not_called()


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


# --- add_target: field forwarding --------------------------------------


def test_add_target_forwards_ports_ipv4_ipv6_and_description(patched_db):
    """add_target used to only ever forward `name` - every other POST
    field (ports/ipv4/ipv6/description/task_duration) was silently
    dropped, so the created row never reflected what the client sent.
    Fixed: all of them are now forwarded onto the created Target."""
    patched_db.add_target.side_effect = lambda target: target

    result = TargetService.add_target(
        "target",
        str(uuid.uuid4()),
        ipv4="192.168.1.1",
        ipv6="::1",
        description="a description",
        ports=[80, 443],
        task_duration=120,
    )

    assert result.ipv4 == "192.168.1.1"
    assert result.ipv6 == "::1"
    assert result.description == "a description"
    assert result.ports == [80, 443]
    assert result.task_duration == 120


def test_add_target_defaults_ports_to_empty_list_when_not_given(patched_db):
    patched_db.add_target.side_effect = lambda target: target

    result = TargetService.add_target("target", str(uuid.uuid4()))

    assert result.ports == []


def test_add_target_rejects_malformed_ipv4_like_update_target(patched_db):
    with pytest.raises(ValueError):
        TargetService.add_target("target", str(uuid.uuid4()), ipv4="not-an-ip")

    patched_db.add_target.assert_not_called()


def test_add_target_rejects_out_of_range_port_like_update_target(patched_db):
    with pytest.raises(ValueError, match="ports"):
        TargetService.add_target("target", str(uuid.uuid4()), ports=[65536])

    patched_db.add_target.assert_not_called()


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
