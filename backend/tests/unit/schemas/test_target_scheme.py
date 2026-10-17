import uuid

import pytest
from pydantic import ValidationError

from src.schemas.target_scheme import ResponseTarget


def _target(ports):
    return ResponseTarget(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        name="box",
        ipv4="10.0.0.5",
        ipv6=None,
        description=None,
        ports=ports,
        task_duration=60,
    )


@pytest.mark.parametrize("port", [1, 65535])
def test_port_at_valid_boundary_is_accepted(port):
    assert _target([port]).ports == [port]


@pytest.mark.parametrize("port", [0, 65536])
def test_port_outside_valid_range_is_rejected(port):
    with pytest.raises(ValidationError):
        _target([port])


def test_none_ports_stay_none_and_are_not_coerced_to_empty_list():
    assert _target(None).ports is None
