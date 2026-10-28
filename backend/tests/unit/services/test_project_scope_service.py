import uuid

import pytest

from src.schemas.project_scheme import AuthorizationAcknowledgment, ProjectScope
from src.services.project_scope_service import ProjectScopeService


@pytest.fixture
def service_db(monkeypatch, fake_db_manager):
    monkeypatch.setattr("src.services.project_scope_service.db_manager", fake_db_manager)
    return fake_db_manager


def make_scope(**overrides):
    defaults = dict(
        project_id=uuid.uuid4(),
        host_range="10.0.0.1",
        port_range_start=1,
        port_range_end=1024,
    )
    defaults.update(overrides)
    return ProjectScope(**defaults)


def make_acknowledgment(**overrides):
    defaults = dict(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        acknowledged_by="alice",
        description="pentest engagement",
        acknowledged_host_range="10.0.0.1",
        acknowledged_port_range_start=1,
        acknowledged_port_range_end=1024,
    )
    defaults.update(overrides)
    return AuthorizationAcknowledgment(**defaults)


# --- is_acknowledged: the security-critical containment check ----------


@pytest.mark.parametrize(
    "scope_kwargs, ack_kwargs, expected",
    [
        # Exact match on both dimensions.
        pytest.param(
            dict(host_range="10.0.0.1", port_range_start=1, port_range_end=1024),
            dict(
                acknowledged_host_range="10.0.0.1",
                acknowledged_port_range_start=1,
                acknowledged_port_range_end=1024,
            ),
            True,
            id="exact-match",
        ),
        # Host narrower than the ack (single host inside an acked /24).
        pytest.param(
            dict(host_range="10.0.0.5", port_range_start=1, port_range_end=1024),
            dict(
                acknowledged_host_range="10.0.0.0/24",
                acknowledged_port_range_start=1,
                acknowledged_port_range_end=1024,
            ),
            True,
            id="host-narrower",
        ),
        # Host wider than the ack (acked a single host, scope widened to a /24).
        pytest.param(
            dict(host_range="10.0.0.0/24", port_range_start=1, port_range_end=1024),
            dict(
                acknowledged_host_range="10.0.0.5",
                acknowledged_port_range_start=1,
                acknowledged_port_range_end=1024,
            ),
            False,
            id="host-wider",
        ),
        # Port narrower than the ack.
        pytest.param(
            dict(host_range="10.0.0.1", port_range_start=100, port_range_end=200),
            dict(
                acknowledged_host_range="10.0.0.1",
                acknowledged_port_range_start=1,
                acknowledged_port_range_end=1024,
            ),
            True,
            id="port-narrower",
        ),
        # Port wider than the ack.
        pytest.param(
            dict(host_range="10.0.0.1", port_range_start=1, port_range_end=2048),
            dict(
                acknowledged_host_range="10.0.0.1",
                acknowledged_port_range_start=1,
                acknowledged_port_range_end=1024,
            ),
            False,
            id="port-wider",
        ),
        # Mixed: host narrower, port wider -> must still fail (either
        # dimension widening fails the whole check, not an average).
        pytest.param(
            dict(host_range="10.0.0.5", port_range_start=1, port_range_end=2048),
            dict(
                acknowledged_host_range="10.0.0.0/24",
                acknowledged_port_range_start=1,
                acknowledged_port_range_end=1024,
            ),
            False,
            id="mixed-host-narrower-port-wider",
        ),
        # Mixed: host wider, port narrower -> must still fail.
        pytest.param(
            dict(host_range="10.0.0.0/24", port_range_start=100, port_range_end=200),
            dict(
                acknowledged_host_range="10.0.0.5",
                acknowledged_port_range_start=1,
                acknowledged_port_range_end=1024,
            ),
            False,
            id="mixed-host-wider-port-narrower",
        ),
        # Multi-entry host list where EVERY entry falls inside the acked
        # CIDR - the case that breaks a naive "check only the first entry"
        # implementation.
        pytest.param(
            dict(
                host_range="10.0.0.1,10.0.0.2",
                port_range_start=1,
                port_range_end=1024,
            ),
            dict(
                acknowledged_host_range="10.0.0.0/24",
                acknowledged_port_range_start=1,
                acknowledged_port_range_end=1024,
            ),
            True,
            id="multi-entry-all-contained",
        ),
        # Multi-entry host list where only ONE entry falls outside the
        # acked range - same reasoning, opposite result.
        pytest.param(
            dict(
                host_range="10.0.0.1,10.0.1.2",
                port_range_start=1,
                port_range_end=1024,
            ),
            dict(
                acknowledged_host_range="10.0.0.0/24",
                acknowledged_port_range_start=1,
                acknowledged_port_range_end=1024,
            ),
            False,
            id="multi-entry-one-outside",
        ),
    ],
)
def test_is_acknowledged_containment_cases(service_db, scope_kwargs, ack_kwargs, expected):
    project_id = uuid.uuid4()
    service_db.get_project_scope.return_value = make_scope(
        project_id=project_id, **scope_kwargs
    )
    service_db.get_latest_acknowledgment.return_value = make_acknowledgment(
        project_id=project_id, **ack_kwargs
    )

    assert ProjectScopeService.is_acknowledged(project_id) is expected


def test_is_acknowledged_returns_false_when_no_acknowledgment_exists(service_db):
    project_id = uuid.uuid4()
    service_db.get_project_scope.return_value = make_scope(project_id=project_id)
    service_db.get_latest_acknowledgment.return_value = None

    assert ProjectScopeService.is_acknowledged(project_id) is False


# --- create_scope --------------------------------------------------------


def test_create_scope_rejects_invalid_host_range(service_db):
    with pytest.raises(ValueError):
        ProjectScopeService.create_scope(uuid.uuid4(), "not-a-host", 1, 1024)

    service_db.update_project_scope.assert_not_called()


def test_create_scope_rejects_port_start_greater_than_end(service_db):
    with pytest.raises(ValueError):
        ProjectScopeService.create_scope(uuid.uuid4(), "10.0.0.1", 1024, 1)

    service_db.update_project_scope.assert_not_called()


def test_create_scope_rejects_port_out_of_range(service_db):
    with pytest.raises(ValueError):
        ProjectScopeService.create_scope(uuid.uuid4(), "10.0.0.1", 1, 65536)

    service_db.update_project_scope.assert_not_called()


def test_create_scope_persists_valid_scope_and_returns_it(service_db):
    project_id = uuid.uuid4()
    service_db.update_project_scope.side_effect = lambda scope: scope

    result = ProjectScopeService.create_scope(project_id, "10.0.0.0/24", 1, 1024)

    assert isinstance(result, ProjectScope)
    assert result.project_id == project_id
    assert result.host_range == "10.0.0.0/24"
    assert result.port_range_start == 1
    assert result.port_range_end == 1024
    service_db.update_project_scope.assert_called_once()


# --- update_scope ---------------------------------------------------------


def test_update_scope_rejects_invalid_host_range(service_db):
    with pytest.raises(ValueError):
        ProjectScopeService.update_scope(uuid.uuid4(), "garbage", 1, 1024)

    service_db.update_project_scope.assert_not_called()


def test_update_scope_persists_new_range_without_touching_acknowledgment(service_db):
    project_id = uuid.uuid4()
    service_db.update_project_scope.side_effect = lambda scope: scope

    result = ProjectScopeService.update_scope(project_id, "10.0.0.0/24", 1, 2048)

    assert result.host_range == "10.0.0.0/24"
    assert result.port_range_end == 2048
    service_db.add_authorization_acknowledgment.assert_not_called()
    service_db.get_latest_acknowledgment.assert_not_called()


# --- submit_acknowledgment -------------------------------------------------


def test_submit_acknowledgment_snapshots_the_current_scope(service_db):
    project_id = uuid.uuid4()
    service_db.get_project_scope.return_value = make_scope(
        project_id=project_id, host_range="10.0.0.1", port_range_start=1, port_range_end=1024
    )
    service_db.add_authorization_acknowledgment.side_effect = lambda ack: ack

    result = ProjectScopeService.submit_acknowledgment(project_id, "alice", "engagement desc")

    assert isinstance(result, AuthorizationAcknowledgment)
    assert result.project_id == project_id
    assert result.acknowledged_by == "alice"
    assert result.description == "engagement desc"
    assert result.acknowledged_host_range == "10.0.0.1"
    assert result.acknowledged_port_range_start == 1
    assert result.acknowledged_port_range_end == 1024


def test_submit_acknowledgment_uses_the_scopes_current_range_not_a_stale_one(service_db):
    """The scope changes after an earlier state was read elsewhere in the
    app - submit_acknowledgment must snapshot whatever db_manager returns
    for the CURRENT scope at call time, not some value cached earlier."""
    project_id = uuid.uuid4()
    service_db.get_project_scope.return_value = make_scope(
        project_id=project_id, host_range="10.0.0.0/24", port_range_start=1, port_range_end=2048
    )
    service_db.add_authorization_acknowledgment.side_effect = lambda ack: ack

    result = ProjectScopeService.submit_acknowledgment(project_id, "alice", "re-ack after widen")

    assert result.acknowledged_host_range == "10.0.0.0/24"
    assert result.acknowledged_port_range_start == 1
    assert result.acknowledged_port_range_end == 2048
