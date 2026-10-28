"""DatabaseManager's ProjectScope/AuthorizationAcknowledgment CRUD - a
real DatabaseManager against an in-memory SQLite engine (StaticPool keeps
the same in-memory database alive across the several Session(self.engine)
calls each DatabaseManager method opens), not Postgres/testcontainers -
this is pure CRUD logic with no Postgres-specific column types involved
for these two tables, so the real-Postgres tier (tests/integration/
test_database_manager.py, pg_container) is unnecessary weight here (see
docs/testing-plan.md's "cheapest test that would actually fail" rule).
Only the tables these tests touch are created - the rest of this file's
models use Postgres-only column types (e.g. ProjectSettings.enabled_tools's
ARRAY(String)) that SQLite's create_all can't build."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel

from src.core.database_manager import DatabaseManager
from src.schemas.project_scheme import (
    AuthorizationAcknowledgment,
    Project,
    ProjectScope,
)


@pytest.fixture
def sqlite_db_manager():
    manager = DatabaseManager("sqlite://")
    manager.engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(
        manager.engine,
        tables=[
            Project.__table__,
            ProjectScope.__table__,
            AuthorizationAcknowledgment.__table__,
        ],
    )
    return manager


@pytest.fixture
def project(sqlite_db_manager):
    return sqlite_db_manager.add_to_database(Project(name="proj"))


def test_add_project_persists_project_and_scope_atomically(sqlite_db_manager):
    project = Project(name="proj")
    scope = ProjectScope(host_range="10.0.0.1", port_range_start=1, port_range_end=1024)

    saved_project = sqlite_db_manager.add_project(project, scope)

    assert sqlite_db_manager.get_project(saved_project.id) is not None
    saved_scope = sqlite_db_manager.get_project_scope(saved_project.id)
    assert saved_scope is not None
    assert saved_scope.host_range == "10.0.0.1"


def test_get_project_scope_returns_none_when_missing(sqlite_db_manager, project):
    assert sqlite_db_manager.get_project_scope(project.id) is None


def test_update_project_scope_round_trips_changed_fields(sqlite_db_manager, project):
    scope = ProjectScope(
        project_id=project.id,
        host_range="10.0.0.1",
        port_range_start=1,
        port_range_end=1024,
    )
    sqlite_db_manager.add_to_database(scope)

    scope.host_range = "10.0.0.0/24"
    updated = sqlite_db_manager.update_project_scope(scope)

    assert updated.host_range == "10.0.0.0/24"
    fetched = sqlite_db_manager.get_project_scope(project.id)
    assert fetched.host_range == "10.0.0.0/24"


def test_add_authorization_acknowledgment_persists_a_new_row(sqlite_db_manager, project):
    ack = AuthorizationAcknowledgment(
        project_id=project.id,
        acknowledged_by="alice",
        description="d",
        acknowledged_host_range="10.0.0.1",
        acknowledged_port_range_start=1,
        acknowledged_port_range_end=1024,
    )

    saved = sqlite_db_manager.add_authorization_acknowledgment(ack)

    assert saved.id is not None
    assert sqlite_db_manager.get_latest_acknowledgment(project.id).id == saved.id


def test_get_latest_acknowledgment_returns_none_when_none_submitted(sqlite_db_manager, project):
    assert sqlite_db_manager.get_latest_acknowledgment(project.id) is None


def test_get_latest_acknowledgment_returns_the_most_recently_created_row(
    sqlite_db_manager, project
):
    base_time = datetime.now(timezone.utc)

    def make_ack(label: str, created_at: datetime) -> AuthorizationAcknowledgment:
        return AuthorizationAcknowledgment(
            project_id=project.id,
            acknowledged_by=label,
            description="d",
            acknowledged_host_range="10.0.0.1",
            acknowledged_port_range_start=1,
            acknowledged_port_range_end=1,
            created_at=created_at,
        )

    sqlite_db_manager.add_authorization_acknowledgment(make_ack("first", base_time))
    sqlite_db_manager.add_authorization_acknowledgment(
        make_ack("third", base_time + timedelta(minutes=10))
    )
    sqlite_db_manager.add_authorization_acknowledgment(
        make_ack("second", base_time + timedelta(minutes=5))
    )

    latest = sqlite_db_manager.get_latest_acknowledgment(project.id)

    assert latest.acknowledged_by == "third"
