"""DatabaseManager integration suite - real Postgres via pg_container (see
tests/integration/conftest.py). Covers §1.4's DatabaseManager bullet in
docs/testing-plan.md: cascade-delete ordering, the Target.ports ARRAY
round-trip, clear_model_references, delete_vulnerability's FK behavior, and
every AttackVector/AgentRun/AgentLog/TestSession/Vulnerability datetime
column's timezone-awareness."""

import pytest
from sqlalchemy import DateTime, func, text
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, SQLModel, select

from src.schemas.agent_log_scheme import AgentLog, AgentLogType
from src.schemas.agent_run_scheme import AgentRun, AgentRunState
from src.schemas.attack_vector_scheme import AttackVector
from src.schemas.project_scheme import Project, project_settings_factory
from src.schemas.target_scheme import Target
from src.schemas.vulnerability_scheme import Vulnerability

VALID_CVSS4_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def _count(pg_container, model, **filters):
    with Session(pg_container.engine) as session:
        statement = select(func.count()).select_from(model)
        for field, value in filters.items():
            statement = statement.where(getattr(model, field) == value)
        return session.exec(statement).one()


def _make_target(pg_container, project_id, **overrides):
    fields = dict(
        project_id=project_id,
        name="target",
        ipv4=None,
        ipv6=None,
        description=None,
        ports=None,
        task_duration=None,
    )
    fields.update(overrides)
    return pg_container.add_target(Target(**fields))


def _make_vulnerability(pg_container, target_id, project_id):
    return pg_container.add_vulnerability(
        Vulnerability(
            name="vuln",
            cvss4_vector=VALID_CVSS4_VECTOR,
            proof_of_concept="poc",
            found_in=target_id,
            related_to_project=project_id,
        )
    )


def _make_attack_vector(pg_container, project_id, target_id, **overrides):
    fields = dict(project_id=project_id, target_id=target_id, description="vector")
    fields.update(overrides)
    return pg_container.add_attack_vector(AttackVector(**fields))


def _make_agent_run(pg_container, project_id, target_id):
    return pg_container.add_to_database(
        AgentRun(
            target_id=target_id,
            project_id=project_id,
            status=AgentRunState.RUNNING,
            remaining_seconds=60,
        )
    )


def _make_agent_log(pg_container, project_id, target_id):
    return pg_container.add_agent_log(
        AgentLog(
            project_id=project_id,
            target_id=target_id,
            type=AgentLogType.ACTION,
            content="log entry",
        )
    )


def test_delete_project_cascades_all_dependent_rows(pg_container):
    project = pg_container.add_project(Project(name="proj"))
    target = _make_target(pg_container, project.id)
    vulnerability = _make_vulnerability(pg_container, target.id, project.id)
    attack_vector = _make_attack_vector(
        pg_container, project.id, target.id, linked_vulnerability_id=vulnerability.id
    )
    agent_run = _make_agent_run(pg_container, project.id, target.id)
    agent_log = _make_agent_log(pg_container, project.id, target.id)

    pg_container.delete_project(project.id)

    assert pg_container.get_project(project.id) is None
    assert _count(pg_container, Target, id=target.id) == 0
    assert _count(pg_container, AttackVector, id=attack_vector.id) == 0
    assert _count(pg_container, Vulnerability, id=vulnerability.id) == 0
    assert _count(pg_container, AgentRun, id=agent_run.id) == 0
    assert _count(pg_container, AgentLog, id=agent_log.id) == 0


def test_delete_target_only_removes_that_targets_rows(pg_container):
    project = pg_container.add_project(Project(name="proj"))
    target_to_delete = _make_target(pg_container, project.id, name="doomed")
    surviving_target = _make_target(pg_container, project.id, name="survivor")

    deleted_vulnerability = _make_vulnerability(pg_container, target_to_delete.id, project.id)
    # linked_vulnerability_id is what makes the ordering load-bearing (a real
    # FK, no ON DELETE clause - see test_delete_vulnerability_with_linked_
    # attack_vector_raises_integrity_error below) - without it this test
    # can't tell delete_target's ordering apart from no ordering at all.
    deleted_vector = _make_attack_vector(
        pg_container,
        project.id,
        target_to_delete.id,
        linked_vulnerability_id=deleted_vulnerability.id,
    )
    deleted_run = _make_agent_run(pg_container, project.id, target_to_delete.id)
    deleted_log = _make_agent_log(pg_container, project.id, target_to_delete.id)

    surviving_vulnerability = _make_vulnerability(pg_container, surviving_target.id, project.id)
    surviving_vector = _make_attack_vector(pg_container, project.id, surviving_target.id)
    surviving_run = _make_agent_run(pg_container, project.id, surviving_target.id)
    surviving_log = _make_agent_log(pg_container, project.id, surviving_target.id)

    pg_container.delete_target(target_to_delete.id)

    assert pg_container.get_target(target_to_delete.id) is None
    assert _count(pg_container, Vulnerability, id=deleted_vulnerability.id) == 0
    assert _count(pg_container, AttackVector, id=deleted_vector.id) == 0
    assert _count(pg_container, AgentRun, id=deleted_run.id) == 0
    assert _count(pg_container, AgentLog, id=deleted_log.id) == 0

    assert pg_container.get_target(surviving_target.id) is not None
    assert _count(pg_container, Vulnerability, id=surviving_vulnerability.id) == 1
    assert _count(pg_container, AttackVector, id=surviving_vector.id) == 1
    assert _count(pg_container, AgentRun, id=surviving_run.id) == 1
    assert _count(pg_container, AgentLog, id=surviving_log.id) == 1


def test_target_ports_array_round_trips_exact_order(pg_container):
    project = pg_container.add_project(Project(name="proj"))
    target = _make_target(pg_container, project.id, ports=[22, 80, 443])

    fetched = pg_container.get_target(target.id)

    assert fetched.ports == [22, 80, 443]


def test_clear_model_references_clears_all_six_model_fields(pg_container):
    project = pg_container.add_project(Project(name="proj"))
    model_name = "llama3:8b"
    settings = project_settings_factory(project_id=project.id)
    settings.base_model_name = model_name
    settings.parsing_model_name = model_name
    settings.orchestrator_model_name = model_name
    settings.scouting_model_name = model_name
    settings.pentesting_model_name = model_name
    settings.reporting_model_name = model_name
    pg_container.add_to_database(settings)

    pg_container.clear_model_references(model_name)

    # Pinned to the behavior the docstring promises (all six model-name
    # fields), not to what the method currently does - see final report.
    refreshed = pg_container.get_project_settings(project.id, create_new=False)
    assert refreshed.base_model_name == ""
    assert refreshed.parsing_model_name == ""
    assert refreshed.orchestrator_model_name == ""
    assert refreshed.scouting_model_name == ""
    assert refreshed.pentesting_model_name == ""
    assert refreshed.reporting_model_name == ""


def test_delete_vulnerability_with_linked_attack_vector_raises_integrity_error(pg_container):
    project = pg_container.add_project(Project(name="proj"))
    target = _make_target(pg_container, project.id)
    vulnerability = _make_vulnerability(pg_container, target.id, project.id)
    _make_attack_vector(
        pg_container, project.id, target.id, linked_vulnerability_id=vulnerability.id
    )

    with pytest.raises(IntegrityError):
        pg_container.delete_vulnerability(vulnerability.id)


def _datetime_columns():
    table_names = ("attackvector", "agentrun", "agentlog", "testsession", "vulnerability")
    return [
        (table_name, column.name)
        for table_name in table_names
        for column in SQLModel.metadata.tables[table_name].columns
        if isinstance(column.type, DateTime)
    ]


@pytest.mark.parametrize("table_name,column_name", _datetime_columns())
def test_datetime_columns_are_timezone_aware(pg_container, table_name, column_name):
    with pg_container.engine.connect() as conn:
        data_type = conn.execute(
            text(
                "SELECT data_type FROM information_schema.columns "
                "WHERE table_name = :table_name AND column_name = :column_name"
            ),
            {"table_name": table_name, "column_name": column_name},
        ).scalar_one()

    assert data_type == "timestamp with time zone"
