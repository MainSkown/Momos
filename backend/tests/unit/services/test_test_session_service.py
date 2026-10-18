import uuid
from types import SimpleNamespace

import pytest

from src.schemas.attack_vector_scheme import AttackVectorStatus
from src.schemas.test_session_scheme import TestSession, TestSessionOutcome
from src.services.test_session_service import TestSessionService
from src.utils.exceptions import SessionDoesNotExistException, SessionIsRunningException


@pytest.fixture
def patched_db(fake_db_manager, monkeypatch):
    monkeypatch.setattr("src.services.test_session_service.db_manager", fake_db_manager)
    return fake_db_manager


def make_session(**overrides):
    defaults = dict(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        target_id=uuid.uuid4(),
        outcome=TestSessionOutcome.RUNNING,
        pipeline_mode="single_agent",
        max_concurrent_agents=1,
        base_model_name="llama3",
        orchestrator_model_name="llama3",
        scouting_model_name="llama3",
        pentesting_model_name="llama3",
        reporting_model_name="llama3",
    )
    defaults.update(overrides)
    return TestSession(**defaults)


def make_vector(status, linked_vulnerability_id=None):
    return SimpleNamespace(status=status, linked_vulnerability_id=linked_vulnerability_id)


# --- get_session_detail: derived vector_counts / vulnerability_count ---


def test_get_session_detail_with_no_vectors_reports_every_status_at_zero(patched_db):
    session = make_session()
    patched_db.get_test_session.return_value = session
    patched_db.get_attack_vectors_for_session.return_value = []

    detail = TestSessionService.get_session_detail(str(session.id))

    assert detail.vector_counts == {s.value: 0 for s in AttackVectorStatus}
    assert detail.vulnerability_count == 0


def test_get_session_detail_dedups_vulnerability_count_by_linked_id(patched_db):
    session = make_session()
    shared_vuln_id = uuid.uuid4()
    vectors = [
        make_vector(AttackVectorStatus.TESTED_VULNERABLE, shared_vuln_id),
        make_vector(AttackVectorStatus.TESTED_VULNERABLE, shared_vuln_id),
    ]
    patched_db.get_test_session.return_value = session
    patched_db.get_attack_vectors_for_session.return_value = vectors

    detail = TestSessionService.get_session_detail(str(session.id))

    assert detail.vulnerability_count == 1
    assert detail.vector_counts[AttackVectorStatus.TESTED_VULNERABLE.value] == 2


def test_get_session_detail_excludes_unlinked_vectors_from_vulnerability_count(patched_db):
    session = make_session()
    vectors = [
        make_vector(AttackVectorStatus.PENDING, linked_vulnerability_id=None),
        make_vector(AttackVectorStatus.TESTED_NOT_VULNERABLE, linked_vulnerability_id=None),
    ]
    patched_db.get_test_session.return_value = session
    patched_db.get_attack_vectors_for_session.return_value = vectors

    detail = TestSessionService.get_session_detail(str(session.id))

    # Both vectors have no linked vulnerability: excluded from the count...
    assert detail.vulnerability_count == 0
    # ...but still counted in vector_counts.
    assert detail.vector_counts[AttackVectorStatus.PENDING.value] == 1
    assert detail.vector_counts[AttackVectorStatus.TESTED_NOT_VULNERABLE.value] == 1


def test_get_session_detail_reports_every_attack_vector_status_even_at_zero(patched_db):
    session = make_session()
    vectors = [make_vector(AttackVectorStatus.TESTING)]
    patched_db.get_test_session.return_value = session
    patched_db.get_attack_vectors_for_session.return_value = vectors

    detail = TestSessionService.get_session_detail(str(session.id))

    assert set(detail.vector_counts.keys()) == {s.value for s in AttackVectorStatus}
    assert sum(detail.vector_counts.values()) == len(vectors)
    assert detail.vector_counts[AttackVectorStatus.TESTING.value] == 1
    for status in AttackVectorStatus:
        if status != AttackVectorStatus.TESTING:
            assert detail.vector_counts[status.value] == 0


def test_get_session_detail_raises_for_missing_session(patched_db):
    patched_db.get_test_session.return_value = None

    with pytest.raises(SessionDoesNotExistException):
        TestSessionService.get_session_detail("missing-id")

    patched_db.get_attack_vectors_for_session.assert_not_called()


# --- delete_session: refuses a RUNNING session --------------------------


def test_delete_session_refuses_running_session(patched_db):
    session = make_session(outcome=TestSessionOutcome.RUNNING)
    patched_db.get_test_session.return_value = session

    with pytest.raises(SessionIsRunningException):
        TestSessionService.delete_session(str(session.id))

    patched_db.delete_test_session.assert_not_called()


@pytest.mark.parametrize(
    "outcome", [o for o in TestSessionOutcome if o != TestSessionOutcome.RUNNING]
)
def test_delete_session_allows_every_non_running_outcome(patched_db, outcome):
    session = make_session(outcome=outcome)
    patched_db.get_test_session.return_value = session
    session_id = str(session.id)

    TestSessionService.delete_session(session_id)

    patched_db.delete_test_session.assert_called_once_with(session_id)


def test_delete_session_raises_for_missing_session(patched_db):
    patched_db.get_test_session.return_value = None

    with pytest.raises(SessionDoesNotExistException):
        TestSessionService.delete_session("missing-id")

    patched_db.delete_test_session.assert_not_called()
