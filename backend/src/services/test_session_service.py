from typing import List, Optional, Tuple

from src.core.database_manager import db_manager
from src.schemas.agent_log_scheme import AgentLog, AgentLogType
from src.schemas.agent_run_scheme import AgentRun
from src.schemas.attack_vector_scheme import AttackVector, AttackVectorStatus
from src.schemas.test_session_scheme import (
    TestSession,
    TestSessionDetailResponse,
    TestSessionOutcome,
)
from src.utils.exceptions import SessionDoesNotExistException, SessionIsRunningException


class TestSessionService:
    @staticmethod
    def get_sessions_for_project(
        project_id: str,
        target_id: Optional[str] = None,
        outcome: Optional[TestSessionOutcome] = None,
    ) -> List[TestSession]:
        return db_manager.get_test_sessions_for_project(project_id, target_id, outcome)

    @staticmethod
    def get_session(session_id: str) -> TestSession:
        session = db_manager.get_test_session(session_id)
        if session is None:
            raise SessionDoesNotExistException(
                f"Session does not exist: {session_id}", session_id
            )
        return session

    @staticmethod
    def get_session_detail(session_id: str) -> TestSessionDetailResponse:
        """TestSessionResponse plus two counts derived at read time (see
        test_session_scheme.py's own "Decisions" note - not stored, so
        they can never go stale relative to the actual vector/vulnerability
        rows): every AttackVectorStatus this session's vectors fall into,
        and how many distinct Vulnerability rows they produced."""
        session = TestSessionService.get_session(session_id)
        vectors = db_manager.get_attack_vectors_for_session(session_id)

        vector_counts = {s.value: 0 for s in AttackVectorStatus}
        linked_vulnerability_ids = set()
        for vector in vectors:
            vector_counts[vector.status.value] = vector_counts.get(vector.status.value, 0) + 1
            if vector.linked_vulnerability_id is not None:
                linked_vulnerability_ids.add(vector.linked_vulnerability_id)

        return TestSessionDetailResponse(
            **session.model_dump(),
            vector_counts=vector_counts,
            vulnerability_count=len(linked_vulnerability_ids),
        )

    @staticmethod
    def get_session_attack_vectors(session_id: str) -> List[AttackVector]:
        TestSessionService.get_session(session_id)
        return db_manager.get_attack_vectors_for_session(session_id)

    @staticmethod
    def get_session_runs(session_id: str) -> List[AgentRun]:
        TestSessionService.get_session(session_id)
        return db_manager.get_agent_runs_for_session(session_id)

    @staticmethod
    def get_session_logs(
        session_id: str,
        role: Optional[str] = None,
        agent_run_id: Optional[str] = None,
        log_type: Optional[AgentLogType] = None,
        q: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> Tuple[List[AgentLog], int]:
        TestSessionService.get_session(session_id)
        return db_manager.get_agent_logs_for_session(
            session_id,
            role=role,
            agent_run_id=agent_run_id,
            log_type=log_type,
            q=q,
            limit=limit,
            offset=offset,
        )

    @staticmethod
    def delete_session(session_id: str) -> None:
        session = TestSessionService.get_session(session_id)
        if session.outcome == TestSessionOutcome.RUNNING:
            raise SessionIsRunningException(
                f"Cannot delete a running session: {session_id}", session_id
            )
        db_manager.delete_test_session(session_id)
