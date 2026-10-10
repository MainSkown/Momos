from typing import List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from src.schemas import (
    AgentLogResponse,
    AgentLogType,
    AgentRunResponse,
    ResponseAttackVector,
    TestSessionDetailResponse,
    TestSessionOutcome,
    TestSessionResponse,
)
from src.services import TestSessionService
from src.utils.exceptions import SessionDoesNotExistException, SessionIsRunningException

router = APIRouter()


class SessionLogsResponse(BaseModel):
    items: List[AgentLogResponse]
    total: int


@router.get(
    "/project/{project_id}/sessions",
    response_model=List[TestSessionResponse],
    operation_id="GetProjectTestSessions",
)
def get_project_test_sessions(
    project_id: str,
    target_id: Optional[str] = None,
    outcome: Optional[TestSessionOutcome] = None,
):
    try:
        return TestSessionService.get_sessions_for_project(project_id, target_id, outcome)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not list sessions for project: {project_id}",
        )


@router.get(
    "/session/{session_id}",
    response_model=TestSessionDetailResponse,
    operation_id="GetTestSession",
)
def get_test_session(session_id: str):
    try:
        return TestSessionService.get_session_detail(session_id)
    except SessionDoesNotExistException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not fetch session: {session_id}",
        )


@router.get(
    "/session/{session_id}/attack_vectors",
    response_model=List[ResponseAttackVector],
    operation_id="GetTestSessionAttackVectors",
)
def get_test_session_attack_vectors(session_id: str):
    try:
        return TestSessionService.get_session_attack_vectors(session_id)
    except SessionDoesNotExistException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not fetch session attack vectors: {session_id}",
        )


@router.get(
    "/session/{session_id}/runs",
    response_model=List[AgentRunResponse],
    operation_id="GetTestSessionRuns",
)
def get_test_session_runs(session_id: str):
    try:
        return TestSessionService.get_session_runs(session_id)
    except SessionDoesNotExistException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not fetch session runs: {session_id}",
        )


@router.get(
    "/session/{session_id}/logs",
    response_model=SessionLogsResponse,
    operation_id="GetTestSessionLogs",
)
def get_test_session_logs(
    session_id: str,
    role: Optional[str] = None,
    agent_run_id: Optional[str] = None,
    type: Optional[AgentLogType] = None,
    q: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
):
    try:
        items, total = TestSessionService.get_session_logs(
            session_id,
            role=role,
            agent_run_id=agent_run_id,
            log_type=type,
            q=q,
            limit=limit,
            offset=offset,
        )
        return SessionLogsResponse(items=items, total=total)
    except SessionDoesNotExistException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not fetch session logs: {session_id}",
        )


@router.delete(
    "/session/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="DeleteTestSession",
)
def delete_test_session(session_id: str):
    try:
        TestSessionService.delete_session(session_id)
        return
    except SessionDoesNotExistException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except SessionIsRunningException as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not delete session: {session_id}",
        )
