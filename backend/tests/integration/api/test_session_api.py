"""§1.4b: session_router through the real app against pg_container.
test_session_service.delete_session is supposed to reject deleting a
RUNNING session - this proves the real row survives the rejected call, not
just that the HTTP response was an error."""

from src.schemas.target_scheme import Target
from src.schemas.test_session_scheme import TestSession, TestSessionOutcome


def test_delete_running_session_is_rejected_and_row_survives(
    api_integration_client, pg_container
):
    project = api_integration_client.post(
        "/api/project",
        json={"name": "Session Host", "base_model_name": "", "parsing_model_name": ""},
    ).json()
    target = pg_container.add_target(
        Target(
            name="t1",
            project_id=project["id"],
            ipv4=None,
            ipv6=None,
            description=None,
            ports=[],
            task_duration=None,
        )
    )
    session = pg_container.add_test_session(
        TestSession(
            project_id=project["id"],
            target_id=target.id,
            outcome=TestSessionOutcome.RUNNING,
            pipeline_mode="single_agent",
            max_concurrent_agents=1,
            base_model_name="",
            orchestrator_model_name="",
            scouting_model_name="",
            pentesting_model_name="",
            reporting_model_name="",
        )
    )

    response = api_integration_client.delete(f"/api/session/{session.id}")
    assert response.status_code == 409

    persisted = pg_container.get_test_session(session.id)
    assert persisted is not None
    assert persisted.outcome == TestSessionOutcome.RUNNING
