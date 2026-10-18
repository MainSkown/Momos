"""§1.4b: project_router through the real app against pg_container. Every
assertion checks real DB state after the HTTP call, not just the response
body - that's the whole point of this tier over the mocked router/service
unit tests (see docs/testing-plan.md §1.4b)."""

from src.schemas.target_scheme import Target
from src.schemas.test_session_scheme import TestSession


def test_post_project_is_reachable_via_real_get_afterward(api_integration_client, pg_container):
    response = api_integration_client.post(
        "/api/project",
        json={"name": "Acme Corp", "base_model_name": "", "parsing_model_name": ""},
    )
    assert response.status_code == 200
    project_id = response.json()["id"]

    stored = pg_container.get_project(project_id)
    assert stored is not None
    assert stored.name == "Acme Corp"


def test_put_settings_persists_to_the_real_row(api_integration_client, pg_container):
    created = api_integration_client.post(
        "/api/project",
        json={"name": "Settings Target", "base_model_name": "", "parsing_model_name": ""},
    ).json()
    project_id = created["id"]

    current = api_integration_client.get(f"/api/project/{project_id}/settings").json()
    current["should_interrupt"] = True
    current["starting_prompt"] = "a brand new starting prompt"
    current["project_id"] = project_id

    response = api_integration_client.put(
        f"/api/project/{project_id}/settings", json=current
    )
    assert response.status_code == 200

    persisted = pg_container.get_project_settings(project_id, create_new=False)
    assert persisted.should_interrupt is True
    assert persisted.starting_prompt == "a brand new starting prompt"


def test_delete_project_cascades_to_target_and_session(api_integration_client, pg_container):
    created = api_integration_client.post(
        "/api/project",
        json={"name": "Cascade Target", "base_model_name": "", "parsing_model_name": ""},
    ).json()
    project_id = created["id"]

    target = pg_container.add_target(
        Target(
            name="t1",
            project_id=project_id,
            ipv4=None,
            ipv6=None,
            description=None,
            ports=[],
            task_duration=None,
        )
    )
    session = pg_container.add_test_session(
        TestSession(
            project_id=project_id,
            target_id=target.id,
            pipeline_mode="single_agent",
            max_concurrent_agents=1,
            base_model_name="",
            orchestrator_model_name="",
            scouting_model_name="",
            pentesting_model_name="",
            reporting_model_name="",
        )
    )

    response = api_integration_client.delete(f"/api/project/{project_id}")
    assert response.status_code == 204

    assert pg_container.get_project(project_id) is None
    assert pg_container.get_target(target.id) is None
    assert pg_container.get_test_session(session.id) is None
