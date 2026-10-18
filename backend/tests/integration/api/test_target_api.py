"""§1.4b: target_router through the real app against pg_container. The PUT
out-of-range-port case pins whatever status the real
target_service.update_target validator produces today (routers.md's gap
table flags target PUT as a generic 500 for this case) rather than
asserting what it "should" be - that's a separate, already-planned unit-
tier task (docs/testing-plan.md §1.4)."""


def _create_project(client):
    return client.post(
        "/api/project",
        json={"name": "Target Host", "base_model_name": "", "parsing_model_name": ""},
    ).json()


def test_post_target_is_reachable_via_real_get_afterward(api_integration_client, pg_container):
    project = _create_project(api_integration_client)

    response = api_integration_client.post(
        f"/api/project/{project['id']}/target",
        json={
            "name": "web-server",
            "ipv4": None,
            "ipv6": None,
            "description": None,
            "ports": None,
            "task_duration": None,
        },
    )
    assert response.status_code == 200
    target_id = response.json()["id"]

    stored = pg_container.get_target(target_id)
    assert stored is not None
    assert stored.name == "web-server"
    assert str(stored.project_id) == project["id"]


def test_put_target_persists_real_changes(api_integration_client, pg_container):
    project = _create_project(api_integration_client)
    created = api_integration_client.post(
        f"/api/project/{project['id']}/target",
        json={
            "name": "db-server",
            "ipv4": None,
            "ipv6": None,
            "description": None,
            "ports": None,
            "task_duration": None,
        },
    ).json()

    response = api_integration_client.put(
        f"/api/target/{created['id']}",
        json={
            "name": "db-server",
            "ipv4": "10.0.0.5",
            "ipv6": None,
            "description": "renamed",
            "ports": [22, 443],
            "task_duration": None,
        },
    )
    assert response.status_code == 200

    stored = pg_container.get_target(created["id"])
    assert stored.ipv4 == "10.0.0.5"
    assert stored.description == "renamed"
    assert sorted(stored.ports) == [22, 443]


def test_delete_target_removes_the_real_row(api_integration_client, pg_container):
    project = _create_project(api_integration_client)
    created = api_integration_client.post(
        f"/api/project/{project['id']}/target",
        json={
            "name": "to-delete",
            "ipv4": None,
            "ipv6": None,
            "description": None,
            "ports": None,
            "task_duration": None,
        },
    ).json()

    response = api_integration_client.delete(f"/api/target/{created['id']}")
    assert response.status_code == 204

    assert pg_container.get_target(created["id"]) is None


def test_put_target_with_out_of_range_port_hits_current_real_behavior(
    api_integration_client, pg_container
):
    project = _create_project(api_integration_client)
    created = api_integration_client.post(
        f"/api/project/{project['id']}/target",
        json={
            "name": "port-boundary",
            "ipv4": None,
            "ipv6": None,
            "description": None,
            "ports": None,
            "task_duration": None,
        },
    ).json()

    response = api_integration_client.put(
        f"/api/target/{created['id']}",
        json={
            "name": "port-boundary",
            "ipv4": None,
            "ipv6": None,
            "description": None,
            "ports": [65536],
            "task_duration": None,
        },
    )

    # ValidPort (TargetBase.ports' pydantic type) is `ge=1, le=65535`, so
    # FastAPI's own request-body validation rejects 65536 before it ever
    # reaches target_service.update_target's hand-written port-range check -
    # a 422, not the generic 500 target_service's own ValueError would map
    # to (see target_router.py's update_target). Pin this real behavior.
    assert response.status_code == 422

    # add_target (TargetService.add_target) only ever uses data.name - the
    # created row's ports start at [] regardless of what the POST body
    # said, which is why the PUT never touched a None here.
    stored = pg_container.get_target(created["id"])
    assert stored.ports == []
