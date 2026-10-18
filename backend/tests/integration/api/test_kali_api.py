"""§1.4b: kali_router through the real app - kali_router -> KaliService ->
kali_registry/kali_user_registry -> KaliManger, Docker faked only at its
one real call site (fake_docker_client, see kali_container_ready). The
actual container build (kali_user_registry.create_user's background
_create_user task) runs asynchronously, so the test polls the real GET
endpoint rather than asserting immediately after the POST - see
docs/testing-plan.md §1.4b."""

import time


def _create_project(client):
    return client.post(
        "/api/project",
        json={"name": "Kali Target", "base_model_name": "", "parsing_model_name": ""},
    ).json()


def _poll_until_not_pending(client, project_id, timeout_seconds=5.0):
    deadline = time.monotonic() + timeout_seconds
    status = None
    while time.monotonic() < deadline:
        response = client.get(f"/api/project/{project_id}/kali_client")
        if response.status_code == 200:
            status = response.json()
            if not status.get("pending"):
                return status
        time.sleep(0.05)
    return status


def test_create_kali_client_is_tracked_by_the_real_registry(
    api_integration_client, kali_container_ready
):
    project = _create_project(api_integration_client)

    created = api_integration_client.post(f"/api/project/{project['id']}/kali_client")
    assert created.status_code == 200
    client_id = created.json()["client_id"]

    # Immediately after the POST, create_user's background container build
    # hasn't finished yet - the pending entry is the real, synchronous half
    # of the contract.
    pending_status = api_integration_client.get(
        f"/api/project/{project['id']}/kali_client"
    ).json()
    assert pending_status["client_id"] == client_id

    final_status = _poll_until_not_pending(api_integration_client, project["id"])
    assert final_status is not None, "container build never completed"
    assert final_status["client_id"] == client_id
    assert not final_status.get("pending")

    # Confirms the real registry bookkeeping, not just what the router
    # happens to report - get_client_for_project/get_status read straight
    # off kali_user_registry.active_users/kali_registry._active_managers.
    status_response = api_integration_client.get(
        f"/api/project/{project['id']}/kali/status"
    ).json()
    assert status_response["active"] is True
    assert status_response["building"] is False

    # The real container was actually driven through KaliManger's exec
    # pipeline (apt-get update/install, user setup, verification checks) -
    # not just "docker.from_env() got called once".
    assert kali_container_ready.exec_run.call_count > 0
