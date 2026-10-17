"""§1.4b: websocket_router through the real app - proves router ->
service -> ws_registry wiring end-to-end by connecting a real websocket
client and confirming a real HTTP-triggered event actually broadcasts to
it. Reuses the same real kali_client creation flow test_kali_api.py
exercises (kali_registry.get_manager's own KaliContainerActiveMessage
broadcast, and kali_user_registry's CreatedKaliUserMessage once the build
finishes) - both go through ws_registry.send_message for real, to every
connected socket, with no per-project filtering (see
websocket_registry.py's send_message - it's a plain broadcast). See
docs/testing-plan.md §1.4b."""

import pytest


@pytest.mark.timeout(10)
def test_kali_client_creation_broadcasts_over_the_real_websocket(
    api_integration_client, kali_container_ready
):
    project = api_integration_client.post(
        "/api/project",
        json={"name": "WS Target", "base_model_name": "", "parsing_model_name": ""},
    ).json()

    with api_integration_client.websocket_connect("/ws/client") as websocket:
        created = api_integration_client.post(
            f"/api/project/{project['id']}/kali_client"
        )
        assert created.status_code == 200
        client_id = created.json()["client_id"]

        # KaliRegistry.get_manager's own KaliContainerActiveMessage fires
        # first (the chokepoint every Kali trigger goes through), then
        # kali_user_registry's CreatedKaliUserMessage once create_user's
        # background build actually finishes - read messages until both
        # are seen rather than assuming a fixed order/count.
        seen_types = set()
        client_id_confirmed = False
        for _ in range(10):
            message = websocket.receive_json()
            seen_types.add(message["type"])
            if message["type"] == "CreatedKaliUserMessage":
                assert message["client_id"] == client_id
                assert message["project_id"] == project["id"]
                client_id_confirmed = True
            if "KaliContainerActive" in seen_types and client_id_confirmed:
                break

        assert "KaliContainerActive" in seen_types
        assert client_id_confirmed
