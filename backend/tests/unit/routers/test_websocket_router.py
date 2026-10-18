"""websocket_router.py - see docs/testing-crawler-reports/routers.md's
websocket_router.py section: raising HTTPException inside a websocket
route does not produce an ordinary HTTP response (there's no request/
response cycle to attach one to) - see the empirical check below for
what TestClient.websocket_connect actually surfaces instead, which is
what these assertions pin down rather than guessing at the shape."""

import importlib

import pytest
from fastapi.testclient import TestClient
from starlette.testclient import WebSocketDenialResponse

from main import app

websocket_router = importlib.import_module("src.routers.websocket_router")


def test_client_connect_error_denies_handshake_with_500(api_client, monkeypatch):
    """ws_registry.connect's real first line is `await websocket.accept()`
    (see src/websocket/websocket_registry.py) - raising before that ever
    happens means the ASGI handshake itself is never accepted. Starlette's
    TestClient surfaces that as a WebSocketDenialResponse carrying the
    router's own HTTPException status code, not a normal connection or a
    plain exception - confirmed empirically, not assumed."""

    async def boom(websocket):
        raise RuntimeError("registry exploded")

    monkeypatch.setattr(websocket_router.ws_registry, "connect", boom)

    with pytest.raises(WebSocketDenialResponse) as exc_info:
        with api_client.websocket_connect("/ws/client"):
            pass

    assert exc_info.value.status_code == 500


def test_client_connect_happy_path(api_client, monkeypatch):
    async def accept_and_close(websocket):
        await websocket.accept()
        await websocket.close()

    monkeypatch.setattr(websocket_router.ws_registry, "connect", accept_and_close)

    with api_client.websocket_connect("/ws/client") as ws:
        with pytest.raises(Exception):
            # The server closed right after accepting - the client's next
            # receive must observe that close, not hang or silently
            # succeed.
            ws.receive_text()


def test_ws_types_dummy_always_returns_501():
    client = TestClient(app)
    response = client.get("/ws/_internal/ws-types")
    assert response.status_code == 501


def test_ws_types_dummy_openapi_includes_traffic_schema():
    """The dummy endpoint exists purely so WebsocketTrafficSchema (built
    from InboundTrafficUnion/OutboundTrafficUnion) gets generated into the
    OpenAPI schema for the frontend's codegen, even though the endpoint
    itself is never meant to be called for real."""
    client = TestClient(app)
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert "WebsocketTrafficSchema" in response.text
