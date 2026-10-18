"""Shared fixture for the router unit tests - every test here drives
TestClient(app) with the SERVICE layer mocked at each router's own call
site, never a real Postgres connection (see tests/integration/api for
that tier). See docs/testing-plan.md §1.4's "Routers" bullet and
docs/testing-crawler-reports/routers.md for the full per-endpoint
exception->status-code table these tests confirm against."""

import pytest
from fastapi.testclient import TestClient

from main import app


@pytest.fixture
def api_client():
    """TestClient(app), deliberately never entered via `with` - doing so
    would run main.py's real lifespan (live Postgres connect, checkpointer
    setup, a models.schema.json disk write), none of which any router
    test needs since the service call underneath every route is mocked
    per-test. request.app.state.ollama_models is set directly instead,
    mirroring what the real lifespan would otherwise populate it with."""
    client = TestClient(app)
    client.app.state.ollama_models = []
    return client
