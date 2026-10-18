import uuid
from types import SimpleNamespace

import pytest

from src.core.kali_integration.kali_user import KaliUserRegistry
from src.services.kali_service import KaliService


def _active_user(client_id: uuid.UUID, project_id: str):
    return SimpleNamespace(client_id=client_id, project_id=project_id)


@pytest.fixture
def registry(monkeypatch):
    registry = KaliUserRegistry()
    monkeypatch.setattr("src.services.kali_service.kali_user_registry", registry)
    return registry


def test_get_client_returns_active_user_without_pending_flag(registry):
    client_id = uuid.uuid4()
    registry.active_users.append(_active_user(client_id, "project-a"))

    client = KaliService.get_client(str(client_id))

    assert client.client_id == str(client_id)
    assert client.pending is None


def test_get_client_returns_pending_user_with_pending_flag(registry):
    client_id = uuid.uuid4()
    registry.pending_users[client_id] = "project-a"

    client = KaliService.get_client(str(client_id))

    assert client.client_id == str(client_id)
    assert client.pending is True


def test_get_client_prefers_active_entry_when_id_is_in_both_lists(registry):
    client_id = uuid.uuid4()
    registry.active_users.append(_active_user(client_id, "project-a"))
    registry.pending_users[client_id] = "project-a"

    client = KaliService.get_client(str(client_id))

    assert client.pending is None


def test_get_client_returns_none_for_unknown_id(registry):
    registry.active_users.append(_active_user(uuid.uuid4(), "project-a"))

    assert KaliService.get_client(str(uuid.uuid4())) is None
