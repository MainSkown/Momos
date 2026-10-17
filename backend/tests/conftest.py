"""Shared fixtures for the whole backend test suite - the boundary mocks
that keep every tier (unit AND the §1.4b API-integration tier) from ever
reaching a real Docker daemon, Ollama server or LLM. See
docs/testing-plan.md §1.3 for the full rationale; each test module scripts
these mocks' specific return values/side effects as it needs, these
fixtures only wire the right thing in."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel

from src.core.database_manager import DatabaseManager
from src.core.ollama_manager import ollama_manager


@pytest.fixture
def fake_db_manager():
    """A MagicMock(spec=DatabaseManager) - never a real Postgres connection.
    Module-level singletons are imported by name into each consuming
    module, so patch this onto the CONSUMING module's reference (e.g.
    monkeypatch.setattr("src.services.target_service.db_manager", ...)),
    never onto src.core.database_manager.db_manager itself - that patch
    would have no effect on a module that already imported its own name
    for it."""
    return MagicMock(spec=DatabaseManager)


@pytest.fixture
def fake_docker_client(monkeypatch):
    """A MagicMock standing in for docker.from_env() - no real Docker/Kali
    container is ever touched. Patched at its one real call site
    (KaliManager.start, see kali_manager.py), so every KaliManager built
    during a test receives this same mock as self.client. Script the exact
    container/exec behavior a test needs on the returned mock
    (containers.run, containers.get, api.exec_create/exec_start/
    exec_inspect, ...)."""
    client = MagicMock()
    monkeypatch.setattr(
        "src.core.kali_integration.kali_manager.docker.from_env", lambda: client
    )
    return client


@pytest.fixture
def fake_ollama_client(monkeypatch):
    """An AsyncMock standing in for the real ollama.AsyncClient - no real
    Ollama server is ever reached. Patched directly onto the module-level
    ollama_manager singleton's .client, since ollama_manager (like
    db_manager) is constructed once at import time."""
    client = AsyncMock()
    monkeypatch.setattr(ollama_manager, "client", client)
    return client


@pytest.fixture
def fake_llm():
    """A FakeListChatModel standing in for whatever ChatOllama instance the
    agent code would otherwise construct - no real Ollama call ever
    happens. This default only ever returns one static message; a test
    that needs a specific tool-call sequence builds its own
    FakeListChatModel(responses=[...]) instead of using this fixture."""
    return FakeListChatModel(responses=["ok"])
