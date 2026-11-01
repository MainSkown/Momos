from unittest.mock import AsyncMock, MagicMock

import pytest

import main


@pytest.mark.asyncio
async def test_lifespan_initializes_db_before_checking_orphaned_sessions(monkeypatch):
    # mark_orphaned_sessions_aborted queries tables init_db() creates - if
    # the two calls were ever reordered it would break against a fresh
    # database. See docs/testing-plan.md §1.0.
    call_order = []
    monkeypatch.setattr(main, "export_json_schema", MagicMock())
    monkeypatch.setattr(main, "setup_checkpointer", AsyncMock())
    monkeypatch.setattr(main, "shutdown_checkpointer", AsyncMock())
    monkeypatch.setattr(main.kali_registry, "shutdown", AsyncMock())
    monkeypatch.setattr(
        main.db_manager, "init_db", lambda: call_order.append("init_db")
    )
    async def fake_apply_startup_ollama_connection():
        call_order.append("apply_startup_ollama_connection")

    monkeypatch.setattr(
        main, "_apply_startup_ollama_connection", fake_apply_startup_ollama_connection
    )
    monkeypatch.setattr(
        main.db_manager,
        "mark_orphaned_sessions_aborted",
        lambda: call_order.append("mark_orphaned_sessions_aborted"),
    )

    app = MagicMock()

    async with main.lifespan(app):
        pass

    assert call_order == [
        "init_db",
        "apply_startup_ollama_connection",
        "mark_orphaned_sessions_aborted",
    ]


# --- _apply_startup_ollama_connection: Milestone 3 (remote Ollama
# connection), O4. Provisioning must run unconditionally (Local or Remote);
# only a saved Remote row's effect on ollama_manager differs by mode. ----


class _FakeConnectionRow:
    def __init__(self, mode, remote_url="", remote_api_key_encrypted=None):
        self.mode = mode
        self.remote_url = remote_url
        self.remote_api_key_encrypted = remote_api_key_encrypted


async def test_apply_startup_ollama_connection_always_provisions_encryption_key(monkeypatch):
    provision_mock = MagicMock()
    monkeypatch.setattr(main.encryption_service, "ensure_encryption_key_provisioned", provision_mock)
    monkeypatch.setattr(
        main.db_manager, "get_ollama_connection_settings", lambda: _FakeConnectionRow(mode="local")
    )
    monkeypatch.setattr(main.ollama_manager, "reconfigure", AsyncMock())

    await main._apply_startup_ollama_connection()

    provision_mock.assert_called_once()


async def test_apply_startup_ollama_connection_leaves_local_row_untouched(monkeypatch):
    monkeypatch.setattr(main.encryption_service, "ensure_encryption_key_provisioned", MagicMock())
    monkeypatch.setattr(
        main.db_manager, "get_ollama_connection_settings", lambda: _FakeConnectionRow(mode="local")
    )
    reconfigure_mock = AsyncMock()
    monkeypatch.setattr(main.ollama_manager, "reconfigure", reconfigure_mock)

    await main._apply_startup_ollama_connection()

    reconfigure_mock.assert_not_called()


async def test_apply_startup_ollama_connection_applies_saved_remote_connection_with_key(monkeypatch):
    monkeypatch.setattr(main.encryption_service, "ensure_encryption_key_provisioned", MagicMock())
    monkeypatch.setattr(main.encryption_service, "encryption_key_configured", lambda: True)
    monkeypatch.setattr(main.encryption_service, "decrypt_secret", lambda ciphertext: "decrypted-key")
    connection = _FakeConnectionRow(
        mode="remote", remote_url="http://remote:11434", remote_api_key_encrypted=b"ciphertext"
    )
    monkeypatch.setattr(main.db_manager, "get_ollama_connection_settings", lambda: connection)
    reconfigure_mock = AsyncMock()
    monkeypatch.setattr(main.ollama_manager, "reconfigure", reconfigure_mock)

    await main._apply_startup_ollama_connection()

    reconfigure_mock.assert_called_once_with(
        "http://remote:11434",
        headers={"Authorization": "Bearer decrypted-key"},
        timeout=main.SAVED_CONNECTION_TIMEOUT_SECONDS,
    )


async def test_apply_startup_ollama_connection_applies_saved_remote_connection_without_key(monkeypatch):
    monkeypatch.setattr(main.encryption_service, "ensure_encryption_key_provisioned", MagicMock())
    monkeypatch.setattr(main.encryption_service, "encryption_key_configured", lambda: True)
    connection = _FakeConnectionRow(mode="remote", remote_url="http://remote:11434")
    monkeypatch.setattr(main.db_manager, "get_ollama_connection_settings", lambda: connection)
    reconfigure_mock = AsyncMock()
    monkeypatch.setattr(main.ollama_manager, "reconfigure", reconfigure_mock)

    await main._apply_startup_ollama_connection()

    reconfigure_mock.assert_called_once_with(
        "http://remote:11434", headers=None, timeout=main.SAVED_CONNECTION_TIMEOUT_SECONDS
    )


async def test_apply_startup_ollama_connection_raises_if_remote_but_key_never_provisioned(monkeypatch):
    # Defensive-only path: ensure_encryption_key_provisioned() above should
    # make this unreachable in practice; this proves the literal fail-fast
    # backstop still fires if provisioning was ever bypassed.
    monkeypatch.setattr(main.encryption_service, "ensure_encryption_key_provisioned", MagicMock())
    monkeypatch.setattr(main.encryption_service, "encryption_key_configured", lambda: False)
    connection = _FakeConnectionRow(mode="remote", remote_url="http://remote:11434")
    monkeypatch.setattr(main.db_manager, "get_ollama_connection_settings", lambda: connection)
    reconfigure_mock = AsyncMock()
    monkeypatch.setattr(main.ollama_manager, "reconfigure", reconfigure_mock)

    with pytest.raises(RuntimeError, match="APP_ENCRYPTION_KEY"):
        await main._apply_startup_ollama_connection()

    reconfigure_mock.assert_not_called()
