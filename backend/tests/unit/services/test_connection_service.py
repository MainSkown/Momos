"""Unit tests for backend/src/services/connection_service.py - see
docs/plans/milestone-3-remote-ollama-connection.md's O2 section. Per
CLAUDE.md rule 2.1 (no tautological tests), the switch-guard blocking test,
the key-preservation test and the exception-mapping test are each verified
red->green against a deliberately broken implementation, noted individually
below; this file only encodes the final, correct behavior.

ollama_manager/db_manager are imported by NAME into
src.services.connection_service, so patches target that module's own
reference - same convention test_ollama_service.py already uses."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from ollama import ResponseError

from src.core.agent import run_registry
from src.core.config import settings
from src.schemas.ollama_connection_scheme import OllamaConnectionSettings, OllamaConnectionUpdate
from src.services.connection_service import ConnectionService
from src.utils.exceptions import ConnectionSwitchBlockedException, EncryptionKeyMissingException


@pytest.fixture(autouse=True)
def _reset_run_registry_slots():
    run_registry._project_slot_counts.clear()
    run_registry._global_slot_count = 0
    run_registry._project_slot_condition = asyncio.Condition()
    yield


@pytest.fixture(autouse=True)
def _reset_encryption_key(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENCRYPTION_KEY", None)


def _set_key(monkeypatch, key):
    monkeypatch.setattr(settings, "APP_ENCRYPTION_KEY", key)


@pytest.fixture
def fake_db_manager(monkeypatch):
    manager = MagicMock()
    manager.update_ollama_connection_settings.side_effect = lambda row: row
    monkeypatch.setattr("src.services.connection_service.db_manager", manager)
    return manager


@pytest.fixture
def fake_ollama_manager(monkeypatch):
    manager = MagicMock()
    manager.reconfigure = AsyncMock()
    monkeypatch.setattr("src.services.connection_service.ollama_manager", manager)
    return manager


def _existing(mode="local", remote_url="", remote_api_key_encrypted=None):
    return OllamaConnectionSettings(
        mode=mode, remote_url=remote_url, remote_api_key_encrypted=remote_api_key_encrypted
    )


# --- get_connection ---------------------------------------------------------


def test_get_connection_reports_has_remote_api_key_without_ever_returning_the_key(
    fake_db_manager,
):
    fake_db_manager.get_ollama_connection_settings.return_value = _existing(
        mode="remote", remote_url="https://example.com", remote_api_key_encrypted=b"ciphertext"
    )

    result = ConnectionService.get_connection()

    assert result.mode == "remote"
    assert result.remote_url == "https://example.com"
    assert result.has_remote_api_key is True


def test_get_connection_public_schema_has_no_key_field_at_all():
    from src.schemas.ollama_connection_scheme import OllamaConnectionPublic

    assert not any(name.startswith("remote_api_key") for name in OllamaConnectionPublic.model_fields)


# --- save_connection: switch guard -------------------------------------------


async def test_save_connection_raises_when_a_slot_is_held_and_touches_neither_db_nor_ollama_manager(
    fake_db_manager, fake_ollama_manager
):
    """Verified red->green: temporarily removing save_connection's
    run_exclusively_if_idle wrapping (calling the DB write + reconfigure
    directly instead) made this test fail, since the save then proceeds
    anyway while a slot is held - confirming it actually exercises the
    guard rather than always passing."""
    fake_db_manager.get_ollama_connection_settings.return_value = _existing()
    run_registry._global_slot_count = 1

    with pytest.raises(ConnectionSwitchBlockedException):
        await ConnectionService.save_connection(OllamaConnectionUpdate(mode="remote", remote_url="https://x"))

    fake_db_manager.update_ollama_connection_settings.assert_not_called()
    fake_ollama_manager.reconfigure.assert_not_called()


# --- save_connection: validation ---------------------------------------------


async def test_save_connection_remote_with_no_url_ever_saved_raises_value_error_before_touching_db(
    fake_db_manager, fake_ollama_manager
):
    fake_db_manager.get_ollama_connection_settings.return_value = _existing()

    with pytest.raises(ValueError):
        await ConnectionService.save_connection(OllamaConnectionUpdate(mode="remote", remote_url=""))

    fake_db_manager.update_ollama_connection_settings.assert_not_called()


async def test_save_connection_with_a_key_but_no_encryption_key_configured_raises_before_touching_db(
    fake_db_manager, fake_ollama_manager
):
    fake_db_manager.get_ollama_connection_settings.return_value = _existing()

    with pytest.raises(EncryptionKeyMissingException):
        await ConnectionService.save_connection(
            OllamaConnectionUpdate(mode="remote", remote_url="https://x", remote_api_key="secret")
        )

    fake_db_manager.update_ollama_connection_settings.assert_not_called()


# --- save_connection: None/""/non-empty key semantics ------------------------


async def test_save_connection_with_key_omitted_leaves_the_existing_encrypted_key_untouched(
    fake_db_manager, fake_ollama_manager, monkeypatch
):
    from cryptography.fernet import Fernet
    from src.core import encryption_service

    _set_key(monkeypatch, Fernet.generate_key().decode())
    already_encrypted = encryption_service.encrypt_secret("previously-saved-key")
    fake_db_manager.get_ollama_connection_settings.return_value = _existing(
        mode="remote", remote_url="https://x", remote_api_key_encrypted=already_encrypted
    )

    result = await ConnectionService.save_connection(
        OllamaConnectionUpdate(mode="remote", remote_url="https://x", remote_api_key=None)
    )

    saved_row = fake_db_manager.update_ollama_connection_settings.call_args.args[0]
    assert saved_row.remote_api_key_encrypted == already_encrypted
    assert result.has_remote_api_key is True


async def test_save_connection_with_empty_string_key_clears_the_stored_key(
    fake_db_manager, fake_ollama_manager, monkeypatch
):
    _set_key(monkeypatch, "an-irrelevant-key-not-used-in-this-case")
    fake_db_manager.get_ollama_connection_settings.return_value = _existing(
        mode="remote", remote_url="https://x", remote_api_key_encrypted=b"already-encrypted"
    )

    result = await ConnectionService.save_connection(
        OllamaConnectionUpdate(mode="remote", remote_url="https://x", remote_api_key="")
    )

    saved_row = fake_db_manager.update_ollama_connection_settings.call_args.args[0]
    assert saved_row.remote_api_key_encrypted is None
    assert result.has_remote_api_key is False


async def test_save_connection_with_a_non_empty_key_stores_it_encrypted_not_as_plaintext(
    fake_db_manager, fake_ollama_manager, monkeypatch
):
    from cryptography.fernet import Fernet

    _set_key(monkeypatch, Fernet.generate_key().decode())
    fake_db_manager.get_ollama_connection_settings.return_value = _existing()

    result = await ConnectionService.save_connection(
        OllamaConnectionUpdate(mode="remote", remote_url="https://x", remote_api_key="plaintext-key")
    )

    saved_row = fake_db_manager.update_ollama_connection_settings.call_args.args[0]
    assert saved_row.remote_api_key_encrypted is not None
    assert saved_row.remote_api_key_encrypted != b"plaintext-key"
    assert result.has_remote_api_key is True


# --- save_connection: switching mode never clobbers remote_url/key ----------


async def test_switching_back_and_forth_between_local_and_remote_preserves_the_saved_remote_values(
    fake_db_manager, fake_ollama_manager, monkeypatch
):
    """The one test directly protecting the "switch without re-entering
    anything" requirement (Scope note point 3). Verified red->green:
    making a bare mode switch also overwrite remote_url with the request's
    (empty) value made this test fail, since the Remote values were then
    lost on the Local save - confirming the test actually distinguishes
    the two behaviors instead of trivially passing either way."""
    from cryptography.fernet import Fernet

    _set_key(monkeypatch, Fernet.generate_key().decode())
    connection = _existing()

    def fake_get():
        return connection

    def fake_update(row):
        nonlocal connection
        connection = row
        return row

    fake_db_manager.get_ollama_connection_settings.side_effect = fake_get
    fake_db_manager.update_ollama_connection_settings.side_effect = fake_update

    await ConnectionService.save_connection(
        OllamaConnectionUpdate(mode="remote", remote_url="https://remote.example", remote_api_key="secret-key")
    )

    await ConnectionService.save_connection(OllamaConnectionUpdate(mode="local", remote_url=""))

    assert connection.mode == "local"
    assert connection.remote_url == "https://remote.example"
    assert connection.remote_api_key_encrypted is not None

    result = await ConnectionService.save_connection(OllamaConnectionUpdate(mode="remote", remote_url=""))

    assert result.mode == "remote"
    assert result.remote_url == "https://remote.example"
    assert result.has_remote_api_key is True


# --- save_connection: Local mode's reconfigure stays untouched --------------


async def test_save_connection_to_local_does_not_override_ollama_managers_timeout(
    fake_db_manager, fake_ollama_manager
):
    """Regression test: save_connection's Local branch previously passed
    SAVED_CONNECTION_TIMEOUT_SECONDS (120s) to reconfigure even for Local,
    contradicting the spec's "Local mode is exactly today's behavior"
    requirement and diverging from O4's boot path, which leaves a fresh/
    Local row on OllamaManager's unmodified default. Verified red->green:
    reverting the fix (passing timeout=SAVED_CONNECTION_TIMEOUT_SECONDS
    again) makes this fail, since the call would then include a timeout
    kwarg."""
    fake_db_manager.get_ollama_connection_settings.return_value = _existing()

    await ConnectionService.save_connection(OllamaConnectionUpdate(mode="local", remote_url=""))

    fake_ollama_manager.reconfigure.assert_called_once_with(
        settings.ollama_url, headers=None
    )


# --- save_connection / test_connection: SSRF-closing URL validation (S1) ----
# A rejected URL must surface as ValueError (the router maps this to 400),
# never reach AsyncClient/the DB, and never block a plausible real use of
# this feature - a private-LAN remote Ollama host.


async def test_save_connection_rejects_a_file_scheme_url_before_touching_db(
    fake_db_manager, fake_ollama_manager
):
    fake_db_manager.get_ollama_connection_settings.return_value = _existing()

    with pytest.raises(ValueError):
        await ConnectionService.save_connection(
            OllamaConnectionUpdate(mode="remote", remote_url="file:///etc/passwd")
        )

    fake_db_manager.update_ollama_connection_settings.assert_not_called()


async def test_save_connection_rejects_a_link_local_metadata_url_before_touching_db(
    fake_db_manager, fake_ollama_manager
):
    fake_db_manager.get_ollama_connection_settings.return_value = _existing()

    with pytest.raises(ValueError):
        await ConnectionService.save_connection(
            OllamaConnectionUpdate(mode="remote", remote_url="http://169.254.169.254/")
        )

    fake_db_manager.update_ollama_connection_settings.assert_not_called()


async def test_save_connection_accepts_a_normal_https_url(fake_db_manager, fake_ollama_manager):
    fake_db_manager.get_ollama_connection_settings.return_value = _existing()

    result = await ConnectionService.save_connection(
        OllamaConnectionUpdate(mode="remote", remote_url="https://ollama.example.com")
    )

    assert result.remote_url == "https://ollama.example.com"
    fake_db_manager.update_ollama_connection_settings.assert_called_once()


async def test_save_connection_accepts_a_private_lan_url(fake_db_manager, fake_ollama_manager):
    """The actual use case this feature exists for - a remote Ollama host
    on the operator's own LAN - must not be blocked by the SSRF fix."""
    fake_db_manager.get_ollama_connection_settings.return_value = _existing()

    result = await ConnectionService.save_connection(
        OllamaConnectionUpdate(mode="remote", remote_url="http://192.168.1.50:11434")
    )

    assert result.remote_url == "http://192.168.1.50:11434"
    fake_db_manager.update_ollama_connection_settings.assert_called_once()


async def test_test_connection_rejects_a_file_scheme_url_without_ever_building_a_client(
    monkeypatch,
):
    client_factory = MagicMock()
    monkeypatch.setattr("src.services.connection_service.AsyncClient", client_factory)

    with pytest.raises(ValueError):
        await ConnectionService.test_connection("file:///etc/passwd", None)

    client_factory.assert_not_called()


async def test_test_connection_rejects_a_link_local_metadata_url_without_ever_building_a_client(
    monkeypatch,
):
    client_factory = MagicMock()
    monkeypatch.setattr("src.services.connection_service.AsyncClient", client_factory)

    with pytest.raises(ValueError):
        await ConnectionService.test_connection("http://169.254.169.254/", None)

    client_factory.assert_not_called()


async def test_test_connection_accepts_a_normal_https_url(monkeypatch):
    fake_client = MagicMock(list=AsyncMock(return_value=None))
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(
        "src.services.connection_service.AsyncClient", lambda *a, **k: fake_client
    )

    result = await ConnectionService.test_connection("https://ollama.example.com", None)

    assert result.reachable is True


async def test_test_connection_accepts_a_private_lan_url(monkeypatch):
    fake_client = MagicMock(list=AsyncMock(return_value=None))
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(
        "src.services.connection_service.AsyncClient", lambda *a, **k: fake_client
    )

    result = await ConnectionService.test_connection("http://192.168.1.50:11434", None)

    assert result.reachable is True


# --- test_connection: exception mapping --------------------------------------


class _FakeOllamaClient:
    def __init__(self, list_side_effect):
        self._list_side_effect = list_side_effect

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def list(self):
        raise self._list_side_effect


@pytest.mark.parametrize(
    ("side_effect", "expected_error"),
    [
        (ConnectionError("refused"), "connection refused or host unreachable"),
        (httpx.ConnectTimeout("timed out"), "timed out — endpoint may be cold/waking up"),
        (httpx.ReadTimeout("timed out"), "timed out — endpoint may be cold/waking up"),
        (ResponseError("nope", status_code=401), "authentication failed"),
        (ResponseError("nope", status_code=403), "authentication failed"),
        (ResponseError("teapot", status_code=418), None),  # falls back to str(e)
        (RuntimeError("something else entirely"), "something else entirely"),
    ],
)
async def test_test_connection_maps_each_exception_to_its_own_distinct_error_string(
    monkeypatch, side_effect, expected_error
):
    """Verified red->green: collapsing the mapping to a single `except
    Exception: return error=str(e)` branch (removing the dedicated
    ConnectionError/timeout/ResponseError-401/403 cases) made the first
    four parametrized cases above fail, since they'd then report str(e)
    (e.g. 'refused', 'timed out') instead of the distinct strings asserted
    here - confirming this test actually distinguishes the branches."""
    monkeypatch.setattr(
        "src.services.connection_service.AsyncClient",
        lambda *a, **k: _FakeOllamaClient(side_effect),
    )

    result = await ConnectionService.test_connection("https://x", None)

    assert result.reachable is False
    assert result.latency_ms is None
    if expected_error is not None:
        assert result.error == expected_error
    else:
        assert result.error == str(side_effect)


async def test_test_connection_closes_the_probe_client_after_use(monkeypatch):
    """Q2 (Milestone 3 code review): the one-off probe client must be used
    as an async context manager so it's closed after the probe, instead of
    relying on GC to ever clean up its connection pool."""

    class _TrackedClient:
        def __init__(self):
            self.entered = False
            self.exited = False

        async def __aenter__(self):
            self.entered = True
            return self

        async def __aexit__(self, *exc_info):
            self.exited = True
            return False

        async def list(self):
            return None

    client = _TrackedClient()
    monkeypatch.setattr(
        "src.services.connection_service.AsyncClient", lambda *a, **k: client
    )

    await ConnectionService.test_connection("https://x", None)

    assert client.entered is True
    assert client.exited is True


async def test_test_connection_returns_reachable_true_with_latency_on_success(monkeypatch):
    fake_client = MagicMock(list=AsyncMock(return_value=None))
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(
        "src.services.connection_service.AsyncClient", lambda *a, **k: fake_client
    )

    result = await ConnectionService.test_connection("https://x", None)

    assert result.reachable is True
    assert result.error is None
    assert result.latency_ms is not None and result.latency_ms >= 0
