"""encryption_service.py - see Milestone 3 plan Part E (docs/plans/
milestone-3-remote-ollama-connection.md). Tests monkeypatch the live
`settings` singleton's APP_ENCRYPTION_KEY and the resolved env-file path
(via Settings.model_config["env_file"]) so nothing here ever touches the
real backend/.env."""

import stat
from pathlib import Path

import pytest

from src.core import encryption_service
from src.core.config import Settings, settings
from src.utils.exceptions import EncryptionKeyMissingException


@pytest.fixture(autouse=True)
def _reset_encryption_key(monkeypatch):
    """Every test gets a known APP_ENCRYPTION_KEY starting point instead of
    whatever the real .env (if any) left on the process-wide settings
    singleton."""
    monkeypatch.setattr(settings, "APP_ENCRYPTION_KEY", None)


def _set_key(monkeypatch, key: str | None):
    monkeypatch.setattr(settings, "APP_ENCRYPTION_KEY", key)


# --- encrypt_secret / decrypt_secret --------------------------------------


def test_encrypt_then_decrypt_round_trips_the_original_string(monkeypatch):
    _set_key(monkeypatch, encryption_service.Fernet.generate_key().decode())

    ciphertext = encryption_service.encrypt_secret("super-secret-api-key")

    assert encryption_service.decrypt_secret(ciphertext) == "super-secret-api-key"


def test_encrypt_secret_raises_when_key_unset():
    with pytest.raises(EncryptionKeyMissingException):
        encryption_service.encrypt_secret("whatever")


def test_decrypt_secret_raises_when_key_unset():
    with pytest.raises(EncryptionKeyMissingException):
        encryption_service.decrypt_secret(b"whatever")


def test_encrypt_secret_is_not_deterministic(monkeypatch):
    """Fernet includes a random nonce/IV per call - two ciphertexts of the
    same plaintext must differ, otherwise an attacker (or another operator
    reading the DB) could tell two stored secrets are identical without
    ever decrypting either."""
    _set_key(monkeypatch, encryption_service.Fernet.generate_key().decode())

    first = encryption_service.encrypt_secret("same-plaintext")
    second = encryption_service.encrypt_secret("same-plaintext")

    assert first != second


# --- encryption_key_configured --------------------------------------------


def test_encryption_key_configured_false_when_unset():
    assert encryption_service.encryption_key_configured() is False


def test_encryption_key_configured_true_when_set(monkeypatch):
    _set_key(monkeypatch, "some-key")

    assert encryption_service.encryption_key_configured() is True


# --- ensure_encryption_key_provisioned ------------------------------------


def test_provisions_a_new_key_into_an_empty_env_file(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    monkeypatch.setitem(Settings.model_config, "env_file", str(env_file))

    encryption_service.ensure_encryption_key_provisioned()

    lines = env_file.read_text().splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("APP_ENCRYPTION_KEY=")
    assert settings.APP_ENCRYPTION_KEY == lines[0].removeprefix("APP_ENCRYPTION_KEY=")


def test_provisioned_env_file_is_not_world_or_group_readable(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    monkeypatch.setitem(Settings.model_config, "env_file", str(env_file))

    encryption_service.ensure_encryption_key_provisioned()

    mode = stat.S_IMODE(env_file.stat().st_mode)
    assert mode == 0o600


def test_provisioning_twice_is_idempotent_and_never_adds_a_second_line(
    tmp_path, monkeypatch
):
    env_file = tmp_path / ".env"
    monkeypatch.setitem(Settings.model_config, "env_file", str(env_file))

    encryption_service.ensure_encryption_key_provisioned()
    first_contents = env_file.read_text()

    encryption_service.ensure_encryption_key_provisioned()

    assert env_file.read_text() == first_contents
    assert len(first_contents.splitlines()) == 1


def test_never_overwrites_an_operators_preexisting_key_line(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("APP_ENCRYPTION_KEY=operator-managed-key\n")
    original_bytes = env_file.read_bytes()
    monkeypatch.setitem(Settings.model_config, "env_file", str(env_file))
    # settings.APP_ENCRYPTION_KEY is unset (autouse fixture) even though the
    # file already has a line - simulates an operator-managed key arriving
    # some other way than the live process's own env var at this instant.

    encryption_service.ensure_encryption_key_provisioned()

    assert env_file.read_bytes() == original_bytes


def test_does_nothing_when_settings_already_has_a_key(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    monkeypatch.setitem(Settings.model_config, "env_file", str(env_file))
    _set_key(monkeypatch, "already-set-key")

    encryption_service.ensure_encryption_key_provisioned()

    assert not env_file.exists()
    assert settings.APP_ENCRYPTION_KEY == "already-set-key"
