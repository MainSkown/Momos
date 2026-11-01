"""Encryption at rest for secrets stored in the database - today, a saved
remote Ollama connection's API key (connection_service.py); Milestone 4's
Foothold.password_encrypted is planned to reuse this same key/service, so
it lives here as its own importable module rather than inlined into a
single caller."""

import os
from pathlib import Path

from cryptography.fernet import Fernet

from src.utils.exceptions import EncryptionKeyMissingException

from . import settings
from .config import Settings


def encryption_key_configured() -> bool:
    return bool(settings.APP_ENCRYPTION_KEY)


def _fernet() -> Fernet:
    if not settings.APP_ENCRYPTION_KEY:
        raise EncryptionKeyMissingException(
            "APP_ENCRYPTION_KEY is not set - cannot encrypt or decrypt secrets."
        )
    return Fernet(settings.APP_ENCRYPTION_KEY.encode())


def encrypt_secret(plaintext: str) -> bytes:
    return _fernet().encrypt(plaintext.encode())


def decrypt_secret(ciphertext: bytes) -> str:
    return _fernet().decrypt(ciphertext).decode()


def _env_file_has_uncommented_key_line(env_text: str) -> bool:
    return any(
        line.strip().startswith("APP_ENCRYPTION_KEY=")
        for line in env_text.splitlines()
    )


def ensure_encryption_key_provisioned() -> None:
    """Self-provisions APP_ENCRYPTION_KEY on first boot so Remote can be
    turned on from the Connection tab with zero .env editing, instead of
    the operator having to generate and add one by hand.

    Safety invariants this relies on:
    - Idempotent: a no-op whenever a key is already set, from a real env
      var or an existing .env line.
    - Never clobbers an operator-managed key: if the env file already has
      an APP_ENCRYPTION_KEY= line (even with settings.APP_ENCRYPTION_KEY
      unset for some other reason), this returns without writing anything.
    - Never leaves the key in-memory-only: a write failure propagates
      rather than being swallowed, since an in-memory-only key would be
      lost on restart, silently bricking anything already encrypted under
      it.
    """
    if settings.APP_ENCRYPTION_KEY:
        return

    env_file = Path(Settings.model_config["env_file"])
    current_text = env_file.read_text() if env_file.exists() else ""

    if _env_file_has_uncommented_key_line(current_text):
        return

    key = Fernet.generate_key().decode()
    env_file.write_text(current_text + f"APP_ENCRYPTION_KEY={key}\n")
    os.chmod(env_file, 0o600)
    settings.APP_ENCRYPTION_KEY = key
