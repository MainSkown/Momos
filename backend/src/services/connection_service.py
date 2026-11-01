"""Reads and updates the singleton Ollama connection row, and runs the
unsaved "Test Connection" dry run against an arbitrary URL/key. See
docs/plans/milestone-3-remote-ollama-connection.md's O2 section for the
None/""/non-empty remote_api_key semantics and the atomic switch-guard
this module's save_connection relies on (run_registry.run_exclusively_if_idle)."""

import ipaddress
import time
from typing import Optional
from urllib.parse import urlparse

import httpx
from ollama import AsyncClient, ResponseError

from src.core import db_manager, encryption_service, ollama_manager, settings
from src.core.agent.run_registry import run_exclusively_if_idle
from src.schemas.ollama_connection_scheme import (
    OllamaConnectionPublic,
    OllamaConnectionSettings,
    OllamaConnectionTestResult,
    OllamaConnectionUpdate,
)

TEST_CONNECTION_TIMEOUT_SECONDS = 15.0
SAVED_CONNECTION_TIMEOUT_SECONDS = 120.0


def _validate_remote_url(url: str) -> None:
    """Closes the SSRF vector where any caller could make this backend's
    process originate an outbound request to an arbitrary host via
    remote_url (S1 of the Milestone 3 code review). Deliberately narrow:
    this is a single-operator local pentesting tool whose remote-Ollama
    feature genuinely needs to reach private LAN hosts (192.168.x.x,
    10.x.x.x), so only the scheme and the link-local range (169.254.0.0/16,
    which covers the common cloud metadata endpoint 169.254.169.254) are
    rejected. DNS-rebinding protection (resolving hostnames to check their
    IPs) is a deliberately out-of-scope, larger fix."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"remote_url must use the http or https scheme, got '{parsed.scheme}'."
        )

    hostname = parsed.hostname
    if hostname:
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            address = None
        if address is not None and address.is_link_local:
            raise ValueError("remote_url may not target a link-local address.")


def _to_public(connection: OllamaConnectionSettings) -> OllamaConnectionPublic:
    return OllamaConnectionPublic(
        mode=connection.mode,
        remote_url=connection.remote_url,
        has_remote_api_key=connection.remote_api_key_encrypted is not None,
    )


class ConnectionService:
    @staticmethod
    def get_connection() -> OllamaConnectionPublic:
        return _to_public(db_manager.get_ollama_connection_settings())

    @staticmethod
    async def save_connection(update: OllamaConnectionUpdate) -> OllamaConnectionPublic:
        existing = db_manager.get_ollama_connection_settings()

        # Empty/omitted remote_url means "don't touch it" so a bare mode
        # flip never loses a previously-saved URL (Scope note point 3) -
        # the dashboard only ever sends a non-empty value when the user
        # actually edited the field.
        merged_remote_url = update.remote_url or existing.remote_url

        if merged_remote_url:
            _validate_remote_url(merged_remote_url)

        if update.mode == "remote" and not merged_remote_url:
            raise ValueError("remote_url is required when mode is 'remote'.")

        if update.remote_api_key is None:
            merged_key_encrypted = existing.remote_api_key_encrypted
        elif update.remote_api_key == "":
            merged_key_encrypted = None
        else:
            # Propagates EncryptionKeyMissingException before anything is
            # written - the save-time half of the spec's fail-fast
            # requirement.
            merged_key_encrypted = encryption_service.encrypt_secret(update.remote_api_key)

        existing.mode = update.mode
        existing.remote_url = merged_remote_url
        existing.remote_api_key_encrypted = merged_key_encrypted

        async def _save_and_reconfigure() -> OllamaConnectionSettings:
            saved = db_manager.update_ollama_connection_settings(existing)
            if saved.mode == "remote":
                key = (
                    encryption_service.decrypt_secret(saved.remote_api_key_encrypted)
                    if saved.remote_api_key_encrypted
                    else None
                )
                headers = {"Authorization": f"Bearer {key}"} if key else None
                await ollama_manager.reconfigure(
                    saved.remote_url, headers=headers, timeout=SAVED_CONNECTION_TIMEOUT_SECONDS
                )
            else:
                # No timeout override here - Local must stay byte-for-byte
                # today's behavior (spec's Behavior details), same as the
                # O4 boot path leaving a fresh/Local row on OllamaManager's
                # unmodified constructor default. Only a saved Remote
                # connection gets the longer SAVED_CONNECTION_TIMEOUT_SECONDS.
                await ollama_manager.reconfigure(settings.ollama_url, headers=None)
            return saved

        saved = await run_exclusively_if_idle(_save_and_reconfigure)
        return _to_public(saved)

    @staticmethod
    async def test_connection(url: str, api_key: Optional[str]) -> OllamaConnectionTestResult:
        _validate_remote_url(url)
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        started_at = time.monotonic()

        async with AsyncClient(
            url, headers=headers, timeout=TEST_CONNECTION_TIMEOUT_SECONDS
        ) as client:
            try:
                await client.list()
            except ConnectionError:
                # ollama.AsyncClient's own _request_raw already catches
                # httpx.ConnectError and re-raises it as this builtin type -
                # catching httpx.ConnectError here would never match.
                return OllamaConnectionTestResult(
                    reachable=False, error="connection refused or host unreachable"
                )
            except (httpx.ConnectTimeout, httpx.ReadTimeout):
                # Genuinely uncaught inside ollama's client, so these
                # propagate raw - must come before the generic Exception
                # fallback below.
                return OllamaConnectionTestResult(
                    reachable=False, error="timed out — endpoint may be cold/waking up"
                )
            except ResponseError as e:
                error = "authentication failed" if e.status_code in (401, 403) else str(e)
                return OllamaConnectionTestResult(reachable=False, error=error)
            except Exception as e:
                return OllamaConnectionTestResult(reachable=False, error=str(e))

        latency_ms = (time.monotonic() - started_at) * 1000
        return OllamaConnectionTestResult(reachable=True, latency_ms=latency_ms)
