"""ollama_manager.py - see docs/testing-crawler-reports/core-config-ollama-misc.md.
Uses the conftest fake_ollama_client fixture (patches the ollama_manager
singleton's .client attribute) so the real OllamaManager/capabilities_from_show_info
code runs unmodified against a scripted AsyncClient."""

import asyncio

import ollama
import pytest
import sqlalchemy

from src.core.config import Settings
from src.core.ollama_manager import capabilities_from_show_info, ollama_manager


def _settings(**overrides):
    defaults = dict(
        POSTGRES_USER="user",
        POSTGRES_PASSWORD="password",
        POSTGRES_DB="db",
        POSTGRES_HOST="localhost",
        OLLAMA_HOST="ollama",
        OLLAMA_PORT=11434,
    )
    defaults.update(overrides)
    return Settings(_env_file=None, **defaults)


# --- config.py: database_url credential encoding (Phase 4 item 2) --------
# Lives here rather than a dedicated test_config.py because the task's own
# layout/verification command only runs test_ollama_manager.py and
# test_ollama_service.py, and the crawler report that surfaced this bug
# (core-config-ollama-misc.md) covers config.py together with
# ollama_manager.py as one area.


def test_database_url_does_not_percent_encode_special_characters():
    """A Postgres password containing '@' is embedded into the connection
    string raw. sqlalchemy.create_engine (what DatabaseManager actually
    uses) parses the URL with its own make_url, which splits userinfo from
    host on the FIRST '@' - the embedded '@' in the password creates an
    extra, wrong split point. The result isn't an error, it's silent
    corruption: the password is truncated and the host gains the rest of
    the password as a prefix - a real connection would then fail to
    authenticate (or worse, resolve a wrong host) with no indication the
    original password was ever different."""
    settings = _settings(POSTGRES_PASSWORD="p@ssword")

    assert settings.database_url == "postgresql://user:p@ssword@localhost:5432/db"

    parsed = sqlalchemy.engine.make_url(settings.database_url)

    assert parsed.password != "p@ssword"
    assert parsed.host != "localhost"


def test_database_url_round_trips_a_plain_password():
    """Sanity check / contrast case: without a special character, the same
    construction DOES parse correctly - isolating the bug to the encoding
    gap, not to database_url's basic shape."""
    settings = _settings(POSTGRES_PASSWORD="plainpassword")

    url = sqlalchemy.engine.make_url(settings.database_url)

    assert url.username == "user"
    assert url.password == "plainpassword"
    assert url.host == "localhost"
    assert url.port == 5432
    assert url.database == "db"


# --- capabilities_from_show_info: context-window detection ---------------


def test_context_window_read_from_real_show_response():
    """Pins the .modelinfo/model_info alias contract: a real ollama.ShowResponse
    is constructed with the library's own alias kwarg (model_info=...), and the
    code must read it back via the real attribute name (.modelinfo), not the
    alias. If a future ollama version renames the attribute, this breaks."""
    show_info = ollama.ShowResponse(model_info={"llama.context_length": 32768})

    result = capabilities_from_show_info("llama3:8b", show_info)

    assert result["context_window"] == 32768


def test_context_window_falls_back_to_2048_when_key_missing():
    show_info = ollama.ShowResponse(model_info={"some.other_key": 99})

    result = capabilities_from_show_info("llama3:8b", show_info)

    assert result["context_window"] == 2048


def test_context_window_requires_exact_context_length_suffix():
    """A key that merely contains "context_length" without the leading dot
    (or as a prefix of a longer suffix) must not match - only an exact
    "*.context_length" suffix should."""
    show_info = ollama.ShowResponse(
        model_info={"llama.context_length_hint": 16384, "context_length": 8192}
    )

    result = capabilities_from_show_info("llama3:8b", show_info)

    assert result["context_window"] == 2048


def test_context_window_coerces_string_value_to_int():
    show_info = ollama.ShowResponse(model_info={"llama.context_length": "32768"})

    result = capabilities_from_show_info("llama3:8b", show_info)

    assert result["context_window"] == 32768
    assert isinstance(result["context_window"], int)


# --- capabilities_from_show_info: thinking detection ----------------------


def test_thinking_true_when_capability_present():
    show_info = ollama.ShowResponse(model_info={}, capabilities=["completion", "thinking"])

    result = capabilities_from_show_info("some-model", show_info)

    assert result["thinking"] is True


def test_thinking_false_when_capability_absent_and_name_has_no_hit():
    show_info = ollama.ShowResponse(model_info={}, capabilities=["completion"])

    result = capabilities_from_show_info("llama3:8b", show_info)

    assert result["thinking"] is False


def test_thinking_true_from_name_fallback_case_insensitive():
    show_info = ollama.ShowResponse(model_info={})

    result = capabilities_from_show_info("DeepSeek-R1-Distill", show_info)

    assert result["thinking"] is True


def test_thinking_handles_missing_capabilities_without_error():
    show_info = ollama.ShowResponse(model_info={}, capabilities=None)

    result = capabilities_from_show_info("llama3:8b", show_info)

    assert result["thinking"] is False


# --- OllamaManager.list_models / show / delete_model: error wrapping -----


@pytest.mark.asyncio
async def test_list_models_wraps_client_exception_in_runtime_error(
    fake_ollama_client,
):
    fake_ollama_client.list.side_effect = ConnectionError("ollama is down")

    with pytest.raises(RuntimeError, match="ollama is down"):
        await ollama_manager.list_models()


@pytest.mark.asyncio
async def test_list_models_does_not_swallow_cancelled_error(fake_ollama_client):
    """asyncio.CancelledError is a BaseException, not an Exception - the
    bare `except Exception` in list_models must let it propagate unwrapped."""
    fake_ollama_client.list.side_effect = asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await ollama_manager.list_models()


@pytest.mark.asyncio
async def test_delete_model_names_the_model_in_the_error(fake_ollama_client):
    fake_ollama_client.delete.side_effect = Exception("boom")

    with pytest.raises(RuntimeError, match="llama3:8b"):
        await ollama_manager.delete_model("llama3:8b")


@pytest.mark.asyncio
async def test_show_wraps_client_exception_in_runtime_error(fake_ollama_client):
    fake_ollama_client.show.side_effect = Exception("not found")

    with pytest.raises(RuntimeError, match="llama3:8b"):
        await ollama_manager.show("llama3:8b")


@pytest.mark.asyncio
async def test_get_model_capabilities_delegates_to_pure_function(fake_ollama_client):
    fake_ollama_client.show.return_value = ollama.ShowResponse(
        model_info={"llama.context_length": 4096}, capabilities=["thinking"]
    )

    result = await ollama_manager.get_model_capabilities("llama3:8b")

    fake_ollama_client.show.assert_awaited_once_with("llama3:8b")
    assert result == {"thinking": True, "context_window": 4096}


# --- OllamaManager.pull_model: async generator ----------------------------


async def _fake_progress_stream(items):
    for item in items:
        yield item


@pytest.mark.asyncio
async def test_pull_model_yields_progress_with_model_name_set(fake_ollama_client):
    fake_ollama_client.pull.return_value = _fake_progress_stream(
        [ollama.ProgressResponse(status="downloading", completed=10, total=100)]
    )

    results = [item async for item in ollama_manager.pull_model("llama3:8b")]

    assert len(results) == 1
    assert results[0].model == "llama3:8b"
    assert results[0].status == "downloading"
    assert results[0].completed == 10
    assert results[0].total == 100


@pytest.mark.asyncio
async def test_pull_model_status_none_becomes_empty_string(fake_ollama_client):
    fake_ollama_client.pull.return_value = _fake_progress_stream(
        [ollama.ProgressResponse(status=None, completed=None, total=None)]
    )

    results = [item async for item in ollama_manager.pull_model("llama3:8b")]

    assert results[0].status == ""


@pytest.mark.asyncio
async def test_pull_model_mid_stream_failure_still_yields_earlier_items_then_raises(
    fake_ollama_client,
):
    async def failing_stream():
        yield ollama.ProgressResponse(status="downloading", completed=1, total=100)
        yield ollama.ProgressResponse(status="downloading", completed=2, total=100)
        raise ConnectionError("connection dropped")

    fake_ollama_client.pull.return_value = failing_stream()

    collected = []
    with pytest.raises(RuntimeError, match="llama3:8b"):
        async for item in ollama_manager.pull_model("llama3:8b"):
            collected.append(item)

    assert len(collected) == 2
    assert [c.completed for c in collected] == [1, 2]
