"""B1 regression tests: agent_tools/category/common.py's _parse_output and
_verify_claim_against_evidence, and agent_tools/category/terminal_tools.py's
_suggest_command_fix, each build their own parsing/verification ChatOllama
client with base_url=settings.ollama_url and no headers, completely
ignoring a configured Remote connection's ollama_manager.base_url/.headers -
unlike agent.py's Agent, which already reads ollama_manager for its main
model (see test_agent_core.py's own TestOllamaConnectionWiring, the pattern
mirrored here). A Local connection (ollama_manager.headers == {}) must
build ChatOllama with no client_kwargs at all, byte-for-byte identical to
before this existed."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from src.core.agent import agent_tools
from src.core.agent.agent_tools.category import common, terminal_tools


def _patch_project_settings(monkeypatch, parsing_model_name):
    # _parse_output/_verify_claim_against_evidence/_suggest_command_fix all
    # resolve this through _package()._get_project_settings(project_id),
    # which re-reads the `agent_tools` package module's own attribute at
    # call time - see common.py's _package docstring for why this is the
    # patchable seam, not db_manager directly.
    monkeypatch.setattr(
        agent_tools,
        "_get_project_settings",
        AsyncMock(
            return_value=SimpleNamespace(
                parsing_model_name=parsing_model_name, max_context_window=None
            )
        ),
    )


def _fake_ollama_manager(base_url, headers):
    manager = MagicMock()
    manager.base_url = base_url
    manager.headers = headers
    manager.get_model_capabilities = AsyncMock(return_value={"context_window": 4096})
    return manager


def _patch_chat_ollama(monkeypatch, module, structured_result):
    fake_structured = MagicMock()
    fake_structured.ainvoke = AsyncMock(return_value=structured_result)
    fake_llm = MagicMock()
    fake_llm.with_structured_output.return_value = fake_structured
    chat_ollama_mock = MagicMock(return_value=fake_llm)
    monkeypatch.setattr(module, "ChatOllama", chat_ollama_mock)
    return chat_ollama_mock


class TestParseOutputOllamaWiring:
    async def test_omits_client_kwargs_when_headers_empty(self, monkeypatch):
        _patch_project_settings(monkeypatch, f"parser-{uuid.uuid4()}")
        monkeypatch.setattr(
            common, "ollama_manager", _fake_ollama_manager("http://localhost:11434", {})
        )
        chat_ollama_mock = _patch_chat_ollama(
            monkeypatch, common, common._ParsedCommandOutput(summary="parsed", facts=[])
        )

        await common._parse_output("proj1", "echo hi", "raw output", lambda entries: None)

        assert "client_kwargs" not in chat_ollama_mock.call_args.kwargs
        assert chat_ollama_mock.call_args.kwargs["base_url"] == "http://localhost:11434"

    async def test_passes_headers_through_client_kwargs_when_present(self, monkeypatch):
        _patch_project_settings(monkeypatch, f"parser-{uuid.uuid4()}")
        monkeypatch.setattr(
            common,
            "ollama_manager",
            _fake_ollama_manager(
                "http://remote-host:11434", {"Authorization": "Bearer abc"}
            ),
        )
        chat_ollama_mock = _patch_chat_ollama(
            monkeypatch, common, common._ParsedCommandOutput(summary="parsed", facts=[])
        )

        await common._parse_output("proj1", "echo hi", "raw output", lambda entries: None)

        assert chat_ollama_mock.call_args.kwargs["client_kwargs"] == {
            "headers": {"Authorization": "Bearer abc"}
        }
        assert chat_ollama_mock.call_args.kwargs["base_url"] == "http://remote-host:11434"


class TestVerifyClaimAgainstEvidenceOllamaWiring:
    async def test_omits_client_kwargs_when_headers_empty(self, monkeypatch):
        _patch_project_settings(monkeypatch, f"parser-{uuid.uuid4()}")
        monkeypatch.setattr(
            common, "ollama_manager", _fake_ollama_manager("http://localhost:11434", {})
        )
        chat_ollama_mock = _patch_chat_ollama(
            monkeypatch, common, common._ClaimVerification(supported=True, reason="ok")
        )

        await common._verify_claim_against_evidence(
            "proj1", "finding", "claim text", "some raw evidence"
        )

        assert "client_kwargs" not in chat_ollama_mock.call_args.kwargs
        assert chat_ollama_mock.call_args.kwargs["base_url"] == "http://localhost:11434"

    async def test_passes_headers_through_client_kwargs_when_present(self, monkeypatch):
        _patch_project_settings(monkeypatch, f"parser-{uuid.uuid4()}")
        monkeypatch.setattr(
            common,
            "ollama_manager",
            _fake_ollama_manager(
                "http://remote-host:11434", {"Authorization": "Bearer abc"}
            ),
        )
        chat_ollama_mock = _patch_chat_ollama(
            monkeypatch, common, common._ClaimVerification(supported=True, reason="ok")
        )

        await common._verify_claim_against_evidence(
            "proj1", "finding", "claim text", "some raw evidence"
        )

        assert chat_ollama_mock.call_args.kwargs["client_kwargs"] == {
            "headers": {"Authorization": "Bearer abc"}
        }
        assert chat_ollama_mock.call_args.kwargs["base_url"] == "http://remote-host:11434"


class TestSuggestCommandFixOllamaWiring:
    def _patch_ollama_manager(self, monkeypatch, base_url, headers):
        # _get_parsing_model_num_ctx AND the shared _parsing_chat_ollama_kwargs
        # (both defined in common.py, imported into terminal_tools.py) read
        # `ollama_manager` through common.py's own module global - patching
        # it there is enough even though _suggest_command_fix itself lives
        # in terminal_tools.py.
        manager = _fake_ollama_manager(base_url, headers)
        monkeypatch.setattr(common, "ollama_manager", manager)
        return manager

    async def test_omits_client_kwargs_when_headers_empty(self, monkeypatch):
        _patch_project_settings(monkeypatch, f"parser-{uuid.uuid4()}")
        self._patch_ollama_manager(monkeypatch, "http://localhost:11434", {})
        chat_ollama_mock = _patch_chat_ollama(
            monkeypatch,
            terminal_tools,
            terminal_tools._UsageSuggestion(corrected_command="fixed", explanation=""),
        )

        await terminal_tools._suggest_command_fix(
            "proj1", "some command", "some output", "some reference"
        )

        assert "client_kwargs" not in chat_ollama_mock.call_args.kwargs
        assert chat_ollama_mock.call_args.kwargs["base_url"] == "http://localhost:11434"

    async def test_passes_headers_through_client_kwargs_when_present(self, monkeypatch):
        _patch_project_settings(monkeypatch, f"parser-{uuid.uuid4()}")
        self._patch_ollama_manager(
            monkeypatch, "http://remote-host:11434", {"Authorization": "Bearer abc"}
        )
        chat_ollama_mock = _patch_chat_ollama(
            monkeypatch,
            terminal_tools,
            terminal_tools._UsageSuggestion(corrected_command="fixed", explanation=""),
        )

        await terminal_tools._suggest_command_fix(
            "proj1", "some command", "some output", "some reference"
        )

        assert chat_ollama_mock.call_args.kwargs["client_kwargs"] == {
            "headers": {"Authorization": "Bearer abc"}
        }
        assert chat_ollama_mock.call_args.kwargs["base_url"] == "http://remote-host:11434"
