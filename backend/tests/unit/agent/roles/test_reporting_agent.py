"""roles/agents/reporting_agent.py. _render_transcript is a pure function
and the highest-value target here (reporting's only real input is this
rendering of a pentesting run's log rows) - see crawler finding #6 (tail-
drop on truncation, confirmed below)."""

import uuid
from unittest.mock import MagicMock

from src.core.agent.roles.agents import reporting_agent as reporting_mod


def _log(type_="tool", content="did a thing", tool_name="run", raw_output=None):
    return MagicMock(type=type_, content=content, tool_name=tool_name, raw_output=raw_output)


# --- _render_transcript ---


def test_render_transcript_empty_logs():
    assert reporting_mod._render_transcript([]) == "(no log entries found for this run)"


def test_render_transcript_only_thinking_entries_renders_as_empty():
    logs = [_log(type_="thinking", content="pondering...")]
    assert reporting_mod._render_transcript(logs) == "(no log entries found for this run)"


def test_render_transcript_skips_thinking_but_keeps_others():
    logs = [
        _log(type_="thinking", content="pondering..."),
        _log(type_="tool", content="ran nmap", tool_name="nmap_scan"),
    ]
    transcript = reporting_mod._render_transcript(logs)
    assert "pondering" not in transcript
    assert "[TOOL CALL: nmap_scan] ran nmap" in transcript


def test_render_transcript_log_with_no_tool_name_omits_name_suffix():
    logs = [_log(type_="tool", content="did something", tool_name=None)]
    transcript = reporting_mod._render_transcript(logs)
    assert transcript == "[TOOL CALL] did something"


def test_render_transcript_unknown_type_falls_to_result():
    logs = [_log(type_="weird", content="??", tool_name=None)]
    transcript = reporting_mod._render_transcript(logs)
    assert transcript.startswith("[RESULT]")


def test_render_transcript_entry_raw_output_exactly_at_cap_not_truncated():
    raw = "x" * reporting_mod._TRANSCRIPT_ENTRY_RAW_OUTPUT_CAP
    logs = [_log(raw_output=raw)]
    transcript = reporting_mod._render_transcript(logs)
    assert "[...truncated here...]" not in transcript
    assert raw in transcript


def test_render_transcript_entry_raw_output_over_cap_is_truncated():
    raw = "x" * (reporting_mod._TRANSCRIPT_ENTRY_RAW_OUTPUT_CAP + 1)
    logs = [_log(raw_output=raw)]
    transcript = reporting_mod._render_transcript(logs)
    assert "[...truncated here...]" in transcript
    kept = transcript.split("Real output:\n")[1].split("\n[...truncated here...]")[0]
    assert len(kept) == reporting_mod._TRANSCRIPT_ENTRY_RAW_OUTPUT_CAP


def test_render_transcript_total_exactly_at_cap_not_truncated(monkeypatch):
    # Force a transcript whose total length lands exactly on
    # _TRANSCRIPT_TOTAL_CAP by controlling a single log's content length
    # directly (content isn't capped per-entry, only raw_output is).
    cap = reporting_mod._TRANSCRIPT_TOTAL_CAP
    header = "[TOOL CALL: run] "
    content = "x" * (cap - len(header))
    logs = [_log(type_="tool", content=content, tool_name="run")]
    transcript = reporting_mod._render_transcript(logs)
    assert len(transcript) == cap
    assert "omitted" not in transcript


def test_render_transcript_total_over_cap_is_truncated_with_exact_omitted_count():
    cap = reporting_mod._TRANSCRIPT_TOTAL_CAP
    header = "[TOOL CALL: run] "
    content = "x" * (cap - len(header) + 1)
    logs = [_log(type_="tool", content=content, tool_name="run")]
    full_len = len(header) + len(content)
    transcript = reporting_mod._render_transcript(logs)

    omitted = full_len - cap
    assert f"[...{omitted} characters of this transcript omitted here" in transcript
    assert len(transcript) > cap  # the omission notice itself adds length back


def test_render_transcript_tail_is_dropped_on_truncation():
    # Crawler finding #6: _render_transcript truncates at
    # _TRANSCRIPT_TOTAL_CAP with no tail preservation - the final,
    # usually most important, log entry (e.g. the successful proof) is
    # the most likely to be cut. Pinning the CURRENT (defective)
    # behavior: a final, distinctive marker placed after the cap is lost.
    cap = reporting_mod._TRANSCRIPT_TOTAL_CAP
    filler = _log(type_="tool", content="x" * (cap + 500), tool_name="run")
    final_proof = _log(type_="tool", content="FINAL_PROOF_MARKER", tool_name="run")
    transcript = reporting_mod._render_transcript([filler, final_proof])
    assert "FINAL_PROOF_MARKER" not in transcript


# --- ReportingAgent's always-open gate / constant finish behavior ---


def _make_agent(monkeypatch, logs=None):
    fake_llm = MagicMock()
    fake_llm.bind_tools.return_value = MagicMock()
    monkeypatch.setattr(reporting_mod, "ChatOllama", MagicMock(return_value=fake_llm))

    from langgraph.checkpoint.memory import MemorySaver

    agent = reporting_mod.ReportingAgent(
        model_name="test-model",
        checkpointer=MemorySaver(),
        project_id=str(uuid.uuid4()),
        target_id=str(uuid.uuid4()),
        agent_run_id=str(uuid.uuid4()),
        attack_vector_id=str(uuid.uuid4()),
        pentesting_logs=logs or [],
    )
    return agent


def test_has_tested_is_always_true(monkeypatch):
    agent = _make_agent(monkeypatch)
    assert agent._has_tested() is True


def test_requires_interrupt_is_always_false(monkeypatch):
    agent = _make_agent(monkeypatch)
    assert agent._get_mode() == "exploiting"


def test_on_reported_sets_finish_summary_with_cvss_score(monkeypatch):
    agent = _make_agent(monkeypatch)
    vulnerability = MagicMock(name="SQLi", cvss4_score=8.7)
    vulnerability.name = "SQLi"
    agent._on_reported(vulnerability)
    assert agent.created_vulnerability is vulnerability
    assert "SQLi" in agent.finish_summary
    assert "8.7" in agent.finish_summary


def test_empty_logs_produce_the_no_entries_placeholder_in_transcript_text(monkeypatch):
    agent = _make_agent(monkeypatch, logs=[])
    assert agent.transcript_text == "(no log entries found for this run)"
