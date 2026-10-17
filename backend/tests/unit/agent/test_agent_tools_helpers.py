"""Pure-function unit tests for backend/src/core/agent/agent_tools.py.

Scope: only the pure helpers (no Docker, no LLM, no fixtures) - see
docs/testing-plan.md §1.4's "Agent / orchestration layer" bullet and
docs/testing-crawler-reports/agent-tools.md (18 numbered findings). The
tool-factory functions (create_kali_tool, create_pentest_tools, ...) are
out of scope here.
"""

import subprocess

import pytest

from src.core.agent.agent_tools import (
    PACKAGE_NAME_PATTERN,
    RAW_OUTPUT_MAX_CHARS,
    _RAW_OUTPUT_HEAD_CHARS,
    _RAW_OUTPUT_TAIL_CHARS,
    _SAFE_EDB_ID_PATTERN,
    _SAFE_EXTENSIONS_PATTERN,
    _SAFE_FILENAME_PATTERN,
    _SAFE_PATH_PATTERN,
    _SAFE_PORT_SPEC_PATTERN,
    _cap_raw_output,
    _clean_man_output,
    _expand_port_spec,
    _extract_binary_name,
    _find_binary_token,
    _ftp_active_mode_fallback,
    _ftp_data_connection_stalled,
    _is_network_facing,
    _looks_like_open_prompt,
    _maybe_inject_nmap_pn,
    _parse_nmap_output,
    _render_activation_no_output_note,
    _safe_join_args,
    _safe_shell_word,
    _summarize_nmap_entries,
)


def _run_in_shell(shell_fragment: str) -> str:
    return subprocess.run(
        ["sh", "-c", shell_fragment], capture_output=True, text=True
    ).stdout


# ---------------------------------------------------------------------------
# _safe_shell_word / _safe_join_args - the highest-value target in the file.
# ---------------------------------------------------------------------------


class TestSafeShellWord:
    @pytest.mark.parametrize(
        "value",
        [
            "simple",
            "a'b",
            'a"b',
            "a`id`b",
            "$(id)",
            "a; rm -rf /",
            "a && echo injected",
            "a | cat",
            "line1\nline2",
            "",
            "   leading and trailing spaces   ",
        ],
    )
    def test_round_trips_exactly_through_a_real_shell(self, value):
        quoted = _safe_shell_word(value)
        output = _run_in_shell(f"printf %s {quoted}")
        assert output == value

    def test_command_substitution_payload_does_not_execute(self, tmp_path):
        marker = tmp_path / "INJECTED"
        payload = f"$(touch {marker})"
        quoted = _safe_shell_word(payload)
        output = _run_in_shell(f"printf %s {quoted}")
        assert output == payload
        assert not marker.exists()

    def test_semicolon_payload_does_not_execute_a_second_command(self, tmp_path):
        marker = tmp_path / "INJECTED"
        payload = f"192.168.0.235 21; touch {marker}"
        quoted = _safe_shell_word(payload)
        _run_in_shell(f"echo {quoted}")
        assert not marker.exists()

    def test_backtick_payload_does_not_execute(self, tmp_path):
        marker = tmp_path / "INJECTED"
        payload = f"`touch {marker}`"
        quoted = _safe_shell_word(payload)
        _run_in_shell(f"echo {quoted}")
        assert not marker.exists()


class TestSafeJoinArgs:
    def test_unbalanced_single_quote_is_rejected(self):
        assert _safe_join_args("a 'b") is None

    def test_unbalanced_double_quote_is_rejected(self):
        assert _safe_join_args('a "b') is None

    def test_multi_word_payload_splits_into_literal_argv_words(self, tmp_path):
        # Each whitespace-separated word of the ORIGINAL string becomes its
        # own argv word downstream, including "rm"/"-rf" - a would-be second
        # command never gets a chance to run as shell syntax.
        marker = tmp_path / "INJECTED"
        joined = _safe_join_args(f"192.168.0.235 21; rm -rf {marker}")
        assert joined is not None
        _run_in_shell(f"echo {joined}")
        assert not marker.exists()

    def test_command_substitution_payload_is_quoted_to_a_literal(self):
        joined = _safe_join_args("$(id)")
        output = _run_in_shell(f"echo {joined}")
        assert output == "$(id)\n"

    def test_argv_word_count_matches_original_whitespace_tokenization(self):
        joined = _safe_join_args("a && echo injected")
        # set -- feeds the joined string to a fresh shell's positional
        # params, so this proves the exact word boundaries downstream code
        # will see, not just that "it looks escaped".
        script = f'set -- {joined}; printf "<%s>" "$@"'
        output = _run_in_shell(script)
        assert output == "<a><&&><echo><injected>"

    def test_newline_is_treated_as_a_word_separator_like_shlex_split(self):
        # Documents actual behavior: shlex treats \n like whitespace, so a
        # newline-separated pair collapses into two space-joined argv words
        # rather than being rejected or preserved as one literal value.
        assert _safe_join_args("line1\nline2") == "line1 line2"


# ---------------------------------------------------------------------------
# Finding 1 (agent-tools.md): every ^...$ validator is bypassed by a
# trailing newline, because Python's $ matches before a final \n.
# ---------------------------------------------------------------------------


class TestTrailingNewlineValidatorBypass:
    def test_package_name_pattern_accepts_a_trailing_newline(self):
        assert PACKAGE_NAME_PATTERN.match("hydra\n") is not None

    def test_package_name_pattern_rejects_the_same_value_without_newline_variants(self):
        # Sanity anchor: the pattern isn't simply broken outright - it
        # correctly rejects these. Only the trailing-\n case leaks through.
        assert PACKAGE_NAME_PATTERN.match("hydra;id") is None
        assert PACKAGE_NAME_PATTERN.match("-y hydra") is None
        assert PACKAGE_NAME_PATTERN.match("../x") is None
        assert PACKAGE_NAME_PATTERN.match("Hydra") is None
        assert PACKAGE_NAME_PATTERN.match("hydra") is not None

    def test_safe_port_spec_pattern_accepts_a_trailing_newline(self):
        assert _SAFE_PORT_SPEC_PATTERN.match("21\n") is not None

    def test_safe_path_pattern_accepts_a_trailing_newline(self):
        assert _SAFE_PATH_PATTERN.match("/tmp/momos-files/x\n") is not None

    def test_safe_extensions_pattern_accepts_a_trailing_newline(self):
        assert _SAFE_EXTENSIONS_PATTERN.match("php,txt\n") is not None

    def test_safe_edb_id_pattern_accepts_a_trailing_newline(self):
        assert _SAFE_EDB_ID_PATTERN.match("49757\n") is not None

    def test_safe_filename_pattern_accepts_a_trailing_newline(self):
        assert _SAFE_FILENAME_PATTERN.match("report.txt\n") is not None

    def test_package_name_pattern_trailing_newline_breaks_into_a_second_shell_line(
        self,
    ):
        # Concrete consequence of finding 1: Python's $ matches right
        # before a newline that is the LAST character of the string, so
        # only a value ending exactly in "\n" (nothing after it) passes -
        # "hydra\nrm -rf /" does NOT match, only "hydra\n" does. That
        # single trailing \n is still enough to start a new shell line as
        # soon as anything is concatenated after the validated value in
        # the eventual command string (the real call sites that do this
        # concatenation live in the tool-factory functions, out of this
        # file's scope - this isolates the regex-level mechanism against a
        # real shell).
        package = "hydra\n"
        assert PACKAGE_NAME_PATTERN.match(package) is not None
        assert PACKAGE_NAME_PATTERN.match("hydra\nrm -rf /") is None

        output = _run_in_shell(f"echo installing {package}echo INJECTED")
        assert output == "installing hydra\nINJECTED\n"


# ---------------------------------------------------------------------------
# _expand_port_spec
# ---------------------------------------------------------------------------


class TestExpandPortSpec:
    def test_comma_list(self):
        assert _expand_port_spec("21,25,53") == {21, 25, 53}

    def test_simple_range(self):
        assert _expand_port_spec("1-3,5") == {1, 2, 3, 5}

    def test_single_port(self):
        assert _expand_port_spec("80") == {80}

    def test_reversed_range_silently_returns_empty_set_instead_of_raising(self):
        # Finding 3: a reversed range like "5-1" or "100-1" is accepted by
        # _SAFE_PORT_SPEC_PATTERN, then range(5, 2) is empty - the
        # authorized-ports scope check this feeds sees "no ports requested"
        # rather than an error, instead of rejecting the malformed spec.
        assert _expand_port_spec("5-1") == set()
        assert _expand_port_spec("100-1") == set()

    def test_dangling_hyphen_raises_uncaught_value_error(self):
        # Finding 3: "1-" passes _SAFE_PORT_SPEC_PATTERN (only digits/,/-
        # are checked), then int("") blows up uncaught.
        with pytest.raises(ValueError):
            _expand_port_spec("1-")

    def test_bare_hyphen_raises_uncaught_value_error(self):
        with pytest.raises(ValueError):
            _expand_port_spec("-")


# ---------------------------------------------------------------------------
# _parse_nmap_output
# ---------------------------------------------------------------------------


class TestParseNmapOutput:
    def test_open_port_with_service_and_version(self):
        result = _parse_nmap_output("21/tcp open  ftp     vsftpd 2.3.4")
        assert result == {"21": {"service": "ftp", "version": "vsftpd 2.3.4", "notes": ""}}

    def test_filtered_port_produces_no_entry(self):
        assert _parse_nmap_output("22/tcp filtered ssh") == {}

    def test_open_port_without_version(self):
        result = _parse_nmap_output("80/tcp open http")
        assert result == {"80": {"service": "http", "version": "", "notes": ""}}

    def test_open_port_without_service_token_is_not_captured(self):
        # The regex requires both a state and a service token; a bare
        # "80/tcp open" with nothing after it does not match at all.
        assert _parse_nmap_output("80/tcp open") == {}

    def test_nse_script_lines_attach_to_the_preceding_open_port(self):
        raw = (
            "21/tcp open ftp vsftpd 2.3.4\n"
            "| ftp-anon: \n"
            "|_  Anonymous FTP login allowed"
        )
        result = _parse_nmap_output(raw)
        assert result["21"]["notes"] == "| ftp-anon:\n|_  Anonymous FTP login allowed"

    def test_blank_line_resets_current_port_so_a_later_pipe_line_is_dropped(self):
        raw = "21/tcp open ftp vsftpd 2.3.4\n\n| orphaned note"
        result = _parse_nmap_output(raw)
        assert result["21"]["notes"] == ""

    def test_non_blank_non_port_line_does_not_reset_current_port(self):
        # Gap noted in agent-tools.md: a line like "Service Info: ..." is
        # neither blank nor a port line, so current_port survives it and a
        # later "|" line attaches to the WRONG port's notes.
        raw = "21/tcp open ftp vsftpd 2.3.4\nService Info: OS: Unix\n| stray note"
        result = _parse_nmap_output(raw)
        assert result["21"]["notes"] == "| stray note"

    def test_empty_input_returns_empty_dict(self):
        assert _parse_nmap_output("") == {}

    def test_udp_port_is_keyed_without_its_protocol_suffix(self):
        # Finding 6: _proto is parsed but discarded, so "53/udp" and a
        # hypothetical "53/tcp" line would collide under the same "53" key.
        result = _parse_nmap_output("53/udp open  domain")
        assert result == {"53": {"service": "domain", "version": "", "notes": ""}}


class TestSummarizeNmapEntries:
    def test_ports_are_sorted_numerically_not_lexically(self):
        entries = {
            "10": {"service": "x", "version": "", "notes": ""},
            "9": {"service": "y", "version": "", "notes": ""},
        }
        summary = _summarize_nmap_entries(entries)
        assert summary.index("9/tcp") < summary.index("10/tcp")

    def test_header_includes_service_and_version(self):
        entries = {"21": {"service": "ftp", "version": "vsftpd 2.3.4", "notes": ""}}
        assert _summarize_nmap_entries(entries) == "21/tcp ftp vsftpd 2.3.4"

    def test_header_with_no_version_has_no_trailing_space(self):
        entries = {"80": {"service": "http", "version": "", "notes": ""}}
        assert _summarize_nmap_entries(entries) == "80/tcp http"

    def test_notes_are_indented_two_spaces_under_the_header(self):
        entries = {
            "21": {
                "service": "ftp",
                "version": "",
                "notes": "line one\nline two",
            }
        }
        assert (
            _summarize_nmap_entries(entries)
            == "21/tcp ftp\n  line one\n  line two"
        )


# ---------------------------------------------------------------------------
# _find_binary_token / _extract_binary_name / _is_network_facing
# ---------------------------------------------------------------------------


class TestFindBinaryToken:
    def test_sudo_prefix(self):
        assert _find_binary_token(["sudo", "-E", "nmap", "x"]) == 2

    def test_env_assignment_prefix(self):
        assert _find_binary_token(["FOO=bar", "hydra"]) == 1

    def test_timeout_with_integer_duration(self):
        assert _find_binary_token(["timeout", "30", "nmap"]) == 2

    def test_timeout_with_suffixed_duration(self):
        assert _find_binary_token(["timeout", "5m", "nmap"]) == 2

    def test_bare_prefix_with_nothing_after_returns_none(self):
        assert _find_binary_token(["sudo"]) is None

    def test_timeout_skips_its_own_flag_before_the_duration(self):
        assert _find_binary_token(["timeout", "--kill-after=5", "nmap"]) == 2


class TestExtractBinaryName:
    def test_absolute_path_is_reduced_to_basename(self):
        assert _extract_binary_name("/usr/bin/nmap -sV x") == "nmap"

    def test_semicolon_attached_to_binary_name_is_rejected(self):
        assert _extract_binary_name("nmap;id") is None

    def test_command_substitution_as_first_token_is_rejected(self):
        assert _extract_binary_name("$(rm -rf /) x") is None

    def test_only_the_first_pipe_segment_is_considered(self):
        assert _extract_binary_name("a|b") == "a"

    def test_unbalanced_quotes_return_none_rather_than_guessing(self):
        assert _extract_binary_name("nmap 'x") is None


class TestIsNetworkFacing:
    @pytest.mark.parametrize("command", ["sqlmap", "dig", "nmap", "sudo nmap x"])
    def test_network_facing_binaries(self, command):
        assert _is_network_facing(command) is True

    @pytest.mark.parametrize("command", ["searchsploit", "cat /etc/passwd"])
    def test_non_network_facing_binaries(self, command):
        assert _is_network_facing(command) is False

    def test_unparseable_command_is_treated_as_not_network_facing(self):
        assert _is_network_facing("nmap 'x") is False


# ---------------------------------------------------------------------------
# _maybe_inject_nmap_pn
# ---------------------------------------------------------------------------


class TestMaybeInjectNmapPn:
    def test_inserts_pn_right_after_nmap(self):
        assert _maybe_inject_nmap_pn("nmap -sV x") == ("nmap -Pn -sV x", True)

    def test_leaves_command_unchanged_when_pn_already_present(self):
        assert _maybe_inject_nmap_pn("nmap -Pn x") == ("nmap -Pn x", False)

    def test_inserts_after_a_sudo_prefix(self):
        assert _maybe_inject_nmap_pn("sudo nmap x") == ("sudo nmap -Pn x", True)

    def test_only_rewrites_the_segment_before_a_pipe(self):
        rewritten, changed = _maybe_inject_nmap_pn("nmap x | grep open")
        assert changed is True
        assert rewritten == "nmap -Pn x| grep open"

    def test_does_not_rewrite_when_nmap_is_after_the_pipe(self):
        assert _maybe_inject_nmap_pn("echo hi | nmap x") == ("echo hi | nmap x", False)

    def test_unbalanced_quotes_are_left_unchanged(self):
        assert _maybe_inject_nmap_pn("a 'b") == ("a 'b", False)

    def test_gap_second_nmap_after_a_semicolon_is_not_rewritten(self):
        # Finding 2: splitting only on the first "|" (never on ";"/"&&")
        # means a second, semicolon-chained nmap invocation never gets -Pn.
        rewritten, changed = _maybe_inject_nmap_pn("nmap -sV x; nmap -sS y")
        assert changed is True
        assert rewritten == "nmap -Pn -sV 'x;' nmap -sS y"
        assert "-Pn" not in rewritten.split("nmap", 2)[-1]


# ---------------------------------------------------------------------------
# _clean_man_output
# ---------------------------------------------------------------------------


class TestCleanManOutput:
    def test_strips_backspace_overstrike_sequences(self):
        assert _clean_man_output("N\x08NA\x08AM\x08ME") == "NAME"

    def test_strips_ansi_escape_sequences(self):
        assert _clean_man_output("\x1b[1mBold\x1b[0m") == "Bold"

    def test_plain_text_is_unchanged(self):
        assert _clean_man_output("NAME\n       nmap - scan utility") == (
            "NAME\n       nmap - scan utility"
        )


# ---------------------------------------------------------------------------
# _cap_raw_output
# ---------------------------------------------------------------------------


class TestCapRawOutput:
    def test_exact_limit_is_returned_unchanged(self):
        text = "x" * RAW_OUTPUT_MAX_CHARS
        assert _cap_raw_output(text) is text

    def test_one_over_the_limit_is_truncated_with_an_exact_omitted_count(self):
        text = "x" * (RAW_OUTPUT_MAX_CHARS + 1)
        result = _cap_raw_output(text)
        expected_omitted = len(text) - _RAW_OUTPUT_HEAD_CHARS - _RAW_OUTPUT_TAIL_CHARS
        assert f"[...{expected_omitted} characters omitted here" in result
        assert result.startswith("x" * _RAW_OUTPUT_HEAD_CHARS)
        assert result.endswith("x" * _RAW_OUTPUT_TAIL_CHARS)

    def test_truncated_result_preserves_distinguishable_head_and_tail(self):
        # Total length must exceed RAW_OUTPUT_MAX_CHARS (20000) for
        # truncation to trigger at all - head+tail alone (18000) is not
        # enough, so the middle section here must push past that.
        middle_chars = 3000
        text = "H" * _RAW_OUTPUT_HEAD_CHARS + "M" * middle_chars + "T" * _RAW_OUTPUT_TAIL_CHARS
        assert len(text) > RAW_OUTPUT_MAX_CHARS
        result = _cap_raw_output(text)
        assert result.startswith("H" * _RAW_OUTPUT_HEAD_CHARS)
        assert result.endswith("T" * _RAW_OUTPUT_TAIL_CHARS)
        assert "M" not in result


# ---------------------------------------------------------------------------
# _looks_like_open_prompt
# ---------------------------------------------------------------------------


class TestLooksLikeOpenPrompt:
    def test_bare_password_prompt(self):
        assert _looks_like_open_prompt("Password: ") is True

    def test_password_prompt_followed_by_trailing_newline(self):
        assert _looks_like_open_prompt("Password: \n") is True

    def test_login_prompt(self):
        assert _looks_like_open_prompt("login: ") is True

    def test_ordinary_shell_output_is_not_a_credential_prompt(self):
        assert _looks_like_open_prompt("Last login: Mon") is False

    def test_ordinary_shell_prompt_is_not_flagged(self):
        assert _looks_like_open_prompt("momos@host:~$ ") is False

    def test_prompt_followed_by_more_text_is_not_flagged(self):
        assert _looks_like_open_prompt("Password: accepted, welcome") is False

    def test_ftp_default_username_prompt_is_not_recognized(self):
        # agent-tools.md's own function-by-function section claims
        # "Name (host:momos): " should be True, but the pattern only
        # matches the literal words username/login/password/passphrase -
        # none of which appear here. Pinning the ACTUAL behavior: this
        # genuine open credential prompt is silently NOT protected from
        # condensation, contradicting that section's own expectation.
        assert _looks_like_open_prompt("Name (host:momos): ") is False


# ---------------------------------------------------------------------------
# _render_activation_no_output_note
# ---------------------------------------------------------------------------


class TestRenderActivationNoOutputNote:
    def test_silent_on_connect_binary_gets_the_raw_connection_note(self):
        note = _render_activation_no_output_note("nc 10.0.0.1 4444")
        assert "expected for a raw connection" in note

    def test_silent_on_connect_binary_by_absolute_path(self):
        note = _render_activation_no_output_note("/usr/bin/ncat x")
        assert "expected for a raw connection" in note

    def test_other_binary_gets_the_generic_delayed_banner_note(self):
        note = _render_activation_no_output_note("python3")
        assert "may be a delayed banner" in note


# ---------------------------------------------------------------------------
# FTP pure helpers (_ftp_data_connection_stalled / _ftp_active_mode_fallback)
#
# agent-tools.md's own framing (RIO tags) puts _ensure_ftp_session/
# ftp_connect's end-to-end passive/active-fallback BEHAVIOR in the
# real-I/O tier (needs a real ftp client against ftp_target), but these two
# helpers are plain regex matches over a string - pure and testable here
# without any socket.
# ---------------------------------------------------------------------------


class TestFtpDataConnectionStalled:
    def test_opening_with_no_completion_is_stalled(self):
        assert _ftp_data_connection_stalled("150 Opening data connection") is True

    def test_opening_followed_by_transfer_complete_is_not_stalled(self):
        raw = "150 Opening data connection\n226 Transfer complete"
        assert _ftp_data_connection_stalled(raw) is False

    def test_150_requires_a_space_or_dash_separator(self):
        assert _ftp_data_connection_stalled("1500 bytes") is False

    def test_connection_closed_counts_as_done(self):
        raw = "150 Opening data connection\n426 Connection closed; transfer aborted"
        assert _ftp_data_connection_stalled(raw) is False


class TestFtpActiveModeFallback:
    def test_illegal_port_command_is_detected(self):
        assert _ftp_active_mode_fallback("500 Illegal PORT command.") is True

    def test_cant_bind_for_data_connection_is_detected(self):
        assert _ftp_active_mode_fallback("Can't bind for data connection.") is True

    def test_ordinary_success_output_is_not_flagged(self):
        assert _ftp_active_mode_fallback("226 Transfer complete") is False
