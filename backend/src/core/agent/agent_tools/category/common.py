"""Shared constants/helpers used by more than one tool category below -
output parsing/condensation (the LLM parsing model, the deterministic nmap
path), target/session resolution, and the one-shot exec primitive every
Tier 1/file/guided-session tool is built on. Category-specific tools live
in file_tools.py/pentest_tools.py/guided_session_tools.py/terminal_tools.py/
admin_tools.py instead; builders.py assembles all of them per role."""

import asyncio
import os
import re
import shlex
from typing import Callable, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from src.core import ollama_manager, settings
from src.core.kali_integration import kali_registry
from src.core.kali_integration.kali_manager import KaliManger
from src.core.kali_integration.kali_session import KaliSessionError, NO_OUTPUT_MESSAGE
from src.schemas import Target


def _package():
    """Deferred self-import of this package, returning the fully-loaded
    `agent_tools` package module - safe to call from inside a function body
    (by the time any tool actually runs, package import has long since
    completed), never at module import time.

    A handful of names the pre-split, single-file agent_tools.py exposed
    (db_manager, _get_project_settings, ...) are monkeypatched by the
    existing test suite as `agent_tools.<name>` - a pattern that only
    reaches this submodule's own call sites if they resolve that name
    through the package's namespace at call time, rather than through a
    private copy bound in this module's own globals at import time (which
    monkeypatch.setattr(agent_tools, ...) never touches). Used only at the
    specific call sites that need to stay patchable this way."""
    from src.core.agent import agent_tools

    return agent_tools


# Name of the session auto-opened by Agent.start_agent before the first
# turn, and re-opened by run() as a defensive fallback if every session
# ever ends up closed.
DEFAULT_SESSION_NAME = "default"
DEFAULT_SESSION_COMMAND = "/bin/bash"

# How long new_session/ftp_connect/switch_session wait for a session's
# initial output (a banner, a prompt) before returning - kept short since
# most either respond immediately or not at all until something is sent.
# Shared by terminal_tools.py and guided_session_tools.py.
SESSION_OPEN_READ_SECONDS = 3

# Only a genuine, still-unanswered credential prompt should block
# condensation regardless of length - NOT an ordinary shell prompt (which
# also ends in $/#/> with no trailing newline, but reappears after every
# single completed command in the persistent session model).
_CREDENTIAL_PROMPT_PATTERN = re.compile(
    r"(username|login|password|passphrase)\s*:\s*$", re.IGNORECASE
)

# The Kali session's own local username - appears in the shell prompt
# ("momos@<container>:~$") and in clients' own default-username prompts
# (ftp's "Name (host:momos):"), and the parsing model has repeatedly
# (confirmed in production, more than once) misread either as a discovered
# TARGET credential. Scrubbing it out of the text the parser actually sees
# (see _parse_output) is more reliable than a prompt instruction alone,
# which the parsing model can and does ignore.
_LOCAL_USERNAME_PATTERN = re.compile(r"\bmomos\b")
_LOCAL_USERNAME_PLACEHOLDER = "<local-shell-account>"

# Prefix tokens to skip past when identifying the actual binary a failed
# command invoked, e.g. "sudo nmap ..." or "env FOO=bar nmap ...".
_COMMAND_PREFIX_TOKENS = {"sudo", "env", "timeout"}
_ENV_ASSIGNMENT_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
# "timeout" (unlike sudo/env) takes its own positional duration argument
# before the real command, e.g. "timeout 30 nmap ..." or "timeout 5m nmap
# ..." - without skipping this too, the duration itself would be
# misidentified as the binary.
_DURATION_ARG_PATTERN = re.compile(r"^\d+(\.\d+)?[smhd]?$")


def _find_binary_token(tokens: List[str]) -> Optional[int]:
    """Index of the actual binary token within `tokens`, skipping past any
    leading env-assignment / sudo / env / timeout prefix tokens - e.g.
    ["sudo", "nmap", "-sV", ...] -> 1, ["FOO=bar", "hydra", ...] -> 1.
    Returns None if the token list is exhausted before a real binary is
    found (a bare prefix with nothing after it). Shared by
    _extract_binary_name (below) and terminal_tools's
    _maybe_inject_nmap_pn - both need to locate the real binary past the
    same prefix shapes."""
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if _ENV_ASSIGNMENT_PATTERN.match(token):
            i += 1
            continue
        if token in _COMMAND_PREFIX_TOKENS:
            i += 1
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 1
            if (
                token == "timeout"
                and i < len(tokens)
                and _DURATION_ARG_PATTERN.match(tokens[i])
            ):
                i += 1
            continue
        break

    return i if i < len(tokens) else None


def _extract_binary_name(command: str) -> Optional[str]:
    """Best-effort extraction of the actual binary a shell command line
    invokes, for looking up its man page/--help - e.g. "sudo nmap -sV
    <target>" -> "nmap", "FOO=bar hydra ..." -> "hydra". Deliberately
    conservative: returns None (skip usage-help entirely, rather than
    guessing) for anything shlex can't tokenize or that doesn't end up
    looking like a bare command name."""
    first_segment = command.split("|", 1)[0]
    try:
        tokens = shlex.split(first_segment)
    except ValueError:
        return None

    index = _find_binary_token(tokens)
    if index is None:
        return None

    binary = os.path.basename(tokens[index])
    if not re.match(r"^[a-zA-Z0-9_.+-]+$", binary):
        return None
    return binary


# Binaries whose output can legitimately describe the TARGET's live network
# state (open ports, running services, discovered hosts) - shared between
# _parse_output (which only trusts `facts` from one of these for populating
# the enumeration table - see its own comment) and the silent-on-connect
# table below. Deliberately a narrow allowlist, not a blocklist: anything
# NOT in here - including any binary _extract_binary_name/_find_binary_token
# fails to identify at all - is treated as NOT network-facing, since
# wrongly trusting an unrecognized tool's output is a worse failure mode
# (a fabricated open port silently entering the enumeration table) than
# wrongly distrusting a real one (the agent just doesn't get an enumeration
# entry from that specific command, same as if no parsing model were
# configured at all).
_NETWORK_FACING_BINARIES = {
    "nmap", "curl", "wget", "nc", "ncat", "netcat", "telnet", "ftp", "ssh",
    "gobuster", "nikto", "whatweb", "smbclient", "whois", "hydra",
    "sqlmap", "dig", "nslookup", "host", "ping", "ping6", "traceroute",
    "msfconsole", "msfvenom",
}

# Binaries/session commands known to give NO natural confirmation of their
# own when a connection actually starts (no banner, no "connected" line) -
# see _render_activation_no_output_note below (F4). A program not in here
# still gets a (more neutral) generic no-output note rather than the bare
# NO_OUTPUT_MESSAGE placeholder.
_SILENT_ON_CONNECT_BINARIES = {"nc", "ncat", "netcat"}

# Extra, command-specific guidance appended to _parse_output's classification
# note for whatever's left going through the LLM parser (nmap/hydra/gobuster/
# searchsploit's most common uses now have their own dedicated tools with
# deterministic parsing - see create_pentest_tools - and never reach this
# dict at all). Each entry captures a real, observed misreading risk for
# that specific tool's output format, the same way the generic
# classification_note below already does for exploit-db IDs vs port
# numbers - this just extends that idea per-binary instead of one-size-
# fits-all.
_PARSER_COMMAND_HINTS: Dict[str, str] = {
    "searchsploit": (
        "This is a local exploit-database search - titles and Exploit-DB "
        "IDs are never live ports, hosts, or credentials."
    ),
    "nikto": (
        "Findings are prefixed with '+' and reference OSVDB/CVE IDs and "
        "paths - report the web server's own version banner as the "
        "service version, not an OSVDB number."
    ),
    "whatweb": (
        "Output lists detected web technologies/versions as "
        "'Plugin[version]' pairs - treat these as the service's software "
        "stack, not open ports."
    ),
    "smbclient": (
        "Share/listing output describes filesystem contents, not network "
        "services - only report port/service facts from the initial "
        "connection banner, if any."
    ),
    "sqlmap": (
        "Narrative injection-testing output - only report a "
        "vulnerability-relevant fact if sqlmap explicitly confirms an "
        "injection point, never from a parameter name or URL alone."
    ),
    "dig": "DNS record output - record types (A/MX/TXT/...) and TTLs are not port numbers.",
    "nslookup": "DNS record output - record types are not port numbers.",
    "host": "DNS record output - record types are not port numbers.",
    "whois": (
        "Registration metadata (dates, registrar, name servers) - not "
        "live port/service state."
    ),
}


def _is_network_facing(command: str) -> bool:
    """Whether `command` invokes a binary whose output is eligible to
    populate the enumeration table - see _NETWORK_FACING_BINARIES."""
    binary = _extract_binary_name(command)
    return binary is not None and binary in _NETWORK_FACING_BINARIES


# Shared between PARSER_SYSTEM_PROMPT and _CLAIM_VERIFICATION_SYSTEM_PROMPT -
# both independently restated this almost sentence-for-sentence (see
# PROMPT_AUDIT.md finding 3.3); one canonical wording referenced by both
# instead.
_LOCAL_USERNAME_CAVEAT = (
    "The local Kali session itself runs as user 'momos' - this string "
    "appearing in a shell prompt (e.g. 'momos@host:~$') or as a client's "
    "own default-username suggestion (e.g. ftp's 'Name (host:momos):') is "
    "your OWN local username, never a credential found on the target; "
    "never report it as one."
)
_APPLICATION_LAYER_EVIDENCE_CAVEAT = (
    "A bare network/transport-level connection succeeding (e.g. netcat's "
    "own \"Connection to <host> <port> succeeded!\", or a TCP port simply "
    "being open/reachable) is NOT evidence of anything at the application "
    "layer"
)


PARSER_SYSTEM_PROMPT = (
    "You are a data-extraction assistant supporting an autonomous "
    "penetration-testing agent. You are given ONLY the raw output from one "
    "command the agent just ran directly in its own Kali Linux terminal "
    "session - not the command itself, and no other context. You have no "
    "way to know what was attempted or intended - describe only what the "
    "output itself actually shows, never guess or infer intent from it.\n\n"
    "In 'summary', condense the output to only the information it actually "
    "contains that's relevant to a security assessment: open ports, service "
    "names/versions, discovered hosts, vulnerabilities, file paths, "
    "credentials, and other actionable findings. Only mention a category if "
    "the output actually contains something about it - if this command "
    "never addressed a category at all (e.g. a plain port scan says nothing "
    "about credentials), that is not information, so leave it out entirely. "
    "Do NOT write that something was 'not found'/'not discovered' for a "
    "category this command never looked for - stating that falsely implies "
    "it was checked for and ruled out. The one exception: if the output "
    "ITSELF explicitly reports a negative result for something it actually "
    "checked (e.g. nmap reporting 0 hosts up, or a scan completing with no "
    "matches), that IS real information - state that plainly. Never pad the "
    "summary with a checklist of every category this command didn't "
    "address. Remove repetitive noise, banners, and formatting clutter. "
    "Quote any credentials, paths, or flags VERBATIM - never paraphrase or "
    f"approximate them. {_LOCAL_USERNAME_CAVEAT} A program asking for a "
    "username/password is not itself evidence of a credential - only an "
    f"actual authentication result (success or failure) is. "
    f"{_APPLICATION_LAYER_EVIDENCE_CAVEAT} - "
    "never report a login, authentication, or exploit as successful unless "
    "the output itself contains an explicit application-level response "
    "from the actual service (a protocol status code such as FTP 230/530, "
    "an explicit success/failure message from the service, an actual "
    "returned result). If the command "
    "failed or produced an error, clearly "
    "state the failure and its cause. There is no separate human 'user' "
    "here - never write 'the user ran/attempted/tried ...'; state what the "
    "command did and produced directly instead (e.g. \"msfconsole: command "
    "not found\", not \"the user attempted to run msfconsole\"). Plain, "
    "concise text only - no commentary or suggestions.\n\n"
    "In 'facts', list any specific network ports this output identifies a "
    "service name and/or version for, one entry per port in the exact "
    "'<number>/tcp' or '<number>/udp' form. Leave it empty if none were "
    "found - never invent one."
)


class _PortFact(BaseModel):
    port: str = Field(description="e.g. '80/tcp' or '53/udp'")
    service: str = ""
    version: str = ""
    notes: str = ""


class _ParsedCommandOutput(BaseModel):
    """Structured result of condensing one Kali command's raw output.

    Used as the schema for parser_llm.with_structured_output() - Ollama
    constrains decoding to this JSON shape directly, which is far more
    reliable than asking a (often small, local) model to self-format an
    extra marker line inside free text and then regex it back out; that
    approach was tried and broke in practice (wrong casing, non-array
    formatting, trailing prose after the marker)."""

    summary: str
    facts: List[_PortFact] = Field(default_factory=list)


async def _get_project_settings(project_id: str):
    loop = asyncio.get_running_loop()
    # _package() (not a bare `db_manager` import) - see its own docstring:
    # keeps `monkeypatch.setattr(agent_tools, "db_manager", ...)` (used
    # throughout the existing test suite, written against the pre-split
    # flat module) reaching this call after the split into submodules.
    return await loop.run_in_executor(
        None, _package().db_manager.get_project_settings, project_id
    )


# Per-process cache of a model's own capabilities (context window/thinking
# support), keyed by model name - a model's capabilities don't change during
# a run, and _parse_output/_suggest_command_fix are called on essentially
# every tool result, so re-fetching via Ollama's show() on every single call
# would be wasteful. Mirrors the per-run _usage_reference_cache pattern used
# for man pages inside terminal_tools.create_terminal_tools.
_parsing_model_capabilities_cache: Dict[str, dict] = {}


async def _get_parsing_model_num_ctx(parsing_model_name: str, project_settings) -> Optional[int]:
    """Effective num_ctx to request for the project's configured parsing
    model - its own detected max context, clamped to project_settings' own
    max_context_window override (or settings.DEFAULT_MAX_CONTEXT_WINDOW if
    unset/None) - same clamping agent_service.py applies to the base model.
    Takes the caller's already-fetched project_settings (both call sites
    need it anyway for parsing_model_name itself) instead of re-fetching -
    avoids a second DB round-trip per call, and means this can never raise
    from ITS OWN DB access. Returns None (let ChatOllama fall back to
    Ollama's own server-side default) only if the model's own capabilities
    lookup fails - best-effort, never blocks a parsing call over what's
    only ever an optimization."""
    if parsing_model_name in _parsing_model_capabilities_cache:
        capabilities = _parsing_model_capabilities_cache[parsing_model_name]
    else:
        try:
            capabilities = await ollama_manager.get_model_capabilities(parsing_model_name)
        except Exception as e:
            print(f"Could not fetch capabilities for parsing model '{parsing_model_name}': {e}")
            return None
        _parsing_model_capabilities_cache[parsing_model_name] = capabilities

    ceiling = (
        (project_settings.max_context_window if project_settings else None)
        or settings.DEFAULT_MAX_CONTEXT_WINDOW
    )
    return min(capabilities["context_window"], ceiling)


async def _parse_output(
    project_id: str,
    command: str,
    raw_output: str,
    on_enumeration: Callable[[dict], None],
) -> str:
    # _package()._get_project_settings (not a bare call) - see _package's
    # own docstring: keeps a test's
    # `monkeypatch.setattr(agent_tools, "_get_project_settings", ...)`
    # reaching this call after the split into submodules.
    project_settings = await _package()._get_project_settings(project_id)
    parsing_model_name = project_settings.parsing_model_name if project_settings else None

    if not parsing_model_name:
        # No parsing model configured for this project - fall back to raw output
        return raw_output

    num_ctx = await _get_parsing_model_num_ctx(parsing_model_name, project_settings)
    parser_llm = ChatOllama(
        model=parsing_model_name, base_url=settings.ollama_url, num_ctx=num_ctx
    )
    structured_llm = parser_llm.with_structured_output(_ParsedCommandOutput)

    # Prompt-level hint (best-effort, see the code-level gate below for the
    # part that actually matters): tell the parser whether this command even
    # CAN legitimately describe the target's live network state, so it
    # doesn't force-fit unrelated numbers/strings (exploit-db IDs, the
    # shell's own reappeared prompt, ...) into the ports/hosts categories
    # for something like a local `searchsploit` lookup. See
    # _NETWORK_FACING_BINARIES.
    network_facing = _is_network_facing(command)
    classification_note = (
        "This command interacted with the network/target directly - port, "
        "service, host, and credential information in its output, if any, "
        "can be trusted."
        if network_facing
        else "This command does NOT interact with the network or the "
        "target at all (a local, offline, or reference tool) - it has no "
        "access to the target's live port/service/host state. Do not "
        "report open ports, hosts, or service versions from it, even if "
        "the output happens to contain numbers that could look like port "
        "numbers (file IDs, version numbers, line counts, ...) - none of "
        "those are network information."
    )
    binary = _extract_binary_name(command)
    hint = _PARSER_COMMAND_HINTS.get(binary or "")
    if hint:
        classification_note = f"{classification_note}\n\n{hint}"

    # Scrub the local shell account's own name out of the copy the parsing
    # model sees - it has repeatedly misread it (from the shell prompt or a
    # client's own default-username suggestion) as a discovered TARGET
    # credential. The real raw_output (returned to the caller/persisted as
    # the tool's artifact) is left untouched - this only affects what goes
    # into this specific model call.
    scrubbed_output = _LOCAL_USERNAME_PATTERN.sub(_LOCAL_USERNAME_PLACEHOLDER, raw_output)

    try:
        result = await structured_llm.ainvoke(
            [
                SystemMessage(content=PARSER_SYSTEM_PROMPT),
                HumanMessage(
                    content=f"{classification_note}\n\nOutput:\n{scrubbed_output}"
                ),
            ]
        )
    except Exception as e:
        # Don't lose a real command result just because the parsing model
        # hiccuped (or doesn't support structured output) - give the agent
        # the raw output instead.
        print(f"Output parsing failed, using raw output: {e}")
        return raw_output

    # Code-level gate, not just a prompt-level hint - a purely local/
    # reference command's output never populates the enumeration table
    # (state()["enumeration"], which _render_context_message tells the
    # agent to "trust... over your own memory"), regardless of what the
    # parsing model's `facts` list claims. Observed in production:
    # `searchsploit ftpd 2.3.4`'s exploit-db entry IDs (e.g. "49757.py")
    # got reported as open ports ("49757/tcp") despite the prompt-level
    # instruction above, and the shell's own reappeared prompt got reported
    # as a discovered host - a purely textual instruction isn't reliable
    # enough for something this consequential to fabricate, so this doesn't
    # even look at `result.facts` unless the command is one we actually
    # trust to have talked to the target.
    if network_facing:
        entries: Dict[str, dict] = {}
        for fact in result.facts:
            port = fact.port.strip()
            if not port:
                continue
            entries[port] = {
                "service": fact.service,
                "version": fact.version,
                "notes": fact.notes,
            }
        if entries:
            on_enumeration(entries)

    return result.summary or raw_output


class _ClaimVerification(BaseModel):
    supported: bool
    reason: str


# System prompt for _verify_claim_against_evidence below - deliberately
# separate from PARSER_SYSTEM_PROMPT (a different job: PARSER_SYSTEM_PROMPT
# condenses one command's output on its own; this checks a CLAIM the agent
# wants to record against whatever its last real tool output actually
# showed, at the moment the claim is made).
_CLAIM_VERIFICATION_SYSTEM_PROMPT = (
    "You are a skeptical fact-checker for an autonomous penetration-testing "
    "agent. You are given the agent's most recent real tool output, and a "
    "claim it wants to record based on it. Decide whether the claim is "
    "actually supported by that output.\n\n"
    "An unanswered username/password prompt, a login prompt the agent "
    "never actually completed, or text that only echoes what the agent "
    "itself typed or attempted are NOT evidence of success - only an "
    "explicit result in the output counts: an explicit success/failure "
    "indicator (e.g. an FTP 230 vs 530 reply code), an actual returned "
    f"file listing or command result, or a clear stated error. "
    f"{_APPLICATION_LAYER_EVIDENCE_CAVEAT} - a login, authentication, or "
    "exploit claim needs an explicit application-level response from the "
    "actual service itself, not just a successful network connection to "
    "it. A username or password appearing only in the ATTEMPTED command "
    "(not echoed back with a server confirmation) is not a discovered "
    f"credential. {_LOCAL_USERNAME_CAVEAT}\n\n"
    "Set 'supported' to true only if the output clearly backs the claim. "
    "If the output is ambiguous, incomplete, or silent on the specific "
    "claim, set 'supported' to false - the agent should re-verify rather "
    "than record something uncertain. 'reason' should be one short "
    "sentence explaining your verdict, quoting the relevant part of the "
    "output where possible."
)


# Prefix of _verify_claim_against_evidence's rejection message below -
# exported so agent.py's stall-recovery nudge (see its
# MAX_CONSECUTIVE_NO_TOOL_CALLS handling) can detect "the last tool result
# was a rejected finding claim" without duplicating the literal string.
# Observed in production: granite4.1:8b, right after this exact rejection,
# stopped producing any output at all (not even empty thinking text) for
# every remaining nudge turn until the stall circuit breaker ended the run
# - the generic nudge wasn't enough to get it to retry constructively.
CLAIM_REJECTED_MARKER = "A check against your last real tool output could not confirm"


async def _verify_claim_against_evidence(
    project_id: str, claim_label: str, claim_text: str, raw_evidence: Optional[str]
) -> Optional[str]:
    """Best-effort second opinion at the moment a "vulnerable"/formal
    finding claim is made, checking it against the agent's own most recent
    real tool output (see Agent._last_raw_output). Returns None if the
    claim looks supported (or verification itself couldn't be attempted -
    this is a safety net, not something that should be able to break the
    tool entirely), or a rejection message to hand back to the model.

    Exists because the pre-existing proof-of-testing gate (_require_tested)
    only checks THAT a run() happened since the last claim, never WHAT it
    showed - confirmed in production to let a claim built on a misread
    prompt, or on the command's own attempted-but-unconfirmed input, sail
    straight through untouched."""
    if not raw_evidence or not raw_evidence.strip():
        return (
            "No recent real tool output is available to verify this "
            f"{claim_label} against - make a real run() call against the "
            "target first, then try again."
        )

    project_settings = await _package()._get_project_settings(project_id)
    parsing_model_name = project_settings.parsing_model_name if project_settings else None
    if not parsing_model_name:
        # No parsing model configured for this project - nothing to check
        # against, so don't block on a feature that isn't set up.
        return None

    try:
        num_ctx = await _get_parsing_model_num_ctx(parsing_model_name, project_settings)
        verifier_llm = ChatOllama(
            model=parsing_model_name, base_url=settings.ollama_url, num_ctx=num_ctx
        )
        structured_verifier = verifier_llm.with_structured_output(_ClaimVerification)
        result = await structured_verifier.ainvoke(
            [
                SystemMessage(content=_CLAIM_VERIFICATION_SYSTEM_PROMPT),
                HumanMessage(
                    content=(
                        f"Most recent real tool output:\n{raw_evidence}\n\n"
                        f"Claim to check ({claim_label}): {claim_text}"
                    )
                ),
            ]
        )
    except Exception as e:
        print(f"Claim verification failed, allowing the claim through: {e}")
        return None

    if result.supported:
        return None

    return (
        f"{CLAIM_REJECTED_MARKER} "
        f"this {claim_label}: {result.reason} Re-verify with a real "
        "run() call before recording this, or revise it to match what you "
        "actually observed."
    )


# Hard safety cap on any raw tool output returned to the agent, applied
# regardless of whether a parsing model is configured for the project (see
# _maybe_condense below) - a project simply not configuring one is the
# out-of-the-box default (project_settings_factory sets
# parsing_model_name=""), and without this, a large scan's raw output (e.g.
# nmap -p- across a wide port range) would otherwise flow straight into a
# small local model's own already-tight context, completely uncondensed.
# Head+tail rather than a flat head-only cut, similar in spirit to
# terminal_tools.USAGE_REFERENCE_MAX_CHARS's man-page truncation: the start
# usually has the command's own banner/early results, the end usually has a
# scan's final summary - both are more useful than an equivalent-sized
# arbitrary slice out of the middle.
RAW_OUTPUT_MAX_CHARS = 20000
_RAW_OUTPUT_HEAD_CHARS = 12000
_RAW_OUTPUT_TAIL_CHARS = 6000


def _cap_raw_output(raw_output: str) -> str:
    if len(raw_output) <= RAW_OUTPUT_MAX_CHARS:
        return raw_output

    omitted = len(raw_output) - _RAW_OUTPUT_HEAD_CHARS - _RAW_OUTPUT_TAIL_CHARS
    return (
        raw_output[:_RAW_OUTPUT_HEAD_CHARS]
        + f"\n\n[...{omitted} characters omitted here - output too large to "
        "show in full...]\n\n"
        + raw_output[-_RAW_OUTPUT_TAIL_CHARS:]
    )


def _looks_like_open_prompt(raw_output: str) -> bool:
    """True only if the output looks like it ends on an unanswered
    credential prompt (username/login/password/passphrase) - condensing
    that risks paraphrasing away exactly the text the agent still needs
    verbatim, regardless of length.

    Deliberately does NOT trigger on "ends without a trailing newline" or
    "ends in :/$/>/#" alone - every run() call against the persistent
    default bash session ends that way (that's just what a shell prompt
    looks like, reappearing after every single completed command), so a
    broader check here would silently disable condensation for ordinary
    terminal output entirely, which is what happened before this was
    narrowed to only the specific credential-prompt case."""
    return bool(_CREDENTIAL_PROMPT_PATTERN.search(raw_output[-80:]))


def _render_activation_no_output_note(session_command: str) -> str:
    """Replaces the bare NO_OUTPUT_MESSAGE placeholder with an explicit,
    tool-aware statement that the session is genuinely live even though it
    hasn't printed anything - see F4. Without this, a silent-by-design
    program (nc opening a raw connection, most obviously - see
    _SILENT_ON_CONNECT_BINARIES) reads as "this might not have worked" when
    it almost certainly did; the bare placeholder gives the agent no way to
    tell "confirmed silent" apart from "possibly failed"."""
    binary = _extract_binary_name(session_command)
    if binary is not None and binary in _SILENT_ON_CONNECT_BINARIES:
        return (
            f"`{session_command}` is running and is now your current "
            "session. It hasn't printed anything yet - that's expected for "
            "a raw connection like this (it stays silent until data is "
            "sent, not a failure). Send your first line with run() "
            "whenever you're ready."
        )
    return (
        f"`{session_command}` is running and is now your current session. "
        "It hasn't printed anything yet within the wait window - this may "
        "be a delayed banner, or it may still be starting/connecting. A "
        "follow-up run() with no input will pick up anything that arrives, "
        "or you can send input directly if you're ready."
    )


async def _maybe_condense(
    project_id: str,
    label: str,
    raw_output: str,
    on_enumeration: Callable[[dict], None],
    session_command: Optional[str] = None,
) -> str:
    """Every command result that actually has content is routed through
    the parsing model (when one is configured for the project - see
    _parse_output) rather than only output long enough to seem worth the
    extra call. This keeps what the agent sees consistently condensed to
    what's relevant instead of raw tool noise, and keeps the enumeration
    table populated from every result rather than only from the larger
    ones - previously a normal, reasonably-sized scan skipped parsing
    entirely, so the table stayed empty while the model narrated made-up
    service versions with nothing auto-maintained to check itself against.

    Two things are still deliberately excluded, since there is nothing for
    a parser to usefully condense: a still-open credential prompt (see
    _looks_like_open_prompt - paraphrasing that risks losing the exact
    verbatim text the agent still needs to respond to), and the
    NO_OUTPUT_MESSAGE placeholder substituted when a read genuinely produced
    nothing - which, when the caller knows which session command is running
    (`session_command`, e.g. from new_session/run()), gets replaced with an
    explicit, tool-aware note instead of surfaced verbatim (see
    _render_activation_no_output_note/F4). Callers that don't have a
    session command handy (or genuinely don't know it) keep the old bare
    placeholder - still a valid, if less informative, result.

    A third exclusion: `label` (the command whose output this is - see each
    caller in terminal_tools.create_terminal_tools) not being one of
    _NETWORK_FACING_BINARIES at all. Previously every non-empty result was
    still sent to the parsing model "to summarize," and only the returned
    `facts` were discarded for a non-network-facing command - so a plain
    shell builtin (cd/ls/cat/whoami/...) was still a full LLM call, and a
    fresh chance for a small local model to hallucinate a "summary" out of
    it for nothing. Skipping the call entirely for these is both safer and
    cheaper - this is meant to condense enumeration output, not narrate
    shell noise."""
    if raw_output == NO_OUTPUT_MESSAGE and session_command:
        return _render_activation_no_output_note(session_command)

    if (
        not raw_output.strip()
        or raw_output == NO_OUTPUT_MESSAGE
        or _looks_like_open_prompt(raw_output)
    ):
        return raw_output

    # Cap BEFORE handing off to _parse_output, not just on its result - the
    # parsing model is itself often a small local model, so the whole point
    # of this cap (see RAW_OUTPUT_MAX_CHARS's comment) is defeated if it
    # only trims what's shown to the agent afterward while the parsing
    # model call still receives the full, uncapped output.
    capped = _cap_raw_output(raw_output)
    if not _is_network_facing(label):
        return capped

    return await _parse_output(project_id, label, capped, on_enumeration)


async def _resolve_current_session(
    manager: KaliManger, target_id: str, agent_run_id: str, on_session_change
):
    """Ensures target_id/agent_run_id has a current session, opening a
    fresh default one if every session somehow ended up closed (idle
    timeout, process exit, ...) - start_agent() already opens "default"
    before the first turn, so this is only a defensive fallback. Returns
    (session, was_replaced) - was_replaced is True exactly when this call
    itself had to silently open the replacement, so the caller can tell the
    model its previous session is gone. Raises KaliSessionError if even
    opening a fresh one fails."""
    was_replaced = not manager.has_current_session(target_id, agent_run_id)
    if was_replaced:
        await manager.open_session(
            target_id, agent_run_id, DEFAULT_SESSION_NAME, DEFAULT_SESSION_COMMAND
        )
        on_session_change(DEFAULT_SESSION_NAME, DEFAULT_SESSION_COMMAND)
    return manager.get_current_session(target_id, agent_run_id), was_replaced


async def _send_and_condense(
    manager: KaliManger,
    project_id: str,
    target_id: str,
    agent_run_id: str,
    current_session,
    input: Optional[str],
    wait_seconds: int,
    on_enumeration: Callable[[dict], None],
    mark_tested: Callable[[], None],
    on_session_change: Callable[[Optional[str], Optional[str]], None],
    on_prompt_state_change: Callable[[bool], None],
    on_raw_output: Callable[[str], None],
    session_was_replaced: bool = False,
) -> tuple:
    """Shared core of run() and the guided session tools (ftp_connect/
    ftp_command - see create_guided_session_tools): sends `input` (or just
    polls, if None) to `current_session` (already resolved by the caller -
    see _resolve_current_session), handles stuck-session auto-promotion
    exactly like run() always has, marks the turn tested, and condenses the
    result. Returns (condensed_text, raw_output) - raw_output is None only
    when a KaliSessionError happened before anything could run.

    Deliberately does NOT include run()'s own nmap -Pn auto-injection or
    its post-hoc usage-error suggestion - both are specific to a model-
    typed raw shell command line, meaningless for a guided tool's own
    internally-constructed input."""
    try:
        raw_output = await manager.run_in_current_session(
            target_id, agent_run_id, input, wait_seconds=wait_seconds
        )
    except KaliSessionError as e:
        return str(e), None

    # current_session is the same live object kali_manager mutates
    # in-place during the call above, so its at_shell_prompt now reflects
    # what just happened - surface it so Agent's per-turn reminder can tell
    # the model when it may still be stuck inside another program's prompt
    # (see _looks_like_shell_prompt).
    on_prompt_state_change(current_session.at_shell_prompt if current_session else True)
    on_raw_output(raw_output)

    # Mechanical recovery, not just a reminder - confirmed in production
    # that the "you may still be inside another program" reminder alone
    # gets ignored for many turns in a row. Gated on confusion_streak (2+
    # turns of the current program's own "I don't understand that"
    # rejection), not merely "not at shell prompt" - the latter is also the
    # correct, persistent state for a genuinely productive interactive
    # session and was confirmed to sever one prematurely (see
    # promote_stuck_session's docstring).
    promoted_name = None
    if current_session is not None and current_session.confusion_streak >= 2:
        promoted_name = await manager.promote_stuck_session(
            target_id, agent_run_id, DEFAULT_SESSION_NAME, DEFAULT_SESSION_COMMAND
        )
        if promoted_name:
            on_session_change(DEFAULT_SESSION_NAME, DEFAULT_SESSION_COMMAND)
            on_prompt_state_change(True)

    # Only counts as "tested" when input was actually sent - a bare poll
    # (no input) doesn't itself constitute an attempt against the target,
    # and shouldn't be enough to unlock report_vulnerability/
    # log_attack_attempt on its own.
    if input is not None:
        mark_tested()

    # The real command whose output this is, used only for
    # _is_network_facing classification (see _maybe_condense/_parse_output
    # - its text is never shown to the parsing model itself) - a bare poll
    # (input is None) didn't send anything of its own, so classify by
    # whatever program the session is actually running instead of a
    # placeholder that would never match any known binary.
    classify_as = input if input is not None else (
        current_session.command if current_session else None
    )
    condensed = await _maybe_condense(
        project_id,
        classify_as or "",
        raw_output,
        on_enumeration,
        session_command=current_session.command if current_session else None,
    )

    if session_was_replaced:
        condensed = (
            "[Your previous session was gone (closed, idle-timed-out, "
            "or its process exited) - a brand-new plain shell session "
            "was opened for you. Any prior state - working directory, "
            "environment variables, an interactive program's prompt - "
            "is lost; you're at a fresh shell prompt now.]\n\n" + condensed
        )

    if promoted_name:
        condensed = (
            "[Your session's last output didn't look like your plain "
            f"shell prompt, so it's been automatically split off as a "
            f"separate session named '{promoted_name}' - its "
            f"connection is untouched, switch_session('{promoted_name}') "
            "to go back to it (useful if you were mid-login to "
            "something like ftp/telnet, or if this was actually a "
            "slow command like a long scan still working). You are "
            "now in a fresh 'default' plain shell.]\n\n" + condensed
        )

    return condensed, raw_output


async def _get_target_info(target_id: str) -> Tuple[Optional[Target], Optional[str]]:
    """Returns (target, error_message) - the full Target row, for a tool
    that needs more than just the host (e.g. nmap_scan validating `ports`
    against target.ports)."""
    loop = asyncio.get_running_loop()
    # _package() - see its own docstring for why this isn't a bare
    # `db_manager` import.
    target = await loop.run_in_executor(None, _package().db_manager.get_target, target_id)
    if target is None:
        return None, "Could not resolve this run's target - internal error."
    return target, None


async def _get_target_host(target_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Returns (host, error_message) for a Tier 1/2 tool's target - host is
    target.ipv4 or target.ipv6 (preferring v4); error_message is set (and
    host is None) whenever the target can't be resolved or has no address
    configured at all."""
    target, error = await _get_target_info(target_id)
    if error:
        return None, error
    host = target.ipv4 or target.ipv6
    if not host:
        return None, "This target has no IPv4/IPv6 address configured - cannot proceed."
    return host, None


# Shared by every Tier 1/2 tool and the local-file tools that accept a
# caller-supplied filesystem path (a wordlist, a file to read/list) -
# pentest_tools.py has the matching patterns for port specs/extensions/EDB
# IDs, and file_tools.py has _SAFE_FILENAME_PATTERN for a bare filename
# component (no "/" at all, unlike this one) - every such free-text
# argument is restricted to one of these narrow structural patterns before
# being interpolated into a shell command string, run via `bash -c`
# (KaliManger.execute/_exec_in_container) - not a formality. \Z, not $, for
# the same reason PACKAGE_NAME_PATTERN (admin_tools.py) uses it - a bare $
# would still accept a value ending in exactly one trailing "\n".
_SAFE_PATH_PATTERN = re.compile(r"^[\w./-]+\Z")


async def _execute_one_shot(
    project_id: str, command: str, timeout_seconds: int
) -> Tuple[bool, str]:
    """Runs `command` as a one-shot exec (KaliManger.execute, unprivileged
    momos user, no session involved) - shared by every Tier 1 tool below.
    Returns (ok, output); ok is False on a non-zero exit or a timeout, in
    which case `output` is already a clear message ready to return
    straight to the agent (see KaliManger._exec_in_container - it raises
    RuntimeError for both cases, with the command's own output embedded in
    the message)."""
    manager = await kali_registry.get_manager(project_id)
    try:
        output = await manager.execute(command, timeout_seconds=timeout_seconds)
    except RuntimeError as e:
        return False, str(e)
    return True, output


async def _file_exists_in_container(project_id: str, path: str) -> bool:
    ok, _ = await _execute_one_shot(project_id, f"test -f {shlex.quote(path)}", 10)
    return ok
