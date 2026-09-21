import asyncio
import json
import os
import re
import shlex
from typing import Callable, Dict, List, Literal, Optional, Tuple
from pydantic import BaseModel, Field, ValidationError
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama
from src.core import db_manager, ollama_manager, settings
from src.core.kali_integration import kali_registry
from src.core.kali_integration.kali_manager import KaliManger, KALI_USERS
from src.core.kali_integration.kali_session import KaliSessionError, NO_OUTPUT_MESSAGE
from src.schemas import Vulnerability, VulnerabilityBase, SEVERITY_LEVELS, Target

KALI_COMMAND_TOOL_NAME = "execute_kali_command"
REPORT_VULNERABILITY_TOOL_NAME = "report_vulnerability"
FINISH_TASK_TOOL_NAME = "finish_task"
RUN_TOOL_NAME = "run"
NEW_SESSION_TOOL_NAME = "new_session"
SWITCH_SESSION_TOOL_NAME = "switch_session"
CLOSE_SESSION_TOOL_NAME = "close_session"
LIST_SESSIONS_TOOL_NAME = "list_sessions"
INTERRUPT_SESSION_TOOL_NAME = "interrupt_session"
INSTALL_PACKAGE_TOOL_NAME = "install_kali_package"
ATTACK_LOG_TOOL_NAME = "log_attack_attempt"
SWITCH_MODE_TOOL_NAME = "switch_mode"

# Tier 1 (one-shot structured tools) and Tier 2 (guided session tools) - see
# create_pentest_tools/create_guided_session_tools. Always registered
# regardless of allow_shell (build_agent_tools) - the constrained/guided
# alternative to the raw shell, not something gated behind it.
NMAP_SCAN_TOOL_NAME = "nmap_scan"
HYDRA_BRUTEFORCE_TOOL_NAME = "hydra_bruteforce"
GOBUSTER_SCAN_TOOL_NAME = "gobuster_scan"
SEARCHSPLOIT_SEARCH_TOOL_NAME = "searchsploit_search"
SEARCHSPLOIT_VIEW_TOOL_NAME = "searchsploit_view"
SEARCHSPLOIT_RUN_TOOL_NAME = "searchsploit_run"
FTP_CONNECT_TOOL_NAME = "ftp_connect"
FTP_COMMAND_TOOL_NAME = "ftp_command"
SSH_CHECK_LOGIN_TOOL_NAME = "ssh_check_login"
SSH_RUN_TOOL_NAME = "ssh_run"
TELNET_PROBE_TOOL_NAME = "telnet_probe"

ATTACK_OUTCOMES = {"vulnerable", "not_vulnerable", "inconclusive"}
VALID_MODES = {"scouting", "exploiting"}

# Name of the session auto-opened by Agent.start_agent before the first
# turn, and re-opened by run() as a defensive fallback if every session
# ever ends up closed.
DEFAULT_SESSION_NAME = "default"
DEFAULT_SESSION_COMMAND = "/bin/bash"

# Debian package-name policy: lowercase letters, digits, '+', '-', '.', must
# start with an alphanumeric. Enforced strictly here (not just relying on
# apt's own error) because this string is interpolated straight into a root
# shell command - anything looser would open command injection.
PACKAGE_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")

# Package installs can be slow (large tools, dependency resolution) - longer
# than the default one-shot command timeout.
PACKAGE_INSTALL_TIMEOUT_SECONDS = 300

# How long new_session waits for the command's initial output (a banner,
# a prompt) before returning - kept short since most either respond
# immediately or not at all until something is sent.
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

# A junior model - especially at 8B scale - regularly gets a real CLI
# tool's own flag/argument syntax wrong (wrong flag spelling, wrong
# argument order, a flag that doesn't exist in this tool's version, ...).
# This is deliberately narrow to the SHELL/ARGUMENT-PARSING layer
# complaining about how it was invoked, not the target/service refusing
# the connection - "Connection refused"/"No route to host"/"Connection
# timed out" must NOT trigger this, since a man page can't fix a
# network-level failure and offering one there would be actively
# misleading. See _maybe_help_with_usage below.
_USAGE_ERROR_PATTERN = re.compile(
    r"command not found"
    r"|(?:invalid|unrecognized|unknown)\s+option"
    r"|invalid\s+argument"
    r"|usage:\s"
    r"|missing\s+(?:required\s+)?(?:operand|argument)"
    r"|try\s+['\"].*--help"
    r"|requires?\s+an?\s+argument",
    re.IGNORECASE,
)

# Only a plain shell prompt is something _extract_binary_name's parsing of
# `input` as a shell command line actually makes sense for - once the
# current session is INSIDE another interactive program (ftp, msfconsole,
# ...), `input` is a line typed at THAT program's own prompt, not a Kali
# shell command, and "man <first word>" would be fetching documentation
# for something that was never actually invoked as a standalone command.
_USAGE_HELP_ELIGIBLE_SESSION_COMMANDS = {DEFAULT_SESSION_COMMAND}

# Kept short - this is a quick, best-effort lookup running alongside the
# agent's regular turn, not a scan; man/--help/-h all answer near-instantly
# once the package itself is installed.
USAGE_HELP_TIMEOUT_SECONDS = 15

# Man pages can run to tens of thousands of characters (nmap's is a good
# example) - far more than a small local parsing model needs to fix one
# invocation, and more than its context window may comfortably hold
# alongside the failed command/output. Truncating from the top keeps
# NAME/SYNOPSIS (and usually the start of OPTIONS), which is what actually
# answers "what's the right flag/argument shape" - deep per-flag detail
# further down matters far less for this than for reading the whole page.
USAGE_REFERENCE_MAX_CHARS = 8000

# Escape/overstrike cleanup for `man` output read back over a non-tty exec
# (no pager) - equivalent to what `col -bx` does, done in Python instead of
# depending on the `bsdmainutils`/`util-linux` package (not guaranteed to
# be installed) providing that binary inside the container.
_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_OVERSTRIKE_PATTERN = re.compile(r".\x08")

# Prefix tokens to skip past when identifying the actual binary a failed
# command invoked, e.g. "sudo nmap ..." or "env FOO=bar nmap ...".
_COMMAND_PREFIX_TOKENS = {"sudo", "env", "timeout"}
_ENV_ASSIGNMENT_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
# "timeout" (unlike sudo/env) takes its own positional duration argument
# before the real command, e.g. "timeout 30 nmap ..." or "timeout 5m nmap
# ..." - without skipping this too, the duration itself would be
# misidentified as the binary.
_DURATION_ARG_PATTERN = re.compile(r"^\d+(\.\d+)?[smhd]?$")

USAGE_HELP_SYSTEM_PROMPT = (
    "You are a command-line syntax assistant supporting an autonomous "
    "penetration-testing agent working in a Kali Linux shell. The agent "
    "ran one command and it looks like the tool itself rejected the "
    "command line - wrong flag, wrong argument order, or a similar syntax "
    "mistake - not a network or target-side failure. You are given the "
    "exact command it ran, the output that came back, and a reference "
    "(a man page or --help/-h output) for that specific tool.\n\n"
    "Your ONLY job is to fix the command's SYNTAX so it runs the way the "
    "agent already intended - correct flag spelling, correct argument "
    "order/form, correct quoting. Do not change what the agent is trying "
    "to do, do not suggest a different tool, and do not suggest what "
    "target, service, or vulnerability to investigate or which one to try "
    "next - that is entirely the agent's own decision, not yours. If the "
    "reference doesn't let you tell what a valid corrected command would "
    "be, leave 'corrected_command' empty rather than guessing.\n\n"
    "In 'corrected_command', give ONE concrete, directly runnable corrected "
    "command line (empty string if you can't determine one). In "
    "'explanation', one short sentence on what was wrong with the "
    "original - syntax only, not strategy."
)


class _UsageSuggestion(BaseModel):
    corrected_command: str = ""
    explanation: str = ""


def _find_binary_token(tokens: List[str]) -> Optional[int]:
    """Index of the actual binary token within `tokens`, skipping past any
    leading env-assignment / sudo / env / timeout prefix tokens - e.g.
    ["sudo", "nmap", "-sV", ...] -> 1, ["FOO=bar", "hydra", ...] -> 1.
    Returns None if the token list is exhausted before a real binary is
    found (a bare prefix with nothing after it). Shared by
    _extract_binary_name and _maybe_inject_nmap_pn below - both need to
    locate the real binary past the same prefix shapes."""
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


# nmap's default host-discovery probes (a ping-scan-style pass before the
# actual port scan) go to a handful of common ports (80, 443, ICMP, ...)
# that this environment's nftables rules almost never authorize for a given
# target (see kali_manager.py's prepare_nftables) - without -Pn, those
# probes are unconditionally blocked ("Operation not permitted"/"Offending
# packet" noise) and the scan is left incomplete. This isn't a judgment
# call worth asking the agent to remember every time - the starting prompt
# already says "always include -Pn", but a model deep into a long run
# doesn't reliably keep re-applying a one-time instruction from turn one
# (observed in production: exactly this failure). -Pn is correct here
# essentially unconditionally, so add it automatically rather than relying
# on the agent to.
_NMAP_PN_INJECTED_NOTE = (
    "[Note: -Pn was added to this nmap command automatically - "
    "host-discovery probes to ports outside what's authorized for this "
    "target are always blocked in this environment, so -Pn (skip host "
    "discovery, scan directly) is effectively required for every nmap "
    "invocation here.]"
)


def _maybe_inject_nmap_pn(command: str) -> tuple[str, bool]:
    """If `command` invokes nmap without an explicit -Pn, inserts one right
    after the nmap token (past any sudo/env/timeout prefix - see
    _find_binary_token) and returns (rewritten command, True). Returns the
    original command unchanged (and False) for anything that doesn't parse,
    doesn't invoke nmap, or already has -Pn. Only rewrites the segment
    before a pipe, if any - anything piped into another command is left
    untouched."""
    segments = command.split("|", 1)
    try:
        tokens = shlex.split(segments[0])
    except ValueError:
        return command, False

    index = _find_binary_token(tokens)
    if index is None or os.path.basename(tokens[index]) != "nmap":
        return command, False
    if "-Pn" in tokens:
        return command, False

    new_tokens = tokens[: index + 1] + ["-Pn"] + tokens[index + 1 :]
    rewritten_first_segment = shlex.join(new_tokens)
    return "|".join([rewritten_first_segment] + segments[1:]), True


def _clean_man_output(text: str) -> str:
    text = _ANSI_ESCAPE_PATTERN.sub("", text)
    text = _OVERSTRIKE_PATTERN.sub("", text)
    return text


async def _fetch_usage_reference(manager: "KaliManger", binary: str) -> Optional[str]:
    """One-shot, isolated lookup of a tool's own usage documentation -
    never touches the agent's interactive session (uses manager.execute(),
    the same one-shot exec path as install_kali_package, not
    run_in_current_session), so this can't itself leave stray output
    sitting in whatever session the agent is mid-command in. Tries `man`
    first, falling back to --help/-h for tools that don't ship a man page
    at all (common for smaller/newer utilities)."""
    for candidate_command, is_man in (
        (f"MANWIDTH=100 man {binary} 2>&1", True),
        (f"{binary} --help 2>&1", False),
        (f"{binary} -h 2>&1", False),
    ):
        try:
            output = await manager.execute(
                candidate_command,
                user=KALI_USERS.momos,
                timeout_seconds=USAGE_HELP_TIMEOUT_SECONDS,
            )
        except RuntimeError:
            # Nonzero exit (e.g. "No manual entry for X", or --help itself
            # exiting non-zero as some tools do) - try the next fallback
            # rather than giving up on the first miss.
            continue

        if is_man and "no manual entry" in output.lower():
            continue

        cleaned = _clean_man_output(output).strip()
        if cleaned:
            return cleaned[:USAGE_REFERENCE_MAX_CHARS]

    return None


async def _suggest_command_fix(
    project_id: str, command: str, output: str, reference: str
) -> Optional[str]:
    """Asks the project's configured parsing model to propose a corrected
    invocation for a command that looks like it hit a syntax/usage error,
    given that tool's own man page/--help text. Returns None (never raises)
    on any failure - this is a best-effort assist layered on top of the
    regular tool result, not something that should ever break run() itself
    if the parsing model is unavailable or misbehaves."""
    project_settings = await _get_project_settings(project_id)
    parsing_model_name = project_settings.parsing_model_name if project_settings else None
    if not parsing_model_name:
        return None

    num_ctx = await _get_parsing_model_num_ctx(parsing_model_name, project_settings)
    parser_llm = ChatOllama(
        model=parsing_model_name, base_url=settings.ollama_url, num_ctx=num_ctx
    )
    structured_llm = parser_llm.with_structured_output(_UsageSuggestion)

    try:
        result = await structured_llm.ainvoke(
            [
                SystemMessage(content=USAGE_HELP_SYSTEM_PROMPT),
                HumanMessage(
                    content=(
                        f"Command attempted:\n{command}\n\n"
                        f"Output/error:\n{output}\n\n"
                        f"Reference (man/--help) for this tool:\n{reference}"
                    )
                ),
            ]
        )
    except Exception as e:
        print(f"Usage-help suggestion failed, skipping: {e}")
        return None

    corrected = result.corrected_command.strip()
    if not corrected:
        return None

    note = f"Suggested corrected command: {corrected}"
    if result.explanation.strip():
        note += f" ({result.explanation.strip()})"
    return note


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
    "approximate them. The local Kali session itself runs as user 'momos' - "
    "this string appearing in a shell prompt (e.g. 'momos@host:~$') or as a "
    "client's own default-username suggestion (e.g. ftp's 'Name "
    "(host:momos):') is your OWN local username, never a credential found "
    "on the target; never report it as one. A program asking for a "
    "username/password is not itself evidence of a credential - only an "
    "actual authentication result (success or failure) is. A bare network/"
    "transport-level connection succeeding (e.g. netcat's own \"Connection "
    "to <host> <port> succeeded!\", or a TCP port simply being open/"
    "reachable) is NOT evidence of anything at the application layer - "
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
    return await loop.run_in_executor(None, db_manager.get_project_settings, project_id)


# Per-process cache of a model's own capabilities (context window/thinking
# support), keyed by model name - a model's capabilities don't change during
# a run, and _parse_output/_suggest_command_fix are called on essentially
# every tool result, so re-fetching via Ollama's show() on every single call
# would be wasteful. Mirrors the per-run _usage_reference_cache pattern used
# for man pages inside create_terminal_tools below.
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
    project_settings = await _get_project_settings(project_id)
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
    "file listing or command result, or a clear stated error. A bare "
    "network/transport-level connection succeeding (e.g. netcat's own "
    "\"Connection to <host> <port> succeeded!\", or a TCP port simply "
    "being open/reachable) is NOT evidence of anything at the "
    "application layer - a login, authentication, or exploit claim needs "
    "an explicit application-level response from the actual service "
    "itself, not just a successful network connection to it. A username "
    "or password appearing only in the ATTEMPTED command (not echoed back "
    "with a server confirmation) is not a discovered credential - the "
    "agent's own local shell account is also never a target credential, "
    "even if it appears in the output (e.g. as a shell prompt or a "
    "client's own default-username suggestion).\n\n"
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

    project_settings = await _get_project_settings(project_id)
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
# USAGE_REFERENCE_MAX_CHARS's man-page truncation above: the start usually
# has the command's own banner/early results, the end usually has a scan's
# final summary - both are more useful than an equivalent-sized arbitrary
# slice out of the middle.
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
    caller in create_terminal_tools) not being one of _NETWORK_FACING_
    BINARIES at all. Previously every non-empty result was still sent to
    the parsing model "to summarize," and only the returned `facts` were
    discarded for a non-network-facing command - so a plain shell builtin
    (cd/ls/cat/whoami/...) was still a full LLM call, and a fresh chance
    for a small local model to hallucinate a "summary" out of it for
    nothing. Skipping the call entirely for these is both safer and
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


async def _resolve_current_session(manager: KaliManger, target_id: str, on_session_change):
    """Ensures target_id has a current session, opening a fresh default one
    if every session somehow ended up closed (idle timeout, process exit,
    ...) - start_agent() already opens "default" before the first turn, so
    this is only a defensive fallback. Returns (session, was_replaced) -
    was_replaced is True exactly when this call itself had to silently open
    the replacement, so the caller can tell the model its previous session
    is gone. Raises KaliSessionError if even opening a fresh one fails."""
    was_replaced = not manager.has_current_session(target_id)
    if was_replaced:
        await manager.open_session(target_id, DEFAULT_SESSION_NAME, DEFAULT_SESSION_COMMAND)
        on_session_change(DEFAULT_SESSION_NAME, DEFAULT_SESSION_COMMAND)
    return manager.get_current_session(target_id), was_replaced


async def _send_and_condense(
    manager: KaliManger,
    project_id: str,
    target_id: str,
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
            target_id, input, wait_seconds=wait_seconds
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
            target_id, DEFAULT_SESSION_NAME, DEFAULT_SESSION_COMMAND
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


async def _install_kali_package(project_id: str, package: str) -> str:
    if not PACKAGE_NAME_PATTERN.match(package):
        return (
            f"Invalid package name '{package}'. Only a single, bare apt "
            "package name is allowed - lowercase letters, digits, '+', '-', "
            "'.', starting with a letter or digit. No flags, paths, spaces, "
            "or shell operators."
        )

    manager = await kali_registry.get_manager(project_id)

    # Shares command_lock with the (now commented-out) one-shot execute
    # path - an apt-get invocation holds dpkg's lock for its whole run, so
    # a concurrent install would fail against it anyway.
    async with manager.command_lock:
        try:
            # `env VAR=val cmd` rather than a bare `VAR=val cmd` prefix -
            # execute() wraps this in `timeout <secs> <command>`, and
            # `timeout` execs its next token directly (no shell), so a
            # leading VAR=val there isn't treated as an env assignment, it's
            # passed straight to timeout as the (nonexistent) command to
            # run, failing with exit 127. `env` is a real binary timeout can
            # exec, and it sets the var before exec'ing apt-get itself.
            output = await manager.execute(
                f"env DEBIAN_FRONTEND=noninteractive apt-get install -y {package}",
                user=KALI_USERS.root,
                timeout_seconds=PACKAGE_INSTALL_TIMEOUT_SECONDS,
            )
        except RuntimeError as e:
            return f"Failed to install package '{package}': {e}"

    return f"Package '{package}' installed successfully.\n\n{output.strip()}"


def create_install_package_tool(project_id: str):
    """Builds an install_kali_package tool bound to a specific project's Kali container."""

    @tool(INSTALL_PACKAGE_TOOL_NAME)
    async def install_kali_package(package: str) -> str:
        """Installs a single apt package inside the Kali container (runs as
        root, equivalent to `apt install <package>`). Use this when a tool
        you need isn't already installed. Only a bare package name is
        accepted - no flags, paths, spaces, or shell operators (e.g.
        "hydra", not "hydra; rm -rf /" or "-y hydra"). Installing can take a
        while for larger packages.

        Your regular terminal session (run()) is NOT root - `apt`,
        `apt-get`, `dpkg`, and anything else needing root will fail there
        with a permission error. This tool is the only way to install
        something; do not try `apt install`/`apt update` directly in run().

        Args:
            package: The exact apt package name to install, e.g. "hydra" or
                "metasploit-framework".
        """
        return await _install_kali_package(project_id, package)

    return install_kali_package


async def _run_kali_command(
    project_id: str, command: str, on_enumeration: Callable[[dict], None]
) -> str:
    """Retained but unused by build_agent_tools (see create_kali_tool) -
    the underlying one-shot exec path, kept intact rather than deleted in
    case the terminal/session-only model doesn't pan out."""
    manager = await kali_registry.get_manager(project_id)

    async with manager.command_lock:
        try:
            raw_output = await manager.execute(command)
        except RuntimeError as e:
            raw_output = str(e)

        if not raw_output.strip():
            return "(command produced no output)"

        return await _parse_output(project_id, command, raw_output, on_enumeration)


def create_kali_tool(project_id: str, on_enumeration: Callable[[dict], None]):
    """Builds an execute_kali_command tool bound to a specific project's
    Kali container. NOT wired into build_agent_tools right now - having
    both this one-shot path and the session tools as two ways to "run
    something" is exactly what made the agent unreliably pick between them
    (see the terminal-tools redesign). Kept intact, commented out at the
    call site, so it's a one-line change to bring back."""

    @tool(KALI_COMMAND_TOOL_NAME)
    async def execute_kali_command(command: str) -> str:
        """Executes a command in the Kali Linux container and returns a condensed
        summary of its output. Use this for anything that runs to completion
        on its own (nmap, curl, gobuster, cat, ls, ...) - note that every
        call is a fresh, independent process with no memory of previous
        calls. For anything interactive or stateful that needs to stay open
        and be driven turn by turn, use the session tools instead."""
        return await _run_kali_command(project_id, command, on_enumeration)

    return execute_kali_command


# ---------------------------------------------------------------------------
# Tier 1 (one-shot structured tools) and Tier 2 (guided session tools) - see
# create_pentest_tools/create_guided_session_tools below. Always registered
# by build_agent_tools regardless of allow_shell: these are the constrained,
# structured/guided alternative to the raw shell, not something gated behind
# it - a project with allow_shell=False still has real, working access to
# the highest-value pentesting commands and to ftp/ssh/telnet.
# ---------------------------------------------------------------------------

async def _get_target_info(target_id: str) -> Tuple[Optional[Target], Optional[str]]:
    """Returns (target, error_message) - the full Target row, for a tool
    that needs more than just the host (e.g. nmap_scan validating `ports`
    against target.ports)."""
    loop = asyncio.get_running_loop()
    target = await loop.run_in_executor(None, db_manager.get_target, target_id)
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


# Every free-text argument accepted by the tools below is either restricted
# to one of these narrow structural patterns (for things that genuinely
# have a fixed format - ports, file paths, an Exploit-DB ID) or passed
# through _safe_shell_word/_safe_join_args (shlex-quoting - the actual
# injection defense for arbitrary text like a password or a search query)
# before being interpolated into a shell command string - these still run
# via `bash -c` inside the container (KaliManger.execute/_exec_in_container),
# the same reasoning as PACKAGE_NAME_PATTERN's for install_kali_package, not
# a formality.
_SAFE_PORT_SPEC_PATTERN = re.compile(r"^[\d,-]+$")
_SAFE_PATH_PATTERN = re.compile(r"^[\w./-]+$")
_SAFE_EXTENSIONS_PATTERN = re.compile(r"^[\w,]*$")
_SAFE_EDB_ID_PATTERN = re.compile(r"^\d+$")


def _expand_port_spec(spec: str) -> set:
    """Expands an already-_SAFE_PORT_SPEC_PATTERN-validated port spec like
    "21,25,53" or "1-100" into the concrete set of port numbers it names -
    used to validate a requested scan against the target's own authorized
    ports before ever invoking nmap (see nmap_scan)."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return ports


def _safe_shell_word(value: str) -> str:
    return shlex.quote(value)


def _safe_join_args(args: str) -> Optional[str]:
    """Splits `args` into words the way a user typing them at a prompt
    would (shlex), then re-quotes each resulting token individually - so a
    multi-argument string like "192.168.0.235 21" reaches the eventual
    command as two separate argv words, exactly as intended, while
    anything that looks like a shell metacharacter inside one token is
    neutralized as literal text rather than interpreted. Returns None if
    `args` can't even be tokenized (unbalanced quotes, ...)."""
    try:
        tokens = shlex.split(args)
    except ValueError:
        return None
    return " ".join(shlex.quote(t) for t in tokens)


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


NMAP_SCAN_TIMEOUT_SECONDS = 240
HYDRA_BRUTEFORCE_TIMEOUT_SECONDS = 300
GOBUSTER_SCAN_TIMEOUT_SECONDS = 300
SEARCHSPLOIT_LOOKUP_TIMEOUT_SECONDS = 30
SEARCHSPLOIT_RUN_TIMEOUT_SECONDS = 120
SSH_CHECK_LOGIN_TIMEOUT_SECONDS = 20
SSH_RUN_TIMEOUT_SECONDS = 60
TELNET_PROBE_TIMEOUT_SECONDS = 15

_NMAP_TIMING_FLAGS = {
    "paranoid": "-T0", "sneaky": "-T1", "polite": "-T2",
    "normal": "-T3", "aggressive": "-T4", "insane": "-T5",
}
# Matches nmap's normal port-table row, e.g.
# "21/tcp   open  ftp     vsftpd 2.3.4".
_NMAP_PORT_LINE = re.compile(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$", re.MULTILINE)


def _parse_nmap_output(raw_output: str) -> Dict[str, dict]:
    """Deterministic, LLM-free extraction of nmap's own port table -
    including, when -sC was used, the indented '|'-prefixed NSE script
    lines directly beneath each port (appended to that port's notes), so
    script findings reach the enumeration table too, not just the bare
    version string. Only ever reads what nmap itself printed - see
    PARSER_SYSTEM_PROMPT's history for why this bypasses the LLM parser
    entirely rather than trusting it with the same output."""
    entries: Dict[str, dict] = {}
    current_port: Optional[str] = None
    for line in raw_output.splitlines():
        match = _NMAP_PORT_LINE.match(line)
        if match:
            port, _proto, state, service, version = match.groups()
            if not state.startswith("open"):
                current_port = None
                continue
            current_port = port
            entries[port] = {"service": service, "version": (version or "").strip(), "notes": ""}
            continue
        if current_port is not None and line.startswith("|"):
            entries[current_port]["notes"] = (
                f"{entries[current_port]['notes']}\n{line.strip()}"
                if entries[current_port]["notes"]
                else line.strip()
            )
        elif not line.strip():
            current_port = None
    return entries


def _summarize_nmap_entries(entries: Dict[str, dict]) -> str:
    """Builds a human-readable digest from _parse_nmap_output's result for
    nmap_scan's returned content - one port/service/version header per
    port, each followed by that port's full NSE script notes, structured
    per-port instead of dumping the entire raw scan as one undifferentiated
    blob (the previous behavior - the only tool result that wasn't actually
    condensed, unlike everything else in this module)."""
    sections = []
    for port in sorted(entries, key=int):
        info = entries[port]
        service = info.get("service", "")
        version = info.get("version", "")
        header = f"{port}/tcp {service}" + (f" {version}" if version else "")

        notes = (info.get("notes") or "").strip()
        if not notes:
            sections.append(header)
            continue

        indented = "\n".join(f"  {line}" for line in notes.splitlines())
        sections.append(f"{header}\n{indented}")
    return "\n\n".join(sections)


_HYDRA_DEFAULT_PORTS = {"ftp": 21, "ssh": 22, "telnet": 23, "mysql": 3306, "smtp": 25, "pop3": 110}
# Matches hydra's own success-line format, e.g.
# "[21][ftp] host: 192.168.0.235   login: anonymous   password: "
_HYDRA_SUCCESS_LINE = re.compile(
    # [ \t] rather than \s for the separators - \s also matches a newline,
    # and a blank password (the anonymous-FTP case) leaves nothing but a
    # trailing space before end-of-line for the final \s+ to greedily
    # consume ACROSS into the next line, capturing garbage from whatever
    # follows instead of the intended empty string.
    r"^\[(\d+)\]\[(\S+)\][ \t]+host:[ \t]+(\S+)[ \t]+login:[ \t]+(\S*)[ \t]+password:[ \t]*(.*)$",
    re.MULTILINE,
)

# Matches gobuster dir mode's own output line, e.g.
# "/admin (Status: 301) [Size: 315]".
_GOBUSTER_LINE = re.compile(r"^(\S+)\s+\(Status:\s+(\d+)\)(?:\s+\[Size:\s+(\d+)\])?", re.MULTILINE)
DEFAULT_GOBUSTER_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

SEARCHSPLOIT_EXPLOITDB_PREFIX = "/usr/share/exploitdb/"
_SEARCHSPLOIT_PATH_LINE = re.compile(r"^\s*Path:\s*(\S+)", re.MULTILINE)
_SEARCHSPLOIT_INTERPRETER_BY_EXTENSION = {".py": "python3", ".pl": "perl", ".rb": "ruby", ".sh": "bash"}


async def _resolve_exploit_path(project_id: str, edb_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Returns (path, error) - resolves an Exploit-DB ID to its mirrored
    file path via `searchsploit -p`, deterministically (a regex on
    searchsploit's own fixed "Path: ..." line, not the LLM parser), and
    defensively rejects anything outside exploitdb's own directory (not
    expected to ever actually trigger)."""
    ok, output = await _execute_one_shot(
        project_id, f"searchsploit -p {edb_id}", SEARCHSPLOIT_LOOKUP_TIMEOUT_SECONDS
    )
    if not ok:
        return None, output
    match = _SEARCHSPLOIT_PATH_LINE.search(output)
    if not match:
        return None, f"Could not resolve EDB-ID {edb_id} to a file.\n\n{output}"
    path = match.group(1)
    if not path.startswith(SEARCHSPLOIT_EXPLOITDB_PREFIX):
        return None, f"Resolved path '{path}' is outside the exploit-db directory - refusing."
    return path, None


# Exploit-db mirrors both standalone scripts and Metasploit-framework
# modules as plain .rb files in the same directories - path alone can't
# tell them apart. A Metasploit module (require 'msf/core', include
# Msf::Exploit, ...) isn't a standalone script; it only runs inside
# msfconsole, and trying to run one via a bare `ruby` interpreter fails
# with a confusing RubyGems/framework-loading traceback (observed in
# production: EDB-ID 17491). Checked by content instead.
_METASPLOIT_MODULE_MARKERS = ("msf/core", "Msf::Exploit", "MetasploitModule", "class Metasploit")


async def _looks_like_metasploit_module(project_id: str, path: str) -> bool:
    ok, head = await _execute_one_shot(project_id, f"head -c 4000 {shlex.quote(path)}", 10)
    return ok and any(marker in head for marker in _METASPLOIT_MODULE_MARKERS)


def create_pentest_tools(
    project_id: str,
    target_id: str,
    on_enumeration: Callable[[dict], None],
    mark_tested: Callable[[], None],
    on_raw_output: Callable[[str], None],
) -> list:
    """Tier 1: one-shot, typed-argument tools for the highest-value
    pentesting commands - no free-text host/command, no session involved
    (KaliManger.execute, not run_in_current_session), and deterministic
    parsing straight into the enumeration table instead of the LLM parser
    (nmap/hydra/gobuster via regex, searchsploit via its own --json output)
    - the small local parsing model has repeatedly hallucinated facts from
    exactly this kind of output (see PARSER_SYSTEM_PROMPT's history), so
    these bypass it entirely."""

    @tool(NMAP_SCAN_TOOL_NAME, response_format="content_and_artifact")
    async def nmap_scan(
        ports: Optional[str] = None,
        run_default_scripts: bool = False,
        timing: Optional[
            Literal["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"]
        ] = None,
    ) -> str:
        """Runs nmap -Pn -sV against this run's target and returns its
        parsed port table - no host to type, and no way to point it at
        anything outside this run's own target.

        Args:
            ports: Port(s)/range to scan, e.g. "21" or "21,80,443" or
                "1-1000". Omit to use nmap's own default port set.
            run_default_scripts: Also run nmap's default NSE script set
                (-sC) - often finds far more than a bare version scan
                (e.g. anonymous-FTP/vuln-check scripts), at the cost of a
                slower scan.
            timing: Timing/aggressiveness template - "paranoid"/"sneaky"
                are slower and quieter, "aggressive"/"insane" are faster
                and noisier. Omit for nmap's normal default.
        """
        target, error = await _get_target_info(target_id)
        if error:
            return error, None
        host = target.ipv4 or target.ipv6
        if not host:
            return "This target has no IPv4/IPv6 address configured - cannot proceed.", None

        if ports is not None:
            if not _SAFE_PORT_SPEC_PATTERN.match(ports):
                return (
                    "Invalid `ports` - use digits, commas, and hyphens only "
                    '(e.g. "21,80" or "1-1000").',
                    None,
                )
            if target.ports:
                requested = _expand_port_spec(ports)
                out_of_scope = sorted(requested - set(target.ports))
                if out_of_scope:
                    return (
                        f"Port(s) {', '.join(map(str, out_of_scope))} are "
                        "outside this target's authorized scope "
                        f"({', '.join(map(str, sorted(target.ports)))}) - "
                        "refusing to scan them. Use only authorized ports.",
                        None,
                    )

        flags = ["nmap", "-Pn", "-sV"]
        if run_default_scripts:
            flags.append("-sC")
        if timing:
            flags.append(_NMAP_TIMING_FLAGS[timing])
        if ports:
            flags += ["-p", ports]
        flags.append(host)

        ok, output = await _execute_one_shot(
            project_id, " ".join(flags), NMAP_SCAN_TIMEOUT_SECONDS
        )
        mark_tested()
        if not ok:
            return output, None
        on_raw_output(output)

        entries = _parse_nmap_output(output)
        if entries:
            on_enumeration(entries)
            ports_found = ", ".join(sorted(entries, key=int))
            summary = _summarize_nmap_entries(entries)
            return f"Found {len(entries)} open port(s): {ports_found}.\n\n{summary}", output
        return output, output

    @tool(HYDRA_BRUTEFORCE_TOOL_NAME, response_format="content_and_artifact")
    async def hydra_bruteforce(
        service: Literal["ftp", "ssh", "telnet", "mysql", "smtp", "pop3"],
        port: Optional[int] = None,
        username: Optional[str] = None,
        username_list: Optional[str] = None,
        password: Optional[str] = None,
        password_list: Optional[str] = None,
    ) -> str:
        """Tries username/password combinations against this run's
        target's `service`. Give either a single `username` or a
        `username_list` file path (not both), and either a single
        `password` or a `password_list` file path (not both). For an
        anonymous-FTP check, omit all four credential args - defaults to
        username "anonymous" with a blank password.

        Args:
            service: Which service to attack.
            port: Port to connect to. Omit to use the service's standard
                port.
            username: A single username to try.
            username_list: Path to an existing file of usernames (one per
                line) inside the Kali container.
            password: A single password to try.
            password_list: Path to an existing file of passwords inside
                the Kali container.
        """
        host, error = await _get_target_host(target_id)
        if error:
            return error, None

        if (
            service == "ftp"
            and username is None
            and username_list is None
            and password is None
            and password_list is None
        ):
            username, password = "anonymous", ""

        if username is None and username_list is None:
            return "Provide either `username` or `username_list`.", None
        if password is None and password_list is None:
            return "Provide either `password` or `password_list`.", None
        if username is not None and username_list is not None:
            return "Provide only one of `username`/`username_list`, not both.", None
        if password is not None and password_list is not None:
            return "Provide only one of `password`/`password_list`, not both.", None

        for path in (username_list, password_list):
            if path is None:
                continue
            if not _SAFE_PATH_PATTERN.match(path):
                return f"Invalid file path '{path}'.", None
            if not await _file_exists_in_container(project_id, path):
                return f"File '{path}' does not exist in the Kali container.", None

        flags = ["hydra"]
        if username is not None:
            flags += ["-l", _safe_shell_word(username)]
        else:
            flags += ["-L", username_list]
        if password is not None:
            flags += ["-p", _safe_shell_word(password)]
        else:
            flags += ["-P", password_list]
        flags.append(f"{service}://{host}:{port or _HYDRA_DEFAULT_PORTS[service]}")

        ok, output = await _execute_one_shot(
            project_id, " ".join(flags), HYDRA_BRUTEFORCE_TIMEOUT_SECONDS
        )
        mark_tested()
        if not ok:
            return output, None
        on_raw_output(output)

        matches = list(_HYDRA_SUCCESS_LINE.finditer(output))
        if not matches:
            return f"No valid credentials found.\n\n{output}", output

        entries: Dict[str, dict] = {}
        for m in matches:
            found_port, found_service, _found_host, login, pw = m.groups()
            entries[found_port] = {
                "service": found_service,
                "version": "",
                "notes": f"hydra: valid credentials login={login!r} password={pw!r}",
            }
        on_enumeration(entries)
        return f"Valid credentials found!\n\n{output}", output

    @tool(GOBUSTER_SCAN_TOOL_NAME, response_format="content_and_artifact")
    async def gobuster_scan(
        port: int = 80,
        use_tls: bool = False,
        wordlist: Optional[str] = None,
        extensions: Optional[str] = None,
    ) -> str:
        """Directory/file brute-forces this run's target's web server on
        `port` using gobuster.

        Args:
            port: Web server port to scan. Defaults to 80.
            use_tls: Use https instead of http.
            wordlist: Path to an existing wordlist file inside the Kali
                container. Defaults to a small, fast built-in list.
            extensions: Comma-separated file extensions to also try, e.g.
                "php,txt,html". Omit for none.
        """
        host, error = await _get_target_host(target_id)
        if error:
            return error, None

        wordlist = wordlist or DEFAULT_GOBUSTER_WORDLIST
        if not _SAFE_PATH_PATTERN.match(wordlist):
            return f"Invalid wordlist path '{wordlist}'.", None
        if not await _file_exists_in_container(project_id, wordlist):
            return f"Wordlist '{wordlist}' does not exist in the Kali container.", None
        if extensions is not None and not _SAFE_EXTENSIONS_PATTERN.match(extensions):
            return (
                "Invalid `extensions` - comma-separated alphanumeric "
                'extensions only, e.g. "php,txt".',
                None,
            )

        scheme = "https" if use_tls else "http"
        flags = ["gobuster", "dir", "-u", f"{scheme}://{host}:{port}/", "-w", wordlist, "-q"]
        if extensions:
            flags += ["-x", extensions]

        ok, output = await _execute_one_shot(
            project_id, " ".join(flags), GOBUSTER_SCAN_TIMEOUT_SECONDS
        )
        mark_tested()
        if not ok:
            return output, None
        on_raw_output(output)

        matches = list(_GOBUSTER_LINE.finditer(output))
        if not matches:
            return output, output

        findings = "; ".join(f"{m.group(1)} (Status: {m.group(2)})" for m in matches)
        on_enumeration({str(port): {"service": scheme, "version": "", "notes": findings}})
        return f"Found {len(matches)} path(s).\n\n{output}", output

    @tool(SEARCHSPLOIT_SEARCH_TOOL_NAME, response_format="content_and_artifact")
    async def searchsploit_search(query: str) -> str:
        """Searches the local exploit-database (exploit-db) mirror for
        `query` (e.g. a service name and version, like "vsftpd 2.3.4")
        and returns matching Exploit-DB IDs and titles. Use
        searchsploit_view to read a candidate's source, then
        searchsploit_run to actually run it.

        Args:
            query: Search terms, e.g. "vsftpd 2.3.4".
        """
        ok, output = await _execute_one_shot(
            project_id,
            f"searchsploit --json {_safe_shell_word(query)}",
            SEARCHSPLOIT_LOOKUP_TIMEOUT_SECONDS,
        )
        mark_tested()
        if not ok:
            return output, None
        on_raw_output(output)

        try:
            data = json.loads(output)
        except ValueError:
            return output, output

        results = data.get("RESULTS_EXPLOIT", [])
        if not results:
            return "No matching exploits found.", output

        lines = [f"{r.get('EDB-ID', '?')}: {r.get('Title', '')}" for r in results]
        return "\n".join(lines), output

    @tool(SEARCHSPLOIT_VIEW_TOOL_NAME, response_format="content_and_artifact")
    async def searchsploit_view(edb_id: str) -> str:
        """Reads the source of exploit-db entry `edb_id` (from
        searchsploit_search) - use this to see what language it's in and
        what arguments/target format it expects before running it.

        Args:
            edb_id: The numeric Exploit-DB ID, e.g. "49757".
        """
        if not _SAFE_EDB_ID_PATTERN.match(edb_id):
            return "Invalid edb_id - digits only.", None
        path, error = await _resolve_exploit_path(project_id, edb_id)
        mark_tested()
        if error:
            return error, None

        ok, output = await _execute_one_shot(
            project_id, f"cat {shlex.quote(path)}", SEARCHSPLOIT_LOOKUP_TIMEOUT_SECONDS
        )
        if not ok:
            return output, None
        on_raw_output(output)
        return output, output

    @tool(SEARCHSPLOIT_RUN_TOOL_NAME, response_format="content_and_artifact")
    async def searchsploit_run(edb_id: str, exploit_args: str = "") -> str:
        """Runs exploit-db entry `edb_id` (from searchsploit_search)
        against whatever it's given in `exploit_args` - read it first with
        searchsploit_view to see what it expects (target/port/etc. as its
        own arguments; you already know this run's target's address).
        Only works for a plain Python/Perl/Ruby/shell script - a script
        needing further interactive back-and-forth of its own isn't a
        good fit for this one-shot tool.

        Args:
            edb_id: The numeric Exploit-DB ID, e.g. "49757".
            exploit_args: Arguments to pass to the exploit script,
                space-separated exactly as you would type them, e.g.
                "192.168.0.235 21".
        """
        if not _SAFE_EDB_ID_PATTERN.match(edb_id):
            return "Invalid edb_id - digits only.", None
        path, error = await _resolve_exploit_path(project_id, edb_id)
        if error:
            mark_tested()
            return error, None

        _, ext = os.path.splitext(path)
        if ext == ".rb" and await _looks_like_metasploit_module(project_id, path):
            mark_tested()
            return (
                "This is a Metasploit-framework module, not a standalone "
                "script - it needs the full msfconsole runtime (`require "
                "'msf/core'`), not a bare `ruby` interpreter. If "
                "allow_shell is enabled, drive msfconsole yourself via "
                "run() instead (e.g. search for the right module name "
                'with `msfconsole -q -x "search <name>"`).',
                None,
            )

        interpreter = _SEARCHSPLOIT_INTERPRETER_BY_EXTENSION.get(ext)
        if interpreter is None:
            mark_tested()
            return (
                f"Don't know how to run a '{ext}' file - use "
                "searchsploit_view to read it, and run() it yourself if "
                "allow_shell is enabled.",
                None,
            )

        safe_args = _safe_join_args(exploit_args) if exploit_args else ""
        if exploit_args and safe_args is None:
            return "Could not parse `exploit_args` - check for unbalanced quotes.", None

        command = f"{interpreter} {shlex.quote(path)} {safe_args}".strip()
        ok, output = await _execute_one_shot(project_id, command, SEARCHSPLOIT_RUN_TIMEOUT_SECONDS)
        mark_tested()
        if not ok:
            return output, None
        on_raw_output(output)
        return output, output

    return [
        nmap_scan,
        hydra_bruteforce,
        gobuster_scan,
        searchsploit_search,
        searchsploit_view,
        searchsploit_run,
    ]


FTP_SESSION_NAME = "ftp"


async def _ensure_ftp_session(manager: KaliManger, target_id: str, host: str, on_session_change):
    """Opens target_id's 'ftp' session if it doesn't exist yet (running
    `ftp -n {host}` - -n suppresses ftp's own immediate auto-login prompt,
    since login is driven explicitly via the `user` command in
    ftp_connect below, not the interactive Name:/Password: exchange), or
    switches to it if it already exists - either way, returns the
    now-current KaliSession for it, plus whether this call itself opened a
    brand-new session (vs. reusing an already-open, possibly already-
    authenticated one - see ftp_connect's _ftp_logged_in tracking)."""
    command = f"ftp -n {host}"
    sessions = await manager.list_sessions(target_id)
    existing = next((s for s in sessions if s.name == FTP_SESSION_NAME and not s.closed), None)
    freshly_opened = existing is None
    if existing is None:
        await manager.open_session(target_id, FTP_SESSION_NAME, command)
    elif manager.get_current_session_name(target_id) != FTP_SESSION_NAME:
        await manager.switch_session(target_id, FTP_SESSION_NAME)
    on_session_change(FTP_SESSION_NAME, command)
    return manager.get_current_session(target_id), freshly_opened


def create_guided_session_tools(
    project_id: str,
    target_id: str,
    on_enumeration: Callable[[dict], None],
    mark_tested: Callable[[], None],
    on_session_change: Callable[[Optional[str], Optional[str]], None],
    on_prompt_state_change: Callable[[bool], None],
    on_raw_output: Callable[[str], None],
) -> list:
    """Tier 2: guided wrappers around the three interactive protocols the
    agent needs most often (ftp/ssh/telnet), for when it doesn't know -
    or keeps getting wrong - the underlying client's own syntax (observed
    in production: typing the raw USER/PASS wire-protocol commands into
    ftp's interactive Name:/Password: prompts, which want bare values).
    Unlike Tier 1, ftp_connect/ftp_command use the real session machinery
    (_resolve_current_session/_send_and_condense - the same helpers run()
    itself uses), so they get the exact same stuck-session confusion
    detection and auto-recovery for free."""

    # Per-target FTP login state, closure-scoped (fresh per Agent/run, so
    # it can never leak across independent test runs the way a module-level
    # dict would). Lets ftp_connect tell "already logged in, this re-auth
    # attempt is pointless" apart from "actually failed" - see ftp_connect's
    # own comment for the production bug this fixes.
    _ftp_logged_in: Dict[str, bool] = {}

    @tool(FTP_CONNECT_TOOL_NAME, response_format="content_and_artifact")
    async def ftp_connect(username: str = "anonymous", password: str = "") -> str:
        """Connects to this run's target's FTP service and logs in -
        handles ftp's own login sequence for you, so there's no need to
        figure out its interactive Name:/Password: prompts or type raw
        protocol commands (USER/PASS) yourself; just give the credentials
        to try. Only call this once per set of credentials - once it
        reports a successful login, the session is already open and
        authenticated, so use ftp_command for everything else (ls, get,
        pwd, cd, ...) instead of calling this again. Only retry this tool
        if the previous call actually failed (login failed, connection
        dropped) or you need to try different credentials.

        Args:
            username: FTP username to try. Defaults to "anonymous".
            password: Password to try. Defaults to blank (the
                anonymous-FTP convention).
        """
        if "\n" in username or "\r" in username or "\n" in password or "\r" in password:
            return "Username/password cannot contain newlines.", None

        host, error = await _get_target_host(target_id)
        if error:
            return error, None

        manager = await kali_registry.get_manager(project_id)
        try:
            current_session, freshly_opened = await _ensure_ftp_session(
                manager, target_id, host, on_session_change
            )
        except KaliSessionError as e:
            return str(e), None

        if freshly_opened:
            _ftp_logged_in[target_id] = False
        elif _ftp_logged_in.get(target_id):
            # Observed in production: re-sending `user` into an already-
            # authenticated session gets a real but misleading "530 Can't
            # change from guest user" - vsftpd correctly refusing
            # re-authentication mid-session, which the (correct) reply-code
            # regex below reads as "Login failed", even though the session
            # was in fact already logged in and working.
            return (
                "Already connected and logged in on this FTP session - no "
                "need to reconnect. Use ftp_command for anything else "
                "(ls, get, pwd, cd, ...).",
                None,
            )

        # Sent as two separate lines, mirroring exactly what a human typing
        # at ftp's own interactive Name:/Password: prompts would send - NOT
        # "user <name> <password>" on one line. A blank password
        # interpolated into one line contributes no second token at all
        # (observed in production: the anonymous-FTP case left the session
        # sitting unanswered at its own "Password:" sub-prompt, since
        # nothing was ever sent for it).
        condensed, raw_output = await _send_and_condense(
            manager,
            project_id,
            target_id,
            current_session,
            f"user {username}",
            SESSION_OPEN_READ_SECONDS,
            on_enumeration,
            mark_tested,
            on_session_change,
            on_prompt_state_change,
            on_raw_output,
        )
        if raw_output is None:
            return condensed, None

        # "Not connected." is ftp's own client-side reply to `user` when
        # there is no actual control connection to send it over - observed
        # in production on a session _ensure_ftp_session reused that had
        # gone dead (sessions aren't closed between agent runs, only
        # "default" is touched at run start - see Agent.start_agent), which
        # then stayed broken for the rest of every subsequent run against
        # this target, since nothing else ever re-opens it. One automatic
        # close+reopen+retry here, rather than reporting a dead session as
        # just another "unclear" login outcome.
        if "Not connected." in raw_output:
            await manager.close_session(target_id, FTP_SESSION_NAME)
            try:
                current_session, _ = await _ensure_ftp_session(
                    manager, target_id, host, on_session_change
                )
            except KaliSessionError as e:
                return str(e), None
            _ftp_logged_in[target_id] = False
            condensed, raw_output = await _send_and_condense(
                manager,
                project_id,
                target_id,
                current_session,
                f"user {username}",
                SESSION_OPEN_READ_SECONDS,
                on_enumeration,
                mark_tested,
                on_session_change,
                on_prompt_state_change,
                on_raw_output,
            )
            if raw_output is None:
                return condensed, None
            if "Not connected." in raw_output:
                return (
                    "Could not establish an FTP control connection to this "
                    "target even after reopening the session - the service "
                    "may be down or unreachable right now rather than a "
                    "stale-session issue. Re-check with nmap_scan before "
                    "retrying.",
                    raw_output,
                )

        # Only sent if the ftp session is still the current one - a
        # confusion-streak promotion triggered by the line above (unlikely
        # this early, but possible if the session was already stuck from an
        # earlier attempt) would otherwise send the password into whatever
        # session became current instead.
        if manager.get_current_session_name(target_id) == FTP_SESSION_NAME:
            current_session = manager.get_current_session(target_id)
            condensed2, raw_output2 = await _send_and_condense(
                manager,
                project_id,
                target_id,
                current_session,
                password,
                SESSION_OPEN_READ_SECONDS,
                on_enumeration,
                mark_tested,
                on_session_change,
                on_prompt_state_change,
                on_raw_output,
            )
            if raw_output2 is not None:
                condensed = f"{condensed}\n{condensed2}"
                raw_output = f"{raw_output}\n{raw_output2}"

        # Line-anchored, real FTP reply-code format ("CODE text" or
        # "CODE-text" at the START of a line) - NOT a bare \b23\d\b
        # anywhere in the text. Observed in production: that looser form
        # matched "235" inside the target's own IP address
        # (192.168.0.235, echoed back in "Connected to ...") and reported
        # a successful login before the password had even been sent.
        if re.search(r"(?m)^230[ -]", raw_output):
            prefix = "Login successful."
            _ftp_logged_in[target_id] = True
        elif re.search(r"(?m)^5\d\d[ -]", raw_output):
            prefix = "Login failed."
            _ftp_logged_in[target_id] = False
        else:
            prefix = "Login outcome unclear from the response - check the raw output below."

        return f"{prefix}\n\n{condensed}", raw_output

    @tool(FTP_COMMAND_TOOL_NAME, response_format="content_and_artifact")
    async def ftp_command(command: str) -> str:
        """Sends one command to your already-open, already-authenticated
        FTP session (ls, get, pwd, cd, binary, ...) - call ftp_connect
        first if you haven't yet, but once it reports a successful login
        you are already logged in and should use this tool for every
        further command instead of calling ftp_connect again. Not gated
        by shell access: ftp's own command grammar can't reach outside
        the already-open connection to the target.

        Args:
            command: The ftp command to send, e.g. "ls" or "get file.txt".
        """
        if "\n" in command or "\r" in command:
            return "Command cannot contain newlines - send one command at a time.", None

        manager = await kali_registry.get_manager(project_id)
        sessions = await manager.list_sessions(target_id)
        existing = next((s for s in sessions if s.name == FTP_SESSION_NAME and not s.closed), None)
        if existing is None:
            return "No FTP session is currently open - call ftp_connect first.", None
        if manager.get_current_session_name(target_id) != FTP_SESSION_NAME:
            try:
                await manager.switch_session(target_id, FTP_SESSION_NAME)
            except KaliSessionError as e:
                return str(e), None
        current_session = manager.get_current_session(target_id)

        return await _send_and_condense(
            manager,
            project_id,
            target_id,
            current_session,
            command,
            SESSION_OPEN_READ_SECONDS,
            on_enumeration,
            mark_tested,
            on_session_change,
            on_prompt_state_change,
            on_raw_output,
        )

    @tool(SSH_CHECK_LOGIN_TOOL_NAME, response_format="content_and_artifact")
    async def ssh_check_login(username: str, password: str) -> str:
        """Tries exactly one username/password pair against this run's
        target's SSH service and reports success or failure - use this to
        confirm a single candidate credential (e.g. found elsewhere); for
        trying many candidates at once use
        hydra_bruteforce(service="ssh", ...) instead.

        Args:
            username: SSH username to try.
            password: SSH password to try.
        """
        host, error = await _get_target_host(target_id)
        if error:
            return error, None

        command = (
            f"sshpass -p {shlex.quote(password)} ssh -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=10 {shlex.quote(username)}@{host} exit"
        )
        ok, output = await _execute_one_shot(project_id, command, SSH_CHECK_LOGIN_TIMEOUT_SECONDS)
        mark_tested()
        on_raw_output(output)
        if ok:
            return f"Login successful for '{username}'.\n\n{output}", output
        return f"Login failed for '{username}' (or a connection error).\n\n{output}", output

    @tool(SSH_RUN_TOOL_NAME, response_format="content_and_artifact")
    async def ssh_run(username: str, password: str, command: str) -> str:
        """Logs into this run's target over SSH and runs exactly one
        command, returning its output. If login itself fails, that shows
        up in the output text (e.g. "Permission denied") rather than as a
        separate error - there's no persistent shell here, just one
        authenticated command per call.

        Args:
            username: SSH username.
            password: SSH password.
            command: The single command to run on the target, e.g.
                "cat /etc/passwd".
        """
        host, error = await _get_target_host(target_id)
        if error:
            return error, None

        # `; true` so the REMOTE command's own exit code (a normal,
        # informative outcome - e.g. "Permission denied" from a
        # permissions probe - not a failure of this tool) never gets
        # mistaken for a local exec failure by _execute_one_shot.
        shell_command = (
            f"sshpass -p {shlex.quote(password)} ssh -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=10 {shlex.quote(username)}@{host} "
            f"{shlex.quote(command)} ; true"
        )
        ok, output = await _execute_one_shot(project_id, shell_command, SSH_RUN_TIMEOUT_SECONDS)
        mark_tested()
        if not ok:
            return output, None
        on_raw_output(output)
        return await _maybe_condense(project_id, f"ssh {command}", output, on_enumeration)

    @tool(TELNET_PROBE_TOOL_NAME, response_format="content_and_artifact")
    async def telnet_probe(port: int) -> str:
        """Connects briefly to `port` on this run's target and returns
        whatever banner/greeting it sends back - a quick "what's
        listening here" check. For an actual interactive telnet login
        session, use new_session/run() instead (if allow_shell is
        enabled) - a login prompt's exact format is specific to whatever
        service is running, with no generic shortcut this tool can offer.

        Args:
            port: Port to probe.
        """
        host, error = await _get_target_host(target_id)
        if error:
            return error, None

        # Nested `bash -c '...'`, not a bare `(...)` subshell - _execute_one_shot
        # (via KaliManger.execute's timeout_seconds) prepends its own
        # `timeout --kill-after=5 {N} ` in front of this whole string before
        # handing it to the outer bash -c, and `timeout N (subshell)` is a
        # bash syntax error (confirmed in production: every single
        # telnet_probe call failed with "syntax error near unexpected token
        # '('"). Wrapping in a nested `bash -c` avoids a bare `(` at the top
        # level entirely. `|| true` (inside the nested shell) for the same
        # reason as ssh_run above - telnet only exits on its own once the
        # inner `timeout 3` kills it, which otherwise looks like a local
        # exec failure.
        command = f"bash -c 'echo | timeout 3 telnet {host} {port} || true'"
        ok, output = await _execute_one_shot(project_id, command, TELNET_PROBE_TIMEOUT_SECONDS)
        mark_tested()
        if not ok:
            return output, None
        on_raw_output(output)
        return output, output

    return [ftp_connect, ftp_command, ssh_check_login, ssh_run, telnet_probe]


async def _save_vulnerability(vulnerability: Vulnerability) -> Vulnerability:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, db_manager.add_vulnerability, vulnerability)


def _require_tested(
    get_mode: Callable[[], str], has_tested: Callable[[], bool], tool_name: str
) -> Optional[str]:
    """Shared gate for report_vulnerability/log_attack_attempt. Mode alone
    isn't enough - observed in production: the agent called
    switch_mode("exploiting", ...) and then immediately reported a fully
    fabricated CVE/CVSS score with no real run() call against the target
    anywhere in between. This additionally requires at least one real
    run()/new_session() call since the last switch_mode before either tool
    can succeed, so a mode switch alone can no longer be used as a
    substitute for actually testing something."""
    if get_mode() != "exploiting":
        return (
            "Not in exploiting mode - call switch_mode(\"exploiting\", "
            f"<reason>) first. {tool_name} is only for a finding you have "
            "already reproduced while actively testing a specific vector, "
            "not while scouting."
        )
    if not has_tested():
        return (
            "You haven't actually run anything against the target since "
            "switching to exploiting mode - call run() to make the real "
            f"attempt first. {tool_name} requires a real tool result you "
            "have seen, not just a plan for one."
        )
    return None


CVSS4_EXAMPLE_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

# Repeated verbatim in both the tool's own error message (so a failed
# attempt gets a strong, concrete correction signal every retry, not just
# the raw pydantic-cvss error text) and the docstring below - observed in
# production: a model repeatedly substituted CVSS v3.x metric names (a bare
# "S"/"C"/"I"/"A") for v4.0's actual ones despite a correct example already
# sitting right there in the docstring, so the error path needed the same
# reference restated, not just a pointer back to instructions already
# proven not to be enough on their own.
CVSS4_METRIC_REFERENCE = (
    "CVSS v4.0 base metrics use exactly these 11 keys, in this order: "
    "AV (N/A/L/P), AC (L/H), AT (N/P), PR (N/L/H), UI (N/P/A), "
    "VC/VI/VA (H/L/N - impact on the VULNERABLE system), "
    "SC/SI/SA (H/L/N - impact on a SUBSEQUENT system, or N/N/N if none). "
    "There is no separate Scope (S) metric and no bare C/I/A metrics in "
    "v4.0 - those are CVSS v3.x names, replaced by the VC/VI/VA + SC/SI/SA "
    "pairs above. Do not mix v3 and v4 metric names."
)


def create_vulnerability_tool(
    project_id: str,
    target_id: str,
    get_mode: Callable[[], str],
    has_tested: Callable[[], bool],
    clear_tested: Callable[[], None],
    on_reported: Callable[[], None],
    get_last_raw_output: Callable[[], Optional[str]],
):
    """Builds a report_vulnerability tool bound to a specific project/target."""

    @tool(REPORT_VULNERABILITY_TOOL_NAME)
    async def report_vulnerability(
        name: str, severity: str = "", proof_of_concept: str = "", cvss4_vector: str = ""
    ) -> str:
        """Records a confirmed vulnerability found on the current target. Only
        call this once a finding has actually been verified - not for suspected
        or untested issues. Only works while in "exploiting" mode, and only
        after you have actually run something against the target since
        switching to it - call switch_mode("exploiting", ...) first if you
        haven't already, then run() the real attempt before this.

        Args:
            name: A short, descriptive name for the vulnerability.
            severity: Your own assessment of impact - one of "low",
                "medium", "high", or "critical". This is the field that
                actually matters here; always give your honest best
                judgment for it.
            proof_of_concept: Step-by-step instructions describing exactly how to
                verify or exploit the vulnerability, in enough detail to reproduce it.
            cvss4_vector: OPTIONAL - leave this empty unless you are
                confident you can construct a precise, valid CVSS v4.0
                vector yourself, e.g.
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N".
                severity alone is enough to record the finding - a wrong or
                malformed vector is worse than none, so when unsure, omit
                it rather than guess. Its score is derived automatically;
                do not include one. CVSS v4.0 uses different base metric
                names than v3.x - VC/VI/VA and SC/SI/SA, not a bare C/I/A
                or a Scope (S) metric.
        """
        gate_error = _require_tested(get_mode, has_tested, REPORT_VULNERABILITY_TOOL_NAME)
        if gate_error:
            return gate_error

        verification_error = await _verify_claim_against_evidence(
            project_id, "vulnerability report", proof_of_concept, get_last_raw_output()
        )
        if verification_error:
            return verification_error

        try:
            # SQLModel table models don't run Pydantic validators on
            # construction - validate through the plain base model first,
            # then build the table row from the already-validated data.
            validated = VulnerabilityBase(
                name=name,
                severity=severity,
                cvss4_vector=cvss4_vector or None,
                proof_of_concept=proof_of_concept,
            )
        except ValidationError as e:
            # A bad `severity` is now the common failure (name/
            # proof_of_concept have no format to get wrong). cvss4_vector
            # is optional, so its simplest fix is usually to just drop it
            # rather than get the syntax right - only repeat the full
            # metric reference when a vector was actually supplied, since
            # that's the only case a vector-specific mistake could be why
            # this failed.
            extra = ""
            if cvss4_vector.strip():
                extra = (
                    f"\n\n{CVSS4_METRIC_REFERENCE}\n"
                    f"Example of a valid vector: {CVSS4_EXAMPLE_VECTOR}\n"
                    "Or simply omit cvss4_vector entirely and report "
                    "severity alone - it is optional."
                )
            return (
                f"Could not record vulnerability, fix the input and try again: {e}\n\n"
                f"Valid severities: {', '.join(sorted(SEVERITY_LEVELS))}."
                f"{extra}"
            )

        vulnerability = Vulnerability(
            name=validated.name,
            severity=validated.severity,
            cvss4_vector=validated.cvss4_vector,
            cvss4_score=validated.cvss4_score,
            proof_of_concept=validated.proof_of_concept,
            found_in=target_id,
            related_to_project=project_id,
        )

        saved = await _save_vulnerability(vulnerability)

        # Proof-of-testing is a per-CLAIM requirement, not a per-mode-switch
        # one - see Agent._clear_tested's docstring. A fresh run() is
        # required again before the NEXT report_vulnerability/
        # log_attack_attempt call.
        clear_tested()

        # Resolves one outstanding "vulnerable" log_attack_attempt claim
        # (see Agent._unresolved_vulnerable_claims) - a real, PoC-backed
        # report now exists for a human to actually review.
        on_reported()

        return (
            f"Recorded vulnerability '{saved.name}' (severity: {saved.severity}, "
            f"CVSS v4.0 score: {saved.cvss4_score})."
        )

    return report_vulnerability


def create_finish_task_tool(
    on_finish: Callable[[str], None],
    get_unresolved_vulnerable_claims_count: Callable[[], int],
):
    """Builds a finish_task tool that lets the agent end its own run early,
    once it considers the assessment complete."""

    @tool(FINISH_TASK_TOOL_NAME)
    async def finish_task(summary: str) -> str:
        """Call this once the assessment is complete - all reachable findings
        have been reported and there is nothing productive left to
        investigate. This ends the run immediately, even if time remains,
        and cannot be undone.

        Args:
            summary: A short summary of what was accomplished and why the
                task is considered complete.
        """
        # Observed in production: the run ended with 2 of 3 logged
        # "vulnerable" claims never escalated to a real report_vulnerability
        # call, despite the per-turn reminder saying so on that exact turn -
        # a reminder alone wasn't enough to stop it. This makes it a real
        # gate, matching _require_tested's pattern elsewhere.
        unresolved = get_unresolved_vulnerable_claims_count()
        if unresolved > 0:
            return (
                f"Cannot finish yet - you have {unresolved} 'vulnerable' "
                "attack-log entry(ies) with no matching report_vulnerability "
                "call. For each: call report_vulnerability with a real "
                "proof_of_concept, or if it doesn't actually hold up, "
                "log_attack_attempt the same target/vector again with "
                "outcome=\"not_vulnerable\" or \"inconclusive\" to retract "
                "it. Then call finish_task again."
            )

        on_finish(summary)
        return "Task marked as finished. Ending the run now."

    return finish_task


def create_attack_log_tool(
    project_id: str,
    on_attempt: Callable[[dict], None],
    get_mode: Callable[[], str],
    has_tested: Callable[[], bool],
    clear_tested: Callable[[], None],
    get_last_raw_output: Callable[[], Optional[str]],
):
    """Builds a log_attack_attempt tool - the agent's own working-memory
    audit trail of what it has tried against the target and whether it
    worked. Deliberately separate from report_vulnerability: this is a
    lightweight note (including failed/inconclusive attempts, so the agent
    doesn't re-try or re-imagine the same thing later), not the formal,
    CVSS-scored record of a confirmed finding."""

    @tool(ATTACK_LOG_TOOL_NAME)
    async def log_attack_attempt(
        target: str, vector: str, outcome: str, notes: str = ""
    ) -> str:
        """Records one attempted attack/exploitation vector against a
        specific port or service, and its outcome. Call this ONLY right
        after the actual attempt - a real run() call whose result you have
        actually seen. Never call this for something you only planned or
        described in your reasoning without a matching tool call actually
        running it first - "inconclusive" must mean "I tried it and the
        result was unclear", not "I thought about trying it". If you have
        not actually run the command yet, run it now instead of logging
        anything. Only works while in "exploiting" mode - call
        switch_mode("exploiting", ...) first if you haven't already. A
        logged failure keeps you (and future turns) from repeating or
        hallucinating the same attempt again. This is separate from
        report_vulnerability: a genuinely confirmed vulnerability still
        needs its own report_vulnerability call with a CVSS vector for the
        formal record.

        Args:
            target: The port/service or host the attempt was against, e.g.
                "21/tcp (identified service and version)".
            vector: What was tried, e.g. "searchsploit match for the
                identified service/version" or a short description of the
                manual technique.
            outcome: One of "vulnerable", "not_vulnerable", or "inconclusive".
            notes: Any short additional context - error messages, why it
                failed, what would be needed to confirm it, etc.
        """
        gate_error = _require_tested(get_mode, has_tested, ATTACK_LOG_TOOL_NAME)
        if gate_error:
            return gate_error

        normalized = outcome.strip().lower()
        if normalized not in ATTACK_OUTCOMES:
            return (
                f"Invalid outcome '{outcome}'. Use one of: "
                f"{', '.join(sorted(ATTACK_OUTCOMES))}."
            )

        if normalized == "vulnerable":
            verification_error = await _verify_claim_against_evidence(
                project_id, "attack attempt", vector, get_last_raw_output()
            )
            if verification_error:
                return verification_error

        on_attempt(
            {"target": target, "vector": vector, "outcome": normalized, "notes": notes}
        )

        # Proof-of-testing is a per-CLAIM requirement, not a per-mode-switch
        # one - see Agent._clear_tested's docstring. A fresh run() is
        # required again before the NEXT report_vulnerability/
        # log_attack_attempt call.
        clear_tested()

        if normalized == "vulnerable":
            return (
                f"Logged attack attempt against '{target}' as VULNERABLE. "
                "This is now unresolved - report_vulnerability requires a "
                "fresh run() first (this log_attack_attempt call itself "
                "just consumed your current proof-of-testing), then call "
                "report_vulnerability with a step-by-step proof_of_concept "
                "to make this a real, reviewable finding. It will keep "
                "being flagged every turn until you do."
            )

        return f"Logged attack attempt against '{target}' ({normalized})."

    return log_attack_attempt


def create_switch_mode_tool(
    on_mode_change: Callable[[str], None],
    has_tested: Callable[[], bool],
    note_rejected: Callable[[], int],
    note_allowed: Callable[[], None],
):
    """Builds the switch_mode tool that toggles the agent's own working
    focus between scouting and exploiting - see agent.py's
    _render_context_message for how the current mode is re-shown every
    turn, and create_vulnerability_tool/create_attack_log_tool for the
    gating this enables."""

    @tool(SWITCH_MODE_TOOL_NAME)
    async def switch_mode(mode: str, reason: str) -> str:
        """Switches your current focus between "scouting" (broad
        enumeration/recon) and "exploiting" (testing one specific attack
        vector). Freely bidirectional - switch back and forth as many times
        as you like: scout broadly, switch to exploiting to test a specific
        finding, switch back to scouting if that didn't pan out, and so on.
        report_vulnerability and log_attack_attempt only work while in
        "exploiting" mode. Requires a real tool call (nmap_scan,
        ftp_connect, run(), ...) since your last mode switch - you can't
        switch again on thinking alone.

        Args:
            mode: Either "scouting" or "exploiting".
            reason: A short reason for the switch, e.g. "identified the
                service/version on 21/tcp, want to test a candidate
                vulnerability for it" or "that attempt didn't pan out, going
                back to enumerate the remaining ports".
        """
        normalized = mode.strip().lower()
        if normalized not in VALID_MODES:
            return f"Invalid mode '{mode}'. Use one of: {', '.join(sorted(VALID_MODES))}."

        # Observed in production: after a failed tool call, the model got
        # stuck alternating switch_mode(scouting)/switch_mode(exploiting)
        # for several turns straight with no real tool call in between -
        # re-deriving the same failed hypothesis each time instead of
        # actually acting on it. has_tested() (reset by _set_mode on every
        # switch, set by any real run()/nmap_scan/ftp_connect/...) is the
        # same "did anything actually happen" signal report_vulnerability/
        # log_attack_attempt already gate on - reusing it here stops a
        # mode-flipping loop the same way.
        if not has_tested():
            streak = note_rejected()
            if streak < 2:
                return (
                    "Rejected: you haven't run anything (a real tool call "
                    "- nmap_scan, ftp_connect, run(), ...) since your last "
                    "mode switch. Do something concrete first, then "
                    "switch modes based on what it showed - switching "
                    "back and forth without acting in between makes no "
                    "progress."
                )
            # 2nd+ consecutive rejection - mechanically release instead of
            # rejecting forever. Confirmed in production: a static
            # rejection message repeated verbatim did not stop the model
            # from just retrying the identical action - 18 consecutive
            # rejections burned an entire 15-minute run. This bounds the
            # worst case to 2 wasted turns instead, the same "mechanically
            # resolve it, don't just keep reminding" reasoning behind
            # promote_stuck_session (kali_manager.py).
            note_allowed()
            on_mode_change(normalized)
            return (
                f"Switched to {normalized} mode (auto-allowed after "
                "repeated rejections - you still haven't run anything "
                f"concrete; do that now): {reason}"
            )

        note_allowed()
        on_mode_change(normalized)
        return f"Switched to {normalized} mode: {reason}"

    return switch_mode


def create_terminal_tools(
    project_id: str,
    target_id: str,
    on_enumeration: Callable[[dict], None],
    mark_tested: Callable[[], None],
    on_session_change: Callable[[Optional[str], Optional[str]], None],
    on_prompt_state_change: Callable[[bool], None],
    on_raw_output: Callable[[str], None],
) -> list:
    """Builds the terminal-style tool set (run/new_session/switch_session/
    list_sessions/close_session/interrupt_session), bound to a project's
    Kali container and the target whose run opened them, so ending that run
    closes only its own sessions.

    One session is always "current" for this target - Agent.start_agent
    opens a "default" bash session before the first turn, and run() itself
    defensively re-opens one if every session somehow ends up closed. This
    replaces the old execute_kali_command + open/send/read/close/list
    session tools: having two ways to "run something" and, within sessions,
    two ways to "interact" (send vs read) was the actual source of the
    agent unreliably picking the wrong one - collapsing to one verb (run)
    for "do something" removes that choice entirely.

    Deliberately does NOT use manager.command_lock (a long-lived session
    must never block install_kali_package, or vice versa)."""

    # Per-run cache of a binary's man/--help text, keyed by binary name -
    # shared by every call to _maybe_help_with_usage below. A man page is
    # static reference material, so there's no reason to re-fetch it from
    # the container every time the agent mis-invokes the same tool again
    # in a different way; only the parsing-model suggestion (which depends
    # on the specific failed command) is ever redone.
    _usage_reference_cache: Dict[str, Optional[str]] = {}

    async def _maybe_help_with_usage(command: str, raw_output: str) -> Optional[str]:
        """Best-effort syntax-fix suggestion for a command that looks like
        it hit a CLI usage/argument-parsing error (see _USAGE_ERROR_PATTERN)
        - fetches that tool's own man page/--help (cached per binary) and
        asks the parsing model to propose a corrected invocation. Returns
        None whenever it can't help or anything along the way fails; never
        raises, since this rides along with the regular tool result and
        must never be the reason a real run() call fails."""
        if not _USAGE_ERROR_PATTERN.search(raw_output):
            return None

        try:
            manager = await kali_registry.get_manager(project_id)
            current_name = manager.get_current_session_name(target_id)
            sessions = await manager.list_sessions(target_id=target_id)
            current = next((s for s in sessions if s.name == current_name), None)
            if (
                current is None
                or current.command not in _USAGE_HELP_ELIGIBLE_SESSION_COMMANDS
                or not current.at_shell_prompt
            ):
                # Not a plain shell prompt (e.g. mid-way through ftp/
                # msfconsole) - `command` isn't a Kali shell command line
                # here, so "man <first word>" wouldn't mean anything.
                # current.command alone isn't enough to catch this: it only
                # changes via new_session, so an interactive program
                # launched as a plain run() input (e.g. run("ftp <host>"))
                # never updates it - at_shell_prompt (updated from the
                # session's own live output, see kali_manager.py's
                # _looks_like_shell_prompt) is what actually detects that
                # case.
                return None

            binary = _extract_binary_name(command)
            if not binary:
                return None

            if binary in _usage_reference_cache:
                reference = _usage_reference_cache[binary]
            else:
                reference = await _fetch_usage_reference(manager, binary)
                _usage_reference_cache[binary] = reference

            if not reference:
                return None

            return await _suggest_command_fix(project_id, command, raw_output, reference)
        except Exception as e:
            print(f"Usage-help lookup failed, skipping: {e}")
            return None

    @tool(RUN_TOOL_NAME, response_format="content_and_artifact")
    async def run(input: Optional[str] = None, wait_seconds: int = 8) -> str:
        """Runs something in your current terminal session - the one tool
        for actually doing anything (recon commands, interactive login
        exchanges, everything). If `input` is given, it's sent (as if typed
        and followed by Enter) to the current session first; either way,
        this then waits for `wait_seconds` of continuous quiet in the
        session before returning everything that appeared - never a
        partial, still-in-progress read. Omit `input` to just wait for new
        output without sending anything (e.g. picking up more from
        something already running in the background in another session).

        Omitting `input` never sends anything, no matter what you just
        said you were about to run - it only waits on whatever is already
        happening in the session (which, on an otherwise-idle session, is
        nothing at all, and this will simply time out empty). If you have
        decided on a command to run, put it directly in `input` on THIS
        call - do not call run() with no input first "to check", planning
        to send the actual command on a later turn.

        You always have a current session ready to use - no setup needed.
        Use new_session/switch_session if you want a second terminal (e.g.
        to keep a listener running while continuing recon elsewhere in
        another session). Do NOT background a command in your CURRENT
        session (e.g. "nmap ... &") to try to get the same effect - its
        output arrives on the same connection as everything else you send
        afterward, with no way to tell it apart from a later, unrelated
        run() call's own output. Open a second session with new_session
        instead whenever you want something running in parallel. Likewise,
        run("/bin/bash") or re-running any other shell binary inside your
        current session does NOT give you a fresh terminal - it just types
        that program's name at whatever prompt you're currently at; use
        new_session for an actual second terminal.

        If a command you send at your plain shell prompt looks like it
        failed on its own syntax (wrong flag, wrong argument form, ...),
        the result may include a line starting "Suggested corrected
        command:" - that's looked up from the tool's own documentation for
        you; it only ever fixes how a command is written, never what to
        run or why, which stays entirely your own call.

        Since this always waits out the FULL `wait_seconds` of quiet before
        returning, set it based on the longest pause the command might take
        while it's still working, not just its typical total runtime - a
        command can print a little (a banner, a warning) and then go quiet
        for real seconds while it keeps computing before printing its
        actual result. Too short a `wait_seconds` is what returns a
        partial result; when in doubt, prefer a larger value over a
        smaller one. Only fall back to a follow-up run() with no input if
        a command outlasts even a generous wait_seconds. Only use
        interrupt_session once a follow-up wait still shows nothing at all
        - not just because one call is taking a while.

        Examples:
        - One-shot recon: run("nmap -Pn -sV <target>") - the `-Pn` skips
          host-discovery probes to ports outside what's authorized here,
          which would otherwise be blocked and print irrelevant permission
          errors.
        - A scan expected to have long internal pauses: run("nmap -Pn -p- -sV <target>", wait_seconds=120)
        - Driving an interactive program one line at a time, after
          run("python3") has dropped you at its ">>>" prompt: run("print(1+1)")
          sends that single line and returns its output, exactly as if typed.
          An interactive network client works the same way - connect with
          one run() call, then send each subsequent line as its own call.

        Args:
            input: The line to send, without a trailing newline. Omit
                (leave as None) to only wait for output.
            wait_seconds: How long the session must stay completely quiet
                before its output is considered complete, 1-1800 (default
                8). The call always waits this long, even for a command
                that finishes sooner - set it based on the longest pause
                the command might have mid-run, not just how long it
                usually takes overall.
        """
        manager = await kali_registry.get_manager(project_id)

        try:
            current_session, session_was_replaced = await _resolve_current_session(
                manager, target_id, on_session_change
            )
        except KaliSessionError as e:
            return str(e), None

        # -Pn is effectively required for every nmap invocation in this
        # environment (see _maybe_inject_nmap_pn's own comment) - rather
        # than relying on the agent to keep re-applying the starting
        # prompt's one-time "always include -Pn" instruction over a long
        # run, add it automatically whenever it's missing. Only makes sense
        # to parse `input` as a shell command line at all when the current
        # session is a plain shell - inside another interactive program
        # (ftp, msfconsole, ...) it's a line typed at THAT program's own
        # prompt, not a Kali shell command.
        nmap_pn_injected = False
        if (
            input is not None
            and current_session is not None
            and current_session.command == DEFAULT_SESSION_COMMAND
            and current_session.at_shell_prompt
        ):
            input, nmap_pn_injected = _maybe_inject_nmap_pn(input)

        condensed, raw_output = await _send_and_condense(
            manager,
            project_id,
            target_id,
            current_session,
            input,
            wait_seconds,
            on_enumeration,
            mark_tested,
            on_session_change,
            on_prompt_state_change,
            on_raw_output,
            session_was_replaced=session_was_replaced,
        )
        if raw_output is None:
            return condensed, None

        # Detection runs against the RAW output, before condensation may
        # paraphrase away the exact wording the regex looks for - only
        # matters when input was actually sent (a bare poll never invoked
        # a command in the first place).
        if input is not None:
            usage_note = await _maybe_help_with_usage(input, raw_output)
            if usage_note:
                condensed = f"{condensed}\n\n{usage_note}"

        if nmap_pn_injected:
            condensed = f"{_NMAP_PN_INJECTED_NOTE}\n\n{condensed}"

        return condensed, raw_output

    @tool(NEW_SESSION_TOOL_NAME, response_format="content_and_artifact")
    async def new_session(name: str, command: str = DEFAULT_SESSION_COMMAND) -> str:
        """Opens a new named terminal session and makes it your current
        session (run() will act on it from now on, until you switch_session
        elsewhere). Omit `command` for a plain shell; pass another
        interactive command (e.g. "ftp <target>", "msfconsole -q") to start
        there instead. Reverse-shell listeners are not a supported use of
        this yet.

        Once `command` is an interactive program, you are AT ITS OWN PROMPT
        from the very next run() call onward - send exactly what you would
        type into that program directly, one command per run() call, not
        the program's own launch command again (e.g. after
        new_session("msf", "msfconsole -q"), send run("use <module>"), then
        run("set RHOSTS <target>"), then run("run") - never another
        "msfconsole ..." into that same session, which most such programs
        refuse or mishandle as
        an attempt to nest themselves). Also don't assume chaining several
        of the program's own commands with ";" on one line works the way it
        does in bash - many interactive programs (msfconsole included) only
        support that for their own one-shot startup flag, not for lines
        typed at their prompt afterward; when unsure, send one command per
        run() call.

        Some interactive programs' own prompts ask for a bare VALUE, not a
        protocol command - ftp is the clearest example: its "Name
        (host:...):" prompt wants just the username itself (e.g.
        "anonymous"), and its "Password:" prompt wants just the password
        itself (which can be empty - just send nothing after the prompt,
        or a dummy value like an email address), NOT the literal words
        "USER anonymous" or "PASS" - the client already constructs those
        actual protocol commands itself from what you type. Typing "USER
        anonymous" at the Name prompt sends a literal username of "USER
        anonymous" to the server, not "anonymous" - a real, observed cause
        of an anonymous-login test failing that had nothing to do with the
        target actually blocking it. If you want to send the raw protocol
        commands yourself instead (e.g. against a plain socket via
        telnet/nc), that's a different situation - there, typing "USER
        anonymous" IS correct, because there's no client wrapping your
        input.

        Only open a second session when you specifically need two terminals
        active at once - for one thing at a time, just use run() in your
        current session instead of opening a new one.

        Args:
            name: A short name for this session, e.g. "ftp" or "recon2".
            command: The shell command to run, default a plain bash shell.
        """
        manager = await kali_registry.get_manager(project_id)
        try:
            await manager.open_session(target_id, name, command)
            initial_output = await manager.run_in_current_session(
                target_id, None, wait_seconds=SESSION_OPEN_READ_SECONDS
            )
        except KaliSessionError as e:
            return str(e), None

        # Opening a session launches `command` for real against the
        # container - counts as testing the same way run()'s mark_tested
        # does when input is actually sent (see the comment there). Matches
        # what Agent.__init__'s own comment on _tested_since_mode_switch
        # already documents as the intended gate ("a real run()/
        # new_session() call") - this was previously never implemented.
        mark_tested()
        on_session_change(name, command)
        on_raw_output(initial_output)

        condensed = await _maybe_condense(
            project_id,
            command,
            initial_output,
            on_enumeration,
            session_command=command,
        )
        return f"Session '{name}' opened and is now current.\n\n{condensed}", initial_output

    @tool(SWITCH_SESSION_TOOL_NAME, response_format="content_and_artifact")
    async def switch_session(name: str) -> str:
        """Makes an already-open session current, so run() acts on it
        instead, and shows whatever that session has produced since you were
        last on it (or since it opened, if you've never checked). Use
        list_sessions if you've lost track of what's open."""
        manager = await kali_registry.get_manager(project_id)
        try:
            await manager.switch_session(target_id, name)
        except KaliSessionError as e:
            return f"{e} Use list_sessions to see what's currently open.", None
        current = manager.get_current_session(target_id)
        if current is None:
            return f"Switched to session '{name}'.", None

        on_session_change(current.name, current.command)

        # Show what's actually happening in the session being switched to,
        # not just confirm the pointer moved - the same "did this actually
        # work" ambiguity F4 addresses for new_session applies here too,
        # e.g. switching back to a quiet `nc` session with no way to tell
        # whether it's still alive.
        try:
            initial_output = await manager.run_in_current_session(
                target_id, None, wait_seconds=SESSION_OPEN_READ_SECONDS
            )
        except KaliSessionError as e:
            return f"Switched to session '{name}'.\n\n{e}", None
        on_raw_output(initial_output)
        condensed = await _maybe_condense(
            project_id,
            current.command,
            initial_output,
            on_enumeration,
            session_command=current.command,
        )
        return f"Switched to session '{name}'.\n\n{condensed}", initial_output

    @tool(LIST_SESSIONS_TOOL_NAME)
    async def list_sessions() -> str:
        """Lists your open terminal sessions (name and the command each is
        running), marking which one is current."""
        manager = await kali_registry.get_manager(project_id)
        sessions = await manager.list_sessions(target_id=target_id)
        if not sessions:
            return "No open sessions."
        current = manager.get_current_session_name(target_id)
        return "\n".join(
            f"{s.name}{' (current)' if s.name == current else ''}: {s.command}"
            for s in sessions
        )

    @tool(CLOSE_SESSION_TOOL_NAME)
    async def close_session(name: str) -> str:
        """Closes a session. If it was your current one, another open
        session (if any) automatically becomes current. Close a session
        once you're done with it - a small number can be open at once."""
        manager = await kali_registry.get_manager(project_id)
        existed = await manager.close_session(target_id, name)
        if not existed:
            return (
                f"No such session '{name}' - nothing to close (it may "
                "already be closed, idle-timed-out, or never existed)."
            )
        current = manager.get_current_session(target_id)
        on_session_change(
            current.name if current else None, current.command if current else None
        )
        return f"Session '{name}' closed."

    @tool(INTERRUPT_SESSION_TOOL_NAME)
    async def interrupt_session() -> str:
        """Sends Ctrl-C to your current session, to recover from a
        genuinely hung or unwanted foreground command (e.g. one you forgot
        would block, or a long scan you deliberately want to abandon).
        Returns whatever output that produces (usually "^C" plus a fresh
        prompt).

        run() itself already waits for a command to actually finish rather
        than returning early, so reach for this only once a follow-up
        run() with no input still shows no progress at all - not just
        because a command is taking a while."""
        manager = await kali_registry.get_manager(project_id)
        try:
            raw_output = await manager.interrupt_session(target_id)
        except KaliSessionError as e:
            return str(e)
        return await _maybe_condense(
            project_id, "(sending Ctrl-C)", raw_output, on_enumeration
        )

    return [run, new_session, switch_session, list_sessions, close_session, interrupt_session]


def build_agent_tools(
    project_id: str,
    target_id: str,
    on_finish: Callable[[str], None],
    on_enumeration: Callable[[dict], None],
    on_attempt: Callable[[dict], None],
    get_mode: Callable[[], str],
    on_mode_change: Callable[[str], None],
    has_tested: Callable[[], bool],
    note_switch_mode_rejected: Callable[[], int],
    note_switch_mode_allowed: Callable[[], None],
    mark_tested: Callable[[], None],
    clear_tested: Callable[[], None],
    on_session_change: Callable[[Optional[str], Optional[str]], None],
    on_prompt_state_change: Callable[[bool], None],
    on_reported: Callable[[], None],
    on_raw_output: Callable[[str], None],
    get_last_raw_output: Callable[[], Optional[str]],
    get_unresolved_vulnerable_claims_count: Callable[[], int],
    allow_shell: bool = True,
    allow_install_packages: bool = True,
) -> list:
    tools = [
        # create_kali_tool(project_id, on_enumeration),  # commented out, not
        # deleted - see create_kali_tool's docstring. The terminal tools
        # below are the agent's only way to run arbitrary commands now.
        *create_pentest_tools(project_id, target_id, on_enumeration, mark_tested, on_raw_output),
        *create_guided_session_tools(
            project_id,
            target_id,
            on_enumeration,
            mark_tested,
            on_session_change,
            on_prompt_state_change,
            on_raw_output,
        ),
    ]
    if allow_install_packages:
        tools.append(create_install_package_tool(project_id))
    if allow_shell:
        tools.extend(
            create_terminal_tools(
                project_id,
                target_id,
                on_enumeration,
                mark_tested,
                on_session_change,
                on_prompt_state_change,
                on_raw_output,
            )
        )
    tools.append(
        create_switch_mode_tool(
            on_mode_change, has_tested, note_switch_mode_rejected, note_switch_mode_allowed
        )
    )
    tools.append(
        create_vulnerability_tool(
            project_id,
            target_id,
            get_mode,
            has_tested,
            clear_tested,
            on_reported,
            get_last_raw_output,
        )
    )
    tools.append(
        create_attack_log_tool(
            project_id, on_attempt, get_mode, has_tested, clear_tested, get_last_raw_output
        )
    )
    tools.append(create_finish_task_tool(on_finish, get_unresolved_vulnerable_claims_count))
    return tools
