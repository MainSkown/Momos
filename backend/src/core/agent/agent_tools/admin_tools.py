"""Administrative/bookkeeping tools: package installs, the raw one-shot
shell escape hatch (kept but unused by build_agent_tools), scoped-port
requests, vulnerability/attack-log recording, and finish_task."""

import asyncio
import re
from typing import Callable, List, Literal, Optional

from langchain_core.tools import tool
from pydantic import ValidationError

from src.core.kali_integration import kali_registry
from src.core.kali_integration.kali_manager import KALI_USERS
from src.schemas import Vulnerability, VulnerabilityBase, severity_label

from .common import _get_target_info, _package, _parse_output, _verify_claim_against_evidence

KALI_COMMAND_TOOL_NAME = "execute_kali_command"
REPORT_VULNERABILITY_TOOL_NAME = "report_vulnerability"
FINISH_TASK_TOOL_NAME = "finish_task"
INSTALL_PACKAGE_TOOL_NAME = "install_kali_package"
ATTACK_LOG_TOOL_NAME = "log_attack_attempt"
REQUEST_PORT_ACCESS_TOOL_NAME = "request_port_access"

ATTACK_OUTCOMES = {"vulnerable", "not_vulnerable", "inconclusive"}

# Debian package-name policy: lowercase letters, digits, '+', '-', '.', must
# start with an alphanumeric. Enforced strictly here (not just relying on
# apt's own error) because this string is interpolated straight into a root
# shell command - anything looser would open command injection. \Z (not a
# bare trailing $) deliberately - re.match's $ also matches right before a
# single trailing "\n", which would otherwise let a value like "hydra\n"
# through and start a second shell line once concatenated into the command.
PACKAGE_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9+.-]*\Z")

# Package installs can be slow (large tools, dependency resolution) - longer
# than the default one-shot command timeout.
PACKAGE_INSTALL_TIMEOUT_SECONDS = 300


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


def create_request_port_access_tool(
    project_id: str, target_id: str, on_ports_changed: Callable[[List[int]], None]
):
    """Builds request_port_access, bound to a specific project/target. This
    is the ONLY sanctioned way to reach a port outside this target's
    "Authorized ports" (target.ports) - every other tool either refuses
    out-of-scope ports outright (nmap_scan) or is silently dropped by the
    sandbox's own nftables allowlist (prepare_nftables). It exists because
    that allowlist, while real and load-bearing sandboxing, also blocks
    ordinary pentest follow-through: a successful exploit routinely opens a
    port that was never in the pre-scan list (e.g. CVE-2011-2523's vsftpd
    backdoor only becomes reachable on port 6200 after a successful trigger
    over the already-authorized port 21), and an FTP data connection needs
    a random passive-mode port.

    Deliberately NOT an automated grant: this tool always pauses for human
    approval (see agent.py's _ALWAYS_INTERRUPT_TOOL_NAMES, independent of
    this project's own should_interrupt setting) rather than trying to
    algorithmically corroborate "is this really a consequence of something
    already authorized" - a more automated version of this was designed and
    rejected as too complex. The human approving the request is the entire
    gate; on denial LangGraph's existing rejection path means this
    function's body never runs at all."""

    @tool(REQUEST_PORT_ACCESS_TOOL_NAME, response_format="content_and_artifact")
    async def request_port_access(
        port: int, protocol: Literal["tcp", "udp"], reason: str
    ) -> str:
        """Asks a human operator for permission to add `port` to this
        target's authorized-ports allowlist. This ALWAYS pauses for human
        approval, regardless of this project's approval setting - only
        call it with a concrete reason (e.g. "exploit X opened a shell on
        this port"), never speculatively "just in case".

        Note: the underlying allowlist has no protocol dimension - approval
        opens `port` for both tcp and udp, not just whichever you request.

        Args:
            port: The port number (1-65535) to request.
            protocol: "tcp" or "udp" - context for the human reviewing this
                request, not an enforced restriction (see the note above).
            reason: A short, concrete justification - what you found, and
                why you need this specific port to continue.
        """
        if not 1 <= port <= 65535:
            return f"Invalid port {port} - must be between 1 and 65535.", None

        target, error = await _get_target_info(target_id)
        if error:
            return error, None
        if not target.ports:
            return (
                "This target has no port restriction configured - every "
                "port is already reachable, nothing to authorize."
            ), None
        if port in target.ports:
            return f"Port {port} is already authorized - no change needed.", None

        manager = await kali_registry.get_manager(project_id)
        # Shares command_lock with Tier 1 tools' one-shot execute() calls
        # (see create_install_package_tool above) - prepare_nftables issues
        # a long sequence of its own execute() calls and doesn't take this
        # lock internally, so without it a concurrent Tier 1 tool call
        # could interleave with the destroy/rebuild sequence below. Does
        # NOT protect against a concurrent run()/ftp/ssh/telnet session -
        # those deliberately never take this lock (a long-lived session
        # must never block a one-shot command or vice versa) - so the
        # brief window where prepare_nftables has destroyed the old table
        # and not yet rebuilt it (during which the sandbox is effectively
        # unscoped) is a real, accepted trade-off, not fully closed here.
        async with manager.command_lock:
            # Re-check under the lock - a concurrent request_port_access
            # call for the same port shouldn't double-add it or rebuild
            # the firewall twice for nothing.
            target, error = await _get_target_info(target_id)
            if error:
                return error, None
            if port in (target.ports or []):
                return f"Port {port} is already authorized - no change needed.", None

            new_ports = sorted(set(target.ports or []) | {port})
            target.ports = new_ports

            loop = asyncio.get_running_loop()
            # _package() (not a bare `db_manager` import) - see
            # common._package's own docstring: keeps a test's
            # monkeypatch.setattr(agent_tools, "db_manager", ...) reaching
            # this call after the split into submodules.
            await loop.run_in_executor(None, _package().db_manager.update_target, target)

            try:
                await manager.prepare_nftables(target)
            except Exception as e:
                return (
                    f"Port {port} was saved to the target's authorized "
                    f"ports, but reapplying the firewall failed: {e}. The "
                    "database and the actual firewall may now be out of "
                    "sync - a human should check this before relying on "
                    "the port being reachable."
                ), None

        # Called synchronously, from within this tool call itself - not
        # deferred to a later message-processing hook - so the very next
        # turn's "Authorized ports" reminder is correct immediately, even
        # within the same astream() call this tool just ran in (see
        # agent.py's _authorized_ports_override for why a checkpoint-only
        # patch would otherwise lag by a whole extra turn). NOT called in
        # the prepare_nftables-failed branch above - the firewall may not
        # actually allow the port yet there, so the agent shouldn't be told
        # it does.
        on_ports_changed(new_ports)

        return (
            f"Approved - port {port}/{protocol} is now authorized "
            f"(reason: {reason}). Authorized ports: "
            f"{', '.join(map(str, new_ports))}."
        ), new_ports

    return request_port_access


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


async def _save_vulnerability(vulnerability: Vulnerability) -> Vulnerability:
    loop = asyncio.get_running_loop()
    # _package() - see common._package's own docstring.
    return await loop.run_in_executor(None, _package().db_manager.add_vulnerability, vulnerability)


def _require_tested(
    get_mode: Callable[[], str], has_tested: Callable[[], bool], tool_name: str
) -> Optional[str]:
    """Shared gate for report_vulnerability/log_attack_attempt (and, via
    pentesting_tools.create_report_outcome_tool/the reporting role's own
    constant-pass usage, report_outcome) - "exploiting" alone isn't enough.
    Observed in production, back when the Single Agent flow's own "mode"
    was a free-floating toggle (switch_mode) independent of any specific
    vector: the agent switched to exploiting and immediately reported a
    fully fabricated CVE/CVSS score with no real run() call against the
    target anywhere in between. get_mode()'s real meaning is caller-
    specific now (Agent._get_vector_mode derives it from whether a vector
    is currently selected via start_attack_vector; pentesting/reporting
    pass a constant "exploiting" since they have nothing else to be "in")
    - either way, this additionally requires at least one real run()/
    new_session() call since get_mode() last became "exploiting" before
    either tool can succeed, so entering exploiting focus alone can never
    be used as a substitute for actually testing something."""
    if get_mode() != "exploiting":
        return (
            "Not in exploiting mode - start_attack_vector(<id>) to select "
            f"and begin testing a specific attack vector first. {tool_name} "
            "is only for a finding you have already reproduced while "
            "actively testing a specific vector, not while scouting."
        )
    if not has_tested():
        return (
            "You haven't actually run anything against the target since "
            "selecting this vector - call run() to make the real attempt "
            f"first. {tool_name} requires a real tool result you have "
            "seen, not just a plan for one."
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
    on_reported: Callable[[Vulnerability], None],
    get_last_raw_output: Optional[Callable[[], Optional[str]]],
    get_model_name: Callable[[], str],
    verify_evidence: bool = True,
):
    """Builds a report_vulnerability tool bound to a specific project/target.

    verify_evidence gates the _verify_claim_against_evidence check below.
    Single-agent mode leaves it True: it still has run() and every other
    tool available, so it can act on a rejection by gathering real evidence
    and trying again. build_reporting_agent_tools passes False instead -
    reporting has exactly one tool (this one), max_turns=6, and no run() of
    its own; a rejection would just burn its turn budget rephrasing the
    same already-fixed transcript with nothing it can do to "re-verify",
    stalling the run with created_vulnerability left None (see the
    orchestrator's linked_vulnerability_id wait in _is_done). The evidence
    this records was already vetted once, at the moment it was claimed, by
    pentesting_tools.create_report_outcome_tool's own
    _verify_claim_against_evidence check."""

    @tool(REPORT_VULNERABILITY_TOOL_NAME)
    async def report_vulnerability(
        name: str, proof_of_concept: str = "", cvss4_vector: str = ""
    ) -> str:
        """Records a confirmed vulnerability found on the current target. Only
        call this once a finding has actually been verified - not for suspected
        or untested issues. Only works while actively testing a specific
        attack vector, and only after you have actually run something
        against the target since selecting it - call
        start_attack_vector(<id>) first if you haven't already, then run()
        the real attempt before this.

        Args:
            name: A short, descriptive name for the vulnerability.
            proof_of_concept: Step-by-step instructions describing exactly how to
                verify or exploit the vulnerability, in enough detail to reproduce it.
            cvss4_vector: REQUIRED - a precise, valid CVSS v4.0 vector, e.g.
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N".
                A wrong or malformed vector will be rejected and asked for
                again rather than silently accepted, so take your time and
                follow the metric reference below exactly - there is no
                severity-word shortcut anymore. Its score is derived
                automatically; do not include one. CVSS v4.0 uses different
                base metric names than v3.x - VC/VI/VA and SC/SI/SA, not a
                bare C/I/A or a Scope (S) metric.
        """
        gate_error = _require_tested(get_mode, has_tested, REPORT_VULNERABILITY_TOOL_NAME)
        if gate_error:
            return gate_error

        if verify_evidence:
            verification_error = await _verify_claim_against_evidence(
                project_id,
                "vulnerability report",
                proof_of_concept,
                get_last_raw_output() if get_last_raw_output else None,
            )
            if verification_error:
                return verification_error

        try:
            # SQLModel table models don't run Pydantic validators on
            # construction - validate through the plain base model first,
            # then build the table row from the already-validated data.
            validated = VulnerabilityBase(
                name=name,
                cvss4_vector=cvss4_vector,
                proof_of_concept=proof_of_concept,
            )
        except ValidationError as e:
            # cvss4_vector is required now, with no severity-word fallback
            # - always repeat the full metric reference, since a bad/
            # missing vector is the only way this can fail (name/
            # proof_of_concept have no format to get wrong).
            return (
                f"Could not record vulnerability, fix the input and try again: {e}\n\n"
                f"{CVSS4_METRIC_REFERENCE}\n"
                f"Example of a valid vector: {CVSS4_EXAMPLE_VECTOR}"
            )

        vulnerability = Vulnerability(
            name=validated.name,
            cvss4_vector=validated.cvss4_vector,
            cvss4_score=validated.cvss4_score,
            proof_of_concept=validated.proof_of_concept,
            found_in=target_id,
            related_to_project=project_id,
            found_by_model=get_model_name(),
        )

        saved = await _save_vulnerability(vulnerability)

        # Local import, not module-top - run_registry.py already does
        # `from src.core.agent import agent_tools` at ITS top (for
        # render_tool_call_content's agent_tools.X tool-name constants), so
        # importing run_registry at this module's own top-level risks a
        # circular import depending on which module happens to get
        # imported first.
        from src.core.agent import run_registry

        await run_registry.broadcast_vulnerability_found(saved)

        # Proof-of-testing is a per-CLAIM requirement, not a per-mode-switch
        # one - see Agent._clear_tested's docstring. A fresh run() is
        # required again before the NEXT report_vulnerability/
        # log_attack_attempt call.
        clear_tested()

        # Resolves one outstanding "vulnerable" log_attack_attempt claim
        # (see Agent._unresolved_vulnerable_claims) - a real, PoC-backed
        # report now exists for a human to actually review.
        on_reported(saved)

        return (
            f"Recorded vulnerability '{saved.name}' "
            f"(severity: {severity_label(saved.cvss4_score)}, "
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
        anything. Only works while actively testing a specific attack
        vector - call start_attack_vector(<id>) first if you haven't
        already. A logged failure keeps you (and future turns) from repeating or
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
