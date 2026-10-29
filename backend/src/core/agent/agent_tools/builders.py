"""Per-role tool-set assembly: build_agent_tools (Single Agent flow) and
the build_*_agent_tools gatherers for the multi-agent pipeline's
scouting/pentesting/reporting/orchestrator roles. This is the single place
"which tools does role X get" is decided."""

from typing import Callable, List, Optional

from src.core import tool_groups
from src.schemas import Vulnerability

from .category.admin_tools import (
    create_attack_log_tool,
    create_finish_task_tool,
    create_install_package_tool,
    create_request_port_access_tool,
    create_vulnerability_tool,
)
from .category.file_tools import create_file_tools
from .category.guided_session_tools import create_guided_session_tools
from .category.pentest_tools import create_pentest_tools
from .category.terminal_tools import create_terminal_tools


def build_agent_tools(
    project_id: str,
    target_id: str,
    agent_run_id: str,
    on_finish: Callable[[str], None],
    on_enumeration: Callable[[dict], None],
    on_attempt: Callable[[dict], None],
    get_mode: Callable[[], str],
    has_tested: Callable[[], bool],
    mark_tested: Callable[[], None],
    clear_tested: Callable[[], None],
    on_session_change: Callable[[Optional[str], Optional[str]], None],
    on_prompt_state_change: Callable[[bool], None],
    on_reported: Callable[[], None],
    on_raw_output: Callable[[str], None],
    get_last_raw_output: Callable[[], Optional[str]],
    get_unresolved_vulnerable_claims_count: Callable[[], int],
    get_model_name: Callable[[], str],
    on_ports_changed: Callable[[List[int]], None],
    get_current_vector_id: Callable[[], Optional[str]],
    set_current_vector_id: Callable[[Optional[str]], None],
    allow_shell: bool = True,
    allow_install_packages: bool = True,
    enabled_tools: Optional[List[str]] = None,
) -> list:
    optional_tools = [
        # create_kali_tool(project_id, on_enumeration),  # commented out, not
        # deleted - see create_kali_tool's docstring. The terminal tools
        # below are the agent's only way to run arbitrary commands now.
        *create_pentest_tools(project_id, target_id, on_enumeration, mark_tested, on_raw_output),
        *create_guided_session_tools(
            project_id,
            target_id,
            agent_run_id,
            on_enumeration,
            mark_tested,
            on_session_change,
            on_prompt_state_change,
            on_raw_output,
        ),
    ]
    # enabled_tools (project_scheme.py's ProjectSettings field, see
    # tool_groups.py) only ever filters OUT tools in
    # tool_groups.ALL_GROUPED_TOOL_NAMES - nmap_scan/searchsploit_search/
    # searchsploit_view are core/always-on and never touched here, same as
    # every non-Tier-1/2 tool appended below. enabled_tools=None resolves
    # to each group's own default_enabled (see tool_names_for) rather than
    # "no filtering" - an opt-in-only group like metasploit stays excluded
    # even for a project that's never touched this field.
    allowed_tool_names = tool_groups.tool_names_for(enabled_tools)
    optional_tools = [
        t
        for t in optional_tools
        if t.name not in tool_groups.ALL_GROUPED_TOOL_NAMES or t.name in allowed_tool_names
    ]
    tools = optional_tools
    # Unconditional - not gated by allow_shell/allow_install_packages, since
    # asking a human to widen the authorized-ports scope is independent of
    # this project's shell/install permissions.
    tools.append(create_request_port_access_tool(project_id, target_id, on_ports_changed))
    # Also unconditional - local file I/O inside the sandbox, its own
    # capability distinct from both raw shell access and target
    # interaction (see create_file_tools' own docstring).
    tools.extend(create_file_tools(project_id))
    if allow_install_packages:
        tools.append(create_install_package_tool(project_id))
    if allow_shell:
        tools.extend(
            create_terminal_tools(
                project_id,
                target_id,
                agent_run_id,
                on_enumeration,
                mark_tested,
                on_session_change,
                on_prompt_state_change,
                on_raw_output,
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
            get_model_name,
        )
    )
    tools.append(
        create_attack_log_tool(
            project_id, on_attempt, get_mode, has_tested, clear_tested, get_last_raw_output
        )
    )
    tools.append(create_finish_task_tool(on_finish, get_unresolved_vulnerable_claims_count))

    # Deferred import - see this module's own comment above
    # build_scouting_agent_tools for why (single_agent_vector_tools needs
    # run_registry, which imports this package back).
    from .roles import single_agent_vector_tools as vector_tools

    tools.append(
        vector_tools.create_propose_attack_vector_tool(
            project_id, target_id, agent_run_id, has_tested
        )
    )
    tools.append(
        vector_tools.create_start_attack_vector_tool(
            target_id, get_current_vector_id, set_current_vector_id, clear_tested
        )
    )
    tools.append(
        vector_tools.create_report_outcome_tool(
            project_id,
            target_id,
            agent_run_id,
            get_current_vector_id,
            set_current_vector_id,
            has_tested,
            clear_tested,
        )
    )
    return tools


# --- Multi-agent pipeline role gatherers ---
# One builder per role, right alongside build_agent_tools (single_agent
# mode's own, above) - this is the single place "which tools does role X
# get" is decided, so that policy never has to be found by reading four
# different files. Each builder imports its role's OWN new tool
# implementations from agent_tools/roles/<role>_tools.py - a DEFERRED import (inside
# the function, not at module level) specifically because those modules
# import this package (for the shared tool-name constants their own
# writer/reader sets are built from) - importing them back at this
# module's own top level would cycle. Every tool that's genuinely shared
# with the Single Agent flow (nmap_scan, the terminal tools, Tier-1/2
# tools, request_port_access, file tools, ...) is assembled here from the
# exact same factories build_agent_tools itself uses - nothing below
# duplicates a tool body.


def build_scouting_agent_tools(
    project_id: str,
    target_id: str,
    agent_run_id: str,
    on_enumeration: Callable[[dict], None],
    mark_tested: Callable[[], None],
    has_tested: Callable[[], bool],
    on_session_change: Callable[[Optional[str], Optional[str]], None],
    on_prompt_state_change: Callable[[bool], None],
    on_raw_output: Callable[[str], None],
    on_ports_changed: Callable[[List[int]], None],
    on_finish: Callable[[str], None],
    allow_shell: bool = True,
    allow_install_packages: bool = True,
    enabled_tools: Optional[List[str]] = None,
) -> list:
    """Scouting gets enumeration-only tools (nmap_scan/gobuster_scan/
    searchsploit lookups - not searchsploit_run/hydra/ftp/ssh/telnet/
    metasploit, pentesting-only, see the tool matrix in the implementation
    plan) plus the always-available request_port_access/file tools and
    shell access, and exactly one terminal action of its own,
    propose_attack_vector (plus finish_scouting)."""
    from .roles import scouting_tools

    pentest_tools = create_pentest_tools(
        project_id, target_id, on_enumeration, mark_tested, on_raw_output
    )
    allowed_tool_names = tool_groups.tool_names_for(enabled_tools)
    tools = [
        t
        for t in pentest_tools
        if t.name in scouting_tools.ALLOWED_PENTEST_TOOL_NAMES
        and (t.name not in tool_groups.ALL_GROUPED_TOOL_NAMES or t.name in allowed_tool_names)
    ]

    tools.append(create_request_port_access_tool(project_id, target_id, on_ports_changed))
    tools.extend(create_file_tools(project_id))
    if allow_install_packages:
        tools.append(create_install_package_tool(project_id))
    if allow_shell:
        tools.extend(
            create_terminal_tools(
                project_id,
                target_id,
                agent_run_id,
                on_enumeration,
                mark_tested,
                on_session_change,
                on_prompt_state_change,
                on_raw_output,
            )
        )

    tools.append(
        scouting_tools.create_propose_attack_vector_tool(
            project_id, target_id, agent_run_id, has_tested
        )
    )
    tools.append(scouting_tools.create_finish_scouting_tool(on_finish))
    return tools


def build_pentesting_agent_tools(
    project_id: str,
    target_id: str,
    agent_run_id: str,
    attack_vector_id: str,
    on_enumeration: Callable[[dict], None],
    mark_tested: Callable[[], None],
    get_mode: Callable[[], str],
    has_tested: Callable[[], bool],
    on_session_change: Callable[[Optional[str], Optional[str]], None],
    on_prompt_state_change: Callable[[bool], None],
    on_raw_output: Callable[[str], None],
    on_ports_changed: Callable[[List[int]], None],
    on_outcome_reported: Callable[[str, str, List[str]], None],
    get_last_raw_output: Callable[[], Optional[str]],
    allow_shell: bool = True,
    allow_install_packages: bool = True,
    enabled_tools: Optional[List[str]] = None,
) -> list:
    """Pentesting gets every "vulnerability testing" tool except nmap_scan
    (scouting-only, see the tool matrix in the implementation plan) -
    gobuster_scan/searchsploit_run/hydra_bruteforce/metasploit_run (per
    tool_groups/enabled_tools, same gating as today) plus all of the ftp/
    ssh/telnet guided tools - and exactly one terminal action of its own,
    report_outcome."""
    from .roles import pentesting_tools

    pentest_tools = create_pentest_tools(
        project_id, target_id, on_enumeration, mark_tested, on_raw_output
    )
    allowed_tool_names = tool_groups.tool_names_for(enabled_tools)
    tools = [
        t
        for t in pentest_tools
        if t.name in pentesting_tools.ALLOWED_PENTEST_TOOL_NAMES
        and (t.name not in tool_groups.ALL_GROUPED_TOOL_NAMES or t.name in allowed_tool_names)
    ]

    guided_tools = create_guided_session_tools(
        project_id,
        target_id,
        agent_run_id,
        on_enumeration,
        mark_tested,
        on_session_change,
        on_prompt_state_change,
        on_raw_output,
    )
    tools.extend(
        t
        for t in guided_tools
        if t.name not in tool_groups.ALL_GROUPED_TOOL_NAMES or t.name in allowed_tool_names
    )

    tools.append(create_request_port_access_tool(project_id, target_id, on_ports_changed))
    tools.extend(create_file_tools(project_id))
    if allow_install_packages:
        tools.append(create_install_package_tool(project_id))
    if allow_shell:
        tools.extend(
            create_terminal_tools(
                project_id,
                target_id,
                agent_run_id,
                on_enumeration,
                mark_tested,
                on_session_change,
                on_prompt_state_change,
                on_raw_output,
            )
        )

    tools.append(
        pentesting_tools.create_report_outcome_tool(
            project_id,
            target_id,
            agent_run_id,
            attack_vector_id,
            get_mode,
            has_tested,
            on_outcome_reported,
            get_last_raw_output,
        )
    )
    return tools


def build_reporting_agent_tools(
    project_id: str,
    target_id: str,
    get_mode: Callable[[], str],
    has_tested: Callable[[], bool],
    clear_tested: Callable[[], None],
    on_reported: Callable[[Vulnerability], None],
    get_model_name: Callable[[], str],
) -> list:
    """Reporting gets exactly one tool: report_vulnerability, reused as-is
    from create_vulnerability_tool (now vector-required per Phase 1, no
    severity-word fallback) - not reimplemented. get_mode/has_tested are
    constant closures so its existing _require_tested gate trivially passes
    (same trick pentesting_tools.create_report_outcome_tool's own gate
    uses) - reporting's "evidence" is a pentesting run's already-real,
    already-persisted transcript, not something it freshly tests itself.
    No shell, no session, no other target-touching tool at all (see the
    tool matrix in the implementation plan) - reporting never acts on the
    target directly. verify_evidence=False for the same reason: reporting
    has no run() to re-verify with and only max_turns=6, so
    _verify_claim_against_evidence's "re-verify with a real run() call"
    rejection would be a dead end here, not something it can act on - see
    create_vulnerability_tool's own docstring."""
    return [
        create_vulnerability_tool(
            project_id,
            target_id,
            get_mode,
            has_tested,
            clear_tested,
            on_reported,
            None,
            get_model_name,
            verify_evidence=False,
        )
    ]


def build_orchestrator_agent_tools(
    project_id: str,
    target_id: str,
    orchestrator_run_id: str,
    should_interrupt: bool,
    on_scouting_done: Callable[[], None],
) -> list:
    """Orchestrator gets exactly four tools - run_scouting,
    dispatch_pentest_batch, request_report, request_tool_access - and
    nothing else: no shell, no session, no target-touching tool of its own
    at all (see the tool matrix in the implementation plan). It never acts
    on the target directly, only through the scouting/pentesting/reporting
    sub-agents each of these spawns and awaits."""
    from .roles import orchestrator_tools

    return [
        orchestrator_tools.create_run_scouting_tool(
            project_id, target_id, orchestrator_run_id, should_interrupt, on_scouting_done
        ),
        orchestrator_tools.create_dispatch_pentest_batch_tool(
            project_id, target_id, orchestrator_run_id, should_interrupt
        ),
        orchestrator_tools.create_request_report_tool(project_id, target_id, orchestrator_run_id),
        orchestrator_tools.create_request_tool_access_tool(project_id, target_id),
    ]
