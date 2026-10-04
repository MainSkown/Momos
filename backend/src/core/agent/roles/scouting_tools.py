"""Scouting role's own tool set - see the tool matrix in
docs/features/multi-agent-pentest-pipeline.md's implementation plan.
Scouting gets enumeration-only tools (nmap_scan/gobuster_scan/searchsploit
lookups, not searchsploit_run/hydra/ftp/ssh/telnet/metasploit - those are
pentesting-only) plus the always-available request_port_access/file tools
and shell access, and exactly one terminal action of its own:
propose_attack_vector. The underlying @tool implementations that are
genuinely shared with the Single Agent flow (nmap_scan, the terminal
tools, ...) are imported from agent_tools.py, not reimplemented - see
build_scouting_tools below."""

import asyncio
from typing import Callable, List, Optional
from langchain_core.tools import tool
from src.core import db_manager, tool_groups
from src.core.agent import agent_tools
from src.schemas.attack_vector_scheme import AttackVector

PROPOSE_ATTACK_VECTOR_TOOL_NAME = "propose_attack_vector"
FINISH_SCOUTING_TOOL_NAME = "finish_scouting"

# Tools scouting is allowed to keep from agent_tools.create_pentest_tools'
# full Tier-1 bundle (which also includes hydra_bruteforce/searchsploit_run/
# metasploit_run - pentesting-only, see the tool matrix).
_ALLOWED_PENTEST_TOOL_NAMES = {
    agent_tools.NMAP_SCAN_TOOL_NAME,
    agent_tools.GOBUSTER_SCAN_TOOL_NAME,
    agent_tools.SEARCHSPLOIT_SEARCH_TOOL_NAME,
    agent_tools.SEARCHSPLOIT_VIEW_TOOL_NAME,
}

# Writer/reader sets for roles/common.py's make_guarded_tools_node - see
# its own docstring for why mixing these in one turn is a real race, not
# just a style concern. No switch_mode here at all - scouting has no mode
# to switch.
WRITER_TOOL_NAMES = {
    agent_tools.RUN_TOOL_NAME,
    agent_tools.NEW_SESSION_TOOL_NAME,
    agent_tools.NMAP_SCAN_TOOL_NAME,
    agent_tools.GOBUSTER_SCAN_TOOL_NAME,
}
READER_TOOL_NAMES = {PROPOSE_ATTACK_VECTOR_TOOL_NAME}
# Every writer is target-touching here, so the same set doubles as the
# should_interrupt-gated set (mirrors agent.py's own _INTERRUPT_GATED_TOOL_NAMES,
# narrowed to what scouting actually has).
INTERRUPT_GATED_TOOL_NAMES = WRITER_TOOL_NAMES
ALWAYS_INTERRUPT_TOOL_NAMES = {agent_tools.REQUEST_PORT_ACCESS_TOOL_NAME}


def create_propose_attack_vector_tool(
    project_id: str,
    target_id: str,
    agent_run_id: str,
    has_tested: Callable[[], bool],
):
    """Builds propose_attack_vector, scouting's only terminal action.
    Gated on has_tested() - a simple, monotonic "has at least one real
    tool call happened this run" flag (never cleared, unlike the Single
    Agent flow's per-claim has_tested/clear_tested cycle - scouting
    proposes several vectors off of one scan, not one claim per tool
    call) so the agent can't fabricate a vector out of thin air before
    ever actually scanning anything."""

    @tool(PROPOSE_ATTACK_VECTOR_TOOL_NAME)
    async def propose_attack_vector(description: str) -> str:
        """Records one concrete, specific candidate attack vector for this
        target - name the service/version and what about it is worth
        testing (e.g. "vsftpd 2.3.4 on port 21 - check for the known
        backdoor, EDB-ID 49757"), not a vague "check this port" note. Call
        this once per vector you've identified, after you've actually
        enumerated the service it's about.

        Args:
            description: A specific, actionable candidate.
        """
        if not has_tested():
            return (
                "You haven't actually run anything against the target yet "
                "this run - scan or probe something first (e.g. "
                "nmap_scan), then propose vectors based on what you "
                "actually found. An unverified guess is not a candidate "
                "vector."
            )

        description = description.strip()
        if not description:
            return "description cannot be empty."

        vector = AttackVector(
            description=description,
            project_id=project_id,
            target_id=target_id,
            discovered_by_run_id=agent_run_id,
        )
        loop = asyncio.get_running_loop()
        saved = await loop.run_in_executor(None, db_manager.add_attack_vector, vector)
        return f"Recorded attack vector: {saved.description}"

    return propose_attack_vector


def create_finish_scouting_tool(on_finish: Callable[[str], None]):
    @tool(FINISH_SCOUTING_TOOL_NAME)
    async def finish_scouting(summary: str) -> str:
        """Call this once enumeration is complete and you've called
        propose_attack_vector for every service worth testing. Ends the
        run immediately, even if there's more you could check.

        Args:
            summary: A short summary of what was enumerated and proposed.
        """
        on_finish(summary)
        return "Scouting marked as finished. Ending the run now."

    return finish_scouting


def build_scouting_tools(
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
    pentest_tools = agent_tools.create_pentest_tools(
        project_id, target_id, on_enumeration, mark_tested, on_raw_output
    )
    allowed_tool_names = tool_groups.tool_names_for(enabled_tools)
    tools = [
        t
        for t in pentest_tools
        if t.name in _ALLOWED_PENTEST_TOOL_NAMES
        and (t.name not in tool_groups.ALL_GROUPED_TOOL_NAMES or t.name in allowed_tool_names)
    ]

    tools.append(
        agent_tools.create_request_port_access_tool(project_id, target_id, on_ports_changed)
    )
    tools.extend(agent_tools.create_file_tools(project_id))
    if allow_install_packages:
        tools.append(agent_tools.create_install_package_tool(project_id))
    if allow_shell:
        tools.extend(
            agent_tools.create_terminal_tools(
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

    tools.append(create_propose_attack_vector_tool(project_id, target_id, agent_run_id, has_tested))
    tools.append(create_finish_scouting_tool(on_finish))
    return tools
