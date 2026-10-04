"""Scouting role's own NEW tool implementations - propose_attack_vector
and finish_scouting - plus the tool-name-set constants agent_tools.py's
build_scouting_agent_tools (the actual gatherer - see its own docstring
for why that lives there, centralized alongside every other role's
gatherer, rather than here) and roles/agents/scouting_agent.py (the race-guard/
interrupt-gating wiring) both need. Every tool that's genuinely shared
with the Single Agent flow (nmap_scan, the terminal tools, ...) stays
defined once in agent_tools.py - nothing here duplicates a tool body."""

import asyncio
from typing import Callable, List
from langchain_core.tools import tool
from src.core import db_manager
from src.core.agent import agent_tools, run_registry
from src.schemas.attack_vector_scheme import AttackVector

PROPOSE_ATTACK_VECTOR_TOOL_NAME = "propose_attack_vector"
FINISH_SCOUTING_TOOL_NAME = "finish_scouting"

# Tools scouting is allowed to keep from agent_tools.create_pentest_tools'
# full Tier-1 bundle (which also includes hydra_bruteforce/searchsploit_run/
# metasploit_run - pentesting-only, see the tool matrix). Read by
# agent_tools.build_scouting_agent_tools.
ALLOWED_PENTEST_TOOL_NAMES = {
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
    Takes a batch of descriptions in one call - each local-model tool-call
    round trip is slow, and scouting routinely has a dozen-plus services to
    propose vectors for off of one scan, so one call per vector would
    multiply that cost for no benefit. Gated on has_tested() - a simple,
    monotonic "has at least one real tool call happened this run" flag
    (never cleared, unlike the Single Agent flow's per-claim has_tested/
    clear_tested cycle) so the agent can't fabricate vectors out of thin
    air before ever actually scanning anything."""

    @tool(PROPOSE_ATTACK_VECTOR_TOOL_NAME)
    async def propose_attack_vector(descriptions: List[str]) -> str:
        """Records one or more concrete, specific candidate attack vectors
        for this target - name the service/version and what about it is
        worth testing (e.g. "vsftpd 2.3.4 on port 21 - check for the known
        backdoor, EDB-ID 49757"), not a vague "check this port" note. Call
        this once with every vector you've identified so far, after you've
        actually enumerated the services they're about - batch them rather
        than calling this tool once per vector.

        Args:
            descriptions: One or more specific, actionable candidates.
        """
        if not has_tested():
            return (
                "You haven't actually run anything against the target yet "
                "this run - scan or probe something first (e.g. "
                "nmap_scan), then propose vectors based on what you "
                "actually found. An unverified guess is not a candidate "
                "vector."
            )

        cleaned = [d.strip() for d in descriptions if d.strip()]
        if not cleaned:
            return "descriptions cannot be empty."

        loop = asyncio.get_running_loop()
        saved = []
        for description in cleaned:
            vector = AttackVector(
                description=description,
                project_id=project_id,
                target_id=target_id,
                discovered_by_run_id=agent_run_id,
            )
            new_vector = await loop.run_in_executor(None, db_manager.add_attack_vector, vector)
            saved.append(new_vector)
            await run_registry.broadcast_attack_vector(new_vector)

        lines = "\n".join(f"- {v.description}" for v in saved)
        return f"Recorded {len(saved)} attack vector(s):\n{lines}"

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
