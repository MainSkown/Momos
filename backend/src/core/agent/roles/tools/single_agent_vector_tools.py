"""Single Agent mode's own Attack Vector tools - propose_attack_vector,
start_attack_vector, report_outcome - giving it the same discover-then-work
pipeline multi-agent mode already has (scouting_tools.py/pentesting_tools.py),
but as one agent doing both discovery and testing itself: no dispatch/
orchestration step, since there's only one agent to pick its own next
vector. Lives under roles/tools/ (not agent_tools.py itself) purely to
reuse run_registry.broadcast_attack_vector - agent_tools.py can't import
run_registry at module level (run_registry imports agent_tools, so that
would cycle); this module, like scouting_tools.py/pentesting_tools.py, is
instead deferred-imported from inside agent_tools.build_agent_tools.

Unlike pentesting's report_outcome (one AttackVector bound at tool-build
time, since a pentesting sub-agent only ever works one), the single agent
works every vector in the same run, one at a time - start_attack_vector
is the selection step (PENDING -> TESTING) that makes report_outcome's
"resolve whichever vector is current" signature possible without an
attack_vector_id argument, and is what makes the TESTING column on the
Kanban board meaningful for a single-agent run too."""

import asyncio
from typing import Callable, List, Literal, Optional
from langchain_core.tools import tool
from src.core import db_manager
from src.core.agent import run_registry
from src.schemas.attack_vector_scheme import AttackVector, AttackVectorStatus

PROPOSE_ATTACK_VECTOR_TOOL_NAME = "propose_attack_vector"
START_ATTACK_VECTOR_TOOL_NAME = "start_attack_vector"
REPORT_OUTCOME_TOOL_NAME = "report_outcome"

_OUTCOME_TO_STATUS = {
    "vulnerable": AttackVectorStatus.TESTED_VULNERABLE,
    "not_vulnerable": AttackVectorStatus.TESTED_NOT_VULNERABLE,
    "inconclusive": AttackVectorStatus.INCONCLUSIVE,
}


def create_propose_attack_vector_tool(
    project_id: str,
    target_id: str,
    agent_run_id: str,
    has_tested: Callable[[], bool],
):
    """Same shape as scouting_tools.create_propose_attack_vector_tool -
    batched, gated on has_tested() so the agent can't fabricate vectors
    before actually scanning/probing anything."""

    @tool(PROPOSE_ATTACK_VECTOR_TOOL_NAME)
    async def propose_attack_vector(descriptions: List[str]) -> str:
        """Records one or more concrete, specific candidate attack vectors
        for this target - name the service/version and what about it is
        worth testing, not a vague "check this port" note. Batch every
        vector you've identified so far into one call, after you've
        actually enumerated the services they're about.

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

        lines = "\n".join(f"- {v.id}: {v.description}" for v in saved)
        return f"Recorded {len(saved)} attack vector(s):\n{lines}"

    return propose_attack_vector


def create_start_attack_vector_tool(
    target_id: str,
    get_current_vector_id: Callable[[], Optional[str]],
    set_current_vector_id: Callable[[Optional[str]], None],
    clear_tested: Callable[[], None],
):
    """Selection step with no multi-agent equivalent (a pentesting sub-agent
    is always already assigned its one vector at construction) - flips a
    "pending" vector to "testing" and remembers it as the one
    report_outcome will resolve. clear_tested() on selection requires a
    FRESH real tool call before report_outcome can resolve THIS vector,
    rather than letting old evidence from a previously resolved vector (or
    from scouting) carry over."""

    @tool(START_ATTACK_VECTOR_TOOL_NAME)
    async def start_attack_vector(attack_vector_id: str) -> str:
        """Marks one "pending" attack vector as the one you're about to
        test now (moves it to "testing"), and remembers it as the target of
        your next report_outcome call. Only one vector can be selected at a
        time - call report_outcome to resolve it before selecting another.

        Args:
            attack_vector_id: The id of a currently "pending" attack vector
                from the list you've been shown.
        """
        if get_current_vector_id() is not None:
            return (
                "A vector is already selected and not yet resolved - call "
                "report_outcome for it first before starting another."
            )

        loop = asyncio.get_running_loop()
        vector = await loop.run_in_executor(None, db_manager.get_attack_vector, attack_vector_id)
        if vector is None or str(vector.target_id) != str(target_id):
            return f"{attack_vector_id}: not found."
        if vector.status != AttackVectorStatus.PENDING:
            return f"{attack_vector_id}: not pending (status={vector.status.value}) - skipped."

        vector.status = AttackVectorStatus.TESTING
        vector = await loop.run_in_executor(None, db_manager.update_attack_vector, vector)
        await run_registry.broadcast_attack_vector(vector)

        set_current_vector_id(attack_vector_id)
        clear_tested()

        return f"Selected {attack_vector_id}: {vector.description}. Test it for real, then call report_outcome."

    return start_attack_vector


def create_report_outcome_tool(
    project_id: str,
    target_id: str,
    agent_run_id: str,
    get_current_vector_id: Callable[[], Optional[str]],
    set_current_vector_id: Callable[[Optional[str]], None],
    has_tested: Callable[[], bool],
    clear_tested: Callable[[], None],
):
    """Same resolution logic as pentesting_tools.create_report_outcome_tool
    (status/result_summary update, new_vectors enqueued as fresh pending
    rows), except the vector being resolved is whichever one
    start_attack_vector most recently selected (get_current_vector_id),
    not one bound at tool-build time - and, unlike pentesting's version,
    this does NOT end the run: the single agent picks its own next pending
    vector afterward."""

    @tool(REPORT_OUTCOME_TOOL_NAME)
    async def report_outcome(
        outcome: Literal["vulnerable", "not_vulnerable", "inconclusive"],
        summary: str,
        new_vectors: Optional[List[str]] = None,
    ) -> str:
        """Reports the final outcome of testing your currently selected
        attack vector (see start_attack_vector). Call this exactly once per
        vector, after you've actually made the real attempt - never
        speculatively.

        Args:
            outcome: "vulnerable" if you reproduced the issue yourself with
                a real tool call, "not_vulnerable" if you tested it and it
                does not hold up, "inconclusive" if you genuinely could not
                determine either way after a real attempt.
            summary: A short summary of what you did and found.
            new_vectors: Any OTHER candidate attack vectors you noticed
                while testing this one - each becomes a new pending vector.
                Leave empty if you didn't notice anything else.
        """
        attack_vector_id = get_current_vector_id()
        if attack_vector_id is None:
            return "No attack vector currently selected - call start_attack_vector first."
        if not has_tested():
            return (
                "You haven't actually run anything against the target "
                "since selecting this vector - call run() to make the "
                "real attempt first. report_outcome requires a real tool "
                "result you have seen, not just a plan for one."
            )

        loop = asyncio.get_running_loop()

        vector = await loop.run_in_executor(None, db_manager.get_attack_vector, attack_vector_id)
        if vector is not None:
            vector.status = _OUTCOME_TO_STATUS[outcome]
            vector.result_summary = summary
            vector = await loop.run_in_executor(None, db_manager.update_attack_vector, vector)
            await run_registry.broadcast_attack_vector(vector)

        for description in new_vectors or []:
            description = description.strip()
            if not description:
                continue
            new_vector = AttackVector(
                description=description,
                project_id=project_id,
                target_id=target_id,
                discovered_by_run_id=agent_run_id,
            )
            new_vector = await loop.run_in_executor(None, db_manager.add_attack_vector, new_vector)
            await run_registry.broadcast_attack_vector(new_vector)

        set_current_vector_id(None)
        clear_tested()

        return f"Recorded outcome for {attack_vector_id}: {outcome}. Pick another pending vector, or finish_task if none remain."

    return report_outcome
