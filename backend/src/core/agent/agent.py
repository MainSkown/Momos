import asyncio
import json
import logging
import re
import uuid
from typing import (
    Annotated,
    Any,
    AsyncGenerator,
    Callable,
    Dict,
    List,
    Literal,
    Optional,
    TypedDict,
)
from langchain_core.messages import AIMessage, BaseMessage, SystemMessage, ToolMessage
from langchain_ollama import ChatOllama
from ollama import ResponseError as OllamaResponseError
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from . import agent_tools
from src.core.kali_integration import kali_registry
from src.schemas import AgentTargetScope, Target
from src.core import settings, tool_groups
import time

logger = logging.getLogger("momos.agent")

# Matches Qwen's own native tool-call wire syntax
# (<tool_call>{"name": ..., "arguments": {...}}</tool_call>). Ollama is
# supposed to parse this into the response's structured tool_calls, but has
# a confirmed bug (ollama/ollama #11662, #14601) where it sometimes doesn't -
# the block just falls through as plain text in .content or
# additional_kwargs['reasoning_content'] instead, and the tool call silently
# never executes. Observed in production: a real log_attack_attempt call
# lost this way, with no error and no log entry - see
# Agent._recover_leaked_tool_calls.
_LEAKED_TOOL_CALL_PATTERN = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)

# Used only when ollama_manager.get_model_capabilities couldn't be reached
# for this model (see Agent.__init__/_prepare_and_run) - a conservative
# floor, not a real default any current model actually ships with, so the
# message-trimming budget below stays tight rather than silently assuming
# a large window it hasn't actually confirmed. Matches
# ollama_manager.capabilities_from_show_info's own fallback (2048) - the
# path with LESS information about the model should never fall back to a
# LARGER assumed window than the path that at least got a response.
DEFAULT_CONTEXT_WINDOW_FALLBACK = 2048

# _trim_messages_for_model first subtracts the fixed, measurable per-request
# overhead (the starting prompt plus the bound tools' own JSON-schema
# descriptions, sent with every request once bound - see
# Agent._fixed_overhead_tokens) from the model's context window, then
# reserves this fraction of what's left for the trimmed conversation
# history it sends; the remainder stays available for the per-turn context
# message (target scope, mode, enumeration table, attack log - see
# _render_context_message) and the model's own generation. No tokenizer is
# available for an arbitrary local Ollama model, so this is necessarily a
# rough per-message token estimate rather than an exact count -
# deliberately conservative in both constants below, since UNDER-trimming
# (context overflow silently truncating from the wrong end, or the request
# failing outright) is a much worse failure mode than trimming a little
# more eagerly than strictly necessary.
_CONTEXT_BUDGET_FRACTION = 0.5
_EST_TOKENS_PER_MESSAGE = 250
_MAX_MESSAGES_SENT_TO_MODEL = 80
# Rough chars-per-token estimate for the one-time fixed-overhead
# measurement below - same reasoning as _EST_TOKENS_PER_MESSAGE, no real
# tokenizer available for an arbitrary local model.
_CHARS_PER_TOKEN_ESTIMATE = 4
# How many of the auto-maintained attack-log entries _render_context_message
# renders in full each turn (most recent first) - see _render_context_message.
# Unlike the trimmed conversation history, this table has no natural size
# cap of its own (enumeration is bounded by port count, but attack attempts
# can accumulate indefinitely over a long run) and is rendered in addition
# to, not instead of, the trimmed messages, so it needs its own bound.
_MAX_ATTACK_LOG_ENTRIES_SHOWN = 40

# Tool names whose success path WRITES to the exploiting-mode "proof of
# testing" state (self.mode / self._tested_since_mode_switch - see
# _set_mode/_mark_tested/_clear_tested below) vs. tool names whose gate
# check READS that same state (_require_tested in agent_tools.py).
# LangGraph's ToolNode runs every tool call from one LLM turn concurrently
# via asyncio.gather (confirmed against the installed langgraph source), so
# a writer and a reader landing in the SAME turn is order-dependent, not
# just theoretically racy - see Agent._tools_node below, which rejects the
# whole batch outright whenever a turn mixes one of each, rather than
# trying to out-time the race.
_MODE_GATE_WRITER_TOOL_NAMES = {
    agent_tools.RUN_TOOL_NAME,
    agent_tools.NEW_SESSION_TOOL_NAME,
    agent_tools.SWITCH_MODE_TOOL_NAME,
    # Tier 1/2 tools (create_pentest_tools/create_guided_session_tools) -
    # every one of these calls mark_tested()/updates _last_raw_output just
    # like run() does, so the same batched-with-a-reader race applies to
    # them too.
    agent_tools.NMAP_SCAN_TOOL_NAME,
    agent_tools.HYDRA_BRUTEFORCE_TOOL_NAME,
    agent_tools.GOBUSTER_SCAN_TOOL_NAME,
    agent_tools.SEARCHSPLOIT_SEARCH_TOOL_NAME,
    agent_tools.SEARCHSPLOIT_VIEW_TOOL_NAME,
    agent_tools.SEARCHSPLOIT_RUN_TOOL_NAME,
    agent_tools.FTP_CONNECT_TOOL_NAME,
    agent_tools.FTP_COMMAND_TOOL_NAME,
    agent_tools.SSH_CHECK_LOGIN_TOOL_NAME,
    agent_tools.SSH_RUN_TOOL_NAME,
    agent_tools.TELNET_PROBE_TOOL_NAME,
    agent_tools.METASPLOIT_RUN_TOOL_NAME,
}
_MODE_GATE_READER_TOOL_NAMES = {
    agent_tools.REPORT_VULNERABILITY_TOOL_NAME,
    agent_tools.ATTACK_LOG_TOOL_NAME,
}

# What should_interrupt (start_agent's optional pause-for-human-approval
# gate) actually pauses before - run()/new_session() (raw shell, gated
# separately by allow_shell - always interrupt-gated here regardless of
# tool selection below), nmap_scan, plus exactly the "vulnerability
# testing" Tier-1/2 tools a project can individually enable/disable
# (tool_groups.py - hydra_bruteforce, gobuster_scan, searchsploit_run,
# ftp_connect/command, ssh_check_login/run, telnet_probe). Deliberately
# narrower than _MODE_GATE_WRITER_TOOL_NAMES only for searchsploit_search/
# searchsploit_view - both are local Exploit-DB lookups that never send a
# single packet to the target, unlike nmap_scan, which does (real SYN/
# connect scans against the live target) and so stays interrupt-gated even
# though it's core/always-on for tool-selection purposes (tool_groups.py).
# switch_mode is pure bookkeeping and was never included here either way.
_INTERRUPT_GATED_TOOL_NAMES = (
    {agent_tools.RUN_TOOL_NAME, agent_tools.NEW_SESSION_TOOL_NAME, agent_tools.NMAP_SCAN_TOOL_NAME}
    | tool_groups.ALL_GROUPED_TOOL_NAMES
)

# Tool names that must ALWAYS pause for human approval, independent of
# project_settings.should_interrupt entirely (see start_agent's
# requires_interrupt below) - unlike _INTERRUPT_GATED_TOOL_NAMES (only
# gates when the operator opted into reviewing every real action),
# request_port_access exists specifically so a human gates a real
# widening of the sandbox's own authorized-ports scope; that gate must
# hold even on a project that has "pause for approval" turned off.
# Deliberately NOT folded into _MODE_GATE_WRITER_TOOL_NAMES/
# _INTERRUPT_GATED_TOOL_NAMES above: this tool doesn't call mark_tested()/
# touch _last_raw_output the way every member of that set does, so it has
# no part in the writer/reader batch-rejection race those sets exist to
# prevent (see _tools_node below).
_ALWAYS_INTERRUPT_TOOL_NAMES = {agent_tools.REQUEST_PORT_ACCESS_TOOL_NAME}


def _mode_gate_conflict(names: set) -> tuple:
    """Returns (writers, reader_like) for one turn's tool-call names.
    reader_like is empty when there's no same-turn conflict; otherwise
    it's the set of tool(s) that must NOT run in the same turn as the
    other writer(s) they're paired with here, because they read state a
    writer only sets after an await (mark_tested()) - so they'd reliably
    read it stale if run concurrently (asyncio.gather) in the same batch.

    Two cases collapse into this one helper because they're the same race
    shape: the real _MODE_GATE_READER_TOOL_NAMES members (report_
    vulnerability/log_attack_attempt), and switch_mode itself when paired
    with any OTHER writer - switch_mode is bucketed as a writer (a
    successful switch resets _tested_since_mode_switch), but its own body
    is also a reader of that exact state (has_tested()), with no await
    before that read, so it reliably wins the race against whatever writer
    it's paired with. Used by both _tools_node (the actual per-turn
    dispatch gate) and start_agent's batch_will_be_rejected pre-check
    (which must reject the identical set of turns _tools_node will, or an
    operator can be asked to approve a batch that's rejected anyway the
    moment it's resumed) - kept as one function specifically so those two
    checks can't drift apart the way they briefly did for the switch_mode
    case."""
    writers = names & _MODE_GATE_WRITER_TOOL_NAMES
    readers = names & _MODE_GATE_READER_TOOL_NAMES
    if writers and readers:
        return writers, readers
    if agent_tools.SWITCH_MODE_TOOL_NAME in names:
        other_writers = writers - {agent_tools.SWITCH_MODE_TOOL_NAME}
        if other_writers:
            return writers, {agent_tools.SWITCH_MODE_TOOL_NAME}
    return writers, set()


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    target_scope: AgentTargetScope
    # Auto-maintained running knowledge base, re-injected into every turn's
    # context by _render_context_message - see build_agent_tools/_call_model.
    # Both are plain last-write-wins fields (no Annotated reducer): each
    # _call_model call always writes back the FULL merged value, not a
    # delta, so overwrite-on-write is the correct semantics here. They ride
    # along with `messages` in the same Postgres checkpoint, so they survive
    # pause/resume for free.
    enumeration: Dict[str, Dict[str, str]]
    attack_log: List[Dict[str, str]]
    # Current focus - "scouting" or "exploiting" (see agent_tools.py's
    # switch_mode/VALID_MODES). Mirrors Agent.mode, which is the live,
    # synchronously-updated source of truth (see Agent._set_mode) - this
    # field only exists so the value survives a pause/resume via the same
    # Postgres checkpoint as everything else.
    mode: str
    # Mirrors Agent._tested_since_mode_switch, the live synchronously-
    # updated source of truth (see _mark_tested/_clear_tested/_set_mode) -
    # same reasoning as `mode` above: without this, resuming a paused run
    # that had genuinely tested something would come back on a fresh Agent
    # instance defaulting to False, falsely re-showing the "you have NOT
    # yet run() anything" warning even though it had.
    tested_since_mode_switch: bool
    # Mirrors Agent._unresolved_vulnerable_claims - see
    # _record_attack_attempt/_mark_vulnerability_reported. Same pause/resume
    # reasoning as tested_since_mode_switch above: without this, resuming a
    # paused run with a real outstanding "vulnerable" claim would come back
    # on a fresh Agent instance defaulting to empty, silently dropping the
    # reminder to actually report it. Checkpointed as a plain list of
    # [target, vector] pairs (not a Python set) since the Postgres
    # checkpointer needs a JSON-friendly type - converted to/from the live
    # set at the two mirror points below (_call_model / start_agent resume).
    unresolved_vulnerable_claims: List[List[str]]
    # Mirrors Agent.finish_summary - see _mark_finished. Checkpointed for
    # the same reason as the two fields above, even though in the normal
    # flow this is largely masked: AgentService.start_agent deletes the
    # checkpoint whenever the persisted run status isn't PAUSED, and both
    # real completion paths leave the run FINISHED, not PAUSED, so a stale
    # checkpoint can't normally be silently "resumed" as already finished.
    finish_summary: Optional[str]


class AgentInterruptAction(TypedDict):
    kind: Literal["interrupt"]
    accept: Callable[[bool], None]
    tool_calls: list[Any]


class AgentContextUsageEvent(TypedDict):
    """Yielded once per real LLM turn (see start_agent's event loop) when
    Ollama reported real token-usage numbers for it - see
    ChatOllama._get_usage_metadata_from_generation_info (langchain_ollama),
    which populates AIMessage.usage_metadata straight from Ollama's own
    prompt_eval_count. Surfaced to the frontend as an AgentContextUsage
    websocket message (agent_service.py) to drive a live "how full is the
    context window" indicator."""
    kind: Literal["context_usage"]
    used_tokens: int
    context_window: int


# Previously this graph made two LLM calls per turn - a plain reasoning-only
# call, then a separate tool-bound call told to act on it - because many
# tool-calling chat templates only allow text OR a tool call in one turn,
# never both. That split turned out not to actually prevent the failure it
# was built for (the model narrating a command instead of calling a tool
# happened in EITHER phase, in production runs against Metasploitable 2),
# while doubling per-turn latency and - since the reasoning text got folded
# into persisted message content whenever the tool-call response came back
# empty - permanently bloating every future turn's context with what was
# often just decorative narration, not functional reasoning. Collapsed back
# to one call: bind tools directly with reasoning=True, and let each
# model's own template decide how (or whether) to interleave thinking and
# tool-calling, rather than hand-rolling a scaffold around it. Reasoning
# text - when the model/Ollama actually populates it - is captured from
# additional_kwargs['reasoning_content'] for logging, and deliberately
# never folded into .content, since LangChain's message serialization back
# to the provider only resends .content/.tool_calls, not additional_kwargs -
# so it stays visible in the UI without ever being replayed into the
# model's own future context. Accepted trade-off: for a model whose
# template genuinely can't produce text and a tool call together, a turn
# may now come back with a tool call and no visible reasoning at all -
# there's no second call trying to force it out. The
# consecutive_no_tool_calls/NUDGE_MESSAGE stall-recovery loop in
# start_agent() is the backstop for whenever a turn comes back with
# neither.


class Agent:
    def __init__(
        self,
        model_name: str,
        checkpointer: AsyncPostgresSaver,
        project_id: str,
        target_id: str,
        reasoning: Optional[bool] = None,
        context_window: Optional[int] = None,
        allow_shell: bool = True,
        allow_install_packages: bool = True,
        enabled_tools: Optional[List[str]] = None,
        agent_run_id: Optional[str] = None,
    ):
        self.project_id = project_id
        self.target_id = target_id
        # Identifies this Agent instance's own Kali sessions, independent
        # of any sibling agent concurrently running on the same target -
        # see kali_manager.py's _session_key/_owner_key. None (every
        # existing caller, today's single-agent flow) falls back to
        # target_id itself, which reproduces the exact session cardinality
        # this had before agent_run_id existed - single-agent mode is,
        # structurally, "the one agent run this target will ever have at
        # once," so its own target_id already uniquely identifies it.
        self.agent_run_id = agent_run_id or target_id
        self.checkpointer = checkpointer
        self.ollama_url = settings.ollama_url
        self.finish_summary: Optional[str] = None

        # Best-effort per-model info from ollama_manager.get_model_capabilities
        # (see agent_service.py's _prepare_and_run, which fetches this,
        # clamps it to the project's/global max-context-window ceiling, and
        # passes the already-clamped result here) - None whenever that
        # lookup wasn't available/failed, in which case changeModel/
        # _message_budget fall back to conservative, previously-hardcoded
        # defaults rather than guessing. context_window is now the single
        # source of truth for BOTH the message-trimming budget below AND
        # the actual num_ctx requested from Ollama in changeModel - the two
        # used to be computed from the same detected value but only the
        # budget ever actually used it; changeModel silently left Ollama on
        # its own server-side default instead.
        self.context_window = context_window or DEFAULT_CONTEXT_WINDOW_FALLBACK
        # Memoized by _fixed_overhead_tokens on first use - see there.
        self._cached_fixed_overhead_tokens: Optional[int] = None

        # Live, synchronously-updated source of truth for the current
        # scouting/exploiting focus (see agent_tools.py's switch_mode) -
        # read directly by report_vulnerability/log_attack_attempt's gating
        # via _get_mode, so a switch_mode call is visible to them
        # immediately rather than only after the next _call_model flush.
        # Mirrored into the checkpointed AgentState.mode field every turn
        # (see _call_model) purely so it survives a pause/resume; restored
        # from checkpoint in start_agent() when resuming.
        self.mode: str = "scouting"

        # Whether a real run()/new_session() call has happened since the
        # last switch_mode call - gates report_vulnerability/
        # log_attack_attempt alongside mode itself. Mode gating alone
        # turned out not to be enough: observed in production, the agent
        # called switch_mode("exploiting", ...) and then immediately
        # log_attack_attempt + report_vulnerability with a fully fabricated
        # CVE, exploit-db id, and CVSS score - without ever actually
        # running anything against the target in between. Same
        # synchronous-instance-attribute pattern as self.mode (see
        # _get_mode/_set_mode) and the same reasoning for why: tool calls
        # need to observe this immediately, not just after the next
        # _call_model flush.
        self._tested_since_mode_switch: bool = False

        # Consecutive switch_mode calls rejected by the has_tested() gate
        # above with nothing productive in between - see
        # _note_switch_mode_rejected/_note_switch_mode_allowed and
        # create_switch_mode_tool. Not checkpointed, same reasoning as
        # KaliSession.confusion_streak: a live in-memory streak, not state
        # worth persisting across a pause/resume.
        self._consecutive_rejected_switch_mode: int = 0

        # (target, vector) pairs (normalized: stripped/lowercased) logged
        # with outcome="vulnerable" that have no matching
        # report_vulnerability call yet - added in _record_attack_attempt,
        # removed by either _mark_vulnerability_reported (a report
        # succeeded) or by re-logging the SAME (target, vector) with
        # outcome="not_vulnerable"/"inconclusive" (an explicit retraction -
        # see _record_attack_attempt). A set, not a counter, so retrying the
        # exact same claim doesn't inflate the count - observed in
        # production: three identical "FTP Anonymous Login Test" attempts
        # against the same target counted as 3 outstanding claims instead
        # of 1. report_vulnerability requires a real proof_of_concept,
        # which is the actual artifact a human reviews; log_attack_attempt
        # does not, so without this a fabricated "vulnerable" claim could
        # sit forever as an informal note that nothing ever prompts a human
        # to look at - see also finish_task's gate in agent_tools.py, which
        # reads this via _get_unresolved_vulnerable_claims_count. Mirrored
        # into AgentState.unresolved_vulnerable_claims every turn (as a
        # plain list of pairs - see that field's comment), same pattern as
        # tested_since_mode_switch above, for the same pause/resume reason.
        self._unresolved_vulnerable_claims: set[tuple[str, str]] = set()

        # Written to by tool calls (log_attack_attempt, run()'s FACTS
        # extraction) as they happen inside the "tools" node - tools have no
        # direct handle on graph state, so these buffer updates until the
        # next _call_model run, which folds them into the checkpointed
        # enumeration/attack_log state fields and clears the buffer. Safe
        # because the graph always routes tools -> agent (never two
        # tool-executing turns back to back), and because asyncio's
        # single-threaded event loop makes these plain (non-await-ing)
        # dict/list mutations atomic even when several tool calls from one
        # LLM turn run concurrently.
        self._pending_enumeration: Dict[str, dict] = {}
        self._pending_attack_log: List[dict] = []

        # Live, synchronously-updated record of which terminal session is
        # current and what it's running - same pattern as self.mode above,
        # for the same reason: _render_context_message re-injects this every
        # turn (see there) so the model can't lose track of "you're inside
        # telnet, not a Kali shell" the same way it can't lose track of mode.
        # None until start_agent()'s pre-open of the default session sets it
        # (see there) - never checkpointed, since every session is
        # unconditionally closed at the end of any run (paused or finished,
        # see agent_service.py's close_sessions_for_target) and start_agent
        # always re-opens a fresh default session before turn one regardless
        # of what was open before pausing, so this always resets to match
        # reality at that same point rather than needing to persist across it.
        self._current_session_name: Optional[str] = None
        self._current_session_command: Optional[str] = None

        # Live, synchronously-updated override of target_scope's ports -
        # same pattern as self.mode/_current_session_name above, and for
        # the same reason: request_port_access (agent_tools.py) can only
        # update the CHECKPOINTED target_scope (via _apply_granted_ports)
        # from the message-consumption loop BETWEEN graph steps, but
        # interrupt_before=["tools"] means the "tools" step that just ran
        # request_port_access and the very next "agent" step - the one
        # whose prompt is supposed to show the newly authorized port - both
        # execute inside the SAME astream() call, off the SAME in-memory
        # checkpoint snapshot loaded once at that call's start (confirmed
        # against langgraph's AsyncPregelLoop: aget_tuple is only called in
        # __aenter__, tick() never re-reads the checkpointer). A checkpoint
        # patch alone would only become visible one extra turn later than
        # intended. This live override is set synchronously from within
        # the tool call itself (see on_ports_changed) so the very next
        # turn's reminder is correct immediately, exactly like self.mode
        # already is for switch_mode. None until a grant happens; not
        # checkpointed on its own - _apply_granted_ports still patches the
        # real target_scope for a paused-then-resumed run, since a fresh
        # Agent instance on resume starts this back at None.
        self._authorized_ports_override: Optional[List[int]] = None

        # Live, synchronously-updated guess at whether the current session's
        # last output ended at a plain shell prompt vs. some other program's
        # (ftp, an interpreter, ...) - see agent_tools.py's run() and
        # kali_manager.py's _looks_like_shell_prompt. Defaults True (matches
        # KaliSession.at_shell_prompt's own default) since nothing has run
        # yet. Not checkpointed - same reasoning as _current_session_command
        # above, it's cheaply recomputed on the very next run() call.
        self._at_shell_prompt: bool = True

        # Most recent real tool output (run()/new_session()/switch_session()),
        # used to sanity-check a report_vulnerability/log_attack_attempt
        # claim against actual evidence at the moment it's made - see
        # _verify_claim_against_evidence in agent_tools.py. Observed in
        # production: the existing proof-of-testing gate (_require_tested)
        # only checks THAT a run() happened, never what it showed, so a
        # claim built on a misread prompt or an unrelated command sailed
        # straight through it. Not checkpointed, same reasoning as
        # _at_shell_prompt above.
        self._last_raw_output: Optional[str] = None

        # A callable, not the value itself - changeModel() (which actually
        # sets self.model_name) runs AFTER build_agent_tools below, so
        # report_vulnerability reads this lazily at call time instead of
        # capturing an unset value now.
        self._get_model_name = lambda: getattr(self, "model_name", "")

        self.tools = agent_tools.build_agent_tools(
            project_id,
            target_id,
            self.agent_run_id,
            self._mark_finished,
            self._record_enumeration,
            self._record_attack_attempt,
            self._get_mode,
            self._set_mode,
            self._get_tested_since_mode_switch,
            self._note_switch_mode_rejected,
            self._note_switch_mode_allowed,
            self._mark_tested,
            self._clear_tested,
            self._set_current_session,
            self._set_at_shell_prompt,
            self._mark_vulnerability_reported,
            self._set_last_raw_output,
            self._get_last_raw_output,
            self._get_unresolved_vulnerable_claims_count,
            self._get_model_name,
            self._set_authorized_ports,
            allow_shell,
            allow_install_packages,
            enabled_tools,
        )

        self.changeModel(model_name=model_name, reasoning=reasoning)

        self.app = self._build_graph()

    def _mark_finished(self, summary: str):
        self.finish_summary = summary

    def _record_enumeration(self, entries: Dict[str, dict]):
        self._pending_enumeration.update(entries)

    def _record_attack_attempt(self, entry: dict):
        self._pending_attack_log.append(entry)
        outcome = entry.get("outcome")
        key = (
            str(entry.get("target", "")).strip().lower(),
            str(entry.get("vector", "")).strip().lower(),
        )
        if outcome == "vulnerable":
            self._unresolved_vulnerable_claims.add(key)
        elif outcome in ("not_vulnerable", "inconclusive"):
            # Explicit retraction: re-logging the SAME (target, vector)
            # with a downgraded outcome supersedes an earlier "vulnerable"
            # claim for it - the only way to clear one short of an actual
            # report_vulnerability, needed now that finish_task refuses to
            # end the run while any remain outstanding.
            self._unresolved_vulnerable_claims.discard(key)

    def _mark_vulnerability_reported(self, vulnerability=None):
        # `vulnerability` (the created Vulnerability row) is unused here -
        # only the reporting role's own on_reported closure needs it (to
        # link it back onto an AttackVector). Accepted so
        # create_vulnerability_tool's on_reported callback can have one
        # signature shared by both callers. No shared key between
        # report_vulnerability's args and an
        # attack-log entry to resolve the exact matching claim - popping an
        # arbitrary one is an accepted, scoped imprecision, still strictly
        # better than the previous plain counter (which never deduped
        # retries of the identical claim at all).
        if self._unresolved_vulnerable_claims:
            self._unresolved_vulnerable_claims.pop()

    def _get_unresolved_vulnerable_claims_count(self) -> int:
        return len(self._unresolved_vulnerable_claims)

    def _set_at_shell_prompt(self, value: bool):
        self._at_shell_prompt = value

    def _set_last_raw_output(self, raw_output: Optional[str]):
        self._last_raw_output = raw_output

    def _get_last_raw_output(self) -> Optional[str]:
        return self._last_raw_output

    def _get_mode(self) -> str:
        return self.mode

    def _set_mode(self, mode: str):
        self.mode = mode
        # Fresh mode, fresh requirement to prove something was actually
        # tried in it - including re-entering "exploiting" after having
        # left it, so a vector's confirmation can't ride on testing done
        # for a different, earlier vector.
        self._tested_since_mode_switch = False

    def _get_tested_since_mode_switch(self) -> bool:
        return self._tested_since_mode_switch

    def _mark_tested(self):
        self._tested_since_mode_switch = True
        # Any real tool call clears the rejected-switch_mode streak too -
        # it only grows across consecutive switch_mode calls with nothing
        # productive in between (see _note_switch_mode_rejected).
        self._consecutive_rejected_switch_mode = 0

    def _note_switch_mode_rejected(self) -> int:
        self._consecutive_rejected_switch_mode += 1
        return self._consecutive_rejected_switch_mode

    def _note_switch_mode_allowed(self):
        self._consecutive_rejected_switch_mode = 0

    def _clear_tested(self):
        """Resets the "tested since mode switch" flag right after a
        report_vulnerability/log_attack_attempt call actually succeeds -
        makes proof-of-testing a per-CLAIM requirement rather than a
        per-mode-switch one. Without this, a single real run() call used to
        unlock an unlimited number of subsequent report_vulnerability/
        log_attack_attempt calls until the next switch_mode - closing that
        gap this way (rather than tracking exactly which vector was tested)
        matches the existing starting prompt, which already tells the model
        to log "immediately after" each attempt: requiring a fresh run()
        before the *next* claim is the intended workflow, not an extra
        burden. Same synchronous-instance-attribute pattern as
        _mark_tested/_set_mode - see their comments for why tool calls need
        to observe this immediately rather than only after the next
        _call_model flush."""
        self._tested_since_mode_switch = False

    def _set_current_session(self, name: Optional[str], command: Optional[str]):
        """Updates the live "current session" record read by
        _render_context_message every turn - see that field's comment in
        __init__. Called from agent_tools.py's new_session/switch_session/
        close_session (whenever the current session's identity actually
        changes) and from run()'s defensive auto-reopen path, plus once
        from start_agent()'s pre-open of the default session before turn
        one. Pass (None, None) when no session is current at all (e.g.
        right after close_session removes the last open session)."""
        self._current_session_name = name
        self._current_session_command = command

    def _set_authorized_ports(self, new_ports: List[int]):
        """Updates the live authorized-ports override read by
        _render_context_message every turn - see _authorized_ports_override's
        comment in __init__ for why this needs to be a synchronous, live
        attribute rather than only a checkpoint patch. Called directly from
        request_port_access's own tool call (agent_tools.py), the moment a
        grant is actually committed to the DB/firewall - unlike
        _apply_granted_ports below, this takes effect on the very next
        turn even within the SAME astream() call that just ran the tool."""
        self._authorized_ports_override = new_ports

    async def _apply_granted_ports(self, config: RunnableConfig, new_ports: list[int]):
        """Patches AgentState.target_scope's ports in place right after
        request_port_access successfully widens Target.ports and reopens
        the firewall for it - for PERSISTENCE across a pause/resume only
        (a fresh Agent instance on resume starts _authorized_ports_override
        back at None, so without this the checkpointed target_scope would
        revert to showing the pre-grant ports list after a pause). Without
        _set_authorized_ports's live override above, this alone would also
        be the mechanism for same-run visibility, but a checkpoint patch
        takes effect one whole turn later than intended (see
        _authorized_ports_override's comment) - it is not a substitute for
        that live update, only a complement to it for the resume case.

        Merges into whatever's already in the checkpoint (union, not
        overwrite) rather than trusting `new_ports` as the final word: if
        two request_port_access calls land in the same turn, this method
        runs once per call in tool_calls list order, which is NOT
        necessarily the order they actually committed in (each call's own
        `new_ports` snapshot is only guaranteed to include grants already
        committed before IT ran) - overwriting with a possibly-earlier
        snapshot after a later, more-complete one was already applied
        would silently drop a just-granted port from the reminder. A union
        is order-independent and always converges to the full set.

        Must only ever be called BETWEEN graph steps (see its call site in
        start_agent's message-consumption loop, right after a completed
        step's messages are yielded) - never from within a live tool call's
        own execution. A step's checkpoint is written as part of that
        step, before its update is made visible to the stream consumer;
        calling aupdate_state from inside the tool coroutine itself would
        race that write and be silently discarded once the step's own
        (target_scope-unaware) checkpoint lands after it."""
        current_state = await self.app.aget_state(config)
        scope = dict(current_state.values.get("target_scope") or {})
        scope["ports"] = sorted(set(scope.get("ports") or []) | set(new_ports))
        await self.app.aupdate_state(config, {"target_scope": scope})

    async def _tools_node(self, state: AgentState, config: RunnableConfig):
        """Wraps the real ToolNode with a pre-dispatch check for the race
        described above _MODE_GATE_WRITER_TOOL_NAMES: a turn whose
        tool_calls mix a writer (run/new_session/switch_mode/...) with a
        reader (report_vulnerability/log_attack_attempt), OR pair
        switch_mode with any other writer, is rejected outright - NONE of
        that turn's calls execute for real, and every one gets a synthetic
        ToolMessage explaining why, so the model can retry them as separate
        turns instead. This removes the race by construction (a writer and
        a reader - including switch_mode's own read of has_tested() - can
        never actually run concurrently against each other) rather than
        trying to out-time asyncio.gather."""
        last_message: AIMessage = state["messages"][-1]
        tool_calls = last_message.tool_calls

        names = {tc["name"] for tc in tool_calls}
        writers, reader_like = _mode_gate_conflict(names)

        if reader_like:
            # reader_like must run AFTER writers - writers (minus
            # reader_like itself, for the switch_mode-vs-writer case where
            # switch_mode is a member of both sets) is what needs to go
            # first. See _mode_gate_conflict's own docstring for why
            # switch_mode can end up as reader_like here.
            rejection = (
                "Rejected: this turn called "
                f"{', '.join(sorted(writers))} together with "
                f"{', '.join(sorted(reader_like))} in the SAME turn - none "
                "of these calls ran. Tool calls in one turn execute "
                "concurrently, so a report_vulnerability/log_attack_attempt "
                "call (or switch_mode) can't reliably see a run()/"
                "new_session()/searchsploit_run/... result from the very "
                "same turn. See the result of "
                f"{', '.join(sorted(writers - reader_like))} on its own "
                f"turn FIRST, then call {', '.join(sorted(reader_like))} "
                "on a later turn."
            )
            return {
                "messages": [
                    ToolMessage(content=rejection, tool_call_id=tc["id"], name=tc["name"])
                    for tc in tool_calls
                ]
            }

        try:
            return await self._tool_node.ainvoke(state, config)
        except Exception as e:
            # A malformed tool call - observed in production: a local model
            # passed a list where a tool declares a plain str argument,
            # raising a raw TypeError ("unexpected keyword argument") during
            # argument binding, before the tool's own body ever runs. This
            # happens outside what LangGraph's ToolNode treats as a normal
            # "tool raised an exception" case (which it already converts to
            # a ToolMessage on its own), so it propagated all the way up and
            # ended the entire run over a single bad call. Converting it
            # into a ToolMessage per call instead lets the model see the
            # failure and retry with corrected argument types next turn.
            print(f"Tool dispatch failed for {sorted(names)}: {e}")
            return {
                "messages": [
                    ToolMessage(
                        content=(
                            f"Tool call failed: {e}. Check that each "
                            "argument's type matches what the tool expects "
                            "(e.g. a plain string, not a list) and try "
                            "again."
                        ),
                        tool_call_id=tc["id"],
                        name=tc["name"],
                    )
                    for tc in tool_calls
                ]
            }

    def _build_graph(self):
        workflow = StateGraph(AgentState)

        # Nodes
        workflow.add_node("agent", self._call_model)
        self._tool_node = ToolNode(self.tools)
        workflow.add_node("tools", self._tools_node)

        # Edges
        workflow.add_edge(START, "agent")
        workflow.add_conditional_edges("agent", self._should_continue, ["tools", END])
        workflow.add_edge("tools", "agent")

        return workflow.compile(
            checkpointer=self.checkpointer, interrupt_before=["tools"]
        )

    @staticmethod
    def _render_target_scope_reminder(target_scope: Optional[AgentTargetScope]) -> str:
        """Re-states the exact authorized address every turn, for the same
        reason mode/enumeration are re-injected below - the starting
        prompt's target scope is otherwise only ever seen once, as part of
        the very first message. Observed in production: on a target named
        after a well-known vulnerable-by-design box (e.g. "Metasploitable
        2"), a local model drifted into scanning a plausible-looking IP it
        associated with that name from its own training data instead of
        the actual one given in scope - wasting a run chasing a host that
        was never actually configured here. Re-stating the real address
        every turn gives it much less room to substitute a memorized one."""
        if not target_scope:
            return ""

        def _value(v):
            if isinstance(v, list):
                return ", ".join(str(x) for x in v) if v else "not defined"
            return str(v) if v not in (None, "") else "not defined"

        return (
            "### Authorized target - use exactly this, never a different "
            "address you recall for a target with this name:\n"
            f"- Name: {_value(target_scope.get('name'))}\n"
            f"- IPv4: {_value(target_scope.get('ipv4'))}\n"
            f"- IPv6: {_value(target_scope.get('ipv6'))}\n"
            f"- Authorized ports: {_value(target_scope.get('ports'))}"
        )

    def _render_context_message(self, state: AgentState) -> SystemMessage:
        """Renders the current scouting/exploiting mode plus the running
        enumeration table / attack-attempt log as one compact reminder,
        every turn - so neither the current focus nor a fact from many
        turns ago (or from before a pause/resume) depends on the model
        re-finding it buried in a long transcript. The one-time starting
        prompt's directives are only ever sent once, as the very first
        message of what can be a long run - re-injecting this every turn is
        far more reliable than relying on the model to remember that, which
        matters more here than usual given this runs on local Ollama models
        with comparatively weak long-context recall and often a small
        context window to begin with."""
        target_scope = state.get("target_scope")
        if self._authorized_ports_override is not None and target_scope:
            # See _authorized_ports_override's comment - overrides the
            # checkpointed ports with whatever's actually been granted this
            # run, since the checkpoint alone can lag by a turn.
            target_scope = {**target_scope, "ports": self._authorized_ports_override}
        scope_reminder = self._render_target_scope_reminder(target_scope)
        lines = [scope_reminder, ""] if scope_reminder else []

        mode = self.mode
        lines.append(f"### Current mode: {mode}")
        if mode == "scouting":
            lines.append(
                "Focus on enumeration - identify open ports/services and "
                "their versions. switch_mode to \"exploiting\" once you "
                "have a specific service/version and a candidate "
                "vulnerability to test."
            )
        else:
            lines.append(
                "Focus on testing the specific vector you switched here "
                "for. Before improvising your own exploit/payload (e.g. a "
                "hand-rolled one-liner), check for an existing tested "
                "approach first - e.g. searchsploit for this "
                "service/version, or the relevant tool's own checks - and "
                "follow a real match exactly. switch_mode back to "
                "\"scouting\" if you need broader enumeration first."
            )
            if not self._tested_since_mode_switch:
                lines.append(
                    "You have NOT yet run() anything against the target "
                    "since switching to exploiting mode - report_vulnerability "
                    "and log_attack_attempt will be refused until you do. "
                    "Make the real attempt first."
                )

        unresolved_count = len(self._unresolved_vulnerable_claims)
        if unresolved_count > 0:
            lines.append(
                f"You have {unresolved_count} 'vulnerable' "
                "attack-log entry(ies) with no matching report_vulnerability "
                "call yet - report_vulnerability requires a fresh run() "
                "since your last claim (log_attack_attempt/"
                "report_vulnerability itself consumes proof-of-testing), so "
                "run() again first if you haven't since, then call "
                "report_vulnerability with a real proof_of_concept for "
                "each, or the finding will not be recorded. finish_task "
                "will be refused while any remain unresolved - if one turns "
                "out not to hold up, log_attack_attempt the same target/"
                "vector again with outcome=\"not_vulnerable\" or "
                "\"inconclusive\" to retract it."
            )

        if self._current_session_name is not None:
            lines.append("")
            lines.append(
                f'### Current terminal session: "{self._current_session_name}" '
                f"running `{self._current_session_command}`"
            )
            if self._current_session_command != agent_tools.DEFAULT_SESSION_COMMAND:
                lines.append(
                    f"You are INSIDE {self._current_session_command} right "
                    "now - run()'s input goes directly to it, not a Kali "
                    "shell. Send exactly what you'd type into it (protocol "
                    "commands, credentials, ...), never a shell/Kali command "
                    "like nmap or ls, until you switch_session back to a "
                    "plain-shell session or open a new one."
                )
            elif not self._at_shell_prompt:
                lines.append(
                    "Your last output did not look like your plain shell "
                    "prompt - you may still be inside another program you "
                    "launched directly (e.g. run(\"ftp <host>\")), such as "
                    "ftp, telnet, or an interpreter, even though this "
                    "session was opened as a plain shell. If you didn't "
                    "mean to be, exit it first (e.g. `quit`/`exit`/`bye`) "
                    "before running further shell commands like nmap - they "
                    "will otherwise just be typed at that program's prompt "
                    "and silently fail."
                )

        enumeration = state.get("enumeration") or {}
        attack_log = state.get("attack_log") or []

        if enumeration or attack_log:
            lines.append("")
            lines.append(
                "### Known so far (auto-maintained - trust this over your "
                "own memory of earlier turns, and don't repeat work it "
                "already covers):"
            )

            if enumeration:
                lines.append("Enumeration:")
                for port in sorted(enumeration):
                    info = enumeration[port]
                    detail = " ".join(
                        part
                        for part in (info.get("service", ""), info.get("version", ""))
                        if part
                    )
                    line = f"- {port}: {detail}" if detail else f"- {port}"
                    if info.get("notes"):
                        line += f" ({info['notes']})"
                    lines.append(line)

            if attack_log:
                lines.append("Attempted attack vectors:")
                shown_attack_log = attack_log
                omitted_count = len(attack_log) - _MAX_ATTACK_LOG_ENTRIES_SHOWN
                if omitted_count > 0:
                    shown_attack_log = attack_log[-_MAX_ATTACK_LOG_ENTRIES_SHOWN:]
                    lines.append(
                        f"[{omitted_count} earlier attempt(s) also logged - "
                        "don't repeat one of those just because it scrolled "
                        "out of this view.]"
                    )
                for entry in shown_attack_log:
                    line = (
                        f"- [{entry.get('outcome', '?')}] {entry.get('target', '?')}: "
                        f"{entry.get('vector', '?')}"
                    )
                    if entry.get("notes"):
                        line += f" - {entry['notes']}"
                    lines.append(line)

        return SystemMessage(content="\n".join(lines))

    def _recover_leaked_tool_calls(self, response: AIMessage) -> AIMessage:
        """Recovers a tool call Ollama failed to parse into
        response.tool_calls (see _LEAKED_TOOL_CALL_PATTERN above) by
        pulling it back out of .content/reasoning_content, validating it
        names one of our actual tools, and promoting it to a real
        structured tool call so the graph executes it like any other. Also
        strips every matched block from whatever field it was found in -
        regardless of whether it ended up recovered - so garbled or
        duplicate JSON never lingers in the persisted message (and future
        context) as-is, and deduplicates identical calls (by name+args)
        found across both fields or repeated within one, so a leaked block
        that's mirrored/repeated (a real failure mode for a model prone to
        output oscillation) can't be promoted into two real tool
        executions."""
        if response.tool_calls:
            return response

        valid_tool_names = {t.name for t in self.tools}
        recovered: list = []
        seen_calls: set = set()
        update: dict = {}
        any_matches = False

        for field, text in (
            ("content", str(response.content) if response.content else ""),
            ("reasoning_content", response.additional_kwargs.get("reasoning_content") or ""),
        ):
            matches = list(_LEAKED_TOOL_CALL_PATTERN.finditer(text))
            if not matches:
                continue
            any_matches = True

            cleaned = text
            for match in matches:
                try:
                    call = json.loads(match.group(1))
                except json.JSONDecodeError:
                    cleaned = cleaned.replace(
                        match.group(0), "[malformed tool call removed]"
                    ).strip()
                    continue

                name = call.get("name")
                if name not in valid_tool_names:
                    cleaned = cleaned.replace(
                        match.group(0), "[malformed tool call removed]"
                    ).strip()
                    continue

                args = call.get("arguments") or {}
                cleaned = cleaned.replace(match.group(0), "").strip()

                dedup_key = (name, json.dumps(args, sort_keys=True))
                if dedup_key in seen_calls:
                    # Same call leaked more than once - already stripped
                    # above, but only ever promoted to a real tool call once.
                    continue
                seen_calls.add(dedup_key)
                recovered.append(
                    {
                        "name": name,
                        "args": args,
                        "id": f"recovered-{uuid.uuid4()}",
                        "type": "tool_call",
                    }
                )

            if field == "content":
                update["content"] = cleaned
            else:
                update["additional_kwargs"] = {
                    **response.additional_kwargs,
                    "reasoning_content": cleaned,
                }

        if not recovered:
            # Still apply whatever stripping happened above (malformed/
            # duplicate/unknown-tool blocks removed) even when nothing was
            # promotable - previously this returned the response completely
            # unmodified whenever recovery produced zero calls, leaving raw
            # <tool_call>...</tool_call> text sitting in the persisted
            # message (and every future turn's context) forever.
            return response.model_copy(update=update) if any_matches else response

        logger.warning(
            f"Recovered {len(recovered)} tool call(s) Ollama failed to parse "
            f"natively: {[c['name'] for c in recovered]}"
        )
        update["tool_calls"] = recovered
        return response.model_copy(update=update)

    def _fixed_overhead_tokens(self, first_message: BaseMessage) -> int:
        """One-time (memoized) estimate of the fixed per-request cost that
        trimming can never reduce: the starting prompt (messages[0], always
        kept verbatim - see _trim_messages_for_model) plus the bound tools'
        own JSON-schema descriptions, resent with every request once bound
        (see changeModel). Computed lazily against the real first message
        the first time it's needed, rather than guessed at __init__ time -
        the rendered starting prompt isn't known until the graph's first
        turn actually runs."""
        if self._cached_fixed_overhead_tokens is not None:
            return self._cached_fixed_overhead_tokens

        prompt_chars = len(str(first_message.content))
        tools_chars = sum(len(t.description or "") for t in self.tools)
        self._cached_fixed_overhead_tokens = (
            prompt_chars + tools_chars
        ) // _CHARS_PER_TOKEN_ESTIMATE
        return self._cached_fixed_overhead_tokens

    def _message_budget(self, messages: list[BaseMessage]) -> int:
        """How many of the persisted conversation's messages
        _trim_messages_for_model keeps, sized off self.context_window minus
        the fixed overhead this same request will also carry (see
        _fixed_overhead_tokens) - see the module-level comment above
        _CONTEXT_BUDGET_FRACTION for the reasoning behind the constants
        used here. Deliberately does NOT force the result up to some
        minimum floor when the honest computed value is smaller -
        inflating past what the estimate says actually fits is exactly the
        under-trimming failure mode this module exists to avoid; a
        genuinely tiny effective window should produce a genuinely tiny
        budget, not get padded back up."""
        reserved = self._fixed_overhead_tokens(messages[0]) if messages else 0
        usable_tokens = max(0, self.context_window - reserved) * _CONTEXT_BUDGET_FRACTION
        budget = int(usable_tokens // _EST_TOKENS_PER_MESSAGE)
        return max(1, min(_MAX_MESSAGES_SENT_TO_MODEL, budget))

    def _trim_messages_for_model(self, messages: list[BaseMessage]) -> list[BaseMessage]:
        """Shrinks what's actually SENT to the model each turn, independent
        of what's PERSISTED - state["messages"] (and so the UI's full audit
        log via agent_service.py) keeps every message regardless; this only
        affects the invoke() input built here. Safe to drop older turns
        outright because the model's actual working memory - current mode,
        the enumeration table, the attack-attempt log - is independently
        re-synthesized into context_message every single turn (see
        _render_context_message), not reconstructed by the model re-reading
        old messages. Without this, a long-running turn count would grow
        this call's prompt without bound, which a small local model's often
        narrow (commonly 4k-8k token) context window can't absorb.

        Always keeps the very first message (the rendered starting prompt -
        target scope, tool inventory, operating directives) as a stable
        anchor, plus as many of the most recent messages as the budget
        allows. Never lets the kept "recent" window start on a bare
        ToolMessage - every backend's tool-call/tool-response linkage
        expects one to immediately follow the AIMessage(tool_calls=...) it
        answers, so an orphaned one at the very start of the window (i.e.
        missing that AIMessage, which fell on the trimmed side of the cut)
        risks a hard error from the chat template, not just confusion."""
        budget = self._message_budget(messages)
        if len(messages) <= budget:
            return messages

        first = messages[0]
        candidate_start = max(1, len(messages) - (budget - 1))

        start = candidate_start
        while start < len(messages) and isinstance(messages[start], ToolMessage):
            start += 1

        if start <= 1:
            # Budget is generous enough relative to how much history exists
            # that trimming would keep nearly the whole conversation anyway
            # - not worth an "earlier turns omitted" notice for near-zero
            # savings.
            return messages

        if start >= len(messages):
            # No message at/after the candidate cut point is safe to start
            # the kept "recent" window on - either budget collapsed so far
            # (e.g. fixed overhead alone now exceeds a small model's real
            # context - see _message_budget) that candidate_start itself
            # landed at/past the end, or the whole remaining tail turned
            # out to be one unbroken run of ToolMessages. Previously this
            # fell back to the FULL untrimmed conversation - which, now
            # that _message_budget no longer inflates a tiny honest budget
            # up to a artificial floor, turned this rare edge case into the
            # COMMON case for any small-context model: trimming would
            # silently do NOTHING AT ALL, exactly the under-trimming
            # failure mode this whole module exists to prevent. Dropping
            # the ENTIRE recent window instead (keep only the anchor) is
            # always safe re: orphaning (there is no trailing ToolMessage
            # left to orphan when nothing trailing is kept) and is the
            # correct, conservative response to a genuinely tiny budget.
            notice = SystemMessage(
                content=(
                    f"[{len(messages) - 1} earlier turn(s) omitted here - "
                    "your effective context window is small enough that "
                    "none of the recent conversation fits alongside the "
                    "starting prompt and tools. They are NOT lost: the "
                    "current mode, enumeration table, and attack-attempt "
                    "log shown below already reflect everything learned in "
                    "them. Don't re-run something already listed there.]"
                )
            )
            return [first, notice]

        recent = messages[start:]
        trimmed_count = start - 1

        notice = SystemMessage(
            content=(
                f"[{trimmed_count} earlier turn(s) omitted here to keep "
                "this prompt a manageable size - they are NOT lost: the "
                "current mode, enumeration table, and attack-attempt log "
                "shown below already reflect everything learned in them. "
                "Don't re-run something already listed there just because "
                "you can no longer see the turn that found it.]"
            )
        )
        return [first, notice] + recent

    async def _call_model(self, state: AgentState):
        """Node: one LLM call per turn, tools bound directly, with
        reasoning=True (set in changeModel) so native "thinking" models can
        surface their reasoning via additional_kwargs['reasoning_content']
        - see the module-level comment above for why this replaced the
        previous two-call split. The response is persisted as-is;
        reasoning_content (when present) is read out for logging by
        agent_service.py's _message_to_log_specs, not touched here.

        async + ainvoke (not sync invoke) is required for "finish" to
        actually abort a mid-generation call, not just discard its result:
        a sync invoke() runs in a thread-pool executor under astream(),
        and asyncio.Task.cancel() (see start_agent's stream_task.cancel())
        can only interrupt code at an await point on the event loop - it
        cannot stop code already running in a worker thread. ainvoke()
        awaits langchain_ollama's async (httpx) client directly, so a
        cancel here actually tears down the in-flight HTTP request instead
        of letting Ollama keep generating in the background."""
        messages = list(state["messages"])
        context_message = self._render_context_message(state)

        trimmed_messages = self._trim_messages_for_model(messages)
        try:
            response = await self.llm_with_tools.ainvoke(trimmed_messages + [context_message])
        except OllamaResponseError as e:
            # Observed in production: a model detected as reasoning-capable
            # (via Ollama's own reported capabilities list, or the name/
            # modelfile heuristic in capabilities_from_show_info) can still
            # have Ollama itself reject the `think` parameter outright at
            # the first real chat call - e.g. "granite4.1:8b" does not
            # support thinking (status code: 400) - a genuine mismatch
            # between what's advertised and what the loaded template
            # actually accepts, not something detectable up front without
            # just trying it. Rather than crash the whole run over a wrong
            # capability guess, permanently disable reasoning for this
            # Agent instance (changeModel rebuilds self.llm_with_tools in
            # place, so every later turn already uses the corrected model)
            # and retry this exact turn once.
            if e.status_code == 400 and "does not support thinking" in (e.error or ""):
                print(
                    f"Model {self.model_name} rejected reasoning=True "
                    f"({e.error}) - retrying with reasoning=False"
                )
                self.changeModel(self.model_name, reasoning=False)
                response = await self.llm_with_tools.ainvoke(trimmed_messages + [context_message])
            else:
                raise
        response = self._recover_leaked_tool_calls(response)

        # Fold whatever tool calls buffered since the last turn (see
        # _record_enumeration/_record_attack_attempt) into the checkpointed
        # state fields, per-field-merging enumeration entries rather than
        # replacing them outright so a later, narrower fact about a port
        # (e.g. just a note) can't clobber an earlier service/version.
        enumeration = dict(state.get("enumeration") or {})
        for port, fact in self._pending_enumeration.items():
            merged = {**enumeration.get(port, {}), **{k: v for k, v in fact.items() if v}}
            enumeration[port] = merged
        self._pending_enumeration = {}

        attack_log = list(state.get("attack_log") or [])
        attack_log.extend(self._pending_attack_log)
        self._pending_attack_log = []

        return {
            "messages": [response],
            "enumeration": enumeration,
            "attack_log": attack_log,
            "mode": self.mode,
            "tested_since_mode_switch": self._tested_since_mode_switch,
            "unresolved_vulnerable_claims": [
                list(pair) for pair in self._unresolved_vulnerable_claims
            ],
            "finish_summary": self.finish_summary,
        }

    def _should_continue(self, state: AgentState):
        last_message = state["messages"][-1]
        if isinstance(last_message, AIMessage) and last_message.tool_calls:
            return "tools"
        return END

    def changeModel(self, model_name: str, reasoning: Optional[bool] = None):
        # Stored so _call_model can rebuild this on the fly (same model,
        # reasoning forced off) if Ollama itself rejects `think` for this
        # model at the first real chat call - see _call_model's own
        # handling of ollama.ResponseError below.
        self.model_name = model_name
        # repeat_penalty/repeat_last_n: previously raised to 1.3/256 (above
        # Ollama's own defaults of ~1.1/64) because qwen3:8b was observed
        # getting stuck oscillating within a single reasoning generation
        # ("it's A - no, maybe B - no, it's A" repeated many times) rather
        # than converging - reasoned at the time to be a "universal"
        # anti-repetition knob, not conditioned on model name/family.
        # That assumption didn't hold: the same 1.3/256 tuning, tried
        # against qwen3.5:9b, produced the opposite failure mode instead -
        # forced to avoid any token used in the last 256, it ran out of
        # normal vocabulary and spiraled into emoji/symbol noise within two
        # turns, never once reaching a tool call. Reverted to Ollama's own
        # defaults (omitted here entirely rather than re-hardcoded, so a
        # future Ollama default change is inherited automatically) - well-
        # tested across model families generally, unlike a one-off value
        # tuned against a single model's single observed failure. If
        # qwen3:8b's oscillation resurfaces, that's a model-specific
        # problem to solve for that model specifically, not by pushing a
        # global sampling knob further for everyone.
        #
        # reasoning, by contrast, IS model-specific and was previously
        # hardcoded True for every model regardless of whether its own
        # chat template actually supports interleaving thinking with a
        # tool call - a non-reasoning model (e.g. a plain instruct-tuned
        # 8B) forced into reasoning=True was observed able to return
        # empty/garbled output instead of a usable response. `reasoning`
        # here comes from ollama_manager.get_model_capabilities (see
        # agent_service.py) when that lookup succeeded; None (lookup
        # unavailable/failed, or a direct changeModel call from elsewhere
        # that doesn't pass one) preserves the old default of True rather
        # than silently disabling reasoning for a model that might need it.
        use_reasoning = True if reasoning is None else reasoning
        llm = ChatOllama(
            model=model_name,
            base_url=self.ollama_url,
            reasoning=use_reasoning,
            # repeat_penalty/repeat_last_n deliberately left unset - see
            # this method's opening comment for why they're no longer
            # overridden here.
            # Force Ollama to actually allocate this model's real (or
            # project-/globally-capped) context window - self.context_window
            # is set in __init__ from ollama_manager.get_model_capabilities,
            # already clamped to settings.DEFAULT_MAX_CONTEXT_WINDOW or the
            # project's own override (see agent_service.py's
            # _prepare_and_run). Without this, Ollama silently falls back to
            # its own server-side default (commonly 2048-4096) regardless of
            # what the model actually supports or what _message_budget()
            # above assumes it has room for.
            num_ctx=self.context_window,
        )
        self.llm_with_tools = llm.bind_tools(self.tools)

    # --- Execution and Interaction ---
    async def start_agent(
        self,
        target: Target,
        start_prompt: str,
        thread_id: str,
        should_interrupt: bool,
        duration_seconds: int,
        stop_event: asyncio.Event | None = None,
        run_state: dict | None = None,
    ) -> AsyncGenerator[BaseMessage | AgentInterruptAction | AgentContextUsageEvent, None]:
        config: RunnableConfig = {"configurable": {"thread_id": thread_id}}

        if stop_event is None:
            stop_event = asyncio.Event()

        if run_state is None:
            run_state = {}

        existing_state = await self.app.aget_state(config)

        if existing_state.values:
            input_data = None
            # Restore the live mode from the checkpoint - a fresh Agent
            # instance always starts at self.mode = "scouting" (see
            # __init__), so resuming a paused run that had switched to
            # "exploiting" needs this or it would silently reset. Same
            # reasoning for tested_since_mode_switch/finish_summary - see
            # their fields on AgentState.
            self.mode = existing_state.values.get("mode", self.mode)
            self._tested_since_mode_switch = existing_state.values.get(
                "tested_since_mode_switch", self._tested_since_mode_switch
            )
            checkpointed_claims = existing_state.values.get("unresolved_vulnerable_claims")
            if checkpointed_claims is not None:
                self._unresolved_vulnerable_claims = {
                    tuple(pair) for pair in checkpointed_claims
                }
            self.finish_summary = existing_state.values.get(
                "finish_summary", self.finish_summary
            )
        else:
            target_scope: AgentTargetScope = {
                "name": target.name,
                "ipv4": target.ipv4,
                "ipv6": target.ipv6,
                "description": target.description,
                "ports": target.ports,
            }
            input_data = {
                "messages": [("user", start_prompt)],
                "target_scope": target_scope,
            }

        # Give the agent a terminal from turn one - no "open a session
        # first" step for it to forget. Best-effort: if this fails (should
        # only happen if the container isn't actually ready yet), the run
        # tool itself opens "default" defensively on its first call anyway.
        manager = await kali_registry.get_manager(self.project_id)
        if not manager.has_current_session(self.target_id, self.agent_run_id):
            try:
                await manager.open_session(
                    self.target_id,
                    self.agent_run_id,
                    agent_tools.DEFAULT_SESSION_NAME,
                    agent_tools.DEFAULT_SESSION_COMMAND,
                )
            except Exception as e:
                print(f"Could not pre-open default session for {self.target_id}: {e}")

        # Prime the "current session" reminder (see _set_current_session) for
        # both a fresh start and a resume - whatever session is actually
        # current right now (just pre-opened above, already open from
        # before this call, or still none if the pre-open itself failed)
        # becomes the value _render_context_message shows from turn one.
        current = manager.get_current_session(self.target_id, self.agent_run_id)
        self._set_current_session(
            current.name if current else None,
            current.command if current else None,
        )

        time_left = duration_seconds
        run_state["time_left"] = time_left

        # The only sanctioned way for the agent to end its own run is
        # finish_task. If the model instead responds with no tool call at
        # all - a real risk especially for smaller local models, and
        # observed in practice - the graph reaches END on its own, which
        # would otherwise silently end the whole run even with time left on
        # the clock and no error logged anywhere. Nudge it back into acting
        # instead, and only actually give up after several such turns in a
        # row (protects against a truly stuck model spinning forever).
        consecutive_no_tool_calls = 0
        MAX_CONSECUTIVE_NO_TOOL_CALLS = 5
        NUDGE_MESSAGE = (
            "You did not call a tool on your last turn - every turn must "
            "end with a tool call. If you wrote out a command or session "
            "prompt as plain text or in a code block, that did NOT run it; "
            "nothing happens until you make a real tool call - if you meant "
            "to send input to your current session, call run(input=...) "
            "now. Continue the assessment with a tool call, or call "
            "finish_task if it is genuinely complete."
        )
        # A rejected report_vulnerability/log_attack_attempt claim (see
        # agent_tools.CLAIM_REJECTED_MARKER) is a special case of the above:
        # observed in production (granite4.1:8b) going completely silent -
        # not even thinking text, an actually empty completion - for every
        # remaining nudge turn after this specific rejection, until the
        # stall circuit breaker below ended the run. The generic nudge
        # doesn't name a concrete next step for "your finding wasn't
        # believed"; this one does.
        NUDGE_MESSAGE_AFTER_CLAIM_REJECTED = (
            "You did not call a tool on your last turn. Your last finding "
            "claim was rejected because the evidence didn't support it - "
            "that does not mean the assessment is over, and going silent "
            "is not a valid response. Pick one concrete action right now: "
            "(1) make the real run() call you were claiming credit for and "
            "report only what it actually shows, (2) try a different "
            "vector against the same service, (3) move on to a different "
            "port/service you haven't fully tested yet, or (4) call "
            "finish_task if you're confident there is genuinely nothing "
            "left worth trying. Make a real tool call now."
        )

        while (
            not stop_event.is_set()
            and time_left > 0
            and self.finish_summary is None
        ):
            loop_start = time.monotonic()
            
            event_queue = asyncio.Queue()
            
            async def _stream_worker():
                try:
                    async for event in self.app.astream(
                        input_data, config=config, stream_mode="updates"
                    ):
                        await event_queue.put(event)
                except Exception as e:
                    # Without this, any failure here (bad checkpointer state,
                    # Ollama unreachable, etc.) would silently look identical
                    # to the graph reaching END - the run would just "finish"
                    # instantly with no explanation.
                    await event_queue.put(e)
                finally:
                    await event_queue.put(None)
                    
            stream_task = asyncio.get_running_loop().create_task(_stream_worker())

            try:
                while not stop_event.is_set():
                    # Race waiting for next event vs stop_event being set
                    get_event_task = asyncio.create_task(event_queue.get())
                    stop_wait_task = asyncio.create_task(stop_event.wait())
                    
                    done, pending = await asyncio.wait(
                        [get_event_task, stop_wait_task],
                        return_when=asyncio.FIRST_COMPLETED
                    )    
                    
                    for task in pending:
                        task.cancel()
                        
                    if stop_wait_task in done:
                        # User requested pause/stop mid-generation - abort 
                        stream_task.cancel()
                        return
                    
                    event = get_event_task.result()
                    if event is None:
                        break

                    if isinstance(event, BaseException):
                        raise event

                    # stream_mode="updates" yields {node_name: {"messages": [...]}} -
                    # the update is keyed by the node that produced it, not "messages"
                    # directly.
                    for node_update in event.values():
                        if not isinstance(node_update, dict):
                            continue
                        for message in node_update.get("messages", []):
                            yield message
                            if (
                                isinstance(message, ToolMessage)
                                and message.name == agent_tools.REQUEST_PORT_ACCESS_TOOL_NAME
                                and message.artifact
                            ):
                                await self._apply_granted_ports(config, message.artifact)
                            # Real per-turn token counts from Ollama itself
                            # (see AgentContextUsageEvent's own comment) -
                            # only ever present on the AIMessage _call_model
                            # just produced, never on a ToolMessage.
                            if isinstance(message, AIMessage) and message.usage_metadata:
                                input_tokens = message.usage_metadata.get("input_tokens")
                                if input_tokens is not None:
                                    yield AgentContextUsageEvent(
                                        kind="context_usage",
                                        used_tokens=input_tokens,
                                        context_window=self.context_window,
                                    )

                    if self.finish_summary is not None:
                        # finish_task just ran as part of this step - stop
                        # immediately rather than letting the unconditional
                        # tools -> agent edge run one more (wasted) LLM turn.
                        stream_task.cancel()
                        return
            finally:
                if not stream_task.done():
                    stream_task.cancel()
            
            if stop_event.is_set():
                break                
            
            input_data = None
            state = await self.app.aget_state(config)

            if state.next == ("tools",):
                consecutive_no_tool_calls = 0
                last_message: AIMessage = state.values["messages"][-1]
                tool_calls = last_message.tool_calls

                # execute_kali_command is commented out (see agent_tools.py)
                # - run/new_session and the Tier 1/2 tools are what actually
                # execute something in the container/against the target, so
                # those are what should_interrupt gates on instead (see
                # _INTERRUPT_GATED_TOOL_NAMES).
                tool_call_names = {tc["name"] for tc in tool_calls}
                # _tools_node rejects this exact turn outright (see its own
                # docstring and _mode_gate_conflict) whenever it mixes a
                # writer with a reader-like tool (a real reader, or
                # switch_mode paired with another writer) - don't ask the
                # user to approve a run()/new_session() call that's going
                # to be rejected the moment it's resumed regardless of
                # their answer; that made an approval look like a silent
                # no-op. Let it flow straight through to _tools_node
                # instead, which explains the rejection to the model
                # directly. Uses the exact same _mode_gate_conflict helper
                # _tools_node itself calls, specifically so this pre-check
                # can't drift out of sync with what _tools_node will
                # actually reject.
                _, reader_like = _mode_gate_conflict(tool_call_names)
                batch_will_be_rejected = bool(reader_like)
                # request_port_access must pause for approval unconditionally
                # - see _ALWAYS_INTERRUPT_TOOL_NAMES - even on a project that
                # has should_interrupt turned off entirely.
                always_interrupt = bool(tool_call_names & _ALWAYS_INTERRUPT_TOOL_NAMES)
                requires_interrupt = not batch_will_be_rejected and (
                    always_interrupt
                    or (should_interrupt and bool(tool_call_names & _INTERRUPT_GATED_TOOL_NAMES))
                )

                if not requires_interrupt:
                    time_left -= (time.monotonic() - loop_start)
                    run_state["time_left"] = time_left
                    input_data = None
                    continue
                else:
                    loop = asyncio.get_running_loop()
                    resume_future: asyncio.Future[bool] = loop.create_future()

                    def accept(approved: bool):
                        if not resume_future.done():
                            resume_future.set_result(approved)

                    interrupt_action: AgentInterruptAction = {
                        "kind": "interrupt",
                        "accept": accept,
                        "tool_calls": tool_calls,
                    }

                    # Pause timer awaiting for user's action
                    time_left -= (time.monotonic() - loop_start)
                    run_state["time_left"] = time_left

                    yield interrupt_action

                    # Race the approval against stop_event, the same way the
                    # streaming loop above does - without this, pausing
                    # while a run()/new_session() call is awaiting approval
                    # had zero effect: the only way out used to be an actual
                    # approve/reject via the websocket, so the run stayed
                    # stuck at INTERRUPTED indefinitely regardless of a
                    # pause request.
                    stop_wait_task = asyncio.create_task(stop_event.wait())
                    done, pending = await asyncio.wait(
                        [resume_future, stop_wait_task],
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for task in pending:
                        task.cancel()

                    if resume_future not in done:
                        # Paused while this approval was still pending -
                        # leave resume_future unresolved (cancelled, never
                        # approved or rejected) rather than force a decision.
                        # Nothing is lost: state.next is still ("tools",) in
                        # the checkpoint (the tools node never actually ran),
                        # so resuming this run re-enters this exact branch
                        # against the same pending tool call and re-surfaces
                        # the same approval request normally.
                        resume_future.cancel()
                        return

                    is_approved: bool = resume_future.result()

                    # Resume the clock fresh - time spent waiting for the
                    # user's decision must not count against the budget.
                    loop_start = time.monotonic()

                    if is_approved:
                        input_data = None
                    else:
                        rejection_messages = [
                            ToolMessage(
                                content="User Denied Execution. Do not attempt this specific command again. Re-evaluate your approach.",
                                tool_call_id=tc["id"],
                                name=tc["name"],
                            )
                            for tc in tool_calls
                        ]
                        await self.app.aupdate_state(
                            config, {"messages": rejection_messages}, as_node="tools"
                        )
                        input_data = None

            else:
                consecutive_no_tool_calls += 1
                if consecutive_no_tool_calls >= MAX_CONSECUTIVE_NO_TOOL_CALLS:
                    yield AIMessage(
                        content=(
                            "Stopping the run: the model did not call a "
                            f"tool for {MAX_CONSECUTIVE_NO_TOOL_CALLS} "
                            "consecutive turns."
                        )
                    )
                    break

                # The most recent ToolMessage stays fixed for the whole
                # no-tool-call streak (nothing produces a new one until a
                # real tool call succeeds again), so this reliably reflects
                # what triggered THIS stall, however many nudge turns deep
                # into it we already are.
                nudge_message = NUDGE_MESSAGE
                messages = state.values.get("messages", [])
                last_tool_message = next(
                    (m for m in reversed(messages) if isinstance(m, ToolMessage)),
                    None,
                )
                if last_tool_message is not None and agent_tools.CLAIM_REJECTED_MARKER in str(
                    last_tool_message.content
                ):
                    nudge_message = NUDGE_MESSAGE_AFTER_CLAIM_REJECTED

                input_data = {"messages": [SystemMessage(content=nudge_message)]}

            time_left -= (time.monotonic() - loop_start)
            run_state["time_left"] = time_left