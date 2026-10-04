"""Generic, non-behavioral plumbing shared by every multi-agent pipeline
role (orchestrator/scouting/pentesting/reporting) - see the "Each role is
its own file/class, not one Agent parametrized by a role flag" decision in
docs/features/multi-agent-pentest-pipeline.md's implementation plan.

Nothing here encodes role-specific judgment - what tools a role has, what
its prompt says, when it considers itself "done" - only mechanics every
role's own graph needs identically: model-capability resolution, token-
budget trimming, the turn-level writer/reader race guard, and the
cancellation-safe stream-and-stop loop. agent.py (the Single Agent
implementation) is deliberately never imported from or reached into here -
it stays its own separate, untouched implementation; this module just
happens to solve the same mechanical problems for the new roles, ported
from (not inherited from) the same proven logic.
"""

import asyncio
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
)
from langchain_core.messages import AIMessage, BaseMessage, SystemMessage, ToolMessage
from langchain_core.runnables import RunnableConfig
from langgraph.prebuilt import ToolNode
from src.core import ollama_manager
from src.core import settings as core_settings

# --- Model capability resolution ---
# Used whenever ollama_manager.get_model_capabilities couldn't be reached -
# a conservative floor, not a real default any current model ships with,
# matching ollama_manager.capabilities_from_show_info's own fallback.
DEFAULT_CONTEXT_WINDOW_FALLBACK = 2048


async def resolve_model_capabilities(
    model_name: str, max_context_window_override: Optional[int]
) -> Tuple[Optional[bool], int]:
    """Best-effort (reasoning, context_window) for model_name - mirrors
    agent_service.py's _prepare_and_run exactly (same ceiling-clamping:
    the project's own max_context_window override, or the system-wide
    DEFAULT_MAX_CONTEXT_WINDOW), extracted here so each of the 4 roles
    doesn't duplicate it. Falls back to (None, DEFAULT_CONTEXT_WINDOW_FALLBACK)
    - never raising - on any lookup failure: a model whose capabilities
    can't be looked up still gets to run, just with conservative
    defaults rather than failing the whole run over a lookup that's only
    ever an optimization."""
    try:
        capabilities = await ollama_manager.get_model_capabilities(model_name)
        ceiling = max_context_window_override or core_settings.DEFAULT_MAX_CONTEXT_WINDOW
        return capabilities["thinking"], min(capabilities["context_window"], ceiling)
    except Exception as e:
        print(f"Could not fetch capabilities for model '{model_name}', using defaults: {e}")
        return None, DEFAULT_CONTEXT_WINDOW_FALLBACK


# --- Token-budget trimming ---
# Same constants/reasoning as agent.py's Agent - see its own module-level
# comments for the full justification. Ported verbatim as plain functions
# (no `self`) rather than imported from agent.py - that file stays the
# Single Agent implementation's own, untouched.
_CONTEXT_BUDGET_FRACTION = 0.5
_EST_TOKENS_PER_MESSAGE = 250
_MAX_MESSAGES_SENT_TO_MODEL = 80
_CHARS_PER_TOKEN_ESTIMATE = 4


def _fixed_overhead_tokens(first_message_content: str, tools: list) -> int:
    tools_chars = sum(len(t.description or "") for t in tools)
    return (len(first_message_content) + tools_chars) // _CHARS_PER_TOKEN_ESTIMATE


def _message_budget(context_window: int, fixed_overhead: int) -> int:
    usable_tokens = max(0, context_window - fixed_overhead) * _CONTEXT_BUDGET_FRACTION
    budget = int(usable_tokens // _EST_TOKENS_PER_MESSAGE)
    return max(1, min(_MAX_MESSAGES_SENT_TO_MODEL, budget))


def trim_messages_for_model(
    messages: List[BaseMessage], context_window: int, tools: list
) -> List[BaseMessage]:
    """Shrinks what's SENT to the model each turn, independent of what's
    PERSISTED - see agent.py's Agent._trim_messages_for_model for the full
    reasoning this is ported from (a small local model's narrow context
    window can't absorb an unbounded turn count; each role's own
    _render_context_message-equivalent re-synthesizes working state every
    turn, so dropping old turns here is safe). Always keeps messages[0]
    (the starting prompt) and never starts the kept window on an orphaned
    ToolMessage."""
    if not messages:
        return messages

    fixed_overhead = _fixed_overhead_tokens(str(messages[0].content), tools)
    budget = _message_budget(context_window, fixed_overhead)
    if len(messages) <= budget:
        return messages

    first = messages[0]
    candidate_start = max(1, len(messages) - (budget - 1))
    start = candidate_start
    while start < len(messages) and isinstance(messages[start], ToolMessage):
        start += 1

    if start <= 1:
        return messages

    if start >= len(messages):
        notice = SystemMessage(
            content=(
                f"[{len(messages) - 1} earlier turn(s) omitted here - your "
                "effective context window is small enough that none of the "
                "recent conversation fits alongside the starting prompt and "
                "tools. Trust the state shown to you each turn over your "
                "own memory of earlier ones.]"
            )
        )
        return [first, notice]

    recent = messages[start:]
    trimmed_count = start - 1
    notice = SystemMessage(
        content=(
            f"[{trimmed_count} earlier turn(s) omitted here to keep this "
            "prompt a manageable size - trust the state shown to you each "
            "turn over your own memory of earlier ones.]"
        )
    )
    return [first, notice] + recent


# --- Turn-level writer/reader race guard ---
# Generalizes agent.py's _mode_gate_conflict/_tools_node - the
# switch_mode-vs-other-writer special case is dropped, since none of the 4
# new roles has a mode to switch at all.


def turn_conflict(
    tool_call_names: Set[str], writer_names: Set[str], reader_names: Set[str]
) -> Tuple[Set[str], Set[str]]:
    """Returns (writers, readers) present in this turn's tool_calls;
    `readers` is empty whenever there's no conflict. See
    make_guarded_tools_node's own docstring for why mixing the two in one
    turn is a real race, not just a style concern."""
    writers = tool_call_names & writer_names
    readers = tool_call_names & reader_names
    if writers and readers:
        return writers, readers
    return writers, set()


def make_guarded_tools_node(
    tool_node: ToolNode, writer_names: Set[str], reader_names: Set[str]
) -> Callable[[dict, RunnableConfig], Awaitable[dict]]:
    """Wraps `tool_node` with the same per-turn writer/reader race guard
    agent.py's _tools_node uses - LangGraph's ToolNode runs every tool
    call from one LLM turn concurrently (asyncio.gather), so a turn that
    mixes a writer (e.g. run()) with a reader of state only that writer
    sets (e.g. report_outcome's has_tested() check) would read it stale
    half the time. Rejecting the whole turn outright (every call in it,
    with an explanatory ToolMessage) removes the race by construction
    instead of trying to out-time it. Also converts a malformed-argument
    TypeError into a ToolMessage per call instead of letting it crash the
    whole run, same as agent.py."""

    async def guarded_tools_node(state: dict, config: RunnableConfig) -> dict:
        last_message: AIMessage = state["messages"][-1]
        tool_calls = last_message.tool_calls
        names = {tc["name"] for tc in tool_calls}
        writers, readers = turn_conflict(names, writer_names, reader_names)

        if readers:
            rejection = (
                "Rejected: this turn called "
                f"{', '.join(sorted(writers))} together with "
                f"{', '.join(sorted(readers))} in the SAME turn - none of "
                "these calls ran. Tool calls in one turn execute "
                "concurrently, so a claim-reporting call can't reliably "
                "see a real action's result from the very same turn. See "
                f"the result of {', '.join(sorted(writers))} on its own "
                f"turn FIRST, then call {', '.join(sorted(readers))} on a "
                "later turn."
            )
            return {
                "messages": [
                    ToolMessage(content=rejection, tool_call_id=tc["id"], name=tc["name"])
                    for tc in tool_calls
                ]
            }

        try:
            return await tool_node.ainvoke(state, config)
        except Exception as e:
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

    return guarded_tools_node


# --- The cancellation-safe stream-and-stop loop ---
# Generalizes agent.py's Agent.start_agent - same async patterns (a
# background task consuming astream() via a queue, raced against
# stop_event so a pause can actually abort an in-flight model call - see
# agent.py's own comment on why ainvoke(), not sync invoke(), is required
# for that), with every role-specific policy decision (when a turn needs
# human approval, what "done" means, what to do with a ToolMessage's
# artifact) taken as a parameter instead of hardcoded.

NUDGE_MESSAGE = (
    "You did not call a tool on your last turn - every turn must end with "
    "a tool call. If you wrote out a command as plain text or in a code "
    "block, that did NOT run it; nothing happens until you make a real "
    "tool call. Continue with a tool call, or call your finish tool if "
    "you are genuinely done."
)
MAX_CONSECUTIVE_NO_TOOL_CALLS = 5


class AgentInterruptAction(Dict[str, Any]):
    """Same shape as agent.py's own - a plain dict with kind="interrupt",
    accept (a callable the caller invokes with True/False), and
    tool_calls. Kept as a dict, not a TypedDict class instance, so
    agent_service.py's existing `isinstance(event, dict)` event-shape
    checks keep working unchanged for every role."""


async def run_graph_loop(
    app,
    thread_id: str,
    input_data: Optional[dict],
    stop_event: asyncio.Event,
    context_window: int,
    is_done: Callable[[], bool],
    requires_interrupt: Callable[[Set[str]], bool],
    on_tool_message: Optional[
        Callable[[ToolMessage, RunnableConfig], Awaitable[None]]
    ] = None,
    duration_seconds: Optional[int] = None,
    run_state: Optional[dict] = None,
    max_turns: Optional[int] = None,
    nudge_message: str = NUDGE_MESSAGE,
    max_consecutive_no_tool_calls: int = MAX_CONSECUTIVE_NO_TOOL_CALLS,
):
    """Runs `app` (a compiled LangGraph, interrupt_before=["tools"]) until
    it's done, stopped, or runs out of budget - yielding raw BaseMessages,
    or dicts shaped like AgentContextUsageEvent/AgentInterruptAction (the
    exact two shapes agent_service.py's _run_agent already knows how to
    consume from the Single Agent flow), one outer iteration per real
    agent turn.

    `input_data=None` resumes an existing checkpoint; a real dict (e.g.
    `{"messages": [...]}`) starts fresh. `is_done()` is checked after
    every processed node update (not just at the top of the outer loop) -
    a role's own finish tool setting its "I'm done" flag mid-step must
    stop this immediately rather than paying for one more (wasted) LLM
    turn. `requires_interrupt(tool_call_names)` decides whether a turn
    paused right before "tools" needs human approval - callers build
    their own predicate (typically from turn_conflict + their own
    interrupt-gated tool names + an "always interrupt" set), since what
    counts as "a real action worth approving" differs per role.
    `on_tool_message`, when given, is awaited once per ToolMessage a step
    produced - e.g. to apply a request_port_access grant - without this
    loop needing to know that tool exists.

    `duration_seconds`/`run_state` are optional: only the orchestrator
    (which owns the pipeline's user-facing timer) needs a wall-clock
    budget; sub-roles pass `duration_seconds=None` and rely on
    `max_turns` (and their own finish tool) instead - an inherently
    bounded task (one scan pass, one vector, one report) has no obvious
    "time remaining" to show a user anyway. `run_state`, when duration
    tracking is in use, is a plain mutable dict updated with
    `"time_left"` on every turn - same shape as agent.py's own, so
    whatever reads it (e.g. the interrupt-response handler flipping the
    timer back to RUNNING) doesn't need a role-specific case."""
    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
    time_left = duration_seconds
    if run_state is not None and time_left is not None:
        run_state["time_left"] = time_left

    consecutive_no_tool_calls = 0
    turns_taken = 0

    while not stop_event.is_set() and not is_done():
        if time_left is not None and time_left <= 0:
            return
        if max_turns is not None and turns_taken >= max_turns:
            yield AIMessage(
                content=(
                    f"Stopping the run: reached the maximum of {max_turns} "
                    "turns for this task."
                )
            )
            return
        turns_taken += 1

        import time as _time

        loop_start = _time.monotonic()
        event_queue: asyncio.Queue = asyncio.Queue()

        async def _stream_worker():
            try:
                async for event in app.astream(input_data, config=config, stream_mode="updates"):
                    await event_queue.put(event)
            except Exception as e:
                await event_queue.put(e)
            finally:
                await event_queue.put(None)

        stream_task = asyncio.get_running_loop().create_task(_stream_worker())

        try:
            while not stop_event.is_set():
                get_event_task = asyncio.create_task(event_queue.get())
                stop_wait_task = asyncio.create_task(stop_event.wait())

                done, pending = await asyncio.wait(
                    [get_event_task, stop_wait_task], return_when=asyncio.FIRST_COMPLETED
                )
                for task in pending:
                    task.cancel()

                if stop_wait_task in done:
                    stream_task.cancel()
                    return

                event = get_event_task.result()
                if event is None:
                    break
                if isinstance(event, BaseException):
                    raise event

                # stream_mode="updates" yields {node_name: {"messages": [...]}}.
                for node_update in event.values():
                    if not isinstance(node_update, dict):
                        continue
                    for message in node_update.get("messages", []):
                        yield message
                        if (
                            isinstance(message, ToolMessage)
                            and on_tool_message is not None
                        ):
                            await on_tool_message(message, config)
                        if isinstance(message, AIMessage) and message.usage_metadata:
                            input_tokens = message.usage_metadata.get("input_tokens")
                            if input_tokens is not None:
                                yield {
                                    "kind": "context_usage",
                                    "used_tokens": input_tokens,
                                    "context_window": context_window,
                                }

                if is_done():
                    stream_task.cancel()
                    return
        finally:
            if not stream_task.done():
                stream_task.cancel()

        if stop_event.is_set():
            return

        input_data = None
        state = await app.aget_state(config)

        if state.next == ("tools",):
            consecutive_no_tool_calls = 0
            last_message: AIMessage = state.values["messages"][-1]
            tool_calls = last_message.tool_calls
            tool_call_names = {tc["name"] for tc in tool_calls}

            if not requires_interrupt(tool_call_names):
                if time_left is not None:
                    time_left -= _time.monotonic() - loop_start
                    if run_state is not None:
                        run_state["time_left"] = time_left
                continue

            loop = asyncio.get_running_loop()
            resume_future: asyncio.Future = loop.create_future()

            def accept(approved: bool):
                if not resume_future.done():
                    resume_future.set_result(approved)

            if time_left is not None:
                time_left -= _time.monotonic() - loop_start
                if run_state is not None:
                    run_state["time_left"] = time_left

            yield {"kind": "interrupt", "accept": accept, "tool_calls": tool_calls}

            stop_wait_task = asyncio.create_task(stop_event.wait())
            done, pending = await asyncio.wait(
                [resume_future, stop_wait_task], return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()

            if resume_future not in done:
                # Paused while this approval was still pending - leave it
                # unresolved rather than force a decision. Nothing is
                # lost: state.next is still ("tools",) in the checkpoint
                # (the tools node never actually ran), so resuming re-
                # enters this exact branch and re-surfaces the same
                # approval request normally.
                resume_future.cancel()
                return

            is_approved: bool = resume_future.result()
            loop_start = _time.monotonic()

            if is_approved:
                input_data = None
            else:
                rejection_messages = [
                    ToolMessage(
                        content=(
                            "User Denied Execution. Do not attempt this "
                            "specific command again. Re-evaluate your "
                            "approach."
                        ),
                        tool_call_id=tc["id"],
                        name=tc["name"],
                    )
                    for tc in tool_calls
                ]
                await app.aupdate_state(config, {"messages": rejection_messages}, as_node="tools")
                input_data = None
        else:
            consecutive_no_tool_calls += 1
            if consecutive_no_tool_calls >= max_consecutive_no_tool_calls:
                yield AIMessage(
                    content=(
                        "Stopping the run: the model did not call a tool "
                        f"for {max_consecutive_no_tool_calls} consecutive "
                        "turns."
                    )
                )
                return
            input_data = {"messages": [SystemMessage(content=nudge_message)]}

        if time_left is not None:
            time_left -= _time.monotonic() - loop_start
            if run_state is not None:
                run_state["time_left"] = time_left
