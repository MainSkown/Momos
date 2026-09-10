import asyncio
from typing import Annotated, Any, AsyncGenerator, Callable, TypedDict
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from . import agent_tools
from src.schemas import AgentTargetScope, Target
from src.core import settings
import time


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    target_scope: AgentTargetScope


class AgentInterruptAction(TypedDict):
    accept: Callable[[bool], None]
    tool_calls: list[Any]


class Agent:
    def __init__(
        self,
        model_name: str,
        checkpointer: AsyncPostgresSaver,
        project_id: str,
        target_id: str,
    ):
        self.project_id = project_id
        self.target_id = target_id
        self.checkpointer = checkpointer
        self.ollama_url = settings.ollama_url
        self.tools = agent_tools.build_agent_tools(project_id, target_id)

        self.changeModel(model_name=model_name)

        self.app = self._build_graph()

    def _build_graph(self):
        workflow = StateGraph(AgentState)

        # Nodes
        workflow.add_node("agent", self._call_model)
        workflow.add_node("tools", ToolNode(self.tools))

        # Edges
        workflow.add_edge(START, "agent")
        workflow.add_conditional_edges("agent", self._should_continue, ["tools", END])
        workflow.add_edge("tools", "agent")

        return workflow.compile(
            checkpointer=self.checkpointer, interrupt_before=["tools"]
        )

    def _call_model(self, state: AgentState):
        """Node: LLM processes the current state"""
        response = self.llm_with_tools.invoke(state["messages"])
        return {"messages": [response]}

    def _should_continue(self, state: AgentState):
        last_message = state["messages"][-1]
        if isinstance(last_message, AIMessage) and last_message.tool_calls:
            return "tools"
        return END

    def changeModel(self, model_name: str):
        self.llm = ChatOllama(model=model_name, base_url=self.ollama_url)
        self.llm_with_tools = self.llm.bind_tools(self.tools)

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
    ) -> AsyncGenerator[BaseMessage | AgentInterruptAction, None]:
        config: RunnableConfig = {"configurable": {"thread_id": thread_id}}

        if stop_event is None:
            stop_event = asyncio.Event()

        if run_state is None:
            run_state = {}

        existing_state = await self.app.aget_state(config)

        if existing_state.values:
            input_data = None
        else:
            input_data = {
                "messages": [("user", start_prompt)],
                "target_scope": target,
            }

        time_left = duration_seconds
        run_state["time_left"] = time_left

        while not stop_event.is_set() and time_left > 0:
            loop_start = time.monotonic()
            
            event_queue = asyncio.Queue()
            
            async def _stream_worker():
                try:
                    async for event in self.app.astream(
                        input_data, config=config, stream_mode="updates"
                    ):
                        await event_queue.put(event)
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
                    
                    if "messages" in event:
                        last_message: BaseMessage = event["messages"][-1]
                        yield last_message
            finally:
                if not stream_task.done():
                    stream_task.cancel()
            
            if stop_event.is_set():
                break                
            
            input_data = None
            state = await self.app.aget_state(config)

            if state.next == ("tools",):
                last_message: AIMessage = state.values["messages"][-1]
                tool_calls = last_message.tool_calls

                requires_interrupt = should_interrupt and any(
                    tc["name"] == agent_tools.KALI_COMMAND_TOOL_NAME
                    for tc in tool_calls
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
                        "accept": accept,
                        "tool_calls": tool_calls,
                    }

                    # Pause timer awaiting for user's action
                    time_left -= (time.monotonic() - loop_start)
                    run_state["time_left"] = time_left

                    yield interrupt_action

                    is_approved: bool = await resume_future

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
                break

            time_left -= (time.monotonic() - loop_start)
            run_state["time_left"] = time_left