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
from src.schemas import AgentTargetScope


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    target_scope: AgentTargetScope


class AgentInterruptAction(TypedDict):
    accept: Callable[[bool], None]
    tool_calls: list[Any]


class Agent:
    def __init__(self, model_name: str, checkpointer: AsyncPostgresSaver):
        self.changeModel(model_name=model_name)

        self.checkpointer = checkpointer

        self.app = self._build_graph()

    def _build_graph(self):
        workflow = StateGraph(AgentState)

        # Nodes
        workflow.add_node("agent", self._call_model)
        workflow.add_node("tools", ToolNode(agent_tools))

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
        self.llm = ChatOllama(model=model_name)
        self.llm_with_tools = self.llm.bind_tools(agent_tools)

    # --- Execution and Interaction ---
    async def start_agent(
        self,
        target: AgentTargetScope,
        start_prompt: str,
        thread_id: str,
        should_interrupt: bool,
    ) -> AsyncGenerator[BaseMessage | AgentInterruptAction, None]:
        config: RunnableConfig = {"configurable": {"thread_id": thread_id}}

        existing_state = await self.app.aget_state(config)

        if existing_state.values:
            input_data = None
        else:
            input_data = {
                "messages": [("user", start_prompt)],
                "target_scope": target,
            }

        running = True

        while running:
            async for event in self.app.astream(
                input_data, config=config, stream_mode="values"
            ):
                if "messages" in event:
                    latest_message: BaseMessage = event["messages"][-1]
                    yield latest_message

            input_data = None
            state = await self.app.aget_state(config)

            if state.next == ("tools",):
                last_message: AIMessage = state.values["messages"][-1]
                tool_calls = last_message.tool_calls

                if not should_interrupt:
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

                    yield interrupt_action

                    is_approved: bool = await resume_future

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
                running = False
