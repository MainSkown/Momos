import asyncio
from typing import Callable, Dict, List, Optional, Tuple
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_ollama import ChatOllama
from src.core import db_manager, settings
from src.core.agent import Agent, agent_tools
from src.core.agent.agent_checkpointer import checkpointer
from src.core.kali_integration import kali_registry
from src.schemas.target_scheme import Target
from src.schemas.project_scheme import ProjectSettings
from src.schemas.agent_log_scheme import AgentLog, AgentLogResponse, AgentLogType
from src.utils.exceptions import (
    ProjectDoesNotExistException,
    TargetDoesNotExistException,
    DurationNotDefinedInTarget,
)
from src.websocket import (
    ws_registry,
    WsTypes,
    AgentMessage,
    AgentInterruptRequest,
    AgentInterruptResponseMessage,
)

# thread_id (== target_id) -> pending interrupt's accept callback
_pending_interrupts: Dict[str, Callable[[bool], None]] = {}


async def _on_interrupt_response(message: AgentInterruptResponseMessage):
    accept = _pending_interrupts.pop(message.target_id, None)

    if accept is None:
        print(f"No pending interrupt for target {message.target_id}. Ignoring.")
        return

    accept(message.approved)


ws_registry.add_hook(WsTypes.AgentInterruptResponse, _on_interrupt_response)


def _stringify_content(content) -> str:
    return content if isinstance(content, str) else str(content)


def _render_tool_call_content(tool_name: str, args: dict) -> str:
    if tool_name == agent_tools.KALI_COMMAND_TOOL_NAME:
        return str(args.get("command", ""))

    if tool_name == agent_tools.REPORT_VULNERABILITY_TOOL_NAME:
        return str(args.get("name", ""))

    return ", ".join(f"{k}={v}" for k, v in args.items())


LOG_SUMMARY_SYSTEM_PROMPT = (
    "You are summarizing a penetration-testing agent's activity for a live "
    "status log. Rewrite the given text as a single short, clear sentence "
    "describing what the agent is doing, thinking, or found. Keep it factual "
    "and concise - no preamble, no commentary, just the summary."
)


async def _summarize_for_log(project_id: str, content: str) -> str:
    parsing_model_name = await agent_tools.get_parsing_model_name(project_id)

    if not parsing_model_name:
        # No parsing model configured for this project - fall back to raw content
        return content

    parser_llm = ChatOllama(model=parsing_model_name, base_url=settings.ollama_url)

    response = await parser_llm.ainvoke(
        [
            SystemMessage(content=LOG_SUMMARY_SYSTEM_PROMPT),
            HumanMessage(content=content),
        ]
    )

    return str(response.content)


def _message_to_log_specs(
    message: BaseMessage,
) -> List[Tuple[AgentLogType, str, Optional[str]]]:
    """Turns one agent message into zero or more (type, content, tool_name) specs."""
    specs: List[Tuple[AgentLogType, str, Optional[str]]] = []

    if isinstance(message, AIMessage):
        content = _stringify_content(message.content)

        if content.strip():
            specs.append(("thinking", content, None))

        for tc in message.tool_calls:
            specs.append(
                ("tool", _render_tool_call_content(tc["name"], tc["args"]), tc["name"])
            )

    elif isinstance(message, ToolMessage):
        content = _stringify_content(message.content)

        if content.strip():
            specs.append(("action", content, None))

    return specs


async def _persist_and_broadcast(
    project_id: str,
    target_id: str,
    log_type: AgentLogType,
    content: str,
    tool_name: Optional[str] = None,
) -> AgentLog:
    log = AgentLog(
        type=log_type,
        content=content,
        tool_name=tool_name,
        project_id=project_id,
        target_id=target_id,
    )

    loop = asyncio.get_running_loop()
    saved = await loop.run_in_executor(None, db_manager.add_agent_log, log)

    await ws_registry.send_message(
        AgentMessage(
            type=WsTypes.AgentMessage,
            log=AgentLogResponse.model_validate(saved),
        )
    )

    return saved


class AgentService:
    @staticmethod
    async def start_agent(project_id: str, target_id: str):
        # Check if project exists
        project = db_manager.get_project(project_id)

        if project is None:
            raise ProjectDoesNotExistException(
                f"Tried accessing nonexistent project ({project_id}) when starting agent",
                project_id,
            )

        # Check for target, scoped to this project
        target = db_manager.get_target(target_id)

        if target is None or str(target.project_id) != str(project.id):
            raise TargetDoesNotExistException(
                f"Target {target_id} does not exist in project {project_id}", target_id
            )

        if target.task_duration is None or target.task_duration == 0:
            raise DurationNotDefinedInTarget(
                f"Target {target_id} does not have defined scan duration"
            )

        # Initiate kali manager for this project
        # TODO - Message to frontend that container init
        kali_manager = await kali_registry.get_manager(project_id)
        await kali_manager.prepare_nftables(target)
        # TODO - Message to frontend that container started

        project_settings = db_manager.get_project_settings(project_id)

        agent = Agent(
            model_name=project_settings.base_model_name,
            checkpointer=checkpointer,
            project_id=project_id,
            target_id=target_id,
        )

        asyncio.create_task(
            AgentService._run_agent(agent, target, project_settings)
        )

    @staticmethod
    async def _run_agent(
        agent: Agent, target: Target, project_settings: ProjectSettings
    ):
        project_id = str(target.project_id)
        target_id = str(target.id)

        try:
            await _persist_and_broadcast(
                project_id,
                target_id,
                "action",
                f"Starting analysis on target: {target.name}",
            )

            async for event in agent.start_agent(
                target=target,
                start_prompt=project_settings.starting_prompt,
                thread_id=target_id,
                should_interrupt=project_settings.should_interrupt,
            ):
                if isinstance(event, dict):
                    # AgentInterruptAction - pause and wait for approval
                    _pending_interrupts[target_id] = event["accept"]

                    await ws_registry.send_message(
                        AgentInterruptRequest(
                            type=WsTypes.AgentInterruptRequest,
                            project_id=project_id,
                            target_id=target_id,
                            tool_calls=[
                                {"name": tc["name"], "args": tc["args"]}
                                for tc in event["tool_calls"]
                            ],
                        )
                    )
                    continue

                for log_type, content, tool_name in _message_to_log_specs(event):
                    if log_type in ("thinking", "action"):
                        content = await _summarize_for_log(project_id, content)

                    await _persist_and_broadcast(
                        project_id, target_id, log_type, content, tool_name
                    )
        except Exception as e:
            print(f"Agent run failed for target {target_id}: {e}")
            await _persist_and_broadcast(
                project_id, target_id, "action", f"Agent run failed: {e}"
            )
        finally:
            _pending_interrupts.pop(target_id, None)
