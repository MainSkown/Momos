import asyncio
from typing import Callable, Dict
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from src.core import db_manager
from src.core.agent import Agent
from src.core.agent.agent_checkpointer import checkpointer
from src.core.kali_integration import kali_registry
from src.schemas.target_scheme import Target
from src.schemas.project_scheme import ProjectSettings
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


def _message_to_role_and_content(message: BaseMessage) -> tuple[str, str] | None:
    content = message.content if isinstance(message.content, str) else str(message.content)

    if isinstance(message, ToolMessage):
        return "tool", content

    if isinstance(message, AIMessage):
        return "assistant", content

    return None


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

                role_and_content = _message_to_role_and_content(event)

                if role_and_content is None:
                    continue

                role, content = role_and_content

                if not content:
                    continue

                await ws_registry.send_message(
                    AgentMessage(
                        type=WsTypes.AgentMessage,
                        project_id=project_id,
                        target_id=target_id,
                        role=role,
                        content=content,
                    )
                )
        except Exception as e:
            print(f"Agent run failed for target {target_id}: {e}")
            await ws_registry.send_message(
                AgentMessage(
                    type=WsTypes.AgentMessage,
                    project_id=project_id,
                    target_id=target_id,
                    role="assistant",
                    content=f"Agent run failed: {e}",
                )
            )
        finally:
            _pending_interrupts.pop(target_id, None)
