import asyncio
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama
from src.core import db_manager, settings
from src.core.kali_integration import kali_registry

KALI_COMMAND_TOOL_NAME = "execute_kali_command"

PARSER_SYSTEM_PROMPT = (
    "You are a data-extraction assistant supporting a penetration-testing agent. "
    "You are given the exact shell command that was run inside a Kali Linux "
    "container and its raw output. Extract and condense only the information "
    "relevant to a security assessment: open ports, service names/versions, "
    "discovered hosts, vulnerabilities, file paths, credentials, and other "
    "actionable findings. Remove repetitive noise, banners, and formatting "
    "clutter. If the command failed or produced an error, clearly state the "
    "failure and its cause. Respond with plain, concise text only - no "
    "commentary or suggestions."
)


async def _get_parsing_model_name(project_id: str) -> str | None:
    loop = asyncio.get_running_loop()
    project_settings = await loop.run_in_executor(
        None, db_manager.get_project_settings, project_id
    )

    return project_settings.parsing_model_name if project_settings else None


async def _parse_output(project_id: str, command: str, raw_output: str) -> str:
    parsing_model_name = await _get_parsing_model_name(project_id)

    if not parsing_model_name:
        # No parsing model configured for this project - fall back to raw output
        return raw_output

    parser_llm = ChatOllama(model=parsing_model_name, base_url=settings.ollama_url)

    response = await parser_llm.ainvoke(
        [
            SystemMessage(content=PARSER_SYSTEM_PROMPT),
            HumanMessage(content=f"Command: {command}\n\nOutput:\n{raw_output}"),
        ]
    )

    return str(response.content)


async def _run_kali_command(project_id: str, command: str) -> str:
    manager = await kali_registry.get_manager(project_id)

    try:
        raw_output = await manager.execute(command)
    except RuntimeError as e:
        raw_output = str(e)

    if not raw_output.strip():
        return "(command produced no output)"

    return await _parse_output(project_id, command, raw_output)


def create_kali_tool(project_id: str):
    """Builds an execute_kali_command tool bound to a specific project's Kali container."""

    @tool(KALI_COMMAND_TOOL_NAME)
    async def execute_kali_command(command: str) -> str:
        """Executes a command in the Kali Linux container and returns a condensed
        summary of its output. Use this to interact with the environment. Note
        that every command is executed in a different session."""
        return await _run_kali_command(project_id, command)

    return execute_kali_command


def build_agent_tools(project_id: str) -> list:
    return [create_kali_tool(project_id)]
