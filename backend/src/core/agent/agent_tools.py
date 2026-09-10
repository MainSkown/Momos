import asyncio
from pydantic import ValidationError
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama
from src.core import db_manager, settings
from src.core.kali_integration import kali_registry
from src.schemas import Vulnerability, VulnerabilityBase

KALI_COMMAND_TOOL_NAME = "execute_kali_command"
REPORT_VULNERABILITY_TOOL_NAME = "report_vulnerability"

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


async def get_parsing_model_name(project_id: str) -> str | None:
    loop = asyncio.get_running_loop()
    project_settings = await loop.run_in_executor(
        None, db_manager.get_project_settings, project_id
    )

    return project_settings.parsing_model_name if project_settings else None


async def _parse_output(project_id: str, command: str, raw_output: str) -> str:
    parsing_model_name = await get_parsing_model_name(project_id)

    if not parsing_model_name:
        # No parsing model configured for this project - fall back to raw output
        return raw_output

    parser_llm = ChatOllama(model=parsing_model_name, base_url=settings.ollama_url)

    try:
        response = await parser_llm.ainvoke(
            [
                SystemMessage(content=PARSER_SYSTEM_PROMPT),
                HumanMessage(content=f"Command: {command}\n\nOutput:\n{raw_output}"),
            ]
        )
    except Exception as e:
        # Don't lose a real command result just because the parsing model
        # hiccuped - give the agent the raw output instead.
        print(f"Output parsing failed, using raw output: {e}")
        return raw_output

    return str(response.content)


async def _run_kali_command(project_id: str, command: str) -> str:
    manager = await kali_registry.get_manager(project_id)

    # Serialize the whole command (docker exec + its parsing call) so that
    # several kali-command tool calls issued in the same LLM turn don't all
    # hit Docker and the local parsing model at once.
    async with manager.command_lock:
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


async def _save_vulnerability(vulnerability: Vulnerability) -> Vulnerability:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, db_manager.add_vulnerability, vulnerability)


def create_vulnerability_tool(project_id: str, target_id: str):
    """Builds a report_vulnerability tool bound to a specific project/target."""

    @tool(REPORT_VULNERABILITY_TOOL_NAME)
    async def report_vulnerability(
        name: str, cvss4_vector: str, proof_of_concept: str
    ) -> str:
        """Records a confirmed vulnerability found on the current target. Only
        call this once a finding has actually been verified - not for suspected
        or untested issues.

        Args:
            name: A short, descriptive name for the vulnerability.
            cvss4_vector: A valid CVSS v4.0 vector string, e.g.
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N".
                Its severity score is derived automatically - do not include one.
            proof_of_concept: Step-by-step instructions describing exactly how to
                verify or exploit the vulnerability, in enough detail to reproduce it.
        """
        try:
            # SQLModel table models don't run Pydantic validators on
            # construction - validate through the plain base model first,
            # then build the table row from the already-validated data.
            validated = VulnerabilityBase(
                name=name,
                cvss4_vector=cvss4_vector,
                proof_of_concept=proof_of_concept,
            )
        except ValidationError as e:
            return f"Could not record vulnerability, fix the input and try again: {e}"

        vulnerability = Vulnerability(
            name=validated.name,
            cvss4_vector=validated.cvss4_vector,
            cvss4_score=validated.cvss4_score,
            proof_of_concept=validated.proof_of_concept,
            found_in=target_id,
            related_to_project=project_id,
        )

        saved = await _save_vulnerability(vulnerability)

        return (
            f"Recorded vulnerability '{saved.name}' "
            f"(CVSS v4.0 score: {saved.cvss4_score})."
        )

    return report_vulnerability


def build_agent_tools(project_id: str, target_id: str) -> list:
    return [
        create_kali_tool(project_id),
        create_vulnerability_tool(project_id, target_id),
    ]
