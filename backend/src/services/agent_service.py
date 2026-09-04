from src.core import db_manager
from src.utils.exceptions import (
    ProjectDoesNotExistException,
    TargetDoesNotExistException,
    DurationNotDefinedInTarget,
)
from src.core.kali_integration import kali_registry


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

        # Check for target
        target = next((t for t in project.targets if t.id == target_id), None)

        if target is None:
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
        # TODO - Message to frontend that container started

        # Prepare sandbox
        kali_manager.prepare_nftables(target)
