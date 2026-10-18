from typing import List
import uuid
import ipaddress

from src.schemas.target_scheme import Target, TargetBase
from src.core.database_manager import db_manager
from src.utils.exceptions import (
    InvalidProjectIdException,
    InvalidTargetDataException,
    ProjectDoesNotExistException,
    TargetDoesNotExistException,
)


class TargetService:
    @staticmethod
    def _validate_target_fields(target: Target):
        # Check if ports are in range 1 to 65535 - None falls through the
        # same ValueError rather than crashing the `all(...)` generator
        # with a TypeError.
        if target.ports is None or not all(1 <= port <= 65535 for port in target.ports):
            raise ValueError("All ports must be between 1 and 65535")

        # Check if IPv4 is really IPv4
        if(target.ipv4 is not None):
            try:
                ipaddress.IPv4Address(target.ipv4)
            except:
                raise InvalidTargetDataException("Given IPv4 is not IPv4")

        # Check if IPv6 is really IPv6
        if(target.ipv6 is not None):
            try:
                ipaddress.IPv6Address(target.ipv6)
            except:
                raise InvalidTargetDataException("Given IPv6 is not IPv6")

    @staticmethod
    def add_target(
        name: str,
        project_id: str,
        ipv4: str | None = None,
        ipv6: str | None = None,
        description: str | None = None,
        ports: List[int] | None = None,
        task_duration: int | None = None,
    ) -> Target:
        try:
            parsed_project_id = uuid.UUID(project_id)
        except ValueError:
            raise InvalidProjectIdException(f"Malformed project_id: {project_id}", project_id)

        if db_manager.get_project(parsed_project_id) is None:
            raise ProjectDoesNotExistException(f"Project does not exist: {project_id}", project_id)

        target = Target(
            name=name,
            project_id=parsed_project_id,
            ipv4=ipv4,
            ipv6=ipv6,
            description=description,
            # A target that doesn't specify ports starts with none
            # monitored, not with a validation error - same default the
            # old hard-coded `ports=[]` gave every created row.
            ports=ports if ports is not None else [],
            task_duration=task_duration,
        )
        TargetService._validate_target_fields(target)
        target = db_manager.add_target(target)
        return target

    @staticmethod
    def get_all_targets(project_id: str) -> List[Target]:
        return db_manager.get_all_targets_in_project(project_id)

    @staticmethod
    def delete_target(target_id: str):
        db_manager.delete_target(target_id)

    @staticmethod
    def update_target(target: Target):
        TargetService._validate_target_fields(target)

        # Check if object exists in database
        if(db_manager.get_target(target.id) is None):
                raise TargetDoesNotExistException(
                    "Target does not exist in database", str(target.id)
                )


        db_manager.update_target(target)
