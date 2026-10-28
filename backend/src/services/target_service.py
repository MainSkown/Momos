from typing import List
import uuid
import ipaddress

from src.schemas.project_scheme import ProjectScope
from src.schemas.scope_parsing import is_network_in_any, parse_host_range
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
    def _validate_target_fields(target: Target, scope: ProjectScope | None):
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

        TargetService._validate_target_within_scope(target, scope)

    @staticmethod
    def _validate_target_within_scope(target: Target, scope: ProjectScope | None):
        # A manually-created Target is scope-checked the same as a
        # discovery-proposed one - otherwise the scope boundary is
        # trivially bypassable by just typing in an out-of-scope host
        # (see docs/features/project-scope-and-authorization.md's
        # "Decisions"). Every project is mandatorily created with a
        # ProjectScope (B1), so a missing scope here is a data-integrity
        # bug, not a reason to silently let the target through.
        if scope is None:
            raise InvalidTargetDataException(
                "Project has no configured scope; cannot validate target against it"
            )

        allowed_networks = parse_host_range(scope.host_range)

        if target.ipv4 is not None:
            candidate = ipaddress.ip_network(target.ipv4)
            if not is_network_in_any(candidate, allowed_networks):
                raise InvalidTargetDataException(
                    f"IPv4 {target.ipv4} is outside the project's authorized "
                    f"host range ({scope.host_range})"
                )

        if target.ipv6 is not None:
            candidate = ipaddress.ip_network(target.ipv6)
            if not is_network_in_any(candidate, allowed_networks):
                raise InvalidTargetDataException(
                    f"IPv6 {target.ipv6} is outside the project's authorized "
                    f"host range ({scope.host_range})"
                )

        for port in target.ports:
            if not (scope.port_range_start <= port <= scope.port_range_end):
                raise InvalidTargetDataException(
                    f"Port {port} is outside the project's authorized port "
                    f"range ({scope.port_range_start}-{scope.port_range_end})"
                )

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

        scope = db_manager.get_project_scope(parsed_project_id)

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
        TargetService._validate_target_fields(target, scope)
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
        scope = db_manager.get_project_scope(target.project_id)
        TargetService._validate_target_fields(target, scope)

        # Check if object exists in database
        if(db_manager.get_target(target.id) is None):
                raise TargetDoesNotExistException(
                    "Target does not exist in database", str(target.id)
                )


        db_manager.update_target(target)
