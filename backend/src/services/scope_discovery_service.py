import logging
import uuid
from typing import List

from src.core.agent.scope_discovery import parse_nmap_ping_sweep
from src.core.database_manager import db_manager
from src.core.kali_integration import kali_registry
from src.schemas.project_scheme import DiscoveredHost
from src.schemas.scope_parsing import parse_host_range
from src.services.project_scope_service import ProjectScopeService
from src.utils.exceptions import ProjectDoesNotExistException

logger = logging.getLogger("momos.scope")

# nmap -sn against a /16 still has to finish inside the request's own
# lifetime - matches NMAP_SCAN_TIMEOUT_SECONDS in agent_tools.py (a host-
# discovery sweep is normally faster than a full port scan, but the spec's
# "large range still runs, no hard cap" edge case means this has to budget
# for a genuinely large sweep, not just a /24).
DISCOVERY_TIMEOUT_SECONDS = 240


class ScopeDiscoveryService:
    @staticmethod
    async def discover_hosts(project_id: str | uuid.UUID) -> List[DiscoveredHost]:
        if db_manager.get_project(project_id) is None:
            raise ProjectDoesNotExistException(
                f"Project does not exist: {project_id}", project_id
            )

        scope = db_manager.get_project_scope(project_id)

        # host_range is comma-separated in storage, but nmap's own target
        # spec takes multiple targets space-separated on the command line -
        # re-emitting parse_host_range's already-validated networks (their
        # own str() is just digits/dots/colons/slashes) both does that
        # translation and sidesteps passing raw free text to the shell.
        networks = parse_host_range(scope.host_range)
        command = "nmap -sn " + " ".join(str(network) for network in networks)

        manager = await kali_registry.get_manager(project_id)
        output = await manager.execute(command, timeout_seconds=DISCOVERY_TIMEOUT_SECONDS)

        discovered = []
        for host in parse_nmap_ping_sweep(output):
            in_scope = ProjectScopeService._is_host_range_contained(host, scope.host_range)
            if not in_scope:
                logger.warning(
                    f"discovery found host {host} outside project {project_id}'s "
                    "declared scope, rejected"
                )
            discovered.append(DiscoveredHost(host=host, in_scope=in_scope))

        return discovered
