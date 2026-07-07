from typing import List
import uuid
import ipaddress

from src.schemas.target_scheme import Target, TargetBase
from src.core.database_manager import db_manager


class TargetService:
    @staticmethod
    def add_target(name: str, project_id: str) -> Target:
        target = Target(name=name, project_id=uuid.UUID(project_id), ports=[])
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
        # Check if ports are in range 1 to 65535 
        if not all(1 <= port <= 65535 for port in target.ports):
            raise ValueError("All ports must be between 1 and 65535")
        
        # Check if IPv4 is really IPv4
        if(target.ipv4 is not None):
            try:
                ipaddress.IPv4Address(target.ipv4)
            except:
                raise ValueError("Given IPv4 is not IPv4")
            
        # Check if IPv6 is really IPv6
        if(target.ipv6 is not None):
            try:
                ipaddress.IPv6Address(target.ipv6)
            except:
                raise ValueError("Given IPv6 is not IPv6")
            
        # Check if object exists in database
        if(db_manager.get_target(target.id) is None):
                raise ValueError("Target does not exist in database")

            
        db_manager.update_target(target)
