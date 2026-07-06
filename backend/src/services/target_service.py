from typing import List
import uuid

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
