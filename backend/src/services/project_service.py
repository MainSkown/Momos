from typing import List

from src.schemas.project_scheme import Project
from src.core.database_manager import db_manager

class ProjectService:
    def add_project(name: str) -> Project:
        project = Project(name=name)
        project = db_manager.add_project(project)
        return project

    def get_projects() -> List[Project]:
        projects = db_manager.get_all_projects()
        return projects