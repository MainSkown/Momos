from typing import List

from src.schemas.project_scheme import (
    Project,
    ProjectScope,
    ProjectSettings,
    ProjectSettingsBody,
)
from src.core.database_manager import db_manager
from src.utils.exceptions import ProjectDoesNotExistException

class ProjectService:
    @staticmethod
    def add_project(
        name: str,
        base_model_name: str,
        parsing_model_name: str,
        host_range: str,
        port_range_start: int,
        port_range_end: int,
    ) -> Project:
        # Creating project and its mandatory scope together, atomically -
        # see database_manager.add_project's own comment on why a Project
        # row must never exist without a ProjectScope row.
        project = Project(name=name)
        scope = ProjectScope(
            host_range=host_range,
            port_range_start=port_range_start,
            port_range_end=port_range_end,
        )
        project = db_manager.add_project(project, scope)

        # Creating project settings
        settings = db_manager.get_project_settings(project.id)
        settings.base_model_name = base_model_name
        settings.parsing_model_name = parsing_model_name
        db_manager.update_project_settings(settings)

        return project
    
    @staticmethod
    def get_projects() -> List[Project]:
        projects = db_manager.get_all_projects()
        return projects
    
    @staticmethod
    def get_project_settings(project_id: str) -> ProjectSettings:
        # get_project_settings(create_new=True) inserts a settings row on
        # first access - for an unknown project_id that insert fails on the
        # settings table's FK to Project, surfacing as an opaque
        # IntegrityError. Checking existence up front, the same way
        # AgentService._get_owned_target does for project_id, gives callers
        # the typed exception instead.
        if db_manager.get_project(project_id) is None:
            raise ProjectDoesNotExistException(
                f"Project does not exist: {project_id}", project_id
            )

        settings = db_manager.get_project_settings(project_id)
        return settings
    
    @staticmethod
    def update_project_settings(settings: ProjectSettingsBody):
        project_settings = ProjectSettings(**settings.model_dump())
        updated_settings = db_manager.update_project_settings(project_settings)
        return updated_settings

    @staticmethod
    def delete_project(project_id: str):
        db_manager.delete_project(project_id)