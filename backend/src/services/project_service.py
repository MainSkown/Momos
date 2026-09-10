from typing import List

from src.schemas.project_scheme import Project, ProjectSettings, ProjectSettingsBody
from src.core.database_manager import db_manager

class ProjectService:
    @staticmethod
    def add_project(name: str, base_model_name: str, parsing_model_name: str) -> Project:
        # Creating project
        project = Project(name=name)
        project = db_manager.add_project(project)
        
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