import uuid
from sqlmodel import SQLModel, Session, create_engine, select
from sqlalchemy import delete, text
from . import settings
from typing import List, TypeVar, Type

# SQLModels Imports #
from src.schemas.project_scheme import Project
from src.schemas.target_scheme import Target

T = TypeVar("T", bound=SQLModel)


class DatabaseManager:
    def __init__(self, db_url: str):
        self.engine = create_engine(db_url, echo=True)

        self.init_db()

    def init_db(self):
        with self.engine.connect() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            conn.commit()

        SQLModel.metadata.create_all(self.engine)

    def get_session(self):
        with Session(self.engine) as session:
            yield session

    # --- Base functions ---
    def get_all(self, model: Type[T]) -> List[T]:
        with Session(self.engine) as session:
            statement = select(model)
            results = session.exec(statement).all()
            return list(results)

    def add_to_database(self, model_instance: T) -> T:
        with Session(self.engine) as session:
            session.add(model_instance)
            session.commit()
            session.refresh(model_instance)
            return model_instance

    # --- Managing Projects ---
    def get_all_projects(self):
        return self.get_all(Project)

    def add_project(self, project: Project):
        return self.add_to_database(project)

    def get_project(self, project_id: str) -> Project | None:
        parsed_uuid = uuid.UUID(project_id)

        with Session(self.engine) as session:
            project = session.get(Project, parsed_uuid)
            return project

    # --- Managing Targets ---
    def get_all_targets_in_project(self, project_id: str) -> List[Target]:
        parsed_uuid = uuid.UUID(project_id)

        with Session(self.engine) as session:
            statement = select(Target).where(Target.project_id == parsed_uuid)
            return session.exec(statement).all()

    def add_target(self, target: Target):
        return self.add_to_database(target)
    
    def delete_target(self, target_id: str):
        parsed_uuid = uuid.UUID(target_id)
        
        with Session(self.engine) as session:
            statement = delete(Target).where(Target.id == parsed_uuid)
            session.exec(statement)
            session.commit()
            
    def update_target(self, target: Target):
        with Session(self.engine) as session:
            session.merge(target)
            session.commit()
            
    def get_target(self, target_id: str) -> Target | None:
        parsed_uuid = uuid.UUID(target_id)
        
        with Session(self.engine) as session:
            target = session.get(Target, parsed_uuid)
            return target
        


db_manager = DatabaseManager(settings.database_url)
