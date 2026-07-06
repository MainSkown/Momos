from sqlmodel import SQLModel, Session, create_engine, select
from sqlalchemy import text
from . import settings
from src.schemas.project_scheme import Project
from typing import List, TypeVar, Type

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

db_manager = DatabaseManager(settings.database_url)

