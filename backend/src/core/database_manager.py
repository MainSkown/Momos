import uuid
from datetime import datetime, timezone
from sqlmodel import SQLModel, Session, create_engine, select
from sqlalchemy import delete, text, inspect
from . import settings
from typing import List, Optional, TypeVar, Type

# SQLModels Imports #
from src.schemas.project_scheme import (
    Project,
    ProjectSettings,
    project_settings_factory,
)
from src.schemas.target_scheme import Target
from src.schemas.vulnerability_scheme import Vulnerability
from src.schemas.agent_log_scheme import AgentLog
from src.schemas.agent_run_scheme import AgentRun
from src.schemas.attack_vector_scheme import AttackVector

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

        # There is no migration tool (e.g. Alembic) in this project -
        # create_all above only creates tables that don't exist yet, it
        # never alters an existing one. New nullable columns on an
        # already-existing table (like agentlog.raw_output) need an
        # explicit, idempotent ALTER here instead - a no-op on a brand-new
        # database (create_all already includes the column there), a real
        # patch on an existing one.
        with self.engine.connect() as conn:
            conn.execute(text("ALTER TABLE agentlog ADD COLUMN IF NOT EXISTS raw_output TEXT"))
            conn.execute(
                text(
                    "ALTER TABLE projectsettings ADD COLUMN IF NOT EXISTS "
                    "allow_shell BOOLEAN NOT NULL DEFAULT true"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE projectsettings ADD COLUMN IF NOT EXISTS "
                    "allow_install_packages BOOLEAN NOT NULL DEFAULT true"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE projectsettings ADD COLUMN IF NOT EXISTS "
                    "enabled_tools TEXT[]"
                )
            )
            # Multi-agent pipeline fields - see project_scheme.py's
            # ProjectSettingsBase. Existing rows default to pipeline_mode
            # 'single_agent' (unaffected by this migration); the 4 role
            # model/prompt fields default to '' like base_model_name/
            # parsing_model_name always have - a role falls back to its own
            # module-level default prompt constant at render time when its
            # stored prompt is empty (see the roles/ package), the same way
            # an empty model name is simply "not chosen yet", not an error
            # until a run actually starts.
            conn.execute(
                text(
                    "ALTER TABLE projectsettings ADD COLUMN IF NOT EXISTS "
                    "pipeline_mode TEXT NOT NULL DEFAULT 'single_agent'"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE projectsettings ADD COLUMN IF NOT EXISTS "
                    "max_concurrent_agents INTEGER NOT NULL DEFAULT 1"
                )
            )
            for _role_col in (
                "orchestrator_model_name",
                "scouting_model_name",
                "pentesting_model_name",
                "reporting_model_name",
                "orchestrator_starting_prompt",
                "scouting_starting_prompt",
                "pentesting_starting_prompt",
                "reporting_starting_prompt",
            ):
                conn.execute(
                    text(
                        f"ALTER TABLE projectsettings ADD COLUMN IF NOT EXISTS "
                        f"{_role_col} TEXT NOT NULL DEFAULT ''"
                    )
                )
            conn.execute(
                text(
                    "ALTER TABLE vulnerability ADD COLUMN IF NOT EXISTS "
                    "created_at TIMESTAMPTZ NOT NULL DEFAULT now()"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE vulnerability ADD COLUMN IF NOT EXISTS "
                    "found_by_model TEXT"
                )
            )
            # severity is no longer a settable field (VulnerabilityBase
            # dropped it entirely - see vulnerability_scheme.py's
            # severity_label()) and create_all() never drops a column on
            # an existing table, so an old NOT NULL severity column would
            # otherwise keep rejecting every insert that no longer
            # supplies one. Nothing of value is lost: severity_label()
            # re-derives an equivalent label from cvss4_score on every
            # read, and cvss4_score was already stored before this change.
            conn.execute(text("ALTER TABLE vulnerability DROP COLUMN IF EXISTS severity"))
            # cvss4_vector was nullable (it used to be optional - see the
            # same history above); the Python model now requires it
            # (VulnerabilityBase.cvss4_vector: str), but create_all() never
            # tightens an existing column's NOT NULL constraint, so the DB
            # itself would still silently accept a NULL a direct insert
            # bypassing the ORM could write. No existing row can be
            # soundly backfilled with a real vector (the severity data that
            # used to stand in for one is already gone), so this only ever
            # succeeds as a no-op when no such row exists; it fails loudly
            # (rather than silently diverging from the model) if one ever
            # does.
            conn.execute(text("ALTER TABLE vulnerability ALTER COLUMN cvss4_vector SET NOT NULL"))
            conn.commit()

        # Same idea for an existing Postgres ENUM TYPE: create_all() never
        # adds a new label to one that already exists, so AgentRunState.FAILED
        # (agent_run_scheme.py) needs its own idempotent ALTER TYPE - without
        # this, persisting a run as "failed" raises InvalidTextRepresentation
        # ("invalid input value for enum agentrunstate"). SQLAlchemy stores a
        # str Enum column by its member NAME by default (RUNNING/PAUSED/...,
        # not "running"/"paused"), hence the uppercase value here.
        # AUTOCOMMIT isolation is required, not a plain transaction - Postgres
        # forbids using a brand-new enum value in the same transaction that
        # added it, and (pre-PG12) forbids ADD VALUE inside a transaction
        # block at all.
        with self.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TYPE agentrunstate ADD VALUE IF NOT EXISTS 'FAILED'"))

        # agentrun's primary key changed from target_id to a new surrogate
        # id column, to support a target's pipeline being a TREE of runs
        # (role/parent_run_id/attack_vector_id - see agent_run_scheme.py)
        # instead of the single row it used to be. create_all() builds this
        # shape correctly for a BRAND NEW database (including the
        # agentrun_single_agent_per_target partial unique index declared in
        # __table_args__), but never alters an existing table's primary
        # key - an existing deployment needs this one-time structural
        # migration instead. Guarded by checking whether the `id` column
        # already exists, so this only ever runs once per database: a
        # no-op on both a freshly created table (already has `id`) and an
        # already-migrated one.
        inspector = inspect(self.engine)
        if "agentrun" in inspector.get_table_names():
            existing_columns = {col["name"] for col in inspector.get_columns("agentrun")}
            if "id" not in existing_columns:
                with self.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE agentrun ADD COLUMN id UUID"))
                    conn.execute(text("ALTER TABLE agentrun ADD COLUMN role TEXT"))
                    conn.execute(text("ALTER TABLE agentrun ADD COLUMN parent_run_id UUID"))
                    conn.execute(text("ALTER TABLE agentrun ADD COLUMN attack_vector_id UUID"))
                    # Every pre-existing row predates the multi-agent
                    # pipeline entirely, so it unconditionally belongs to
                    # the single-agent flow.
                    conn.execute(text("UPDATE agentrun SET role = 'single_agent' WHERE role IS NULL"))
                    conn.execute(text("UPDATE agentrun SET id = gen_random_uuid() WHERE id IS NULL"))
                    conn.execute(text("ALTER TABLE agentrun ALTER COLUMN id SET NOT NULL"))
                    conn.execute(text("ALTER TABLE agentrun ALTER COLUMN role SET NOT NULL"))
                    conn.execute(text("ALTER TABLE agentrun DROP CONSTRAINT IF EXISTS agentrun_pkey"))
                    conn.execute(text("ALTER TABLE agentrun ADD PRIMARY KEY (id)"))
                    conn.execute(
                        text(
                            "CREATE UNIQUE INDEX IF NOT EXISTS "
                            "agentrun_single_agent_per_target ON agentrun (target_id) "
                            "WHERE role = 'single_agent'"
                        )
                    )
                    conn.commit()

        # agentlog's role/agent_run_id columns - see AgentLogBase's own
        # comment. Nullable, so every pre-existing (and every new
        # single_agent-mode) row stays valid without a backfill.
        with self.engine.connect() as conn:
            conn.execute(text("ALTER TABLE agentlog ADD COLUMN IF NOT EXISTS agent_run_id UUID"))
            conn.execute(text("ALTER TABLE agentlog ADD COLUMN IF NOT EXISTS role TEXT"))
            conn.commit()

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

    def _parse_uuid(self, value: str | uuid.UUID) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(value)

    def get_project(self, project_id: str | uuid.UUID) -> Project | None:
        parsed_uuid = self._parse_uuid(project_id)

        with Session(self.engine) as session:
            project = session.get(Project, parsed_uuid)
            return project

    # -- Managing Project Settings ---
    def get_project_settings(
        self, project_id: str | uuid.UUID, create_new: bool = True
    ) -> ProjectSettings | None:
        parsed_uuid = self._parse_uuid(project_id)

        with Session(self.engine) as session:
            settings = session.get(ProjectSettings, parsed_uuid)

            if settings is None and create_new:
                settings = project_settings_factory(project_id=parsed_uuid)

                session.add(settings)
                session.commit()
                session.refresh(settings)

            return settings

    def update_project_settings(
        self, project_settings: ProjectSettings
    ) -> ProjectSettings:
        with Session(self.engine) as session:
            merged_settings = session.merge(project_settings)
            session.commit()
            session.refresh(merged_settings)
            return merged_settings

    def clear_model_references(self, model_name: str) -> None:
        """Nulls out base_model_name/parsing_model_name on any project's
        settings that reference model_name - called right before the model
        itself is deleted from Ollama, so a project can never keep pointing
        at a model that no longer exists."""
        with Session(self.engine) as session:
            statement = select(ProjectSettings).where(
                (ProjectSettings.base_model_name == model_name)
                | (ProjectSettings.parsing_model_name == model_name)
            )
            for settings in session.exec(statement).all():
                if settings.base_model_name == model_name:
                    settings.base_model_name = ""
                if settings.parsing_model_name == model_name:
                    settings.parsing_model_name = ""
                session.add(settings)
            session.commit()

    def delete_project(self, project_id: str | uuid.UUID):
        parsed_uuid = self._parse_uuid(project_id)

        with Session(self.engine) as session:
            # Children referencing target/project via a FK must go before
            # their parents, or Postgres rejects the parent delete.
            # AttackVector itself references Vulnerability/AgentRun
            # (linked_vulnerability_id/discovered_by_run_id/assigned_run_id),
            # so it must go before both of those, not after.
            session.exec(delete(AttackVector).where(AttackVector.project_id == parsed_uuid))
            session.exec(delete(Vulnerability).where(Vulnerability.related_to_project == parsed_uuid))
            session.exec(delete(AgentLog).where(AgentLog.project_id == parsed_uuid))
            session.exec(delete(AgentRun).where(AgentRun.project_id == parsed_uuid))
            session.exec(delete(Target).where(Target.project_id == parsed_uuid))
            session.exec(delete(ProjectSettings).where(ProjectSettings.project_id == parsed_uuid))
            session.exec(delete(Project).where(Project.id == parsed_uuid))
            session.commit()

    # --- Managing Targets ---
    def get_all_targets_in_project(self, project_id: str | uuid.UUID) -> List[Target]:
        parsed_uuid = self._parse_uuid(project_id)

        with Session(self.engine) as session:
            statement = select(Target).where(Target.project_id == parsed_uuid)
            return session.exec(statement).all()

    def add_target(self, target: Target):
        return self.add_to_database(target)

    def delete_target(self, target_id: str | uuid.UUID):
        parsed_uuid = self._parse_uuid(target_id)

        with Session(self.engine) as session:
            # Same ordering requirement as delete_project - clear rows that
            # reference this target before deleting the target itself.
            # AttackVector references Vulnerability/AgentRun, so it must go
            # before both of those, not after.
            session.exec(delete(AttackVector).where(AttackVector.target_id == parsed_uuid))
            session.exec(delete(Vulnerability).where(Vulnerability.found_in == parsed_uuid))
            session.exec(delete(AgentLog).where(AgentLog.target_id == parsed_uuid))
            session.exec(delete(AgentRun).where(AgentRun.target_id == parsed_uuid))
            session.exec(delete(Target).where(Target.id == parsed_uuid))
            session.commit()

    def update_target(self, target: Target):
        with Session(self.engine) as session:
            merged_target = session.merge(target)
            session.commit()
            session.refresh(merged_target)
            
            return merged_target
            

    def get_target(self, target_id: str | uuid.UUID) -> Target | None:
        parsed_uuid = self._parse_uuid(target_id)

        with Session(self.engine) as session:
            target = session.get(Target, parsed_uuid)
            return target

    # --- Managing Vulnerabilities ---
    def get_all_vulnerabilities_in_project(
        self, project_id: str | uuid.UUID
    ) -> List[Vulnerability]:
        parsed_uuid = self._parse_uuid(project_id)

        with Session(self.engine) as session:
            statement = select(Vulnerability).where(
                Vulnerability.related_to_project == parsed_uuid
            )
            return session.exec(statement).all()

    def get_all_vulnerabilities_in_target(
        self, target_id: str | uuid.UUID
    ) -> List[Vulnerability]:
        parsed_uuid = self._parse_uuid(target_id)

        with Session(self.engine) as session:
            statement = select(Vulnerability).where(
                Vulnerability.found_in == parsed_uuid
            )
            return session.exec(statement).all()

    def add_vulnerability(self, vulnerability: Vulnerability):
        return self.add_to_database(vulnerability)

    def update_vulnerability(self, vulnerability: Vulnerability) -> Vulnerability:
        with Session(self.engine) as session:
            merged_vulnerability = session.merge(vulnerability)
            session.commit()
            session.refresh(merged_vulnerability)

            return merged_vulnerability

    def get_vulnerability(self, vulnerability_id: str | uuid.UUID) -> Vulnerability | None:
        parsed_uuid = self._parse_uuid(vulnerability_id)

        with Session(self.engine) as session:
            return session.get(Vulnerability, parsed_uuid)

    def delete_vulnerability(self, vulnerability_id: str | uuid.UUID):
        parsed_uuid = self._parse_uuid(vulnerability_id)

        with Session(self.engine) as session:
            statement = delete(Vulnerability).where(Vulnerability.id == parsed_uuid)
            session.exec(statement)
            session.commit()

    # --- Managing Agent Logs ---
    def add_agent_log(self, agent_log: AgentLog):
        return self.add_to_database(agent_log)

    def get_all_agent_logs_in_project(
        self, project_id: str | uuid.UUID
    ) -> List[AgentLog]:
        parsed_uuid = self._parse_uuid(project_id)

        with Session(self.engine) as session:
            statement = (
                select(AgentLog)
                .where(AgentLog.project_id == parsed_uuid)
                .order_by(AgentLog.created_at)
            )
            return session.exec(statement).all()

    def get_agent_logs_for_run(self, agent_run_id: str | uuid.UUID) -> List[AgentLog]:
        """Every log entry for one specific agent_run, in chronological
        order, including raw_output - the complete transcript of what that
        run actually did. This is how the reporting role builds its
        starting context from a pentesting run (resolved via
        AttackVector.assigned_run_id), rather than trusting a hand-carried
        summary - see pentesting_starting_prompt/reporting_starting_prompt
        in project_scheme.py."""
        parsed_uuid = self._parse_uuid(agent_run_id)

        with Session(self.engine) as session:
            statement = (
                select(AgentLog)
                .where(AgentLog.agent_run_id == parsed_uuid)
                .order_by(AgentLog.created_at)
            )
            return session.exec(statement).all()

    # --- Managing Agent Runs ---
    def upsert_agent_run(self, agent_run: AgentRun) -> AgentRun:
        """Insert or update the row for this (target_id, role). AgentRun's
        PK is now a surrogate `id` (see agent_run_scheme.py), and every
        AgentRun(...) construction gets a fresh random id by default - a
        plain session.merge() keyed on that id would therefore INSERT a new
        row every call instead of updating one, which would both break
        single_agent mode's old "one row per target" behavior and violate
        agentrun_single_agent_per_target the moment a second row for the
        same target+role appeared. Looking up any existing row for this
        (target_id, role) first and reusing its id is what keeps
        _persist_run_state's existing call sites (agent_service.py) working
        completely unchanged for single_agent mode. Multi-agent roles that
        legitimately want a fresh historical row per call (a new pentesting
        run is NOT an update to a previous one) should use
        add_to_database directly instead of this method."""
        with Session(self.engine) as session:
            existing = session.exec(
                select(AgentRun).where(
                    AgentRun.target_id == agent_run.target_id,
                    AgentRun.role == agent_run.role,
                )
            ).first()
            if existing is not None:
                agent_run.id = existing.id

            merged = session.merge(agent_run)
            session.commit()
            session.refresh(merged)
            return merged

    def save_agent_run(self, agent_run: AgentRun) -> AgentRun:
        """Plain merge-by-id (AgentRun's real PK) - for a multi_agent
        pipeline's own sub-runs (scouting/pentesting/reporting/
        orchestrator), which always already know their own row's real id
        (they mint it via add_to_database once, when the run starts - see
        the roles/ package's own run-lifecycle helper) and pass it
        explicitly on every subsequent status update. Deliberately NOT
        upsert_agent_run's (target_id, role) lookup - several concurrent
        pentesting sub-runs legitimately share the same (target_id, role)
        at once, and that lookup would silently collapse them onto one
        row."""
        with Session(self.engine) as session:
            merged = session.merge(agent_run)
            session.commit()
            session.refresh(merged)
            return merged

    def get_agent_run(
        self, target_id: str | uuid.UUID, role: str = "single_agent"
    ) -> AgentRun | None:
        """Defaults to role="single_agent" so every existing call site
        (which only ever passed target_id, from before AgentRun became a
        run-tree) keeps returning exactly what it used to: the one row for
        that target's single-agent flow. agentrun_single_agent_per_target
        guarantees at most one such row exists; order_by+first() is
        defensive, not load-bearing."""
        parsed_uuid = self._parse_uuid(target_id)

        with Session(self.engine) as session:
            statement = (
                select(AgentRun)
                .where(AgentRun.target_id == parsed_uuid, AgentRun.role == role)
                .order_by(AgentRun.recorded_at.desc())
            )
            return session.exec(statement).first()

    def get_agent_runs_for_target(self, target_id: str | uuid.UUID) -> List[AgentRun]:
        """Every run in a target's pipeline (all roles) - the run-tree a
        multi_agent mode target accumulates, vs. the single row
        single_agent mode has. Used for log/run-tree grouping, not by
        single_agent mode's own call sites."""
        parsed_uuid = self._parse_uuid(target_id)

        with Session(self.engine) as session:
            statement = select(AgentRun).where(AgentRun.target_id == parsed_uuid)
            return session.exec(statement).all()

    # --- Managing Attack Vectors ---
    def add_attack_vector(self, attack_vector: AttackVector) -> AttackVector:
        return self.add_to_database(attack_vector)

    def get_attack_vector(self, attack_vector_id: str | uuid.UUID) -> Optional[AttackVector]:
        parsed_uuid = self._parse_uuid(attack_vector_id)

        with Session(self.engine) as session:
            return session.get(AttackVector, parsed_uuid)

    def get_attack_vectors_for_target(
        self, target_id: str | uuid.UUID
    ) -> List[AttackVector]:
        parsed_uuid = self._parse_uuid(target_id)

        with Session(self.engine) as session:
            statement = (
                select(AttackVector)
                .where(AttackVector.target_id == parsed_uuid)
                .order_by(AttackVector.created_at)
            )
            return session.exec(statement).all()

    def update_attack_vector(self, attack_vector: AttackVector) -> AttackVector:
        with Session(self.engine) as session:
            attack_vector.updated_at = datetime.now(timezone.utc)
            merged = session.merge(attack_vector)
            session.commit()
            session.refresh(merged)
            return merged


db_manager = DatabaseManager(settings.database_url)
