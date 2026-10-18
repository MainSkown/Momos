import uuid
from datetime import datetime, timezone
from sqlmodel import SQLModel, Session, create_engine, select
from sqlalchemy import delete, text, inspect, func, or_
from . import settings
from typing import List, Optional, Tuple, TypeVar, Type, TYPE_CHECKING

# SQLModels Imports #
from src.schemas.project_scheme import (
    Project,
    ProjectSettings,
    project_settings_factory,
)
from src.schemas.target_scheme import Target
from src.schemas.vulnerability_scheme import Vulnerability
from src.schemas.agent_log_scheme import AgentLog, AgentLogType
from src.schemas.agent_run_scheme import AgentRun
from src.schemas.attack_vector_scheme import AttackVector, AttackVectorStatus
from src.schemas.test_session_scheme import (
    TestSession,
    TestSessionOutcome,
    DEFAULT_LOG_PAGE_SIZE,
)

if TYPE_CHECKING:
    # Deferred to a function-local import at each actual call site below
    # (get_user_settings/update_user_settings) - user_settings_scheme.py
    # itself imports src.core.config.settings at module level, so an eager
    # import HERE would import src.core (this package) while it is still
    # mid-import (we're inside database_manager.py, which src.core's own
    # __init__ imports), landing back on this same, still-partially-loaded
    # user_settings_scheme module and raising ImportError. See
    # project_scheme.py's own comment on pipeline_mode for the same class
    # of cycle avoided the same way.
    from src.schemas.user_settings_scheme import UserSettings

T = TypeVar("T", bound=SQLModel)


class DatabaseManager:
    def __init__(self, db_url: str):
        # create_engine is lazy (SQLAlchemy doesn't open a socket until the
        # first actual use) - init_db() is NOT called here on purpose, since
        # this class is instantiated at import time (module-level
        # db_manager below) and every backend module that imports it would
        # otherwise require a live, correctly-provisioned Postgres just to
        # be imported. Callers that need the schema to exist call init_db()
        # explicitly (main.py's lifespan, in production).
        self.engine = create_engine(db_url, echo=True)

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

        # target.task_duration predates this migration block entirely and so
        # has never had one of its own - it only exists on a database whose
        # target table was built fresh via create_all(). Backfilled here
        # opportunistically while adding its two new siblings below, so it's
        # no longer the one non-migrated column in this area. run_mode
        # defaults every existing Target to 'timer' - see TargetBase - so
        # pre-existing targets keep their exact current behavior.
        with self.engine.connect() as conn:
            conn.execute(text("ALTER TABLE target ADD COLUMN IF NOT EXISTS task_duration INTEGER"))
            conn.execute(
                text(
                    "ALTER TABLE target ADD COLUMN IF NOT EXISTS "
                    "run_mode TEXT NOT NULL DEFAULT 'timer'"
                )
            )
            conn.execute(text("ALTER TABLE target ADD COLUMN IF NOT EXISTS safety_cap_duration INTEGER"))
            conn.commit()

        # TestSession - create_all above already creates the table itself
        # (brand new, no existing rows to migrate), but agentrun/agentlog/
        # attackvector all predate it and need their new nullable
        # session_id column added the same idempotent way as every other
        # column in this method. No REFERENCES constraint here, matching
        # this file's existing convention for every other FK-shaped column
        # added via ALTER (agent_run_id, parent_run_id, attack_vector_id,
        # ...) - enforced at the ORM/Python level only, not the DB's.
        with self.engine.connect() as conn:
            conn.execute(text("ALTER TABLE agentrun ADD COLUMN IF NOT EXISTS session_id UUID"))
            conn.execute(text("ALTER TABLE agentlog ADD COLUMN IF NOT EXISTS session_id UUID"))
            conn.execute(text("ALTER TABLE attackvector ADD COLUMN IF NOT EXISTS session_id UUID"))
            conn.commit()

        # Indexes for session_id (all three tables) and target_id
        # (agentrun/agentlog/attackvector, which never had one despite
        # being queried by it just as often) - create_all() already adds
        # these for a brand-new database (the schemas now declare
        # index=True), but an existing one needs them added explicitly
        # the same way every other structural change in this file does.
        # Named to match SQLModel/SQLAlchemy's own `ix_<table>_<column>`
        # convention for `index=True`, so a fresh and a migrated database
        # end up with identically-named indexes. Without these, every
        # session-scoped read (get_attack_vectors_for_target,
        # attack_vectors_all_checked, get_agent_logs_for_session, ...) is
        # a full sequential scan - previously masked by
        # delete_attack_vectors_for_target keeping these tables tiny, no
        # longer true now that rows persist across every session a target
        # has ever had.
        with self.engine.connect() as conn:
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_agentrun_session_id ON agentrun (session_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_agentlog_session_id ON agentlog (session_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_attackvector_session_id ON attackvector (session_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_agentrun_target_id ON agentrun (target_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_agentlog_target_id ON agentlog (target_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_attackvector_target_id ON attackvector (target_id)"))
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
        """Nulls out every one of the six model-name fields (base_model_name/
        parsing_model_name plus the four per-role fields - see
        ProjectSettingsBase in project_scheme.py) on any project's settings
        that reference model_name - called right before the model itself is
        deleted from Ollama, so a project can never keep pointing at a model
        that no longer exists."""
        model_fields = (
            "base_model_name",
            "parsing_model_name",
            "orchestrator_model_name",
            "scouting_model_name",
            "pentesting_model_name",
            "reporting_model_name",
        )
        with Session(self.engine) as session:
            statement = select(ProjectSettings).where(
                or_(*[getattr(ProjectSettings, field) == model_name for field in model_fields])
            )
            for settings in session.exec(statement).all():
                for field in model_fields:
                    if getattr(settings, field) == model_name:
                        setattr(settings, field, "")
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
            session.exec(delete(TestSession).where(TestSession.project_id == parsed_uuid))
            session.exec(delete(Target).where(Target.project_id == parsed_uuid))
            session.exec(delete(ProjectSettings).where(ProjectSettings.project_id == parsed_uuid))
            session.exec(delete(Project).where(Project.id == parsed_uuid))
            session.commit()

    # --- Managing User Settings ---
    def get_user_settings(self, create_new: bool = True) -> "UserSettings | None":
        from src.schemas.user_settings_scheme import UserSettings, user_settings_factory

        with Session(self.engine) as session:
            user_settings = session.exec(select(UserSettings)).first()
            if user_settings is None and create_new:
                user_settings = user_settings_factory()
                session.add(user_settings)
                session.commit()
                session.refresh(user_settings)
            return user_settings

    def update_user_settings(self, user_settings: "UserSettings") -> "UserSettings":
        with Session(self.engine) as session:
            merged = session.merge(user_settings)
            session.commit()
            session.refresh(merged)
            return merged

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
            session.exec(delete(TestSession).where(TestSession.target_id == parsed_uuid))
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
        self,
        target_id: str | uuid.UUID,
        session_id: str | uuid.UUID | None = None,
    ) -> List[AttackVector]:
        """Scoped to the target's CURRENT session (its most recently
        started one, live or not - see get_latest_session_for_target) so
        the Overview board and the agents' own reads (propose/
        attack_vectors_all_checked) only ever see this run's vectors, not
        every session this target has ever had - AttackVector rows are no
        longer deleted on a fresh start (see TestSession's own docstring),
        so without this scoping a target with any history would show every
        past run's vectors mixed together. Falls back to unscoped (every
        vector for this target) only if the target somehow has no session
        yet at all - defensive, since start_agent always creates one
        before anything can propose a vector.

        session_id is an optional pre-resolved value - a caller already
        holding one in-process (orchestrator_agent.py/agent.py, via
        run_registry.current_session_id_for_target - a plain dict lookup,
        no DB round trip) should pass it, skipping get_latest_session_for_target's
        own query entirely; this matters here specifically because this
        method runs on effectively every agent/orchestrator turn. A caller
        with no live run in process (e.g. AgentService.get_attack_vectors,
        serving a plain REST read) omits it and falls back to resolving it
        from the database as before."""
        parsed_uuid = self._parse_uuid(target_id)
        if session_id is not None:
            current_test_session_id = self._parse_uuid(session_id)
        else:
            latest = self.get_latest_session_for_target(parsed_uuid)
            current_test_session_id = latest.id if latest is not None else None

        with Session(self.engine) as session:
            statement = select(AttackVector).where(AttackVector.target_id == parsed_uuid)
            if current_test_session_id is not None:
                statement = statement.where(AttackVector.session_id == current_test_session_id)
            statement = statement.order_by(AttackVector.created_at)
            return session.exec(statement).all()

    def update_attack_vector(self, attack_vector: AttackVector) -> AttackVector:
        with Session(self.engine) as session:
            attack_vector.updated_at = datetime.now(timezone.utc)
            merged = session.merge(attack_vector)
            session.commit()
            session.refresh(merged)
            return merged

    def attack_vectors_all_checked(
        self,
        target_id: str | uuid.UUID,
        session_id: str | uuid.UUID | None = None,
    ) -> bool:
        """The stop condition for Target.run_mode == "until_vectors_checked":
        true once every AttackVector proposed for the target's CURRENT
        session (see get_attack_vectors_for_target's own comment on why
        this is scoped, not every vector the target has ever had) has
        reached a terminal status (anything but PENDING/TESTING). A
        session with zero vectors proposed yet is NOT "all checked" - it
        must return False, or a fresh run would stop before scouting ever
        gets a chance to propose the first one. See
        get_attack_vectors_for_target's own comment on the optional
        session_id - same pre-resolved-value optimization, same reason."""
        parsed_uuid = self._parse_uuid(target_id)
        if session_id is not None:
            current_test_session_id = self._parse_uuid(session_id)
        else:
            latest = self.get_latest_session_for_target(parsed_uuid)
            current_test_session_id = latest.id if latest is not None else None

        with Session(self.engine) as session:
            scope = [AttackVector.target_id == parsed_uuid]
            if current_test_session_id is not None:
                scope = [AttackVector.session_id == current_test_session_id]

            total = session.exec(
                select(func.count()).select_from(AttackVector).where(*scope)
            ).one()
            if total == 0:
                return False

            unresolved = session.exec(
                select(func.count())
                .select_from(AttackVector)
                .where(
                    *scope,
                    AttackVector.status.in_(
                        [AttackVectorStatus.PENDING, AttackVectorStatus.TESTING]
                    ),
                )
            ).one()
            return unresolved == 0

    # --- Managing Test Sessions ---
    def add_test_session(self, test_session: TestSession) -> TestSession:
        return self.add_to_database(test_session)

    def get_test_session(self, session_id: str | uuid.UUID) -> Optional[TestSession]:
        parsed_uuid = self._parse_uuid(session_id)

        with Session(self.engine) as session:
            return session.get(TestSession, parsed_uuid)

    def update_test_session(self, test_session: TestSession) -> TestSession:
        with Session(self.engine) as session:
            merged = session.merge(test_session)
            session.commit()
            session.refresh(merged)
            return merged

    def get_test_sessions_for_project(
        self,
        project_id: str | uuid.UUID,
        target_id: str | uuid.UUID | None = None,
        outcome: TestSessionOutcome | None = None,
    ) -> List[TestSession]:
        parsed_uuid = self._parse_uuid(project_id)

        with Session(self.engine) as session:
            statement = select(TestSession).where(TestSession.project_id == parsed_uuid)
            if target_id is not None:
                statement = statement.where(TestSession.target_id == self._parse_uuid(target_id))
            if outcome is not None:
                statement = statement.where(TestSession.outcome == outcome)
            statement = statement.order_by(TestSession.started_at.desc())
            return session.exec(statement).all()

    def get_latest_session_for_target(
        self, target_id: str | uuid.UUID
    ) -> Optional[TestSession]:
        """The target's most recently STARTED session, regardless of its
        outcome - live while it's RUNNING/PAUSED, otherwise simply the one
        that just ended. Named "latest", not "current", specifically to
        not be confused with run_registry.current_session_for_target (a
        different thing: that dict only ever holds an entry while a
        session is actually live, popped the moment it ends - see its own
        module comment). This is what scopes both the live board's own
        reads (get_attack_vectors_for_target/attack_vectors_all_checked)
        and start_agent's own paused-session-reuse check to exactly one
        session at a time, and rolls over to the new one automatically the
        moment a fresh start creates it - see TestSession's own module
        docstring."""
        parsed_uuid = self._parse_uuid(target_id)

        with Session(self.engine) as session:
            statement = (
                select(TestSession)
                .where(TestSession.target_id == parsed_uuid)
                .order_by(TestSession.started_at.desc())
            )
            return session.exec(statement).first()

    def get_attack_vectors_for_session(
        self, session_id: str | uuid.UUID
    ) -> List[AttackVector]:
        parsed_uuid = self._parse_uuid(session_id)

        with Session(self.engine) as session:
            statement = (
                select(AttackVector)
                .where(AttackVector.session_id == parsed_uuid)
                .order_by(AttackVector.created_at)
            )
            return session.exec(statement).all()

    def get_run_options_for_session(
        self, session_id: str | uuid.UUID
    ) -> List[Tuple[uuid.UUID, Optional[str]]]:
        """Every distinct (agent_run_id, role) pair this session's own
        AgentLog rows were actually written under - the sub-run filter
        dropdown's real data source (session_router.py's
        GetTestSessionRuns). Deliberately NOT `select(AgentRun).where(
        AgentRun.session_id == session_id)` (an earlier version of this
        method did exactly that): single_agent mode's root run, and
        multi_agent's orchestrator root run, are each a single row REUSED
        across every session on that target (see upsert_agent_run's own
        docstring - the (target_id, role) upsert lookup is what makes that
        reuse possible) - the moment a newer session starts, that row's
        session_id moves on with it, so a plain AgentRun filter made an
        OLDER session's own root run silently vanish from its own
        dropdown, even though its logs (AgentLog.session_id, stamped
        independently per row at write time - see
        run_registry.persist_and_broadcast) still correctly belong to it.
        Querying AgentLog directly sidesteps the whole problem: it's the
        actual ground truth for which agent_run_id values are filterable
        in this session's own logs, and needs no AgentRun row to exist or
        stay correctly attributed at all - single_agent mode's own
        agent_run_id (always == target_id, never a real AgentRun.id - see
        Agent.__init__'s own comment) works here for exactly the same
        reason: get_agent_logs_for_session filters on this same column,
        not on any AgentRun table."""
        parsed_uuid = self._parse_uuid(session_id)

        with Session(self.engine) as session:
            statement = (
                select(AgentLog.agent_run_id, AgentLog.role)
                .where(
                    AgentLog.session_id == parsed_uuid,
                    AgentLog.agent_run_id.is_not(None),
                )
                .distinct()
            )
            return session.exec(statement).all()

    def get_agent_logs_for_session(
        self,
        session_id: str | uuid.UUID,
        role: Optional[str] = None,
        agent_run_id: str | uuid.UUID | None = None,
        log_type: Optional[AgentLogType] = None,
        q: Optional[str] = None,
        limit: int = DEFAULT_LOG_PAGE_SIZE,
        offset: int = 0,
        from_end: bool = False,
    ) -> Tuple[List[AgentLog], int, int]:
        """Server-side filtered/paginated log read for one session - the
        History Logs tab's own data source (unlike
        get_all_agent_logs_in_project/get_agent_logs_for_run, which are
        unfiltered and unpaginated, fine for a live single-run view but not
        for a session that can accumulate a very large transcript over
        its lifetime). Returns (page, total, offset) - the effective
        offset is returned (not just echoed back) because from_end=True
        computes it server-side from `total`, letting a caller opening a
        session land on its last page (the usual "see how it ended" entry
        point) in one round trip instead of probing for `total` first."""
        parsed_uuid = self._parse_uuid(session_id)

        with Session(self.engine) as session:
            filters = [AgentLog.session_id == parsed_uuid]
            if role is not None:
                filters.append(AgentLog.role == role)
            if agent_run_id is not None:
                filters.append(AgentLog.agent_run_id == self._parse_uuid(agent_run_id))
            if log_type is not None:
                filters.append(AgentLog.type == log_type)
            if q:
                like = f"%{q}%"
                filters.append(
                    (AgentLog.content.ilike(like)) | (AgentLog.tool_name.ilike(like))
                )

            total = session.exec(
                select(func.count()).select_from(AgentLog).where(*filters)
            ).one()

            effective_offset = max(0, total - limit) if from_end else offset

            statement = (
                select(AgentLog)
                .where(*filters)
                .order_by(AgentLog.created_at)
                .offset(effective_offset)
                .limit(limit)
            )
            return session.exec(statement).all(), total, effective_offset

    def delete_test_session(self, session_id: str | uuid.UUID) -> None:
        """Removes this session's own AttackVector/AgentLog/AgentRun rows,
        then the session itself. Vulnerability rows are untouched - they're
        durable findings that outlive the session that produced them (see
        TestSession's own module docstring); only the vector that reported
        one is session-scoped, not the vulnerability."""
        parsed_uuid = self._parse_uuid(session_id)

        with Session(self.engine) as session:
            session.exec(delete(AttackVector).where(AttackVector.session_id == parsed_uuid))
            session.exec(delete(AgentLog).where(AgentLog.session_id == parsed_uuid))
            session.exec(delete(AgentRun).where(AgentRun.session_id == parsed_uuid))
            session.exec(delete(TestSession).where(TestSession.id == parsed_uuid))
            session.commit()

    def mark_orphaned_sessions_aborted(self) -> None:
        """Called once at backend startup (main.py's lifespan).
        _running_targets (agent_service.py) is a plain in-memory dict,
        empty after every restart, so any session still RUNNING in the
        database belongs to a pipeline that was genuinely mid-execution
        when the backend went down, with no live task left to ever end it
        - without this it would sit forever looking live in History.
        Deliberately does NOT touch a PAUSED session - pausing has always
        been a deliberate, resumable stopping point in this codebase
        (AgentRunState.PAUSED already survives a restart untouched), restart
        or not, so a paused session is not "orphaned". ended_at is set to
        the last known activity for that session (its last log or run
        update), not "now" - "now" would make a backend that was down for
        hours look like the run itself lasted that long."""
        with Session(self.engine) as session:
            orphaned = session.exec(
                select(TestSession).where(TestSession.outcome == TestSessionOutcome.RUNNING)
            ).all()

            for test_session in orphaned:
                last_log_at = session.exec(
                    select(func.max(AgentLog.created_at)).where(
                        AgentLog.session_id == test_session.id
                    )
                ).one()
                last_run_at = session.exec(
                    select(func.max(AgentRun.recorded_at)).where(
                        AgentRun.session_id == test_session.id
                    )
                ).one()
                # last_resumed_at is itself a floor candidate - a resume
                # right before the crash (no new log/run row written yet in
                # the window between resuming and the backend going down)
                # would otherwise fall back to stale pre-pause activity
                # that predates the resume, setting ended_at to a
                # timestamp BEFORE the session's own last_resumed_at.
                candidates = [
                    t
                    for t in (last_log_at, last_run_at, test_session.last_resumed_at)
                    if t is not None
                ]
                last_activity = max(candidates) if candidates else test_session.started_at

                if test_session.last_resumed_at is not None:
                    test_session.active_seconds += max(
                        0,
                        int((last_activity - test_session.last_resumed_at).total_seconds()),
                    )
                    test_session.last_resumed_at = None

                test_session.outcome = TestSessionOutcome.ABORTED
                test_session.ended_at = last_activity
                session.add(test_session)

            session.commit()


db_manager = DatabaseManager(settings.database_url)
