"""Real-Postgres fixtures shared by every test under tests/integration/
(the DatabaseManager suite and the §1.4b API-integration suite alike).
Everything here is deliberately session-scoped except the per-test
cleanup - starting pgvector/pgvector:pg16 is slow enough that a fresh
container per test would make this whole tier painfully slow for no extra
bug-finding power."""

import uuid

import docker
import docker.errors
import pytest
from sqlalchemy import text
from testcontainers.community.postgres import PostgresContainer

from src.core.database_manager import DatabaseManager


@pytest.fixture(scope="session")
def postgres_container():
    """A real, disposable pgvector/pgvector:pg16 container - one per test
    run, torn down automatically when the session ends. username/password/
    dbname are fixed (not left to the image's defaults) so postgres_dsn
    below can be built without reflecting on the container's internals."""
    with PostgresContainer(
        "pgvector/pgvector:pg16",
        username="momos_test",
        password="momos_test",
        dbname="momos_test",
        driver="psycopg2",
    ) as postgres:
        yield postgres


@pytest.fixture(scope="session")
def postgres_dsn(postgres_container):
    """A plain `postgresql://` DSN with no SQLAlchemy dialect suffix -
    usable by both create_engine (DatabaseManager/SQLAlchemy, defaults to
    psycopg2) and psycopg3's AsyncConnectionPool (agent_checkpointer.py),
    unlike postgres_container.get_connection_url(), which bakes in a
    "+psycopg2" suffix only SQLAlchemy understands."""
    host = postgres_container.get_container_host_ip()
    port = postgres_container.get_exposed_port(5432)
    return f"postgresql://momos_test:momos_test@{host}:{port}/momos_test"


@pytest.fixture(scope="session")
def pg_container(postgres_dsn):
    """A DatabaseManager pointed at the session container, with init_db()
    already run once - mirrors main.py's own explicit call (see
    DatabaseManager.__init__'s comment on why construction alone no longer
    does this)."""
    manager = DatabaseManager(postgres_dsn)
    manager.init_db()
    return manager


@pytest.fixture(autouse=True)
def _clean_database(pg_container):
    """Truncates every table after each test using pg_container, so tests
    never leak state into one another despite sharing one container.
    TRUNCATE ... CASCADE handles FK ordering automatically - unlike the
    application's own delete_* methods, which must delete children before
    parents by hand."""
    yield
    with pg_container.engine.connect() as conn:
        tables = conn.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        ).scalars().all()
        if tables:
            conn.execute(text(f"TRUNCATE TABLE {', '.join(tables)} CASCADE"))
            conn.commit()


@pytest.fixture(scope="session")
def generic_container():
    """A real, plain `alpine` container (no custom image, no pentest
    tools) - used only by test_kali_session.py to exercise
    KaliManger/KaliSession's actual exec/timeout/cleanup plumbing through
    create_terminal_tools, per docs/testing-plan.md §1.4a tier 1. Session-
    scoped (not per-test) since starting a container is slow relative to
    the plumbing tests themselves; each test wires its own fresh
    KaliManger onto this one shared container instead of getting a fresh
    container per test.

    `tty=True` alone (no `stdin_open`) is enough to keep the container's
    default `/bin/sh` running in the background - confirmed empirically,
    and exactly what KaliManger._create_container itself relies on for the
    production Kali image.

    Two small, deliberate additions on top of the stock image - both
    testability requirements of KaliManger's own code, not a "configured
    Kali" in any real sense: `bash` (open_session's real callers default to
    DEFAULT_SESSION_COMMAND = "/bin/bash", which plain Alpine doesn't ship)
    and a `momos` user with a home directory (open_session's own default
    `user` param is KALI_USERS.momos, and _open_session_sync execs into
    that user's home directory unconditionally). Without either, every
    session-opening call in kali_manager.py would fail before any of the
    actual plumbing being tested ever ran - this is the minimum needed to
    exercise that code at all, not a reimplementation of
    KaliManger._configure_container (which assumes a Debian/apt-based
    image and is deliberately NOT run here - see
    backend/tests/integration/tools/conftest.py's live_kali_session for
    the same reasoning applied to the tools tier)."""
    client = docker.from_env()
    name = f"momos-test-generic-{uuid.uuid4().hex[:8]}"
    container = client.containers.run(
        "alpine:3.21",
        name=name,
        detach=True,
        tty=True,
        remove=True,
    )
    try:
        for setup_cmd in (
            ["apk", "add", "--no-cache", "bash"],
            ["adduser", "-D", "momos"],
        ):
            result = container.exec_run(setup_cmd, user="root")
            if result.exit_code != 0:
                raise RuntimeError(
                    f"generic_container setup command {setup_cmd} failed: "
                    f"{result.output.decode(errors='replace')}"
                )
        yield container
    finally:
        try:
            container.stop(timeout=5)
        except docker.errors.NotFound:
            pass
