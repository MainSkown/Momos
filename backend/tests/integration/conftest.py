"""Real-Postgres fixtures shared by every test under tests/integration/
(the DatabaseManager suite and the §1.4b API-integration suite alike).
Everything here is deliberately session-scoped except the per-test
cleanup - starting pgvector/pgvector:pg16 is slow enough that a fresh
container per test would make this whole tier painfully slow for no extra
bug-finding power."""

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
