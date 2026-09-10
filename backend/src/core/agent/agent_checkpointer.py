from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from psycopg_pool import AsyncConnectionPool
from psycopg.rows import dict_row
from src.core import settings

_pool: AsyncConnectionPool | None = None
checkpointer: AsyncPostgresSaver | None = None


async def setup_checkpointer() -> AsyncPostgresSaver:
    """Opens the checkpoint connection pool and ensures its tables exist. Must be
    called once at application startup, before any Agent is constructed."""
    global _pool, checkpointer

    _pool = AsyncConnectionPool(
        conninfo=settings.database_url,
        max_size=20,
        kwargs={"autocommit": True, "prepare_threshold": 0, "row_factory": dict_row},
        open=False,
    )
    await _pool.open()

    checkpointer = AsyncPostgresSaver(_pool)
    await checkpointer.setup()

    return checkpointer


async def shutdown_checkpointer():
    global _pool, checkpointer

    if _pool is not None:
        await _pool.close()

    _pool = None
    checkpointer = None
