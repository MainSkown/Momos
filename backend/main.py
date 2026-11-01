from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from src.core.kali_integration import kali_registry
from src.core.database_manager import db_manager
from src.core.ollama_manager import ollama_manager
from src.core import encryption_service
from src.core.agent.agent_checkpointer import setup_checkpointer, shutdown_checkpointer
from src.routers import (
    project_router,
    target_router,
    websocket_router,
    kali_router,
    ollama_router,
    agent_router,
    vulnerability_router,
    session_router,
    user_settings_router,
    scope_discovery_router,
    connection_router,
)
from src.schemas import export_json_schema, OllamaModelsList
from src.services.connection_service import SAVED_CONNECTION_TIMEOUT_SECONDS


async def _apply_startup_ollama_connection() -> None:
    """Runs once at boot, right after init_db() seeds the connection
    settings row on a fresh database. Provisioning must happen
    unconditionally (Local or Remote) so Remote can be turned on later from
    the Connection tab with zero .env editing (Milestone 3 plan's Scope note
    point 5); applying a saved Remote connection here is what makes a
    restart come back up already pointed at it, instead of silently
    falling back to Local until the next save. A fresh/Local row takes
    neither further branch, leaving ollama_manager on its constructor
    default - "behaves exactly as today" with zero extra calls."""
    encryption_service.ensure_encryption_key_provisioned()

    connection = db_manager.get_ollama_connection_settings()
    if connection is None or connection.mode != "remote":
        return

    if not encryption_service.encryption_key_configured():
        # Defensive only - ensure_encryption_key_provisioned() above means
        # this should be unreachable in practice; kept as the literal
        # fail-fast backstop the spec calls for, in case provisioning
        # itself was ever bypassed (e.g. a future code path that skips
        # lifespan).
        raise RuntimeError(
            "A remote Ollama connection is configured but APP_ENCRYPTION_KEY "
            "is not set - refusing to start rather than risk storing the "
            "API key unencrypted."
        )

    key = (
        encryption_service.decrypt_secret(connection.remote_api_key_encrypted)
        if connection.remote_api_key_encrypted
        else None
    )
    headers = {"Authorization": f"Bearer {key}"} if key else None
    await ollama_manager.reconfigure(
        connection.remote_url, headers=headers, timeout=SAVED_CONNECTION_TIMEOUT_SECONDS
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # == Startup ==
    # Must run before mark_orphaned_sessions_aborted() below - that call
    # queries tables init_db() creates. See DatabaseManager.__init__'s own
    # comment for why this isn't done at construction time instead.
    db_manager.init_db()

    await _apply_startup_ollama_connection()

    export_json_schema(Path("models.schema.json"))

    base_dir = Path(__file__).resolve().parent
    json_path = base_dir / "models_list.json"
    if json_path.exists():
        models_list = OllamaModelsList.model_validate_json(json_path.read_text())
        app.state.ollama_models = models_list.models
    else:
        app.state.ollama_models = []

    await setup_checkpointer()

    # _running_targets (agent_service.py) is a plain in-memory dict, empty
    # after every restart - any TestSession still RUNNING in the database
    # belongs to a pipeline that was genuinely mid-execution when the
    # backend went down, with no live task left to ever end it. See
    # DatabaseManager.mark_orphaned_sessions_aborted's own docstring for
    # why a PAUSED session is deliberately left untouched here.
    db_manager.mark_orphaned_sessions_aborted()

    yield
    await kali_registry.shutdown()
    await shutdown_checkpointer()


app = FastAPI(lifespan=lifespan)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Momos Backend API", version="0.0.1", routes=app.routes
    )

    openapi_schema["servers"] = [{"url": ""}]  # App uses proxies to communicate

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# Routers
# --- APIs ---
app.include_router(project_router, prefix="/api")
app.include_router(target_router, prefix="/api")
app.include_router(kali_router, prefix="/api")
app.include_router(ollama_router, prefix="/api")
app.include_router(agent_router, prefix="/api")
app.include_router(vulnerability_router, prefix="/api")
app.include_router(session_router, prefix="/api")
app.include_router(user_settings_router, prefix="/api")
app.include_router(scope_discovery_router, prefix="/api")
app.include_router(connection_router, prefix="/api")
# --- WebSockets ---
app.include_router(websocket_router, prefix="/ws")
