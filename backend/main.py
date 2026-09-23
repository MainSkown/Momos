from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from src.core.kali_integration import kali_registry
from src.core.agent.agent_checkpointer import setup_checkpointer, shutdown_checkpointer
from src.routers import (
    project_router,
    target_router,
    websocket_router,
    kali_router,
    ollama_router,
    agent_router,
    vulnerability_router,
)
from src.schemas import export_json_schema, OllamaModelsList

@asynccontextmanager
async def lifespan(app: FastAPI):
    # == Startup ==
    export_json_schema(Path("models.schema.json"))

    base_dir = Path(__file__).resolve().parent
    json_path = base_dir / "models_list.json"
    if json_path.exists():
        models_list = OllamaModelsList.model_validate_json(json_path.read_text())
        app.state.ollama_models = models_list.models
    else:
        app.state.ollama_models = []

    await setup_checkpointer()

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
# --- WebSockets ---
app.include_router(websocket_router, prefix="/ws")
