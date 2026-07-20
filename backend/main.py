from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from src.core.kali_integration import kali_registry
from src.routers import (
    project_router,
    target_router,
    websocket_router,
    kali_router,
    ollama_router,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await kali_registry.shutdown()


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
# --- WebSockets ---
app.include_router(websocket_router, prefix="/ws")
