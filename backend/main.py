from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from src.routers import project_router, target_router, websocket_router
from src.core.kali_integration import kali_user_registry # Import for loading registry

app = FastAPI()

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
app.include_router(project_router, prefix="/api")
app.include_router(target_router, prefix="/api")
app.include_router(websocket_router, prefix="/ws")
