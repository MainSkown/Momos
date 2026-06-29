from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

app = FastAPI()

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema= get_openapi(
        title="Momos Backend API",
        version="0.0.1",
        routes=app.routes
    )

    openapi_schema["servers"] = [{"url": ""}] # App uses proxies to communicate

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi


@app.get("/api")
def read_root():
    return {"Hello": "World"}