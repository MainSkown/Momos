from fastapi import APIRouter, HTTPException, status

from src.schemas import (
    OllamaConnectionPublic,
    OllamaConnectionTestRequest,
    OllamaConnectionTestResult,
    OllamaConnectionUpdate,
)
from src.services.connection_service import ConnectionService
from src.utils.exceptions import (
    ConnectionSwitchBlockedException,
    EncryptionKeyMissingException,
)

router = APIRouter()


@router.get(
    "/ollama/connection",
    response_model=OllamaConnectionPublic,
    operation_id="GetOllamaConnection",
)
def get_ollama_connection():
    """Return the saved Ollama connection. The API key is never returned; only `has_remote_api_key` says whether one is stored."""
    return ConnectionService.get_connection()


@router.put(
    "/ollama/connection",
    response_model=OllamaConnectionPublic,
    operation_id="UpdateOllamaConnection",
)
async def update_ollama_connection(data: OllamaConnectionUpdate):
    """Save the Ollama connection and reconfigure the live client. Returns 409 while agents are running, and 500 when APP_ENCRYPTION_KEY is unset and a key must be stored."""
    try:
        return await ConnectionService.save_connection(data)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except EncryptionKeyMissingException:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="APP_ENCRYPTION_KEY is not configured, so the remote API key cannot be stored.",
        )
    except ConnectionSwitchBlockedException as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{e} ({e.running_count} agent run(s) still active.)",
        )


@router.post(
    "/ollama/connection/test",
    response_model=OllamaConnectionTestResult,
    operation_id="TestOllamaConnection",
)
async def test_ollama_connection(data: OllamaConnectionTestRequest):
    """Probe an Ollama endpoint without saving it. Always returns 200; an unreachable endpoint is reported as `reachable: false`."""
    return await ConnectionService.test_connection(data.remote_url, data.remote_api_key)
