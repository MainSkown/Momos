from .project_router import router as project_router
from .target_router import router as target_router
from .websocket_router import router as websocket_router
from .kali_router import router as kali_router
from .ollama_router import router as ollama_router
from .agent_router import router as agent_router

__all__ = [
    "project_router",
    "target_router",
    "websocket_router",
    "kali_router",
    "ollama_router",
    "agent_router",
]