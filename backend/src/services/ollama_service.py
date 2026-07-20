from src.core import ollama_manager
from src.websocket import ws_registry, ModelPullingUpdate, WsTypes


class OllamaService:
    @staticmethod
    async def get_models_list():
        return await ollama_manager.list_models()

    @staticmethod
    async def download_model(model_name: str, project_id: str):
        async for process in ollama_manager.pull_model(model_name):
            update = ModelPullingUpdate(
                **process.model_dump(), type=WsTypes.ModelPullingUpdate
            )
            await ws_registry.send_message(project_id, update)
            
    @staticmethod
    async def delete_model(model_name: str):
        await ollama_manager.delete_model(model_name)
