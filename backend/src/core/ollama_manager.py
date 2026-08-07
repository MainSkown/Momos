from typing import AsyncGenerator
from src.schemas import OllamaDownloadProgress
from ollama import AsyncClient
from . import settings


class OllamaManager:
    def __init__(self):
        self.client = AsyncClient(settings.ollama_url)

    async def list_models(self):
        try:
            model_list = await self.client.list()
            return model_list
        except Exception as e:
            raise RuntimeError(f"Could not list available models: {str(e)}")

    async def pull_model(
        self, model_name: str
    ) -> AsyncGenerator[OllamaDownloadProgress, None]:
        try:
            response = await self.client.pull(model_name, stream=True)

            async for progress in response:
                completed = progress.completed
                total = progress.total

                yield OllamaDownloadProgress(
                    model=model_name,
                    status=progress.status if progress.status != None else "",
                    completed=completed,
                    total=total,
                )

        except Exception as e:
            raise RuntimeError(
                f"Could not pull requested model: {model_name}, {str(e)}"
            )

    async def delete_model(self, model_name: str):
        try:
            await self.client.delete(model_name)
        except Exception as e:
            raise RuntimeError(
                f"Could not delete requested model: {model_name}, {str(e)}"
            )

    async def show(self, model_name: str):
        try:
            return await self.client.show(model_name)
        except Exception as e:
            raise RuntimeError(
                f"Could not show requested model: {model_name}, {str(e)}"
            )


ollama_manager = OllamaManager()
