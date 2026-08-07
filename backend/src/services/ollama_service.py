from src.core import ollama_manager
from src.websocket import ws_registry, ModelPullingUpdate, WsTypes
from src.schemas import (
    OllamaModelsList,
    OllamaModelData,
    parse_parameter_size,
    OllamaQueueDetails,
)
import asyncio


class OllamaService:
    # Queue for downloading models
    _download_queue: asyncio.Queue[str] = asyncio.Queue()

    # Trackers
    _current_download: str | None = None
    _queued_models: list[str] = []
    _worker_task: asyncio.Task | None = None

    @staticmethod
    async def get_models_list() -> OllamaModelsList:
        try:
            response = await ollama_manager.list_models()
            parsed_models: list[OllamaModelData] = []

            for model in response.models:
                show_info = await ollama_manager.show(model.model)
                model_info = getattr(show_info, "model_info", {}) or {}
                details = getattr(model, "details", None)

                context_window = next(
                    (v for k, v in model_info.items() if k.endswith(".context_length")),
                    2048,
                )

                family = getattr(details, "family", "") if details else ""
                param_str = getattr(details, "parameter_size", "") if details else ""
                parameters_size_b = parse_parameter_size(param_str)

                # Checking if downloaded models has "thinking/reasoning" attribute
                model_file = getattr(show_info, "modelfile", "").lower()
                thinking = any(
                    [
                        "deepseek-r1" in model.model.lower(),
                        "qwq" in model.model.lower(),
                        "thinking" in model_file,
                    ]
                )

                size_bytes = getattr(model, "size", 0)
                size_gb = round(size_bytes / (1024**3), 2)

                parsed_models.append(
                    OllamaModelData(
                        family=family,
                        name=model.model,
                        parameters_size_b=parameters_size_b,
                        thinking=thinking,
                        context_window=int(context_window),
                        size_gb=size_gb,
                    )
                )

            return OllamaModelsList(models=parsed_models)

        except Exception as e:
            raise RuntimeError(f"Could not list available models: {str(e)}")

    @classmethod
    def get_download_queue(cls):
        return OllamaQueueDetails(
            current=cls._current_download, queue=list(cls._queued_models)
        )

    @classmethod
    async def download_model(cls, model_name: str):
        if model_name == cls._current_download or model_name in cls._queued_models:
            raise ValueError(f"Model '{model_name}' is already downloading or queued.")
        
        # Check if already downloaded
        downloaded = await cls.get_models_list()
        if any(model_name == model.name for model in downloaded.models):
            raise ValueError(f"Model {model_name} already downloaded")
        
        cls._queued_models.append(model_name)
        await cls._download_queue.put(model_name)
        
        cls._ensure_worker_running()
        
    @classmethod
    def _ensure_worker_running(cls):
        """Starts the background worker loop if it isn't already running."""
        if cls._worker_task is None or cls._worker_task.done():
            cls._worker_task = asyncio.create_task(cls._download_worker())
        
    @classmethod
    async def _download_worker(cls):
        while not cls._download_queue.empty():
            model_name = await cls._download_queue.get()
            
            cls._current_download = model_name
            if model_name in cls._queued_models:
                cls._queued_models.remove(model_name)
            
            try:        
                async for progress in ollama_manager.pull_model(model_name):
                    update = ModelPullingUpdate(
                        progress=progress, type=WsTypes.ModelPullingUpdate
                    )
                    await ws_registry.send_message(update)
            except Exception as e:
                print(f"Error while downloading model {model_name}: {e}")
            finally:
                cls._current_download = None
                cls._download_queue.task_done()

    @staticmethod
    async def delete_model(model_name: str):
        await ollama_manager.delete_model(model_name)
