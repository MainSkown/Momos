from src.core import ollama_manager
from src.websocket import ws_registry, ModelPullingUpdate, WsTypes
from src.schemas import OllamaModelsList, OllamaModelData, parse_parameter_size


class OllamaService:
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
                    2048 
                )
                
                family = getattr(details, "family", "") if details else ""
                param_str = getattr(details, "parameter_size", "") if details else ""
                parameters_size_b = parse_parameter_size(param_str)

                # Checking if downloaded models has "thinking/reasoning" attribute 
                model_file = getattr(show_info, "modelfile", "").lower()
                thinking = any([
                    "deepseek-r1" in model.model.lower(),
                    "qwq" in model.model.lower(),
                    "thinking" in model_file
                ])
             
                size_bytes = getattr(model, "size", 0)
                size_gb = round(size_bytes / (1024 ** 3), 2)

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

    @staticmethod
    async def download_model(model_name: str):
        async for process in ollama_manager.pull_model(model_name):
            update = ModelPullingUpdate(
                **process.model_dump(), type=WsTypes.ModelPullingUpdate
            )
            await ws_registry.send_message(update)
            
    @staticmethod
    async def delete_model(model_name: str):
        await ollama_manager.delete_model(model_name)
