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

    async def get_model_capabilities(self, model_name: str) -> dict:
        """Single source of truth for the "does this model natively
        support reasoning/thinking, and how big is its context window"
        heuristics - see capabilities_from_show_info below for the actual
        detection logic (pulled out as a pure function so a caller that
        already has a show() result, like OllamaService.get_models_list(),
        can reuse it without a second network round-trip). Used by
        Agent.changeModel so reasoning isn't hardcoded on for every model
        regardless of whether its own chat template actually supports it -
        a non-reasoning model forced into reasoning=True can return
        empty/garbled output."""
        show_info = await self.show(model_name)
        return capabilities_from_show_info(model_name, show_info)


def capabilities_from_show_info(model_name: str, show_info) -> dict:
    """Pure detection logic behind OllamaManager.get_model_capabilities -
    Ollama doesn't expose a clean boolean capability for "does this model
    support reasoning" on every server version, hence the name/modelfile
    heuristic as a fallback alongside the real capability flag.

    Returns {"thinking": bool, "context_window": int} - context_window
    falls back to 2048 (a conservative floor, not a real default any
    current model actually ships with) if model_info has no
    "*.context_length" key to read it from."""
    # NOTE: the installed `ollama` client's ShowResponse declares this field
    # as `modelinfo: ... = Field(alias='model_info')` - "model_info" is only
    # the Pydantic *alias* (used for (de)serialization), never a real
    # attribute name, so `getattr(show_info, "model_info", {})` always
    # misses and silently returns {}. Read the real attribute instead.
    model_info = getattr(show_info, "modelinfo", {}) or {}
    context_window = next(
        (v for k, v in model_info.items() if k.endswith(".context_length")),
        2048,
    )

    # `modelfile` is a declared-but-nullable field - present-but-None (not
    # merely absent) for some models, which crashes a bare `.lower()`.
    model_file = (getattr(show_info, "modelfile", None) or "").lower()
    # Prefer Ollama's own reported capability list when the server provides
    # one; the name/modelfile substring checks remain as a fallback for
    # servers/models that don't populate `capabilities`.
    capabilities = getattr(show_info, "capabilities", None) or []
    thinking = any(
        [
            "thinking" in capabilities,
            "deepseek-r1" in model_name.lower(),
            "qwq" in model_name.lower(),
            "thinking" in model_file,
        ]
    )

    return {"thinking": thinking, "context_window": int(context_window)}


ollama_manager = OllamaManager()
