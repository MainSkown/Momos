from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status
from src.services import OllamaService
from ollama import ListResponse
from src.schemas import (
    OllamaModelName,
    OllamaModelData,
    OllamaModelsList,
    OllamaQueueDetails,
)

router = APIRouter()


@router.get(
    "/ollama/models", response_model=OllamaModelsList, operation_id="GetModelsList"
)
async def get_models_list():
    try:
        return await OllamaService.get_models_list()
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not return all models",
        )


@router.post(
    "/ollama/model",
    status_code=status.HTTP_202_ACCEPTED,
    operation_id="DownloadOllamaModel",
)
async def post_ollama_model(data: OllamaModelName):
    try:
        await OllamaService.download_model(data.model_name)
        return {
            "status": "pending",
            "message": f"Download initiated for {data.model_name}",
        }
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not download model: {data.model_name}",
        )


@router.delete(
    "/ollama/model", status_code=status.HTTP_200_OK, operation_id="DeleteModel"
)
async def delete_model(data: OllamaModelName):
    try:
        await OllamaService.delete_model(data.model_name)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not delete model: {data.model_name}",
        )


@router.get(
    "/ollama/downloadable_models",
    response_model=OllamaModelsList,
    operation_id="GetDownloadableModels",
)
async def get_ollama_downloadable_models(request: Request):
    models: list[OllamaModelData] = request.app.state.ollama_models
    return OllamaModelsList(models=models)


@router.get(
    "/ollama/download_queue",
    response_model=OllamaQueueDetails,
    operation_id="GetOllamaDownloadQueueDetails",
)
async def get_ollama_download_queue_details():
    return OllamaService.get_download_queue()
