from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from src.services import OllamaService
from ollama import ListResponse
from src.schemas import PostRequestOllamaModel, ModelData

router = APIRouter()


@router.get("/ollama/models", response_model=ListResponse, operation_id="GetModelsList")
async def get_models_list():
    try:
        return await OllamaService.get_models_list()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not return all models",
        )


@router.post(
    "/ollama/model", status_code=status.HTTP_202_ACCEPTED, operation_id="PostModel"
)
async def post_ollama_model(data: PostRequestOllamaModel, bg_tasks: BackgroundTasks):
    try:
        bg_tasks.add_task(
            OllamaService.download_model, data.model_name, data.project_id
        )
        return {
            "status": "pending",
            "message": f"Download initiated for {data.model_name}",
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not download model: {data.model_name}",
        )


@router.delete("/ollama/model", operation_id="DeleteModel")
async def delete_model(data: ModelData):
    try:
        await OllamaService.delete_model(data.model_name)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not delete model: {data.model_name}",
        )
