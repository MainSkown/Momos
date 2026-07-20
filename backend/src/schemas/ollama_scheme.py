from pydantic import BaseModel

class OllamaDownloadProgress(BaseModel):
    model: str
    status: str
    completed: int
    total: int
    
class ModelData(BaseModel):
    model_name: str
    
class PostRequestOllamaModel(ModelData):    
    project_id: str