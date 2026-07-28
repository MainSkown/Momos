from pydantic import BaseModel

class OllamaDownloadProgress(BaseModel):
    model: str
    status: str
    completed: int
    total: int
    
class OllamaModelName(BaseModel):
    model_name: str
    