from pathlib import Path
from pydantic import BaseModel
import json


class OllamaDownloadProgress(BaseModel):
    model: str
    status: str
    completed: int
    total: int


class OllamaModelName(BaseModel):
    model_name: str


class OllamaModelData(BaseModel):
    # Base identification
    family: str
    name: str

    # Sizing & Specs
    parameters_size_b: float
    thinking: bool
    context_window: int  # Raw token count
    size_gb: float  # Disk footprint in GB


class OllamaModelsList(BaseModel):
    models: list[OllamaModelData]
    
def export_json_schema(output_path: Path = Path("models.schema.json")):
    schema = OllamaModelsList.model_json_schema()
    output_path.write_text(json.dumps(schema, indent=2))