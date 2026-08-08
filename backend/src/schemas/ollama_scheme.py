from pathlib import Path
from pydantic import BaseModel
import json
import re

def parse_parameter_size(param_str: str | None) -> float:
    """Converts string to float - B"""
    if not param_str:
        return 0.0
    match = re.search(r"([\d.]+)\s*B", param_str, re.IGNORECASE)
    return float(match.group(1)) if match else 0.0

class OllamaQueueDetails(BaseModel):
    current: str | None
    queue: list[str]

class OllamaDownloadProgress(BaseModel):
    model: str # name   
    status: str # downloading / error
    completed: int | None 
    total: int | None


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