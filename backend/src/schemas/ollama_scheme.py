from pathlib import Path
from typing import Literal, Optional
from pydantic import BaseModel
import json
import re

def parse_parameter_size(param_str: str | None) -> float:
    """Converts string to float - B. Falls back to 0.0 for anything that
    isn't a clean billions/millions-scale number instead of letting a
    malformed match (e.g. "1.2.3B") raise out of float()."""
    if not param_str:
        return 0.0

    billions_match = re.search(r"([\d.]+)\s*B", param_str, re.IGNORECASE)
    if billions_match:
        try:
            return float(billions_match.group(1))
        except ValueError:
            return 0.0

    millions_match = re.search(r"([\d.]+)\s*M", param_str, re.IGNORECASE)
    if millions_match:
        try:
            return float(millions_match.group(1)) / 1000
        except ValueError:
            return 0.0

    return 0.0

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
    recommended: Optional[Literal["parsing", "agent"]] = None


class OllamaModelsList(BaseModel):
    models: list[OllamaModelData]
    
def export_json_schema(output_path: Path = Path("models.schema.json")):
    schema = OllamaModelsList.model_json_schema()
    output_path.write_text(json.dumps(schema, indent=2))