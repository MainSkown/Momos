import json

import pytest

from src.schemas.ollama_scheme import (
    OllamaModelsList,
    export_json_schema,
    parse_parameter_size,
)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("7B", 7.0),
        ("7.6B", 7.6),
        ("7b", 7.0),
        ("70 B", 70.0),
        ("qwen2.5-7B-instruct", 7.0),
        (None, 0.0),
        ("", 0.0),
        ("Unknown", 0.0),
    ],
)
def test_parse_parameter_size_reads_billions(raw, expected):
    assert parse_parameter_size(raw) == expected


def test_parse_parameter_size_does_not_raise_on_malformed_number():
    assert isinstance(parse_parameter_size("1.2.3B"), float)


def test_parse_parameter_size_converts_million_scale_to_billions():
    assert parse_parameter_size("137M") == pytest.approx(0.137)


def test_export_json_schema_writes_schema_of_models_list(tmp_path):
    output = tmp_path / "models.schema.json"

    export_json_schema(output)

    assert json.loads(output.read_text()) == OllamaModelsList.model_json_schema()
