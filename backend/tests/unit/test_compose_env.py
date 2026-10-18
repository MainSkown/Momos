import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None or not COMPOSE_FILE.exists(),
    reason="needs the docker CLI and the repo-root docker-compose.yml",
)

ENV = {
    "POSTGRES_USER": "sentinel_user",
    "POSTGRES_PASSWORD": "sentinel_password",
    "POSTGRES_DB": "sentinel_db",
    "POSTGRES_HOST": "sentinel-host",
    "POSTGRES_PORT": "6543",
    "OLLAMA_HOST": "sentinel-ollama",
    "OLLAMA_PORT": "9999",
}


def _render(env_file: Path) -> dict:
    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "--env-file", str(env_file),
         "config", "--format", "json"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_db_credentials_come_from_env_file(tmp_path):
    env_file = tmp_path / "env"
    env_file.write_text("".join(f"{k}={v}\n" for k, v in ENV.items()))

    db_env = _render(env_file)["services"]["db"]["environment"]

    assert db_env["POSTGRES_USER"] == "sentinel_user"
    assert db_env["POSTGRES_PASSWORD"] == "sentinel_password"
    assert db_env["POSTGRES_DB"] == "sentinel_db"


def test_backend_receives_env_file_values(tmp_path):
    env_file = tmp_path / "env"
    env_file.write_text("".join(f"{k}={v}\n" for k, v in ENV.items()))

    backend_env = _render(env_file)["services"]["momos-backend"]["environment"]

    assert backend_env["POSTGRES_HOST"] == "sentinel-host"
    assert backend_env["OLLAMA_PORT"] == "9999"


def test_missing_credentials_fail_loudly(tmp_path):
    env_file = tmp_path / "env"
    env_file.write_text("")

    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "--env-file", str(env_file),
         "config"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )

    assert result.returncode != 0
    assert "POSTGRES_PASSWORD" in result.stderr
