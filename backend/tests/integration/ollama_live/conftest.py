"""T1 fixture (docs/plans/milestone-3-remote-ollama-connection.md's T1
section) - a real, ephemeral `ollama/ollama` container that
test_remote_ollama_connection.py drives end-to-end. Follows
tests/integration/tools/conftest.py's existing convention **exactly**:
plain `docker` SDK (not `testcontainers` - this repo already has that
convention for Docker-backed fixtures, no reason to introduce a second one
for one feature), the same module-level `_stop_and_remove_container`
helper, and unconditional cleanup in a `finally` regardless of what the
test does with the yielded URL - an orphaned `ollama/ollama` container left
running is a worse outcome than a failed assertion.

Implicitly `live_tools`-marked the same way tools/conftest.py's own
fixtures are: only ever requested by a `live_tools`-marked test, so pytest
never instantiates it for the deselected default suite (`-m 'not
live_tools'`, the addopts default) and this file never touches Docker
because of the default run.

No model is pulled into the container - `list()` on an empty Ollama server
already proves reachability end-to-end (see
test_remote_ollama_connection.py); pulling a real model would make this
test slow and bandwidth-heavy for no added assertion value."""

import time

import docker
import docker.errors
import httpx
import pytest

READINESS_POLL_ATTEMPTS = 30
READINESS_POLL_INTERVAL_SECONDS = 1.0


def _stop_and_remove_container(container) -> None:
    try:
        container.stop(timeout=5)
    except docker.errors.NotFound:
        pass
    try:
        container.remove(force=True)
    except docker.errors.NotFound:
        pass


@pytest.fixture(scope="session")
def live_ollama_url():
    client = docker.from_env()
    container = client.containers.run(
        "ollama/ollama:latest",
        ports={"11434/tcp": None},
        detach=True,
    )
    try:
        container.reload()
        mapped_port = container.ports["11434/tcp"][0]["HostPort"]
        base_url = f"http://127.0.0.1:{mapped_port}"

        for _attempt in range(READINESS_POLL_ATTEMPTS):
            try:
                response = httpx.get(f"{base_url}/api/tags", timeout=2.0)
                if response.status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(READINESS_POLL_INTERVAL_SECONDS)
        else:
            raise RuntimeError(
                f"ollama/ollama container never became ready on {base_url} "
                f"after {READINESS_POLL_ATTEMPTS} attempts"
            )

        yield base_url
    finally:
        _stop_and_remove_container(container)
