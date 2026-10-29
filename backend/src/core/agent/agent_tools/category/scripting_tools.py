"""run_python_script - a new, off-by-default capability: running
arbitrary Python inside the sandbox, gated by its own tool_groups entry
(see tool_groups.py's "scripting" group) independently of allow_shell -
a project can allow shell but not scripting, or vice versa."""

import base64
import shlex
import uuid
from typing import Callable

from langchain_core.tools import tool

from .common import _execute_one_shot
from .file_tools import LOCAL_FILES_DIR, WRITE_LOCAL_FILE_TIMEOUT_SECONDS

RUN_PYTHON_SCRIPT_TOOL_NAME = "run_python_script"


def create_scripting_tools(
    project_id: str,
    on_raw_output: Callable[[str], None],
    mark_tested: Callable[[], None],
) -> list:
    @tool(RUN_PYTHON_SCRIPT_TOOL_NAME, response_format="content_and_artifact")
    async def run_python_script(code: str, timeout_seconds: int = 30) -> str:
        """Runs `code` as a Python 3 script inside the sandbox and
        returns its combined stdout/stderr. Use this for quick scripted
        logic (parsing, encoding, a small exploit helper) that's awkward
        to do with the shell tools alone.

        Args:
            code: The exact Python source to run.
            timeout_seconds: How long to allow the script to run before
                it's killed. Defaults to 30.
        """
        file_id = uuid.uuid4().hex[:12]
        path = f"{LOCAL_FILES_DIR}/{file_id}-script.py"
        encoded = base64.b64encode(code.encode()).decode()
        write_command = (
            f"mkdir -p {shlex.quote(LOCAL_FILES_DIR)} && "
            f"echo {shlex.quote(encoded)} | base64 -d > {shlex.quote(path)}"
        )
        ok, output = await _execute_one_shot(
            project_id, write_command, WRITE_LOCAL_FILE_TIMEOUT_SECONDS
        )
        if not ok:
            return output, None

        ok, output = await _execute_one_shot(
            project_id, f"python3 {shlex.quote(path)}", timeout_seconds
        )
        mark_tested()
        if not ok:
            return output, None
        on_raw_output(output)
        return output, output

    return [run_python_script]
