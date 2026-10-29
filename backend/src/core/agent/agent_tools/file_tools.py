"""Unconditional local file read/write/list/download tools - core sandbox
utility, not gated by allow_shell (distinct capability from raw shell
access) and not part of tool_groups.py (not target interaction, so never
choosable/never interrupt-gated). See create_file_tools."""

import base64
import re
import shlex
import uuid
from typing import Optional
from urllib.parse import urlparse

from langchain_core.tools import tool

from .common import _execute_one_shot, _file_exists_in_container, _SAFE_PATH_PATTERN

WRITE_LOCAL_FILE_TOOL_NAME = "write_local_file"
READ_LOCAL_FILE_TOOL_NAME = "read_local_file"
LIST_LOCAL_FILES_TOOL_NAME = "list_local_files"
DOWNLOAD_FILE_TOOL_NAME = "download_file"

LOCAL_FILES_DIR = "/tmp/momos-files"
WRITE_LOCAL_FILE_TIMEOUT_SECONDS = 15
READ_LOCAL_FILE_TIMEOUT_SECONDS = 10
LIST_LOCAL_FILES_TIMEOUT_SECONDS = 10
# Generous enough for a script/payload/config file, small enough that a
# base64-encoded blob of it can't strain the exec pipeline or dump
# something huge into the agent's context on a later read.
WRITE_LOCAL_FILE_MAX_BYTES = 65536
READ_LOCAL_FILE_MAX_BYTES = 65536
DOWNLOAD_FILE_TIMEOUT_SECONDS = 60
# A download can legitimately be a lot bigger than something the agent
# types/pastes itself (WRITE_LOCAL_FILE_MAX_BYTES) - large enough for a
# real payload/wordlist/archive fetched from a target, small enough to
# bound how long a stray huge response ties up the container. Enforced by
# curl's own --max-filesize, so an oversized response is aborted mid-
# transfer rather than filling the sandbox disk first.
DOWNLOAD_FILE_MAX_BYTES = 26_214_400
_DOWNLOAD_ALLOWED_SCHEMES = {"http", "https"}

# No "/" (or ".."-via-"/") at all, unlike common._SAFE_PATH_PATTERN - this
# is a bare filename component write_local_file/download_file append to
# their own generated directory, never a caller-supplied path, so it must
# not be able to escape that directory.
_SAFE_FILENAME_PATTERN = re.compile(r"^[\w.-]+\Z")


def create_file_tools(project_id: str) -> list:
    """Unconditional local file read/write/list/download tools - core
    sandbox utility, not gated by allow_shell (distinct capability from
    raw shell access) and not part of tool_groups.py (not target
    interaction, so never choosable/never interrupt-gated). Deliberately
    doesn't call mark_tested() - writing/reading a local file inside the
    sandbox isn't "testing" the target, same reasoning as install_kali_package sitting
    outside _MODE_GATE_WRITER_TOOL_NAMES."""

    @tool(WRITE_LOCAL_FILE_TOOL_NAME, response_format="content_and_artifact")
    async def write_local_file(content: str, filename: Optional[str] = None) -> str:
        """Writes `content` to a new file inside the sandbox (under
        /tmp/momos-files) and returns its absolute path - use this to save
        a script, payload, wordlist, or config file to reference later
        with run()/read_local_file(), or to point another tool at.
        Nothing else remembers this path for you - if you forget it, call
        list_local_files() to see what you've already saved.

        Args:
            content: The exact text to write.
            filename: Optional filename to make the returned path easier
                to recognize later (e.g. "exploit.py") - a bare filename,
                no slashes. A unique prefix is always added too, so this
                is never required and never collides with an earlier file.
        """
        content_bytes = content.encode()
        if len(content_bytes) > WRITE_LOCAL_FILE_MAX_BYTES:
            return (
                f"Content is {len(content_bytes)} bytes, over the "
                f"{WRITE_LOCAL_FILE_MAX_BYTES}-byte limit - write "
                "something smaller."
            ), None
        if filename is not None and not _SAFE_FILENAME_PATTERN.match(filename):
            return (
                f"Invalid filename '{filename}' - letters, digits, '.', "
                "'_', '-' only, no slashes."
            ), None

        file_id = uuid.uuid4().hex[:12]
        name = f"{file_id}-{filename}" if filename else file_id
        path = f"{LOCAL_FILES_DIR}/{name}"
        encoded = base64.b64encode(content_bytes).decode()
        command = (
            f"mkdir -p {shlex.quote(LOCAL_FILES_DIR)} && "
            f"echo {shlex.quote(encoded)} | base64 -d > {shlex.quote(path)}"
        )
        ok, output = await _execute_one_shot(
            project_id, command, WRITE_LOCAL_FILE_TIMEOUT_SECONDS
        )
        if not ok:
            return output, None
        return f"Wrote {len(content_bytes)} bytes to {path}", None

    @tool(READ_LOCAL_FILE_TOOL_NAME, response_format="content_and_artifact")
    async def read_local_file(path: str) -> str:
        """Reads back a file's content - one written by write_local_file,
        or any other text file inside the sandbox. Output is capped; a
        file larger than that only has its start returned.

        Args:
            path: Absolute path inside the sandbox, e.g.
                "/tmp/momos-files/abc123def456-exploit.py".
        """
        if not _SAFE_PATH_PATTERN.match(path):
            return f"Invalid path '{path}'.", None
        if not await _file_exists_in_container(project_id, path):
            return f"'{path}' does not exist.", None

        ok, output = await _execute_one_shot(
            project_id,
            f"head -c {READ_LOCAL_FILE_MAX_BYTES} {shlex.quote(path)}",
            READ_LOCAL_FILE_TIMEOUT_SECONDS,
        )
        if not ok:
            return output, None
        if len(output.encode()) >= READ_LOCAL_FILE_MAX_BYTES:
            output += f"\n\n[... truncated at {READ_LOCAL_FILE_MAX_BYTES} bytes]"
        return output, output

    @tool(LIST_LOCAL_FILES_TOOL_NAME, response_format="content_and_artifact")
    async def list_local_files(directory: Optional[str] = None) -> str:
        """Lists files in `directory` (defaults to /tmp/momos-files, where
        write_local_file always saves) - use this when you've forgotten
        the exact path of a file you saved earlier.

        Args:
            directory: Directory to list inside the sandbox. Defaults to
                /tmp/momos-files.
        """
        target_dir = directory if directory is not None else LOCAL_FILES_DIR
        if not _SAFE_PATH_PATTERN.match(target_dir):
            return f"Invalid directory '{target_dir}'.", None

        ok, output = await _execute_one_shot(
            project_id, f"ls -la {shlex.quote(target_dir)}", LIST_LOCAL_FILES_TIMEOUT_SECONDS
        )
        if not ok:
            return output, None
        return output, output

    @tool(DOWNLOAD_FILE_TOOL_NAME, response_format="content_and_artifact")
    async def download_file(url: str, filename: Optional[str] = None) -> str:
        """Downloads `url` into the sandbox (under /tmp/momos-files) and
        returns its absolute path - use this once you've confirmed a file
        exists on an HTTP server (e.g. via run()'s curl -I) and actually
        want its contents, to then read with read_local_file() or
        reference from another tool.

        Args:
            url: The http:// or https:// URL to fetch.
            filename: Optional filename to make the returned path easier
                to recognize later (e.g. "backup.zip") - a bare filename,
                no slashes. A unique prefix is always added too, so this
                is never required and never collides with an earlier file.
        """
        parsed = urlparse(url)
        if parsed.scheme not in _DOWNLOAD_ALLOWED_SCHEMES or not parsed.netloc:
            return (
                f"Invalid URL '{url}' - only http:// and https:// URLs are supported."
            ), None
        if filename is not None and not _SAFE_FILENAME_PATTERN.match(filename):
            return (
                f"Invalid filename '{filename}' - letters, digits, '.', "
                "'_', '-' only, no slashes."
            ), None

        file_id = uuid.uuid4().hex[:12]
        name = f"{file_id}-{filename}" if filename else file_id
        path = f"{LOCAL_FILES_DIR}/{name}"
        command = (
            f"mkdir -p {shlex.quote(LOCAL_FILES_DIR)} && "
            f"curl -fsSL --max-time {DOWNLOAD_FILE_TIMEOUT_SECONDS} "
            f"--max-filesize {DOWNLOAD_FILE_MAX_BYTES} "
            f"-o {shlex.quote(path)} {shlex.quote(url)} && "
            f"stat --format=%s {shlex.quote(path)}"
        )
        ok, output = await _execute_one_shot(
            project_id, command, DOWNLOAD_FILE_TIMEOUT_SECONDS
        )
        if not ok:
            return output, None
        size = output.strip()
        return f"Downloaded {size} bytes from {url} to {path}", None

    return [write_local_file, read_local_file, list_local_files, download_file]
