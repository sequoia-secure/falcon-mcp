"""
RTR file collection module for Falcon MCP Server.

Pulls one file off one host with the RTR Active Responder ``get`` command and
returns only its metadata. The file's bytes never pass through this server: the
Falcon cloud holds the extracted file (a password-protected 7z archive, kept for
about seven days) and the investigator downloads it from the Falcon console.

This module is opt-in. It is not part of the default "all modules" set, so a
deployment loads it only by naming it (``--modules rtrcollect`` or
``FALCON_MCP_MODULES=rtrcollect``). That keeps a write-tier capability that
reads arbitrary files off endpoints out of every server that merely runs with
the defaults.
"""

import re
import time
from typing import Any

from mcp.server import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule

logger = get_logger(__name__)

COLLECT_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)

_DEVICE_ID = re.compile(r"^[0-9a-fA-F]{32}$")
# Absolute POSIX path, or a Windows drive or UNC path.
_ABSOLUTE_PATH = re.compile(r"^(/|[A-Za-z]:\\|\\\\)")
_FORBIDDEN_PATH_CHARS = ('"', "\n", "\r", "\x00")
_MIN_JUSTIFICATION = 10


class RTRCollectModule(BaseModule):
    """Opt-in module: collect a single file from a host via RTR ``get``."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.collect_file,
            name="rtr_collect_file",
            annotations=COLLECT_ANNOTATIONS,
        )

    def collect_file(
        self,
        device_id: str = Field(
            description="The host agent ID (AID, 32 hex characters) to collect from.",
        ),
        file_path: str = Field(
            description=(
                "Absolute path of the one file to collect, exactly as it exists on the "
                "host. No wildcards, no `~`. Example: "
                "`/Users/jdoe/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/"
                "ChatStorage.sqlite`."
            ),
        ),
        justification: str = Field(
            description=(
                "Why this file is being collected: case or ticket reference and the "
                "authorizing decision. Recorded in the server log with the request."
            ),
        ),
        queue_offline: bool = Field(
            default=False,
            description=(
                "Queue the collection if the host is offline. The tool then returns "
                "without a file; check the session later in the Falcon console."
            ),
        ),
        timeout_seconds: int = Field(
            default=120,
            ge=10,
            le=160,
            description=(
                "Maximum seconds to wait for the upload to finish. Max: 160, which "
                "keeps the call under a 180-second proxy limit. A larger file can "
                "outlast this; the get keeps running on the host and the result "
                "reports the session to check."
            ),
        ),
        poll_interval_seconds: float = Field(
            default=3.0,
            ge=0.0,
            le=30.0,
            description="Seconds between status checks.",
        ),
    ) -> dict[str, Any]:
        """Collect one file from a host with RTR `get` and return its metadata.

        Opens an RTR session, runs `get` as an Active Responder command, waits for
        the upload, and returns the session ID, file name, SHA256 and size. The file
        stays in the Falcon cloud as a 7z archive (password `infected`) for about
        seven days; download it from the Falcon console. File contents are never
        returned by this tool.
        """
        problem = _validate(device_id, file_path, justification)
        if problem:
            return {"error": problem, "phase": "validate"}

        logger.info(
            "RTR collect requested: device_id=%s path=%r justification=%r",
            device_id,
            file_path,
            justification,
        )

        session = self._base_query_api_call(
            operation="RTR_InitSession",
            body_params={
                "device_id": device_id,
                "origin": "falcon-mcp-collect",
                "queue_offline": queue_offline,
            },
            error_message="Failed to initialize RTR session",
        )
        if self._is_error(session):
            session["phase"] = "init_session"
            return session
        session_id = _first(session, "session_id")
        if not session_id:
            return {
                "error": "RTR session initialization did not return a session_id.",
                "phase": "init_session",
            }

        command = self._base_query_api_call(
            operation="RTR_ExecuteActiveResponderCommand",
            body_params={
                "session_id": session_id,
                "device_id": device_id,
                "base_command": "get",
                "command_string": f'get "{file_path}"',
                "persist": queue_offline,
            },
            error_message="Failed to execute RTR get",
        )
        if self._is_error(command):
            command["phase"] = "get"
            command["session_id"] = session_id
            return command
        cloud_request_id = _first(command, "cloud_request_id")
        if not cloud_request_id:
            return {
                "error": "RTR get did not return a cloud_request_id.",
                "phase": "get",
                "session_id": session_id,
            }

        base = {
            "device_id": device_id,
            "file_path": file_path,
            "session_id": session_id,
            "cloud_request_id": cloud_request_id,
        }
        deadline = time.monotonic() + timeout_seconds

        stderr = ""
        sequence_id = 0
        while True:
            status = self._base_query_api_call(
                operation="RTR_CheckActiveResponderCommandStatus",
                query_params={
                    "cloud_request_id": cloud_request_id,
                    "sequence_id": sequence_id,
                },
                error_message="Failed to check RTR get status",
            )
            if self._is_error(status):
                return {**status, **base, "phase": "status"}
            chunks = [c for c in status if isinstance(c, dict)] if isinstance(status, list) else []
            stderr += "".join(str(c.get("stderr") or "") for c in chunks)
            if any(c.get("complete") is True for c in chunks):
                break
            if time.monotonic() >= deadline:
                return {
                    **base,
                    "complete": False,
                    "timed_out": True,
                    "warning": (
                        "The host has not finished the get. It may still complete; "
                        "check this session in the Falcon console."
                    ),
                }
            if chunks:
                sequence_id = chunks[-1].get("sequence_id", sequence_id)
            time.sleep(poll_interval_seconds)

        if stderr.strip():
            return {**base, "complete": True, "error": stderr.strip(), "phase": "get"}

        # The command can report complete a moment before the file is listed.
        while True:
            listed = self._base_query_api_call(
                operation="RTR_ListFilesV2",
                query_params={"session_id": session_id},
                error_message="Failed to list RTR session files",
            )
            if self._is_error(listed):
                return {**listed, **base, "phase": "list_files"}
            match = _match_file(listed, cloud_request_id, file_path)
            if match:
                break
            if time.monotonic() >= deadline:
                return {
                    **base,
                    "complete": True,
                    "timed_out": True,
                    "warning": "The get completed but the file is not listed yet.",
                }
            time.sleep(poll_interval_seconds)

        logger.info(
            "RTR collect stored: device_id=%s session_id=%s sha256=%s size=%s",
            device_id,
            session_id,
            match.get("sha256"),
            match.get("size"),
        )
        return {
            **base,
            "complete": True,
            "file": {
                "name": match.get("name"),
                "sha256": match.get("sha256"),
                "size": match.get("size"),
                "created_at": match.get("created_at"),
            },
            "retrieval": (
                "The file is held in the Falcon cloud for about 7 days as a 7z archive "
                "with password `infected`. Download it from this RTR session's files "
                "in the Falcon console, then verify the SHA256 above."
            ),
        }


def _validate(device_id: str, file_path: str, justification: str) -> str | None:
    if not isinstance(device_id, str) or not _DEVICE_ID.match(device_id):
        return "device_id must be a 32-character hex host agent ID."
    if not isinstance(file_path, str) or not _ABSOLUTE_PATH.match(file_path):
        return "file_path must be an absolute path to a single file."
    if any(ch in file_path for ch in _FORBIDDEN_PATH_CHARS):
        return "file_path must not contain quotes, newlines or NUL characters."
    if "*" in file_path or "?" in file_path:
        return "file_path must name one file; wildcards are not allowed."
    if not isinstance(justification, str) or len(justification.strip()) < _MIN_JUSTIFICATION:
        return f"justification is required (at least {_MIN_JUSTIFICATION} characters)."
    return None


def _first(result: Any, key: str) -> Any:
    if isinstance(result, list) and result and isinstance(result[0], dict):
        return result[0].get(key)
    return None


def _match_file(listed: Any, cloud_request_id: str, file_path: str) -> dict[str, Any] | None:
    if not isinstance(listed, list):
        return None
    files = [f for f in listed if isinstance(f, dict)]
    for f in files:
        if f.get("cloud_request_id") == cloud_request_id:
            return f
    for f in files:
        if f.get("name") == file_path:
            return f
    return None
