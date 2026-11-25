"""The stdio bridge to the MCP HTTP transport (`hst mcp --remote URL`).

An MCP client that launches only stdio servers runs `hst mcp --remote
https://host/api/mcp`. The bridge reads one JSON-RPC message per line from
stdin, posts the line unchanged to the URL with the personal access token of
`HST_MCP_TOKEN` as a bearer token, and writes each JSON-RPC message of the
answer to stdout, one per line and byte for byte. The bridge holds no database
credentials. The server authenticates the token, checks each permission and
writes the audit rows.

A request that the server answers with an HTTP error, or that fails in
transit, is answered on stdout with a JSON-RPC error that holds the cause.
Diagnostics go to stderr.

The module imports only the standard library and httpx.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Callable
from typing import Any, BinaryIO
from urllib.parse import urlsplit

import httpx

TOKEN_ENV = "HST_MCP_TOKEN"  # noqa: S105 - an environment variable name
PROTOCOL_HEADER = "MCP-Protocol-Version"
# The longest wait for one answer.
REQUEST_TIMEOUT_S = 300.0
# JSON-RPC error codes of the answers the bridge writes itself
PARSE_ERROR = -32700
TRANSPORT_ERROR = -32000

_ACCEPT = "application/json, text/event-stream"
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


class BridgeError(Exception):
    """A configuration error that stops the bridge before it starts."""


def check_url(url: str) -> str:
    """Return `url` when the bridge may send the token to it.

    An https URL is accepted. A plain http URL is accepted only for a loopback
    host.
    """
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return url
    if parts.scheme == "http" and parts.hostname in _LOOPBACK:
        return url
    raise BridgeError(f"--remote {url!r}: the URL must be https, or http to localhost, 127.0.0.1 or ::1")


class Bridge:
    """Relays JSON-RPC messages to one MCP HTTP endpoint.

    `write` receives each line for stdout, newline included. After an
    `initialize` answer, every later request has the negotiated protocol
    version in the `MCP-Protocol-Version` header.
    """

    def __init__(
        self,
        url: str,
        token: str,
        write: Callable[[bytes], None],
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout_s: float = REQUEST_TIMEOUT_S,
    ) -> None:
        self.url = url
        self._write = write
        self._protocol_version: str | None = None
        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(timeout_s, connect=10.0),
            headers={"Authorization": f"Bearer {token}"},
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def forward(self, line: bytes) -> None:
        """Post one message and write the answer. `forward` raises no exception."""
        try:
            message = json.loads(line)
        except ValueError:
            self._write_error(None, PARSE_ERROR, "Parse error: the line is not JSON")
            return
        headers = {"Content-Type": "application/json", "Accept": _ACCEPT}
        if self._protocol_version is not None:
            headers[PROTOCOL_HEADER] = self._protocol_version
        try:
            response = await self._client.post(self.url, content=line, headers=headers)
        except httpx.HTTPError as exc:
            self._fail(message, f"the request to {self.url} failed: {type(exc).__name__}: {exc}")
            return
        if response.status_code in (202, 204):
            return
        media_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
        if response.is_success and media_type == "text/event-stream":
            for data in _event_data(response.text):
                self._emit(message, data.encode())
            return
        if response.is_success and media_type == "application/json":
            self._emit(message, response.content)
            return
        self._fail(message, f"HTTP {response.status_code} from {self.url}: {_detail(response)}")

    def _emit(self, message: Any, data: bytes) -> None:
        """Write one answer as one line. A body the server wrote over more than
        one line is written compact."""
        text = data.strip()
        if not text:
            return
        if b"\n" in text or b"\r" in text:
            text = json.dumps(json.loads(text), ensure_ascii=False, separators=(",", ":")).encode()
        if isinstance(message, dict) and message.get("method") == "initialize":
            self._note_version(text)
        self._write(text + b"\n")

    def _note_version(self, text: bytes) -> None:
        try:
            answer = json.loads(text)
        except ValueError:
            return
        result = answer.get("result") if isinstance(answer, dict) else None
        version = result.get("protocolVersion") if isinstance(result, dict) else None
        if isinstance(version, str):
            self._protocol_version = version

    def _fail(self, message: Any, text: str) -> None:
        """Answer a request with a JSON-RPC error. The error of a notification
        or a batch goes to stderr only."""
        print(f"hst mcp --remote: {text}", file=sys.stderr, flush=True)
        if isinstance(message, dict) and "method" in message and "id" in message:
            self._write_error(message["id"], TRANSPORT_ERROR, text)

    def _write_error(self, request_id: Any, code: int, text: str) -> None:
        error = {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": text}}
        self._write(json.dumps(error, separators=(",", ":")).encode() + b"\n")


def _event_data(text: str) -> list[str]:
    """The data of each server-sent event in `text` that has data."""
    events: list[str] = []
    data: list[str] = []
    for line in [*text.splitlines(), ""]:
        if line == "":
            if data and "".join(data).strip():
                events.append("\n".join(data))
            data = []
        elif line.startswith("data:"):
            value = line[len("data:") :]
            data.append(value[1:] if value.startswith(" ") else value)
    return events


def _detail(response: httpx.Response) -> str:
    """The server's reason for an error answer, cut at 500 characters."""
    try:
        body = response.json()
    except ValueError:
        return response.text.strip()[:500] or response.reason_phrase
    if isinstance(body, dict):
        if isinstance(body.get("error"), str):
            return body["error"][:500]
        error = body.get("error")
        if isinstance(error, dict) and isinstance(error.get("message"), str):
            return error["message"][:500]
    return response.text.strip()[:500]


async def relay(
    url: str,
    token: str,
    stdin: BinaryIO,
    stdout: BinaryIO,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    """Relay every line of `stdin` until it ends, then wait for the answers.

    Each message is posted when it is read. Answers are written in the order
    they arrive.
    """

    def write(data: bytes) -> None:
        stdout.write(data)
        stdout.flush()

    bridge = Bridge(url, token, write, transport=transport)
    pending: set[asyncio.Task[None]] = set()
    try:
        while True:
            line = await asyncio.to_thread(stdin.readline)
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            task = asyncio.create_task(bridge.forward(line))
            pending.add(task)
            task.add_done_callback(pending.discard)
        if pending:
            await asyncio.gather(*pending)
    finally:
        await bridge.aclose()


def main(url: str) -> int:
    """Run the bridge on this process's stdin and stdout. Returns the exit code."""
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        print(
            f"hst mcp --remote: {TOKEN_ENV} is not set; create a personal access token under "
            "Settings, Access tokens and set it in the environment of the MCP client",
            file=sys.stderr,
        )
        return 2
    try:
        check_url(url)
    except BridgeError as exc:
        print(f"hst mcp --remote: {exc}", file=sys.stderr)
        return 2
    asyncio.run(relay(url, token, sys.stdin.buffer, sys.stdout.buffer))
    return 0
