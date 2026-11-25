"""The request body limit of the HTTP API."""

from __future__ import annotations

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MIB = 1024 * 1024


def _declared_length(scope: Scope) -> int | None:
    """The `Content-Length` of the request, None when it is absent or not a number."""
    value = Headers(scope=scope).get("content-length", "")
    if not (value.isascii() and value.isdigit()):
        return None
    try:
        return int(value)
    except ValueError:
        # `int` refuses a string of more than `sys.get_int_max_str_digits()` digits.
        return None


class BodyLimit:
    """Answers 413 to a request whose body is larger than `max_bytes`.

    A request whose `Content-Length` is above the limit is refused before its
    body is read. The bytes of every other body are counted as the app reads
    them. At the first chunk that takes the count above the limit, the app gets
    `http.disconnect` and the caller gets the 413.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    def _refusal(self) -> JSONResponse:
        # `Connection: close` makes uvicorn close the connection and read no more
        # of the body.
        return JSONResponse(
            {"error": f"the request body exceeds {self.max_bytes // MIB} MiB"},
            status_code=413,
            headers={"Connection": "close"},
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = _declared_length(scope)
        if declared is not None and declared > self.max_bytes:
            await self._refusal()(scope, receive, send)
            return

        seen = 0
        refused = False
        started = False

        async def counted_receive() -> Message:
            nonlocal seen, refused
            if refused:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] != "http.request":
                return message
            seen += len(message.get("body", b""))
            if seen <= self.max_bytes:
                return message
            refused = True
            if not started:
                await self._refusal()(scope, receive, send)
            return {"type": "http.disconnect"}

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if refused:
                return
            started = True
            await send(message)

        try:
            await self.app(scope, counted_receive, guarded_send)
        except Exception:
            # The app fails on the `http.disconnect` that follows a refusal.
            if not refused:
                raise
