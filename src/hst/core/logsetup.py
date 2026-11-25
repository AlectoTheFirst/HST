"""Root logger setup, called once at process start by every CLI command and by
`hst serve` before uvicorn.run().
"""

from __future__ import annotations

import faulthandler
import io
import json
import logging
import signal
import sys
from typing import Any, TextIO

from .config import Settings

_TEXT_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

# The `extra=` keys of a record that the JSON line includes. The line has no
# other attribute of the record.
LOG_FIELDS = (
    "request_id",
    "user_id",
    "surface",
    "conversation_id",
    "message_id",
    "step_id",
    "tool",
    "tool_version",
    "provider",
    "model_requested",
    "model_served",
    "latency_ms",
    "tokens_in",
    "tokens_out",
    "outcome",
    "error_class",
    "snapshot",
    # a stable name for a record a reader filters on, e.g. "unifi.uplink_contradicted"
    "event",
)


class JsonFormatter(logging.Formatter):
    """One JSON object per line. The object has the timestamp, the level, the
    logger name, the message, the `LOG_FIELDS` keys of the record and the
    exception text of the record.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        fields = record.__dict__
        payload.update((key, fields[key]) for key in LOG_FIELDS if key in fields)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class _StderrHandler(logging.StreamHandler):
    """A handler that writes each record to the `sys.stderr` of that moment."""

    @property
    def stream(self) -> TextIO:
        return sys.stderr

    @stream.setter
    def stream(self, value: TextIO) -> None:
        """The setter ignores the stream that `StreamHandler` assigns."""


def configure_logging(settings: Settings | None = None) -> None:
    """Attach one stderr handler to the root logger. HST_LOG_LEVEL sets the level
    and HST_LOG_FORMAT sets the format.
    """
    settings = settings or Settings()
    handler = _StderrHandler()
    formatter: logging.Formatter = (
        JsonFormatter() if settings.hst_log_format == "json" else logging.Formatter(_TEXT_FORMAT)
    )
    handler.setFormatter(formatter)
    logging.basicConfig(level=settings.hst_log_level.upper(), handlers=[handler], force=True)
    # `kill -USR1 <pid>` writes the traceback of every thread to stderr.
    try:
        faulthandler.enable(file=sys.stderr, all_threads=True)
        if hasattr(faulthandler, "register") and hasattr(signal, "SIGUSR1"):
            faulthandler.register(signal.SIGUSR1, file=sys.stderr, all_threads=True)
    except (io.UnsupportedOperation, ValueError):
        # A stderr in a test runner can have no file descriptor.
        pass
