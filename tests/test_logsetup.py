"""configure_logging: level and format selection from Settings or environment,
the stderr-only handler, and the force=True idempotence that stops a second
call from stacking a duplicate handler.
"""

import json
import logging
import sys

import pytest

from hst.core.config import Settings
from hst.core.logsetup import JsonFormatter, configure_logging


@pytest.fixture(autouse=True)
def _restore_root_logger():
    """configure_logging replaces the root logger's handlers; put back what
    the test session had so caplog and later tests are unaffected."""
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    yield
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


def _settings(**kwargs) -> Settings:
    return Settings(_env_file=None, **kwargs)


def test_default_is_one_info_text_handler_on_stderr():
    configure_logging(_settings())
    root = logging.getLogger()
    assert root.level == logging.INFO
    assert len(root.handlers) == 1
    handler = root.handlers[0]
    assert isinstance(handler, logging.StreamHandler)
    assert handler.stream is sys.stderr
    assert not isinstance(handler.formatter, JsonFormatter)
    record = logging.LogRecord("some.module", logging.WARNING, __file__, 1, "hello", None, None)
    assert handler.formatter.format(record).endswith("WARNING some.module: hello")


def test_level_is_taken_from_settings_case_insensitively():
    configure_logging(_settings(hst_log_level="debug"))
    assert logging.getLogger().level == logging.DEBUG


def test_json_format_selects_the_json_formatter():
    configure_logging(_settings(hst_log_format="json"))
    handler = logging.getLogger().handlers[0]
    assert isinstance(handler.formatter, JsonFormatter)


def test_no_argument_call_reads_the_environment(monkeypatch):
    monkeypatch.setenv("HST_LOG_LEVEL", "warning")
    monkeypatch.setenv("HST_LOG_FORMAT", "json")
    configure_logging()
    root = logging.getLogger()
    assert root.level == logging.WARNING
    assert isinstance(root.handlers[0].formatter, JsonFormatter)


def test_a_second_call_leaves_one_handler():
    configure_logging(_settings())
    configure_logging(_settings())
    assert len(logging.getLogger().handlers) == 1


def test_json_formatter_emits_one_object_per_line():
    record = logging.LogRecord("hst.demo", logging.INFO, __file__, 1, "imported %d rows", (7,), None)
    line = JsonFormatter().format(record)
    payload = json.loads(line)
    assert "\n" not in line
    assert payload["level"] == "INFO"
    assert payload["logger"] == "hst.demo"
    assert payload["message"] == "imported 7 rows"
    assert "timestamp" in payload
    assert "exc_info" not in payload


def test_json_formatter_carries_the_exception_text():
    try:
        raise ValueError("boom")
    except ValueError:
        record = logging.LogRecord("hst.demo", logging.ERROR, __file__, 1, "failed", None, sys.exc_info())
    payload = json.loads(JsonFormatter().format(record))
    assert "ValueError: boom" in payload["exc_info"]


def test_json_formatter_carries_the_allowlisted_extra_fields_only():
    record = logging.makeLogRecord(
        {
            "name": "hst.ai",
            "levelno": logging.INFO,
            "levelname": "INFO",
            "msg": "agent tool %s finished",
            "args": ("trace_path",),
            "tool": "trace_path",
            "latency_ms": 42,
            "tokens_in": 1200,
            "model_served": "claude-opus-5",
            "snapshot": "3000",
            "question": "not a log field",
        }
    )
    payload = json.loads(JsonFormatter().format(record))
    assert payload["message"] == "agent tool trace_path finished"
    assert (payload["tool"], payload["latency_ms"], payload["tokens_in"]) == ("trace_path", 42, 1200)
    assert (payload["model_served"], payload["snapshot"]) == ("claude-opus-5", "3000")
    assert "question" not in payload


def test_extra_fields_reach_the_json_line_through_a_logger(caplog):
    caplog.set_level(logging.INFO, logger="hst.ai")
    logging.getLogger("hst.ai").info("ask failed", extra={"provider": "bedrock", "error_class": "APIError"})
    payload = json.loads(JsonFormatter().format(caplog.records[-1]))
    assert (payload["provider"], payload["error_class"]) == ("bedrock", "APIError")
    assert "model_served" not in payload


def test_the_text_format_ignores_the_extra_fields():
    configure_logging(_settings())
    handler = logging.getLogger().handlers[0]
    record = logging.makeLogRecord(
        {"name": "hst.ai", "levelno": logging.INFO, "levelname": "INFO", "msg": "hello", "tool": "x"}
    )
    assert handler.formatter.format(record).endswith("INFO hst.ai: hello")
