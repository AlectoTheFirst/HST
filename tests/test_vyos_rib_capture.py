"""Each VyOS RIB answer is read as one debug-capture step (collectors/vyos.py
`_read_rib_answer`)."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

import pytest
from tests.support.synthetic_payloads import make_settings
from tests.support.synthetic_vyos import answers, base_raw, make_collector, new_raw

from hst.app.crypto import dek, generate_key
from hst.collectors import vyos
from hst.core import Settings, debug_capture, rawstore
from hst.core.model import Batch, SectionOutcome

STEP = "vyos.rib_answer"
RIB_LINE = "continuing without its routes"
RIB_STEPS = ["routes", "routes_table_100", "routes6", "routes6_table_100"]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    settings = make_settings(tmp_path, hst_secret_key=generate_key())
    debug_capture.set_switch(settings, "edge", until_ms=int(time.time() * 1000) + 60_000, by="test")
    return settings


def _captured(settings: Settings, raw: dict[str, Any], run_id: str) -> tuple[list[dict[str, Any]], Batch]:
    """The capture records of one `normalize` of `raw`, and its batch."""
    collector = make_collector(settings)
    with debug_capture.capture(settings, source="edge", host="r1", run_id=run_id, collector="vyos", raw=raw):
        batch = collector.normalize(raw)
    collector.release_payload()
    path = rawstore.sibling(
        rawstore.raw_path_of(settings.raw_dir, "edge", "r1", run_id), rawstore.DEBUG_SUFFIX
    )
    records, unreadable = debug_capture.read_records(path, dek(settings))
    assert unreadable == 0
    return records, batch


def _begin_commands(records: list[dict[str, Any]]) -> dict[str, Any]:
    (begin,) = [r for r in records if r["event"] == "begin"]
    commands: dict[str, Any] = begin["payload"]["commands"]
    return commands


def _steps(records: list[dict[str, Any]], event: str) -> list[dict[str, Any]]:
    return [r for r in records if r["event"] == event and r.get("step") == STEP]


def _errors(records: list[dict[str, Any]]) -> list[str]:
    return [r["error"] for r in _steps(records, "end") if r.get("error")]


def _rib_lines(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in records if r["event"] == "log" and RIB_LINE in r["message"]]


def test_an_answer_that_is_not_json_ends_its_step_with_the_outcome_and_is_logged(settings):
    raw = new_raw(answers("fixture/malformed_rib"))

    records, batch = _captured(settings, raw, "1790000000001-abcdef12")

    assert _begin_commands(records)["routes6"]["outcome"] == {"status": "ok"}
    assert [r["command"] for r in _steps(records, "start")] == RIB_STEPS
    detail = batch.sections["routes6"].detail
    assert batch.sections["routes6"].status == "malformed"
    assert _errors(records) == [f"routes6: malformed: {detail}"]
    (line,) = _rib_lines(records)
    assert line["level"] == "WARNING"
    assert line["logger"] == "hst.collectors.vyos"
    assert line["message"] == f"vyos: routes6: malformed: {detail}; {RIB_LINE}"
    assert "exception" not in line

    plain, _ = _captured(settings, new_raw(answers("fixture/plain")), "1790000000002-abcdef12")
    warnings = debug_capture.summarize(records)[0]["warnings"]
    assert warnings == debug_capture.summarize(plain)[0]["warnings"] + 1


def test_a_policy_table_answer_is_named_by_its_outcome_key(settings):
    raw = new_raw(answers("fixture/malformed_table"))

    records, batch = _captured(settings, raw, "1790000000003-abcdef12")

    assert [r["command"] for r in _steps(records, "start")] == RIB_STEPS
    (error,) = _errors(records)
    assert error.startswith("routes_table_100: malformed: ")
    assert batch.sections["routes_table_100"].status == "malformed"
    (line,) = _rib_lines(records)
    assert line["message"].startswith("vyos: routes_table_100: malformed: ")


def test_answers_that_read_record_their_size_and_prefixes_and_log_nothing(settings):
    raw = new_raw(answers("fixture/plain"))

    records, batch = _captured(settings, raw, "1790000000004-abcdef12")

    starts, ends = _steps(records, "start"), _steps(records, "end")
    assert [r["command"] for r in starts] == RIB_STEPS
    texts = [raw["routes"], raw["routes_tables"]["100"], raw["routes6"], raw["routes6_tables"]["100"]]
    assert [r["chars"] for r in starts] == [len(text) for text in texts]
    assert [r["prefixes"] for r in ends] == [batch.sections[name].row_count for name in RIB_STEPS]
    assert sum(r["prefixes"] for r in ends) > 0
    assert _errors(records) == []
    assert _rib_lines(records) == []


def test_a_payload_whose_fetch_decoded_the_answers_has_the_steps_and_no_error(settings):
    raw = base_raw(answers("fixture/malformed_rib"))

    records, batch = _captured(settings, raw, "1790000000005-abcdef12")

    assert _begin_commands(records)["routes6"]["outcome"]["status"] == "malformed"
    starts = _steps(records, "start")
    assert [r["command"] for r in starts] == RIB_STEPS
    assert [r["chars"] for r in starts] == [None] * len(RIB_STEPS)
    assert _errors(records) == []
    assert _rib_lines(records) == []
    assert batch.sections["routes6"].status == "malformed"


def test_outside_a_capture_the_answer_is_logged_once_with_strings_only(tmp_path, caplog):
    raw = new_raw(answers("fixture/malformed_rib"))
    collector = make_collector(make_settings(tmp_path))

    with caplog.at_level(logging.WARNING, logger="hst.collectors.vyos"):
        batch = collector.normalize(raw)
    collector.release_payload()

    lines = [r for r in caplog.records if r.name == "hst.collectors.vyos" and RIB_LINE in r.getMessage()]
    assert len(lines) == 1
    assert lines[0].getMessage().startswith("vyos: routes6: malformed: ")
    assert lines[0].levelno == logging.WARNING
    assert lines[0].exc_info is None
    assert isinstance(lines[0].args, tuple)
    assert all(isinstance(arg, str) for arg in lines[0].args)
    assert batch.sections == vyos.section_outcomes(raw)


def test_a_str_rib_value_is_read_as_text_whichever_fetch_sealed_the_payload(tmp_path):
    collector = make_collector(make_settings(tmp_path))
    raw = base_raw(answers("fixture/plain"))
    assert raw[vyos.RAW_OUTCOMES_KEY]["routes"] == {"status": "ok"}

    raw["routes"] = "abc"
    sections = collector.normalize(raw).sections
    collector.release_payload()
    assert sections["routes"] == SectionOutcome(
        status="malformed", detail="Expecting value: line 1 column 1 (char 0)"
    )

    raw["routes"] = '{"default": {}}'
    sections = collector.normalize(raw).sections
    collector.release_payload()
    assert sections["routes"].status == "empty"
