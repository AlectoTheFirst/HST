"""The cost bounds of a Business Application parse: linear issue positions, the
issue cap, the thread of the parse and the parse slots of the process."""

from __future__ import annotations

import asyncio
import threading
import time

import pytest
import yaml
from pydantic import ValidationError

from hst.applications import validation, yaml_format
from hst.applications.models import NEW_REVISION, BusinessApplicationDefinition
from hst.applications.yaml_format import ApplicationFormatError, parse_application_source


def _unknown_keys(count: int) -> str:
    return "".join(f"k{index}: 1\n" for index in range(count))


def _schema_error_paths(text: str) -> list[str]:
    with pytest.raises(ValidationError) as caught:
        BusinessApplicationDefinition.model_validate(yaml.safe_load(text), context={NEW_REVISION: True})
    return [".".join(str(part) for part in error["loc"]) for error in caught.value.errors()]


def test_the_issues_of_a_document_stop_at_the_cap_and_keep_the_count():
    text = _unknown_keys(500)
    paths = _schema_error_paths(text)

    with pytest.raises(ApplicationFormatError) as caught:
        parse_application_source(text)

    issues = caught.value.errors
    assert len(issues) == 101
    assert [issue.path for issue in issues[:-1]] == paths[:100]
    assert next(issue for issue in issues if issue.path == "k0").line == 1
    assert issues[-1].path == "$"
    assert (
        issues[-1].message == f"the document has {len(paths)} schema errors and the list holds the first 100"
    )
    assert (issues[-1].line, issues[-1].column) == (None, None)
    assert str(caught.value).count("; ") == 100


def test_a_document_of_20000_unknown_keys_costs_a_small_multiple_of_its_yaml_scan():
    text = _unknown_keys(20000)
    started = time.perf_counter()
    yaml.compose(text, Loader=yaml.SafeLoader)
    scan = time.perf_counter() - started

    started = time.perf_counter()
    with pytest.raises(ApplicationFormatError):
        parse_application_source(text)
    parse = time.perf_counter() - started

    assert parse < 8 * scan, f"the parse took {parse:.2f} s and the YAML scan {scan:.2f} s"


def _patch_parse(monkeypatch, parse) -> None:
    monkeypatch.setattr(yaml_format, "parse_application_source", parse)
    monkeypatch.setattr(validation, "parse_application_source", parse, raising=False)


async def _no_resolve(definition, revision):
    raise AssertionError("the resolver is not reached")


async def test_validate_application_parses_in_a_worker_thread(monkeypatch):
    threads: list[int] = []

    def slow_parse(text, *, partial=False):
        threads.append(threading.get_ident())
        time.sleep(0.5)
        raise ApplicationFormatError("refused")

    _patch_parse(monkeypatch, slow_parse)
    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(0.02)
            ticks += 1

    task = asyncio.create_task(ticker())
    try:
        result = await validation.validate_application(
            None, "id: x\n", mode="replace", snapshot={}, resolve=_no_resolve
        )
    finally:
        task.cancel()

    assert result["errors"][0]["message"] == "refused"
    assert threads and threads[0] != threading.get_ident()
    assert ticks >= 5


class _BlockedParses:
    """A parse that waits for `release` and counts the parses that run at once."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.running = 0
        self.peak = 0
        self.lock = threading.Lock()

    def __call__(self, text, *, partial=False):
        with self.lock:
            self.running += 1
            self.peak = max(self.peak, self.running)
        try:
            self.release.wait(10)
        finally:
            with self.lock:
                self.running -= 1
        raise ApplicationFormatError("done")


async def _until(condition) -> None:
    for _ in range(500):
        if condition():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("the condition did not hold within 5 s")


async def test_parses_beyond_the_slots_wait_and_are_refused_after_the_wait(monkeypatch):
    parses = _BlockedParses()
    _patch_parse(monkeypatch, parses)
    monkeypatch.setattr(yaml_format, "PARSE_WAIT_S", 0.2)
    slots = yaml_format.MAX_CONCURRENT_PARSES

    held = [asyncio.create_task(yaml_format.parse_application_bounded("a: 1\n")) for _ in range(slots)]
    await _until(lambda: parses.running == slots)
    with pytest.raises(yaml_format.ParseBusy):
        await yaml_format.parse_application_bounded("a: 1\n")

    waiting = asyncio.create_task(yaml_format.parse_application_bounded("a: 1\n"))
    await asyncio.sleep(0.05)
    parses.release.set()
    for task in [*held, waiting]:
        with pytest.raises(ApplicationFormatError):
            await task
    assert parses.peak == slots


async def test_a_full_wait_queue_refuses_at_once(monkeypatch):
    parses = _BlockedParses()
    _patch_parse(monkeypatch, parses)
    slots = yaml_format.MAX_CONCURRENT_PARSES
    queue = yaml_format.MAX_WAITING_PARSES

    tasks = [
        asyncio.create_task(yaml_format.parse_application_bounded("a: 1\n")) for _ in range(slots + queue)
    ]
    await _until(lambda: parses.running == slots)
    await asyncio.sleep(0.05)
    started = time.monotonic()
    with pytest.raises(yaml_format.ParseBusy):
        await yaml_format.parse_application_bounded("a: 1\n")
    assert time.monotonic() - started < 1.0

    parses.release.set()
    for task in tasks:
        with pytest.raises(ApplicationFormatError):
            await task
    assert parses.peak == slots


async def test_a_cancelled_parse_holds_its_slot_until_the_thread_ends(monkeypatch):
    parses = _BlockedParses()
    _patch_parse(monkeypatch, parses)
    monkeypatch.setattr(yaml_format, "PARSE_WAIT_S", 0.1)
    slots = yaml_format.MAX_CONCURRENT_PARSES

    held = [asyncio.create_task(yaml_format.parse_application_bounded("a: 1\n")) for _ in range(slots)]
    await _until(lambda: parses.running == slots)
    for task in held:
        task.cancel()
    await asyncio.gather(*held, return_exceptions=True)

    with pytest.raises(yaml_format.ParseBusy):
        await yaml_format.parse_application_bounded("a: 1\n")
    parses.release.set()
    await _until(lambda: parses.running == 0)
    with pytest.raises(ApplicationFormatError):
        await yaml_format.parse_application_bounded("a: 1\n")


async def test_a_draft_whose_parse_gets_no_slot_has_a_failed_validation(monkeypatch):
    from hst.app.routes import application_generator
    from hst.applications.generator import Draft

    slots = threading.BoundedSemaphore(1)
    slots.acquire()
    monkeypatch.setattr(yaml_format, "_PARSE_SLOTS", slots)
    monkeypatch.setattr(yaml_format, "PARSE_WAIT_S", 0.0)
    reference = {"snapshot": "4000"}

    result = await application_generator._validate(
        None, None, Draft(yaml="id: x\n", definition=None), reference, can_commit=False
    )

    assert result["errors"] == [
        {"path": "$", "message": "Business Application parsing is busy", "line": None, "column": None}
    ]
    assert result["blocking"] == ["$"]
