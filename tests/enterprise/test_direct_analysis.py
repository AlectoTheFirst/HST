"""Public native evaluations share bounded process ownership with queued work."""

from __future__ import annotations

import multiprocessing
import os
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from hst.assessment.direct import run_isolated
from hst.assessment.jobs import PROCESS_CAPACITY


def _settings(timeout: float = 10) -> SimpleNamespace:
    return SimpleNamespace(
        analysis_enabled=True,
        analysis_memory_mb=512,
        analysis_timeout_s=timeout,
        analysis_engine="symbolic-v2",
        hst_build_revision="test",
    )


def _answer(_settings, inputs, *, progress, cancelled):
    progress({"phase": "test"})
    return {"pid": os.getpid(), "question": inputs["question"], "cancelled": cancelled()}


def _wait(_settings, _inputs, *, progress, cancelled):
    while not cancelled():
        time.sleep(0.01)
    return {}


def _fail(_settings, _inputs, *, progress, cancelled):
    raise ValueError("private-connection-secret")


def test_result_crosses_process_boundary_and_releases_capacity():
    result = run_isolated(_settings(), {"question": "synthetic"}, execute=_answer)
    assert result == {"pid": result["pid"], "question": "synthetic", "cancelled": False}
    assert result["pid"] != os.getpid()
    assert PROCESS_CAPACITY.acquire(blocking=False)
    PROCESS_CAPACITY.release()


def test_busy_capacity_does_not_spawn_another_analysis():
    assert PROCESS_CAPACITY.acquire(blocking=False)
    try:
        with pytest.raises(HTTPException, match="capacity is busy"):
            run_isolated(_settings(), {}, execute=_answer)
    finally:
        PROCESS_CAPACITY.release()


def test_deadline_terminates_child_and_releases_capacity():
    before = set(multiprocessing.active_children())
    with pytest.raises(HTTPException, match="time limit"):
        run_isolated(_settings(0.1), {}, execute=_wait)
    # `_wait` ends only on a cancel, so a child that the deadline did not end is alive here
    assert set(multiprocessing.active_children()) <= before
    assert PROCESS_CAPACITY.acquire(blocking=False)
    PROCESS_CAPACITY.release()


def test_execution_errors_do_not_expose_driver_messages():
    with pytest.raises(HTTPException) as caught:
        run_isolated(_settings(), {}, execute=_fail)
    assert caught.value.status_code == 503
    assert "private-connection-secret" not in str(caught.value.detail)
