"""Failures persisted for the UI must also reach the process log."""

import logging
from unittest.mock import AsyncMock

from hst.app.runs_exec import DeviceOutcome, _record_outcomes


async def test_collection_failure_is_logged_and_persisted(caplog):
    store = AsyncMock()
    error = "TextFSMError: iosxe, command 'show vrf': Input Line: CCCC;"
    outcomes = [
        DeviceOutcome("routers", "r1", False, error=error),
        DeviceOutcome("routers", "r2", True),
    ]

    with caplog.at_level(logging.ERROR, logger="hst.app.runs_exec"):
        await _record_outcomes(store, outcomes)

    assert caplog.messages == [f"collection failed for routers/r1: {error}"]
    assert store.upsert_device_status.await_count == 2
    failed = store.upsert_device_status.await_args_list[0]
    assert failed.args == ("routers", "r1")
    assert failed.kwargs["ok"] is False
    assert failed.kwargs["error"] == error
