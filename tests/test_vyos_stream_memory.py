"""The memory a VyOS load takes: one answer's tree at a time, and row groups."""

from __future__ import annotations

import gc
import tracemalloc
import weakref
from pathlib import Path
from typing import Any

from tests.support.synthetic_payloads import COLLECTOR_SOURCE, RUN_ID, SNAPSHOT_TS, make_settings
from tests.support.synthetic_vyos import (
    MEMORY_ROW_GROUP_ROWS,
    answers,
    load_golden,
    make_collector,
    new_raw,
)
from tests.test_collector_execute import FakeSession

from hst.collectors.base import load_payload
from hst.collectors.vyos import VyosCollector
from hst.core.model import RunManifest

CASE = "medium/plain"

# The share of the recorded peak (`base_peak_bytes`) a load of the same answers may take.
BASE_SHARE = 0.35

# What a load may leave traced once it returns.
RESIDUE_BYTES = 5_000_000


class _Payload(dict[str, Any]):
    """A payload that can be weakly referenced, to see whether anything keeps it."""


def _collector(data_dir: Path) -> VyosCollector:
    return make_collector(make_settings(data_dir, sidestore_row_group_rows=MEMORY_ROW_GROUP_ROWS))


def _load(collector: VyosCollector, payload: dict[str, Any]) -> RunManifest:
    return load_payload(
        collector,
        FakeSession(),
        payload,
        collection_ts=SNAPSHOT_TS,
        run_id=RUN_ID,
        ts_ms=SNAPSHOT_TS,
        source_name=COLLECTOR_SOURCE,
    )


def test_a_load_peaks_under_the_base_share_and_leaves_nothing_behind(tmp_path: Path) -> None:
    golden = load_golden()["cases"][CASE]
    routes, paths = golden["parquet"]["rib"][0], golden["parquet"]["bgp_session_routes"][0]
    # A load of the fixture first: the imports and caches a first load
    # creates live for the process, and are not this load's.
    _load(_collector(tmp_path / "warm"), new_raw(answers("fixture/plain")))
    payload = _Payload(new_raw(answers(CASE)))
    held = weakref.ref(payload)
    collector = _collector(tmp_path / "data")
    gc.collect()
    tracemalloc.start()
    try:
        manifest = _load(collector, payload)
        current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    # the load did the whole job, so the figures are those of a full load
    written = {table: (outcome.status, outcome.row_count) for table, outcome in manifest.tables.items()}
    assert written["rib"] == ("complete", routes)
    assert written["bgp_session_routes"] == ("complete", paths)
    base_peak = golden["base_peak_bytes"]
    assert peak <= BASE_SHARE * base_peak, (
        f"peak {peak:,} B is {peak / base_peak:.0%} of the recorded {base_peak:,} B"
    )
    # the collector is still referenced here, so a read it kept is counted
    assert current < RESIDUE_BYTES, f"{current:,} B still traced after the load returned"
    assert collector._payload_read is None
    del payload
    gc.collect()
    assert held() is None, "something the load left behind still holds the payload"
