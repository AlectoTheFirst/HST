"""An IOS-XE load holds at its peak at most 30% of the recorded peak (`base_peak_bytes` in
`tests/support/stream_golden.json`)."""

from __future__ import annotations

import gc
import tracemalloc
from pathlib import Path
from typing import Any

from tests.support.synthetic_payloads import (
    COLLECTOR_SOURCE,
    RUN_ID,
    SNAPSHOT_TS,
    case_payload,
    load_golden,
    make_collector,
    make_settings,
)
from tests.test_collector_execute import FakeSession

from hst.collectors.base import load_payload
from hst.collectors.cli_collector import CiscoCliCollector
from hst.core.model import RunManifest

CASE = "iosxe/medium/plain"
ROW_GROUP_ROWS = 8192

# The peak budget: the retained `rib` list per route, three row groups of
# side rows in the writer (the rows read, their stamped copies and the arrow
# batch), and a fixed allowance for everything else a load builds. Decimal
# units, the smaller reading of each.
RIB_ROW_BYTES = 600
WRITER_ROW_BYTES = 2_200
FIXED_BYTES = 16_000_000

# What a load may leave traced once it returns.
RESIDUE_BYTES = 5_000_000


def _collector(data_dir: Path) -> CiscoCliCollector:
    return make_collector("iosxe", make_settings(data_dir, sidestore_row_group_rows=ROW_GROUP_ROWS))


def _load(collector: CiscoCliCollector, payload: dict[str, Any]) -> RunManifest:
    return load_payload(
        collector,
        FakeSession(),
        payload,
        collection_ts=SNAPSHOT_TS,
        run_id=RUN_ID,
        ts_ms=SNAPSHOT_TS,
        source_name=COLLECTOR_SOURCE,
    )


def test_a_load_peaks_at_its_row_groups_and_leaves_nothing_behind(tmp_path: Path) -> None:
    golden = load_golden()["cases"][CASE]
    routes, paths = golden["parquet"]["rib"][0], golden["parquet"]["bgp_session_routes"][0]
    # A load of the small fixture first: the imports, template indexes and
    # compiled templates a first load creates live for the process, and are
    # not this load's.
    _load(_collector(tmp_path / "warm"), case_payload("iosxe/fixture/plain"))
    payload = case_payload(CASE)
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
    budget = RIB_ROW_BYTES * routes + 3 * ROW_GROUP_ROWS * WRITER_ROW_BYTES + FIXED_BYTES
    assert peak <= budget, f"peak {peak:,} B above the payload, budget {budget:,} B"
    assert peak <= 0.3 * golden["base_peak_bytes"], (
        f"peak {peak:,} B is {peak / golden['base_peak_bytes']:.0%} of the recorded "
        f"{golden['base_peak_bytes']:,} B"
    )
    # the collector is still referenced here
    assert current < RESIDUE_BYTES, f"{current:,} B still traced after the load returned"
