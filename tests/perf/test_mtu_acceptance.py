"""Opt-in MTU performance harness over the synthetic estate dataset.

The reader budgets are exactly ceil(N/256) batched reads for complete
evidence, a 40 ms warm median and an 8 MiB peak for 1,000 prebuilt subjects, no
per-hop query growth, 128 candidate combinations and MAX_STAGES crossings.
Timing numbers are recorded for the operator; only the budgets and
deterministic counts are asserted. Run with
HST_PERF=1 and optionally HST_MTU_PERF_RESULT=<path> to write the JSON.
"""

from __future__ import annotations

import json
import os
import statistics
import time
import tracemalloc
from math import ceil
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.test_mtu_budget import request, stage
from tests.test_mtu_contract import observation
from tests.test_mtu_end_to_end import ADDR, Estate, estate_observations
from tests.test_mtu_snapshot import row

from hst import path
from hst.core.mtu import MtuRequest
from hst.core.mtu_read import read_mtu
from hst.path.gates import _Trail
from hst.path.mtu import evaluate_stages
from hst.path.mtu_topology import MAX_STAGES, crossing, mtu_request, trace_scope

pytestmark = [
    pytest.mark.perf,
    pytest.mark.skipif(os.environ.get("HST_PERF") != "1", reason="HST_PERF not set"),
]

READER_WARM_BUDGET_MS = 40.0
READER_PEAK_BUDGET_BYTES = 8 * 1024 * 1024
BATCH = 256
RUNS = 10
SNAP = 42
MAX_SUBJECTS = 4096


@pytest.fixture(scope="module")
def results():
    data: dict = {}
    yield data
    target = os.environ.get("HST_MTU_PERF_RESULT")
    if target:
        Path(target).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def prebuilt_observations(count):
    return [observation(subject_uid=f"subject:{i}") for i in range(count)]


def prebuilt(count):
    """Subject -> row mapping in the contract's synthetic baseline shape."""
    return {o.subject_uid: row(o) for o in prebuilt_observations(count)}


class ReadCounter:
    def __init__(self, rows):
        self.rows = rows
        self.batches: list[int] = []

    def read(self, session, query, **params):
        if "HAS_MTU" not in query:
            return []
        self.batches.append(len(params["subject_uids"]))
        return [self.rows[s] for s in params["subject_uids"] if s in self.rows]


def timed(fn, runs=RUNS):
    cold = time.perf_counter()
    fn()
    cold_ms = (time.perf_counter() - cold) * 1000
    warm = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        warm.append((time.perf_counter() - start) * 1000)
    return {"cold_ms": round(cold_ms, 3), "warm_median_ms": round(statistics.median(warm), 3)}


def peak_bytes(fn):
    tracemalloc.start()
    try:
        fn()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("count", [1000, MAX_SUBJECTS])
def test_reader_batches_are_exact_and_bounded(monkeypatch, results, count):
    rows = prebuilt(count)
    counter = ReadCounter(rows)
    monkeypatch.setattr(path, "_read", counter.read)
    subjects = list(rows)
    session = SimpleNamespace(cts=SNAP)

    def read():
        return read_mtu(session, subjects)

    first = read()
    assert first.query_count == ceil(count / BATCH)
    assert len(first.by_subject) == count
    assert not first.truncated and first.gaps == []
    assert max(counter.batches) <= BATCH and sum(counter.batches) == count
    timing = timed(read)
    peak = peak_bytes(read)
    entry = {
        "subjects": count,
        "reads": first.query_count,
        "batch_sizes": sorted(set(counter.batches[: first.query_count])),
        "tracemalloc_peak_bytes": peak,
        **timing,
    }
    results[f"reader_{count}"] = entry
    if count == 1000:
        assert peak <= READER_PEAK_BUDGET_BYTES, entry
        assert timing["warm_median_ms"] <= READER_WARM_BUDGET_MS, entry


def test_reader_caps_subjects_and_observations(monkeypatch, results):
    rows = prebuilt(MAX_SUBJECTS + 1)
    counter = ReadCounter(rows)
    monkeypatch.setattr(path, "_read", counter.read)
    session = SimpleNamespace(cts=SNAP)
    capped = read_mtu(session, list(rows))
    assert capped.truncated and capped.query_count == MAX_SUBJECTS // BATCH
    assert len(capped.by_subject) == MAX_SUBJECTS
    assert "MTU_PATH_COVERAGE_INCOMPLETE" in capped.gaps
    counter.batches.clear()
    small = read_mtu(session, list(rows)[:1000], max_observations=5)
    assert small.truncated and sum(map(len, small.by_subject.values())) == 5
    assert counter.batches == [BATCH]
    results["reader_caps"] = {
        "subjects_offered": MAX_SUBJECTS + 1,
        "subjects_read": MAX_SUBJECTS,
        "reads_at_cap": capped.query_count,
        "reads_with_observation_cap_5": len(counter.batches),
    }


def test_observation_json_size(results):
    synthetic = [len(json.dumps(o.graph_props(), sort_keys=True)) for o in prebuilt_observations(1000)]
    stored = [len(json.dumps(r["observation"], sort_keys=True)) for r in prebuilt(1000).values()]
    estate = [len(json.dumps(o.graph_props(), sort_keys=True)) for o in estate_observations()]
    results["observation_json_bytes"] = {
        "synthetic_props_mean": round(statistics.mean(synthetic), 2),
        "synthetic_stored_row_mean": round(statistics.mean(stored), 2),
        "estate_count": len(estate),
        "estate_mean": round(statistics.mean(estate), 2),
        "estate_max": max(estate),
    }
    assert results["observation_json_bytes"]["estate_max"] <= 4096


def test_trace_with_inventory_versus_off(monkeypatch, results):
    estate = Estate()
    monkeypatch.setattr(path, "_read", estate.read)
    monkeypatch.setattr(path, "_read_one", estate.read_one)
    off = timed(lambda: estate.trace(mtu={"mode": "off"}))
    estate.evidence_reads.clear()
    estate.topology_reads.clear()
    inventory = timed(lambda: estate.trace(mtu={"mode": "inventory"}))
    traces = RUNS + 1
    assert len(estate.evidence_reads) == traces
    assert len(estate.topology_reads) == traces
    result = estate.trace(mtu={"mode": "inventory"})["mtu"]
    stages = len(result["stages"])
    assert stages > 1
    subjects = len(estate.evidence_reads[-1]["subject_uids"])
    assert subjects <= BATCH
    deficit = timed(lambda: estate.trace(ADDR["vip"], mtu={"mode": "unfragmented", "ip_packet_bytes": 1501}))
    results["trace_estate"] = {
        "hops": len(estate.trace(mtu={"mode": "off"})["hops"]),
        "stages": stages,
        "candidates": len(result["candidates"]),
        "observations": len(result["observations"]),
        "evidence_reads_per_trace": 1,
        "topology_reads_per_trace": 1,
        "subjects_per_trace": subjects,
        "off": off,
        "inventory": inventory,
        "unfragmented_via_proxy": deficit,
    }


def test_thousand_crossings_do_not_grow_queries_per_hop(monkeypatch, results):
    rows = prebuilt(1000)
    queries: list[tuple[str, int]] = []

    def read(session, query, **params):
        kind = "evidence" if "HAS_MTU" in query else "topology"
        queries.append((kind, len(params["subject_uids"])))
        if kind == "evidence":
            return [rows[s] for s in params["subject_uids"] if s in rows]
        return []

    monkeypatch.setattr(path, "_read", read)

    @trace_scope()
    def walk(session):
        trail = _Trail()
        for subject in rows:
            crossing(trail, subject, enforcement="l3")
        return {}

    def run():
        with mtu_request(MtuRequest(mode="inventory"), 4):
            return walk(SimpleNamespace(cts=SNAP))["mtu"]

    value = run()
    per_run = len(queries)
    assert [k for k, _ in queries].count("evidence") == ceil(1000 / BATCH)
    assert [k for k, _ in queries].count("topology") == ceil(1000 / BATCH)
    assert all(n <= BATCH for _, n in queries)
    assert len(value["stages"]) == 1000 and value["known_ceiling_bytes"] == 1500
    timing = timed(run)
    assert len(queries) == per_run * (RUNS + 2)
    results["thousand_crossings"] = {
        "stages": len(value["stages"]),
        "queries_per_trace": per_run,
        "peak_bytes": peak_bytes(run),
        **timing,
    }


def test_candidate_and_stage_truncation_budgets(monkeypatch, results):
    bundles = [
        stage(
            1500,
            stage_id=f"{bundle}-{member}",
            candidate_set_id=f"lag:{bundle}",
            candidate_id=f"member:{member}",
            selection="eligible",
        )
        for bundle in range(8)
        for member in range(2)
    ]

    def expand():
        return evaluate_stages(bundles, request(1400))

    result = expand()
    assert len(result.candidates) == 128
    assert result.coverage.truncated and result.guaranteed_bytes is None
    exact = [
        stage(
            1500,
            stage_id=f"{b}-{m}",
            candidate_set_id=f"lag:{b}",
            candidate_id=f"member:{m}",
            selection="eligible",
        )
        for b in range(7)
        for m in range(2)
    ]
    complete = evaluate_stages(exact, request(1400))
    assert len(complete.candidates) == 128 and not complete.coverage.truncated
    monkeypatch.setattr(path, "_read", lambda *a, **k: [])

    @trace_scope()
    def walk(session):
        trail = _Trail()
        for i in range(MAX_STAGES + 1):
            crossing(trail, f"if:perf/{i}", enforcement="l3")
        return {}

    def capped():
        with mtu_request(MtuRequest(mode="inventory"), 4):
            return walk(SimpleNamespace(cts=SNAP))["mtu"]

    value = capped()
    assert len(value["stages"]) == MAX_STAGES and value["coverage"]["truncated"] is True
    results["truncation"] = {
        "candidate_combinations_offered": 256,
        "candidates_returned": len(result.candidates),
        "candidate_expansion_peak_bytes": peak_bytes(expand),
        "candidate_expansion": timed(expand, runs=3),
        "crossings_offered": MAX_STAGES + 1,
        "stages_returned": len(value["stages"]),
        "stage_cap_peak_bytes": peak_bytes(capped),
        "stage_cap": timed(capped, runs=3),
    }
