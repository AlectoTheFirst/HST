"""The fake-fleet benchmark's own correctness."""

from __future__ import annotations

import pytest

from hst.bench import run_bench, run_checkpoint_bench, run_estate_bench


def test_change_rate_selects_who_loads():
    result = run_bench(devices=20, latency_ms=1, jitter_ms=0, concurrency=8, change_rate=0.25)
    assert result.fetched == 20
    assert result.failed == 0
    assert result.loaded == 5  # every 4th device carries a bumped seq
    assert result.skipped == 15


def test_zero_change_rate_skips_the_whole_warm_fleet():
    result = run_bench(devices=10, latency_ms=1, jitter_ms=0, concurrency=4, change_rate=0.0)
    assert result.loaded == 0
    assert result.skipped == 10


def test_mode_b_pays_real_ssh_and_detects_change():
    """Real KEX, auth and exec channels on loopback, tiny fleet: the payload
    round-trips the wire and the skip decision still holds."""
    result = run_bench(devices=4, latency_ms=1, jitter_ms=0, concurrency=4, change_rate=0.25, mode="b")
    assert result.mode == "b"
    assert result.failed == 0
    assert result.loaded == 1
    assert result.skipped == 3
    assert "mode B" in result.line(60)


def test_the_budget_verdict_reads_from_the_measured_walls():
    result = run_bench(devices=4, latency_ms=1, jitter_ms=0, concurrency=4, change_rate=0.5)
    assert result.fits(60) is True
    assert "fits" in result.line(60)
    assert result.fits(0.000001) is False
    assert "does not fit" in result.line(0.000001)


def test_the_estate_bench_measures_the_estate_it_reports():
    """Tiny estate, same shape as the documented one: every device writes its
    three tables for every retained run, the lookup matches the one route
    covering the probe, and the checkpoint covers a node per device and per
    session with a relationship each."""
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")

    result = run_estate_bench(devices=3, runs=2, rib_rows=20, peers=1, paths=5, lookups=3)

    assert result.files == 3 * 2 * 3
    assert result.rows == 3 * 2 * (20 + 5 + 1)
    assert result.bytes_on_disk > 0
    assert result.lpm_matched == 1
    assert result.checkpoint_nodes == 6
    assert result.checkpoint_rels == 3
    assert "3 devices x 2 runs" in result.line()


def test_the_checkpoint_bench_digests_the_shape_it_names():
    result = run_checkpoint_bench(devices=10, peers=3)
    assert result.nodes == 40
    assert result.rels == 30
    assert "40 nodes" in result.line()
