"""Fan-out timing claims and the estate measurement, both behind the perf
marker. Run with HST_PERF=1 pytest -m perf."""

from __future__ import annotations

import os

import pytest

from hst.bench import run_bench, run_checkpoint_bench, run_estate_bench

pytestmark = [
    pytest.mark.perf,
    pytest.mark.skipif(os.environ.get("HST_PERF") != "1", reason="HST_PERF not set"),
]


def test_the_pool_makes_wall_clock_the_slowest_fetch_not_the_sum():
    result = run_bench(devices=200, latency_ms=50, jitter_ms=10, concurrency=64, change_rate=0.0)
    assert result.failed == 0
    assert result.wall_s < 2.0


def test_a_thousand_devices_fit_the_sixty_second_budget():
    result = run_bench(devices=1000, latency_ms=500, jitter_ms=200, concurrency=256, change_rate=0.05)
    assert result.failed == 0
    assert result.fits(60), result.line(60)


def test_a_thousand_real_ssh_sessions_fit_the_sixty_second_budget():
    # The client and the server both run in this process.
    result = run_bench(
        devices=1000, latency_ms=500, jitter_ms=200, concurrency=512, change_rate=0.05, mode="b"
    )
    assert result.failed == 0
    assert result.fits(60), result.line(60)


ESTATE = {"devices": 200, "runs": 3, "rib_rows": 1000, "peers": 2, "paths": 500, "lookups": 50}


def test_the_estate_at_the_documented_cardinality(capsys):
    """The estate measurement at 200 devices, 3 retained runs, 1,000 RIB rows and
    2 peers of 500 paths per device.

    No wall-clock target is asserted.
    """
    result = run_estate_bench(**ESTATE)
    with capsys.disabled():
        print(f"\n{result.line()}")

    tables_per_device = 3  # rib, bgp_session_routes, bgp_sessions
    assert result.files == ESTATE["devices"] * ESTATE["runs"] * tables_per_device
    per_device = ESTATE["rib_rows"] + ESTATE["peers"] * ESTATE["paths"] + ESTATE["peers"]
    assert result.rows == ESTATE["devices"] * ESTATE["runs"] * per_device
    assert result.lpm_matched == 1
    assert result.checkpoint_nodes == ESTATE["devices"] * (1 + ESTATE["peers"])
    assert result.checkpoint_rels == ESTATE["devices"] * ESTATE["peers"]


def test_the_checkpoint_digest_at_estate_scale(capsys):
    """The checkpoint digests the whole open state."""
    result = run_checkpoint_bench(devices=50_000, peers=20)
    with capsys.disabled():
        print(f"\n{result.line()}")

    assert result.nodes == 50_000 * 21
    assert result.rels == 50_000 * 20


def test_the_row_group_size_does_not_change_what_a_file_holds():
    """`sidestore_row_group_rows` bounds what a write holds in memory."""
    small = run_estate_bench(devices=5, runs=1, rib_rows=5000, peers=1, paths=1000, row_group_rows=256)
    whole = run_estate_bench(devices=5, runs=1, rib_rows=5000, peers=1, paths=1000, row_group_rows=100_000)

    assert small.rows == whole.rows and small.files == whole.files
    assert small.lpm_matched == whole.lpm_matched == 1
