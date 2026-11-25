"""`device_status.last_graph_sha`, `last_graph_at` and `last_graph_fetch_at`:
the batch digest the graph change detection compares, when its batch was last
written, and when the payload it was taken from was fetched, recorded by a
cycle or a refresh through `upsert_device_status` and by a device run through
`record_device_graph`.

Both backends, as tests/app/test_store_contract.py runs them: the `pg` leg
skips without `HST_TEST_PG_DSN`.
"""

from __future__ import annotations

from datetime import timedelta

from tests.app.test_store_contract import NOW

# the fixture parametrized over both backends
from tests.app.test_store_contract import store as store


async def _source(store) -> None:
    await store.create_source("edge", "vyos", {}, b"")


async def test_a_written_batch_records_its_digest_and_when_it_was_written(store):
    await _source(store)

    row = await store.upsert_device_status(
        "edge", "r1", now=NOW, ok=True, raw_sha="RAW", obs_sha="OBS", graph_sha="G1", full=True
    )

    assert (row.last_graph_sha, row.last_graph_at, row.last_full_at) == ("G1", NOW, NOW)


async def test_a_batch_that_was_not_written_records_its_digest_and_not_the_time(store):
    await _source(store)
    await store.upsert_device_status("edge", "r1", now=NOW, ok=True, raw_sha="RAW", graph_sha="G1", full=True)
    later = NOW + timedelta(minutes=1)

    row = await store.upsert_device_status("edge", "r1", now=later, ok=True, raw_sha="RAW2", graph_sha="G1")

    assert (row.last_graph_sha, row.last_graph_at, row.last_full_at) == ("G1", NOW, NOW)
    assert (row.last_raw_sha, row.last_success_at) == ("RAW2", later)
    # a first row written this way has a digest and no write time
    first = await store.upsert_device_status("edge", "r2", now=later, ok=True, graph_sha="G2")
    assert (first.last_graph_sha, first.last_graph_at) == ("G2", None)


async def test_a_call_without_a_digest_keeps_the_recorded_one(store):
    await _source(store)
    await store.upsert_device_status("edge", "r1", now=NOW, ok=True, graph_sha="G1", full=True)

    row = await store.upsert_device_status(
        "edge", "r1", now=NOW + timedelta(minutes=1), ok=True, raw_sha="RAW", full=True
    )

    assert (row.last_graph_sha, row.last_graph_at) == ("G1", NOW)


async def test_a_failed_attempt_clears_the_raw_hash_and_the_digest(store):
    """A load that failed may have written a batch judged failed, which the
    carry then filled around: neither hash describes the device's graph, so
    its next success loads and writes in full."""
    await _source(store)
    await store.upsert_device_status(
        "edge", "r1", now=NOW, ok=True, raw_sha="RAW", obs_sha="OBS", graph_sha="G1", full=True
    )
    later = NOW + timedelta(minutes=1)

    row = await store.upsert_device_status(
        "edge",
        "r1",
        now=later,
        ok=False,
        raw_sha="IGNORED",
        graph_sha="IGNORED",
        error="sections not collected",
    )

    assert (row.last_raw_sha, row.last_graph_sha) == ("", "")
    assert (row.consecutive_failures, row.last_error) == (1, "sections not collected")
    # what the failure does not touch
    assert (row.last_obs_sha, row.last_graph_at, row.last_full_at, row.last_success_at) == (
        "OBS",
        NOW,
        NOW,
        NOW,
    )


async def test_a_device_run_records_a_written_and_a_kept_batch(store):
    await _source(store)
    await store.upsert_device_status("edge", "r1", now=NOW, ok=True, raw_sha="RAW", full=True)
    later, latest = NOW + timedelta(minutes=5), NOW + timedelta(minutes=10)

    assert await store.record_device_graph("edge", "r1", now=later, graph_sha="G1", written=True)
    (written,) = await store.list_device_status("edge")
    assert await store.record_device_graph("edge", "r1", now=latest, graph_sha="G1", written=False)
    (kept,) = await store.list_device_status("edge")

    assert (written.last_graph_sha, written.last_graph_at, written.updated_at) == ("G1", later, later)
    assert (kept.last_graph_sha, kept.last_graph_at, kept.updated_at) == ("G1", later, latest)
    # the attempt was recorded when the payload was fetched, and stays as it was
    assert (kept.last_raw_sha, kept.last_attempt_at, kept.last_success_at, kept.last_full_at) == (
        "RAW",
        NOW,
        NOW,
        NOW,
    )
    assert kept.consecutive_failures == 0


async def test_a_device_run_load_that_failed_clears_the_digest_and_the_raw_hash(store):
    await _source(store)
    await store.upsert_device_status(
        "edge", "r1", now=NOW, ok=True, raw_sha="RAW", obs_sha="OBS", graph_sha="G1", full=True
    )

    assert await store.record_device_graph(
        "edge", "r1", now=NOW + timedelta(minutes=5), graph_sha="", written=False
    )
    (row,) = await store.list_device_status("edge")

    assert (row.last_graph_sha, row.last_raw_sha) == ("", "")
    assert (row.last_obs_sha, row.last_graph_at, row.consecutive_failures) == ("OBS", NOW, 0)


async def test_a_device_run_record_for_a_device_with_no_row_changes_nothing(store):
    await _source(store)

    assert not await store.record_device_graph("edge", "gone", now=NOW, graph_sha="G1", written=True)
    assert await store.list_device_status("edge") == []


# `last_graph_fetch_at`, which the device run's supersede check reads, kept to
# the millisecond a fetch time has
FETCHED = NOW - timedelta(seconds=30, milliseconds=123)


async def test_a_digest_records_when_its_payload_was_fetched_written_or_kept(store):
    await _source(store)

    written = await store.upsert_device_status(
        "edge", "r1", now=NOW, ok=True, raw_sha="RAW", graph_sha="G1", graph_fetch_at=FETCHED, full=True
    )
    kept = await store.upsert_device_status(
        "edge",
        "r1",
        now=NOW + timedelta(minutes=1),
        ok=True,
        raw_sha="RAW2",
        graph_sha="G1",
        graph_fetch_at=FETCHED + timedelta(minutes=1),
    )

    assert written.last_graph_fetch_at == FETCHED
    assert (kept.last_graph_fetch_at, kept.last_graph_at) == (FETCHED + timedelta(minutes=1), NOW)


async def test_a_fetch_time_without_a_digest_and_a_failed_attempt_leave_it(store):
    """A fetch that normalized nothing checked no batch; a failed attempt
    leaves the graph's objects dating themselves."""
    await _source(store)
    await store.upsert_device_status(
        "edge", "r1", now=NOW, ok=True, raw_sha="RAW", graph_sha="G1", graph_fetch_at=FETCHED, full=True
    )

    skipped = await store.upsert_device_status(
        "edge", "r1", now=NOW + timedelta(minutes=1), ok=True, raw_sha="RAW", graph_fetch_at=NOW
    )
    failed = await store.upsert_device_status(
        "edge", "r1", now=NOW + timedelta(minutes=2), ok=False, graph_fetch_at=NOW, error="timed out"
    )

    assert skipped.last_graph_fetch_at == FETCHED
    assert (failed.last_graph_fetch_at, failed.last_graph_sha) == (FETCHED, "")


async def test_a_device_run_records_when_the_payload_it_applied_was_fetched(store):
    await _source(store)
    await store.upsert_device_status("edge", "r1", now=NOW, ok=True, raw_sha="RAW", full=True)

    assert await store.record_device_graph(
        "edge", "r1", now=NOW, graph_sha="G1", written=False, fetch_at=FETCHED
    )
    (kept,) = await store.list_device_status("edge")
    assert await store.record_device_graph(
        "edge", "r1", now=NOW + timedelta(minutes=1), graph_sha="", written=False, fetch_at=NOW
    )
    (failed,) = await store.list_device_status("edge")

    assert (kept.last_graph_fetch_at, kept.last_graph_at) == (FETCHED, None)
    assert (failed.last_graph_fetch_at, failed.last_graph_sha) == (FETCHED, "")


async def test_a_device_run_records_the_skip_basis_and_leaves_the_attempt(store):
    """The basis of a parked payload is recorded when a device run
    loads it, by a writer that leaves the attempt the fetch recorded."""
    await _source(store)
    await store.upsert_device_status(
        "edge", "r1", now=NOW, ok=True, raw_sha="OLD", obs_sha="OLDOBS", full=True
    )
    parked = NOW + timedelta(minutes=1)
    await store.upsert_device_status("edge", "r1", now=parked, ok=True)  # the park: the attempt alone
    loaded = NOW + timedelta(minutes=5)

    assert await store.record_device_basis(
        "edge", "r1", now=loaded, raw_sha="NEW", obs_sha="NEWOBS", full=True
    )
    (row,) = await store.list_device_status("edge")

    assert (row.last_raw_sha, row.last_obs_sha, row.last_full_at, row.updated_at) == (
        "NEW",
        "NEWOBS",
        loaded,
        loaded,
    )
    assert (row.last_attempt_at, row.last_success_at, row.consecutive_failures) == (parked, parked, 0)


async def test_a_basis_without_a_hash_or_full_leaves_those_columns(store):
    """An observation payload records its observation hash alone."""
    await _source(store)
    await store.upsert_device_status("edge", "r1", now=NOW, ok=True, raw_sha="RAW", obs_sha="OBS", full=True)

    assert await store.record_device_basis("edge", "r1", now=NOW + timedelta(minutes=5), obs_sha="OBS2")
    (row,) = await store.list_device_status("edge")

    assert (row.last_raw_sha, row.last_obs_sha, row.last_full_at) == ("RAW", "OBS2", NOW)


async def test_a_basis_for_a_device_with_no_row_changes_nothing(store):
    await _source(store)

    assert not await store.record_device_basis("edge", "gone", now=NOW, raw_sha="RAW", full=True)
    assert await store.list_device_status("edge") == []
