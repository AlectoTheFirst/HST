"""`device_status.last_verified_started_at` and `last_verified_at`: the
window of the last fetch that found the device unchanged against the basis on
record. A check belongs to that basis: it is recorded only while the row still
holds the hashes the fetch compared, decided in the writing statement, and
whatever moves or clears either hash withdraws it.

Both backends, as tests/app/test_store_contract.py runs them: the `pg` leg
skips without `HST_TEST_PG_DSN`.
"""

from __future__ import annotations

from datetime import timedelta

from tests.app.test_store_contract import NOW

# the fixture parametrized over both backends
from tests.app.test_store_contract import store as store

START, END = NOW - timedelta(seconds=2), NOW - timedelta(seconds=1)


async def _basis(store, raw: str = "RAW", obs: str = "OBS") -> None:
    await store.create_source("edge", "vyos", {}, b"")
    await store.upsert_device_status("edge", "r1", now=NOW, ok=True, raw_sha=raw, obs_sha=obs, full=True)


async def _offer(store, *, raw: str = "RAW", obs: str = "OBS", start=START, end=END, **kw):
    return await store.upsert_device_status(
        "edge",
        "r1",
        now=NOW,
        ok=True,
        verified_started_at=start,
        verified_at=end,
        verified_raw_sha=raw,
        verified_obs_sha=obs,
        **kw,
    )


async def _checked(store) -> None:
    await _basis(store)
    row = await _offer(store)
    assert (row.last_verified_started_at, row.last_verified_at) == (START, END)


async def _check_of(store) -> tuple:
    (row,) = await store.list_device_status("edge")
    return row.last_verified_started_at, row.last_verified_at


async def test_a_row_without_a_check_reads_none(store):
    await store.create_source("edge", "vyos", {}, b"")
    row = await store.upsert_device_status("edge", "r1", now=NOW, ok=True, raw_sha="RAW", full=True)
    assert (row.last_verified_started_at, row.last_verified_at) == (None, None)


async def test_a_first_row_records_no_check(store):
    """A row that did not exist held no basis a fetch could have compared."""
    await store.create_source("edge", "vyos", {}, b"")
    row = await _offer(store, raw="", obs="")
    assert (row.last_verified_started_at, row.last_verified_at) == (None, None)


async def test_a_check_without_the_hashes_it_compared_is_not_recorded(store):
    await _basis(store)
    row = await store.upsert_device_status(
        "edge", "r1", now=NOW, ok=True, verified_started_at=START, verified_at=END
    )
    assert (row.last_verified_started_at, row.last_verified_at) == (None, None)


async def test_a_check_given_with_the_unchanged_hashes_is_recorded(store):
    """The cycle's skip writes the hashes it compared, equal to the stored
    ones, and its check in one call."""
    await _basis(store)
    row = await _offer(store, raw_sha="RAW", obs_sha="OBS")
    assert (row.last_raw_sha, row.last_verified_started_at, row.last_verified_at) == ("RAW", START, END)


async def test_a_check_is_kept_by_an_upsert_that_moves_no_hash(store):
    await _checked(store)
    row = await store.upsert_device_status("edge", "r1", now=NOW, ok=True, raw_sha="RAW", obs_sha="OBS")
    assert (row.last_verified_started_at, row.last_verified_at) == (START, END)


# -- a basis that moved since the fetch read it ---------------------------------


async def test_a_check_against_a_configuration_another_lane_replaced_is_not_recorded(store):
    """(a) A cycle loads changed configuration while a per-device fetch that
    read the old basis is in flight; the fetch's check lands after the
    cycle's write and compared the old configuration."""
    await _basis(store, raw="X")
    await store.upsert_device_status("edge", "r1", now=NOW, ok=True, raw_sha="Y", obs_sha="OBS", full=True)
    row = await _offer(store, raw="X")
    assert (row.last_raw_sha, row.last_verified_started_at, row.last_verified_at) == ("Y", None, None)


async def test_an_observation_basis_recorded_late_withdraws_and_refuses_the_old_check(store):
    """(b) A device run settles an observation payload and records its basis
    afterwards. A check recorded against the old observation hash before
    that is withdrawn by it, and one that lands after it is refused."""
    await _checked(store)  # against OBS
    assert await store.record_device_basis("edge", "r1", now=NOW, obs_sha="OBS1")
    assert await _check_of(store) == (None, None)
    row = await _offer(store, obs="OBS")
    assert (row.last_obs_sha, row.last_verified_started_at, row.last_verified_at) == ("OBS1", None, None)


async def test_an_upsert_that_moves_the_observation_hash_withdraws_the_check(store):
    await _checked(store)
    row = await store.upsert_device_status("edge", "r1", now=NOW, ok=True, obs_sha="OBS2")
    assert (row.last_verified_started_at, row.last_verified_at) == (None, None)


async def test_a_basis_equal_to_the_stored_one_keeps_the_check(store):
    await _checked(store)
    assert await store.record_device_basis("edge", "r1", now=NOW, raw_sha="RAW", obs_sha="OBS", full=True)
    assert await _check_of(store) == (START, END)


# -- the clock --------------------------------------------------------------------


async def test_a_window_that_ends_before_it_starts_is_not_recorded(store):
    """(c) The host clock stepped back during the fetch."""
    await _basis(store)
    row = await _offer(store, start=END, end=START)
    assert (row.last_verified_started_at, row.last_verified_at) == (None, None)


async def test_a_check_ending_before_the_graphs_payload_was_fetched_is_not_recorded(store):
    """(c) A check that ends before the fetch of the payload the graph stands
    on cannot describe that payload."""
    await _basis(store)
    await store.record_device_graph("edge", "r1", now=NOW, graph_sha="G", written=True, fetch_at=NOW)
    row = await _offer(store)
    assert (row.last_verified_started_at, row.last_verified_at) == (None, None)
    later = await _offer(store, start=NOW + timedelta(seconds=1), end=NOW + timedelta(seconds=2))
    assert later.last_verified_at == NOW + timedelta(seconds=2)


# -- withdrawn ----------------------------------------------------------------------


async def test_a_new_or_cleared_raw_hash_withdraws_the_check(store):
    await _checked(store)
    row = await store.upsert_device_status("edge", "r1", now=NOW, ok=True, raw_sha="")
    assert (row.last_verified_started_at, row.last_verified_at) == (None, None)


async def test_a_failed_attempt_withdraws_the_check(store):
    await _checked(store)
    row = await store.upsert_device_status(
        "edge", "r1", now=NOW, ok=False, error="timeout", verified_started_at=START, verified_at=END
    )
    assert (row.last_verified_started_at, row.last_verified_at) == (None, None)


async def test_a_basis_a_device_run_records_withdraws_the_check(store):
    await _checked(store)
    assert await store.record_device_basis("edge", "r1", now=NOW, raw_sha="RAW2", full=True)
    assert await _check_of(store) == (None, None)


async def test_a_failed_device_run_load_withdraws_the_check(store):
    await _checked(store)
    assert await store.record_device_graph("edge", "r1", now=NOW, graph_sha="", written=False)
    assert await _check_of(store) == (None, None)
