"""A run places every device it holds, also the ones it carries.

A device run collects its scheduled targets and carries the devices of every
other source forward. The site of a carried device comes from the same
assignments as in a cycle, so the run must resolve it from all configured
sources, not only from the ones it collected.
"""

from datetime import UTC, datetime

from hst.app import runs_exec
from hst.app.store import Source


def _prepared(row):
    return runs_exec.PreparedSource(row, [runs_exec.PreparedDevice(None, None, None)])


def _vyos():
    now = datetime.now(UTC)
    return Source(2, "vyos-core1", "vyos", {"site_code": "dcber1"}, b"", True, now, now)


async def _store():
    from tests.app.fakes import FakeStore

    store = FakeStore()
    await store.create_source("unifi1", "unifi", {}, b"", True)
    await store.create_source("vyos-core1", "vyos", {"site_code": "dcber1"}, b"", True)
    await store.create_site("dcber1", "Berlin", "")
    await store.record_target_devices(
        "unifi1",
        "controller",
        ["dev:sw", "dev:ap"],
        {
            "dev:sw": ("default", "Default"),
            "dev:ap": ("default", "Default"),
        },
    )
    await store.record_target_devices("vyos-core1", "192.0.2.1", ["dev:core1"])
    return store


async def test_a_run_that_collects_only_one_source_keeps_the_hand_placement_of_a_carried_device():
    store = await _store()
    await store.assign_device("dev:sw", "dcber1")

    placed = await runs_exec._effective_assignments(store, [_prepared(_vyos())])

    assert placed["dev:sw"] == "dcber1"
    assert placed["dev:core1"] == "dcber1"


async def test_a_run_that_collects_only_one_source_keeps_the_location_binding_of_a_carried_device():
    store = await _store()
    await store.bind_location("unifi1", "default", "dcber1")

    placed = await runs_exec._effective_assignments(store, [_prepared(_vyos())])

    assert placed == {"dev:sw": "dcber1", "dev:ap": "dcber1", "dev:core1": "dcber1"}


async def test_the_prepared_row_decides_over_the_stored_one():
    """The run is built from the prepared configuration, so a group site read
    before the run starts is the one its devices get."""
    store = await _store()
    now = datetime.now(UTC)
    moved = Source(2, "vyos-core1", "vyos", {"site_code": "other"}, b"", True, now, now)

    placed = await runs_exec._effective_assignments(store, [_prepared(moved)])

    assert placed["dev:core1"] == "other"


async def test_a_removed_placement_is_named_with_none_so_a_carried_device_loses_it():
    """A device left out of the map is not resolved, and a carried device
    keeps the site of its previous copy for good. A removed hand placement, an
    unbound location and a group whose site was cleared are each a None."""
    store = await _store()
    await store.assign_device("dev:sw", "dcber1")
    await store.bind_location("unifi1", "default", "dcber1")
    assert await runs_exec._effective_assignments(store, [_prepared(_vyos())]) == {
        "dev:sw": "dcber1",
        "dev:ap": "dcber1",
        "dev:core1": "dcber1",
    }

    await store.assign_device("dev:sw", None)
    await store.bind_location("unifi1", "default", None)
    now = datetime.now(UTC)
    cleared = Source(2, "vyos-core1", "vyos", {"site_code": ""}, b"", True, now, now)

    placed = await runs_exec._effective_assignments(store, [_prepared(cleared)])

    assert placed == {"dev:sw": None, "dev:ap": None, "dev:core1": None}


def test_a_group_site_fills_a_device_the_stored_rows_place_nowhere():
    class _Revealed:
        last_device_uids = ["dev:new", "dev:cleared"]

    row = Source(2, "vyos-core1", "vyos", {"site_code": "dcber1"}, b"", True, *(datetime.now(UTC),) * 2)
    prepared = runs_exec.PreparedSource(row, [runs_exec.PreparedDevice(None, _Revealed(), None)])

    sites = runs_exec._with_group_sites({"dev:cleared": None, "dev:hand": "other"}, [prepared])

    assert sites == {"dev:cleared": "dcber1", "dev:hand": "other", "dev:new": "dcber1"}
