"""A group states its settings; the site it sits at fills in the rest."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

from hst.app import runs_exec, sources
from hst.app.store import Device, Site, Source
from hst.core.config import Settings


def _source(config):
    now = datetime.now(UTC)
    return Source(1, "edge", "vyos", config, b"", True, now, now)


def _device():
    now = datetime.now(UTC)
    return Device(1, "edge", "10.0.0.1", None, True, "", now, now)


def test_a_device_takes_its_groups_site_and_that_sites_routing_scope():
    """The device row states an address and nothing else."""
    row = _source({"site_code": "a"})
    sites = {
        "a": Site(1, "a", "A", "", {"routing_scope": "ra"}),
        "b": Site(2, "b", "B", "", {"routing_scope": "rb"}),
    }

    payload, origins = sources.resolve_normalization(
        row, Settings(_env_file=None), device=_device(), sites=sites
    )

    assert payload["site_code"] == "a"
    assert payload["routing_scope"] == "ra"
    assert payload["l2fabric"] == "fab0"  # the application default, not the site
    assert origins == {"site": "group", "routing_scope": "site", "l2fabric": "application"}


def test_a_site_cannot_state_an_l2_fabric():
    row = _source({"site_code": "a"})
    sites = {"a": Site(1, "a", "A", "", {"routing_scope": "ra", "l2fabric": "fa"})}

    payload, origins = sources.resolve_normalization(row, Settings(_env_file=None), sites=sites)

    assert payload["l2fabric"] == "fab0"
    assert origins["l2fabric"] == "application"


def test_a_group_value_beats_the_site_default_and_falls_through_to_the_fabric_map():
    row = _source({"site_code": "a", "routing_scope": "group-r"})
    settings = Settings(_env_file=None, l2_fabrics={"legacy-f": ["edge"]})

    payload, origins = sources.resolve_normalization(row, settings, device=_device(), sites={})

    assert payload["routing_scope"] == "group-r"
    assert payload["l2fabric"] == "legacy-f"
    assert origins["routing_scope"] == "group"
    assert origins["l2fabric"] == "application"


async def test_empty_device_window_creates_no_run_row(tmp_path, monkeypatch):
    class Store:
        @asynccontextmanager
        async def cycle_lock(self):
            yield 1

        async def start_run(self, *_args, **_kwargs):
            raise AssertionError("empty maintenance must not create a run")

    monkeypatch.setattr(runs_exec.rawstore, "parked", lambda _path: [])
    result = await runs_exec.launch(
        Store(), Settings(_env_file=None, hst_data_dir=tmp_path), runs_exec.DEVICE_RUN
    )
    assert result is None


def test_an_orchestrator_spanning_sites_is_not_a_conflict():
    """Devices are placed by their reported location."""
    row = _source({"site_code": "a", "routing_scope": None, "l2fabric": None})
    sites = {
        "a": Site(1, "a", "A", "", {"routing_scope": "ra", "l2fabric": "fa"}),
        "b": Site(2, "b", "B", "", {"routing_scope": "rb", "l2fabric": "fb"}),
    }
    assert not hasattr(sources, "shared_controller_site")

    payload, origins = sources.resolve_normalization(row, Settings(_env_file=None), sites=sites)
    assert payload["site_code"] == "a"
    assert origins["site"] == "group"


def test_an_orchestrator_with_explicit_network_identity_keeps_it_at_every_site():
    row = _source(
        {
            "site_code": "a",
            "routing_scope": "shared-routing",
            "l2fabric": "shared-fabric",
        }
    )
    sites = {
        "a": Site(1, "a", "A", "", {"routing_scope": "ra", "l2fabric": "fa"}),
        "b": Site(2, "b", "B", "", {"routing_scope": "rb", "l2fabric": "fb"}),
    }

    payload, origins = sources.resolve_normalization(row, Settings(_env_file=None), sites=sites)
    assert payload["routing_scope"] == "shared-routing"
    assert payload["l2fabric"] == "shared-fabric"
    assert origins["site"] == "group"


async def _placed(store, prepared):
    return await runs_exec._effective_assignments(store, prepared)


def _prepared(row):
    return runs_exec.PreparedSource(row, [runs_exec.PreparedDevice(None, None, None)])


def _orchestrator(name="unifi1"):
    now = datetime.now(UTC)
    return Source(1, name, "unifi", {"site_code": "a"}, b"", True, now, now)


async def test_a_bound_location_places_the_devices_it_holds():
    from tests.app.fakes import FakeStore

    store = FakeStore()
    await store.create_source("unifi1", "unifi", {"site_code": "a"}, b"", True)
    await store.create_site("dcber1", "Berlin", "")
    await store.record_target_devices("unifi1", "controller", ["dev:a"], {"dev:a": ("default", "Office")})
    await store.bind_location("unifi1", "default", "dcber1")

    assert await _placed(store, [_prepared(_orchestrator())]) == {"dev:a": "dcber1"}


async def test_an_unbound_location_leaves_its_devices_unplaced():
    """The row's own site_code does not stand in."""
    from tests.app.fakes import FakeStore

    store = FakeStore()
    await store.create_source("unifi1", "unifi", {"site_code": "a"}, b"", True)
    await store.record_target_devices("unifi1", "controller", ["dev:a"], {"dev:a": ("default", "Office")})

    # a device left out keeps its carried site
    assert await _placed(store, [_prepared(_orchestrator())]) == {"dev:a": None}


async def test_a_hand_placement_beats_the_binding():
    from tests.app.fakes import FakeStore

    store = FakeStore()
    await store.create_source("unifi1", "unifi", {"site_code": "a"}, b"", True)
    await store.create_site("dcber1", "Berlin", "")
    await store.create_site("other", "Other", "")
    await store.record_target_devices("unifi1", "controller", ["dev:a"], {"dev:a": ("default", "Office")})
    await store.bind_location("unifi1", "default", "dcber1")
    await store.assign_device("dev:a", "other")

    assert await _placed(store, [_prepared(_orchestrator())]) == {"dev:a": "other"}


async def test_a_hand_placement_never_moves_a_group_device():
    """The assign route refuses one, and the resolver ignores a stored one."""
    from tests.app.fakes import FakeStore

    store = FakeStore()
    await store.create_source("edge", "vyos", {"site_code": "a"}, b"", True)
    await store.create_site("other", "Other", "")
    await store.record_target_devices("edge", "10.0.0.1", ["dev:r1"], {})
    await store.assign_device("dev:r1", "other")

    row = _source({"site_code": "a"})
    prepared = runs_exec.PreparedSource(row, [runs_exec.PreparedDevice(_device(), None, None)])
    assert await _placed(store, [prepared]) == {"dev:r1": "a"}


async def test_a_group_device_sits_at_its_groups_site():
    """One writer: the group row, and nothing below it."""
    from tests.app.fakes import FakeStore

    store = FakeStore()
    await store.create_source("edge", "vyos", {"site_code": "a"}, b"", True)
    await store.record_target_devices("edge", "10.0.0.1", ["dev:r1"], {})

    row = _source({"site_code": "a"})
    prepared = runs_exec.PreparedSource(row, [runs_exec.PreparedDevice(_device(), None, None)])
    assert await _placed(store, [prepared]) == {"dev:r1": "a"}


async def test_a_group_with_no_site_leaves_its_devices_unplaced():
    """A group with no site gives the same answer as an unbound location."""
    from tests.app.fakes import FakeStore

    store = FakeStore()
    await store.create_source("edge", "vyos", {"site_code": ""}, b"", True)
    await store.record_target_devices("edge", "10.0.0.1", ["dev:r1"], {})

    row = _source({"site_code": ""})
    prepared = runs_exec.PreparedSource(row, [runs_exec.PreparedDevice(_device(), None, None)])
    assert await _placed(store, [prepared]) == {"dev:r1": None}


def test_the_newest_observation_of_a_uid_places_the_device():
    """A device known to two groups is placed by the group that collected it
    last, whatever the group names sort like."""
    from hst.app.store import TargetDevice

    now = datetime.now(UTC)
    earlier = now - timedelta(days=1)
    rows = {
        "fr2": Source(1, "fr2", "vyos", {"site_code": "fr2"}, b"", True, now, now),
        "fr6": Source(2, "fr6", "vyos", {"site_code": "fr6"}, b"", True, now, now),
    }
    # sorted by source, as the store returns them: the stale fr6 row comes last
    mappings = [
        TargetDevice("fr2", "10.0.0.1", "dev:r1", now),
        TargetDevice("fr6", "10.0.0.1", "dev:r1", earlier),
    ]

    assert sources.resolve_device_sites({}, mappings, rows, {}) == {"dev:r1": ("fr2", "group")}


class _Collected:
    """A collector that has just published, with the uids it revealed."""

    def __init__(self, *uids):
        self.last_device_uids = list(uids)


def test_the_first_cycle_places_a_group_device_at_the_group_site():
    """A uid revealed by this cycle is not in target_devices."""
    row = _source({"site_code": "a"})
    prepared = runs_exec.PreparedSource(
        row,
        [
            runs_exec.PreparedDevice(_device(), _Collected("dev:r1"), None),
            runs_exec.PreparedDevice(_device(), _Collected("dev:r2"), None),
        ],
    )

    assert runs_exec._group_row_sites([prepared]) == {"dev:r1": "a", "dev:r2": "a"}


def test_the_first_cycle_places_nothing_for_a_group_with_no_site():
    """An empty site_code means the group sits nowhere."""
    row = _source({"site_code": ""})
    prepared = runs_exec.PreparedSource(
        row,
        [
            runs_exec.PreparedDevice(_device(), _Collected("dev:r1"), None),
            runs_exec.PreparedDevice(_device(), _Collected("dev:r2"), None),
        ],
    )

    assert runs_exec._group_row_sites([prepared]) == {}


def test_the_first_cycle_places_no_orchestrator_device():
    """The orchestrator row's site_code does not stand in."""
    prepared = runs_exec.PreparedSource(
        _orchestrator(), [runs_exec.PreparedDevice(None, _Collected("dev:a"), None)]
    )

    assert runs_exec._group_row_sites([prepared]) == {}
