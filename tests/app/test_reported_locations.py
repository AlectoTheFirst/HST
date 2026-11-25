"""Reported locations: what an orchestrator calls a place, and where it binds."""

import pytest
from tests.app.fakes import FakeStore


@pytest.fixture
def store():
    return FakeStore()


async def _seed(store):
    await store.create_source("unifi1", "unifi", {}, b"", True)
    await store.create_site("dcber1", "Berlin", "")


async def test_a_collection_records_the_places_it_reported(store):
    await _seed(store)
    await store.record_target_devices(
        "unifi1",
        "controller",
        ["dev:a", "dev:b"],
        {"dev:a": ("default", "Office"), "dev:b": ("branch", "Branch office")},
    )

    locations = await store.list_reported_locations()
    assert [(loc.location_id, loc.name, loc.site, loc.device_count) for loc in locations] == [
        ("branch", "Branch office", None, 1),
        ("default", "Office", None, 1),
    ]


async def test_a_binding_survives_a_later_collection(store):
    await _seed(store)
    await store.record_target_devices("unifi1", "controller", ["dev:a"], {"dev:a": ("default", "Office")})
    assert await store.bind_location("unifi1", "default", "dcber1")

    await store.record_target_devices(
        "unifi1",
        "controller",
        ["dev:a", "dev:c"],
        {"dev:a": ("default", "Office renamed"), "dev:c": ("default", "Office renamed")},
    )
    locations = await store.list_reported_locations("unifi1")
    assert [(loc.name, loc.site, loc.device_count) for loc in locations] == [("Office renamed", "dcber1", 2)]


async def test_an_unknown_location_and_an_unknown_site_are_both_refused(store):
    await _seed(store)
    await store.record_target_devices("unifi1", "controller", ["dev:a"], {"dev:a": ("default", "Office")})

    assert await store.bind_location("unifi1", "no-such-place", "dcber1") is False
    with pytest.raises(ValueError, match="no such site"):
        await store.bind_location("unifi1", "default", "no-such-site")


async def test_unbinding_returns_the_devices_to_unplaced(store):
    await _seed(store)
    await store.record_target_devices("unifi1", "controller", ["dev:a"], {"dev:a": ("default", "Office")})
    await store.bind_location("unifi1", "default", "dcber1")

    assert await store.bind_location("unifi1", "default", None)
    assert [loc.site for loc in await store.list_reported_locations()] == [None]


async def test_a_device_whose_source_reports_no_place_records_none(store):
    await _seed(store)
    await store.record_target_devices("unifi1", "controller", ["dev:a"], {})

    assert await store.list_reported_locations() == []
    assert [m.location_id for m in await store.target_devices()] == [""]
