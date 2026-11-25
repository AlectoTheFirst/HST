"""Snapshot-bound source population materialization."""

import dataclasses

import pytest

from hst.assessment.populations import (
    InventorySnapshot,
    PopulationError,
    PopulationSelector,
    materialize_population,
)


def test_prefix_and_host_overlap_count_the_exact_qualified_address_union():
    snapshot = InventorySnapshot(
        "a" * 64,
        "nautobot",
        "complete",
        (
            {"id": "prefix", "object_type": "prefix", "address": "10.0.0.0/24", "vrf_id": "blue"},
            {"id": "host", "address": "10.0.0.7/24", "vrf_id": "blue"},
            {"id": "other", "address": "10.0.0.7/24", "vrf_id": "red"},
        ),
    )
    artifact = materialize_population(PopulationSelector("nautobot", vrf_id="blue"), snapshot)

    assert artifact.address_count == 256
    assert {member[1] for member in artifact.members} == {"nautobot::blue"}


def test_ipv6_cardinality_is_exact_without_address_enumeration():
    snapshot = InventorySnapshot(
        "a" * 64,
        "nautobot",
        "complete",
        ({"id": "prefix", "object_type": "prefix", "address": "2001:db8::/64", "vrf_id": "blue"},),
    )

    assert (
        materialize_population(PopulationSelector("nautobot", vrf_id="blue"), snapshot).address_count == 2**64
    )


def test_incomplete_inventory_retains_observed_selected_rows_and_gap():
    artifact = materialize_population(
        PopulationSelector("nautobot", role_id="server"),
        InventorySnapshot(
            "a" * 64,
            "nautobot",
            "incomplete",
            ({"id": "one", "address": "192.0.2.1/24", "vrf_id": "blue", "role_id": "server"},),
        ),
    )

    assert artifact.members
    assert artifact.complete is False
    assert artifact.gaps == ("INVENTORY_NOT_COMPLETE",)


def test_namespace_and_object_id_are_qualified_and_selectable():
    snapshot = InventorySnapshot(
        "a" * 64,
        "nautobot",
        "complete",
        (
            {"id": "same", "namespace_id": "one", "address": "192.0.2.1/24", "vrf_id": "blue"},
            {"id": "same", "namespace_id": "two", "address": "192.0.2.1/24", "vrf_id": "blue"},
        ),
    )
    artifact = materialize_population(
        PopulationSelector("nautobot", namespace_id="two", object_uids=("same",)), snapshot
    )

    assert artifact.members == (("nautobot:two:same", "nautobot:two:blue", 4, "192.0.2.1/32"),)


def test_tampered_artifact_and_invalid_selector_are_rejected():
    with pytest.raises(PopulationError):
        PopulationSelector("unknown")  # type: ignore[arg-type]
    with pytest.raises(PopulationError):
        InventorySnapshot("A" * 64, "nautobot", "complete")

    artifact = materialize_population(
        PopulationSelector("manual", literals=("192.0.2.0/24",)),
        InventorySnapshot("a" * 64, "manual", "complete"),
    )
    with pytest.raises(PopulationError):
        dataclasses.replace(artifact, members=(("manual:0", "manual", 4, "192.0.2.0/25"),))
