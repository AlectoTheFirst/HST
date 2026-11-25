"""Deterministic multi-observer inventory and the observation lifecycle."""

from __future__ import annotations

import pytest
from tests.app.inventory_rig import DSN, Rig, device, fake_rig, pg_rig

from hst.app.inventory import observations as obs
from hst.app.inventory.contracts import Authority, Lifecycle, ObservationState
from hst.app.store import DeviceFilters, DeviceSpec
from hst.core.model import Batch, NodeRecord, SectionOutcome

BACKENDS = [
    pytest.param("fake", id="fake"),
    pytest.param(
        "pg",
        id="pg",
        marks=[pytest.mark.pg, pytest.mark.skipif(not DSN, reason="HST_TEST_PG_DSN not set")],
    ),
]


@pytest.fixture(params=BACKENDS)
async def rig(request):
    r = fake_rig() if request.param == "fake" else await pg_rig()
    try:
        await r.seed_source("vyos-lab", "vyos")
        await r.seed_source("vco", "velocloud")
        await r.seed_source("gw", "checkpoint_gateway")
        await r.seed_site("fra")
        await r.seed_site("ams")
        yield r
    finally:
        if r.pg:
            await r.store.dispose()


VYOS_R1 = ("vyos-lab", "r1")
VYOS_R2 = ("vyos-lab", "r2")
VCO = ("vco", "")
GW = ("gw", "gw1")


# --- identity -----------------------------------------------------------------


async def test_same_uid_from_two_targets_is_one_device_with_both_observations(rig: Rig):
    await rig.run("100", {VYOS_R1: ("complete", [device("dev:x")]), VYOS_R2: ("complete", [device("dev:x")])})
    dev = await rig.device_by_uid("dev:x")
    assert dev is not None and dev.lifecycle == "active"
    observations = await rig.observations("dev:x")
    assert len(observations) == 2
    assert {o.state for o in observations} == {"current"}
    async with rig.repo.transaction() as tx:
        page = await tx.list_devices(DeviceFilters())
    assert [i.device.graph_uid for i in page.items] == ["dev:x"]
    assert sorted(c.host for c in page.items[0].connections) == ["r1", "r2"]


async def test_distinct_uids_with_the_same_hostname_and_address_stay_distinct(rig: Rig):
    same = {"hostname": "edge", "management_address": "10.0.0.1"}
    await rig.run(
        "100",
        {
            VYOS_R1: ("complete", [obs.ObservedDevice("dev:a", **same)]),
            VYOS_R2: ("complete", [obs.ObservedDevice("dev:b", **same)]),
        },
    )
    a, b = await rig.device_by_uid("dev:a"), await rig.device_by_uid("dev:b")
    assert a is not None and b is not None and a.id != b.id
    assert a.hostname == b.hostname == "edge"


async def test_one_target_reporting_several_uids_registers_each_once(rig: Rig):
    await rig.run(
        "100", {VCO: ("complete", [device("vco:e:edge:1"), device("vco:e:edge:2"), device("vco:e:edge:1")])}
    )
    async with rig.repo.transaction() as tx:
        page = await tx.list_devices(DeviceFilters())
    assert sorted(i.device.graph_uid for i in page.items) == ["vco:e:edge:1", "vco:e:edge:2"]
    assert all(len(i.connections) == 1 for i in page.items)


async def test_a_direct_vsx_target_reports_the_appliance_and_its_contexts_are_not_devices(rig: Rig):
    reported = [
        device("dev:x:mgmt:gw1", "gw1"),
        obs.ObservedDevice("firewall-instance:abc123", "vs1"),
        obs.ObservedDevice("firewall-instance:def456", "vs2"),
    ]
    await rig.run("100", {GW: ("complete", reported)})
    assert await rig.device_by_uid("dev:x:mgmt:gw1") is not None
    assert await rig.device_by_uid("firewall-instance:abc123") is None
    async with rig.repo.transaction() as tx:
        page = await tx.list_devices(DeviceFilters())
    assert [i.device.graph_uid for i in page.items] == ["dev:x:mgmt:gw1"]


async def test_a_controller_target_may_report_no_device_and_a_pending_target_is_never_a_device(rig: Rig):
    _, outcome = await rig.run("100", {VCO: ("complete", []), VYOS_R1: ("complete", [])})
    assert outcome is not None and outcome.applied is not None
    async with rig.repo.transaction() as tx:
        page = await tx.list_devices(DeviceFilters(lifecycles=[m.value for m in Lifecycle]))
        targets = await tx.list_targets()
    assert page.items == []
    assert sorted((t.source_key, t.host, t.kind) for t in targets) == [
        ("vco", "", "controller"),
        ("vyos-lab", "r1", "implicit"),
    ]


async def test_target_registration_links_the_fleet_row_and_names_the_kind(rig: Rig):
    await rig.store.replace_devices("vyos-lab", [DeviceSpec("r1")])
    fleet = await rig.store.list_devices("vyos-lab")
    await rig.run("100", {VYOS_R1: ("complete", [device("dev:x")])})
    async with rig.repo.transaction() as tx:
        target = await tx.get_active_target("vyos-lab", "r1")
    assert target is not None and target.kind == "direct" and target.legacy_device_id == fleet[0].id


async def test_staging_registers_a_reported_location_that_the_source_has_not_registered_yet(rig: Rig):
    await rig.run("100", {VCO: ("complete", [device("vco:e:edge:1", location=("site-7", "Frankfurt DC"))])})
    async with rig.repo.transaction() as tx:
        locations = await tx.list_locations("vco")
        (observation,) = await rig.observations("vco:e:edge:1")
    assert [(loc.location_id, loc.name) for loc in locations] == [("site-7", "Frankfurt DC")]
    assert observation.reported_location_handle == locations[0].handle


async def test_collector_warnings_become_redacted_observation_notes(rig: Rig):
    reported = [
        obs.ObservedDevice(
            "dev:x:mgmt:gw1",
            "gw1",
            warnings=("virtual system vs1 on gw1 is keyed by the VS name", "password=hunter2 seen"),
        )
    ]
    await rig.run("100", {GW: ("complete", reported)})
    (observation,) = await rig.observations("dev:x:mgmt:gw1")
    assert observation.notes == {
        "warnings": ["virtual system vs1 on gw1 is keyed by the VS name", "password=hunter2 seen"]
    }
    assert observation.authority == "complete", "a warning is a note, not an authority downgrade"


# --- authority ------------------------------------------------------------------------


def test_authority_of_a_batch_is_partial_when_a_section_failed():
    empty = Batch(source="vco", scope="velocloud:x", nodes=[NodeRecord(label="Device", uid="vco:e:edge:1")])
    assert obs.authority_of(empty) == (Authority.COMPLETE, True)
    partial = empty.model_copy(update={"sections": {"routes": SectionOutcome(status="failed")}})
    assert obs.authority_of(partial) == (Authority.PARTIAL, True)
    failed = empty.model_copy(update={"sections": {"interfaces": SectionOutcome(status="failed")}})
    assert obs.authority_of(failed, authoritative=("interfaces",)) == (Authority.PARTIAL, False)
    ok = empty.model_copy(update={"sections": {"interfaces": SectionOutcome(status="ok")}})
    assert obs.authority_of(ok, authoritative=("interfaces",)) == (Authority.COMPLETE, True)


def test_observed_devices_from_a_batch_skip_contexts_and_carry_the_reported_location():
    from hst.collectors.base import REPORTED_LOCATION_NAME_PROP, REPORTED_LOCATION_PROP

    batch = Batch(
        source="vco",
        scope="velocloud:x",
        nodes=[
            NodeRecord(
                label="Device",
                uid="vco:e:edge:1",
                props={
                    "hostname": "edge1",
                    REPORTED_LOCATION_PROP: "e/7",
                    REPORTED_LOCATION_NAME_PROP: "FRA",
                },
            ),
            NodeRecord(label="Device", uid="firewall-instance:abc", props={"name": "vs1"}),
            NodeRecord(label="Interface", uid="if:1", props={}),
        ],
        warnings=["edge1 reports no serial"],
    )
    (edge,) = obs.observed_devices_from_batch(batch)
    assert edge.graph_uid == "vco:e:edge:1"
    assert edge.reported_location == ("e/7", "FRA")
    assert edge.warnings == ("edge1 reports no serial",)


# --- lifecycle ---------------------------------------------------------------------


async def test_a_complete_empty_result_retires_the_target_claim_and_the_device_goes_missing(rig: Rig):
    await rig.run("100", {VCO: ("complete", [device("vco:e:edge:1"), device("vco:e:edge:2")])})
    rig.clock.tick()
    # edge 2 is absent from a complete response: retired
    await rig.run("101", {VCO: ("complete", [device("vco:e:edge:1")])})
    gone = await rig.device_by_uid("vco:e:edge:2")
    assert gone is not None and gone.lifecycle == "missing"
    (observation,) = await rig.observations("vco:e:edge:2")
    assert observation.state == "absent"
    kept = await rig.device_by_uid("vco:e:edge:1")
    assert kept is not None and kept.lifecycle == "active"
    # missing devices stay searchable in the default view
    async with rig.repo.transaction() as tx:
        page = await tx.list_devices(DeviceFilters(q="edge:2"))
    assert [i.device.graph_uid for i in page.items] == ["vco:e:edge:2"]


async def test_a_missing_device_keeps_intent_and_history_and_returns_to_active_on_reappearance(rig: Rig):
    await rig.run("100", {VYOS_R1: ("complete", [device("dev:x")])})
    dev = await rig.device_by_uid("dev:x")
    assert dev is not None
    async with rig.repo.transaction() as tx:
        from hst.app.inventory.contracts import PlacementMode

        current = await tx.get_placement(dev.id)
        await tx.set_placement(
            dev.id,
            mode=PlacementMode.ASSIGNED,
            site_id=rig.site_ids["fra"],
            origin="manual",
            expected_revision=current.revision if current else 0,
            actor_id=None,
            now=rig.clock(),
        )
    rig.clock.tick()
    await rig.run("101", {VYOS_R1: ("complete", [])})
    missing = await rig.device_by_uid("dev:x")
    assert missing is not None and missing.lifecycle == "missing" and missing.id == dev.id
    placement = await rig.placement("dev:x")
    assert placement is not None and placement.site_id == rig.site_ids["fra"]
    rig.clock.tick()
    await rig.run("102", {VYOS_R1: ("complete", [device("dev:x")])})
    back = await rig.device_by_uid("dev:x")
    assert back is not None and back.lifecycle == "active" and back.id == dev.id
    async with rig.repo.transaction() as tx:
        events, _ = await tx.page_events(entity_type="device", entity_id=str(dev.id))
    actions = [e.action for e in events]
    assert "device.missing" in actions and "device.reappeared" in actions and "device.registered" in actions


async def test_a_partial_result_updates_only_reported_facts_and_leaves_the_rest_stale(rig: Rig):
    await rig.run("100", {VCO: ("complete", [device("vco:e:edge:1"), device("vco:e:edge:2")])})
    rig.clock.tick()
    await rig.run("101", {VCO: ("partial", [device("vco:e:edge:1")])})
    (o1,) = await rig.observations("vco:e:edge:1")
    (o2,) = await rig.observations("vco:e:edge:2")
    assert o1.state == "current" and o1.authority == "partial"
    assert o2.state == "stale"
    d2 = await rig.device_by_uid("vco:e:edge:2")
    assert d2 is not None and d2.lifecycle == "active", "stale evidence is not a missing device"


async def test_a_failed_target_keeps_prior_claims_as_stale_evidence(rig: Rig):
    await rig.run("100", {VYOS_R1: ("complete", [device("dev:x")])})
    rig.clock.tick()
    await rig.run("101", {VYOS_R1: ("failed", [device("dev:x")])})
    (o,) = await rig.observations("dev:x")
    assert o.state == "stale"
    dev = await rig.device_by_uid("dev:x")
    assert dev is not None and dev.lifecycle == "active"


async def test_a_new_complete_observation_without_a_location_clears_the_old_location(rig: Rig):
    await rig.run("100", {VCO: ("complete", [device("vco:e:edge:1", location=("site-7", "FRA"))])})
    (before,) = await rig.observations("vco:e:edge:1")
    assert before.reported_location_handle is not None
    rig.clock.tick()
    await rig.run("101", {VCO: ("complete", [device("vco:e:edge:1")])})
    (after,) = await rig.observations("vco:e:edge:1")
    assert after.reported_location_handle is None and after.state == "current"


async def test_archive_is_explicit_and_new_observations_do_not_unarchive(rig: Rig):
    await rig.run("100", {VYOS_R1: ("complete", [device("dev:x")])})
    dev = await rig.device_by_uid("dev:x")
    assert dev is not None
    async with rig.repo.transaction() as tx:
        await tx.set_lifecycle(dev.id, Lifecycle.ARCHIVED, expected_revision=dev.revision, now=rig.clock())
    rig.clock.tick()
    await rig.run("101", {VYOS_R1: ("complete", [device("dev:x")])})
    archived = await rig.device_by_uid("dev:x")
    assert archived is not None and archived.lifecycle == "archived"
    (o,) = await rig.observations("dev:x")
    assert o.state == "current" and o.last_seen_snapshot_key == "101", "still observed while archived"
    async with rig.repo.transaction() as tx:
        default = await tx.list_devices(DeviceFilters())
        archived_view = await tx.list_devices(DeviceFilters(lifecycles=["archived"]))
    assert default.items == [] and [i.device.graph_uid for i in archived_view.items] == ["dev:x"]


async def test_staging_alone_never_changes_current_observations_and_abort_drops_it(rig: Rig):
    await rig.run("100", {VYOS_R1: ("complete", [device("dev:x")])})
    rig.clock.tick()
    await rig.run("101", {VYOS_R1: ("complete", [device("dev:y")])}, compose=False, publish=False)
    assert await rig.device_by_uid("dev:y") is None
    (o,) = await rig.observations("dev:x")
    assert o.state == "current"
    await rig.service.abort("101")
    async with rig.repo.transaction() as tx:
        pub = await tx.get_publication("101")
        staged_targets, staged_rows = await rig.ctx.aux(tx).staged_rows("101")
    assert pub is not None and pub.state == "aborted"
    assert staged_targets == [] and staged_rows == []
    assert (await rig.state()).read_model_snapshot_key == "100"


async def test_restaging_the_same_target_in_one_run_is_idempotent(rig: Rig):
    async with rig.repo.transaction() as tx:
        await rig.service.stage_observations(tx, "100", VYOS_R1, [device("dev:x")], "complete")
        await rig.service.stage_observations(tx, "100", VYOS_R1, [device("dev:x")], "complete")
    await rig.service.compose_placements("100")
    await rig.service.publish("100")
    assert len(await rig.observations("dev:x")) == 1


async def test_unknown_authority_is_refused(rig: Rig):
    from hst.app.inventory.repository import InventoryError

    async with rig.repo.transaction() as tx:
        with pytest.raises(InventoryError):
            await rig.service.stage_observations(tx, "100", VYOS_R1, [], "maybe")


def test_observation_state_vocabulary_is_the_repository_one():
    assert {s.value for s in ObservationState} == {"current", "stale", "absent"}


# --- source removal ------------------------------------------------------------------------


async def test_archiving_a_sources_targets_preserves_the_device_and_its_history(rig: Rig):
    await rig.run("100", {VYOS_R1: ("complete", [device("dev:x")])})
    dev = await rig.device_by_uid("dev:x")
    assert dev is not None
    async with rig.repo.transaction() as tx:
        from hst.app.inventory.contracts import PlacementMode

        current = await tx.get_placement(dev.id)
        await tx.set_placement(
            dev.id,
            mode=PlacementMode.ASSIGNED,
            site_id=rig.site_ids["fra"],
            origin="manual",
            expected_revision=current.revision if current else 0,
            actor_id=None,
            now=rig.clock(),
        )
    async with rig.repo.transaction() as tx:
        archived = await tx.archive_source_targets(rig.source_ids["vyos-lab"], rig.clock())
    assert [t.source_key for t in archived] == ["vyos-lab"] and archived[0].source_id is None
    (o,) = await rig.observations("dev:x")
    assert o.state == "absent"
    rig.clock.tick()
    report = await rig.service.reconcile("100")
    assert report.collection_states_touched >= 1
    missing = await rig.device_by_uid("dev:x")
    assert missing is not None and missing.id == dev.id and missing.lifecycle == "missing"
    placement = await rig.placement("dev:x")
    assert placement is not None and placement.site_id == rig.site_ids["fra"], "intent survives"
    async with rig.repo.transaction() as tx:
        events, _ = await tx.page_events(entity_type="device", entity_id=str(dev.id))
        page = await tx.list_devices(DeviceFilters(q="dev:x"))
    assert [e.action for e in events] == ["device.missing", "device.registered"], "history survives"
    assert [i.device.id for i in page.items] == [dev.id], "still searchable"
    # seen again through a fresh target of another connection: the same device returns
    rig.clock.tick()
    await rig.run("101", {("vco", ""): ("complete", [device("dev:x")])})
    back = await rig.device_by_uid("dev:x")
    assert back is not None and back.id == dev.id and back.lifecycle == "active"
