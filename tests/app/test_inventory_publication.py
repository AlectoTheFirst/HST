"""Publication: composition, apply, reconciliation and the outbox.

The composer hands back the LOCATED_IN map the run writes into the graph and
captures the placement revisions it read; publish applies exactly those. A
failure of the Postgres side after the graph side leaves the prior coherent
view with `inventory_sync_pending` and retries through the outbox; a late
completion of an older run never overwrites a newer applied one; startup
reconcile finishes what a dead process left half done.
"""

from __future__ import annotations

import pytest
from tests.app.inventory_rig import DSN, Rig, device, fake_rig, pg_rig

from hst.app.inventory.contracts import OutboxState, PlacementMode, PlacementState, PublicationState
from hst.app.inventory.repository import PgInventoryTx
from hst.app.store import DeviceFilters

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
        await r.seed_source("vco2", "velocloud")
        await r.seed_site("fra")
        await r.seed_site("ams")
        yield r
    finally:
        if r.pg:
            await r.store.dispose()


R1 = ("vyos-lab", "r1")
R2 = ("vyos-lab", "r2")
VCO = ("vco", "")
VCO2 = ("vco2", "")


async def _assign(rig: Rig, uid: str, site: str | None, *, mode: PlacementMode = PlacementMode.ASSIGNED):
    async with rig.repo.transaction() as tx:
        dev = await tx.get_device_by_graph_uid(uid)
        assert dev is not None
        current = await tx.get_placement(dev.id)
        placement = await tx.set_placement(
            dev.id,
            mode=mode,
            site_id=rig.site_ids[site] if site else None,
            origin="manual",
            expected_revision=current.revision if current else 0,
            actor_id=None,
            now=rig.clock(),
        )
        await rig.service.read_model.refresh(tx, [dev.id], rig.clock(), collection=False)
        return placement


# --- composition and apply --------------------------------------------------------


async def test_compose_hands_back_bound_auto_and_assigned_placements_and_publish_applies_them(rig: Rig):
    await rig.seed_location("vco", "site-7", "FRA DC", site="fra")
    await rig.seed_location("vco", "site-8", "Nowhere")
    await rig.run("100", {VCO: ("complete", [device("vco:e:edge:1", location=("site-7", "FRA DC"))])})
    placed = await _assign(rig, "vco:e:edge:1", "ams")
    assert placed.revision == 2, "revision 1 is the auto row the first publication gave the device"
    rig.clock.tick()
    reports = {
        VCO: (
            "complete",
            [
                device("vco:e:edge:1", location=("site-7", "FRA DC")),
                device("vco:e:edge:2", location=("site-7", "FRA DC")),
                device("vco:e:edge:3", location=("site-8", "Nowhere")),
            ],
        )
    }
    composed, outcome = await rig.run("101", reports)
    assert composed is not None and outcome is not None
    assert composed.site_assignments == {"vco:e:edge:1": "ams", "vco:e:edge:2": "fra", "vco:e:edge:3": None}
    dev1 = await rig.device_by_uid("vco:e:edge:1")
    assert dev1 is not None
    assert composed.placement_revisions[str(dev1.id)] == {
        "revision": 2,
        "site_id": rig.site_ids["ams"],
        "mode": "assigned",
    }
    assert outcome.state == PublicationState.APPLIED and not outcome.sync_pending
    r1 = await rig.resolved("vco:e:edge:1")
    assert r1.applied_revision == 2 and r1.published_site_id == rig.site_ids["ams"]
    assert r1.published_snapshot_key == "101" and not r1.pending
    r2 = await rig.resolved("vco:e:edge:2")
    assert r2.state == PlacementState.AUTO and r2.desired_site_id == rig.site_ids["fra"]
    # the publication gave the auto device its row to carry the applied side
    assert r2.desired_revision == 1 and r2.applied_revision == 1
    assert r2.published_site_id == rig.site_ids["fra"] and not r2.pending
    r3 = await rig.resolved("vco:e:edge:3")
    assert r3.state == PlacementState.UNPLACED and not r3.pending
    assert (await rig.state()).read_model_snapshot_key == "101"


async def test_an_edit_after_capture_stays_pending_until_the_next_publication(rig: Rig):
    await rig.run("100", {R1: ("complete", [device("dev:x")])})
    await _assign(rig, "dev:x", "fra")
    rig.clock.tick()
    async with rig.repo.transaction() as tx:
        await rig.service.stage_observations(tx, "101", R1, [device("dev:x")], "complete")
    composed = await rig.service.compose_placements("101")
    assert composed.site_assignments == {"dev:x": "fra"}
    # the edit lands between capture and publication
    await _assign(rig, "dev:x", "ams")
    await rig.service.publish("101")
    r = await rig.resolved("dev:x")
    assert r.applied_revision == 2 and r.desired_revision == 3
    assert r.published_site_id == rig.site_ids["fra"] and r.desired_site_id == rig.site_ids["ams"]
    assert r.pending and r.summary_state == PlacementState.PENDING
    rig.clock.tick()
    composed2, _ = await rig.run("102", {R1: ("complete", [device("dev:x")])})
    assert composed2 is not None and composed2.site_assignments == {"dev:x": "ams"}
    after = await rig.resolved("dev:x")
    assert after.applied_revision == 3 and not after.pending


async def test_a_placement_only_edit_is_materialized_even_when_the_device_is_not_in_the_run(rig: Rig):
    await rig.run("100", {R1: ("complete", [device("dev:x")]), R2: ("complete", [device("dev:y")])})
    await _assign(rig, "dev:x", "fra")
    rig.clock.tick()
    # only r2 ran; dev:x has unchanged raw and is not observed by the staged target
    composed, _ = await rig.run("101", {R2: ("complete", [device("dev:y")])})
    assert composed is not None and composed.site_assignments == {"dev:x": "fra", "dev:y": None}
    r = await rig.resolved("dev:x")
    assert r.applied_revision == 2 and r.published_snapshot_key == "101" and not r.pending


async def test_site_counts_come_from_the_same_resolver_as_the_list(rig: Rig):
    await rig.seed_location("vco", "site-7", "FRA DC", site="fra")
    await rig.run(
        "100", {VCO: ("complete", [device("vco:e:edge:1", location=("site-7", "x")), device("vco:e:edge:2")])}
    )
    await _assign(rig, "vco:e:edge:2", "fra")
    async with rig.repo.transaction() as tx:
        counts = await rig.ctx.site_rows(tx).device_counts()
        page = await tx.list_devices(DeviceFilters(site_ids=[rig.site_ids["fra"]]))
    assert counts == {rig.site_ids["fra"]: 2}
    assert len(page.items) == 2


# --- onboarding defaults -----------------------------------------------------------


async def test_an_agreed_onboarding_default_places_a_new_device_once_with_origin_onboarding(rig: Rig):
    await rig.target("vyos-lab", "r1", onboarding_site="fra")
    await rig.target("vyos-lab", "r2", onboarding_site="fra")
    composed, _ = await rig.run(
        "100", {R1: ("complete", [device("dev:x")]), R2: ("complete", [device("dev:x")])}
    )
    assert composed is not None and composed.site_assignments == {"dev:x": "fra"}
    placement = await rig.placement("dev:x")
    assert placement is not None
    assert placement.mode == "assigned" and placement.origin == "onboarding" and placement.revision == 1
    assert placement.applied_revision == 1 and placement.published_site_id == rig.site_ids["fra"]
    r = await rig.resolved("dev:x")
    assert not r.pending and r.basis.value == "onboarding"


async def test_conflicting_onboarding_defaults_leave_auto_with_a_conflict_event(rig: Rig):
    await rig.target("vyos-lab", "r1", onboarding_site="fra")
    await rig.target("vyos-lab", "r2", onboarding_site="ams")
    await rig.run("100", {R1: ("complete", [device("dev:x")]), R2: ("complete", [device("dev:x")])})
    placement = await rig.placement("dev:x")
    assert placement is not None and placement.mode == "auto" and placement.origin != "onboarding"
    dev = await rig.device_by_uid("dev:x")
    assert dev is not None
    async with rig.repo.transaction() as tx:
        events, _ = await tx.page_events(entity_type="device", entity_id=str(dev.id))
    conflict = [e for e in events if e.action == "placement.onboarding_conflict"]
    assert len(conflict) == 1
    assert sorted(conflict[0].after["candidates"]) == sorted([rig.site_ids["fra"], rig.site_ids["ams"]])


async def test_a_later_default_change_never_moves_an_existing_device(rig: Rig):
    target = await rig.target("vyos-lab", "r1", onboarding_site="fra")
    await rig.run("100", {R1: ("complete", [device("dev:x")])})
    async with rig.repo.transaction() as tx:
        await tx.update_target(
            target.id,
            expected_revision=target.revision,
            now=rig.clock(),
            onboarding_site_id=rig.site_ids["ams"],
        )
    rig.clock.tick()
    await rig.run("101", {R1: ("complete", [device("dev:x"), device("dev:new")])})
    old = await rig.placement("dev:x")
    assert old is not None and old.site_id == rig.site_ids["fra"] and old.revision == 1
    new = await rig.placement("dev:new")
    assert new is not None and new.site_id == rig.site_ids["ams"]


async def test_onboarding_default_is_not_applied_to_a_reappearing_device(rig: Rig):
    await rig.target("vyos-lab", "r1", onboarding_site="fra")
    await rig.run("100", {R1: ("complete", [device("dev:x")])})
    await _assign(rig, "dev:x", None, mode=PlacementMode.UNPLACED)
    rig.clock.tick()
    await rig.run("101", {R1: ("complete", [])})
    rig.clock.tick()
    await rig.run("102", {R1: ("complete", [device("dev:x")])})
    placement = await rig.placement("dev:x")
    assert placement is not None and placement.mode == "unplaced"


# --- stale carry-forward and conflicts in publication --------------------------------


async def test_stale_evidence_carries_the_published_site_and_a_conflict_withdraws_it(rig: Rig):
    await rig.seed_location("vco", "site-7", "FRA", site="fra")
    await rig.seed_location("vco2", "site-9", "AMS", site="ams")
    await rig.run("100", {VCO: ("complete", [device("vco:e:edge:1", location=("site-7", "FRA"))])})
    rig.clock.tick()
    composed, _ = await rig.run("101", {VCO: ("failed", [])})
    assert composed is not None and composed.site_assignments == {"vco:e:edge:1": "fra"}
    r = await rig.resolved("vco:e:edge:1")
    assert r.state == PlacementState.STALE and r.published_site_id == rig.site_ids["fra"] and not r.pending
    rig.clock.tick()
    reports = {
        VCO: ("complete", [device("vco:e:edge:1", location=("site-7", "FRA"))]),
        VCO2: ("complete", [device("vco:e:edge:1", location=("site-9", "AMS"))]),
    }
    composed2, _ = await rig.run("102", reports)
    assert composed2 is not None and composed2.site_assignments == {"vco:e:edge:1": None}
    r2 = await rig.resolved("vco:e:edge:1")
    assert r2.state == PlacementState.CONFLICT and r2.published_site_id is None and not r2.pending


# --- late completion, idempotence -------------------------------------------------------


async def test_a_late_completion_of_an_older_run_never_overwrites_a_newer_published_observation(rig: Rig):
    await rig.run("99", {R1: ("complete", [device("dev:x")])})
    rig.clock.tick()
    async with rig.repo.transaction() as tx:
        await rig.service.stage_observations(tx, "100", R1, [device("dev:x")], "complete")
    rig.clock.tick()
    async with rig.repo.transaction() as tx:
        await rig.service.stage_observations(tx, "101", R1, [device("dev:x"), device("dev:y")], "complete")
    await rig.service.compose_placements("101")
    await rig.service.publish("101")
    assert await rig.device_by_uid("dev:y") is not None
    rig.clock.tick()
    late = await rig.service.publish("100")
    assert late.state == PublicationState.ABORTED
    assert (await rig.state()).read_model_snapshot_key == "101"
    y = await rig.device_by_uid("dev:y")
    assert y is not None and y.lifecycle == "active"
    async with rig.repo.transaction() as tx:
        pub = await tx.get_publication("100")
        pending = [o for o in await tx.list_outbox() if o.state != OutboxState.DONE.value]
    assert pub is not None and pub.state == "aborted"
    assert pending == []


async def test_publish_is_idempotent(rig: Rig):
    await rig.run("100", {R1: ("complete", [device("dev:x")])})
    again = await rig.service.publish("100")
    assert again.state == PublicationState.APPLIED and again.detail == "already applied"
    assert len(await rig.observations("dev:x")) == 1


# --- failure after graph publication ------------------------------------------------------


async def test_a_postgres_failure_after_publication_keeps_the_prior_view_and_retries_idempotently(
    rig: Rig, monkeypatch
):
    from tests.app.inventory_fakes import FakeInventoryTx

    await rig.run("100", {R1: ("complete", [device("dev:x")])})
    rig.clock.tick()
    cls = PgInventoryTx if rig.pg else FakeInventoryTx
    original = cls.apply_publication
    failures = {"n": 0}

    async def failing(self, snapshot_key, now):
        failures["n"] += 1
        raise RuntimeError("connection reset")

    monkeypatch.setattr(cls, "apply_publication", failing)
    _, outcome = await rig.run("101", {R1: ("complete", [device("dev:x"), device("dev:y")])})
    assert outcome is not None and outcome.sync_pending and outcome.state == PublicationState.PUBLISHED
    assert failures["n"] == 2, "publish tried once and the outbox retried once"
    state = await rig.state()
    assert state.inventory_sync_pending and state.read_model_snapshot_key == "100"
    assert await rig.device_by_uid("dev:y") is None, "the failed apply rolled back"
    (o,) = await rig.observations("dev:x")
    assert o.state == "current" and o.last_seen_snapshot_key == "100"
    async with rig.repo.transaction() as tx:
        (item,) = [i for i in await tx.list_outbox() if i.dedup_key == "publication:101"]
        pub = await tx.get_publication("101")
    assert item.state == OutboxState.PENDING.value and item.attempt == 1 and "RuntimeError" in item.last_error
    assert pub is not None and pub.state == "published"

    monkeypatch.setattr(cls, "apply_publication", original)
    assert await rig.service.retry() == 0, "not due yet"
    rig.clock.tick(60)
    assert await rig.service.retry() == 1
    state = await rig.state()
    assert not state.inventory_sync_pending and state.read_model_snapshot_key == "101"
    assert await rig.device_by_uid("dev:y") is not None
    (o,) = await rig.observations("dev:x")
    assert o.last_seen_snapshot_key == "101"


# --- startup reconcile ---------------------------------------------------------------------------


async def test_startup_reconcile_finishes_a_publication_the_graph_has_and_aborts_what_it_moved_past(rig: Rig):
    await rig.run("100", {R1: ("complete", [device("dev:x")])})
    rig.clock.tick()
    # a run that died before publishing
    async with rig.repo.transaction() as tx:
        await rig.service.stage_observations(tx, "101", R1, [device("dev:stale")], "complete")
    rig.clock.tick()
    # a run whose graph side published and whose process died before publish()
    async with rig.repo.transaction() as tx:
        await rig.service.stage_observations(tx, "102", R1, [device("dev:x"), device("dev:z")], "complete")
    await rig.service.compose_placements("102")
    rig.clock.tick()
    report = await rig.service.reconcile("102")
    assert report.applied == ["102"] and report.aborted == ["101"] and report.failed == []
    assert not report.sync_pending
    assert (await rig.state()).read_model_snapshot_key == "102"
    assert await rig.device_by_uid("dev:z") is not None
    assert await rig.device_by_uid("dev:stale") is None
    async with rig.repo.transaction() as tx:
        assert (await tx.get_publication("101")).state == "aborted"
        assert all(i.state == OutboxState.DONE.value for i in await tx.list_outbox())


async def test_reconcile_refreshes_collection_states_from_the_execution_records(rig: Rig):
    await rig.run("100", {R1: ("complete", [device("dev:x")]), R2: ("complete", [device("dev:x")])})
    await rig.store.upsert_device_status("vyos-lab", "r1", now=rig.clock(), ok=True)
    await rig.store.upsert_device_status("vyos-lab", "r2", now=rig.clock(), ok=False, error="timeout")
    report = await rig.service.reconcile("100")
    assert report.collection_states_touched == 1
    dev = await rig.device_by_uid("dev:x")
    assert dev is not None and dev.collection_state == "partial"
    assert dev.last_success_at == rig.clock()
    await rig.store.upsert_device_status("vyos-lab", "r2", now=rig.clock(), ok=True)
    await rig.service.reconcile("100")
    dev = await rig.device_by_uid("dev:x")
    assert dev is not None and dev.collection_state == "manual", "no cadence configured: no stale deadline"


async def test_reconcile_with_nothing_to_do_is_a_no_op(rig: Rig):
    report = await rig.service.reconcile(None)
    assert report.applied == [] and report.aborted == [] and report.failed == []
    assert (await rig.state()).read_model_snapshot_key is None
