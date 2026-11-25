"""Inventory repository semantics."""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from tests.app.inventory_fakes import FakeInventoryRepository

from hst.app.crypto import decrypt_secrets, encrypt_secrets
from hst.app.inventory.contracts import (
    REDACTED,
    Authority,
    Lifecycle,
    ObservationState,
    OutboxState,
    PlacementMode,
    PublicationState,
    SortDirection,
    SortField,
)
from hst.app.inventory.repository import (
    Conflict,
    IdempotencyConflict,
    InventoryChanged,
    InventoryError,
    NotFound,
    PreviewExpired,
    StaleRevision,
)
from hst.app.store import DeviceFilters, StagedObservation

DSN = os.environ.get("HST_TEST_PG_DSN")
NOW = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)
LATER = NOW + timedelta(minutes=1)

BACKENDS = [
    pytest.param("fake", id="fake"),
    pytest.param(
        "pg",
        id="pg",
        marks=[pytest.mark.pg, pytest.mark.skipif(not DSN, reason="HST_TEST_PG_DSN not set")],
    ),
]


class Rig:
    """The repository plus the legacy rows it references, seeded the same way on
    both backends: two sources, two sites, one reported location, one user."""

    def __init__(self, repo, *, pg_store=None):
        self.repo = repo
        self.pg_store = pg_store
        self.source_ids: dict[str, int] = {}
        self.site_ids: dict[str, int] = {}
        self.location_handle: uuid.UUID | None = None
        self.user_id: int | None = None

    async def seed(self) -> None:
        if self.pg_store is None:
            fake: FakeInventoryRepository = self.repo
            fake.seed_source(1, "vyos-lab", "vyos")
            fake.seed_source(2, "vco", "velocloud")
            fake.seed_site(10, "fra")
            fake.seed_site(11, "ams")
            self.location_handle = fake.seed_location("vco", "site-7", "Frankfurt DC").handle
            self.source_ids = {"vyos-lab": 1, "vco": 2}
            self.site_ids = {"fra": 10, "ams": 11}
            self.user_id = 1
            return
        st = self.pg_store
        user = await st.create_user("ada", "h", "admin")
        self.user_id = user.id
        for name, type_ in (("vyos-lab", "vyos"), ("vco", "velocloud")):
            row = await st.create_source(name, type_, {}, b"")
            self.source_ids[name] = row.id
        for code in ("fra", "ams"):
            site = await st.create_site(code, code.upper(), "")
            self.site_ids[code] = site.id
        await st.record_target_devices("vco", "", ["dev:x"], {"dev:x": ("site-7", "Frankfurt DC")})
        async with self.repo.transaction() as tx:
            (loc,) = await tx.list_locations("vco")
            self.location_handle = loc.handle


@pytest.fixture(params=BACKENDS)
async def rig(request):
    if request.param == "fake":
        r = Rig(FakeInventoryRepository())
        await r.seed()
        yield r
        return

    from sqlalchemy.ext.asyncio import create_async_engine

    from hst.app.store.pg import PgStore, metadata, upgrade_to_head

    await asyncio.to_thread(upgrade_to_head, DSN)
    engine = create_async_engine(DSN)
    async with engine.begin() as conn:
        for table in reversed(metadata.sorted_tables):
            await conn.execute(table.delete())
    await engine.dispose()
    st = PgStore(DSN)
    r = Rig(st.inventory(), pg_store=st)
    await r.seed()
    yield r
    await st.dispose()


async def _target(rig: Rig, host: str = "r1", source: str = "vyos-lab", **kw):
    async with rig.repo.transaction() as tx:
        return await tx.create_target(
            source_id=rig.source_ids[source], source_key=source, host=host, kind="direct", now=NOW, **kw
        )


async def _device(rig: Rig, uid: str = "dev:vyos:r1", hostname: str = "r1"):
    async with rig.repo.transaction() as tx:
        device, _ = await tx.register_device(
            uid, hostname=hostname, platform="vyos", management_address="10.0.0.1", snapshot_key="s1", now=NOW
        )
        return device


# --- revisions and 409 -----------------------------------------------------------------


async def test_stale_revision_is_refused_with_the_current_one(rig):
    target = await _target(rig)
    async with rig.repo.transaction() as tx:
        updated = await tx.update_target(target.id, expected_revision=1, now=NOW, enabled=False)
    assert updated.revision == 2 and updated.enabled is False
    async with rig.repo.transaction() as tx:
        with pytest.raises(StaleRevision) as exc:
            await tx.update_target(target.id, expected_revision=1, now=NOW, enabled=True)
    assert exc.value.current_revision == 2
    assert exc.value.status == 409
    async with rig.repo.transaction() as tx:
        assert (await tx.get_target(target.id)).enabled is False


async def test_the_second_of_two_writers_with_one_expected_revision_is_refused(rig):
    target = await _target(rig)
    wrote = asyncio.Event()
    commit = asyncio.Event()

    async def first():
        async with rig.repo.transaction() as tx:
            await tx.update_target(target.id, expected_revision=1, now=NOW, enabled=False)
            wrote.set()
            await commit.wait()

    async def second():
        await wrote.wait()
        async with rig.repo.transaction() as tx:
            return await tx.update_target(target.id, expected_revision=1, now=LATER, enabled=True)

    writers = [asyncio.create_task(first()), asyncio.create_task(second())]
    await wrote.wait()
    # the second writer reaches the row while the first transaction is open
    await asyncio.sleep(0.05)
    commit.set()
    await writers[0]
    with pytest.raises(StaleRevision) as exc:
        await writers[1]
    assert exc.value.current_revision == 2
    async with rig.repo.transaction() as tx:
        stored = await tx.get_target(target.id)
    assert (stored.revision, stored.enabled) == (2, False)


async def test_active_target_uniqueness_ignores_archived_rows(rig):
    first = await _target(rig)
    with pytest.raises(Conflict):
        await _target(rig)
    async with rig.repo.transaction() as tx:
        await tx.archive_target(first.id, expected_revision=1, now=NOW)
    second = await _target(rig)
    assert second.id != first.id
    async with rig.repo.transaction() as tx:
        active = await tx.get_active_target("vyos-lab", "r1")
        assert active.id == second.id
        assert len(await tx.list_targets(include_archived=True)) == 2


async def test_intent_writes_advance_the_generation_and_summaries_do_not(rig):
    async with rig.repo.transaction() as tx:
        before = (await tx.get_state()).intent_generation
    device = await _device(rig)
    async with rig.repo.transaction() as tx:
        assert (await tx.get_state()).intent_generation == before  # observation, not intent
        await tx.set_device_summary(device.id, now=NOW, collection_state="current")
        assert (await tx.get_state()).intent_generation == before
        await tx.set_placement(
            device.id,
            mode=PlacementMode.UNPLACED,
            site_id=None,
            origin="manual",
            expected_revision=0,
            actor_id=None,
            now=NOW,
        )
        assert (await tx.get_state()).intent_generation == before + 1


# --- immutable versions --------------------------------------------------------------------


async def test_profile_and_credential_versions_are_immutable_and_pinned(rig):
    from cryptography.fernet import Fernet

    dek = Fernet.generate_key().decode()
    sealed = encrypt_secrets(dek, {"auth.password": "hunter2"})
    async with rig.repo.transaction() as tx:
        cred, v1 = await tx.create_credential(
            display_name="lab ssh",
            sealed=sealed,
            secret_paths=["auth.password"],
            actor_id=rig.user_id,
            now=NOW,
        )
        prof, p1 = await tx.create_profile(
            display_name="lab",
            collector_type="vyos",
            settings={"interval_s": 300},
            credential_id=cred.id,
            credential_revision=1,
            actor_id=rig.user_id,
            now=NOW,
        )
    assert v1.secret_paths == ["auth.password"]
    async with rig.repo.transaction() as tx:
        with pytest.raises(StaleRevision):
            await tx.add_profile_version(
                prof.id,
                expected_revision=3,
                settings={},
                credential_id=cred.id,
                credential_revision=1,
                actor_id=None,
                now=NOW,
            )
        with pytest.raises(Conflict):  # a revision that does not exist cannot be pinned
            await tx.add_profile_version(
                prof.id,
                expected_revision=1,
                settings={},
                credential_id=cred.id,
                credential_revision=9,
                actor_id=None,
                now=NOW,
            )
    async with rig.repo.transaction() as tx:
        v2 = await tx.add_credential_version(
            cred.id,
            expected_revision=1,
            sealed=encrypt_secrets(dek, {"auth.password": "rotated"}),
            secret_paths=["auth.password"],
            actor_id=None,
            now=LATER,
        )
        p2 = await tx.add_profile_version(
            prof.id,
            expected_revision=1,
            settings={"interval_s": 600},
            credential_id=cred.id,
            credential_revision=2,
            actor_id=None,
            now=LATER,
        )
    async with rig.repo.transaction() as tx:
        assert (await tx.get_profile_version(prof.id, 1)).settings == {"interval_s": 300}
        assert (await tx.get_profile_version(prof.id, 1)).credential_revision == 1
        assert (await tx.get_profile_version(prof.id, 2)).credential_revision == 2
        assert (await tx.get_profile(prof.id)).current_revision == 2 == p2.revision
        assert (await tx.get_credential(cred.id)).current_revision == 2 == v2.revision
        old = await tx.get_credential_version(cred.id, 1)
        # The store returns ciphertext only; opening it is the execution process's job.
        assert old.sealed == sealed
        assert decrypt_secrets(dek, old.sealed) == {"auth.password": "hunter2"}
        assert not any("plaintext" in n or n.startswith("decrypt") for n in dir(tx))
        assert [v.revision for v in await tx.list_profile_versions(prof.id)] == [1, 2] and p1.revision == 1


async def test_in_use_profile_and_pinned_credential_cannot_be_archived(rig):
    async with rig.repo.transaction() as tx:
        cred, _ = await tx.create_credential(
            display_name="c", sealed=b"x", secret_paths=[], actor_id=None, now=NOW
        )
        prof, _ = await tx.create_profile(
            display_name="p",
            collector_type="vyos",
            settings={},
            credential_id=cred.id,
            credential_revision=1,
            actor_id=None,
            now=NOW,
        )
    target = await _target(rig, profile_id=prof.id)
    async with rig.repo.transaction() as tx:
        with pytest.raises(Conflict) as exc:
            await tx.archive_profile(prof.id, expected_revision=1, now=NOW)
        assert exc.value.references == [f"target:{target.id}"]
        with pytest.raises(Conflict) as exc2:
            await tx.archive_credential(cred.id, expected_revision=1, now=NOW)
        assert exc2.value.references == [str(prof.id)]
    async with rig.repo.transaction() as tx:
        await tx.update_target(target.id, expected_revision=1, now=NOW, profile_id=None)
        archived = await tx.archive_profile(prof.id, expected_revision=1, now=NOW)
        assert archived.archived_at == NOW
        assert await tx.list_profiles() == []
        assert (await tx.get_profile_version(prof.id, 1)) is not None  # versions retained


# --- events atomic with state --------------------------------------------------------------


async def test_event_and_state_commit_or_roll_back_together(rig):
    device = await _device(rig)
    with pytest.raises(RuntimeError):
        async with rig.repo.transaction() as tx:
            await tx.set_placement(
                device.id,
                mode=PlacementMode.ASSIGNED,
                site_id=rig.site_ids["fra"],
                origin="manual",
                expected_revision=0,
                actor_id=rig.user_id,
                now=NOW,
            )
            await tx.append_event(
                entity_type="device",
                entity_id=str(device.id),
                actor_id=rig.user_id,
                action="place",
                now=NOW,
                after={"mode": "assigned", "password": "leak"},
            )
            raise RuntimeError("service failed after both writes")
    async with rig.repo.transaction() as tx:
        assert await tx.get_placement(device.id) is None
        events, _ = await tx.page_events(entity_type="device", entity_id=str(device.id))
        assert events == []
    async with rig.repo.transaction() as tx:
        await tx.set_placement(
            device.id,
            mode=PlacementMode.ASSIGNED,
            site_id=rig.site_ids["fra"],
            origin="manual",
            expected_revision=0,
            actor_id=rig.user_id,
            now=NOW,
        )
        stored = await tx.append_event(
            entity_type="device",
            entity_id=str(device.id),
            actor_id=rig.user_id,
            action="place",
            now=NOW,
            before={"auth": {"password": "old-secret"}},
            after={"mode": "assigned", "password": "new-secret", "nested": [{"token": "t"}]},
            sensitive=True,
        )
        assert stored.before == {"auth": {"password": REDACTED}}
        assert stored.after == {"mode": "assigned", "password": REDACTED, "nested": [{"token": REDACTED}]}
    async with rig.repo.transaction() as tx:
        assert (await tx.get_placement(device.id)).site_id == rig.site_ids["fra"]
        events, _ = await tx.page_events(entity_type="device", entity_id=str(device.id))
        assert [e.action for e in events] == ["place"]
        assert "secret" not in repr(events)
        hidden, _ = await tx.page_events(
            entity_type="device", entity_id=str(device.id), include_sensitive=False
        )
        assert hidden == []


async def test_event_pages_newest_first_with_a_cursor(rig):
    async with rig.repo.transaction() as tx:
        for i in range(5):
            await tx.append_event(entity_type="site", entity_id="1", actor_id=None, action=f"e{i}", now=NOW)
    async with rig.repo.transaction() as tx:
        page, before = await tx.page_events(entity_type="site", entity_id="1", limit=2)
        assert [e.action for e in page] == ["e4", "e3"] and before is not None
        page2, before2 = await tx.page_events(entity_type="site", entity_id="1", limit=2, before_id=before)
        assert [e.action for e in page2] == ["e2", "e1"]
        page3, before3 = await tx.page_events(entity_type="site", entity_id="1", limit=2, before_id=before2)
        assert [e.action for e in page3] == ["e0"] and before3 is None


# --- previews and idempotency -----------------------------------------------------------------


async def test_preview_is_user_bound_expiring_and_one_shot(rig):
    async with rig.repo.transaction() as tx:
        preview = await tx.create_preview(
            actor_id=rig.user_id,
            operation="place_devices",
            permissions=["sites.write"],
            intent_generation=1,
            snapshot_key=None,
            members=[{"kind": "device", "id": "x", "revision": 1}],
            changes={"mode": "auto"},
            impact={"devices": 1},
            secret_draft=b"sealed-draft",
            now=NOW,
            ttl=timedelta(minutes=10),
        )
    assert preview.secret_draft is None  # never returned by create
    async with rig.repo.transaction() as tx:
        with pytest.raises(NotFound):
            await tx.get_preview(preview.token, rig.user_id + 1, NOW)
        with pytest.raises(PreviewExpired):
            await tx.get_preview(preview.token, rig.user_id, NOW + timedelta(minutes=10))
        got = await tx.get_preview(preview.token, rig.user_id, NOW + timedelta(minutes=9))
        assert got.members == [{"kind": "device", "id": "x", "revision": 1}] and got.secret_draft is None
    async with rig.repo.transaction() as tx:
        consumed = await tx.consume_preview(preview.token, rig.user_id, LATER, result_id=None)
        assert consumed.secret_draft == b"sealed-draft"
    async with rig.repo.transaction() as tx:
        with pytest.raises(PreviewExpired):
            await tx.consume_preview(preview.token, rig.user_id, LATER, result_id=None)
        with pytest.raises(PreviewExpired):
            await tx.get_preview(preview.token, rig.user_id, LATER)
        assert await tx.purge_expired_previews(LATER) == 1


async def test_preview_impacts_are_paginated_with_exact_totals(rig):
    async with rig.repo.transaction() as tx:
        preview = await tx.create_preview(
            actor_id=rig.user_id,
            operation="edit_profile",
            permissions=["sources.write"],
            intent_generation=1,
            snapshot_key=None,
            members=[],
            changes={},
            impact={},
            secret_draft=None,
            now=NOW,
            ttl=timedelta(minutes=10),
        )
        await tx.add_preview_impacts(preview.token, [("device", f"d{i}", {"i": i}) for i in range(7)])
        await tx.add_preview_impacts(preview.token, [("target", "t1", {})])
    async with rig.repo.transaction() as tx:
        page, total = await tx.page_preview_impacts(preview.token, limit=3)
        assert total == 8 and [r.entity_id for r in page] == ["d0", "d1", "d2"]
        page2, _ = await tx.page_preview_impacts(preview.token, after_seq=page[-1].seq, limit=10)
        assert [r.entity_id for r in page2] == ["d3", "d4", "d5", "d6", "t1"]


async def test_idempotency_result_is_reused_and_digest_mismatch_conflicts(rig):
    async with rig.repo.transaction() as tx:
        assert await tx.check_idempotency(rig.user_id, "k1", "digest-a") is None
        rec = await tx.record_operation_result(
            actor_id=rig.user_id,
            idempotency_key="k1",
            request_digest="digest-a",
            status=200,
            response={"ok": True},
            now=NOW,
        )
    async with rig.repo.transaction() as tx:
        again = await tx.check_idempotency(rig.user_id, "k1", "digest-a")
        assert again.id == rec.id and again.response == {"ok": True}
        with pytest.raises(IdempotencyConflict) as exc:
            await tx.check_idempotency(rig.user_id, "k1", "digest-b")
        assert exc.value.status == 409
        with pytest.raises(IdempotencyConflict):
            await tx.record_operation_result(
                actor_id=rig.user_id,
                idempotency_key="k1",
                request_digest="digest-b",
                status=200,
                response={},
                now=NOW,
            )
        retried = await tx.record_operation_result(
            actor_id=rig.user_id,
            idempotency_key="k1",
            request_digest="digest-a",
            status=500,
            response={"ok": False},
            now=NOW,
        )
        assert retried.id == rec.id and retried.status == 200 and retried.response == {"ok": True}


# --- outbox ------------------------------------------------------------------------------------


async def test_outbox_dedup_claim_lease_retry_and_purge(rig):
    async with rig.repo.transaction() as tx:
        first = await tx.enqueue_outbox(
            kind="publication_reconcile", dedup_key="pub:s1", payload={"snapshot_key": "s1"}, now=NOW
        )
        assert first is not None
        assert (
            await tx.enqueue_outbox(kind="publication_reconcile", dedup_key="pub:s1", payload={}, now=NOW)
            is None
        )
        await tx.enqueue_outbox(
            kind="job_enqueue", dedup_key="job:1", payload={}, now=NOW + timedelta(hours=1), max_attempts=1
        )
    async with rig.repo.transaction() as tx:
        claimed = await tx.claim_outbox("w1", now=NOW, lease=timedelta(minutes=5))
        assert [c.dedup_key for c in claimed] == ["pub:s1"]  # job:1 is not due yet
        assert claimed[0].attempt == 1 and claimed[0].claimed_by == "w1"
        assert await tx.claim_outbox("w2", now=NOW, lease=timedelta(minutes=5)) == []
    async with rig.repo.transaction() as tx:
        assert (
            await tx.finish_outbox(first.id, ok=False, now=NOW, claimed_by="w9", error="x") is None
        )  # not the holder
        retried = await tx.finish_outbox(
            first.id, ok=False, now=NOW, claimed_by="w1", error="boom", retry_at=LATER
        )
        assert (
            retried.state == OutboxState.PENDING.value
            and retried.next_attempt_at == LATER
            and retried.last_error == "boom"
        )
    async with rig.repo.transaction() as tx:
        assert await tx.claim_outbox("w1", now=NOW, lease=timedelta(minutes=5)) == []
        (again,) = await tx.claim_outbox("w1", now=LATER, lease=timedelta(minutes=5))
        assert again.attempt == 2
        assert await tx.reap_outbox(LATER + timedelta(minutes=6)) == 1  # lease expired: back to pending
        (third,) = await tx.claim_outbox("w3", now=LATER + timedelta(minutes=6), lease=timedelta(minutes=5))
        done = await tx.finish_outbox(third.id, ok=True, now=LATER + timedelta(minutes=7), claimed_by="w3")
        assert done.state == OutboxState.DONE.value
        (job,) = await tx.claim_outbox("w3", now=NOW + timedelta(hours=2), lease=timedelta(minutes=5))
        failed = await tx.finish_outbox(
            job.id, ok=False, now=NOW, claimed_by="w3", error="dead", retry_at=LATER
        )
        assert failed.state == OutboxState.FAILED.value  # max_attempts 1: kept, not retried
        assert await tx.purge_outbox_done(NOW + timedelta(days=8)) == 1
        assert [o.state for o in await tx.list_outbox()] == ["failed"]


# --- publications ---------------------------------------------------------------------------------


async def test_publication_stage_publish_apply_replaces_membership_and_marks_missing(rig):
    t1 = await _target(rig, "r1")
    t2 = await _target(rig, "", source="vco")
    async with rig.repo.transaction() as tx:
        await tx.stage_publication("s1", parent_snapshot_key=None, now=NOW)
        await tx.stage_target("s1", t1.id, authority=Authority.COMPLETE, succeeded=True, attempted_at=NOW)
        await tx.stage_target("s1", t2.id, authority=Authority.COMPLETE, succeeded=True, attempted_at=NOW)
        await tx.stage_observations(
            "s1",
            [
                StagedObservation(t1.id, "dev:a", hostname="a"),
                StagedObservation(t2.id, "dev:a", hostname="a", reported_location_handle=rig.location_handle),
                StagedObservation(t2.id, "dev:b", hostname="b", notes={"warning": "keyed by the VS name"}),
            ],
        )
        with pytest.raises(Conflict):  # not published yet
            await tx.apply_publication("s1", NOW)
        await tx.mark_published("s1", NOW)
    async with rig.repo.transaction() as tx:
        report = await tx.apply_publication("s1", NOW)
        assert len(report.registered_device_ids) == 2 and report.observations_written == 3
        state = await tx.get_state()
        assert state.read_model_snapshot_key == "s1"
        a = await tx.get_device_by_graph_uid("dev:a")
        b = await tx.get_device_by_graph_uid("dev:b")
        assert {o.target_id for o in await tx.get_observations(a.id)} == {
            t1.id,
            t2.id,
        }  # one device, two observers
        (ob,) = await tx.get_observations(b.id)
        assert ob.notes == {"warning": "keyed by the VS name"} and ob.authority == "complete"
        assert (await tx.get_publication("s1")).state == PublicationState.APPLIED.value
        with pytest.raises(Conflict):
            await tx.apply_publication("s1", NOW)
    # Second run: t2 complete and empty retires its claims; t1 partial keeps a stale claim.
    async with rig.repo.transaction() as tx:
        await tx.stage_publication("s2", parent_snapshot_key="s1", now=LATER)
        await tx.stage_target("s2", t1.id, authority=Authority.PARTIAL, succeeded=True, attempted_at=LATER)
        await tx.stage_target("s2", t2.id, authority=Authority.COMPLETE, succeeded=True, attempted_at=LATER)
        await tx.mark_published("s2", LATER)
        report = await tx.apply_publication("s2", LATER)
    async with rig.repo.transaction() as tx:
        assert report.missing_device_ids == [b.id] and report.observations_retired == 2
        assert (await tx.get_device(b.id)).lifecycle == Lifecycle.MISSING.value
        a_obs = {o.target_id: o.state for o in await tx.get_observations(a.id)}
        assert a_obs == {t1.id: ObservationState.STALE.value, t2.id: ObservationState.ABSENT.value}
        assert (
            await tx.get_device(a.id)
        ).lifecycle == Lifecycle.ACTIVE.value  # stale evidence is not missing
    # Reappearance restores active; an archived device stays archived.
    async with rig.repo.transaction() as tx:
        await tx.set_lifecycle(a.id, Lifecycle.ARCHIVED, expected_revision=1, now=LATER)
        await tx.stage_publication("s3", parent_snapshot_key="s2", now=LATER + timedelta(minutes=1))
        await tx.stage_target("s3", t2.id, authority=Authority.COMPLETE, succeeded=True, attempted_at=LATER)
        await tx.stage_observations(
            "s3", [StagedObservation(t2.id, "dev:a"), StagedObservation(t2.id, "dev:b")]
        )
        await tx.mark_published("s3", LATER)
        report = await tx.apply_publication("s3", LATER + timedelta(minutes=1))
        assert report.reappeared_device_ids == [b.id]
        assert (await tx.get_device(b.id)).lifecycle == Lifecycle.ACTIVE.value
        assert (await tx.get_device(a.id)).lifecycle == Lifecycle.ARCHIVED.value


async def test_older_publication_cannot_overwrite_a_newer_applied_one(rig):
    t1 = await _target(rig)
    async with rig.repo.transaction() as tx:
        await tx.stage_publication("old", parent_snapshot_key=None, now=NOW)
        await tx.stage_target("old", t1.id, authority=Authority.COMPLETE, succeeded=True, attempted_at=NOW)
        await tx.stage_observations("old", [StagedObservation(t1.id, "dev:old")])
        await tx.mark_published("old", NOW)
        await tx.stage_publication("new", parent_snapshot_key=None, now=LATER)
        await tx.stage_target("new", t1.id, authority=Authority.COMPLETE, succeeded=True, attempted_at=LATER)
        await tx.stage_observations("new", [StagedObservation(t1.id, "dev:new")])
        await tx.mark_published("new", LATER)
        await tx.apply_publication("new", LATER)
        with pytest.raises(Conflict):
            await tx.apply_publication("old", LATER)
        assert await tx.get_device_by_graph_uid("dev:old") is None
        aborted = await tx.abort_publication("old", LATER)
        assert aborted.state == PublicationState.ABORTED.value
        assert (await tx.get_state()).read_model_snapshot_key == "new"


async def test_apply_writes_captured_placement_revisions(rig):
    device = await _device(rig)
    async with rig.repo.transaction() as tx:
        placement = await tx.set_placement(
            device.id,
            mode=PlacementMode.ASSIGNED,
            site_id=rig.site_ids["fra"],
            origin="manual",
            expected_revision=0,
            actor_id=None,
            now=NOW,
        )
        await tx.stage_publication("s1", parent_snapshot_key=None, now=NOW)
        await tx.set_placement_revisions(
            "s1", {str(device.id): {"revision": placement.revision, "site_id": rig.site_ids["fra"]}}
        )
        # A concurrent edit after capture stays pending: revision 2 is not covered by s1.
        await tx.set_placement(
            device.id,
            mode=PlacementMode.UNPLACED,
            site_id=None,
            origin="manual",
            expected_revision=1,
            actor_id=None,
            now=LATER,
        )
        await tx.mark_published("s1", NOW)
        report = await tx.apply_publication("s1", LATER)
        assert report.placements_applied == 1
        after = await tx.get_placement(device.id)
        assert after.revision == 2 and after.applied_revision == 1
        assert after.published_site_id == rig.site_ids["fra"] and after.published_snapshot_key == "s1"


# --- placements and locations ------------------------------------------------------------------


async def test_placement_check_and_site_release(rig):
    device = await _device(rig)
    async with rig.repo.transaction() as tx:
        with pytest.raises(InventoryError):
            await tx.set_placement(
                device.id,
                mode=PlacementMode.ASSIGNED,
                site_id=None,
                origin="manual",
                expected_revision=0,
                actor_id=None,
                now=NOW,
            )
        with pytest.raises(StaleRevision):  # a first write must state revision 0
            await tx.set_placement(
                device.id,
                mode=PlacementMode.AUTO,
                site_id=None,
                origin="manual",
                expected_revision=1,
                actor_id=None,
                now=NOW,
            )
        await tx.set_placement(
            device.id,
            mode=PlacementMode.ASSIGNED,
            site_id=rig.site_ids["ams"],
            origin="onboarding",
            expected_revision=0,
            actor_id=None,
            now=NOW,
        )
        released = await tx.release_site_placements(rig.site_ids["ams"], actor_id=None, now=LATER)
        assert released == [device.id]
        pl = await tx.get_placement(device.id)
        assert pl.mode == "unplaced" and pl.site_id is None and pl.revision == 2


async def test_location_binding_by_handle_with_revision(rig):
    async with rig.repo.transaction() as tx:
        loc = await tx.get_location(rig.location_handle)
        assert loc.source == "vco" and loc.location_id == "site-7" and loc.revision == 1
        bound = await tx.bind_location(rig.location_handle, "fra", expected_revision=1, now=NOW)
        assert bound.site == "fra" and bound.revision == 2
        with pytest.raises(StaleRevision):
            await tx.bind_location(rig.location_handle, None, expected_revision=1, now=NOW)
        with pytest.raises(NotFound):
            await tx.bind_location(rig.location_handle, "nowhere", expected_revision=2, now=NOW)
        assert await tx.unbind_site_locations("fra", LATER) == [rig.location_handle]
        assert (await tx.get_location(rig.location_handle)).site is None


async def test_batched_reads_match_the_per_row_reads(rig):
    t1, t2 = await _target(rig, "r1"), await _target(rig, "r2")
    a, b = await _device(rig, "dev:a", "a"), await _device(rig, "dev:b", "b")
    async with rig.repo.transaction() as tx:
        await tx.upsert_observation(t1.id, a.id, now=NOW)
        await tx.upsert_observation(t1.id, b.id, now=NOW)
        await tx.upsert_observation(t2.id, b.id, now=NOW)
    async with rig.repo.transaction() as tx:
        by_target = await tx.list_observations_for_targets([t1.id, t2.id, uuid.uuid4()])
        assert set(by_target) == {t1.id, t2.id}
        for target in (t1, t2):
            assert by_target[target.id] == await tx.list_observations(target.id)
        found = await tx.get_devices_by_graph_uids(["dev:a", "dev:b", "dev:none"])
        assert {d.graph_uid: d.id for d in found} == {"dev:a": a.id, "dev:b": b.id}
        assert await tx.list_observations_for_targets([]) == {}
        assert await tx.get_devices_by_graph_uids([]) == []


# --- archive primitives ------------------------------------------------------------------------


async def test_source_archive_keeps_devices_placements_events_and_source_key(rig):
    t1 = await _target(rig, "r1")
    device = await _device(rig)
    async with rig.repo.transaction() as tx:
        await tx.upsert_observation(t1.id, device.id, now=NOW)
        await tx.set_placement(
            device.id,
            mode=PlacementMode.UNPLACED,
            site_id=None,
            origin="manual",
            expected_revision=0,
            actor_id=None,
            now=NOW,
        )
        await tx.append_event(
            entity_type="target", entity_id=str(t1.id), actor_id=None, action="create", now=NOW
        )
        archived = await tx.archive_source_targets(rig.source_ids["vyos-lab"], LATER)
    async with rig.repo.transaction() as tx:
        (row,) = archived
        assert row.archived_at == LATER and row.source_id is None and row.source_key == "vyos-lab"
        stored = await tx.get_target(t1.id)
        assert stored.source_id is None and stored.source_key == "vyos-lab" and stored.enabled is False
        (obs,) = await tx.get_observations(device.id)
        assert obs.state == ObservationState.ABSENT.value
        assert (await tx.get_device(device.id)).id == device.id
        assert (await tx.get_placement(device.id)).mode == "unplaced"
        events, _ = await tx.page_events(entity_type="target", entity_id=str(t1.id))
        assert len(events) == 1


# --- saved views and routing groups ------------------------------------------------------------------


async def test_saved_views_are_owner_scoped(rig):
    async with rig.repo.transaction() as tx:
        view = await tx.create_view(
            owner_id=rig.user_id,
            name="mine",
            filter={"lifecycle": ["missing"]},
            sort="name",
            direction="asc",
            columns=["name", "site"],
            now=NOW,
        )
        with pytest.raises(Conflict):
            await tx.create_view(
                owner_id=rig.user_id,
                name="mine",
                filter={},
                sort="name",
                direction="asc",
                columns=[],
                now=NOW,
            )
        assert await tx.get_view(view.id, rig.user_id + 1) is None  # foreign: absent, never forbidden
        with pytest.raises(NotFound):
            await tx.update_view(view.id, rig.user_id + 1, expected_revision=1, now=NOW, name="stolen")
        assert await tx.delete_view(view.id, rig.user_id + 1) is False
        updated = await tx.update_view(view.id, rig.user_id, expected_revision=1, now=NOW, name="renamed")
        assert updated.revision == 2 and updated.filter == {"lifecycle": ["missing"]}
        assert [v.name for v in await tx.list_views(rig.user_id)] == ["renamed"]
        assert await tx.delete_view(view.id, rig.user_id) is True


async def test_routing_group_membership_is_explicit_and_revisioned(rig):
    async with rig.repo.transaction() as tx:
        group = await tx.create_routing_group(display_name="core", description="", now=NOW)
        with pytest.raises(Conflict):
            await tx.create_routing_group(display_name="core", description="", now=NOW)
        g2 = await tx.set_routing_members(
            group.id,
            expected_revision=1,
            add=[("vrf:a", "dev:1"), ("vrf:b", "dev:2")],
            remove=[],
            actor_id=rig.user_id,
            now=NOW,
        )
        assert g2.revision == 2
        with pytest.raises(StaleRevision):
            await tx.set_routing_members(
                group.id, expected_revision=1, add=[], remove=["vrf:a"], actor_id=None, now=NOW
            )
        g3 = await tx.set_routing_members(
            group.id, expected_revision=2, add=[("vrf:a", "dev:1")], remove=["vrf:b"], actor_id=None, now=NOW
        )
        assert g3.revision == 3
        assert [m.context_uid for m in await tx.list_routing_members(group.id)] == ["vrf:a"]
        by_ctx = await tx.groups_for_contexts(["vrf:a", "vrf:b"])
        assert list(by_ctx) == ["vrf:a"] and by_ctx["vrf:a"][0].id == group.id
        await tx.archive_routing_group(group.id, expected_revision=3, now=LATER)
        assert await tx.list_routing_groups() == []
        assert await tx.groups_for_contexts(["vrf:a"]) == {}


# --- device list ---------------------------------------------------------------------------------------


async def _seed_fleet(rig: Rig) -> dict[str, uuid.UUID]:
    t1 = await _target(rig, "r1")
    t2 = await _target(rig, "", source="vco")
    ids = {}
    async with rig.repo.transaction() as tx:
        for i, (uid, host, platform, state) in enumerate(
            [
                ("dev:a", "alpha", "vyos", "current"),
                ("dev:b", "Bravo", "nxos", "failed"),
                ("dev:c", "charlie", "vyos", "current"),
                ("dev:d", "delta", "velocloud", "never"),
            ]
        ):
            device, _ = await tx.register_device(
                uid,
                hostname=host,
                platform=platform,
                management_address=f"10.0.0.{i}",
                snapshot_key="s1",
                now=NOW,
            )
            ids[host.lower()] = device.id
            await tx.set_device_summary(
                device.id,
                now=NOW,
                collection_state=state,
                last_success_at=NOW - timedelta(minutes=i) if state == "current" else None,
                resolved_site_id=rig.site_ids["fra"] if host in ("alpha", "delta") else None,
                placement_state="assigned" if host in ("alpha", "delta") else "unplaced",
            )
            await tx.upsert_observation(t2.id if platform == "velocloud" else t1.id, device.id, now=NOW)
        await tx.upsert_observation(t2.id, ids["alpha"], now=NOW, authority=Authority.PARTIAL)
        await tx.set_lifecycle(ids["charlie"], Lifecycle.ARCHIVED, expected_revision=1, now=NOW)
        await tx.advance_read_model("s1", NOW)
    return ids


async def test_list_filters_sorts_and_hides_archived_by_default(rig):
    ids = await _seed_fleet(rig)
    async with rig.repo.transaction() as tx:
        page = await tx.list_devices(DeviceFilters())
        assert [i.device.hostname for i in page.items] == ["alpha", "Bravo", "delta"]
        assert page.next_cursor is None and page.state.read_model_snapshot_key == "s1"
        alpha = page.items[0]
        assert alpha.site_code == "fra"
        assert [(c.source_key, c.authority) for c in alpha.connections] == [
            ("vco", "partial"),
            ("vyos-lab", "complete"),
        ]
        assert [
            i.device.hostname for i in (await tx.list_devices(DeviceFilters(lifecycles=["archived"]))).items
        ] == ["charlie"]
        assert [i.device.hostname for i in (await tx.list_devices(DeviceFilters(q="ALP"))).items] == ["alpha"]
        assert [i.device.hostname for i in (await tx.list_devices(DeviceFilters(q="10.0.0.3"))).items] == [
            "delta"
        ]
        assert [i.device.hostname for i in (await tx.list_devices(DeviceFilters(q="dev:b"))).items] == [
            "Bravo"
        ]
        assert [
            i.device.hostname
            for i in (await tx.list_devices(DeviceFilters(site_ids=[rig.site_ids["fra"]]))).items
        ] == ["alpha", "delta"]
        assert [
            i.device.hostname
            for i in (await tx.list_devices(DeviceFilters(platforms=["nxos", "velocloud"]))).items
        ] == ["Bravo", "delta"]
        assert [
            i.device.hostname
            for i in (await tx.list_devices(DeviceFilters(collection_states=["failed"]))).items
        ] == ["Bravo"]
        assert [
            i.device.hostname
            for i in (await tx.list_devices(DeviceFilters(placement_states=["unplaced"]))).items
        ] == ["Bravo"]
        assert [
            i.device.hostname
            for i in (await tx.list_devices(DeviceFilters(source_ids=[rig.source_ids["vco"]]))).items
        ] == ["alpha", "delta"]
        by_site = await tx.list_devices(DeviceFilters(), sort=SortField.SITE, direction=SortDirection.DESC)
        # the two at "fra" tie and fall back to the id tie-breaker; the unplaced one sorts last
        assert {i.device.hostname for i in by_site.items[:2]} == {"alpha", "delta"}
        assert by_site.items[-1].device.hostname == "Bravo"
        by_success = await tx.list_devices(
            DeviceFilters(), sort=SortField.LAST_SUCCESS, direction=SortDirection.DESC
        )
        # never-collected devices sort as the oldest instant, so they come last
        assert by_success.items[0].device.id == ids["alpha"]
        assert {i.device.hostname for i in by_success.items[1:]} == {"Bravo", "delta"}


async def test_list_cursor_pages_and_is_refused_after_an_intent_write(rig):
    ids = await _seed_fleet(rig)
    async with rig.repo.transaction() as tx:
        first = await tx.list_devices(DeviceFilters(), limit=2)
        assert [i.device.hostname for i in first.items] == ["alpha", "Bravo"] and first.next_cursor
        second = await tx.list_devices(DeviceFilters(), limit=2, cursor=first.next_cursor)
        assert [i.device.hostname for i in second.items] == ["delta"] and second.next_cursor is None
        with pytest.raises(InventoryError):  # same generation, different sort: not this cursor's page
            await tx.list_devices(DeviceFilters(), limit=2, cursor=first.next_cursor, sort=SortField.PLATFORM)
        with pytest.raises(InventoryError):
            await tx.list_devices(DeviceFilters(), limit=2, cursor="not-a-cursor")
        desc = await tx.list_devices(
            DeviceFilters(), limit=2, sort=SortField.LAST_SUCCESS, direction=SortDirection.DESC
        )
        rest = await tx.list_devices(
            DeviceFilters(),
            limit=2,
            sort=SortField.LAST_SUCCESS,
            direction=SortDirection.DESC,
            cursor=desc.next_cursor,
        )
        assert {i.device.id for i in desc.items} | {i.device.id for i in rest.items} == {
            ids["alpha"],
            ids["bravo"],
            ids["delta"],
        }
        await tx.set_placement(
            ids["bravo"],
            mode=PlacementMode.AUTO,
            site_id=None,
            origin="manual",
            expected_revision=0,
            actor_id=None,
            now=NOW,
        )
        with pytest.raises(InventoryChanged) as exc:
            await tx.list_devices(DeviceFilters(), limit=2, cursor=first.next_cursor)
        assert exc.value.code.value == "inventory_changed" and exc.value.status == 409
        empty = await tx.list_devices(DeviceFilters(q="nothing-matches"))
        assert empty.items == [] and empty.state.intent_generation == (await tx.get_state()).intent_generation


async def test_source_inventory_columns_and_activation_state(rig):
    async with rig.repo.transaction() as tx:
        prof, _ = await tx.create_profile(
            display_name="p",
            collector_type="vyos",
            settings={},
            credential_id=None,
            credential_revision=None,
            actor_id=None,
            now=NOW,
        )
        src = await tx.get_source_inventory(rig.source_ids["vyos-lab"])
        assert src.display_name == "" and src.inventory_revision == 1 and src.frozen_normalization is None
        updated = await tx.update_source_inventory(
            src.source_id,
            expected_revision=1,
            now=NOW,
            display_name="Lab routers",
            default_profile_id=prof.id,
        )
        assert updated.inventory_revision == 2 and updated.default_profile_id == prof.id
        with pytest.raises(Conflict):
            await tx.update_source_inventory(
                src.source_id, expected_revision=2, now=NOW, default_profile_id=uuid.uuid4()
            )
        frozen = await tx.set_frozen_normalization(
            src.source_id, {"routing_scope": {"value": "home", "origin": "site_code"}}, NOW
        )
        assert frozen.inventory_revision == 2  # freezing is migration, not an edit
        assert (await tx.get_source_inventory_by_key("vyos-lab")).frozen_normalization["routing_scope"][
            "origin"
        ] == "site_code"
        refs = await tx.profile_references(prof.id)
        assert refs.source_ids == [src.source_id]
        state = await tx.get_state()
        assert state.resolver_version == 1 and state.activation_state == "inactive"
        active = await tx.activate(resolver_version=2, schema_version=1, backfill_version=1, now=LATER)
        assert active.resolver_version == 2 and active.activation_state == "active"
        assert (await tx.set_sync_pending(True, LATER)).inventory_sync_pending is True


# --- redaction backstops beyond events (redacted impact, response, payload) -----------------------


async def test_preview_changes_and_impact_are_masked_by_key(rig):
    async with rig.repo.transaction() as tx:
        preview = await tx.create_preview(
            actor_id=rig.user_id,
            operation="rotate_credential",
            permissions=["sources.write"],
            intent_generation=1,
            snapshot_key=None,
            members=[{"kind": "credential", "id": "c1", "revision": 2}],
            changes={"display_name": "lab", "secrets": {"password": "plain", "username": "u"}},
            impact={"targets": [{"host": "h1", "token": "bearer-x"}], "devices": 3},
            secret_draft=b"sealed",
            now=NOW,
            ttl=timedelta(minutes=10),
        )
    assert preview.changes == {"display_name": "lab", "secrets": {"password": REDACTED, "username": "u"}}
    assert preview.impact == {"targets": [{"host": "h1", "token": REDACTED}], "devices": 3}
    async with rig.repo.transaction() as tx:
        stored = await tx.get_preview(preview.token, rig.user_id, NOW)
        assert stored.changes["secrets"]["password"] == REDACTED
        assert stored.impact["targets"][0]["token"] == REDACTED
        assert stored.members == [{"kind": "credential", "id": "c1", "revision": 2}]


async def test_operation_result_response_is_masked_but_keeps_the_preview_token(rig):
    token = str(uuid.uuid4())
    response = {
        "token": token,
        "status": "applied",
        "results": [{"kind": "credential", "id": "c1", "revision": 3, "password": "leak"}],
    }
    async with rig.repo.transaction() as tx:
        rec = await tx.record_operation_result(
            actor_id=rig.user_id,
            idempotency_key="k-redact",
            request_digest="digest-a",
            status=200,
            response=response,
            now=NOW,
        )
    expected = {
        "token": token,
        "status": "applied",
        "results": [{"kind": "credential", "id": "c1", "revision": 3, "password": REDACTED}],
    }
    assert rec.response == expected
    async with rig.repo.transaction() as tx:
        again = await tx.check_idempotency(rig.user_id, "k-redact", "digest-a")
        assert again.response == expected
        # A bearer-shaped token is not a preview reference and is masked.
        other = await tx.record_operation_result(
            actor_id=rig.user_id,
            idempotency_key="k-bearer",
            request_digest="digest-b",
            status=200,
            response={"token": "eyJhbGciOi.bearer", "ok": True},
            now=NOW,
        )
        assert other.response == {"token": REDACTED, "ok": True}


async def test_outbox_payload_is_masked_by_key(rig):
    async with rig.repo.transaction() as tx:
        item = await tx.enqueue_outbox(
            kind="job_enqueue",
            dedup_key="job:redact",
            payload={"target_id": "t1", "auth": {"password": "plain"}, "note": "x"},
            now=NOW,
        )
    assert item.payload == {"target_id": "t1", "auth": {"password": REDACTED}, "note": "x"}
    async with rig.repo.transaction() as tx:
        (claimed,) = await tx.claim_outbox("w1", now=NOW, lease=timedelta(minutes=5))
        assert claimed.payload == {"target_id": "t1", "auth": {"password": REDACTED}, "note": "x"}


async def test_delete_view_checks_the_expected_revision(rig):
    async with rig.repo.transaction() as tx:
        view = await tx.create_view(
            owner_id=rig.user_id, name="v", filter={}, sort="name", direction="asc", columns=[], now=NOW
        )
        await tx.update_view(view.id, rig.user_id, expected_revision=1, now=NOW, name="v2")
        with pytest.raises(StaleRevision) as exc:
            await tx.delete_view(view.id, rig.user_id, expected_revision=1)
        assert exc.value.current_revision == 2
        # A foreign owner is absent, never a revision conflict.
        assert await tx.delete_view(view.id, rig.user_id + 1, expected_revision=2) is False
        assert await tx.delete_view(view.id, rig.user_id, expected_revision=2) is True
        assert await tx.get_view(view.id, rig.user_id) is None
