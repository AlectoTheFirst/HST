"""Credentials: sealed drafts, rotation, repair and redaction. No plaintext in any response, event, preview,
impact row or error; a rotation re-pins every affected profile in one
transaction; an unreadable version blocks collection until repaired and is
never an empty success. The last test runs the same flow on Postgres.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from tests.app.conftest import PASSWORD, login
from tests.app.test_inventory_collection import (
    NOW,
    VYOS_SECRETS,
    VYOS_SETTINGS,
    FakeCollector,
    activate,
    make_client,
    make_store,
    other_data_key,
    seed_credential,
    seed_profile,
    settings_for,
)
from tests.app.test_inventory_profiles import _apply, _connection, _preview, _target

from hst.app import sources as glue
from hst.app.crypto import dek, encrypt_secrets
from hst.app.inventory import credentials
from hst.app.inventory.connection_routes import register
from hst.app.security import hash_password

API = "/api/inventory"
DSN = os.environ.get("HST_TEST_PG_DSN")


async def test_a_credential_is_write_only_and_its_event_is_redacted(tmp_path):
    store = await make_store()
    settings = settings_for(tmp_path)
    await activate(store)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        r = await client.post(
            f"{API}/credentials", json={"display_name": "lab", "secrets": {"auth.password": "hunter2"}}
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["secret_paths"] == ["auth.password"] and body["current_revision"] == 1
        assert "hunter2" not in r.text
        assert (
            await client.post(
                f"{API}/credentials", json={"display_name": "lab", "secrets": {"auth.password": "x"}}
            )
        ).status_code == 409
        empty = await client.post(
            f"{API}/credentials", json={"display_name": "e", "secrets": {"auth.password": ""}}
        )
        assert empty.status_code == 422
        listed = (await client.get(f"{API}/credentials")).json()
        assert [c["id"] for c in listed] == [body["id"]] and "hunter2" not in str(listed)
    async with store.inventory().transaction() as tx:
        events, _ = await tx.page_events(entity_type="credential", entity_id=body["id"])
        assert events[0].action == "created" and events[0].sensitive
        assert events[0].after == {"display_name": "lab", "secrets": {"auth.password": "***"}}
        version = await tx.get_credential_version(uuid.UUID(body["id"]), 1)
        assert b"hunter2" not in version.sealed
        assert credentials.open_sealed(dek(settings), version) == {"auth.password": "hunter2"}


def test_secret_maps_are_validated_against_the_classification():
    assert credentials.validate_secret_map(["vyos"], {"auth.password": "x"}) == {"auth.password": "x"}
    with pytest.raises(credentials.SecretsRejected) as exc:
        credentials.validate_secret_map(["vyos"], {"auth.username": "u"})
    assert "not a credential field of vyos" in str(exc.value)
    with pytest.raises(credentials.SecretsRejected):
        credentials.validate_secret_map(["vyos"], {"auth.password": ""})
    with pytest.raises(credentials.SecretsRejected):
        credentials.validate_secret_map(["vyos"], {})
    with pytest.raises(credentials.SecretsRejected):
        credentials.validate_secret_map(["velocloud"], {"auth.password": "x"})
    assert credentials.validate_secret_map((), {"auth.key": "k"}) == {"auth.key": "k"}


def test_drafts_are_bound_to_actor_and_preview_and_digests_are_keyed():
    key = other_data_key()
    # Punctuation outside the base64 alphabet prevents accidental ciphertext
    # matches; a two-character secret can occur randomly in a Fernet token.
    password = "draft-password:not-plaintext!"
    secrets = {"auth.password": password}
    draft = credentials.seal_draft(key, 7, secrets, hint="t1")
    assert password.encode() not in draft
    assert credentials.open_draft(key, 7, draft, hint="t1") == secrets
    with pytest.raises(ValueError):
        credentials.open_draft(key, 8, draft, hint="t1")
    with pytest.raises(ValueError):
        credentials.open_draft(key, 7, draft, hint="t2")
    with pytest.raises(ValueError):
        credentials.open_draft(other_data_key(), 7, draft, hint="t1")
    a = credentials.request_digest(key, {"token": "x", "secrets": secrets})
    b = credentials.request_digest(other_data_key(), {"token": "x", "secrets": secrets})
    assert a != b and password not in a and len(a) == 64


async def _rotation_rig(tmp_path):
    store = await make_store()
    settings = settings_for(tmp_path)
    await activate(store)
    cred = await seed_credential(store, settings, VYOS_SECRETS)
    p1 = await seed_profile(store, "p1", "vyos", VYOS_SETTINGS, cred)
    p2 = await seed_profile(store, "p2", "vyos", {**VYOS_SETTINGS, "interval_s": 5}, cred)
    return store, settings, cred, p1, p2


async def test_rotation_previews_every_affected_profile_target_and_device_and_repins_in_one_apply(tmp_path):
    store, settings, cred, p1, p2 = await _rotation_rig(tmp_path)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        conn = await _connection(client, profile_id=p1.id)
        t1 = await _target(client, conn["id"], "r1")
        t2 = await _target(client, conn["id"], "r2", profile_id=str(p2.id))
        async with store.inventory().transaction() as tx:
            a, _ = await tx.register_device(
                "dev:x:a", hostname="a", platform="", management_address="", snapshot_key=None, now=NOW
            )
            await tx.upsert_observation(uuid.UUID(t2["id"]), a.id, now=NOW)
        preview = await _preview(
            client,
            "rotate_credential",
            [str(cred.id)],
            {"secrets": {"auth.password": "n3w-pw"}, "expected_revision": 1},
        )
        assert "n3w-pw" not in str(preview)
        assert preview["changes"]["secrets"] == {"auth.password": "***"}
        assert {(m["kind"], m["id"]) for m in preview["members"]} == {
            ("credential", str(cred.id)),
            ("profile", str(p1.id)),
            ("profile", str(p2.id)),
        }
        assert preview["affected_target_count"] == 2 and preview["affected_device_count"] == 1
        impact = (
            await client.get(f"{API}/operations/previews/{preview['token']}/impact", params={"limit": 200})
        ).json()
        assert "n3w-pw" not in str(impact)
        assert sorted(i["kind"] for i in impact["items"]) == [
            "connection",
            "device",
            "profile",
            "profile",
            "target",
            "target",
        ]
        applied = await _apply(client, preview["token"], key="rot1")
        assert applied["results"][0] == {"kind": "credential", "id": str(cred.id), "revision": 2}
        assert {(r["id"], r["revision"]) for r in applied["results"][1:]} == {
            (str(p1.id), 2),
            (str(p2.id), 2),
        }
        for t in (t1, t2):
            eff = (await client.get(f"{API}/targets/{t['id']}/effective")).json()
            assert eff["credential_revision"] == 2 and eff["profile_revision"] == 2
        assert (await client.get(f"{API}/credentials/{cred.id}")).json()["profiles_using"] == 2
    async with store.inventory().transaction() as tx:
        version = await tx.get_credential_version(cred.id, 2)
        assert credentials.open_sealed(dek(settings), version) == {"auth.password": "n3w-pw"}
        v1 = await tx.get_profile_version(p1.id, 2)
        assert v1.settings == VYOS_SETTINGS and v1.credential_revision == 2
        for entity in ("credential", "profile"):
            events, _ = await tx.page_events(entity_type=entity)
            assert "n3w-pw" not in str([(e.before, e.after) for e in events])
        preview_row = tx.t.previews[uuid.UUID(preview["token"])]
        assert preview_row.secret_draft is None and preview_row.consumed_at is not None


async def test_a_stale_profile_between_preview_and_apply_rolls_the_whole_rotation_back(tmp_path):
    store, settings, cred, p1, p2 = await _rotation_rig(tmp_path)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        preview = await _preview(
            client,
            "rotate_credential",
            [str(cred.id)],
            {"secrets": {"auth.password": "n3w"}, "expected_revision": 1},
        )
        # p2 moves on: its captured revision is stale
        r = await client.patch(
            f"{API}/profiles/{p2.id}",
            json={"settings": {**VYOS_SETTINGS, "interval_s": 9}, "expected_revision": 1},
        )
        assert r.status_code == 200
        r = await client.post(
            f"{API}/operations/apply", json={"token": preview["token"], "idempotency_key": "rot2"}
        )
        assert r.status_code == 409 and r.json()["code"] == "stale_revision"
        assert (await client.get(f"{API}/credentials/{cred.id}")).json()["current_revision"] == 1
        assert (await client.get(f"{API}/profiles/{p1.id}")).json()["current_revision"] == 1
        assert (await client.get(f"{API}/profiles/{p2.id}")).json()["current_revision"] == 2


async def test_direct_rotation_is_for_an_unshared_credential_only(tmp_path):
    store, settings, cred, p1, p2 = await _rotation_rig(tmp_path)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        r = await client.patch(
            f"{API}/credentials/{cred.id}", json={"secrets": {"auth.password": "x"}, "expected_revision": 1}
        )
        assert r.status_code == 409 and sorted(r.json()["references"]) == sorted(
            [f"profile:{p1.id}", f"profile:{p2.id}"]
        )
        solo = await seed_credential(store, settings, {"auth.password": "one"}, name="solo")
        p3 = await seed_profile(store, "p3", "vyos", VYOS_SETTINGS, solo)
        r = await client.patch(
            f"{API}/credentials/{solo.id}", json={"secrets": {"auth.password": "two"}, "expected_revision": 1}
        )
        assert r.status_code == 200 and r.json()["current_revision"] == 2 and "two" not in r.text
        assert (await client.get(f"{API}/profiles/{p3.id}")).json()["credential_revision"] == 2
        wrong = await client.patch(
            f"{API}/credentials/{solo.id}", json={"secrets": {"auth.username": "u"}, "expected_revision": 2}
        )
        assert wrong.status_code == 422
        # rename only: no new version
        r = await client.patch(
            f"{API}/credentials/{solo.id}", json={"display_name": "solo2", "expected_revision": 2}
        )
        assert (
            r.status_code == 200 and r.json()["current_revision"] == 2 and r.json()["display_name"] == "solo2"
        )
        # delete: 409 while pinned
        r = await client.delete(f"{API}/credentials/{solo.id}", params={"expected_revision": 2})
        assert r.status_code == 409 and r.json()["references"] == [f"profile:{p3.id}"]


async def test_an_unreadable_credential_never_probes_as_an_empty_success_and_repairs_by_rotation(
    tmp_path, monkeypatch
):
    store = await make_store()
    settings = settings_for(tmp_path)
    await activate(store)
    async with store.inventory().transaction() as tx:
        cred, _ = await tx.create_credential(
            display_name="old-key",
            sealed=encrypt_secrets(other_data_key(), VYOS_SECRETS),
            secret_paths=sorted(VYOS_SECRETS),
            actor_id=None,
            now=NOW,
        )
    profile = await seed_profile(store, "p", "vyos", VYOS_SETTINGS, cred)
    probes: list[dict] = []

    def build_device(row, device, settings_, **kw):
        probes.append(kw["effective"].payload)
        return FakeCollector(kw["effective"].payload)

    monkeypatch.setattr(glue, "build_device_collector", build_device)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        conn = await _connection(client, profile_id=profile.id)
        t1 = await _target(client, conn["id"], "r1")
        r = await client.post(f"{API}/targets/{t1['id']}/probe", json={})
        assert r.status_code == 200, r.text
        assert (
            r.json()["ok"] is False
            and "repair" in r.json()["message"]
            and str(cred.id) in r.json()["message"]
        )
        assert probes == [], "no collector is built on an unreadable credential"
        eff = await client.get(f"{API}/targets/{t1['id']}/effective")
        assert eff.status_code == 200 and eff.json()["credential_revision"] == 1
        async with store.inventory().transaction() as tx:
            version = await tx.get_credential_version(cred.id, 1)
            assert not credentials.is_readable(dek(settings), version)
        # repair: the complete map as a new version; the old ciphertext stays
        r = await client.patch(
            f"{API}/credentials/{cred.id}",
            json={"secrets": {"auth.password": "fresh"}, "expected_revision": 1},
        )
        assert r.status_code == 200 and r.json()["current_revision"] == 2
        r = await client.post(f"{API}/targets/{t1['id']}/probe", json={})
        assert r.json()["ok"] and r.json()["effective"]["credential_revision"] == 2
        assert probes[0]["auth"]["password"] == "fresh" and "fresh" not in r.text
        async with store.inventory().transaction() as tx:
            old = await tx.get_credential_version(cred.id, 1)
            assert old is not None and not credentials.is_readable(dek(settings), old)


@pytest.mark.pg
@pytest.mark.skipif(not DSN, reason="HST_TEST_PG_DSN not set")
async def test_rotation_and_execution_records_on_postgres(tmp_path, monkeypatch):
    """The same rotation over PgStore: the legacy `sources` and `devices`
    rows are written on the repository's connection, and a rotation writes
    the credential version and both profile revisions in one transaction."""
    from sqlalchemy.ext.asyncio import create_async_engine

    from hst.app.store.pg import PgStore, metadata, upgrade_to_head

    await asyncio.to_thread(upgrade_to_head, DSN)
    engine = create_async_engine(DSN)
    async with engine.begin() as conn:
        for table in reversed(metadata.sorted_tables):
            await conn.execute(table.delete())
    await engine.dispose()
    store = PgStore(DSN)
    try:
        for name, role in (("otto", "operator"), ("ada", "admin")):
            await store.create_user(name, hash_password(PASSWORD), role)
        settings = settings_for(tmp_path)
        async with store.inventory().transaction() as tx:
            await tx.activate(resolver_version=2, schema_version=1, backfill_version=1, now=NOW)
        cred = await seed_credential(store, settings, VYOS_SECRETS)
        p1 = await seed_profile(store, "p1", "vyos", VYOS_SETTINGS, cred)
        p2 = await seed_profile(store, "p2", "vyos", {**VYOS_SETTINGS, "interval_s": 5}, cred)
        async with make_client(store, settings) as client:
            await login(client, "ada")
            conn = await _connection(client, profile_id=p1.id)
            t1 = await _target(client, conn["id"], "r1", port=2202)
            assert t1["port"] == 2202 and t1["legacy_device_id"] is not None
            t2 = await _target(client, conn["id"], "r2", profile_id=str(p2.id))
            renamed = await client.patch(
                f"{API}/connections/{conn['id']}",
                json={"enabled": False, "expected_revision": conn["revision"]},
            )
            assert renamed.status_code == 200 and renamed.json()["enabled"] is False
            assert (await store.get_source("lab")).enabled is False
            rows = await store.list_devices("lab")
            assert [(d.host, d.port) for d in rows] == [("r1", 2202), ("r2", None)]
            src = await store.get_source("lab")
            assert src is not None and src.enabled is False
            [ct] = [t for t in (await client.get(f"{API}/targets")).json() if t["id"] == t1["id"]]
            assert ct["enabled"] is True, "a direct target keeps its own switch"
            preview = await _preview(
                client,
                "rotate_credential",
                [str(cred.id)],
                {"secrets": {"auth.password": "pg-new"}, "expected_revision": 1},
            )
            assert "pg-new" not in str(preview)
            applied = await _apply(client, preview["token"], key="pg-rot")
            assert applied["results"][0]["revision"] == 2
            again = await _apply(client, preview["token"], key="pg-rot")
            assert again["status"] == "reused"
            for t in (t1, t2):
                eff = (await client.get(f"{API}/targets/{t['id']}/effective")).json()
                assert eff["credential_revision"] == 2 and eff["profile_revision"] == 2
                assert eff["values"]["auth.password"] == "***"
            # target deletion removes the execution record on the same connection
            preview = await _preview(client, "delete_target", [t2["id"]])
            await _apply(client, preview["token"], key="pg-del")
            assert [d.host for d in await store.list_devices("lab")] == ["r1"]
            # and the connection goes through the archive-then-delete path
            preview = await _preview(client, "delete_connection", [conn["id"]])
            await _apply(client, preview["token"], key="pg-del-conn")
            assert await store.get_source("lab") is None
        async with store.inventory().transaction() as tx:
            version = await tx.get_credential_version(cred.id, 2)
            assert credentials.open_sealed(dek(settings), version) == {"auth.password": "pg-new"}
            assert (await tx.get_profile_version(p1.id, 2)).credential_revision == 2
            assert (await tx.get_profile_version(p2.id, 2)).credential_revision == 2
            kept = await tx.get_target(uuid.UUID(t1["id"]))
            assert kept.archived_at is not None and kept.source_id is None and kept.source_key == "lab"
    finally:
        await store.dispose()


def test_register_mounts_the_routers_once():
    from fastapi import FastAPI

    app = FastAPI()
    register(app)
    paths = set(app.openapi()["paths"])
    assert f"{API}/connections" in paths and f"{API}/profiles" in paths and f"{API}/credentials" in paths
    assert f"{API}/operations/preview" in paths and f"{API}/targets/{{target_id}}/probe" in paths


@pytest.mark.pg
@pytest.mark.skipif(not DSN, reason="HST_TEST_PG_DSN not set")
async def test_a_claimed_job_lease_blocks_target_deletion_on_postgres(tmp_path):
    """The lease check reads the `jobs` table on the repository's transaction
    connection: a claimed `collect.fetch` job for the target refuses its
    deletion and the connection's, a finished one does not."""
    from datetime import timedelta

    from sqlalchemy.ext.asyncio import create_async_engine

    from hst.app.store.pg import PgStore, metadata, upgrade_to_head
    from hst.worker import queue

    await asyncio.to_thread(upgrade_to_head, DSN)
    engine = create_async_engine(DSN)
    async with engine.begin() as conn:
        for table in reversed(metadata.sorted_tables):
            await conn.execute(table.delete())
    await engine.dispose()
    store = PgStore(DSN)
    try:
        await store.create_user("ada", hash_password(PASSWORD), "admin")
        settings = settings_for(tmp_path)
        async with store.inventory().transaction() as tx:
            await tx.activate(resolver_version=2, schema_version=1, backfill_version=1, now=NOW)
        cred = await seed_credential(store, settings, VYOS_SECRETS)
        profile = await seed_profile(store, "p1", "vyos", VYOS_SETTINGS, cred)
        async with make_client(store, settings) as client:
            await login(client, "ada")
            conn = await _connection(client, profile_id=profile.id)
            t1 = await _target(client, conn["id"], "r1")
            t2 = await _target(client, conn["id"], "r2")
            job = await queue.enqueue(
                store, "collect.fetch", source="lab", device="r2", triggered_by="t", now=NOW
            )
            [claimed] = await store.claim_jobs("w1", 1, NOW, timedelta(minutes=5))
            assert claimed.id == job.id
            refused = await _preview(client, "delete_target", [t2["id"]], expected=409)
            assert refused["references"] == [f"job:{job.id}"]
            await _preview(client, "delete_connection", [conn["id"]], expected=409)
            await _preview(client, "delete_target", [t1["id"]])
            await store.finish_job(job.id, "ok", "", NOW, claimed_by="w1", attempt=claimed.attempt)
            preview = await _preview(client, "delete_target", [t2["id"]])
            await _apply(client, preview["token"], key="pg-lease")
            assert [d.host for d in await store.list_devices("lab")] == ["r1"]
    finally:
        await store.dispose()


def test_one_credential_holds_the_oneapi_secret_for_a_zia_and_a_zpa_profile():
    """ZIA and ZPA sign in with one OneAPI client: the client secret is a
    credential path of both, so one stored credential serves both profiles."""
    secrets = {"auth.client_secret": "s3cret"}
    assert credentials.validate_secret_map(["zia", "zpa"], secrets) == secrets
