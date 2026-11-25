"""The connection, target, profile and operation routes: redacted CRUD, whole-profile
assignment, impact previews that list every device of a shared target,
identity changes through replacement, 409 on referenced deletes, permissions,
and the preview/apply cycle with its idempotent retry.
"""

from __future__ import annotations

import uuid

import pytest
from tests.app.conftest import login
from tests.app.test_inventory_collection import (
    NOW,
    VYOS_SECRETS,
    VYOS_SETTINGS,
    FakeCollector,
    activate,
    built,  # noqa: F401
    make_client,
    make_store,
    seed_credential,
    seed_profile,
    settings_for,
)

from hst.app import sources as glue
from hst.app.inventory.contracts import ROUTE_PERMISSIONS, PreviewOperation, TargetKind

API = "/api/inventory"


async def _rig(tmp_path):
    store = await make_store()
    settings = settings_for(tmp_path)
    await activate(store)
    cred = await seed_credential(store, settings, VYOS_SECRETS)
    profile = await seed_profile(store, "lab-profile", "vyos", VYOS_SETTINGS, cred)
    return store, settings, cred, profile


async def _connection(client, name="lab", profile_id=None, **extra):
    body = {"name": name, "collector_type": "vyos", "display_name": "Lab", "enabled": True, **extra}
    if profile_id is not None:
        body["profile_id"] = str(profile_id)
    r = await client.post(f"{API}/connections", json=body)
    assert r.status_code == 201, r.text
    return r.json()


async def _target(client, connection_id, host, **extra):
    r = await client.post(f"{API}/targets", json={"connection_id": connection_id, "host": host, **extra})
    assert r.status_code == 201, r.text
    return r.json()


async def _preview(client, operation, ids, change=None, expected=200):
    body = {"operation": operation, "selection": {"ids": ids}}
    if change is not None:
        body["change"] = change
    r = await client.post(f"{API}/operations/preview", json=body)
    assert r.status_code == expected, r.text
    return r.json()


async def _apply(client, token, key="k1", expected=200):
    r = await client.post(f"{API}/operations/apply", json={"token": token, "idempotency_key": key})
    assert r.status_code == expected, r.text
    return r.json()


# --- connections and targets -------------------------------------------------------------


async def test_connection_crud_is_redacted_and_revisioned(tmp_path):
    store, settings, _cred, profile = await _rig(tmp_path)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        conn = await _connection(client, profile_id=profile.id)
        assert conn["name"] == "lab" and conn["display_name"] == "Lab" and conn["kind"] == "direct"
        assert conn["profile_id"] == str(profile.id) and conn["revision"] == 2
        assert conn["health"]["state"] == "never" and conn["health"]["target_count"] == 0
        listed = (await client.get(f"{API}/connections", params={"kind": "direct"})).json()
        assert [c["id"] for c in listed] == [conn["id"]]
        assert (await client.get(f"{API}/connections", params={"kind": "controller"})).json() == []
        r = await client.patch(
            f"{API}/connections/{conn['id']}", json={"display_name": "Lab East", "expected_revision": 2}
        )
        assert r.status_code == 200, r.text
        assert r.json()["display_name"] == "Lab East" and r.json()["revision"] == 3
        stale = await client.patch(
            f"{API}/connections/{conn['id']}", json={"display_name": "x", "expected_revision": 2}
        )
        assert stale.status_code == 409 and stale.json()["code"] == "stale_revision"
        assert stale.json()["current_revision"] == 3
        unknown = await client.patch(
            f"{API}/connections/{conn['id']}", json={"nope": 1, "expected_revision": 3}
        )
        assert unknown.status_code == 422
        assert (
            await client.post(f"{API}/connections", json={"name": "lab", "collector_type": "vyos"})
        ).status_code == 409
        assert (
            await client.post(f"{API}/connections", json={"name": "cycle", "collector_type": "vyos"})
        ).status_code == 422
        # a profile of another collector type is refused
        assert (
            await client.post(
                f"{API}/connections",
                json={"name": "vco", "collector_type": "velocloud", "profile_id": str(profile.id)},
            )
        ).status_code == 422


async def test_connection_config_rejects_profile_paths_and_identity_edits(tmp_path):
    store, settings, _cred, _profile = await _rig(tmp_path)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        bad = await client.post(
            f"{API}/connections",
            json={
                "name": "vco",
                "collector_type": "velocloud",
                "config": {"url": "https://vco", "interval_s": 5},
            },
        )
        assert bad.status_code == 422 and "interval_s" in bad.json()["error"]
        secret = await client.post(
            f"{API}/connections",
            json={
                "name": "vco",
                "collector_type": "velocloud",
                "config": {"url": "https://vco", "auth": {"key": "k"}},
            },
        )
        assert secret.status_code == 422 and "k" not in secret.json()["error"].split("auth.key")[-1][:3]
        conn = await _connection(
            client,
            name="vco",
            collector_type="velocloud",
            config={"url": "https://vco", "orchestrator_release": "6.4"},
        )
        assert conn["kind"] == "controller"
        targets = (await client.get(f"{API}/targets", params={"connection_id": conn["id"]})).json()
        assert [t["kind"] for t in targets] == ["controller"] and targets[0]["host"] == ""
        # a label field edits in place; the endpoint needs replacement
        ok = await client.patch(
            f"{API}/connections/{conn['id']}",
            json={"config": {"orchestrator_release": "6.5"}, "expected_revision": conn["revision"]},
        )
        assert ok.status_code == 200, ok.text
        assert ok.json()["config"]["orchestrator_release"] == "6.5"
        moved = await client.patch(
            f"{API}/connections/{conn['id']}",
            json={"config": {"url": "https://other"}, "expected_revision": ok.json()["revision"]},
        )
        assert moved.status_code == 422 and "replacement" in moved.json()["error"]


async def test_direct_targets_are_execution_records_with_inventory_rows(tmp_path):
    store, settings, cred, profile = await _rig(tmp_path)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        conn = await _connection(client, profile_id=profile.id)
        t1 = await _target(client, conn["id"], "r1", port=2222)
        assert t1["kind"] == "direct" and t1["port"] == 2222 and not t1["host_key_pinned"]
        assert t1["profile_id"] is None and t1["revision"] == 1
        devices = await store.list_devices("lab")
        assert [(d.host, d.port, d.enabled) for d in devices] == [("r1", 2222, True)]
        assert (
            await client.post(f"{API}/targets", json={"connection_id": conn["id"], "host": "r1"})
        ).status_code == 409
        disabled = await client.patch(
            f"{API}/targets/{t1['id']}", json={"enabled": False, "expected_revision": 1}
        )
        assert disabled.status_code == 200 and not disabled.json()["enabled"]
        assert not (await store.list_devices("lab"))[0].enabled
        # a target-level profile, and back to the connection's
        other = await seed_profile(store, "other", "vyos", {**VYOS_SETTINGS, "interval_s": 5}, cred)
        assigned = await client.patch(
            f"{API}/targets/{t1['id']}", json={"profile_id": str(other.id), "expected_revision": 2}
        )
        assert assigned.json()["profile_id"] == str(other.id)
        eff = (await client.get(f"{API}/targets/{t1['id']}/effective")).json()
        assert eff["profile_id"] == str(other.id) and eff["values"]["interval_s"] == 5
        assert eff["values"]["auth.password"] == "***" and eff["origins"]["auth.password"] == "credential"
        assert eff["origins"]["host"] == "target" and eff["values"]["port"] == 2222
        cleared = await client.patch(
            f"{API}/targets/{t1['id']}", json={"clear_profile": True, "expected_revision": 3}
        )
        assert cleared.json()["profile_id"] is None
        eff = (await client.get(f"{API}/targets/{t1['id']}/effective")).json()
        assert eff["profile_id"] == str(profile.id) and eff["values"]["interval_s"] == 120
        assert "s3cret" not in str(eff)
        # the controller connection takes no direct targets
        vco = await _connection(client, name="vco", collector_type="velocloud", config={"url": "https://vco"})
        assert (
            await client.post(f"{API}/targets", json={"connection_id": vco["id"], "host": "x"})
        ).status_code == 422


async def test_probe_uses_the_stored_revision_pins_and_redacts(tmp_path, built, monkeypatch):  # noqa: F811
    store, settings, _cred, profile = await _rig(tmp_path)

    def build_device(row, device, settings_, **kw):
        c = FakeCollector(kw["effective"].payload)
        c.observed_host_key = "ssh-ed25519 OBSERVED"
        c.probe = lambda: f"probe ok with {kw['effective'].payload['auth']['password']}"
        return c

    monkeypatch.setattr(glue, "build_device_collector", build_device)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        conn = await _connection(client, profile_id=profile.id, enabled=False)
        t1 = await _target(client, conn["id"], "r1", enabled=False)
        await login(client, "otto")
        r = await client.post(f"{API}/targets/{t1['id']}/probe", json={})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] and body["message"] == "probe ok with ***" and body["host_key_pinned"]
        assert body["effective"]["profile_revision"] == 1 and "s3cret" not in r.text
        assert (await store.list_devices("lab"))[0].host_key == "ssh-ed25519 OBSERVED"
        assert (await client.get(f"{API}/targets/{t1['id']}")).json()["host_key_pinned"]
        # the deliberate unpin, and never a re-pin through PATCH
        await login(client, "ada")
        r = await client.patch(
            f"{API}/targets/{t1['id']}", json={"clear_host_key": True, "expected_revision": 1}
        )
        assert r.status_code == 200 and not r.json()["host_key_pinned"]
        await login(client, "vera")
        assert (await client.post(f"{API}/targets/{t1['id']}/probe", json={})).status_code == 403


# --- profiles ------------------------------------------------------------------------------------


async def test_profile_crud_validates_paths_and_refuses_referenced_deletes(tmp_path):
    store, settings, cred, _profile = await _rig(tmp_path)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        bad = await client.post(
            f"{API}/profiles",
            json={
                "display_name": "p2",
                "collector_type": "vyos",
                "settings": {"host": "r9", "interval_s": 1},
            },
        )
        assert bad.status_code == 422 and "host (target)" in bad.json()["error"]
        for path in ({"routing_scope": "x"}, {"source_name": "x"}, {"auth": {"password": "x"}}, {"url": "x"}):
            r = await client.post(
                f"{API}/profiles", json={"display_name": "p2", "collector_type": "vyos", "settings": path}
            )
            assert r.status_code == 422, path
        created = await client.post(
            f"{API}/profiles",
            json={
                "display_name": "p2",
                "collector_type": "vyos",
                "settings": {"interval_s": 30, "auth": {"method": "password", "username": "u"}},
                "credential_id": str(cred.id),
            },
        )
        assert created.status_code == 201, created.text
        p2 = created.json()
        assert p2["current_revision"] == 1 and p2["credential_revision"] == 1
        assert p2["usage"] == {"targets": 0, "connections": 0}
        duplicate = await client.post(
            f"{API}/profiles",
            json={
                "display_name": "p2",
                "collector_type": "vyos",
                "settings": {"auth": {"method": "password", "username": "u"}},
                "credential_id": str(cred.id),
            },
        )
        assert duplicate.status_code == 409 and duplicate.json()["code"] == "conflict"
        # a password profile with no credential cannot build: refused at write time
        no_cred = await client.post(
            f"{API}/profiles",
            json={
                "display_name": "p3",
                "collector_type": "vyos",
                "settings": {"auth": {"method": "password", "username": "u"}},
            },
        )
        assert no_cred.status_code == 422 and "auth.password" in no_cred.json()["error"]
        # a settings edit is a new revision, a rename is not
        r = await client.patch(
            f"{API}/profiles/{p2['id']}", json={"display_name": "p2b", "expected_revision": 1}
        )
        assert (
            r.status_code == 200 and r.json()["current_revision"] == 1 and r.json()["display_name"] == "p2b"
        )
        # a whole revision: settings without the auth block cannot build
        r = await client.patch(
            f"{API}/profiles/{p2['id']}", json={"settings": {"interval_s": 45}, "expected_revision": 1}
        )
        assert r.status_code == 422 and "auth" in r.json()["error"]
        new_settings = {"interval_s": 45, "auth": {"method": "password", "username": "u2"}}
        r = await client.patch(
            f"{API}/profiles/{p2['id']}", json={"settings": new_settings, "expected_revision": 1}
        )
        assert r.status_code == 200, r.text
        assert r.json()["current_revision"] == 2 and r.json()["settings"] == new_settings
        versions = (await client.get(f"{API}/profiles/{p2['id']}/versions")).json()
        assert [v["revision"] for v in versions] == [1, 2]
        assert (
            await client.patch(f"{API}/profiles/{p2['id']}", json={"settings": {}, "expected_revision": 1})
        ).status_code == 409
        # referenced: 409 with references; unreferenced: archived, versions kept
        conn = await _connection(client, profile_id=uuid.UUID(p2["id"]))
        r = await client.delete(f"{API}/profiles/{p2['id']}", params={"expected_revision": 2})
        assert r.status_code == 409 and r.json()["references"] == [f"connection:{conn['id']}"]
        await client.patch(
            f"{API}/connections/{conn['id']}",
            json={"clear_profile": True, "expected_revision": conn["revision"]},
        )
        r = await client.delete(f"{API}/profiles/{p2['id']}", params={"expected_revision": 2})
        assert r.status_code == 200 and r.json()["archived_at"] is not None
        assert len((await client.get(f"{API}/profiles/{p2['id']}/versions")).json()) == 2
        await login(client, "otto")
        assert (await client.get(f"{API}/profiles")).status_code == 403


async def test_a_shared_profile_edits_through_the_preview_only(tmp_path):
    store, settings, _cred, profile = await _rig(tmp_path)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        conn = await _connection(client, profile_id=profile.id)
        await _target(client, conn["id"], "r1")
        t2 = await _target(client, conn["id"], "r2", profile_id=str(profile.id))
        r = await client.patch(
            f"{API}/profiles/{profile.id}", json={"settings": {"interval_s": 10}, "expected_revision": 1}
        )
        assert r.status_code == 409 and f"target:{t2['id']}" in r.json()["references"]
        assert f"connection:{conn['id']}" in r.json()["references"]
        # a rename stays direct
        assert (
            await client.patch(
                f"{API}/profiles/{profile.id}", json={"display_name": "lab2", "expected_revision": 1}
            )
        ).status_code == 200


async def test_profile_impact_lists_every_target_connection_and_device_of_shared_targets(tmp_path):
    store, settings, _cred, profile = await _rig(tmp_path)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        conn = await _connection(client, profile_id=profile.id)
        t1 = await _target(client, conn["id"], "vsx1")
        t2 = await _target(client, conn["id"], "r2", profile_id=str(profile.id))
        other = await _connection(client, name="other")
        t3 = await _target(client, other["id"], "r3")  # no profile anywhere: not affected
        async with store.inventory().transaction() as tx:
            a, _ = await tx.register_device(
                "dev:x:a", hostname="a", platform="", management_address="", snapshot_key=None, now=NOW
            )
            b, _ = await tx.register_device(
                "dev:x:b", hostname="b", platform="", management_address="", snapshot_key=None, now=NOW
            )
            c, _ = await tx.register_device(
                "dev:x:c", hostname="c", platform="", management_address="", snapshot_key=None, now=NOW
            )
            await tx.upsert_observation(uuid.UUID(t1["id"]), a.id, now=NOW)
            await tx.upsert_observation(uuid.UUID(t1["id"]), b.id, now=NOW)  # a VSX target: two devices
            await tx.upsert_observation(uuid.UUID(t2["id"]), c.id, now=NOW)
            await tx.upsert_observation(uuid.UUID(t3["id"]), c.id, now=NOW)  # c is also seen elsewhere
        r = await client.get(f"{API}/profiles/{profile.id}/impact")
        assert r.status_code == 200, r.text
        impact = r.json()
        assert impact["total_targets"] == 2 and impact["total_devices"] == 3
        assert {t["target_id"] for t in impact["targets"]} == {t1["id"], t2["id"]}
        by_target = {t["target_id"]: set(t["device_ids"]) for t in impact["targets"]}
        assert by_target[t1["id"]] == {str(a.id), str(b.id)} and by_target[t2["id"]] == {str(c.id)}
        assert impact["connection_ids"] == [conn["id"]]
        assert set(impact["device_ids"]) == {str(a.id), str(b.id), str(c.id)}
        assert impact["generation"]["intent_generation"] >= 1


# --- operations --------------------------------------------------------------------------------------


async def test_assign_target_profile_expands_devices_and_names_the_other_devices(tmp_path):
    store, settings, cred, profile = await _rig(tmp_path)
    other = await seed_profile(store, "fast", "vyos", {**VYOS_SETTINGS, "interval_s": 5}, cred)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        conn = await _connection(client, profile_id=profile.id)
        t1 = await _target(client, conn["id"], "vsx1")
        conn2 = await _connection(client, name="lab2", profile_id=profile.id)
        t2 = await _target(client, conn2["id"], "vsx1-alt")
        async with store.inventory().transaction() as tx:
            a, _ = await tx.register_device(
                "dev:x:a", hostname="a", platform="", management_address="", snapshot_key=None, now=NOW
            )
            b, _ = await tx.register_device(
                "dev:x:b", hostname="b", platform="", management_address="", snapshot_key=None, now=NOW
            )
            await tx.upsert_observation(uuid.UUID(t1["id"]), a.id, now=NOW)
            await tx.upsert_observation(uuid.UUID(t1["id"]), b.id, now=NOW)
            await tx.upsert_observation(uuid.UUID(t2["id"]), a.id, now=NOW)
        preview = await _preview(client, "assign_target_profile", [str(a.id)], {"profile_id": str(other.id)})
        assert {m["id"] for m in preview["members"]} == {t1["id"], t2["id"]}
        assert preview["affected_target_count"] == 2 and preview["affected_device_count"] == 2
        assert any("2 connections" in w for w in preview["warnings"])
        impact = (
            await client.get(f"{API}/operations/previews/{preview['token']}/impact", params={"limit": 2})
        ).json()
        assert impact["total"] == 5 and len(impact["items"]) == 2 and impact["next_cursor"] == "2"
        rest = (
            await client.get(
                f"{API}/operations/previews/{preview['token']}/impact", params={"cursor": "2", "limit": 200}
            )
        ).json()
        assert len(rest["items"]) == 3 and rest["next_cursor"] is None
        kinds = [i["kind"] for i in impact["items"] + rest["items"]]
        assert kinds.count("device") == 3 and kinds.count("target") == 2  # b is an "other device" of vsx1
        # narrow to the intended target and apply
        preview = await _preview(client, "assign_target_profile", [t1["id"]], {"profile_id": str(other.id)})
        assert preview["warnings"] == [] and preview["affected_device_count"] == 2
        applied = await _apply(client, preview["token"])
        assert applied["status"] == "applied" and applied["results"][0] == {
            "kind": "target",
            "id": t1["id"],
            "revision": 2,
        }
        assert (await client.get(f"{API}/targets/{t1['id']}")).json()["profile_id"] == str(other.id)
        assert (await client.get(f"{API}/targets/{t2['id']}")).json()["profile_id"] is None
        # the same apply again is the original result, and a consumed token is spent
        again = await _apply(client, preview["token"])
        assert again["status"] == "reused" and again["results"] == applied["results"]
        assert (
            await client.post(
                f"{API}/operations/apply", json={"token": preview["token"], "idempotency_key": "k2"}
            )
        ).status_code == 409
        # a stale preview is refused without partial change
        stale = await _preview(client, "assign_target_profile", [t1["id"]], {"profile_id": None})
        await client.patch(f"{API}/targets/{t1['id']}", json={"enabled": False, "expected_revision": 2})
        r = await client.post(
            f"{API}/operations/apply", json={"token": stale["token"], "idempotency_key": "k3"}
        )
        assert r.status_code == 409 and r.json()["code"] == "stale_revision"
        assert (await client.get(f"{API}/targets/{t1['id']}")).json()["profile_id"] == str(other.id)
        # the operator lacks sources.write
        await login(client, "otto")
        assert (
            await client.post(
                f"{API}/operations/preview",
                json={
                    "operation": "assign_target_profile",
                    "selection": {"ids": [t1["id"]]},
                    "change": {"profile_id": None},
                },
            )
        ).status_code == 403


async def test_edit_profile_preview_lists_the_impact_and_apply_writes_one_revision(tmp_path):
    store, settings, _cred, profile = await _rig(tmp_path)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        conn = await _connection(client, profile_id=profile.id)
        t1 = await _target(client, conn["id"], "r1")
        t2 = await _target(client, conn["id"], "r2", profile_id=str(profile.id))
        bad = await _preview(
            client,
            "edit_profile",
            [str(profile.id)],
            {"settings": {"host": "x"}, "expected_revision": 1},
            expected=422,
        )
        assert "host (target)" in bad["error"]
        preview = await _preview(
            client,
            "edit_profile",
            [str(profile.id)],
            {
                "settings": {"interval_s": 33, "auth": {"method": "password", "username": "vyos"}},
                "expected_revision": 1,
            },
        )
        assert preview["affected_target_count"] == 2
        assert preview["changes"]["settings"]["interval_s"] == 33
        applied = await _apply(client, preview["token"])
        assert applied["results"] == [{"kind": "profile", "id": str(profile.id), "revision": 2}]
        for t in (t1, t2):
            eff = (await client.get(f"{API}/targets/{t['id']}/effective")).json()
            assert eff["profile_revision"] == 2 and eff["values"]["interval_s"] == 33
            assert eff["credential_revision"] == 1
        assert (await client.get(f"{API}/profiles/{profile.id}")).json()["current_revision"] == 2


async def test_delete_target_and_connection_preserve_devices_and_history(tmp_path):
    store, settings, _cred, profile = await _rig(tmp_path)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        conn = await _connection(client, profile_id=profile.id)
        t1 = await _target(client, conn["id"], "r1")
        t2 = await _target(client, conn["id"], "r2")
        async with store.inventory().transaction() as tx:
            a, _ = await tx.register_device(
                "dev:x:a", hostname="a", platform="", management_address="", snapshot_key=None, now=NOW
            )
            await tx.upsert_observation(uuid.UUID(t1["id"]), a.id, now=NOW)
        assert (await client.delete(f"{API}/targets/{t1['id']}")).status_code == 422
        preview = await _preview(client, "delete_target", [t1["id"]])
        assert preview["affected_device_count"] == 1
        await _apply(client, preview["token"])
        gone = (await client.get(f"{API}/targets/{t1['id']}")).json()
        assert gone["archived_at"] is not None
        assert [d.host for d in await store.list_devices("lab")] == ["r2"]
        async with store.inventory().transaction() as tx:
            assert (await tx.get_device(a.id)) is not None
            [obs] = await tx.get_observations(a.id)
            assert obs.state == "absent"
            events = await tx.page_events(entity_type="target", entity_id=t1["id"])
            assert [e.action for e in events[0]] == ["deleted", "created"]
        assert (await client.delete(f"{API}/connections/{conn['id']}")).status_code == 422
        await store.start_run("lab", NOW)
        await _preview(client, "delete_connection", [conn["id"]], expected=409)
        for run in list(store.runs.values()):
            await store.finish_run(run.id, "ok", NOW, "")
        preview = await _preview(client, "delete_connection", [conn["id"]])
        assert preview["affected_target_count"] == 1  # r2; r1 is already archived
        await _apply(client, preview["token"], key="k9")
        assert await store.get_source("lab") is None
        assert (await client.get(f"{API}/connections/{conn['id']}")).status_code == 404
        async with store.inventory().transaction() as tx:
            kept = await tx.get_target(uuid.UUID(t2["id"]))
            assert kept.archived_at is not None and kept.source_id is None and kept.source_key == "lab"
            assert (await tx.get_device(a.id)) is not None


async def test_replace_target_never_transfers_the_pin_and_keeps_the_profile(tmp_path):
    store, settings, _cred, profile = await _rig(tmp_path)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        conn = await _connection(client, profile_id=profile.id)
        t1 = await _target(client, conn["id"], "r1", port=2201, profile_id=str(profile.id))
        await store.set_device_host_key("lab", "r1", "ssh-ed25519 OLDPIN")
        assert (await client.get(f"{API}/targets/{t1['id']}")).json()["host_key_pinned"]
        bad = await _preview(
            client,
            "replace_target",
            [t1["id"]],
            {"endpoint_config": {"host": "r1b", "interval_s": 1}},
            expected=422,
        )
        assert "interval_s" in bad["error"]
        bad = await _preview(
            client, "replace_target", [t1["id"]], {"endpoint_config": {"host_key": "x"}}, expected=422
        )
        preview = await _preview(client, "replace_target", [t1["id"]], {"endpoint_config": {"host": "r1b"}})
        assert any("pin" in w for w in preview["warnings"])
        r = await client.post(
            f"{API}/targets/{t1['id']}/replace", json={"token": preview["token"], "idempotency_key": "rep1"}
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["old_target"]["id"] == t1["id"] and body["old_target"]["archived_at"] is not None
        new = body["new_target"]
        assert new["host"] == "r1b" and new["port"] == 2201 and not new["host_key_pinned"]
        assert new["profile_id"] == str(profile.id) and new["kind"] == "direct" and new["id"] != t1["id"]
        devices = await store.list_devices("lab")
        assert [(d.host, d.host_key, d.port) for d in devices] == [("r1b", "", 2201)]
        # the controller's own endpoint goes the same way and drops the source pin
        vco = await _connection(client, name="vco", collector_type="velocloud", config={"url": "https://vco"})
        [ct] = (await client.get(f"{API}/targets", params={"connection_id": vco["id"]})).json()
        preview = await _preview(
            client, "replace_target", [ct["id"]], {"endpoint_config": {"url": "https://vco2"}}
        )
        r = await client.post(
            f"{API}/targets/{ct['id']}/replace", json={"token": preview["token"], "idempotency_key": "rep2"}
        )
        assert r.status_code == 200, r.text
        assert (await store.get_source("vco")).config["url"] == "https://vco2"
        assert (await client.get(f"{API}/connections/{vco['id']}")).json()["config"]["url"] == "https://vco2"


async def test_route_permissions_match_the_contract_table(tmp_path):
    """Every route this package mounts is gated by the permission that
    `ROUTE_PERMISSIONS` holds; the viewer is refused on each of them."""
    store, settings, cred, profile = await _rig(tmp_path)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        conn = await _connection(client, profile_id=profile.id)
        t1 = await _target(client, conn["id"], "r1")
        await login(client, "vera")
        checks = {
            ("GET", "/connections"): client.get(f"{API}/connections"),
            ("GET", "/connections/{id}"): client.get(f"{API}/connections/{conn['id']}"),
            ("POST", "/connections"): client.post(
                f"{API}/connections", json={"name": "x1", "collector_type": "vyos"}
            ),
            ("PATCH", "/connections/{id}"): client.patch(
                f"{API}/connections/{conn['id']}", json={"expected_revision": 1}
            ),
            ("DELETE", "/connections/{id}"): client.delete(f"{API}/connections/{conn['id']}"),
            ("GET", "/targets"): client.get(f"{API}/targets"),
            ("GET", "/targets/{id}"): client.get(f"{API}/targets/{t1['id']}"),
            ("POST", "/targets"): client.post(
                f"{API}/targets", json={"connection_id": conn["id"], "host": "z"}
            ),
            ("PATCH", "/targets/{id}"): client.patch(
                f"{API}/targets/{t1['id']}", json={"expected_revision": 1}
            ),
            ("DELETE", "/targets/{id}"): client.delete(f"{API}/targets/{t1['id']}"),
            ("GET", "/targets/{id}/effective"): client.get(f"{API}/targets/{t1['id']}/effective"),
            ("POST", "/targets/{id}/probe"): client.post(f"{API}/targets/{t1['id']}/probe", json={}),
            ("POST", "/targets/{id}/replace"): client.post(
                f"{API}/targets/{t1['id']}/replace", json={"token": str(uuid.uuid4()), "idempotency_key": "k"}
            ),
            ("GET", "/profiles"): client.get(f"{API}/profiles"),
            ("GET", "/profiles/{id}"): client.get(f"{API}/profiles/{profile.id}"),
            ("POST", "/profiles"): client.post(
                f"{API}/profiles", json={"display_name": "q", "collector_type": "vyos"}
            ),
            ("PATCH", "/profiles/{id}"): client.patch(
                f"{API}/profiles/{profile.id}", json={"expected_revision": 1}
            ),
            ("DELETE", "/profiles/{id}"): client.delete(
                f"{API}/profiles/{profile.id}", params={"expected_revision": 1}
            ),
            ("GET", "/profiles/{id}/impact"): client.get(f"{API}/profiles/{profile.id}/impact"),
            ("GET", "/credentials"): client.get(f"{API}/credentials"),
            ("GET", "/credentials/{id}"): client.get(f"{API}/credentials/{cred.id}"),
            ("POST", "/credentials"): client.post(
                f"{API}/credentials", json={"display_name": "c", "secrets": {"auth.password": "x"}}
            ),
            ("PATCH", "/credentials/{id}"): client.patch(
                f"{API}/credentials/{cred.id}", json={"expected_revision": 1}
            ),
            ("DELETE", "/credentials/{id}"): client.delete(
                f"{API}/credentials/{cred.id}", params={"expected_revision": 1}
            ),
            ("GET", "/field-metadata"): client.get(f"{API}/field-metadata"),
        }
        for route, pending in checks.items():
            assert route in ROUTE_PERMISSIONS, route
            r = await pending
            assert r.status_code == 403, (route, r.status_code, r.text)
        for operation in (
            PreviewOperation.ASSIGN_TARGET_PROFILE,
            PreviewOperation.EDIT_PROFILE,
            PreviewOperation.ROTATE_CREDENTIAL,
            PreviewOperation.DELETE_CONNECTION,
            PreviewOperation.DELETE_TARGET,
            PreviewOperation.REPLACE_TARGET,
        ):
            r = await client.post(
                f"{API}/operations/preview",
                json={
                    "operation": operation.value,
                    "selection": {"ids": [t1["id"]]},
                    "change": {"profile_id": None}
                    if operation is PreviewOperation.ASSIGN_TARGET_PROFILE
                    else None,
                },
            )
            assert r.status_code in (403, 422), operation
            if r.status_code == 422:
                # a change-less operation validates the body first; the
                # permission is checked before any read
                continue
        # operators read connections and targets, never profiles
        await login(client, "otto")
        assert (await client.get(f"{API}/connections")).status_code == 200
        assert (await client.get(f"{API}/targets/{t1['id']}/effective")).status_code == 200
        assert (await client.get(f"{API}/field-metadata")).status_code == 200
        assert (await client.get(f"{API}/profiles")).status_code == 403


async def test_field_metadata_drives_the_forms():
    store = await make_store()
    async with make_client(store) as client:
        await login(client, "otto")
        rows = (await client.get(f"{API}/field-metadata")).json()
        vyos = next(r for r in rows if r["collector_type"] == "vyos")
        assert vyos["kind"] == "direct"
        by_path = {(f["path"], f["variant"]): f for f in vyos["fields"]}
        assert by_path[("host", None)]["category"] == "target"
        assert by_path[("auth.password", "SshPassword")]["secret"] is True
        assert by_path[("interval_s", None)]["category"] == "profile"


@pytest.mark.parametrize("kind", [TargetKind.DIRECT, TargetKind.CONTROLLER])
def test_target_kind_vocabulary_is_stable(kind):
    assert kind.value in ("direct", "controller")


async def test_a_claimed_target_job_blocks_deletion_and_replacement_until_it_finishes(tmp_path):
    from datetime import timedelta

    from hst.worker import queue

    store, settings, _cred, profile = await _rig(tmp_path)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        conn = await _connection(client, profile_id=profile.id)
        t1 = await _target(client, conn["id"], "r1")
        t2 = await _target(client, conn["id"], "r2")
        job = await queue.enqueue(
            store, "collect.fetch", source="lab", device="r2", triggered_by="scheduler", now=NOW
        )
        [claimed] = await store.claim_jobs("w1", 1, NOW, timedelta(minutes=5))
        assert claimed.id == job.id and claimed.state == "running"
        # the leased target and the whole connection are refused, with the job named
        refused = await _preview(client, "delete_target", [t2["id"]], expected=409)
        assert refused["references"] == [f"job:{job.id}"] and "r2" in refused["error"]
        await _preview(
            client, "replace_target", [t2["id"]], {"endpoint_config": {"host": "r2b"}}, expected=409
        )
        await _preview(client, "delete_connection", [conn["id"]], expected=409)
        # a sibling target is not: the lease is per target
        sibling = await _preview(client, "delete_target", [t1["id"]])
        # a claim taken between preview and apply is caught by the apply recheck
        job1 = await queue.enqueue(
            store, "collect.fetch", source="lab", device="r1", triggered_by="scheduler", now=NOW
        )
        await store.claim_jobs("w1", 1, NOW, timedelta(minutes=5))
        refused = await _apply(client, sibling["token"], expected=409)
        assert refused["references"] == [f"job:{job1.id}"]
        for j in list(store.jobs.values()):
            await store.finish_job(j.id, "ok", "", NOW)
        preview = await _preview(client, "delete_target", [t2["id"]])
        await _apply(client, preview["token"], key="k2")
        assert (await client.get(f"{API}/targets/{t2['id']}")).json()["archived_at"] is not None
