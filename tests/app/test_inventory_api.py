"""The /api/inventory device, site, location and operation routes.

The routers are mounted on the ordinary test app through `register()`, the
way the app integration mounts them, over the fake inventory repository and the rig's
in-memory site rows and graph reader. The performance check at the end runs
against a disposable Postgres and is marked `pg` and `perf`.
"""

from __future__ import annotations

import logging
import os
import statistics
import time
import uuid
from datetime import timedelta

import httpx
import pytest
from tests.app.conftest import PASSWORD, login
from tests.app.inventory_rig import DSN, NOW, FakeGraph, Rig, device, fake_rig, reset_pg, seed_site

from hst.app import permissions as permissions_mod
from hst.app.inventory import inventory_routes
from hst.app.inventory.contracts import (
    API_PREFIX,
    INVENTORY_WRITE,
    ROUTE_PERMISSIONS,
)
from hst.app.inventory.observations import PgSiteRows, RelatedEntityRow
from hst.app.main import create_app
from hst.app.security import hash_password
from hst.core import Settings
from hst.map import site_config

log = logging.getLogger("hst.inventory.perf")

R1 = ("vyos-lab", "r1")
R2 = ("vyos-lab", "r2")
VCO = ("vco", "")
VCO2 = ("vco2", "")


@pytest.fixture
def inventory_write(monkeypatch):
    roles = dict(permissions_mod.ROLE_PERMISSIONS)
    for role in ("operator", "admin"):
        roles[role] = roles[role] | {INVENTORY_WRITE}
    monkeypatch.setattr(permissions_mod, "ROLE_PERMISSIONS", roles)


@pytest.fixture
async def rig() -> Rig:
    r = fake_rig()
    for name, role in (("vera", "viewer"), ("otto", "operator"), ("ada", "admin")):
        await r.store.create_user(name, hash_password(PASSWORD), role)
    await r.seed_source("vyos-lab", "vyos")
    await r.seed_source("vco", "velocloud")
    await r.seed_source("vco2", "velocloud")
    await r.seed_site("fra", "Frankfurt")
    await r.seed_site("ams", "Amsterdam")
    return r


@pytest.fixture
def app(rig: Rig):
    from hst.app.crypto import generate_key

    application = create_app(
        settings=Settings(_env_file=None, hst_secret_key=generate_key()),
        store=rig.store,
        register_inventory=False,
    )
    application.state.inventory_context = rig.ctx
    inventory_routes.register(application)
    return application


@pytest.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}) as c:
        yield c


async def seed_fleet(rig: Rig) -> None:
    await rig.seed_location("vco", "site-7", "FRA DC", site="fra")
    await rig.seed_location("vco2", "site-9", "AMS DC", site="ams")
    await rig.run(
        "1000",
        {
            R1: ("complete", [device("dev:r1", "alpha"), device("dev:shared", "shared")]),
            R2: ("complete", [device("dev:r2", "bravo"), device("dev:shared", "shared")]),
            VCO: ("complete", [device("vco:e:edge:1", "charlie", location=("site-7", "FRA DC"))]),
        },
    )


def set_site_params(rig: Rig, code: str, params: dict) -> None:
    rig.store.sites_rows[code]["params"] = dict(params)


async def uid_map(client) -> dict[str, dict]:
    r = await client.get(f"{API_PREFIX}/devices?lifecycle=active&lifecycle=missing&lifecycle=archived")
    assert r.status_code == 200, r.text
    return {d["graph_uid"]: d for d in r.json()["items"]}


# --- registration ------------------------------------------------------------------------------


async def test_register_mounts_every_route_of_this_task_under_the_prefix_with_its_contract_permission(
    app, client
):
    from fastapi.routing import APIRoute

    declared = {}
    for r in inventory_routes.ROUTERS:
        for route in r.routes:
            if isinstance(route, APIRoute):
                parts = ["{id}" if p.startswith("{") else p for p in route.path.split("/")]
                for method in route.methods:
                    declared[(method, "/".join(parts))] = route
    owned = {
        ("GET", "/devices"),
        ("GET", "/devices/{id}"),
        ("GET", "/devices/{id}/history"),
        ("PATCH", "/devices/{id}/placement"),
        ("PATCH", "/devices/{id}/lifecycle"),
        ("POST", "/devices/{id}/collect"),
        ("GET", "/sites"),
        ("GET", "/sites/{id}"),
        ("POST", "/sites"),
        ("PATCH", "/sites/{id}"),
        ("DELETE", "/sites/{id}"),
        ("GET", "/sites/search"),
        ("POST", "/sites/import"),
        ("GET", "/locations"),
        ("GET", "/locations/search"),
        ("POST", "/locations/bindings"),
        ("PATCH", "/locations/{id}"),
        ("GET", "/views"),
        ("GET", "/views/{id}"),
        ("POST", "/views"),
        ("PATCH", "/views/{id}"),
        ("DELETE", "/views/{id}"),
        ("GET", "/state"),
    }
    missing = owned - set(declared)
    assert not missing, missing
    for key in owned:
        assert key in ROUTE_PERMISSIONS, key
        gates = [d.dependency for d in declared[key].dependencies]
        assert gates, f"{key} has no permission gate"
        assert gates[0].__qualname__.startswith("require_permission"), key
    for key in (
        ("POST", "/operations/preview"),
        ("POST", "/operations/apply"),
        ("GET", "/operations/previews/{id}/impact"),
    ):
        assert key in declared, key
    # mounted under the prefix: an anonymous call reaches the route and is refused there
    for path in ("/state", "/devices", "/sites", "/views", "/locations"):
        r = await client.get(f"{API_PREFIX}{path}")
        assert r.status_code == 401, (path, r.status_code)
    r = await client.post(f"{API_PREFIX}/operations/preview", json={})
    assert r.status_code == 401


# --- list ------------------------------------------------------------------------------


async def test_list_is_server_filtered_sorted_and_carries_every_observing_connection(client, rig):
    await seed_fleet(rig)
    await login(client, "vera")
    r = await client.get(f"{API_PREFIX}/devices")
    assert r.status_code == 200, r.text
    body = r.json()
    assert [d["hostname"] for d in body["items"]] == ["alpha", "bravo", "charlie", "shared"]
    assert (
        body["generation"]["snapshot_key"] == "1000" and body["generation"]["inventory_sync_pending"] is False
    )
    shared = next(d for d in body["items"] if d["graph_uid"] == "dev:shared")
    assert sorted(c["target_host"] for c in shared["connections"]) == ["r1", "r2"]
    assert all(c["connection_id"] == str(rig.source_ids["vyos-lab"]) for c in shared["connections"])
    charlie = next(d for d in body["items"] if d["hostname"] == "charlie")
    assert charlie["site_code"] == "fra" and charlie["placement_state"] == "auto"
    assert rig.graph is not None and rig.graph.calls == [], "the list makes no graph call"

    r = await client.get(f"{API_PREFIX}/devices?q=ALP")
    assert [d["hostname"] for d in r.json()["items"]] == ["alpha"]
    r = await client.get(f"{API_PREFIX}/devices?site_id={rig.site_ids['fra']}")
    assert [d["hostname"] for d in r.json()["items"]] == ["charlie"]
    r = await client.get(
        f"{API_PREFIX}/devices?connection_id={rig.source_ids['vco']}&connection_id={rig.source_ids['vyos-lab']}"
    )
    assert len(r.json()["items"]) == 4
    r = await client.get(f"{API_PREFIX}/devices?placement_state=unplaced&sort=name&direction=desc")
    assert [d["hostname"] for d in r.json()["items"]] == ["shared", "bravo", "alpha"]
    r = await client.get(f"{API_PREFIX}/devices?collection_state=never")
    assert len(r.json()["items"]) == 4


async def test_list_pages_with_a_cursor_and_refuses_it_after_a_generation_change(client, rig):
    await seed_fleet(rig)
    await login(client, "vera")
    r = await client.get(f"{API_PREFIX}/devices?limit=3")
    first = r.json()
    assert len(first["items"]) == 3 and first["next_cursor"]
    r = await client.get(f"{API_PREFIX}/devices?limit=3&cursor={first['next_cursor']}")
    second = r.json()
    assert [d["hostname"] for d in second["items"]] == ["shared"] and second["next_cursor"] is None
    # an intent write in between: the old cursor names rows of another generation
    r = await client.get(f"{API_PREFIX}/devices?limit=3")
    cursor = r.json()["next_cursor"]
    await login(client, "otto")
    alpha = (await uid_map(client))["dev:r1"]
    patch = await client.patch(
        f"{API_PREFIX}/devices/{alpha['id']}/placement",
        json={"mode": "assigned", "site_id": str(rig.site_ids["ams"]), "expected_revision": 1},
    )
    assert patch.status_code == 200, patch.text
    r = await client.get(f"{API_PREFIX}/devices?limit=3&cursor={cursor}")
    assert r.status_code == 409 and r.json()["code"] == "inventory_changed"
    r = await client.get(f"{API_PREFIX}/devices?limit=3&cursor=not-a-cursor")
    assert r.status_code == 422 and r.json()["code"] == "validation"


async def test_empty_results_carry_the_generation_and_malformed_filters_are_422(client, rig):
    await login(client, "vera")
    r = await client.get(f"{API_PREFIX}/devices?q=nothing")
    assert r.status_code == 200
    assert r.json() == {
        "items": [],
        "next_cursor": None,
        "generation": {"snapshot_key": None, "intent_generation": 1, "inventory_sync_pending": False},
    }
    for bad in ("limit=0", "limit=500", "sort=colour", "collection_state=green", "site_id=x", "unknown=1"):
        r = await client.get(f"{API_PREFIX}/devices?{bad}")
        assert r.status_code == 422, (bad, r.text)
        assert r.json()["code"] == "validation"


async def test_a_saved_view_supplies_the_filter_the_query_does_not_state(client, rig):
    await seed_fleet(rig)
    await login(client, "otto")
    r = await client.post(
        f"{API_PREFIX}/views",
        json={
            "name": "vyos only",
            "filter": {"connection_id": [str(rig.source_ids["vyos-lab"])]},
            "sort": "name",
            "direction": "desc",
        },
    )
    assert r.status_code == 201, r.text
    view_id = r.json()["id"]
    r = await client.get(f"{API_PREFIX}/devices?view_id={view_id}")
    assert [d["hostname"] for d in r.json()["items"]] == ["shared", "bravo", "alpha"]
    r = await client.get(f"{API_PREFIX}/devices?view_id={view_id}&direction=asc&q=alp")
    assert [d["hostname"] for d in r.json()["items"]] == ["alpha"]
    await login(client, "vera")
    r = await client.get(f"{API_PREFIX}/devices?view_id={view_id}")
    assert r.status_code == 404, "another user's view is not visible"


# --- detail ------------------------------------------------------------------------------------


async def test_detail_shows_placement_observations_related_entities_and_one_graph_call(client, rig):
    await seed_fleet(rig)
    assert rig.graph is not None
    rig.graph.related_by_uid["dev:shared"] = [
        RelatedEntityRow("firewall-instance:abc", "FirewallInstance", "RUNS_ON", "vs1"),
        RelatedEntityRow("rgrp:cp-cluster:x", "RedundancyGroup", "MEMBER_OF", "cluster-a"),
    ]
    await login(client, "vera")
    shared = (await uid_map(client))["dev:shared"]
    r = await client.get(f"{API_PREFIX}/devices/{shared['id']}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["summary"]["hostname"] == "shared"
    assert sorted(o["host"] for o in body["observations"]) == ["r1", "r2"]
    assert body["placement"]["mode"] == "auto" and body["placement"]["pending"] is False
    assert body["placement"]["desired_revision"] == 1 and body["placement"]["applied_revision"] == 1
    assert [(e["uid"], e["relation"]) for e in body["related"]] == [
        ("firewall-instance:abc", "RUNS_ON"),
        ("rgrp:cp-cluster:x", "MEMBER_OF"),
    ]
    assert body["collection"] is None, "a viewer gets no collection summary"
    assert rig.graph.calls == [["dev:shared"]]
    await login(client, "otto")
    r = await client.get(f"{API_PREFIX}/devices/{shared['id']}")
    summaries = r.json()["collection"]
    assert sorted(s["profile_origin"] for s in summaries) == ["none", "none"]
    assert all(s["consecutive_failures"] == 0 for s in summaries)
    assert (await client.get(f"{API_PREFIX}/devices/{uuid.uuid4()}")).status_code == 404


async def test_detail_on_graph_outage_is_503_with_cached_facts_and_snapshot_age(client, rig):
    await seed_fleet(rig)
    assert rig.graph is not None
    rig.graph.down = True
    await login(client, "vera")
    shared = (await uid_map(client))["dev:shared"]
    r = await client.get(f"{API_PREFIX}/devices/{shared['id']}")
    assert r.status_code == 503, r.text
    body = r.json()
    assert body["code"] == "observed_store_unavailable"
    assert body["detail"]["summary"]["hostname"] == "shared"
    assert len(body["detail"]["observations"]) == 2
    assert body["detail"]["snapshot_key"] == "1000" and body["detail"]["snapshot_age_s"] > 0


# --- history ------------------------------------------------------------------------------------


async def test_history_is_paginated_newest_first_and_hides_sensitive_events_from_viewers(client, rig):
    await seed_fleet(rig)
    await login(client, "otto")
    alpha = (await uid_map(client))["dev:r1"]
    for site in ("fra", "ams", None):
        current = (await client.get(f"{API_PREFIX}/devices/{alpha['id']}")).json()["placement"]
        body = {"mode": "assigned" if site else "unplaced", "expected_revision": current["desired_revision"]}
        if site:
            body["site_id"] = str(rig.site_ids[site])
        r = await client.patch(f"{API_PREFIX}/devices/{alpha['id']}/placement", json=body)
        assert r.status_code == 200, r.text
    async with rig.repo.transaction() as tx:
        await tx.append_event(
            entity_type="device",
            entity_id=alpha["id"],
            actor_id=None,
            action="target.replace",
            now=rig.clock(),
            after={"host": "r1", "password": "x"},
            sensitive=True,
        )
    r = await client.get(f"{API_PREFIX}/devices/{alpha['id']}/history?limit=2")
    assert r.status_code == 200, r.text
    page = r.json()
    assert [e["action"] for e in page["items"]] == ["target.replace", "placement.set"]
    assert page["items"][0]["after"]["password"] == "***"
    assert page["items"][1]["actor_name"] == "otto"
    r = await client.get(f"{API_PREFIX}/devices/{alpha['id']}/history?limit=2&cursor={page['next_cursor']}")
    rest = r.json()
    assert [e["action"] for e in rest["items"]] == ["placement.set", "placement.set"]
    ids = [e["id"] for e in page["items"] + rest["items"]]
    assert ids == sorted(ids, reverse=True)
    await login(client, "vera")
    r = await client.get(f"{API_PREFIX}/devices/{alpha['id']}/history")
    assert [e["action"] for e in r.json()["items"]] == [
        "placement.set",
        "placement.set",
        "placement.set",
        "device.registered",
    ]
    assert (await client.get(f"{API_PREFIX}/devices/{alpha['id']}/history?cursor=x")).status_code == 422


# --- placement and lifecycle -----------------------------------------------------------------


async def test_placement_patch_needs_sites_write_checks_the_revision_and_updates_site_counts(client, rig):
    await seed_fleet(rig)
    await login(client, "vera")
    alpha = (await uid_map(client))["dev:r1"]
    body = {"mode": "assigned", "site_id": str(rig.site_ids["fra"]), "expected_revision": 1}
    assert (await client.patch(f"{API_PREFIX}/devices/{alpha['id']}/placement", json=body)).status_code == 403
    await login(client, "otto")
    r = await client.patch(f"{API_PREFIX}/devices/{alpha['id']}/placement", json=body)
    assert r.status_code == 200, r.text
    placement = r.json()
    assert placement["mode"] == "assigned" and placement["desired_site_code"] == "fra"
    assert placement["desired_revision"] == 2 and placement["applied_revision"] == 1 and placement["pending"]
    assert placement["basis"] == "assigned" and placement["actor_id"]
    r = await client.patch(f"{API_PREFIX}/devices/{alpha['id']}/placement", json=body)
    assert r.status_code == 409 and r.json()["code"] == "stale_revision" and r.json()["current_revision"] == 2
    r = await client.patch(
        f"{API_PREFIX}/devices/{alpha['id']}/placement", json={"mode": "assigned", "expected_revision": 2}
    )
    assert r.status_code == 422
    r = await client.patch(
        f"{API_PREFIX}/devices/{alpha['id']}/placement",
        json={"mode": "assigned", "site_id": "999", "expected_revision": 2},
    )
    assert r.status_code == 404
    sites = {s["code"]: s for s in (await client.get(f"{API_PREFIX}/sites")).json()}
    assert sites["fra"]["device_count"] == 2 and sites["ams"]["device_count"] == 0
    listed = (await uid_map(client))["dev:r1"]
    assert listed["site_code"] == "fra" and listed["placement_state"] == "pending"
    r = await client.patch(
        f"{API_PREFIX}/devices/{alpha['id']}/placement", json={"mode": "unplaced", "expected_revision": 2}
    )
    assert r.json()["mode"] == "unplaced" and r.json()["desired_site_id"] is None
    r = await client.patch(
        f"{API_PREFIX}/devices/{alpha['id']}/placement", json={"mode": "auto", "expected_revision": 3}
    )
    assert r.json()["mode"] == "auto" and r.json()["basis"] == "none"


async def test_auto_placement_shows_both_claims_of_a_conflict_and_never_picks_a_source(client, rig):
    await seed_fleet(rig)
    rig.clock.tick()
    await rig.run(
        "1001",
        {
            VCO: ("complete", [device("vco:e:edge:1", "charlie", location=("site-7", "FRA DC"))]),
            VCO2: ("complete", [device("vco:e:edge:1", "charlie", location=("site-9", "AMS DC"))]),
        },
    )
    await login(client, "vera")
    charlie = (await uid_map(client))["vco:e:edge:1"]
    assert charlie["placement_state"] == "conflict" and charlie["site_id"] is None
    r = await client.get(f"{API_PREFIX}/devices/{charlie['id']}")
    placement = r.json()["placement"]
    assert placement["conflict"] and placement["desired_site_id"] is None
    assert sorted(c["site_code"] for c in placement["contributing"]) == ["ams", "fra"]
    assert all(c["bound"] for c in placement["contributing"])


async def test_lifecycle_patch_is_gated_by_inventory_write_and_archive_hides_without_touching_collection(
    client, rig, inventory_write
):
    await seed_fleet(rig)
    await login(client, "vera")
    alpha = (await uid_map(client))["dev:r1"]
    body = {"action": "archive", "expected_revision": alpha["revision"]}
    assert (await client.patch(f"{API_PREFIX}/devices/{alpha['id']}/lifecycle", json=body)).status_code == 403
    await login(client, "otto")
    r = await client.patch(f"{API_PREFIX}/devices/{alpha['id']}/lifecycle", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["lifecycle"] == "archived" and r.json()["revision"] == alpha["revision"] + 1
    r = await client.get(f"{API_PREFIX}/devices")
    assert "alpha" not in [d["hostname"] for d in r.json()["items"]]
    r = await client.get(f"{API_PREFIX}/devices?lifecycle=archived")
    assert [d["hostname"] for d in r.json()["items"]] == ["alpha"]
    assert (await client.patch(f"{API_PREFIX}/devices/{alpha['id']}/lifecycle", json=body)).status_code == 409
    (obs,) = await rig.observations("dev:r1")
    assert obs.state == "current", "archive changes nothing about collection"
    r = await client.patch(
        f"{API_PREFIX}/devices/{alpha['id']}/lifecycle",
        json={"action": "unarchive", "expected_revision": alpha["revision"] + 1},
    )
    assert r.json()["lifecycle"] == "active"


# --- collect -----------------------------------------------------------------------------


async def test_collect_enqueues_each_eligible_target_once_and_reports_the_rest_as_skipped(client, rig):
    await seed_fleet(rig)
    await login(client, "otto")
    shared = (await uid_map(client))["dev:shared"]
    targets = {c["target_host"]: c["target_id"] for c in shared["connections"]}
    async with rig.repo.transaction() as tx:
        r2 = await tx.get_target(uuid.UUID(targets["r2"]))
        assert r2 is not None
        await tx.update_target(r2.id, expected_revision=r2.revision, now=rig.clock(), enabled=False)
    stranger = str(uuid.uuid4())
    charlie = (await uid_map(client))["vco:e:edge:1"]
    vco_target = charlie["connections"][0]["target_id"]
    body = {"target_ids": [targets["r1"], targets["r1"], targets["r2"], stranger, vco_target]}
    r = await client.post(f"{API_PREFIX}/devices/{shared['id']}/collect", json=body)
    assert r.status_code == 200, r.text
    out = r.json()
    assert [j["host"] for j in out["jobs"]] == ["r1"]
    assert {s["target_id"]: s["reason"] for s in out["skipped"]} == {
        targets["r2"]: "target disabled",
        stranger: "target does not observe this device",
        vco_target: "target does not observe this device",
    }
    jobs = await rig.store.list_jobs()
    assert [(j.kind, j.source, j.device) for j in jobs] == [("collect.fetch", "vyos-lab", "r1")]
    r = await client.post(
        f"{API_PREFIX}/devices/{shared['id']}/collect", json={"target_ids": [targets["r1"]]}
    )
    assert r.json()["jobs"] == [] and r.json()["skipped"][0]["reason"] == "already queued"
    await login(client, "vera")
    assert (await client.post(f"{API_PREFIX}/devices/{shared['id']}/collect", json=body)).status_code == 403


# --- batch operations -------------------------------------------------------------------------


async def test_preview_and_apply_place_devices_with_revisions_impacts_tokens_and_idempotent_retry(
    client, rig
):
    await seed_fleet(rig)
    await login(client, "otto")
    devices = await uid_map(client)
    ids = [devices["dev:r1"]["id"], devices["dev:shared"]["id"]]
    request = {
        "operation": "place_devices",
        "selection": {"ids": ids},
        "change": {"mode": "assigned", "site_id": str(rig.site_ids["ams"])},
    }
    await login(client, "vera")
    assert (await client.post(f"{API_PREFIX}/operations/preview", json=request)).status_code == 403
    await login(client, "otto")
    r = await client.post(f"{API_PREFIX}/operations/preview", json=request)
    assert r.status_code == 200, r.text
    preview = r.json()
    assert preview["member_count"] == 2 and preview["affected_device_count"] == 2
    assert preview["affected_target_count"] == 2, "r1 observes both, r2 observes shared"
    assert [m["revision"] for m in preview["members"]] == [1, 1]
    assert preview["changes"] == {"mode": "assigned", "site_id": rig.site_ids["ams"]}
    token = preview["token"]
    r = await client.get(f"{API_PREFIX}/operations/previews/{token}/impact?limit=1")
    assert r.status_code == 200, r.text
    impact = r.json()
    assert impact["total"] == 2 and len(impact["items"]) == 1 and impact["next_cursor"] == "1"
    r = await client.get(f"{API_PREFIX}/operations/previews/{token}/impact?limit=1&cursor=1")
    assert r.json()["items"][0]["entity_id"] == ids[1] and r.json()["next_cursor"] is None
    await login(client, "ada")
    assert (await client.get(f"{API_PREFIX}/operations/previews/{token}/impact")).status_code == 404
    await login(client, "otto")

    apply = {"token": token, "idempotency_key": "k1"}
    r = await client.post(f"{API_PREFIX}/operations/apply", json=apply)
    assert r.status_code == 200, r.text
    applied = r.json()
    assert applied["status"] == "applied" and [x["revision"] for x in applied["results"]] == [2, 2]
    listed = await uid_map(client)
    assert listed["dev:r1"]["site_code"] == "ams" and listed["dev:shared"]["placement_state"] == "pending"
    r = await client.post(f"{API_PREFIX}/operations/apply", json=apply)
    assert r.status_code == 200 and r.json()["status"] == "reused"
    assert r.json()["results"] == applied["results"]
    r = await client.post(
        f"{API_PREFIX}/operations/apply", json={"token": str(uuid.uuid4()), "idempotency_key": "k1"}
    )
    assert r.status_code == 409 and r.json()["code"] == "idempotency_conflict"
    r = await client.post(f"{API_PREFIX}/operations/apply", json={"token": token, "idempotency_key": "k2"})
    assert r.status_code == 409 and r.json()["code"] == "preview_expired"
    async with rig.repo.transaction() as tx:
        events, _ = await tx.page_events(entity_type="device", entity_id=ids[0])
    assert events[0].action == "placement.set" and events[0].request_id == token


async def test_apply_rechecks_every_revision_and_leaves_nothing_half_done(client, rig):
    await seed_fleet(rig)
    await login(client, "otto")
    devices = await uid_map(client)
    ids = [devices["dev:r1"]["id"], devices["dev:r2"]["id"]]
    r = await client.post(
        f"{API_PREFIX}/operations/preview",
        json={"operation": "place_devices", "selection": {"ids": ids}, "change": {"mode": "unplaced"}},
    )
    token = r.json()["token"]
    # a concurrent edit of the second member
    r = await client.patch(
        f"{API_PREFIX}/devices/{ids[1]}/placement",
        json={"mode": "assigned", "site_id": str(rig.site_ids["fra"]), "expected_revision": 1},
    )
    assert r.status_code == 200
    r = await client.post(f"{API_PREFIX}/operations/apply", json={"token": token, "idempotency_key": "k"})
    assert r.status_code == 409 and r.json()["code"] == "stale_revision"
    listed = await uid_map(client)
    assert listed["dev:r1"]["placement_state"] == "unplaced" and listed["dev:r1"]["site_id"] is None
    r = await client.get(f"{API_PREFIX}/devices/{ids[0]}")
    assert r.json()["placement"]["desired_revision"] == 1, "the first member was rolled back"
    r = await client.post(f"{API_PREFIX}/operations/apply", json={"token": token, "idempotency_key": "k"})
    assert r.status_code == 409


async def test_expired_tokens_foreign_tokens_and_stale_filter_selections_are_refused(client, rig):
    await seed_fleet(rig)
    await login(client, "otto")
    state = (await client.get(f"{API_PREFIX}/state")).json()
    selection = {
        "filter": {"connection_id": [str(rig.source_ids["vyos-lab"])]},
        "intent_generation": state["intent_generation"],
        "snapshot_key": state["read_model_snapshot_key"],
    }
    r = await client.post(
        f"{API_PREFIX}/operations/preview",
        json={"operation": "place_devices", "selection": selection, "change": {"mode": "unplaced"}},
    )
    assert r.status_code == 200, r.text
    assert r.json()["member_count"] == 3
    token = r.json()["token"]
    stale = {**selection, "intent_generation": state["intent_generation"] - 1}
    r = await client.post(
        f"{API_PREFIX}/operations/preview",
        json={"operation": "place_devices", "selection": stale, "change": {"mode": "unplaced"}},
    )
    assert r.status_code == 409 and r.json()["code"] == "inventory_changed"
    await login(client, "ada")
    r = await client.post(f"{API_PREFIX}/operations/apply", json={"token": token, "idempotency_key": "a"})
    assert r.status_code == 404, "a token is bound to its user"
    await login(client, "otto")
    rig.clock.now = rig.clock.now + timedelta(minutes=11)
    r = await client.post(f"{API_PREFIX}/operations/apply", json={"token": token, "idempotency_key": "b"})
    assert r.status_code == 409 and r.json()["code"] == "preview_expired"
    r = await client.post(
        f"{API_PREFIX}/operations/preview",
        json={
            "operation": "place_devices",
            "selection": {"ids": [str(uuid.uuid4()) for _ in range(1001)]},
            "change": {"mode": "unplaced"},
        },
    )
    assert r.status_code == 422
    r = await client.post(
        f"{API_PREFIX}/operations/preview",
        json={
            "operation": "place_devices",
            "selection": {"ids": [str(uuid.uuid4())]},
            "change": {"mode": "unplaced"},
        },
    )
    assert r.status_code == 422 and r.json()["references"]
    r = await client.post(
        f"{API_PREFIX}/operations/preview",
        json={"operation": "edit_profile", "selection": {"ids": ["x"]}, "change": {"expected_revision": 1}},
    )
    assert r.status_code == 403, "sources.write is not an operator permission"


async def test_archive_and_restore_through_preview_and_apply(client, rig, inventory_write):
    await seed_fleet(rig)
    await login(client, "otto")
    devices = await uid_map(client)
    ids = [devices["dev:r1"]["id"], devices["dev:r2"]["id"]]
    r = await client.post(
        f"{API_PREFIX}/operations/preview", json={"operation": "archive_devices", "selection": {"ids": ids}}
    )
    assert r.status_code == 200, r.text
    assert r.json()["warnings"]
    r = await client.post(
        f"{API_PREFIX}/operations/apply", json={"token": r.json()["token"], "idempotency_key": "x"}
    )
    assert r.status_code == 200, r.text
    listed = await uid_map(client)
    assert listed["dev:r1"]["lifecycle"] == "archived" and listed["dev:r2"]["lifecycle"] == "archived"
    r = await client.post(
        f"{API_PREFIX}/operations/preview", json={"operation": "archive_devices", "selection": {"ids": ids}}
    )
    assert r.status_code == 422, "already archived members reject the batch"
    r = await client.post(
        f"{API_PREFIX}/operations/preview",
        json={"operation": "restore_devices", "selection": {"ids": [ids[0]]}},
    )
    r = await client.post(
        f"{API_PREFIX}/operations/apply", json={"token": r.json()["token"], "idempotency_key": "y"}
    )
    assert r.status_code == 200, r.text
    listed = await uid_map(client)
    assert listed["dev:r1"]["lifecycle"] == "active" and listed["dev:r2"]["lifecycle"] == "archived"


# --- sites and locations ------------------------------------------------------------------------


async def test_site_crud_is_revisioned_and_carries_no_routing_field(client, rig):
    await login(client, "vera")
    assert (await client.post(f"{API_PREFIX}/sites", json={"code": "ber"})).status_code == 403
    await login(client, "otto")
    r = await client.post(f"{API_PREFIX}/sites", json={"code": "ber", "name": "Berlin"})
    assert r.status_code == 201, r.text
    site = r.json()
    assert site["revision"] == 1 and site["device_count"] == 0 and "params" not in site
    assert (await client.post(f"{API_PREFIX}/sites", json={"code": "ber"})).status_code == 409
    assert (await client.post(f"{API_PREFIX}/sites", json={"code": "bad code"})).status_code == 422
    r = await client.patch(
        f"{API_PREFIX}/sites/{site['id']}", json={"name": "Berlin DC", "expected_revision": 1}
    )
    assert r.status_code == 200 and r.json()["revision"] == 2 and r.json()["name"] == "Berlin DC"
    r = await client.patch(f"{API_PREFIX}/sites/{site['id']}", json={"name": "x", "expected_revision": 1})
    assert r.status_code == 409 and r.json()["current_revision"] == 2
    r = await client.get(f"{API_PREFIX}/sites/{site['id']}")
    assert r.json()["name"] == "Berlin DC"
    assert (await client.get(f"{API_PREFIX}/sites/999")).status_code == 404
    assert (await client.get(f"{API_PREFIX}/sites/x")).status_code == 422
    assert [s["code"] for s in (await client.get(f"{API_PREFIX}/sites")).json()] == ["ams", "ber", "fra"]


async def test_site_point_is_set_whole_kept_by_other_patches_and_cleared_by_nulls(client, rig):
    await login(client, "otto")
    r = await client.post(f"{API_PREFIX}/sites", json={"code": "ber", "lat": 52.5323, "lon": 13.3846})
    assert r.status_code == 201, r.text
    site = r.json()
    assert (site["lat"], site["lon"]) == (52.5323, 13.3846)
    url = f"{API_PREFIX}/sites/{site['id']}"
    r = await client.patch(url, json={"location": "10115 Berlin", "expected_revision": 1})
    assert r.status_code == 200 and (r.json()["lat"], r.json()["lon"]) == (52.5323, 13.3846)
    for bad in ({"lat": 50.0}, {"lat": 50.0, "lon": None}, {"lat": 91.0, "lon": 0.0}):
        assert (await client.patch(url, json={**bad, "expected_revision": 2})).status_code == 422, bad
    r = await client.patch(url, json={"lat": 50.1, "lon": 8.7, "expected_revision": 2})
    assert r.status_code == 200 and (r.json()["lat"], r.json()["lon"]) == (50.1, 8.7)
    r = await client.patch(url, json={"lat": None, "lon": None, "expected_revision": 3})
    assert r.status_code == 200 and (r.json()["lat"], r.json()["lon"]) == (None, None)
    assert r.json()["location"] == "10115 Berlin"


async def test_site_view_reads_the_site_group_and_blocks_from_the_site_params(client, rig):
    blocks = [{"name": "core", "zone": "internal", "devices": ["dev:r1"]}]
    set_site_params(
        rig, "fra", {"routing_scope": "vrf-a", "site_group": "Area A / Area A1", "blocks": blocks}
    )
    await login(client, "otto")
    r = await client.get(f"{API_PREFIX}/sites/{rig.site_ids['fra']}")
    assert r.status_code == 200, r.text
    assert (r.json()["site_group"], r.json()["blocks"]) == ("Area A / Area A1", blocks)
    assert "routing_scope" not in r.json() and "params" not in r.json()
    listed = {s["code"]: s for s in (await client.get(f"{API_PREFIX}/sites")).json()}
    assert listed["fra"]["blocks"] == blocks
    assert (listed["ams"]["site_group"], listed["ams"]["blocks"]) == (None, None)
    page = (await client.get(f"{API_PREFIX}/sites/search?q=fra")).json()
    assert page["items"][0]["site_group"] == "Area A / Area A1"


async def test_site_patch_writes_the_site_group_and_blocks_into_the_params_and_keeps_the_rest(client, rig):
    seeded = {"routing_scope": "vrf-a", "lat": 50.1, "lon": 8.7}
    set_site_params(rig, "fra", seeded)
    await login(client, "otto")
    fra = rig.site_ids["fra"]
    url = f"{API_PREFIX}/sites/{fra}"
    r = await client.patch(url, json={"lat": 50.1, "lon": 8.7, "expected_revision": 1})
    assert r.status_code == 200, r.text
    sent = [
        {"name": " core ", "zone": "internal", "devices": ["dev:r1", "dev:r2"]},
        {"name": "DMZ", "devices": ["dev:fw"]},
    ]
    r = await client.patch(
        url, json={"site_group": "Area A/ Area A1", "blocks": sent, "expected_revision": 2}
    )
    assert r.status_code == 200, r.text
    blocks = [
        {"name": "core", "zone": "internal", "devices": ["dev:r1", "dev:r2"]},
        {"name": "DMZ", "zone": None, "devices": ["dev:fw"]},
    ]
    view = r.json()
    assert (view["site_group"], view["blocks"]) == ("Area A / Area A1", blocks)
    assert (view["name"], view["lat"], view["lon"], view["revision"]) == ("Frankfurt", 50.1, 8.7, 3)
    params = (await rig.store.get_site("fra")).params
    assert params == {**seeded, "site_group": "Area A / Area A1", "blocks": blocks}
    config = site_config.from_params([("fra", params)])
    assert config.groups == {"fra": ("Area A", "Area A1")}
    assert config.blocks["dev:r2"] == site_config.NamedBlock("fra", "core", "internal")
    assert config.blocks["dev:fw"] == site_config.NamedBlock("fra", "DMZ", None)
    async with rig.repo.transaction() as tx:
        events, _ = await tx.page_events(entity_type="site", entity_id=str(fra))
    assert events[0].action == "site.update"
    assert events[0].before == {
        "name": "Frankfurt",
        "location": "",
        "revision": 2,
        "site_group": None,
        "blocks": None,
    }
    assert events[0].after == {
        "name": "Frankfurt",
        "location": "",
        "revision": 3,
        "site_group": "Area A / Area A1",
        "blocks": blocks,
    }
    r = await client.patch(url, json={"name": "Frankfurt Main", "expected_revision": 3})
    assert r.status_code == 200, r.text
    assert (r.json()["site_group"], r.json()["blocks"]) == ("Area A / Area A1", blocks)
    async with rig.repo.transaction() as tx:
        events, _ = await tx.page_events(entity_type="site", entity_id=str(fra))
    assert "site_group" not in events[0].after and "blocks" not in events[0].after
    r = await client.patch(url, json={"blocks": blocks[1:], "expected_revision": 4})
    assert r.status_code == 200, r.text
    assert (r.json()["site_group"], r.json()["blocks"]) == ("Area A / Area A1", blocks[1:])
    async with rig.repo.transaction() as tx:
        events, _ = await tx.page_events(entity_type="site", entity_id=str(fra))
    assert events[0].before["blocks"] == blocks and events[0].after["blocks"] == blocks[1:]
    assert "site_group" not in events[0].after


async def test_site_patch_clears_the_site_group_and_blocks_with_null_or_empty_and_stores_null(client, rig):
    seeded = {
        "routing_scope": "vrf-a",
        "site_group": "Area A",
        "blocks": [{"name": "core", "zone": None, "devices": ["dev:r1"]}],
    }
    set_site_params(rig, "fra", seeded)
    await login(client, "otto")
    url = f"{API_PREFIX}/sites/{rig.site_ids['fra']}"
    r = await client.patch(url, json={"site_group": "  ", "blocks": [], "expected_revision": 1})
    assert r.status_code == 200, r.text
    assert (r.json()["site_group"], r.json()["blocks"]) == (None, None)
    cleared = {"routing_scope": "vrf-a", "site_group": None, "blocks": None}
    assert (await rig.store.get_site("fra")).params == cleared
    r = await client.patch(
        url, json={"site_group": "Area A", "blocks": seeded["blocks"], "expected_revision": 2}
    )
    assert r.status_code == 200, r.text
    assert (await rig.store.get_site("fra")).params == seeded
    r = await client.patch(url, json={"site_group": None, "blocks": None, "expected_revision": 3})
    assert r.status_code == 200, r.text
    assert (r.json()["site_group"], r.json()["blocks"]) == (None, None)
    assert (await rig.store.get_site("fra")).params == cleared


@pytest.mark.parametrize(
    "body",
    [
        {"site_group": "/".join(["n"] * 9)},
        {"site_group": "Area A / " + "n" * 65},
        {"site_group": "Area A // Area A1"},
        {"blocks": [{"name": "Core"}, {"name": " core"}]},
        {"blocks": [{"name": "core", "devices": ["dev:r1"]}, {"name": "edge", "devices": ["dev:r1"]}]},
        {"blocks": [{"name": "core", "devices": ["dev:r1", "dev:r1"]}]},
        {"blocks": [{"name": "n" * 41}]},
        {"blocks": [{"name": "   "}]},
        {"blocks": [{"name": "core", "zone": "dmz"}]},
    ],
)
async def test_site_patch_refuses_a_site_group_or_blocks_outside_the_rules_and_writes_nothing(
    client, rig, body
):
    set_site_params(rig, "fra", {"routing_scope": "vrf-a"})
    await login(client, "otto")
    url = f"{API_PREFIX}/sites/{rig.site_ids['fra']}"
    r = await client.patch(url, json={**body, "expected_revision": 1})
    assert r.status_code == 422, r.text
    assert (await rig.store.get_site("fra")).params == {"routing_scope": "vrf-a"}
    assert (await client.get(url)).json()["revision"] == 1


@pytest.mark.pg
@pytest.mark.skipif(not DSN, reason="HST_TEST_PG_DSN not set")
async def test_postgres_site_rows_merge_the_site_group_and_blocks_into_the_params_column():
    store = await reset_pg()
    try:
        seeded = {"routing_scope": "vrf-a", "lat": 50.1, "lon": 8.7}
        site_id = await seed_site(store, "fra", "Frankfurt", params=seeded)
        blocks = [{"name": "core", "zone": "internal", "devices": ["dev:r1"]}]
        async with store.inventory().transaction() as tx:
            row = await PgSiteRows(tx.connection).update(
                site_id, expected_revision=1, now=NOW, site_group="Area A", blocks=blocks
            )
        assert (row.site_group, row.blocks, row.lat, row.lon) == ("Area A", blocks, 50.1, 8.7)
        assert (await store.get_site("fra")).params == {**seeded, "site_group": "Area A", "blocks": blocks}
        async with store.inventory().transaction() as tx:
            row = await PgSiteRows(tx.connection).update(
                site_id, expected_revision=2, now=NOW, name="Frankfurt Main"
            )
            await PgSiteRows(tx.connection).update(
                site_id, expected_revision=3, now=NOW, site_group=None, blocks=None
            )
        assert (row.site_group, row.blocks) == ("Area A", blocks)
        assert (await store.get_site("fra")).params == {**seeded, "site_group": None, "blocks": None}
    finally:
        await store.dispose()


async def test_site_deletion_previews_and_releases_placements_bindings_and_defaults_only(client, rig):
    await seed_fleet(rig)
    await rig.target("vyos-lab", "r3", onboarding_site="fra")
    await login(client, "otto")
    devices = await uid_map(client)
    r = await client.patch(
        f"{API_PREFIX}/devices/{devices['dev:r1']['id']}/placement",
        json={"mode": "assigned", "site_id": str(rig.site_ids["fra"]), "expected_revision": 1},
    )
    assert r.status_code == 200
    source_before = await rig.store.get_source("vco")
    fra = str(rig.site_ids["fra"])
    r = await client.delete(f"{API_PREFIX}/sites/{fra}?token={uuid.uuid4()}&idempotency_key=z")
    assert r.status_code == 404, "deletion needs a preview of this site"
    r = await client.post(
        f"{API_PREFIX}/operations/preview", json={"operation": "delete_site", "selection": {"ids": [fra]}}
    )
    assert r.status_code == 200, r.text
    preview = r.json()
    assert preview["members"] == [{"kind": "site", "id": fra, "revision": 1, "label": "fra"}]
    assert preview["affected_device_count"] == 2, (
        "the assigned device and the auto device at the bound location"
    )
    impact = (await client.get(f"{API_PREFIX}/operations/previews/{preview['token']}/impact")).json()
    kinds = sorted((i["kind"], i["detail"].get("effect")) for i in impact["items"])
    assert kinds == [
        ("connection", "unbound"),
        ("device", "recomputed"),
        ("device", "unplaced"),
        ("target", "default cleared"),
    ]
    r = await client.delete(f"{API_PREFIX}/sites/{fra}?token={preview['token']}&idempotency_key=d1")
    assert r.status_code == 200, r.text
    assert r.json()["results"][0] == {"kind": "site", "id": fra, "revision": 1}
    assert [s["code"] for s in (await client.get(f"{API_PREFIX}/sites")).json()] == ["ams"]
    listed = await uid_map(client)
    # explicit unplaced, pending until a publication withdraws the edge
    assert listed["dev:r1"]["placement_state"] == "pending" and listed["dev:r1"]["site_id"] is None
    # its binding is gone and so is the published pointer to the deleted site
    assert (
        listed["vco:e:edge:1"]["placement_state"] == "unplaced" and listed["vco:e:edge:1"]["site_id"] is None
    )
    r = await client.get(f"{API_PREFIX}/devices/{devices['dev:r1']['id']}")
    assert r.json()["placement"]["mode"] == "unplaced" and r.json()["placement"]["desired_revision"] == 3
    locations = (await client.get(f"{API_PREFIX}/locations")).json()
    assert all(loc["site_id"] is None for loc in locations if loc["source_key"] == "vco")
    async with rig.repo.transaction() as tx:
        r3 = await tx.get_active_target("vyos-lab", "r3")
        assert r3 is not None and r3.onboarding_site_id is None
        events, _ = await tx.page_events(entity_type="site", entity_id=fra)
    assert events[0].action == "site.delete" and events[0].after["placements_released"] == 1
    assert (await rig.store.get_source("vco")).config == source_before.config, "no normalization effect"
    r = await client.delete(f"{API_PREFIX}/sites/{fra}?token={preview['token']}&idempotency_key=d1")
    assert r.status_code == 200 and r.json()["status"] == "reused"


async def test_binding_a_location_moves_the_devices_observed_there_and_keys_by_id_not_name(client, rig):
    await seed_fleet(rig)
    await rig.seed_location("vco2", "site-7", "FRA DC")  # same id and name under another source
    rig.clock.tick()
    await rig.run(
        "1001", {VCO2: ("complete", [device("vco:e2:edge:9", "delta", location=("site-7", "FRA DC"))])}
    )
    await login(client, "vera")
    locations = {
        (loc["source_key"], loc["location_id"]): loc
        for loc in (await client.get(f"{API_PREFIX}/locations")).json()
    }
    assert (
        locations[("vco", "site-7")]["site_code"] == "fra"
        and locations[("vco", "site-7")]["device_count"] == 1
    )
    other = locations[("vco2", "site-7")]
    assert other["site_code"] is None and other["device_count"] == 1
    assert other["connection_id"] == str(rig.source_ids["vco2"])
    listed = await uid_map(client)
    assert listed["vco:e2:edge:9"]["placement_state"] == "unplaced", (
        "a same-named location of another source is unbound"
    )
    patch = {"site_id": str(rig.site_ids["ams"]), "expected_revision": other["revision"]}
    assert (await client.patch(f"{API_PREFIX}/locations/{other['id']}", json=patch)).status_code == 403
    await login(client, "otto")
    r = await client.patch(f"{API_PREFIX}/locations/{other['id']}", json=patch)
    assert r.status_code == 200, r.text
    assert r.json()["site_code"] == "ams" and r.json()["revision"] == other["revision"] + 1
    listed = await uid_map(client)
    assert (
        listed["vco:e2:edge:9"]["site_code"] == "ams"
        and listed["vco:e2:edge:9"]["placement_state"] == "pending"
    )
    assert listed["vco:e:edge:1"]["site_code"] == "fra"
    r = await client.patch(f"{API_PREFIX}/locations/{other['id']}", json=patch)
    assert r.status_code == 409 and r.json()["code"] == "stale_revision"
    r = await client.patch(
        f"{API_PREFIX}/locations/{other['id']}",
        json={"site_id": None, "expected_revision": other["revision"] + 1},
    )
    assert r.json()["site_code"] is None
    assert (await uid_map(client))["vco:e2:edge:9"]["site_id"] is None
    r = await client.get(f"{API_PREFIX}/locations?connection_id={rig.source_ids['vco2']}")
    assert [loc["source_key"] for loc in r.json()] == ["vco2", "vco2"]


# --- site and location search and bulk writes ------------------------------------------------


async def test_site_search_filters_sorts_and_pages_and_is_not_read_as_a_site_id(client, rig):
    await rig.seed_site("ber", "Berlin")
    await login(client, "vera")
    r = await client.get(f"{API_PREFIX}/sites/search?limit=2")
    assert r.status_code == 200, r.text
    page = r.json()
    assert page["total"] == 3 and [s["code"] for s in page["items"]] == ["ams", "ber"]
    r = await client.get(f"{API_PREFIX}/sites/search?offset=2&limit=2")
    assert [s["code"] for s in r.json()["items"]] == ["fra"]
    r = await client.get(f"{API_PREFIX}/sites/search?q=furt")
    assert [s["code"] for s in r.json()["items"]] == ["fra"]
    r = await client.get(f"{API_PREFIX}/sites/search?sort=name&direction=desc")
    assert [s["name"] for s in r.json()["items"]] == ["Frankfurt", "Berlin", "Amsterdam"]
    for bad in ("limit=0", "sort=colour", "unknown=1"):
        assert (await client.get(f"{API_PREFIX}/sites/search?{bad}")).status_code == 422, bad


async def test_site_import_reports_each_row_and_writes_nothing_when_a_row_is_refused(client, rig):
    await login(client, "vera")
    body = {"sites": [{"code": "ber", "name": "Berlin"}], "dry_run": True}
    assert (await client.post(f"{API_PREFIX}/sites/import", json=body)).status_code == 403
    await login(client, "otto")
    rows = [
        {"code": "ber", "name": "Berlin"},
        {"code": "fra", "name": "Frankfurt Main"},
        {"code": "ams"},
        {"code": "ber"},
    ]
    r = await client.post(f"{API_PREFIX}/sites/import", json={"sites": rows})
    assert r.status_code == 200, r.text
    result = r.json()
    assert not result["applied"] and result["errors"] == 1
    assert [(x["action"], x["status"]) for x in result["rows"]] == [
        ("create", "change"),
        ("update", "change"),
        ("none", "unchanged"),
        ("none", "error"),
    ]
    assert [s["code"] for s in (await client.get(f"{API_PREFIX}/sites")).json()] == ["ams", "fra"]
    r = await client.post(f"{API_PREFIX}/sites/import", json={"sites": rows[:3], "dry_run": True})
    assert not r.json()["applied"] and r.json()["created"] == 1
    assert len((await client.get(f"{API_PREFIX}/sites")).json()) == 2
    r = await client.post(f"{API_PREFIX}/sites/import", json={"sites": rows[:3]})
    assert r.json()["applied"] and (r.json()["created"], r.json()["updated"], r.json()["unchanged"]) == (
        1,
        1,
        1,
    )
    sites = {s["code"]: s for s in (await client.get(f"{API_PREFIX}/sites")).json()}
    assert sites["ber"]["name"] == "Berlin" and sites["fra"]["name"] == "Frankfurt Main"
    assert sites["ams"]["name"] == "Amsterdam", "a name left out keeps the stored name"
    assert (
        await client.post(f"{API_PREFIX}/sites/import", json={"sites": [{"code": "bad code"}]})
    ).status_code == 422


async def test_site_import_refuses_a_code_that_is_the_same_site_as_another(client, rig):
    """`FRA` beside the stored `fra`, or beside an earlier row of the import, is one graph Site."""
    await login(client, "otto")
    rows = [{"code": "FRA"}, {"code": "ber"}, {"code": "BER"}]

    r = await client.post(f"{API_PREFIX}/sites/import", json={"sites": rows})

    result = r.json()
    assert not result["applied"] and result["errors"] == 2
    assert [(x["status"], x["error"]) for x in result["rows"]] == [
        ("error", "code folds onto 'fra': both are the site site:fra"),
        ("change", None),
        ("error", "code folds onto 'ber': both are the site site:ber"),
    ]
    assert [s["code"] for s in (await client.get(f"{API_PREFIX}/sites")).json()] == ["ams", "fra"]


async def test_location_search_counts_states_and_suggests_only_an_unambiguous_site(client, rig):
    await seed_fleet(rig)
    await rig.seed_site("fra-dc2", "Frankfurt 2")
    await rig.seed_location("vco", "site-8", "AMS")  # site code
    await rig.seed_location("vco", "site-10", "Frankfurt 2")  # site name
    await rig.seed_location("vco", "fra", "Edge 44")  # vendor location id
    await rig.seed_location("vco", "site-11", "AMS edge 12")  # code as a token
    await rig.seed_location("vco", "site-12", "Nowhere")
    await login(client, "vera")
    r = await client.get(f"{API_PREFIX}/locations/search?connection_id={rig.source_ids['vco']}")
    assert r.status_code == 200, r.text
    page = r.json()
    suggested = {row["location"]["location_id"]: row["suggestion"] for row in page["items"]}
    assert suggested["site-8"] == {"site_id": str(rig.site_ids["ams"]), "site_code": "ams", "rule": "code"}
    assert suggested["site-10"]["site_code"] == "fra-dc2" and suggested["site-10"]["rule"] == "name"
    assert suggested["fra"]["site_code"] == "fra" and suggested["fra"]["rule"] == "location_id"
    assert suggested["site-11"]["site_code"] == "ams" and suggested["site-11"]["rule"] == "code_in_name"
    assert suggested["site-12"] is None and suggested["site-7"] is None, (
        "a mapped location gets no suggestion"
    )
    assert page["counts"] == {"all": 6, "mapped": 1, "unmapped": 5, "suggested": 4}
    assert {c["source_key"]: c["count"] for c in page["connections"]} == {"vco": 6, "vco2": 1}
    r = await client.get(f"{API_PREFIX}/locations/search?state=suggested&limit=2")
    assert r.json()["total"] == 4 and len(r.json()["items"]) == 2
    r = await client.get(f"{API_PREFIX}/locations/search?q=nowhere")
    assert [row["location"]["location_id"] for row in r.json()["items"]] == ["site-12"]
    r = await client.get(f"{API_PREFIX}/locations/search?site_id={rig.site_ids['ams']}")
    assert [row["location"]["location_id"] for row in r.json()["items"]] == ["site-9"]
    assert {
        c["source_key"] for c in (await client.get(f"{API_PREFIX}/locations/search")).json()["connections"]
    } == {"vco", "vco2"}
    assert (await client.get(f"{API_PREFIX}/locations/search?state=odd")).status_code == 422


async def test_bulk_bindings_check_every_row_first_and_recompute_the_devices_once(client, rig):
    await seed_fleet(rig)
    other = await rig.seed_location("vco2", "site-7", "FRA DC")
    rig.clock.tick()
    await rig.run(
        "1001", {VCO2: ("complete", [device("vco:e2:edge:9", "delta", location=("site-7", "FRA DC"))])}
    )
    await login(client, "otto")
    url = f"{API_PREFIX}/locations/bindings"
    refused = {
        "bindings": [
            {"id": str(other), "site_code": "ams"},
            {"source_key": "vco", "location_id": "site-7", "site_code": "nope"},
            {"source_key": "vco", "location_id": "missing", "site_id": None},
            {"id": str(other), "site_id": str(rig.site_ids["fra"])},
        ]
    }
    r = await client.post(url, json=refused)
    assert r.status_code == 200, r.text
    result = r.json()
    assert not result["applied"] and result["errors"] == 3
    assert [row["status"] for row in result["rows"]] == ["change", "error", "error", "error"]
    assert "twice" in result["rows"][3]["error"]
    assert (await uid_map(client))["vco:e2:edge:9"]["site_id"] is None, "nothing is written"
    bindings = {
        "bindings": [
            {"id": str(other), "site_code": "ams", "expected_revision": 1},
            {"source_key": "vco", "location_id": "site-7", "site_id": str(rig.site_ids["fra"])},
        ]
    }
    r = await client.post(url, json={**bindings, "dry_run": True})
    assert not r.json()["applied"] and (r.json()["changed"], r.json()["unchanged"]) == (1, 1)
    r = await client.post(url, json=bindings)
    result = r.json()
    assert result["applied"] and result["changed"] == 1 and result["devices_recomputed"] == 1
    assert result["rows"][0]["site_before"] is None and result["rows"][0]["site_after"] == "ams"
    listed = await uid_map(client)
    assert listed["vco:e2:edge:9"]["site_code"] == "ams" and listed["vco:e:edge:1"]["site_code"] == "fra"
    r = await client.post(url, json=bindings)
    assert not r.json()["applied"] and "changed" in r.json()["rows"][0]["error"], "the revision moved on"
    async with rig.repo.transaction() as tx:
        events, _ = await tx.page_events(entity_type="location", entity_id=str(other))
    assert events[0].action == "location.bind" and events[0].after["site"] == "ams"
    await login(client, "vera")
    assert (await client.post(url, json=bindings)).status_code == 403


async def test_state_route_reports_the_read_model_position(client, rig):
    await login(client, "vera")
    r = await client.get(f"{API_PREFIX}/state")
    assert r.status_code == 200
    assert r.json()["resolver_version"] == 1 and r.json()["read_model_snapshot_key"] is None
    await seed_fleet(rig)
    assert (await client.get(f"{API_PREFIX}/state")).json()["read_model_snapshot_key"] == "1000"


# --- performance -------------------------------------------------------------------------------

PERF = pytest.mark.skipif(os.environ.get("HST_PERF") != "1", reason="HST_PERF not set")
DEVICES = 10_000
OBSERVATIONS = 20_000


async def _seed_large(store, rig_ctx) -> dict:
    """10k devices over 20k observations in bulk, with sites, locations,
    placements and events, straight through the store engine."""
    import sqlalchemy as sa

    from hst.app.inventory import tables as t
    from hst.app.store.pg import reported_locations

    now = rig_ctx.clock()
    user = await store.create_user("ada", hash_password(PASSWORD), "admin")
    await store.create_user("vera", hash_password(PASSWORD), "viewer")
    for i in range(50):
        await seed_site(store, f"site-{i:03d}", f"Site {i}")
    sites = await store.list_sites()
    controllers = [await store.create_source(f"vco-{i}", "velocloud", {}, b"") for i in range(10)]
    direct = await store.create_source("fleet", "vyos", {"interval_s": 300}, b"")
    engine = store._engine
    async with engine.begin() as conn:
        await conn.execute(
            reported_locations.insert(),
            [
                {
                    "source": c.name,
                    "location_id": f"loc-{j}",
                    "name": f"Location {j}",
                    "site": sites[(i * 7 + j) % 50].code,
                    "updated_at": now,
                }
                for i, c in enumerate(controllers)
                for j in range(20)
            ],
        )
        handles = {
            (r.source, r.location_id): r.handle
            for r in (
                await conn.execute(
                    sa.select(
                        reported_locations.c.source,
                        reported_locations.c.location_id,
                        reported_locations.c.handle,
                    )
                )
            ).all()
        }
        target_rows = []
        for c in controllers:
            target_rows.append(
                {
                    "id": uuid.uuid4(),
                    "source_id": c.id,
                    "source_key": c.name,
                    "host": "",
                    "kind": "controller",
                    "created_at": now,
                    "updated_at": now,
                }
            )
        for h in range(DEVICES):
            target_rows.append(
                {
                    "id": uuid.uuid4(),
                    "source_id": direct.id,
                    "source_key": direct.name,
                    "host": f"10.{h // 65536}.{(h // 256) % 256}.{h % 256}",
                    "kind": "direct",
                    "created_at": now,
                    "updated_at": now,
                }
            )
        await conn.execute(t.inventory_targets.insert(), target_rows)
        controller_targets = target_rows[:10]
        direct_targets = target_rows[10:]
        device_rows = []
        for h in range(DEVICES):
            device_rows.append(
                {
                    "id": uuid.uuid4(),
                    "graph_uid": f"dev:perf:{h:05d}",
                    "first_seen": now,
                    "last_seen": now,
                    "latest_snapshot_key": "5000",
                    "hostname": f"host-{h:05d}",
                    "platform": ["vyos", "iosxe", "nxos"][h % 3],
                    "management_address": f"10.{h // 65536}.{(h // 256) % 256}.{h % 256}",
                    "lifecycle": "active",
                    "collection_state": ["current", "stale", "failed", "partial"][h % 4],
                    "last_success_at": now - timedelta(seconds=h),
                    "resolved_site_id": sites[h % 50].id,
                    "placement_state": ["auto", "assigned"][h % 2],
                    "updated_at": now,
                }
            )
        await conn.execute(t.inventory_devices.insert(), device_rows)
        obs_rows = []
        for h, d in enumerate(device_rows):
            ctl = controller_targets[h % 10]
            obs_rows.append(
                {
                    "target_id": ctl["id"],
                    "device_id": d["id"],
                    "reported_location_handle": handles[(ctl["source_key"], f"loc-{h % 20}")],
                    "last_success_at": now,
                    "last_seen_snapshot_key": "5000",
                    "state": "current",
                    "authority": "complete",
                    "updated_at": now,
                }
            )
            obs_rows.append(
                {
                    "target_id": direct_targets[h]["id"],
                    "device_id": d["id"],
                    "reported_location_handle": None,
                    "last_success_at": now,
                    "last_seen_snapshot_key": "5000",
                    "state": "current",
                    "authority": "complete",
                    "updated_at": now,
                }
            )
        for i in range(0, len(obs_rows), 5000):
            await conn.execute(t.inventory_observations.insert(), obs_rows[i : i + 5000])
        await conn.execute(
            t.inventory_placements.insert(),
            [
                {
                    "device_id": d["id"],
                    "mode": "assigned" if h % 2 else "auto",
                    "site_id": sites[h % 50].id if h % 2 else None,
                    "origin": "manual",
                    "revision": 1,
                    "actor_id": user.id,
                    "updated_at": now,
                    "applied_revision": 1,
                    "published_site_id": sites[h % 50].id,
                    "published_snapshot_key": "5000",
                }
                for h, d in enumerate(device_rows)
            ],
        )
        events = []
        for d in device_rows[:500]:
            for k in range(20):
                events.append(
                    {
                        "entity_type": "device",
                        "entity_id": str(d["id"]),
                        "actor_id": user.id,
                        "action": "placement.set",
                        "at": now - timedelta(seconds=k),
                        "before": {"revision": k},
                        "after": {"revision": k + 1},
                        "sensitive": False,
                    }
                )
        await conn.execute(t.inventory_events.insert(), events)
        await conn.execute(
            t.inventory_state.insert().values(id=1, read_model_snapshot_key="5000", updated_at=now)
        )
    return {
        "sites": sites,
        "controllers": controllers,
        "direct": direct,
        "sample_device": str(device_rows[0]["id"]),
    }


class QueryCounter:
    def __init__(self, engine) -> None:
        self.count = 0
        self.statements: list[str] = []
        self.engine = engine

    def __enter__(self):
        from sqlalchemy import event

        def before(conn, cursor, statement, parameters, context, executemany):
            self.count += 1
            self.statements.append(statement)

        self._listener = before
        event.listen(self.engine.sync_engine, "before_cursor_execute", before)
        return self

    def __exit__(self, *exc):
        from sqlalchemy import event

        event.remove(self.engine.sync_engine, "before_cursor_execute", self._listener)


@pytest.mark.pg
@pytest.mark.perf
@PERF
@pytest.mark.skipif(not DSN, reason="HST_TEST_PG_DSN not set")
async def test_ten_thousand_devices_page_in_bounded_constant_query_counts(caplog):
    import platform

    import sqlalchemy as sa

    from hst.app.crypto import generate_key

    caplog.set_level(logging.INFO, logger="hst.inventory.perf")
    store = await reset_pg()
    try:
        from tests.app.inventory_rig import Clock

        from hst.app.inventory.observations import InventoryContext

        ctx = InventoryContext(
            store, Settings(_env_file=None, collect_interval_s=0), graph=FakeGraph(), clock=Clock()
        )
        seed_started = time.perf_counter()
        seeded = await _seed_large(store, ctx)
        log.info(
            "seeded %d devices and %d observations in %.1fs on %s %s",
            DEVICES,
            OBSERVATIONS,
            time.perf_counter() - seed_started,
            platform.system(),
            platform.machine(),
        )
        app_settings = Settings(_env_file=None, hst_secret_key=generate_key())
        application = create_app(settings=app_settings, store=store, register_inventory=False)
        application.state.inventory_context = ctx
        inventory_routes.register(application)
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}
        ) as client:
            await login(client, "vera")
            engine = store._engine
            counts = {}
            for limit in (50, 100, 200):
                with QueryCounter(engine) as qc:
                    r = await client.get(f"{API_PREFIX}/devices?limit={limit}")
                assert r.status_code == 200, r.text
                assert len(r.json()["items"]) == limit <= 200
                counts[limit] = qc.count
            log.info("queries per page by page size: %s", counts)
            assert len(set(counts.values())) == 1, f"query count grows with the page: {counts}"
            assert counts[200] <= 6, f"more than a handful of queries per page: {counts}"
            r = await client.get(f"{API_PREFIX}/devices?limit=200")
            with QueryCounter(engine) as qc:
                r = await client.get(f"{API_PREFIX}/devices?limit=200&cursor={r.json()['next_cursor']}")
            assert r.status_code == 200 and qc.count == counts[200]

            site = seeded["sites"][3]
            source = seeded["controllers"][2]
            filters = {
                "name": "q=host-0042",
                "site": f"site_id={site.id}",
                "source": f"connection_id={source.id}",
                "state": "collection_state=failed&collection_state=partial",
                "placement": "placement_state=assigned&sort=site",
            }
            timings = {}
            for name, qs in filters.items():
                samples = []
                for _ in range(15):
                    started = time.perf_counter()
                    r = await client.get(f"{API_PREFIX}/devices?limit=200&{qs}")
                    samples.append((time.perf_counter() - started) * 1000)
                    assert r.status_code == 200, r.text
                    assert len(r.json()["items"]) <= 200
                samples.sort()
                timings[name] = (statistics.median(samples), samples[int(len(samples) * 0.95) - 1])
            log.info("list p50/p95 ms: %s", {k: (round(a, 1), round(b, 1)) for k, (a, b) in timings.items()})

            device_id = seeded["sample_device"]
            samples = []
            for _ in range(15):
                started = time.perf_counter()
                r = await client.get(f"{API_PREFIX}/devices/{device_id}/history?limit=10")
                samples.append((time.perf_counter() - started) * 1000)
                assert r.status_code == 200 and len(r.json()["items"]) == 10
            samples.sort()
            log.info("history p50/p95 ms: %.1f/%.1f", statistics.median(samples), samples[13])

            preview_samples = []
            state = (await client.get(f"{API_PREFIX}/state")).json()
            await login(client, "ada")
            for _ in range(5):
                started = time.perf_counter()
                r = await client.post(
                    f"{API_PREFIX}/operations/preview",
                    json={
                        "operation": "place_devices",
                        "selection": {
                            "filter": {"site_id": [str(site.id)], "limit": 200},
                            "intent_generation": state["intent_generation"],
                            "snapshot_key": state["read_model_snapshot_key"],
                        },
                        "change": {"mode": "unplaced"},
                    },
                )
                preview_samples.append((time.perf_counter() - started) * 1000)
                assert r.status_code == 200, r.text
                assert r.json()["member_count"] == 200
            log.info("preview (200 members) p50 ms: %.1f", statistics.median(preview_samples))
            r = await client.post(
                f"{API_PREFIX}/operations/preview",
                json={
                    "operation": "place_devices",
                    "selection": {
                        "filter": {"limit": 200},
                        "intent_generation": state["intent_generation"],
                        "snapshot_key": state["read_model_snapshot_key"],
                    },
                    "change": {"mode": "unplaced"},
                },
            )
            assert r.status_code == 422, "more than 1000 members is refused"

        plans = {
            "name": sa.text(
                "SELECT * FROM inventory_devices WHERE lower(hostname) LIKE :n AND lifecycle != 'archived' "
                "ORDER BY lower(hostname), id LIMIT 201"
            ).bindparams(n="%host-0042%"),
            "site": sa.text(
                "SELECT * FROM inventory_devices WHERE resolved_site_id = :s AND lifecycle != 'archived' "
                "ORDER BY lower(hostname), id LIMIT 201"
            ).bindparams(s=site.id),
            "source": sa.text(
                "SELECT d.* FROM inventory_devices d WHERE d.lifecycle != 'archived' AND d.id IN ("
                "SELECT o.device_id FROM inventory_observations o "
                "JOIN inventory_targets t ON t.id = o.target_id "
                "WHERE t.source_id = :src AND o.state != 'absent') ORDER BY lower(d.hostname), d.id LIMIT 201"
            ).bindparams(src=source.id),
            "state": sa.text(
                "SELECT * FROM inventory_devices WHERE collection_state IN ('failed', 'partial') "
                "AND lifecycle != 'archived' ORDER BY lower(hostname), id LIMIT 201"
            ),
            "events": sa.text(
                "SELECT * FROM inventory_events WHERE entity_type = 'device' AND entity_id = :e AND id < :b "
                "ORDER BY id DESC LIMIT 11"
            ).bindparams(e=device_id, b=10_000_000),
        }
        async with store._engine.connect() as conn:
            for name, stmt in plans.items():
                rows = (
                    await conn.execute(
                        sa.text(f"EXPLAIN ANALYZE {stmt.text}").bindparams(*stmt._bindparams.values())
                    )
                ).all()
                plan = "\n".join(r[0] for r in rows)
                log.info("EXPLAIN ANALYZE %s:\n%s", name, plan)
                # The site filter and the event page are the selective queries
                # the schema indexes.
                if name in ("site", "events"):
                    assert "Seq Scan" not in plan, f"{name}: sequential scan\n{plan}"
    finally:
        await store.dispose()
    for record in caplog.records:
        print(record.getMessage())


# --- graph enrichment against scratch Neo4j ------------------------------------------------

NEO4J_URI = os.environ.get("NEO4J_TEST_URI")


@pytest.mark.db
@pytest.mark.skipif(not NEO4J_URI, reason="NEO4J_TEST_URI not set")
def test_neo4j_reader_returns_contexts_and_cluster_relations_of_the_published_snapshot():
    """One batched read for a set of devices: the RUNS_ON contexts and the
    MEMBER_OF groups at the read-model snapshot, and nothing from another
    run of the same scope."""
    from hst.app.inventory.observations import Neo4jGraphReader
    from hst.core import db as dbmod
    from hst.core.loader import load
    from hst.core.model import Batch, NodeRecord, RelRecord

    live = Settings(_env_file=None).neo4j_uri
    assert not dbmod.same_endpoint(NEO4J_URI or "", live), "the scratch Neo4j must not be the live twin"
    settings = Settings(
        _env_file=None,
        neo4j_uri=NEO4J_URI,
        neo4j_user=os.environ.get("NEO4J_TEST_USER", "neo4j"),
        neo4j_password=os.environ["NEO4J_TEST_PASSWORD"],
        neo4j_database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j"),
    )
    scope = "test:inventory-related"
    batch = Batch(
        source="gw",
        scope=scope,
        nodes=[
            NodeRecord(
                label="Device",
                uid="dev:x:inv:gw1",
                props={"hostname": "gw1", "platform": "gaia", "role": "firewall"},
            ),
            NodeRecord(
                label="Device",
                uid="dev:x:inv:gw2",
                props={"hostname": "gw2", "platform": "gaia", "role": "firewall"},
            ),
            NodeRecord(
                label="FirewallInstance",
                uid="firewall-instance:inv1",
                props={"name": "vs1", "kind": "virtual-system"},
            ),
            NodeRecord(
                label="RedundancyGroup",
                uid="rgrp:cp-cluster:inv:c1",
                props={"name": "cluster-1", "kind": "cp-cluster"},
            ),
        ],
        rels=[
            RelRecord(
                type="RUNS_ON",
                start_label="FirewallInstance",
                start_uid="firewall-instance:inv1",
                end_label="Device",
                end_uid="dev:x:inv:gw1",
            ),
            RelRecord(
                type="MEMBER_OF",
                start_label="Device",
                start_uid="dev:x:inv:gw1",
                end_label="RedundancyGroup",
                end_uid="rgrp:cp-cluster:inv:c1",
            ),
        ],
    )
    t0, t1 = 1_700_000_000_000, 1_700_000_060_000
    with dbmod.session(settings) as s:
        s.run("MATCH (n:Obj) WHERE n._scope = $scope DETACH DELETE n", scope=scope).consume()
        try:
            load(s, batch, ts_ms=t0, run_id="inv-rel-0", collection_ts=t0)
            # a later run without the cluster relation
            later = batch.model_copy(deep=True)
            later.nodes = [n for n in later.nodes if n.label != "RedundancyGroup"]
            later.rels = [r for r in later.rels if r.rel_type != "MEMBER_OF"]
            load(s, later, ts_ms=t1, run_id="inv-rel-1", collection_ts=t1)
            reader = Neo4jGraphReader(settings)
            at_t0 = reader.related(["dev:x:inv:gw1", "dev:x:inv:gw2", "dev:missing"], str(t0))
            at_t1 = reader.related(["dev:x:inv:gw1"], str(t1))
        finally:
            s.run("MATCH (n:Obj) WHERE n._scope = $scope DETACH DELETE n", scope=scope).consume()
    assert [(r.relation, r.uid, r.label, r.name) for r in at_t0["dev:x:inv:gw1"]] == [
        ("MEMBER_OF", "rgrp:cp-cluster:inv:c1", "RedundancyGroup", "cluster-1"),
        ("RUNS_ON", "firewall-instance:inv1", "FirewallInstance", "vs1"),
    ]
    assert at_t0["dev:x:inv:gw2"] == []
    assert "dev:missing" not in at_t0
    assert [r.relation for r in at_t1["dev:x:inv:gw1"]] == ["RUNS_ON"], (
        "the later snapshot has no cluster relation"
    )
