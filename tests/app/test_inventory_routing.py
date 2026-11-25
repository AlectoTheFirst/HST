"""Routing inspection and routing groups."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from tests.app.conftest import login
from tests.app.inventory_fakes import InventoryFakeStore

from hst.app.inventory import routing_routes
from hst.app.inventory.contracts import (
    ApplyRequest,
    ErrorCode,
    PreviewOperation,
    PreviewRequest,
    RoutingGroupCreate,
    RoutingGroupPatch,
)
from hst.app.inventory.repository import InventoryError, NotFound
from hst.app.inventory.routing import (
    Actor,
    BatchGraphReader,
    ContextKind,
    MembershipBasis,
    ObservedStoreUnavailable,
    RoutingService,
    context_view,
    membership_of,
)
from hst.collectors.checkpoint_gateway import CpGatewayConfig, normalize_checkpoint_gateway
from hst.collectors.velocloud import normalize_velocloud
from hst.core import uid
from hst.core.model import Batch

NOW = datetime(2026, 9, 20, 9, 0, tzinfo=UTC)
FIXTURES = Path(__file__).parents[2] / "fixtures"
DSN = os.environ.get("HST_TEST_PG_DSN")

R1 = "dev:r1"
R2 = "dev:r2"
R1_DEFAULT = uid.vrf(R1, "default")
R1_CORP = uid.vrf(R1, "corp")
R2_CORP = uid.vrf(R2, "corp")
ENT = "ent-1"
BR = f"vco:{ENT}:edge:e-br"
BR_CORP = uid.vrf(BR, "corp")
BR_GLOBAL = uid.vrf(BR, "global-segment")
R3 = "dev:r3"
R3_BLUE = uid.vrf(R3, "blue")
R3_GREEN = uid.vrf(R3, "green")
R3_OLD = uid.vrf(R3, "old")
R3_BOTH = uid.vrf(R3, "both")


def _router(dev: str, *, corp: bool) -> Batch:
    nodes = [
        {"label": "Device", "uid": dev, "props": {"hostname": dev[4:], "platform": "vyos"}},
        {
            "label": "VrfInstance",
            "uid": uid.vrf(dev, "default"),
            "props": {"name": "default", "is_global": True},
        },
        {"label": "RoutingDomain", "uid": uid.routing_domain("lab"), "props": {"name": "lab"}},
    ]
    rels = [
        {"type": "OWNED_BY", "start": ["VrfInstance", uid.vrf(dev, "default")], "end": ["Device", dev]},
        {
            "type": "MEMBER_OF",
            "start": ["VrfInstance", uid.vrf(dev, "default")],
            "end": ["RoutingDomain", uid.routing_domain("lab")],
            "props": {"basis": "declared"},
        },
    ]
    if corp:
        nodes += [
            {"label": "VrfInstance", "uid": uid.vrf(dev, "corp"), "props": {"name": "corp", "rd": "65000:1"}},
            {"label": "RoutingDomain", "uid": uid.routing_domain("lab:corp"), "props": {"name": "lab:corp"}},
            {"label": "RouteTarget", "uid": uid.route_target("65000:1"), "props": {"value": "65000:1"}},
            {"label": "RouteTarget", "uid": uid.route_target("65000:2"), "props": {"value": "65000:2"}},
        ]
        rels += [
            {"type": "OWNED_BY", "start": ["VrfInstance", uid.vrf(dev, "corp")], "end": ["Device", dev]},
            {
                "type": "MEMBER_OF",
                "start": ["VrfInstance", uid.vrf(dev, "corp")],
                "end": ["RoutingDomain", uid.routing_domain("lab:corp")],
                "props": {"basis": "declared"},
            },
            {
                "type": "IMPORTS",
                "start": ["VrfInstance", uid.vrf(dev, "corp")],
                "end": ["RouteTarget", uid.route_target("65000:1")],
            },
            {
                "type": "EXPORTS",
                "start": ["VrfInstance", uid.vrf(dev, "corp")],
                "end": ["RouteTarget", uid.route_target("65000:2")],
            },
        ]
    return Batch.model_validate({"source": "vyos-lab", "scope": f"vyos:{dev}", "nodes": nodes, "rels": rels})


def _basis_router() -> Batch:
    """One router whose four tables carry every membership shape the graph can
    hold: `blue` only the reasoner's `MEMBER_OF {basis: "rt-component"}` edge
    (core/reasoner.py derive_rt_domains), `green` a collector-declared edge and
    the derived one on the same table, `old` only the legacy
    `REALIZES -> L3Domain` edge, `both` a declared edge beside a legacy one."""
    rt_domain = uid.routing_domain("rt:65000:9")
    nodes = [
        {"label": "Device", "uid": R3, "props": {"hostname": "r3", "platform": "vyos"}},
        {
            "label": "RoutingDomain",
            "uid": rt_domain,
            "props": {"name": "rt:65000:9", "basis": "rt-component"},
        },
        {"label": "RoutingDomain", "uid": uid.routing_domain("lab:green"), "props": {"name": "lab:green"}},
        {"label": "RoutingDomain", "uid": uid.routing_domain("lab:both"), "props": {"name": "lab:both"}},
        {"label": "L3Domain", "uid": uid.l3dom("legacy-old"), "props": {"name": "legacy-old"}},
        {"label": "L3Domain", "uid": uid.l3dom("legacy-both"), "props": {"name": "legacy-both"}},
    ]
    rels = []
    for name in ("blue", "green", "old", "both"):
        nodes.append({"label": "VrfInstance", "uid": uid.vrf(R3, name), "props": {"name": name}})
        rels.append({"type": "OWNED_BY", "start": ["VrfInstance", uid.vrf(R3, name)], "end": ["Device", R3]})
    for vrf in (R3_BLUE, R3_GREEN):
        rels.append(
            {
                "type": "MEMBER_OF",
                "start": ["VrfInstance", vrf],
                "end": ["RoutingDomain", rt_domain],
                "props": {"basis": "rt-component"},
            }
        )
    for vrf, domain in ((R3_GREEN, "lab:green"), (R3_BOTH, "lab:both")):
        rels.append(
            {
                "type": "MEMBER_OF",
                "start": ["VrfInstance", vrf],
                "end": ["RoutingDomain", uid.routing_domain(domain)],
                "props": {"basis": "declared"},
            }
        )
    for vrf, domain in ((R3_OLD, "legacy-old"), (R3_BOTH, "legacy-both")):
        rels.append(
            {"type": "REALIZES", "start": ["VrfInstance", vrf], "end": ["L3Domain", uid.l3dom(domain)]}
        )
    return Batch.model_validate({"source": "vyos-lab", "scope": f"vyos:{R3}", "nodes": nodes, "rels": rels})


def velocloud_batch() -> Batch:
    raw = json.loads((FIXTURES / "enterprise" / "velocloud" / "dia-hub-boundary.json").read_text())
    return normalize_velocloud(raw, scope="velocloud:vco.example")


def vsx_config() -> CpGatewayConfig:
    return CpGatewayConfig(
        host="gaia-a",
        auth={"method": "password", "username": "reader", "password": "secret"},
        estate="estate",
        management_authority_uid="manager",
        management_domain_uid="dom-a",
        appliance_uid="member-a",
        observation_uid="snapshot-a",
        vsid_gateway_object_uids={7: "vs-object-7", 8: "vs-object-8"},
        expert_shell_account="reader",
    )


def vsx_batch() -> Batch:
    raw = {
        "contexts": {
            "7": {
                "vsid": 7,
                "kind": "virtual-system",
                "interfaces": [{"ifname": "eth1", "addr_info": [{"local": "192.0.2.1", "prefixlen": 24}]}],
                "routes4": [{"dst": "198.51.100.0/24", "gateway": "192.0.2.2", "dev": "eth1"}],
            },
            "8": {
                "vsid": 8,
                "kind": "virtual-router",
                "interfaces": [{"ifname": "eth1", "addr_info": [{"local": "192.0.2.1", "prefixlen": 24}]}],
            },
        }
    }
    return normalize_checkpoint_gateway(raw, vsx_config())


# the payload has no `show hostname`, so the in-memory registry names the
# appliance `unknown`, with the start of the hash of its ref
VSX_APPLIANCE = "dev:unknown-ce6a"


def reader(current: str = "1000") -> BatchGraphReader:
    return BatchGraphReader(
        {
            "1000": [_router(R1, corp=True), velocloud_batch(), vsx_batch()],
            "2000": [_router(R1, corp=False), _router(R2, corp=True), velocloud_batch(), vsx_batch()],
        },
        current=current,
    )


class Failing:
    """A reader whose store is down."""

    async def current_snapshot(self):
        raise ObservedStoreUnavailable("observed store unavailable: ServiceUnavailable")

    async def has_snapshot(self, snapshot_key):
        raise ObservedStoreUnavailable("observed store unavailable: ServiceUnavailable")

    async def contexts_of(self, device_uid, snapshot_key):
        raise ObservedStoreUnavailable("observed store unavailable: ServiceUnavailable")

    async def segments(self, uids, snapshot_key):
        raise ObservedStoreUnavailable("observed store unavailable: ServiceUnavailable")

    async def present(self, context_uids, snapshot_key):
        raise ObservedStoreUnavailable("observed store unavailable: ServiceUnavailable")


# --- rig ---------------------------------------------------------------------------------------


@pytest.fixture
def store() -> InventoryFakeStore:
    return InventoryFakeStore()


@pytest.fixture
def graph() -> BatchGraphReader:
    return reader()


@pytest.fixture
def app(seeded):
    from hst.app.crypto import generate_key
    from hst.app.main import create_app
    from hst.core import Settings

    return create_app(
        settings=Settings(_env_file=None, hst_secret_key=generate_key()),
        store=seeded,
        register_inventory=False,
    )


@pytest.fixture
def rig(app, seeded, graph):
    routing_routes.register(app, graph)
    return app


async def _register(store: InventoryFakeStore, graph_uid: str, hostname: str, platform: str) -> uuid.UUID:
    async with store.inventory().transaction() as tx:
        device, _ = await tx.register_device(
            graph_uid,
            hostname=hostname,
            platform=platform,
            management_address="",
            snapshot_key="1000",
            now=NOW,
        )
    return device.id


@pytest.fixture
async def devices(seeded):
    return {
        R1: await _register(seeded, R1, "r1", "vyos"),
        R2: await _register(seeded, R2, "r2", "vyos"),
        BR: await _register(seeded, BR, "branch-1", "velocloud-edge"),
        VSX_APPLIANCE: await _register(seeded, VSX_APPLIANCE, "gaia-a", "checkpoint-gaia"),
    }


async def _events(store: InventoryFakeStore, entity_id: str):
    async with store.inventory().transaction() as tx:
        rows, _ = await tx.page_events(entity_type="routing_group", entity_id=entity_id, limit=50)
    return rows


# --- mounting and permissions ----------------------------------------------------------------


def test_register_mounts_every_routing_route_once(app):
    routing_routes.register(app, reader())
    schema = app.openapi()["paths"]
    paths = {(m.upper(), path) for path, ops in schema.items() for m in ops}
    for method, path in (
        ("GET", "/api/inventory/devices/{device_id}/routing"),
        ("GET", "/api/inventory/routing-groups"),
        ("GET", "/api/inventory/routing-groups/{group_id}"),
        ("POST", "/api/inventory/routing-groups"),
        ("PATCH", "/api/inventory/routing-groups/{group_id}"),
        ("DELETE", "/api/inventory/routing-groups/{group_id}"),
        ("POST", "/api/inventory/operations/preview"),
        ("POST", "/api/inventory/operations/apply"),
    ):
        assert (method, path) in paths, (method, path)
    assert set(schema["/api/inventory/routing-groups"]) == {"get", "post"}


async def test_reads_take_graph_read_and_writes_take_sources_write(rig, client, devices):
    routing_url = f"/api/inventory/devices/{devices[R1]}/routing"
    body = {"display_name": "edge-vrfs", "context_uids": [R1_CORP]}
    preview = {
        "operation": "edit_routing_members",
        "selection": {"ids": [str(uuid.uuid4())]},
        "change": {"group_id": str(uuid.uuid4()), "add_context_uids": [], "remove_context_uids": []},
    }
    for username in ("vera", "otto"):
        await login(client, username)
        assert (await client.get("/api/inventory/routing-groups")).status_code == 200
        assert (await client.get(routing_url)).status_code == 200
        assert (await client.post("/api/inventory/routing-groups", json=body)).status_code == 403
        r = await client.patch(
            f"/api/inventory/routing-groups/{uuid.uuid4()}",
            json={"display_name": "x", "expected_revision": 1},
        )
        assert r.status_code == 403
        r = await client.delete(f"/api/inventory/routing-groups/{uuid.uuid4()}?expected_revision=1")
        assert r.status_code == 403
        assert (await client.post("/api/inventory/operations/preview", json=preview)).status_code == 403
        r = await client.post(
            "/api/inventory/operations/apply", json={"token": str(uuid.uuid4()), "idempotency_key": "k"}
        )
        assert r.status_code == 403
    await login(client, "ada")
    assert (await client.post("/api/inventory/routing-groups", json=body)).status_code == 201


async def test_unauthenticated_calls_are_refused(rig, client, devices):
    assert (await client.get("/api/inventory/routing-groups")).status_code == 401
    assert (await client.get(f"/api/inventory/devices/{devices[R1]}/routing")).status_code == 401


# --- inspection ----------------------------------------------------------------------------------


async def test_device_routing_reports_contexts_targets_and_declared_basis(rig, client, devices):
    await login(client, "vera")
    r = await client.get(f"/api/inventory/devices/{devices[R1]}/routing")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["device_id"] == str(devices[R1])
    assert body["snapshot_key"] == "1000"
    assert body["annotations_as_of"] is None
    by_uid = {c["context_uid"]: c for c in body["contexts"]}
    assert list(by_uid) == sorted([R1_CORP, R1_DEFAULT])
    corp = by_uid[R1_CORP]
    assert corp["kind"] == ContextKind.VRF
    assert corp["owner_uid"] == R1
    assert corp["identifier"] == "corp"
    assert corp["declared_domain"] == "lab:corp"
    assert corp["membership_basis"] == MembershipBasis.DECLARED
    assert corp["route_targets"] == [
        {"value": "65000:1", "direction": "import"},
        {"value": "65000:2", "direction": "export"},
    ]
    assert corp["management_domain"] is None and corp["enterprise"] is None and corp["segment"] is None
    assert corp["user_groups"] == []
    default = by_uid[R1_DEFAULT]
    assert default["identifier"] == "default"
    assert default["declared_domain"] == "lab"
    assert default["route_targets"] == []


async def test_sdwan_contexts_carry_enterprise_and_segment_joined_by_uid(rig, client, devices):
    await login(client, "vera")
    body = (await client.get(f"/api/inventory/devices/{devices[BR]}/routing")).json()
    by_uid = {c["context_uid"]: c for c in body["contexts"]}
    corp = by_uid[BR_CORP]
    assert corp["kind"] == ContextKind.SDWAN_SEGMENT
    assert corp["owner_uid"] == BR
    assert corp["enterprise"] == ENT
    assert corp["segment"] == "corp"
    # the table identifier is the segment logicalId the collector keyed the VRF with
    assert corp["identifier"] == "s-1"
    # the collector declares segment membership under the orchestrator scope
    assert corp["declared_domain"] == "velocloud:vco.example:ent-1:corp"
    assert corp["membership_basis"] == MembershipBasis.DECLARED
    glob = by_uid[BR_GLOBAL]
    assert glob["segment"] == "Global Segment"
    assert glob["identifier"] == "s-0"


async def test_vsx_contexts_are_told_apart_by_instance_uid_prefix_not_label(rig, client, devices):
    await login(client, "vera")
    body = (await client.get(f"/api/inventory/devices/{devices[VSX_APPLIANCE]}/routing")).json()
    kinds = {c["identifier"]: c for c in body["contexts"]}
    assert set(kinds) == {"vs:7", "vs:8"}
    vs7, vs8 = kinds["vs:7"], kinds["vs:8"]
    assert vs7["kind"] == "vsx-virtual-system"
    assert vs8["kind"] == "vsx-virtual-router"
    assert vs7["owner_uid"] == vs8["owner_uid"] == VSX_APPLIANCE
    assert vs7["management_domain"] == "dom-a"
    assert vs7["context_uid"].startswith("firewall-vrf-context:")
    # no collector declares a RoutingDomain for a VS and none is invented
    assert vs7["declared_domain"] is None
    assert vs7["membership_basis"] == MembershipBasis.NONE
    assert vs7["route_targets"] == []


async def test_membership_basis_never_reports_derived_or_legacy_grouping_as_declared():
    """A reasoner-derived component and a legacy L3Domain edge are labeled
    for what they are; only a collector-declared edge yields `declared`, and a
    declared edge beside a legacy one is reported as declared."""
    graph = BatchGraphReader({"1000": [_basis_router()]})
    contexts = {c.context_uid: c for c in await graph.contexts_of(R3, "1000")}
    assert set(contexts) == {R3_BLUE, R3_GREEN, R3_OLD, R3_BOTH}
    views = {u: context_view(c, {}, []) for u, c in contexts.items()}

    assert membership_of(contexts[R3_BLUE]) == (None, MembershipBasis.RT_COMPONENT)
    assert views[R3_BLUE].declared_domain is None
    assert views[R3_BLUE].membership_basis == "rt-component"

    assert membership_of(contexts[R3_GREEN]) == ("lab:green", MembershipBasis.DECLARED_AND_RT)
    assert views[R3_GREEN].declared_domain == "lab:green"
    assert views[R3_GREEN].membership_basis == "declared+rt-component"

    assert membership_of(contexts[R3_OLD]) == ("legacy-old", MembershipBasis.LEGACY)
    assert views[R3_OLD].declared_domain == "legacy-old"
    assert views[R3_OLD].membership_basis == "legacy-l3domain"

    assert membership_of(contexts[R3_BOTH]) == ("lab:both", MembershipBasis.DECLARED)
    assert views[R3_BOTH].membership_basis == "declared"


async def test_snapshot_key_pins_a_historical_run_and_rejects_unknown_ones(rig, client, devices):
    await login(client, "ada")
    r = await client.post(
        "/api/inventory/routing-groups", json={"display_name": "g", "context_uids": [R1_CORP]}
    )
    assert r.status_code == 201, r.text
    updated_at = r.json()["updated_at"]
    url = f"/api/inventory/devices/{devices[R1]}/routing"
    old = (await client.get(url, params={"snapshot_key": "1000"})).json()
    new = (await client.get(url, params={"snapshot_key": "2000"})).json()
    assert old["snapshot_key"] == "1000" and new["snapshot_key"] == "2000"
    assert [c["context_uid"] for c in old["contexts"]] == sorted([R1_CORP, R1_DEFAULT])
    assert [c["context_uid"] for c in new["contexts"]] == [R1_DEFAULT]
    # the historical view labels the group as a current annotation with its timestamp
    corp = next(c for c in old["contexts"] if c["context_uid"] == R1_CORP)
    assert corp["user_groups"][0]["display_name"] == "g"
    assert corp["user_groups"][0]["updated_at"] == updated_at
    assert old["annotations_as_of"] == updated_at
    assert new["annotations_as_of"] is None
    r = await client.get(url, params={"snapshot_key": "3000"})
    assert r.status_code == 404 and r.json()["code"] == ErrorCode.NOT_FOUND
    r = await client.get(url, params={"snapshot_key": "latest"})
    assert r.status_code == 422 and r.json()["code"] == ErrorCode.VALIDATION
    r = await client.get(url, params={"snap": "1000"})
    assert r.status_code == 422 and r.json()["code"] == ErrorCode.VALIDATION
    r = await client.get(f"/api/inventory/devices/{uuid.uuid4()}/routing")
    assert r.status_code == 404


async def test_graph_outage_is_a_503_not_an_empty_answer(app, seeded, client, devices):
    routing_routes.register(app, Failing())
    await login(client, "vera")
    r = await client.get(f"/api/inventory/devices/{devices[R1]}/routing")
    assert r.status_code == 503
    assert r.json()["code"] == ErrorCode.OBSERVED_STORE_UNAVAILABLE


# --- group CRUD -----------------------------------------------------------------------------------


async def test_group_crud_with_revisions_and_conflicts(rig, client, seeded, devices):
    await login(client, "ada")
    r = await client.post(
        "/api/inventory/routing-groups",
        json={
            "display_name": "edge-vrfs",
            "description": "corp on the edges",
            "context_uids": [R1_CORP, BR_CORP],
        },
    )
    assert r.status_code == 201, r.text
    group = r.json()
    gid = group["id"]
    assert group["revision"] == 2  # create, then the member write
    assert {m["context_uid"]: m for m in group["members"]}.keys() == {R1_CORP, BR_CORP}
    member = next(m for m in group["members"] if m["context_uid"] == R1_CORP)
    assert member["owner_uid"] == R1 and member["present"] is True and member["actor_id"] is not None
    # a second group with the same name is a conflict
    r = await client.post("/api/inventory/routing-groups", json={"display_name": "edge-vrfs"})
    assert r.status_code == 409 and r.json()["code"] == ErrorCode.CONFLICT
    # a member that no snapshot holds is refused with the offending uids named
    r = await client.post(
        "/api/inventory/routing-groups", json={"display_name": "x", "context_uids": ["vrf:nope"]}
    )
    assert r.status_code == 422 and r.json()["references"] == ["vrf:nope"]
    # an unknown request field is refused
    r = await client.post("/api/inventory/routing-groups", json={"display_name": "y", "colour": "red"})
    assert r.status_code == 422
    # patch: stale then current revision
    r = await client.patch(
        f"/api/inventory/routing-groups/{gid}", json={"display_name": "z", "expected_revision": 1}
    )
    assert r.status_code == 409
    assert r.json()["code"] == ErrorCode.STALE_REVISION and r.json()["current_revision"] == 2
    r = await client.patch(
        f"/api/inventory/routing-groups/{gid}", json={"description": "renamed", "expected_revision": 2}
    )
    assert r.status_code == 200 and r.json()["revision"] == 3 and r.json()["display_name"] == "edge-vrfs"
    assert r.json()["description"] == "renamed"
    # list and detail
    listed = (await client.get("/api/inventory/routing-groups")).json()
    assert [g["id"] for g in listed] == [gid]
    assert (await client.get(f"/api/inventory/routing-groups/{gid}")).json()["revision"] == 3
    # the group shows on the device routing view of both owners
    for dev, ctx in ((R1, R1_CORP), (BR, BR_CORP)):
        body = (await client.get(f"/api/inventory/devices/{devices[dev]}/routing")).json()
        c = next(c for c in body["contexts"] if c["context_uid"] == ctx)
        assert [g["group_id"] for g in c["user_groups"]] == [gid]
    # delete: stale, then archived; archived groups leave every view
    r = await client.delete(f"/api/inventory/routing-groups/{gid}?expected_revision=1")
    assert r.status_code == 409
    r = await client.delete(f"/api/inventory/routing-groups/{gid}?expected_revision=3")
    assert r.status_code == 204
    assert (await client.get(f"/api/inventory/routing-groups/{gid}")).json()["archived_at"] is not None
    assert (await client.get("/api/inventory/routing-groups")).json() == []
    body = (await client.get(f"/api/inventory/devices/{devices[R1]}/routing")).json()
    assert all(c["user_groups"] == [] for c in body["contexts"])
    r = await client.delete(f"/api/inventory/routing-groups/{gid}?expected_revision=4")
    assert r.status_code == 404
    # history: every write left a redacted event with the actor
    events = await _events(seeded, gid)
    assert [e.action for e in events] == ["archive", "update", "create"]
    assert all(e.actor_id is not None for e in events)
    assert events[-1].after["members"] == [R1_CORP, BR_CORP]
    assert events[1].before == {"display_name": "edge-vrfs", "description": "corp on the edges"}


# --- membership through preview and apply ----------------------------------------------------------


async def _create(client, name="g", uids=()):
    r = await client.post(
        "/api/inventory/routing-groups", json={"display_name": name, "context_uids": list(uids)}
    )
    assert r.status_code == 201, r.text
    return r.json()


def _preview_body(gid: str, add=(), remove=()):
    return {
        "operation": "edit_routing_members",
        "selection": {"ids": [gid]},
        "change": {"group_id": gid, "add_context_uids": list(add), "remove_context_uids": list(remove)},
    }


async def test_members_change_through_preview_and_idempotent_apply(rig, client, seeded, devices):
    await login(client, "ada")
    group = await _create(client, "g", [R1_CORP])
    gid = group["id"]
    r = await client.post(
        "/api/inventory/operations/preview", json=_preview_body(gid, add=[BR_CORP, R1_DEFAULT])
    )
    assert r.status_code == 200, r.text
    preview = r.json()
    assert preview["operation"] == "edit_routing_members"
    assert preview["members"] == [{"kind": "routing_group", "id": gid, "revision": 2, "label": "g"}]
    assert preview["member_count"] == 1
    assert preview["affected_device_count"] == 2
    assert preview["affected_target_count"] == 0
    assert preview["changes"]["add_context_uids"] == [BR_CORP, R1_DEFAULT]
    assert preview["warnings"] == []
    token = preview["token"]
    r = await client.post("/api/inventory/operations/apply", json={"token": token, "idempotency_key": "k-1"})
    assert r.status_code == 200, r.text
    applied = r.json()
    assert applied["status"] == "applied"
    assert applied["results"] == [{"kind": "routing_group", "id": gid, "revision": 3}]
    detail = (await client.get(f"/api/inventory/routing-groups/{gid}")).json()
    assert sorted(m["context_uid"] for m in detail["members"]) == sorted([R1_CORP, BR_CORP, R1_DEFAULT])
    assert detail["revision"] == 3
    # the same apply again returns the recorded result
    r = await client.post("/api/inventory/operations/apply", json={"token": token, "idempotency_key": "k-1"})
    assert r.status_code == 200 and r.json()["status"] == "reused"
    assert r.json()["results"] == applied["results"]
    assert (await client.get(f"/api/inventory/routing-groups/{gid}")).json()["revision"] == 3
    # the consumed token cannot be applied under a new key
    r = await client.post("/api/inventory/operations/apply", json={"token": token, "idempotency_key": "k-2"})
    assert r.status_code == 409 and r.json()["code"] == ErrorCode.PREVIEW_EXPIRED
    # a reused key with a different token is an idempotency conflict
    r = await client.post("/api/inventory/operations/preview", json=_preview_body(gid, remove=[R1_DEFAULT]))
    other = r.json()["token"]
    r = await client.post("/api/inventory/operations/apply", json={"token": other, "idempotency_key": "k-1"})
    assert r.status_code == 409 and r.json()["code"] == ErrorCode.IDEMPOTENCY_CONFLICT
    # history carries the membership change with the idempotency key as request id
    events = await _events(seeded, gid)
    change = next(e for e in events if e.action == "members")
    assert change.after["added"] == [BR_CORP, R1_DEFAULT] and change.after["removed"] == []
    assert change.request_id == "k-1"


async def test_preview_validates_group_selection_and_observed_members(rig, client, devices):
    await login(client, "ada")
    gid = (await _create(client, "g", [R1_CORP]))["id"]
    # adding a uid no snapshot holds is refused with the uids named
    r = await client.post("/api/inventory/operations/preview", json=_preview_body(gid, add=["vrf:ghost"]))
    assert r.status_code == 422 and r.json()["references"] == ["vrf:ghost"]
    # the selection must name the group of the change
    body = _preview_body(gid, add=[BR_CORP])
    body["selection"] = {"ids": [str(uuid.uuid4())]}
    r = await client.post("/api/inventory/operations/preview", json=body)
    assert r.status_code == 422
    # an unknown group is not found
    r = await client.post(
        "/api/inventory/operations/preview", json=_preview_body(str(uuid.uuid4()), add=[BR_CORP])
    )
    assert r.status_code == 404
    # a uid on both sides is refused at the request boundary
    r = await client.post(
        "/api/inventory/operations/preview", json=_preview_body(gid, add=[BR_CORP], remove=[BR_CORP])
    )
    assert r.status_code == 422
    # re-adding a member and removing a non-member are warnings, not refusals
    r = await client.post(
        "/api/inventory/operations/preview", json=_preview_body(gid, add=[R1_CORP], remove=[BR_CORP])
    )
    assert r.status_code == 200
    assert r.json()["warnings"] == [f"{R1_CORP} is already a member", f"{BR_CORP} is not a member"]
    # another operation is not served here
    other = {"operation": "archive_devices", "selection": {"ids": [str(uuid.uuid4())]}}
    r = await client.post("/api/inventory/operations/preview", json=other)
    assert r.status_code == 422


async def test_apply_is_refused_when_the_group_changed_after_the_preview(rig, client, devices):
    await login(client, "ada")
    gid = (await _create(client, "g", [R1_CORP]))["id"]
    token = (
        await client.post("/api/inventory/operations/preview", json=_preview_body(gid, add=[BR_CORP]))
    ).json()["token"]
    r = await client.patch(
        f"/api/inventory/routing-groups/{gid}", json={"description": "moved", "expected_revision": 2}
    )
    assert r.status_code == 200
    r = await client.post("/api/inventory/operations/apply", json={"token": token, "idempotency_key": "k"})
    assert r.status_code == 409 and r.json()["code"] == ErrorCode.STALE_REVISION
    # nothing was applied
    members = (await client.get(f"/api/inventory/routing-groups/{gid}")).json()["members"]
    assert [m["context_uid"] for m in members] == [R1_CORP]
    r = await client.post(
        "/api/inventory/operations/apply", json={"token": str(uuid.uuid4()), "idempotency_key": "k2"}
    )
    assert r.status_code == 404


# --- missing references ---------------------------------------------------------------------------


async def test_missing_members_persist_and_never_relink_by_name(app, seeded, client, devices):
    graph = reader(current="1000")
    routing_routes.register(app, graph)
    await login(client, "ada")
    gid = (await _create(client, "g", [R1_CORP]))["id"]
    # the estate moves on: r1 loses corp, r2 gains a VRF of the same name
    graph._current = "2000"
    detail = (await client.get(f"/api/inventory/routing-groups/{gid}")).json()
    assert [(m["context_uid"], m["present"]) for m in detail["members"]] == [(R1_CORP, False)]
    assert detail["members"][0]["owner_uid"] == R1  # the owner as observed when added
    # the decoy on r2 is not a member and its routing view shows no group
    body = (await client.get(f"/api/inventory/devices/{devices[R2]}/routing")).json()
    corp = next(c for c in body["contexts"] if c["context_uid"] == R2_CORP)
    assert corp["identifier"] == "corp" and corp["user_groups"] == []
    # the stale member cannot be re-added (not observed) but can be removed
    r = await client.post("/api/inventory/operations/preview", json=_preview_body(gid, add=[R1_CORP]))
    assert r.status_code == 422
    r = await client.post(
        "/api/inventory/operations/preview", json=_preview_body(gid, remove=[R1_CORP], add=[R2_CORP])
    )
    assert r.status_code == 200
    r = await client.post(
        "/api/inventory/operations/apply", json={"token": r.json()["token"], "idempotency_key": "k"}
    )
    assert r.status_code == 200
    detail = (await client.get(f"/api/inventory/routing-groups/{gid}")).json()
    assert [(m["context_uid"], m["present"], m["owner_uid"]) for m in detail["members"]] == [
        (R2_CORP, True, R2)
    ]


# --- the same service on Postgres ------------------------------------------------------------------


@pytest.mark.pg
@pytest.mark.skipif(not DSN, reason="HST_TEST_PG_DSN not set")
async def test_routing_service_on_postgres_keeps_missing_references_and_events():
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
        user = await store.create_user("ada", "h", "admin")
        repo = store.inventory()
        async with repo.transaction() as tx:
            device, _ = await tx.register_device(
                R1, hostname="r1", platform="vyos", management_address="", snapshot_key="1000", now=NOW
            )
        graph = reader(current="1000")
        actor = Actor(id=user.id, name="ada", permissions=frozenset({"graph.read", "sources.write"}))
        svc = RoutingService(repo, graph, clock=lambda: NOW)
        group = await svc.create_group(RoutingGroupCreate(display_name="g", context_uids=[R1_CORP]), actor)
        assert [m.present for m in group.members] == [True]
        with pytest.raises(InventoryError):
            await svc.create_group(RoutingGroupCreate(display_name="h", context_uids=["vrf:ghost"]), actor)
        preview = await svc.preview_members(
            PreviewRequest(
                operation=PreviewOperation.EDIT_ROUTING_MEMBERS,
                selection={"ids": [str(group.id)]},
                change={
                    "group_id": str(group.id),
                    "add_context_uids": [R1_DEFAULT],
                    "remove_context_uids": [],
                },
            ),
            actor,
        )
        applied = await svc.apply_members(ApplyRequest(token=preview.token, idempotency_key="k"), actor)
        reused = await svc.apply_members(ApplyRequest(token=preview.token, idempotency_key="k"), actor)
        assert applied.status.value == "applied" and reused.status.value == "reused"
        assert reused.results == applied.results
        routing = await svc.device_routing(device.id)
        assert {c.context_uid: [g.display_name for g in c.user_groups] for c in routing.contexts} == {
            R1_CORP: ["g"],
            R1_DEFAULT: ["g"],
        }
        assert routing.annotations_as_of == NOW
        # the estate moves on; the stale member stays as a missing reference
        graph._current = "2000"
        detail = await svc.get_group(group.id)
        assert {m.context_uid: m.present for m in detail.members} == {R1_CORP: False, R1_DEFAULT: True}
        renamed = await svc.patch_group(
            group.id, RoutingGroupPatch(display_name="g2", expected_revision=detail.revision), actor
        )
        await svc.delete_group(group.id, renamed.revision, actor)
        with pytest.raises(NotFound):
            await svc.get_group(uuid.uuid4())
        assert await svc.list_groups() == []
        async with repo.transaction() as tx:
            rows, _ = await tx.page_events(entity_type="routing_group", entity_id=str(group.id), limit=50)
        assert [e.action for e in rows] == ["archive", "update", "members", "create"]
        assert all(e.actor_id == user.id for e in rows)
    finally:
        await store.dispose()
