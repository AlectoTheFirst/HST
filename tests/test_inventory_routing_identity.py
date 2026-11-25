"""The tests check identity and normalization parity for the routing inspection and annotation
layer."""

from __future__ import annotations

import copy
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from tests.app.inventory_fakes import FakeInventoryRepository

from hst import collectors as coll
from hst.app import sources as glue
from hst.app.inventory.contracts import (
    ApplyRequest,
    PreviewOperation,
    PreviewRequest,
    RoutingGroupCreate,
)
from hst.app.inventory.normalization import (
    ALIAS_EFFECTIVE,
    CLASSIFICATION,
    READS_ROUTING_SCOPE,
    backfilled_config,
    effective_identity_anchor,
    freeze_legacy_normalization,
    input_digest,
    v2_namespace,
)
from hst.app.inventory.routing import (
    Actor,
    BatchGraphReader,
    MembershipBasis,
    Neo4jGraphReader,
    RoutingService,
    context_kind,
)
from hst.app.store import Site, Source
from hst.collectors.checkpoint_gateway import CpGatewayConfig, normalize_checkpoint_gateway
from hst.collectors.velocloud import normalize_velocloud
from hst.core import uid
from hst.core.config import DEFAULT_L2_FABRIC, Settings
from hst.core.fixtures import load_fixture
from hst.core.model import Batch

FIXTURES = Path(__file__).parents[1] / "fixtures"
NOW = datetime(2026, 9, 20, 9, 0, tzinfo=UTC)
URI = os.environ.get("NEO4J_TEST_URI")
ACTOR = Actor(id=1, name="ada", permissions=frozenset({"graph.read", "sources.write"}))


# --- 1. normalization freeze parity -------------------------------------------------------------


def _source(name: str, type_: str, config: dict[str, Any], *, enabled: bool = True) -> Source:
    return Source(1, name, type_, config, b"", enabled, NOW, NOW)


def _site(code: str, **params: Any) -> Site:
    return Site(1, code, code.upper(), "", params)


def _settings(**kw: Any) -> Settings:
    return Settings(_env_file=None, **kw)


SITES = {
    "fra": _site("fra", routing_scope="fra-scope"),
    "ams": _site("ams"),
    "home": _site("home"),
}

# (case, collector, config, sites, settings kwargs, expected routing scope, origin,
#  expected l2fabric, origin, pinned keys)
MATRIX = [
    # absent keys: the cycle backfill pins the site code, bypassing the site's own default
    (
        "absent-keys-site-default",
        "vyos",
        {"site_code": "fra"},
        SITES,
        {},
        "fra",
        "backfill",
        DEFAULT_L2_FABRIC,
        "backfill",
    ),
    # absent keys on a row with no site at all: the implicit home
    ("absent-keys-implicit-home", "vyos", {}, SITES, {}, "home", "backfill", DEFAULT_L2_FABRIC, "backfill"),
    # explicit null means inherit: the site's default, then the site code
    (
        "null-site-default",
        "vyos",
        {"site_code": "fra", "routing_scope": None, "l2fabric": None},
        SITES,
        {},
        "fra-scope",
        "site",
        DEFAULT_L2_FABRIC,
        "application",
    ),
    (
        "null-no-site-default",
        "vyos",
        {"site_code": "ams", "routing_scope": None, "l2fabric": None},
        SITES,
        {},
        "ams",
        "site_code",
        DEFAULT_L2_FABRIC,
        "application",
    ),
    # explicit values win
    (
        "explicit",
        "vyos",
        {"site_code": "fra", "routing_scope": "lab", "l2fabric": "dmz"},
        SITES,
        {},
        "lab",
        "group",
        "dmz",
        "group",
    ),
    # a removed or never created site: the code stands in for the scope
    (
        "removed-site",
        "vyos",
        {"site_code": "gone", "routing_scope": None, "l2fabric": None},
        SITES,
        {},
        "gone",
        "site_code",
        DEFAULT_L2_FABRIC,
        "application",
    ),
    # central fabric membership fills a null l2fabric, an explicit value overrides it
    (
        "central-fabric",
        "vyos",
        {"site_code": "ams", "routing_scope": None, "l2fabric": None},
        SITES,
        {"l2_fabrics": {"dmz": ["gw"]}},
        "ams",
        "site_code",
        "dmz",
        "application",
    ),
    (
        "central-fabric-override",
        "vyos",
        {"site_code": "ams", "routing_scope": None, "l2fabric": "campus"},
        SITES,
        {"l2_fabrics": {"dmz": ["gw"]}},
        "ams",
        "site_code",
        "campus",
        "group",
    ),
    # the `l3dom` alias alone: inert for the base model, the site default applies
    (
        "legacy-alias-only",
        "vyos",
        {"site_code": "fra", "l3dom": "old-scope", "l2fabric": None},
        SITES,
        {},
        "fra",
        "backfill",
        DEFAULT_L2_FABRIC,
        "application",
    ),
    (
        "legacy-alias-null-scope",
        "vyos",
        {"site_code": "ams", "l3dom": "old-scope", "routing_scope": None, "l2fabric": None},
        SITES,
        {},
        "ams",
        "site_code",
        DEFAULT_L2_FABRIC,
        "application",
    ),
    # a controller: same resolution, different sensitivity
    (
        "controller",
        "velocloud",
        {"routing_scope": None, "l2fabric": None},
        SITES,
        {},
        "home",
        "site_code",
        DEFAULT_L2_FABRIC,
        "application",
    ),
]


def _v1(row: Source, sites: dict[str, Site], settings: Settings) -> tuple[dict, dict[str, str]]:
    """The v1 resolver the way a cycle runs it: the once-only key backfill of
    app/runs_exec.py _prepare_all, then app/sources.py resolve_normalization."""
    config, _ = backfilled_config(row, settings)
    return glue.resolve_normalization(
        Source(row.id, row.name, row.type, config, b"", True, NOW, NOW), settings, sites=sites
    )


@pytest.mark.parametrize(
    "case,type_,config,sites,settings_kw,scope,scope_origin,fabric,fabric_origin",
    [pytest.param(*row, id=row[0]) for row in MATRIX],
)
def test_frozen_values_equal_the_v1_resolver(
    case, type_, config, sites, settings_kw, scope, scope_origin, fabric, fabric_origin
):
    row = _source("gw", type_, config)
    settings = _settings(**settings_kw)
    frozen = freeze_legacy_normalization(row, sites, settings)
    effective, origins = _v1(row, sites, settings)
    assert frozen.routing_scope.value == effective["routing_scope"] == scope
    assert frozen.l2fabric.value == effective["l2fabric"] == fabric
    assert frozen.site_code.value == effective["site_code"]
    assert frozen.routing_scope.origin == scope_origin
    assert frozen.l2fabric.origin == fabric_origin
    # the v1 origin is "group" wherever the freeze says "backfill": the backfill
    # wrote the value into the row before the resolver saw it
    assert origins["routing_scope"] == ("group" if scope_origin == "backfill" else scope_origin)
    assert origins["l2fabric"] == ("group" if fabric_origin == "backfill" else fabric_origin)
    expected_pinned = tuple(k for k in ("routing_scope", "l2fabric") if k not in config)
    assert frozen.backfill_pinned == expected_pinned
    assert frozen.resolver_version == glue.RESOLVER_VERSION
    # the stored row is never touched by the freeze
    assert row.config == config


def test_frozen_values_are_what_the_collector_config_reads():
    """The effective values the ConfigModel exposes (`effective_routing_scope`,
    `l2fabric`) after the same resolution, for a group collector with the
    `l3dom` alias present and for NetScaler where the alias is a real field."""
    settings = _settings()
    row = _source(
        "gw",
        "vyos",
        {"site_code": "fra", "l3dom": "old-scope", "auth": {"method": "password", "username": "u"}},
    )
    frozen = freeze_legacy_normalization(row, SITES, settings)
    effective, _ = _v1(row, SITES, settings)
    model = glue.model_for("vyos")(**glue.inject_secrets(effective, {"auth.password": "pw"}))
    assert model.effective_routing_scope == frozen.routing_scope.value == "fra"
    assert settings.l2fabric_of(row.name, model.l2fabric) == frozen.l2fabric.value
    # the alias is recorded and marked inert: the resolver's routing_scope wins
    # in AliasChoices("routing_scope", "l3dom")
    assert frozen.l3dom_alias.value == "old-scope" and frozen.l3dom_alias.origin == "alias-inert"
    assert effective_identity_anchor(frozen) == "fra"

    ns_row = _source(
        "lb",
        "netscaler",
        {
            "site_code": "fra",
            "l3dom": "shared-lb",
            "host": "https://ns",
            "scope_name": "dc1-ns01",
            "on_uid": "dev:x",
            "auth": {"username": "u"},
        },
    )
    frozen = freeze_legacy_normalization(ns_row, SITES, settings)
    effective, _ = _v1(ns_row, SITES, settings)
    ns = glue.model_for("netscaler")(**glue.inject_secrets(effective, {"auth.password": "pw"}))
    assert ns.l3dom == "shared-lb" and ns.effective_routing_scope == "fra"
    assert frozen.l3dom_alias.origin == "alias-effective" and frozen.l3dom_alias.sensitivity == "identity"
    # what netscaler.py hands normalize_netscaler as the IpAddress anchor
    assert effective_identity_anchor(frozen) == (ns.l3dom or ns.effective_routing_scope) == "shared-lb"


def test_freeze_is_pure_and_its_digest_tracks_every_input():
    settings = _settings()
    row = _source("gw", "vyos", {"site_code": "fra", "routing_scope": None, "l2fabric": None})
    before = copy.deepcopy(row.config)
    a = freeze_legacy_normalization(row, SITES, settings)
    b = freeze_legacy_normalization(row, SITES, settings)
    assert a == b and row.config == before
    assert a.input_digest == input_digest(row, SITES, settings)
    changed_site = {**SITES, "fra": _site("fra", routing_scope="other")}
    assert freeze_legacy_normalization(row, changed_site, settings).input_digest != a.input_digest
    changed_settings = _settings(l2_fabrics={"dmz": ["gw"]})
    assert freeze_legacy_normalization(row, SITES, changed_settings).input_digest != a.input_digest
    as_dict = a.as_dict()
    assert as_dict["routing_scope"]["value"] == "fra-scope"
    assert json.dumps(as_dict)  # serializable for the migration report


def test_disabled_and_enabled_rows_freeze_alike():
    """The cycle backfills enabled rows only, but a disabled row that is later
    enabled runs through the same backfill; the frozen value is the one it
    collects with, whichever state it is in now."""
    settings = _settings()
    on = freeze_legacy_normalization(_source("gw", "vyos", {"site_code": "fra"}), SITES, settings)
    off = freeze_legacy_normalization(
        _source("gw", "vyos", {"site_code": "fra"}, enabled=False), SITES, settings
    )
    assert on == off


# --- 2. classification ------------------------------------------------------------------------------


def test_classification_covers_the_registry_exactly():
    assert set(CLASSIFICATION) == set(coll.REGISTRY)
    for kind, fields in CLASSIFICATION.items():
        assert set(fields) == {"site_code", "routing_scope", "l2fabric", "l3dom"}, kind
        for name, cls in fields.items():
            assert cls.sensitivity in ("identity", "label"), (kind, name)
            assert cls.evidence and ".py" in cls.evidence, (kind, name)


def test_identity_classification_matches_what_the_collectors_embed_in_uids():
    identity_scope = {k for k, f in CLASSIFICATION.items() if f["routing_scope"].sensitivity == "identity"}
    # NetScaler and every source-scoped endpoint addressing collector
    assert identity_scope == {"apic", "manual", "netscaler", "unifi", "vyos"}
    assert identity_scope <= READS_ROUTING_SCOPE
    # the Cisco family names the declared RoutingDomain from the scope and
    # anchors addresses on the VrfInstance uid, so the scope is a label there
    for kind in ("iosxe", "iosxr", "nxos"):
        assert CLASSIFICATION[kind]["routing_scope"].sensitivity == "label"
        assert CLASSIFICATION[kind]["l2fabric"].sensitivity == "identity"
    identity_fabric = {k for k, f in CLASSIFICATION.items() if f["l2fabric"].sensitivity == "identity"}
    assert identity_fabric == {"checkpoint_gateway", "iosxe", "iosxr", "nxos", "unifi", "vyos"}
    assert (
        {k for k, f in CLASSIFICATION.items() if f["l3dom"].sensitivity == "identity"}
        == ALIAS_EFFECTIVE
        == {"netscaler"}
    )


def test_v2_fallback_namespace_is_keyed_by_the_immutable_source_key():
    assert v2_namespace("edge-gws", "vyos") == "inventory:edge-gws"
    assert v2_namespace("edge-gws", "netscaler") == "inventory:edge-gws"
    # a collector with a native qualified context gets none
    for kind in ("velocloud", "checkpoint_gateway", "checkpoint", "nautobot", "zia", "zpa", "equinix", "ndo"):
        assert v2_namespace("x", kind) is None, kind
    frozen = freeze_legacy_normalization(_source("edge-gws", "vyos", {}), SITES, _settings())
    assert frozen.v2_namespace == "inventory:edge-gws" and frozen.reads_routing_scope
    frozen = freeze_legacy_normalization(_source("vco", "velocloud", {}), SITES, _settings())
    assert frozen.v2_namespace is None and not frozen.reads_routing_scope
    assert effective_identity_anchor(frozen) is None


# --- 3. context identity parity -----------------------------------------------------------------------

ENT = "ent-1"
BR = f"vco:{ENT}:edge:e-br"
HUB = f"vco:{ENT}:edge:e-hub"
# the payload has no `show hostname`, so the in-memory registry names the
# appliance `unknown`, with the start of the hash of its ref
VSX_APPLIANCE = "dev:unknown-ce6a"


def velocloud_batch() -> Batch:
    raw = json.loads((FIXTURES / "enterprise" / "velocloud" / "dia-hub-boundary.json").read_text())
    return normalize_velocloud(raw, scope="velocloud:vco.example")


def vsx_batch() -> Batch:
    config = CpGatewayConfig(
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
    return normalize_checkpoint_gateway(raw, config)


def representative_batches() -> list[Batch]:
    return [
        load_fixture(FIXTURES / "mini-dc.yaml"),
        load_fixture(FIXTURES / "mini-enterprise.yaml"),
        load_fixture(FIXTURES / "path-a.yaml"),
        load_fixture(FIXTURES / "equinix-site.yaml"),
        velocloud_batch(),
        vsx_batch(),
    ]


def _device_uids(batches: list[Batch]) -> list[str]:
    return sorted({n.uid for b in batches for n in b.nodes if n.label == "Device"})


def _context_uids(batches: list[Batch]) -> dict[str, set[str]]:
    """The VrfInstance uids each Device owns, from the batch rels."""
    owned: dict[str, set[str]] = {}
    has_owner: set[str] = set()
    iface_dev: dict[str, str] = {}
    in_vrf: list[tuple[str, str]] = []
    for b in batches:
        for r in b.rels:
            if r.rel_type == "OWNED_BY" and r.start_label == "VrfInstance" and r.end_label == "Device":
                owned.setdefault(r.end_uid, set()).add(r.start_uid)
                has_owner.add(r.start_uid)
            elif r.rel_type == "ON" and r.start_label == "Interface" and r.end_label == "Device":
                iface_dev[r.start_uid] = r.end_uid
            elif r.rel_type == "IN_VRF" and r.start_label == "Interface":
                in_vrf.append((r.start_uid, r.end_uid))
    for iface, vrf in in_vrf:
        if vrf not in has_owner and iface in iface_dev:
            owned.setdefault(iface_dev[iface], set()).add(vrf)
    return owned


async def _inspect(
    service: RoutingService, device_ids: dict[str, uuid.UUID], key: str
) -> dict[str, list[dict]]:
    out = {}
    for graph_uid, device_id in device_ids.items():
        body = (await service.device_routing(device_id, key)).model_dump(mode="json")
        # user groups are the annotation; everything else is observed identity
        for c in body["contexts"]:
            c.pop("user_groups")
        out[graph_uid] = body["contexts"]
    return out


async def _register_all(repo: FakeInventoryRepository, uids: list[str], key: str) -> dict[str, uuid.UUID]:
    ids = {}
    async with repo.transaction() as tx:
        for u in uids:
            device, _ = await tx.register_device(
                u, hostname=u, platform="", management_address="", snapshot_key=key, now=NOW
            )
            ids[u] = device.id
        await tx.advance_read_model(key, NOW)
    return ids


async def _annotate(service: RoutingService, contexts: list[str]) -> None:
    """A create, an add, a remove and an archive: every annotation write."""
    group = await service.create_group(
        RoutingGroupCreate(display_name="parity", context_uids=contexts[:1]), ACTOR
    )
    preview = await service.preview_members(
        PreviewRequest(
            operation=PreviewOperation.EDIT_ROUTING_MEMBERS,
            selection={"ids": [str(group.id)]},
            change={"group_id": str(group.id), "add_context_uids": contexts[1:], "remove_context_uids": []},
        ),
        ACTOR,
    )
    await service.apply_members(ApplyRequest(token=preview.token, idempotency_key="parity-add"), ACTOR)
    preview = await service.preview_members(
        PreviewRequest(
            operation=PreviewOperation.EDIT_ROUTING_MEMBERS,
            selection={"ids": [str(group.id)]},
            change={"group_id": str(group.id), "add_context_uids": [], "remove_context_uids": contexts[:1]},
        ),
        ACTOR,
    )
    await service.apply_members(ApplyRequest(token=preview.token, idempotency_key="parity-remove"), ACTOR)
    detail = await service.get_group(group.id)
    keep = await service.create_group(
        RoutingGroupCreate(display_name="kept", context_uids=contexts[-1:]), ACTOR
    )
    await service.delete_group(group.id, detail.revision, ACTOR)
    assert [m.context_uid for m in (await service.get_group(keep.id)).members] == contexts[-1:]


async def test_inspection_yields_the_collectors_context_uids_and_annotation_writes_change_nothing():
    batches = representative_batches()
    key = "1000"
    reader = BatchGraphReader({key: batches})
    repo = FakeInventoryRepository()
    ids = await _register_all(repo, _device_uids(batches), key)
    service = RoutingService(repo, reader, clock=lambda: NOW)
    before = await _inspect(service, ids, key)
    owned = _context_uids(batches)
    # every context the collectors persisted is inspected under its own uid, no other
    assert {d: {c["context_uid"] for c in cs} for d, cs in before.items() if cs} == owned
    # the collector-contributed identities are the ones the inspection reports
    sdwan = {c["context_uid"]: c for c in before[BR]}
    assert set(sdwan) == {uid.vrf(BR, "corp"), uid.vrf(BR, "global-segment")}
    assert sdwan[uid.vrf(BR, "corp")]["enterprise"] == ENT and sdwan[uid.vrf(BR, "corp")]["segment"] == "corp"
    vsx = {c["identifier"]: c for c in before[VSX_APPLIANCE]}
    assert {vsx["vs:7"]["kind"], vsx["vs:8"]["kind"]} == {"vsx-virtual-system", "vsx-virtual-router"}
    assert all(c["context_uid"].startswith("firewall-vrf-context:") for c in before[VSX_APPLIANCE])
    assert all(c["membership_basis"] == MembershipBasis.NONE for c in before[VSX_APPLIANCE])
    # directed route targets survive on the enterprise fixture
    core = {c["context_uid"]: c for c in before["dev:fra01-core-01"]}
    assert core[uid.vrf("dev:fra01-core-01", "corp")]["route_targets"] == [
        {"value": "65001:50001", "direction": "import"},
        {"value": "65001:50001", "direction": "export"},
    ]
    assert core[uid.vrf("dev:fra01-core-01", "corp")]["membership_basis"] == MembershipBasis.DECLARED
    # every annotation write, then the same inspection
    contexts = sorted(owned[BR] | owned["dev:fra01-core-01"] | owned[VSX_APPLIANCE])
    await _annotate(service, contexts)
    after = await _inspect(service, ids, key)
    assert after == before
    assert [b.model_dump() for b in batches] == [b.model_dump() for b in representative_batches()]


def test_context_kind_is_decided_by_uid_prefix_and_edges_not_by_label():
    reader = BatchGraphReader({"1": [vsx_batch(), velocloud_batch()]})
    index = reader._snapshots["1"]
    systems = list(index.contexts_of(VSX_APPLIANCE))
    assert {ctx.vsid for ctx in systems} == {7, 8}
    for ctx in systems:
        assert ctx.instance_uid is not None and ctx.instance_uid.startswith("firewall-instance:")
        assert ctx.appliance_uid == VSX_APPLIANCE and ctx.vsid in (7, 8)
        # VS 8 is a Device-labeled context node: the kind still comes from the uid prefix
        assert context_kind(ctx) == f"vsx-{ctx.instance_kind}"
    segments = list(index.contexts_of(BR))
    assert segments
    for ctx in segments:
        assert context_kind(ctx) == "sdwan-segment" and ctx.instance_uid is None


# --- 3b. the same on the scratch Neo4j --------------------------------------------------------------

CTS = 1_726_800_000_000  # a run key no other suite uses


def _refuse_if_live() -> None:
    from hst.core import db as dbmod

    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI or "", live):
        pytest.exit(
            f"NEO4J_TEST_URI ({URI}) is the live twin ({live}); point it at a scratch database.", returncode=2
        )


@pytest.fixture
def neo4j_session():
    from neo4j import GraphDatabase

    from hst.core import db as dbmod

    _refuse_if_live()
    driver = GraphDatabase.driver(
        URI, auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"])
    )
    database = os.environ.get("NEO4J_TEST_DATABASE", "neo4j")
    with driver.session(database=database) as s:
        dbmod.init_db(s)
        s.run("MATCH (n:Obj {collection_ts: $cts}) DETACH DELETE n", cts=CTS).consume()
        yield s
        s.run("MATCH (n:Obj {collection_ts: $cts}) DETACH DELETE n", cts=CTS).consume()
    driver.close()


_IDENTITY_ROWS = """
MATCH (n:Obj {collection_ts: $cts})
WHERE n:VrfInstance OR n:RoutingDomain OR n:RouteTarget OR n:Prefix OR n:IpAddress OR n:L3Domain
   OR n:FirewallInstance OR n:SdwanSegment
OPTIONAL MATCH (n)-[r]->(m:Obj {collection_ts: $cts})
WHERE type(r) IN ['MEMBER_OF', 'IMPORTS', 'EXPORTS', 'OWNED_BY', 'IN_CONTEXT', 'RUNS_ON', 'LEARNED_ROUTE',
                  'ORIGINATES', 'IN', 'REALIZES']
RETURN labels(n) AS labels, n.uid AS uid, n.name AS name, n.anchor AS anchor, n.l3dom AS l3dom,
       collect(DISTINCT [type(r), m.uid, coalesce(r.basis, ''), coalesce(r.derived, '')]) AS edges
ORDER BY uid
"""


def _identity_rows(session) -> list[dict]:
    rows = session.run(_IDENTITY_ROWS, cts=CTS).data()
    for r in rows:
        r["labels"] = sorted(r["labels"])
        r["edges"] = sorted(r["edges"])
    return rows


def _load_all(session) -> list[Batch]:
    import test_vyos as tv
    from hst import reasoner
    from hst.collectors.vyos import normalize_vyos
    from hst.core import reasoner as rt_reasoner
    from hst.core.loader import load

    vyos = normalize_vyos(
        {
            "config": tv.CONFIG_PATH_A,
            "version_text": tv.VERSION_PATH_A,
            "links": tv.LINKS_PATH_A,
            "routes_tables": tv.ROUTES_TABLES_PATH_A,
        },
        l3dom="patha",
    )
    batches = [*representative_batches(), vyos]
    for i, batch in enumerate(batches):
        load(session, batch, ts_ms=CTS + i, run_id=f"inv-i04-{i}", collection_ts=CTS)
    reasoner.run(session, ts_ms=CTS + 100, collection_ts=CTS)
    # the cycle's route-target derivation: the rt-component grouping. The routes
    # a route target carries are read where they are used, not written
    settings = Settings(_env_file=None)
    rt_reasoner.execute_rt_domains(session, settings, collection_ts=CTS, ts_ms=CTS + 102)
    # the derived grouping batch as loaded, so the in-memory reader sees the same run
    batches.append(rt_reasoner.derive_rt_domains_batch(session, CTS))
    return batches


def _canon(value: Any) -> Any:
    """A comparable, order-stable copy: tuple keys and sets become strings and
    sorted lists, everything else its JSON form."""
    if isinstance(value, dict):
        return {str(k): _canon(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [_canon(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(str(v) for v in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "__dict__"):
        return _canon(vars(value))
    return str(value)


def _reads(session) -> dict[str, Any]:
    """Trace and assessment outputs over the pinned run."""
    from hst import path as pathmod
    from hst.app import simul_read
    from hst.assessment.evaluation import _model_interfaces

    pinned = pathmod.CycleSession(session, CTS)
    traces = {
        pair: pathmod.trace(pinned, *pair, port=443, proto="tcp")
        for pair in (
            ("10.20.1.50", "10.0.30.10"),
            ("10.0.10.5", "10.0.30.10"),
            ("10.10.10.20", "10.20.20.20"),
        )
    }
    interfaces = [i.__dict__ for i in _model_interfaces(pinned)]
    contexts = sorted({i["context_uid"] for i in interfaces if i["context_uid"]})
    rib = simul_read.read_rib_input(pinned, contexts=contexts)
    return _canon(
        {"traces": traces, "interfaces": interfaces, "rib": rib.input, "rib_errors": rib.errors.as_dicts()}
    )


@pytest.mark.db
@pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")
async def test_annotation_writes_leave_graph_identity_trace_and_assessment_reads_unchanged(neo4j_session):
    import asyncio

    session = neo4j_session
    batches = await asyncio.to_thread(_load_all, session)
    key = str(CTS)
    settings = Settings(_env_file=None)

    from contextlib import contextmanager

    @contextmanager
    def one_session(_settings):
        yield session

    reader = Neo4jGraphReader(settings, session_factory=one_session)
    assert await reader.has_snapshot(key)
    assert not await reader.has_snapshot(str(CTS + 999_999))
    repo = FakeInventoryRepository()
    ids = await _register_all(repo, _device_uids(batches), key)
    service = RoutingService(repo, reader, clock=lambda: NOW)

    identity_before = await asyncio.to_thread(_identity_rows, session)
    reads_before = await asyncio.to_thread(_reads, session)
    inspect_before = await _inspect(service, ids, key)
    assert identity_before and reads_before["interfaces"]
    assert any(t["hops"] for t in reads_before["traces"].values())

    # the typed Cypher and the in-memory walk agree on every device
    memory = RoutingService(repo, BatchGraphReader({key: batches}), clock=lambda: NOW)
    assert await _inspect(memory, ids, key) == inspect_before
    # the reasoner's route-target component is reported as such, never invented
    core = {c["context_uid"]: c for c in inspect_before["dev:fra01-core-01"]}
    assert core[uid.vrf("dev:fra01-core-01", "corp")]["membership_basis"] == MembershipBasis.DECLARED_AND_RT
    assert core[uid.vrf("dev:fra01-core-01", "corp")]["declared_domain"] == "corp"
    for c in inspect_before[VSX_APPLIANCE]:
        assert c["membership_basis"] == MembershipBasis.NONE

    owned = _context_uids(batches)
    vyos_dev = next(n.uid for n in batches[-2].nodes if n.label == "Device")
    assert owned[vyos_dev], "the VyOS half of path A owns at least its global table"
    contexts = sorted(owned[BR] | owned["dev:fra01-core-01"] | owned[VSX_APPLIANCE] | owned[vyos_dev])
    await _annotate(service, contexts)

    assert await asyncio.to_thread(_identity_rows, session) == identity_before
    assert await asyncio.to_thread(_reads, session) == reads_before
    assert await _inspect(service, ids, key) == inspect_before
    # the kept group is visible as an annotation on the pinned view, timestamped
    kept_owner = next(u for u, cs in owned.items() if contexts[-1] in cs)
    routing = await service.device_routing(ids[kept_owner], key)
    annotated = next(c for c in routing.contexts if c.context_uid == contexts[-1])
    assert [g.display_name for g in annotated.user_groups] == ["kept"]
    assert routing.annotations_as_of == NOW
