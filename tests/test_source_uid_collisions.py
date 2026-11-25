"""Objects of two sources, or two objects of one source, never fold onto one
uid."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from tests import test_unifi as tu
from tests import test_vyos as tv
from tests.test_loader_unit import MergingSession

from hst.app import sources as glue
from hst.app.inventory.collection import ORIGIN_FALLBACK, frozen_normalization_values
from hst.app.inventory.normalization import backfilled_config, freeze_legacy_normalization
from hst.app.store import Site, Source
from hst.collectors.unifi import normalize_unifi
from hst.collectors.vyos import normalize_vyos
from hst.core import Settings
from hst.core.identity import MemoryResolver
from hst.core.loader import SOURCE_LOCAL_LABELS, load, rival_writers
from hst.core.model import Batch

NOW = datetime(2026, 10, 1, tzinfo=UTC)


def _settings() -> Settings:
    return Settings(_env_file=None)


def _row(name: str, type_: str, config: dict[str, Any], id_: int = 1) -> Source:
    return Source(id_, name, type_, config, b"", True, NOW, NOW)


def _unifi_row(name: str, id_: int = 1, **config: Any) -> Source:
    return _row(
        name,
        "unifi",
        {"url": f"https://{name}", "auth": {"method": "user_password", "username": "ro"}, **config},
        id_,
    )


class _Secrets:
    def resolve(self, row: Source) -> dict[str, str]:
        return {"auth.password": "pw"}


def _gw(**extra: Any) -> Batch:
    raw = {**tu.RAW, "devices": tu.RAW["devices"] + [tu.UDM], **extra}
    return normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default")


# --- UniFi objects keyed by the controller's id ------------------------------------------


def test_groups_whose_names_fold_alike_stay_two_objects():
    groups = [
        {"_id": "g1", "name": "Cameras", "group_type": "address-group", "group_members": ["192.168.30.50"]},
        {"_id": "g2", "name": "cameras", "group_type": "address-group", "group_members": ["10.0.0.0/8"]},
        {"_id": "g3", "name": "Web Ports", "group_type": "port-group", "group_members": [80]},
        {"_id": "g4", "name": "web-ports", "group_type": "port-group", "group_members": [8443]},
    ]
    rule = {"ruleset": "LAN_IN", "enabled": True, "protocol": "tcp", "action": "drop"}
    rules = [
        {
            **rule,
            "_id": "r1",
            "rule_index": 2000,
            "src_firewallgroup_ids": ["g1"],
            "dst_firewallgroup_ids": ["g3"],
        },
        {
            **rule,
            "_id": "r2",
            "rule_index": 2001,
            "src_firewallgroup_ids": ["g2"],
            "dst_firewallgroup_ids": ["g4"],
        },
    ]
    batch = _gw(firewall_rules=rules, firewall_groups=groups)

    nets = {n.uid: n.props for n in batch.nodes if n.label == "NetObject" and n.props.get("kind") == "group"}
    assert set(nets) == {"unifi:default:grp:g1", "unifi:default:grp:g2"}
    assert {p["name"] for p in nets.values()} == {"Cameras", "cameras"}
    members = {
        (r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "RESOLVES_TO" and r.start_uid in nets
    }
    assert members == {
        ("unifi:default:grp:g1", "ip:home:192.168.30.50"),
        ("unifi:default:grp:g2", "pfx:home:10.0.0.0/8"),
    }
    svcs = {n.uid: n.props for n in batch.nodes if n.label == "SvcObject" and n.props.get("kind") == "group"}
    assert svcs["unifi:default:svc:grp:g3"]["ports"] == ["80"]
    assert svcs["unifi:default:svc:grp:g4"]["ports"] == ["8443"]


def test_zone_pairs_whose_name_slugs_join_alike_get_two_rulebases():
    zones = [
        {"_id": "za-b", "name": "A-B", "network_ids": []},
        {"_id": "zc", "name": "C", "network_ids": []},
        {"_id": "za", "name": "A", "network_ids": []},
        {"_id": "zb-c", "name": "B-C", "network_ids": []},
    ]
    policy = {"enabled": True, "protocol": "all", "action": "BLOCK"}
    policies = [
        {**policy, "_id": "p1", "index": 1, "source": {"zone_id": "za-b"}, "destination": {"zone_id": "zc"}},
        {**policy, "_id": "p2", "index": 2, "source": {"zone_id": "za"}, "destination": {"zone_id": "zb-c"}},
    ]
    batch = _gw(firewall_zones=zones, firewall_policies=policies)

    rulebases = {n.uid: n.props["name"] for n in batch.nodes if n.label == "FwRulebase"}
    assert rulebases == {"unifi:default:fw:zone:za-b:zc": "A-B-C", "unifi:default:fw:zone:za:zb-c": "A-B-C"}
    held = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "HAS_RULE"}
    assert {rb for rb, _ in held} == set(rulebases)
    assert len(held) == 2
    assert {n.uid for n in batch.nodes if n.label == "Zone"} == {
        "unifi:default:zone:za-b",
        "unifi:default:zone:zc",
        "unifi:default:zone:za",
        "unifi:default:zone:zb-c",
    }


def test_ssids_are_keyed_by_the_console_and_the_wlan_id():
    """Two WLANs whose names fold alike are two SSIDs, each bridged to its own
    VLAN, and the console's partition, not the site code, heads the uid."""
    raw = copy.deepcopy(tu.RAW)
    raw["wlans"] = [
        {"_id": "w1", "name": "Corp", "networkconf_id": "n1"},
        {"_id": "w2", "name": "corp", "networkconf_id": "n30"},
    ]
    batch = normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default", partition="hq:default")
    bridged = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "BRIDGED_TO"}
    assert bridged == {
        ("ssid:unifi:hq:default:w1", "vlan:unifi:hq:default:1"),
        ("ssid:unifi:hq:default:w2", "vlan:unifi:hq:default:30"),
    }


# --- a controller row falls back to its own routing scope --------------------------------


def test_a_controller_row_with_no_routing_scope_falls_back_to_its_own_namespace():
    """A controller row that states no site falls back to `inventory:<row>`."""
    sites = {"hq": Site(id=1, code="hq", name="HQ", location="", params={"routing_scope": "corp"})}
    payload, origins = glue.resolve_normalization(_unifi_row("branch-a"), _settings(), sites=sites)
    assert (payload["site_code"], payload["routing_scope"], origins["routing_scope"]) == (
        "home",
        "inventory:branch-a",
        "source",
    )
    # a site param is the group's inheritance, not a controller's
    payload, _ = glue.resolve_normalization(_unifi_row("branch-a", site_code="hq"), _settings(), sites=sites)
    assert payload["routing_scope"] == "inventory:branch-a"

    stated, origins = glue.resolve_normalization(_unifi_row("branch-a", routing_scope="corp"), _settings())
    assert (stated["routing_scope"], origins["routing_scope"]) == ("corp", "group")

    group, origins = glue.resolve_normalization(
        _row("edge", "vyos", {"site_code": "hq"}), _settings(), sites=sites
    )
    assert (group["routing_scope"], origins["routing_scope"]) == ("corp", "site")
    # a controller that does not read the scope keeps the site fallback
    vco, origins = glue.resolve_normalization(_row("vco", "velocloud", {}), _settings())
    assert (vco["routing_scope"], origins["routing_scope"]) == ("home", "site_code")


def test_the_backfill_pins_no_implicit_site_into_a_controller_row():
    assert glue.backfill_routing_scope(_unifi_row("branch-a")) is None
    assert glue.backfill_routing_scope(_unifi_row("branch-a", site_code="hq")) == "hq"
    assert glue.backfill_routing_scope(_row("edge", "vyos", {})) == "home"

    config, pinned = backfilled_config(_unifi_row("branch-a"), _settings())
    assert config["routing_scope"] is None and "routing_scope" in pinned
    frozen = freeze_legacy_normalization(_unifi_row("branch-a"), {}, _settings())
    assert (frozen.routing_scope.value, frozen.routing_scope.origin) == ("inventory:branch-a", "source")


def _frozen(scope_origin: str, site_origin: str, scope: str = "home") -> SimpleNamespace:
    return SimpleNamespace(
        frozen_normalization={
            "values": {"site_code": "home", "routing_scope": scope, "l2fabric": "fab0"},
            "origins": {"site_code": site_origin, "routing_scope": scope_origin, "l2fabric": "application"},
        }
    )


def test_a_frozen_implicit_home_scope_is_re_resolved_per_source():
    """Under v2 a frozen 'home' that came from the implicit site is replaced by
    the row's own namespace. A scope the row stated, a group's scope and a
    frozen value with no origins are kept."""
    row = _unifi_row("branch-a")
    for origin in ("site_code", "backfill"):
        got = frozen_normalization_values(row, _frozen(origin, "implicit"), _settings())
        assert got["values"]["routing_scope"] == "inventory:branch-a"
        assert got["origins"]["routing_scope"] == ORIGIN_FALLBACK

    kept = frozen_normalization_values(row, _frozen("group", "implicit"), _settings())
    assert kept["values"]["routing_scope"] == "home"
    kept = frozen_normalization_values(row, _frozen("site_code", "group"), _settings())
    assert kept["values"]["routing_scope"] == "home"
    kept = frozen_normalization_values(
        _row("edge", "vyos", {}), _frozen("site_code", "implicit"), _settings()
    )
    assert kept["values"]["routing_scope"] == "home"
    flat = SimpleNamespace(frozen_normalization={"site_code": "home", "routing_scope": "home"})
    assert frozen_normalization_values(row, flat, _settings())["values"]["routing_scope"] == "home"


def _console(name: str, id_: int, registry: MemoryResolver):
    return glue.build_collector(_unifi_row(name, id_), _settings(), _Secrets(), identity=registry)


def test_two_unifi_rows_with_no_routing_scope_share_no_prefix_endpoint_or_ssid():
    registry = MemoryResolver()
    a, b = _console("branch-a", 1, registry), _console("branch-b", 2, registry)
    assert (a.config.effective_routing_scope, b.config.effective_routing_scope) == (
        "inventory:branch-a",
        "inventory:branch-b",
    )
    raw_b = copy.deepcopy(tu.RAW)
    for device in raw_b["devices"]:
        device["mac"] = device["mac"][:-2] + "ee"
    one, two = a.normalize(copy.deepcopy(tu.RAW)), b.normalize(raw_b)

    def uids(batch: Batch, label: str) -> set[str]:
        return {n.uid for n in batch.nodes if n.label == label}

    assert uids(one, "Prefix") and uids(one, "Prefix") & uids(two, "Prefix") == set()
    assert uids(one, "Endpoint") & uids(two, "Endpoint") == set()
    assert uids(one, "Ssid") & uids(two, "Ssid") == set()
    assert "ep:unifi:branch-a:default:112233445566" in uids(one, "Endpoint")


def test_a_save_names_the_other_controller_row_on_its_routing_scope():
    rows = [
        _unifi_row("branch-a", 1, routing_scope="corp"),
        _unifi_row("branch-b", 2, routing_scope="corp"),
        _unifi_row("branch-c", 3),
        _row("edge", "vyos", {"site_code": "corp"}, 4),
    ]
    scopes = {r.name: glue.resolve_normalization(r, _settings())[0]["routing_scope"] for r in rows}
    scopes["edge"] = "corp"
    warnings = glue.shared_routing_scope_warnings(rows[0], rows, scopes)
    assert len(warnings) == 1
    assert "'corp'" in warnings[0] and "branch-b" in warnings[0]
    # a group shares its site's scope by design and is not compared
    assert "edge" not in warnings[0]
    assert glue.shared_routing_scope_warnings(rows[2], rows, scopes) == []
    assert glue.shared_routing_scope_warnings(rows[3], rows, scopes) == []


# --- the load warning for two writers of one source-local uid ---------------------------


def _batch(collector: str, source: str, nodes: list[tuple[str, str, dict]]) -> Batch:
    return Batch.model_validate(
        {
            "source": source,
            "scope": f"{collector}:{source}",
            "nodes": [{"label": label, "uid": u, "props": props} for label, u, props in nodes],
        }
    )


def test_two_rows_of_one_collector_type_on_one_policy_uid_are_warned_with_both_writers():
    s = MergingSession()
    rulebase = ("FwRulebase", "unifi:default:fw:lan_in", {"name": "LAN_IN"})
    first = load(s, _batch("unifi", "branch-a", [rulebase]), ts_ms=1_000, collection_ts=42)
    second = load(s, _batch("unifi", "branch-b", [rulebase]), ts_ms=1_001, collection_ts=42)

    assert first.warnings == []
    assert len(second.warnings) == 1
    text = second.warnings[0]
    assert "FwRulebase" in text and "unifi/branch-a" in text and "unifi/branch-b" in text
    assert "unifi:default:fw:lan_in" in text


def test_shared_labels_other_collector_types_and_reloads_are_not_warned():
    s = MergingSession()
    device = ("Device", "dev:fdo123", {"hostname": "leaf-101", "role": "leaf"})
    domain = ("BridgeDomain", "bd:vlan:fab0:30", {"vid": 30})
    zone = ("Zone", "x:zone:inside", {"name": "inside"})
    load(s, _batch("apic", "fab1", [device, domain, zone]), ts_ms=1_000, collection_ts=42)
    # another collector type, and labels two sources share by design
    other = load(s, _batch("nxos", "dc1-leaves", [device, domain, zone]), ts_ms=1_001, collection_ts=42)
    # the same row writing again in the run
    again = load(s, _batch("apic", "fab1", [device, domain, zone]), ts_ms=1_002, collection_ts=42)
    assert other.warnings == [] and again.warnings == []


def test_a_device_load_keeps_the_loader_warning_beside_the_batch_warnings(tmp_path):
    """load_payload copies the batch's warnings onto the manifest; it keeps the
    loader's beside them, so the run detail names both writers."""
    from tests import test_collector_execute as tce

    from hst import collectors as coll
    from hst.collectors.util import GraphBuilder

    class RuleCollector(tce.DevCollector):
        def normalize(self, raw):
            b = GraphBuilder()
            b.node("FwRule", "nxos:edge:fw:acl:10", action="drop")
            batch = b.batch(self.config.source_name, self.scope)
            batch.warnings.append("a batch warning")
            return batch

    class Session:
        def execute_write(self, work):
            return work(self)

        def run(self, q, **p):
            class _Result:
                def data(self_inner):
                    if "UNWIND $rows" in q and "MERGE (n" in q:
                        before = {"collected_at": 1, "_sources": ["row-a"], "_scope": "nxos:row-a"}
                        return [{"uid": r["uid"], "before": before} for r in p["rows"]]
                    return []

            return _Result()

    collector = RuleCollector(tce.HostCfg(host="edge", source_name="row-b"), tce._settings(tmp_path))
    manifest = coll.load_payload(collector, Session(), {"seen": 1}, collection_ts=42, run_id="r1", ts_ms=1)

    assert manifest.warnings[0] == "a batch warning"
    assert len(manifest.warnings) == 2
    assert "nxos/row-a" in manifest.warnings[1] and "nxos/row-b" in manifest.warnings[1]


def test_a_carried_copy_is_not_a_rival():
    before = {"collected_at": 1, "carried": True, "_sources": ["branch-a"], "_scope": "unifi:branch-a"}
    assert rival_writers("FwRule", "unifi", "branch-b", before) == []
    before["carried"] = False
    assert rival_writers("FwRule", "unifi", "branch-b", before) == ["unifi/branch-a"]
    assert rival_writers("Device", "unifi", "branch-b", before) == []


# --- two sources with identical names, loaded into one run ------------------------------

# Two source rows write these labels under one uid by design.
SHARED_BY_DESIGN = {"BridgeDomain", "IpAddress", "Prefix", "RoutingDomain"}


def test_two_sources_with_identical_names_share_only_uids_of_shared_labels():
    """Two UniFi consoles with identical networks, zones, groups, WLANs and
    site id, and two VyOS routers with one hostname and one configuration,
    each pair from two source rows. Loaded into one run, the pairs share no
    uid outside the labels shared by design, and the loader warns of nothing."""
    registry = MemoryResolver()
    unifi: dict[str, Batch] = {}
    for i, name in enumerate(("branch-a", "branch-b"), 1):
        raw = copy.deepcopy(tu.RAW)
        raw["devices"] = [*raw["devices"], copy.deepcopy(tu.UDM)]
        raw["firewall_zones"], raw["firewall_policies"] = copy.deepcopy(tu.ZONES), copy.deepcopy(tu.POLICIES)
        raw["firewall_groups"], raw["firewall_rules"] = (
            copy.deepcopy(tu.GROUPS),
            copy.deepcopy(tu.CLASSIC_RULES),
        )
        # two consoles' own hardware: names repeat, serials and MACs do not
        for device in raw["devices"]:
            device["mac"] = device["mac"][:-2] + f"{i:02x}"
            if device.get("serial"):
                device["serial"] = f"{device['serial']}-{i}"
        unifi[name] = _console(name, i, registry).normalize(raw).model_copy(update={"source": name})
    vyos = {
        name: normalize_vyos(
            {"config": tv.CONFIG, "version_text": "Hardware S/N:     Unknown\n", "links": tv.LINKS},
            l3dom="home",
            source_name=name,
            resolver=registry,
        ).model_copy(update={"source": name})
        for name in ("vyos1", "vyos2")
    }

    for one, two in (tuple(unifi.values()), tuple(vyos.values())):
        labels = {n.label for n in one.nodes}
        assert labels & SOURCE_LOCAL_LABELS, labels
        shared = {(n.label, n.uid) for n in one.nodes} & {(n.label, n.uid) for n in two.nodes}
        assert {label for label, _ in shared} <= SHARED_BY_DESIGN, sorted(shared)

    s = MergingSession()
    manifests = [
        load(s, batch, ts_ms=1_000 + i, collection_ts=42)
        for i, batch in enumerate([*unifi.values(), *vyos.values()])
    ]
    assert [w for m in manifests for w in m.warnings] == []
