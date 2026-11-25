"""The engine contracts, checked against the code."""

from __future__ import annotations

import importlib
import re
from collections import defaultdict
from pathlib import Path

from hst.core import labels
from hst.core.labels import (
    GATE_BINDINGS,
    LABELS,
    NOT_DEVICE_BOUND,
    RELS,
    gate_binding_patterns,
)
from hst.core.model import Batch
from hst.path.gates import gate_safeguard_query

# --- registry invariants ----------------------------------------------------------------

_REL_TOKEN = re.compile(r"\[e\d+:([A-Z_|]+)\]")
_LABEL_TOKEN = re.compile(r"\(:([A-Za-z]+)\)")


def test_every_gate_label_declares_its_binding_or_its_exemption():
    gates = {name for name, spec in LABELS.items() if spec.gate}
    missing = gates - set(GATE_BINDINGS)
    assert not missing, f"gate labels with no GATE_BINDINGS entry: {sorted(missing)}"
    extra = set(GATE_BINDINGS) - gates
    assert not extra, f"GATE_BINDINGS names labels that are not gates: {sorted(extra)}"
    for name, patterns in GATE_BINDINGS.items():
        assert patterns, f"{name}: empty binding declaration"
        if patterns[0] == NOT_DEVICE_BOUND:
            assert len(patterns) == 2 and patterns[1], f"{name}: NOT_DEVICE_BOUND needs a reason"


_EVALUATOR_TOKEN = re.compile(r"hst\.(?:path|app)(?:\.[A-Za-z_][A-Za-z0-9_]*)+")
# The other form the rows use: a repository-relative module path,
# e.g. "path/gates/aci.py" or "path/trace.py nat_uids".
_EVALUATOR_FILE = re.compile(r"\b((?:path|app|core|collectors)(?:/[A-Za-z_][A-Za-z0-9_]*)*\.py)\b")
_SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "hst"


def test_zpa_access_rule_reason_names_the_real_evaluator():
    reason = GATE_BINDINGS["ZpaAccessRule"][1]
    assert "hst.path.trace.trace_from_identity" in reason
    assert "no evaluator exists yet" not in reason


def test_not_device_bound_reasons_naming_an_evaluator_reference_real_symbols():
    """A NOT_DEVICE_BOUND reason that names a specific evaluator names
    one that exists."""
    for name, patterns in GATE_BINDINGS.items():
        if patterns[0] != NOT_DEVICE_BOUND:
            continue
        reason = patterns[1]
        for dotted in _EVALUATOR_TOKEN.findall(reason):
            module_path, _, symbol = dotted.rpartition(".")
            module = importlib.import_module(module_path)
            assert hasattr(module, symbol), f"{name}: {dotted!r} does not exist ({reason!r})"
        for relative in _EVALUATOR_FILE.findall(reason):
            assert (_SRC_ROOT / relative).is_file(), f"{name}: {relative!r} does not exist ({reason!r})"


def test_binding_patterns_use_registered_labels_and_relationships():
    for name, patterns in gate_binding_patterns().items():
        for pattern in patterns:
            assert pattern.startswith("(d)"), f"{name}: pattern must start at the device hop: {pattern}"
            assert "(g)" in pattern, f"{name}: pattern must end at the gate: {pattern}"
            rel_tokens = _REL_TOKEN.findall(pattern)
            assert rel_tokens, f"{name}: no e<N>:REL hop in {pattern}"
            for token in rel_tokens:
                for rel in token.split("|"):
                    assert rel in RELS, f"{name}: unregistered relationship {rel} in {pattern}"
            for label in _LABEL_TOKEN.findall(pattern):
                assert label in LABELS, f"{name}: unregistered label {label} in {pattern}"
            # every hop variable is distinct, so the generated guard names each one once
            vars_ = re.findall(r"\[(e\d+):", pattern)
            assert len(vars_) == len(set(vars_)), f"{name}: duplicate hop variable in {pattern}"


def test_safeguard_query_is_generated_from_the_registry():
    query = gate_safeguard_query()
    assert "$snap" in query and "$devs" in query
    for name, patterns in gate_binding_patterns().items():
        assert f"(g:{name})" in query
        for pattern in patterns:
            for var in re.findall(r"\[(e\d+):", pattern):
                assert f"{var}._retired_at IS NULL" in query
    assert "(g:Gate)" not in query


def test_closed_vocabularies_are_declared():
    assert {"access", "nat", "zone"} <= labels.FWRULEBASE_KINDS
    assert {"snat", "dnat", "static"} == labels.NATRULE_KINDS
    assert {"zone-pair", "device", "interface-acl", "object-attached"} == labels.MATCH_CONTEXTS
    assert labels.TUNNEL_LOCAL_END_REL in RELS and labels.TUNNEL_FAR_END_REL in RELS


# --- normalize-to-gate: helpers ---------------------------------------------------------


class _Index:
    """A collector batch as the gate queries see it: nodes by uid, edges by type."""

    def __init__(self, batch: Batch) -> None:
        self.nodes = {n.uid: n for n in batch.nodes}
        self.out: dict[tuple[str, str], list[str]] = defaultdict(list)
        for r in batch.rels:
            self.out[(r.start_uid, r.rel_type)].append(r.end_uid)

    def ends(self, uid: str, rel: str) -> list[str]:
        return self.out.get((uid, rel), [])

    def label(self, uid: str) -> str | None:
        n = self.nodes.get(uid)
        return n.label if n else None


def _rule_match_objects(ix: _Index) -> list[str]:
    """Every NetObject a FwRule matches on (SRC or DST), deduplicated."""
    seen: list[str] = []
    for n in ix.nodes.values():
        if n.label != "FwRule":
            continue
        for rel in ("SRC", "DST"):
            for target in ix.ends(n.uid, rel):
                if ix.label(target) == "NetObject" and target not in seen:
                    seen.append(target)
    return seen


def _carries_addresses(ix: _Index, uid: str) -> bool:
    """Contract 2: RESOLVES_TO targets, a ranges list, or an explicit opaque marker."""
    node = ix.nodes[uid]
    if node.props.get(labels.OPAQUE_PROP):
        return True
    if node.props.get(labels.NETOBJECT_RANGE_PROP):
        return True
    targets = ix.ends(uid, labels.NETOBJECT_ADDRESS_REL)
    return any(ix.label(t) in ("Prefix", "IpAddress", "DnsRecord") for t in targets)


def _assert_net_objects_carry_addresses(batch: Batch) -> None:
    ix = _Index(batch)
    objects = _rule_match_objects(ix)
    assert objects, "the fixture has no rule with a matched NetObject; the check is vacuous"
    bare = [uid for uid in objects if not _carries_addresses(ix, uid)]
    assert not bare, (
        f"NetObjects a rule matches on that carry no RESOLVES_TO, ranges or opaque marker: {bare}"
    )


# --- normalize-to-gate: firewall address carriage ---------------------------------------


def test_vyos_rule_objects_carry_addresses_by_resolves_to():
    from tests.test_vyos import _batch

    _assert_net_objects_carry_addresses(_batch())


def test_unifi_zone_policy_objects_carry_addresses_by_resolves_to():
    from tests.test_unifi import POLICIES, ZONES, _gw_batch

    # the shared fixture matches on ANY only; add one IP-target policy so the
    # address-carriage check has an object to look at
    ip_policy = {
        "_id": "p-ip",
        "index": 9,
        "enabled": True,
        "action": "BLOCK",
        "name": "guest-to-printer",
        "protocol": "tcp",
        "source": {"zone_id": ZONES[0]["_id"], "matching_target": "IP", "ips": ["192.168.20.0/24"]},
        "destination": {
            "zone_id": ZONES[1]["_id"],
            "matching_target": "IP",
            "ips": ["10.0.0.9"],
            "port": 9100,
        },
    }
    batch = _gw_batch(firewall_zones=ZONES, firewall_policies=[*POLICIES, ip_policy])
    _assert_net_objects_carry_addresses(batch)


def test_unifi_classic_rule_objects_carry_addresses_by_resolves_to():
    from tests.test_unifi import CLASSIC_RULES, GROUPS, _gw_batch

    _assert_net_objects_carry_addresses(_gw_batch(firewall_rules=CLASSIC_RULES, firewall_groups=GROUPS))


def test_checkpoint_rule_objects_carry_addresses_by_resolves_to():
    from tests.test_checkpoint import _norm_cp

    _assert_net_objects_carry_addresses(_norm_cp())


def test_cisco_interface_acl_rule_objects_carry_addresses_by_resolves_to():
    """An interface ACL's FwRule SRC/DST NetObjects follow the same
    address-carriage contract as every other vendor's."""
    from tests.test_iosxe import ACL_RAW as IOSXE_ACL_RAW
    from tests.test_iosxe import _collector as _iosxe_collector
    from tests.test_nxos import ACL_RAW as NXOS_ACL_RAW
    from tests.test_nxos import _collector as _nxos_collector

    _assert_net_objects_carry_addresses(_iosxe_collector().normalize(IOSXE_ACL_RAW))
    _assert_net_objects_carry_addresses(_nxos_collector().normalize(NXOS_ACL_RAW))


# --- normalize-to-gate: ACI ---------------------------------------------------------------


def _apic_batch() -> Batch:
    from tests.test_apic import RAW

    from hst.collectors.apic import normalize_apic

    return normalize_apic(RAW, fabric="fab1", l3dom="dc1")


def test_apic_endpoints_carry_addresses_by_has_ip():
    """Contract 3: an Endpoint's addresses are HAS_IP edges, never an `ip` property."""
    ix = _Index(_apic_batch())
    endpoints = [n for n in ix.nodes.values() if n.label == "Endpoint"]
    assert endpoints, "the fixture has no fvCEp endpoint; the check is vacuous"
    for ep in endpoints:
        assert "ip" not in ep.props, f"{ep.uid}: Endpoint.ip is display only, not an address"
        targets = ix.ends(ep.uid, labels.ENDPOINT_ADDRESS_REL)
        assert targets, f"{ep.uid}: no HAS_IP edge"
        assert all(ix.label(t) == "IpAddress" for t in targets)


def test_aci_gate_resolves_endpoints_through_has_ip():
    import inspect

    from hst.path.gates import aci as aci_gate

    source = inspect.getsource(aci_gate._endpoint_epgs)
    assert "e.ip = ip" not in source
    assert "HAS_IP" in source


def test_apic_filter_entries_use_the_property_names_the_gate_reads():
    import inspect

    from hst.path.gates import aci as aci_gate

    ix = _Index(_apic_batch())
    entries = [n for n in ix.nodes.values() if n.label == "FilterEntry"]
    assert entries, "the fixture has no vzEntry; the check is vacuous"
    source = inspect.getsource(aci_gate._contract_rows)
    # a second argument of coalesce(fe.x, fe.y) is a fallback
    legacy = set(re.findall(r"coalesce\(fe\.[a-z_]+,\s*fe\.([a-z_]+)\)", source))
    read = set(re.findall(r"fe\.([a-z_]+)", source)) - legacy
    written = set().union(*(set(e.props) for e in entries))
    unread = read - written
    assert not unread, f"the ACI gate reads FilterEntry properties no collector writes: {sorted(unread)}"


# --- normalize-to-schema: Device.role ----------------------------------------------------


def test_gateway_roles_is_a_subset_of_device_roles():
    # reasoner.py asserts this at module level.
    from hst import reasoner

    assert set(reasoner.GATEWAY_ROLES) <= labels.DEVICE_ROLES


def _assert_device_roles_are_registered(batch: Batch) -> None:
    """The map (web/src/netmap/look.ts ROLE_SYMBOL) and the reasoner
    (GATEWAY_ROLES) key on Device.role."""
    roles = {n.props["role"] for n in batch.nodes if n.label == "Device"}
    assert roles, "the fixture has no Device node; the check is vacuous"
    unregistered = roles - labels.DEVICE_ROLES
    assert not unregistered, f"Device.role values not in core.labels.DEVICE_ROLES: {sorted(unregistered)}"


def test_cisco_common_device_roles_are_registered():
    from tests.test_cisco_common import _batch

    _assert_device_roles_are_registered(_batch())


def test_iosxe_device_roles_are_registered():
    from tests.test_iosxe import RAW as IOSXE_RAW
    from tests.test_iosxe import _collector as _iosxe_collector

    _assert_device_roles_are_registered(_iosxe_collector().normalize(IOSXE_RAW))


def test_nxos_device_roles_are_registered():
    from tests.test_nxos import RAW as NXOS_RAW
    from tests.test_nxos import _collector as _nxos_collector

    _assert_device_roles_are_registered(_nxos_collector().normalize(NXOS_RAW))


def test_iosxr_device_roles_are_registered():
    from tests.test_iosxr import RAW as IOSXR_RAW
    from tests.test_iosxr import _collector as _iosxr_collector

    _assert_device_roles_are_registered(_iosxr_collector().normalize(IOSXR_RAW))


def test_vyos_device_roles_are_registered():
    from tests.test_vyos import _batch as _vyos_batch

    _assert_device_roles_are_registered(_vyos_batch())


def test_unifi_device_roles_are_registered():
    from tests.test_unifi import _gw_batch

    _assert_device_roles_are_registered(_gw_batch())


def test_checkpoint_device_roles_are_registered():
    from tests.test_checkpoint import _norm_cp

    _assert_device_roles_are_registered(_norm_cp())


def test_manual_device_roles_are_registered():
    from tests.test_manual import _collector as _manual_collector

    c = _manual_collector()
    _assert_device_roles_are_registered(c.normalize(c.fetch()))


def test_nautobot_device_roles_are_registered():
    """The recorded home-lab fixture's "Access Point" role lowercases to "access
    point"."""
    from tests.test_nautobot import _norm

    _assert_device_roles_are_registered(_norm())


def test_apic_device_roles_are_registered():
    _assert_device_roles_are_registered(_apic_batch())


# --- normalize-to-schema: the OSPF observation objects -----------------------------------


def _nxos_ospf_batch() -> Batch:
    from tests.test_nxos import RAW as NXOS_RAW
    from tests.test_nxos import _collector as _nxos_collector

    return _nxos_collector().normalize(NXOS_RAW)


_OSPF_LABELS = ("OspfArea", "OspfAdjacency")


def _assert_ospf_objects_registered(batch: Batch) -> None:
    """Convention 10.8, run against one collector's own fixture: every OSPF
    object it emits carries a registered label, and every edge between them a
    registered relationship type."""
    emitted = {n.label for n in batch.nodes}
    assert set(_OSPF_LABELS) <= emitted, "the fixture emits no OSPF objects; the check is vacuous"
    unregistered = emitted - set(LABELS)
    assert not unregistered, f"labels not in core.labels.LABELS: {sorted(unregistered)}"

    ix = _Index(batch)
    ospf_uids = {n.uid for n in batch.nodes if n.label in _OSPF_LABELS}
    touching = {r.rel_type for r in batch.rels if r.start_uid in ospf_uids or r.end_uid in ospf_uids}
    assert touching, "no relationship touches an OSPF object; the check is vacuous"
    assert not touching - RELS, f"relationship types not in core.labels.RELS: {sorted(touching - RELS)}"

    # the carriage the schema documents: an adjacency endpoints its local
    # interface, and an interface in an area points at the OspfArea node
    for adj in (n for n in batch.nodes if n.label == "OspfAdjacency"):
        ends = ix.ends(adj.uid, "ENDPOINT")
        assert ends, f"{adj.uid}: no ENDPOINT edge"
        assert all(ix.label(e) == "Interface" for e in ends)
    areas = [r for r in batch.rels if r.rel_type == "IN_AREA"]
    assert areas, "the fixture emits no IN_AREA edge; the check is vacuous"
    for edge in areas:
        assert (edge.start_label, edge.end_label) == ("Interface", "OspfArea")
        assert ix.label(edge.end_uid) == "OspfArea"


def test_nxos_ospf_objects_use_registered_labels_and_relationship_types():
    _assert_ospf_objects_registered(_nxos_ospf_batch())


def _vyos_ospf_batch() -> Batch:
    from tests.test_vyos import _ospf_batch

    return _ospf_batch()


def test_vyos_ospf_objects_use_registered_labels_and_relationship_types():
    """The same check as NX-OS's, run against VyOS's own fixture."""
    _assert_ospf_objects_registered(_vyos_ospf_batch())


def test_apic_ospf_objects_use_registered_labels_and_relationship_types():
    """The same check, run against APIC's own fixture."""
    _assert_ospf_objects_registered(_apic_batch())


# --- OSPF coverage report: every (platform, table) pair is captured or
# not-captured with a reason ---------------------------------------------------------
#
# "Captured" is a table a run wrote rows for or found empty
# (`TableOutcome.status` in `complete`/`complete-empty`); "not-captured" is a table
# the run declares it cannot answer for this device, with a reason carried in
# `TableOutcome.detail` (core/model.py `_write_side_tables`).


def _ospf_lsdb_outcome(tmp_path, monkeypatch, *, collector_cls, config_cls, host, user, host_key, raw):
    from tests.conftest import FakeSshSession

    from hst.app.crypto import generate_key
    from hst.collectors.auth import SshPassword
    from hst.collectors.base import _write_side_tables
    from hst.core import Settings

    FakeSshSession(raw).install(monkeypatch)
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())
    collector = collector_cls(
        config_cls(host=host, auth=SshPassword(username=user, password="pw"), site_code="hq", l3dom="corp"),
        settings,
    )
    tables = _write_side_tables(
        collector,
        collector.fetch(),
        "edge",
        host_key,
        run_id="1700000000000-aaaaaaaa",
        collection_ts=1000,
        on_write=None,
    )
    return tables["ospf_lsdb"]


def test_iosxe_and_iosxr_ospf_lsdb_table_is_captured_or_not_captured_with_a_reason(tmp_path, monkeypatch):
    import pytest

    pytest.importorskip("duckdb")

    from tests.test_iosxe import HOST as IOSXE_HOST
    from tests.test_iosxe import OSPF_RAW as IOSXE_OSPF_RAW
    from tests.test_iosxe import RAW as IOSXE_RAW
    from tests.test_iosxe import USER as IOSXE_USER
    from tests.test_iosxr import HOST as IOSXR_HOST
    from tests.test_iosxr import OSPF_RAW as IOSXR_OSPF_RAW
    from tests.test_iosxr import RAW as IOSXR_RAW
    from tests.test_iosxr import USER as IOSXR_USER

    from hst.collectors.iosxe import IosxeCollector, IosxeConfig
    from hst.collectors.iosxr import IosxrCollector, IosxrConfig

    platforms = (
        ("iosxe", IosxeCollector, IosxeConfig, IOSXE_HOST, IOSXE_USER, IOSXE_RAW, IOSXE_OSPF_RAW),
        ("iosxr", IosxrCollector, IosxrConfig, IOSXR_HOST, IOSXR_USER, IOSXR_RAW, IOSXR_OSPF_RAW),
    )
    for name, collector_cls, config_cls, host, user, no_ospf_raw, ospf_raw in platforms:
        assert "ospf_lsdb" in collector_cls.SIDE_TABLES, f"{name}: ospf_lsdb not declared in SIDE_TABLES"

        captured = _ospf_lsdb_outcome(
            tmp_path,
            monkeypatch,
            collector_cls=collector_cls,
            config_cls=config_cls,
            host=host,
            user=user,
            host_key=f"{name}-captured",
            raw=ospf_raw,
        )
        assert captured.status in ("complete", "complete-empty"), (
            f"{name}: a device with an OSPF process must read captured, got {captured.status!r}"
        )
        assert captured.status == "complete" and captured.row_count, (
            f"{name}: the fixture carries no LSA rows"
        )

        not_captured = _ospf_lsdb_outcome(
            tmp_path,
            monkeypatch,
            collector_cls=collector_cls,
            config_cls=config_cls,
            host=host,
            user=user,
            host_key=f"{name}-not-captured",
            raw=no_ospf_raw,
        )
        assert not_captured.status == "unsupported", (
            f"{name}: a device with no OSPF process must read not-captured (unsupported), "
            f"got {not_captured.status!r}"
        )
        assert not_captured.detail, f"{name}: a not-captured table must carry a reason"


# --- normalize-to-schema: the declared success condition ---------------------------------


def test_the_dependency_group_kinds_are_the_ones_the_endpoint_maps():
    """The registry's vocabulary and the map POST /api/impact/evaluate builds the
    evaluator's condition from are the same set. A kind in one and not the other is
    either a declaration nothing can read or a reader inventing a kind."""
    from hst.app.routes.impact import _GROUP_KIND_TO_CONDITION

    assert set(_GROUP_KIND_TO_CONDITION) == set(labels.DEPENDENCY_GROUP_KINDS)


def test_zpa_rule_scopes_use_the_registered_vocabulary():
    from tests.test_zpa import RAW

    from hst.collectors.zpa import normalize_zpa

    vendor = [
        {
            "id": "1",
            "action": "ALLOW",
            "ruleOrder": "1",
            "operator": "OR",
            "conditions": [
                {"operator": "OR", "operands": [{"objectType": "APP", "rhs": "2001"}]},
                {"operator": "OR", "negated": True, "operands": [{"objectType": "SCIM_GROUP", "rhs": "7"}]},
            ],
        },
        {
            "id": "2",
            "action": "DENY",
            "ruleOrder": "2",
            "conditions": [
                {"operator": "OR", "operands": [{"objectType": "POSTURE", "lhs": "u", "rhs": "true"}]},
            ],
        },
    ]
    for raw in (RAW, {**RAW, "access_rules": vendor}):
        for n in normalize_zpa(raw, tenant="acme").nodes:
            if n.label in ("ZpaAccessRule", "ZpaClientForwardingRule"):
                assert n.props["identity_scope"] in labels.ZPA_RULE_SCOPES
                assert n.props["app_scope"] in labels.ZPA_RULE_SCOPES


def test_zpa_rule_edges_follow_their_positive_condition_blocks():
    from tests.test_zpa import RAW

    from hst.collectors.zpa import normalize_zpa
    from hst.core import uid

    vendor = [
        {
            "id": "1",
            "action": "ALLOW",
            "ruleOrder": "1",
            "conditions": [
                {
                    "operator": "OR",
                    "operands": [
                        {"objectType": "APP", "rhs": "2001"},
                        {"objectType": "APP_GROUP", "rhs": "3001"},
                    ],
                },
                {
                    "operator": "OR",
                    "negated": True,
                    "operands": [{"objectType": "SCIM_GROUP", "rhs": "7", "idpId": "i"}],
                },
            ],
        },
        {
            "id": "2",
            "action": "REQUIRE_APPROVAL",
            "ruleOrder": "2",
            "conditions": [
                {"operator": "OR", "operands": [{"objectType": "SCIM_GROUP", "rhs": "8", "idpId": "i"}]},
            ],
        },
    ]
    edge_for = {"ALLOW": "GRANTS", "DENY": "DENIES"}
    for raw in (RAW, {**RAW, "access_rules": vendor}):
        batch = normalize_zpa(raw, tenant="acme")
        for rule in raw["access_rules"]:
            ruid = uid.zpa("acme", "rule", rule["id"])
            positive = [c for c in rule["conditions"] if not c.get("negated")]
            ops = [op for c in positive for op in c["operands"]]
            want_for = {uid.zpa("acme", "seg", op["rhs"]) for op in ops if op["objectType"] == "APP"} | {
                uid.zpa("acme", "seggrp", op["rhs"]) for op in ops if op["objectType"] == "APP_GROUP"
            }
            got_for = {r.end_uid for r in batch.rels if r.rel_type == "FOR" and r.start_uid == ruid}
            assert got_for == want_for, rule["id"]
            rel = edge_for.get(rule["action"].upper(), "APPLIES_TO")
            identity = {
                r.end_uid
                for r in batch.rels
                if r.start_uid == ruid and r.rel_type in ("GRANTS", "DENIES", "APPLIES_TO")
            }
            assert len(identity) == len(
                {
                    (op.get("idpId"), op.get("rhs") or op.get("name"))
                    for op in ops
                    if op["objectType"] == "SCIM_GROUP"
                }
            )
            assert all(r.rel_type == rel for r in batch.rels if r.start_uid == ruid and r.end_uid in identity)


def test_zpa_access_actions_use_the_registered_vocabulary():
    from tests.test_zpa import RAW

    from hst.collectors.zpa import normalize_zpa

    for n in normalize_zpa(RAW, tenant="acme").nodes:
        if n.label == "ZpaAccessRule" and "action" in n.props:
            assert n.props["action"] in labels.ZPA_ACCESS_ACTIONS
