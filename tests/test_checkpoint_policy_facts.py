"""Check Point policy facts that every engine reads the same way.

The tracer, the analysis model, impact and change simulation read these
facts from the management collector: package targets `all` and failed package reads,
the layer's implicit cleanup action, the meta-info revision
and the replay key, the releases and implied-rule coverage that
qualify a package, with installation evidence for the other vendors,
group objects in NAT columns and the reply of a permitted flow.
The last test builds one estate with two gateways, two ordered
layers, an install-on rule, a group NAT rule and a reply flow, and holds the
tracer's verdicts to the symbolic policy's.
"""

from __future__ import annotations

import copy
import ipaddress
from typing import Any

import httpx
from tests.support import checkpoint_batch
from tests.test_checkpoint import _cfg, make_mock
from tests.test_firewall_rule_scope import (
    ACCEPT,
    ANY,
    DOMAIN,
    DROP,
    TARGETS,
    ZONES,
    _cp_rule,
    _gw_batch,
    _inventory,
    _rows,
)
from tests.test_fw_overlay import NAT_QUERY, changeset
from tests.test_fw_overlay import _nat_row as overlay_nat_row

import hst.path as path
from hst.analysis_model.catalogs import project_catalogs
from hst.analysis_model.checkpoint_graph import checkpoint_policy
from hst.analysis_model.graph import GraphNode
from hst.analysis_model.network import _access_policy, _bindings, _node_installed, _state_admission
from hst.analysis_model.overlay import _rebuild
from hst.app.crypto import generate_key
from hst.assessment.regression import SEMANTIC_FIELDS, rule_as_add
from hst.collectors.checkpoint import (
    VENDOR_STATE_POLICY,
    CpCollector,
    _implied_rules_complete,
    _policy_revision,
)
from hst.collectors.cisco_common import acl_stage
from hst.collectors.util import GraphBuilder
from hst.core import Settings
from hst.impact.evaluate import _StatePolicyFilter
from hst.path.gates import firewall as fw
from hst.path.gates.nat import _NAT_RULES_QUERY_STRICT, _nat_stage_rules
from hst.path.verdict import DENY, INDETERMINATE, PERMIT, classify_action
from hst.policy.graph import _state_rules_default
from hst.policy.ir import AllOf, AnyOf, Atom, Constant, ExecutionContext, Not, Ref, Unknown
from hst.policy.nat import _row as nat_row
from hst.policy.nat import normalize_nat_rules
from hst.simul.fw_overlay import _NAT_ROW_DEFAULTS

# --- the estate ---------------------------------------------------------------------

WEB = {"uid": "web", "name": "web", "type": "host", "domain": DOMAIN, "ipv4-address": "10.9.1.1"}
BLOCKED = {"uid": "blocked", "name": "blocked", "type": "host", "domain": DOMAIN, "ipv4-address": "10.9.9.9"}
LAN1 = {
    "uid": "lan1",
    "name": "lan1",
    "type": "network",
    "domain": DOMAIN,
    "subnet4": "10.1.0.0",
    "mask-length4": 24,
}
LANS = {"uid": "lans", "name": "LANS", "type": "group", "domain": DOMAIN, "members": ["lan1"]}
HIDE = {"uid": "hide", "name": "hide", "type": "host", "domain": DOMAIN, "ipv4-address": "198.51.100.1"}
SSH = {
    "uid": "ssh",
    "name": "ssh",
    "type": "service-tcp",
    "domain": DOMAIN,
    "port": "22",
    "source-port": "",
    "protocol": "",
    "match-by-protocol-signature": False,
}
OBJECTS = [ANY, ACCEPT, DROP, TARGETS, WEB, BLOCKED, LAN1, LANS, HIDE, SSH]
META = {"last-modify-time": {"posix": 100}, "last-modifier": "admin"}


def _layer(uid: str, name: str, cleanup: str | None) -> dict[str, Any]:
    layer = {"uid": uid, "name": name, "type": "access-layer", "domain": DOMAIN, "meta-info": META}
    if cleanup is not None:
        layer["implicit-cleanup-action"] = cleanup
    return layer


def _gateway(uid: str, name: str, kind: str = "simple-gateway", **extra: Any) -> dict[str, Any]:
    return {"uid": uid, "name": name, "type": kind, "version": "R81.20", **extra}


MGMT = _gateway(
    "mgmt", "mgmt", "checkpoint-host", **{"management-blades": {"network-policy-management": True}}
)


def _nat_rule() -> dict[str, Any]:
    """A manual hide rule: the LANS group leaves as the hide address."""
    return {
        "uid": "n1",
        "type": "nat-rule",
        "rule-number": 1,
        "enabled": True,
        "method": "hide",
        "original-source": "lans",
        "original-destination": "any",
        "original-service": "any",
        "translated-source": "hide",
        "translated-destination": "any",
        "translated-service": "any",
        "install-on": ["policy-targets"],
    }


def _estate(**over: Any) -> dict[str, Any]:
    """Two gateways and one package of two ordered layers. Network accepts
    ssh to web on gw-a only (install-on) and cleans up with drop; App drops
    traffic to `blocked` and cleans up with accept. The package's NAT hides
    the LANS group. No release is given in the payload: the collector reads
    them from the gateway objects, and the api version from fetch."""
    package = {
        "uid": "package",
        "name": "Policy",
        "type": "package",
        "domain": DOMAIN,
        "access-layers": ["net", "app"],
        "installation-targets": ["gw-a", "gw-b"],
    }
    raw = {
        "gateways": [_gateway("gw-a", "fw-a"), _gateway("gw-b", "fw-b"), MGMT],
        "layers": [_layer("net", "Network", "drop"), _layer("app", "Application", "accept")],
        "packages": [package],
        "package_details": {"package": package},
        "package_revisions": {"package": "100|admin"},
        "rulebases": {
            "net": [
                {
                    "rulebase": [
                        _cp_rule(
                            "r1",
                            1,
                            "accept",
                            destination=["web"],
                            service=["ssh"],
                            **{"install-on": ["gw-a"]},
                        )
                    ],
                    "objects-dictionary": OBJECTS,
                }
            ],
            "app": [
                {
                    "rulebase": [_cp_rule("a1", 1, "drop", destination=["blocked"])],
                    "objects-dictionary": OBJECTS,
                }
            ],
        },
        "nat": {"Policy": [{"rulebase": [_nat_rule()], "objects-dictionary": OBJECTS}]},
        "policy_section_errors": [],
        "api_version": "1.9",
        "implied_rules_complete": True,
    }
    raw.update(over)
    return raw


def _batch(raw: dict[str, Any]):
    return checkpoint_batch.normalize(raw, mgmt="manager", domain="domain")


def _device(graph, raw_uid: str) -> str:
    return next(u for u in graph.labels["Device"] if graph.nodes[u].props.get("cp_raw_uid") == raw_uid)


def _enforces(batch) -> dict[tuple[str, str], dict[str, Any]]:
    """(gateway api uid, rulebase name) to the ENFORCES edge's properties."""
    raw_uid = {n.uid: n.props.get("cp_raw_uid") for n in batch.nodes if n.label == "Device"}
    names = {n.uid: n.props.get("name") for n in batch.nodes if n.label == "FwRulebase"}
    return {
        (raw_uid[r.start_uid], names[r.end_uid]): dict(r.props)
        for r in batch.rels
        if r.rel_type == "ENFORCES" and r.start_uid in raw_uid
    }


def _rulebase_props(batch) -> dict[str, dict[str, Any]]:
    return {n.props.get("name"): dict(n.props) for n in batch.nodes if n.label == "FwRulebase"}


# --- installation targets "all" and failed package reads ----------------------------


def _all_targets(targets: Any) -> dict[str, Any]:
    raw = _estate(
        gateways=[
            _gateway("gw-a", "fw-a"),
            _gateway("gw-b", "fw-b"),
            _gateway(
                "cl", "cluster", "simple-cluster", **{"cluster-members": [{"uid": "m1"}, {"uid": "m2"}]}
            ),
            _gateway("m1", "member-1", "cluster-member"),
            _gateway("m2", "member-2", "cluster-member"),
            MGMT,
        ]
    )
    raw["package_details"]["package"] = {**raw["package_details"]["package"], "installation-targets": targets}
    return raw


def test_targets_all_binds_every_firewall_that_is_not_a_cluster_member():
    """`all` is the API value for a package installed on every gateway (the
    Standard default). It names the firewalls and the cluster object, never
    a member or the management."""
    for targets in ("all", ["all"]):
        edges = _enforces(_batch(_all_targets(targets)))
        bound = {gw for gw, name in edges if name == "Network"}
        assert bound == {"gw-a", "gw-b", "cl"}, targets
        assert all(edges[gw, "Network"].get("configured") is True for gw in bound)
        assert {gw for gw, name in edges if name == "NAT:Policy"} == {"gw-a", "gw-b", "cl"}


def test_all_beside_another_package_on_the_same_gateway_is_approximate():
    """A gateway holds one installed access policy: `all` cannot say whether
    it is this package or the other one that names the gateway."""
    raw = _estate()
    other = {
        "uid": "other",
        "name": "Other",
        "type": "package",
        "domain": DOMAIN,
        "access-layers": ["app"],
        "installation-targets": ["gw-a"],
    }
    raw["packages"] = [raw["packages"][0], other]
    raw["package_details"] = {
        "package": {
            **raw["package_details"]["package"],
            "access-layers": ["net"],
            "installation-targets": "all",
        },
        "other": other,
    }
    edges = _enforces(_batch(raw))
    assert edges["gw-a", "Network"].get("approximate") is True
    assert edges["gw-b", "Network"].get("configured") is True
    # the other package's explicit target on gw-a is the same open question:
    # either package may be the one installed there
    assert edges["gw-a", "Application"].get("approximate") is True


def test_a_failed_package_read_binds_the_rulebases_no_package_claims_approximately():
    """A show-package failure for one package leaves its layers and its NAT
    claimed by no captured package; they bind to every firewall,
    approximately, and the gate reads them as undecided."""
    raw = _estate()
    second = {"uid": "second", "name": "Second", "type": "package", "domain": DOMAIN}
    raw["packages"] = [raw["packages"][0], second]
    raw["package_details"]["package"] = {
        **raw["package_details"]["package"],
        "access-layers": ["net"],
        "installation-targets": ["gw-a"],
    }
    raw["nat"]["Second"] = [{"rulebase": [{**_nat_rule(), "uid": "n2"}], "objects-dictionary": OBJECTS}]
    raw["policy_section_errors"] = ["show-package second: HTTP 500"]
    edges = _enforces(_batch(raw))
    # gw-b is claimed by no captured package: the failed one may be installed
    # there and share Network, so it binds Network approximately
    assert edges["gw-a", "Network"].get("configured") is True
    assert edges["gw-b", "Network"].get("approximate") is True
    for name in ("Application", "NAT:Second"):
        assert edges["gw-a", name].get("approximate") is True, name
        assert edges["gw-b", name].get("approximate") is True, name
    assert edges["gw-a", "NAT:Policy"].get("configured") is True and ("gw-b", "NAT:Policy") not in edges


def test_a_failed_show_packages_binds_every_layer_approximately():
    raw = _estate(packages=[], package_details={}, nat={}, policy_section_errors=["show-packages: HTTP 500"])
    edges = _enforces(_batch(raw))
    for gw in ("gw-a", "gw-b"):
        for name in ("Network", "Application"):
            assert edges[gw, name].get("approximate") is True
    assert ("mgmt", "Network") not in edges


# --- the layer's implicit cleanup action --------------------------------------------


def _rb_row(props: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """A rulebase row as the candidate query returns it."""
    return {
        "rb_uid": props.get("uid", "rb"),
        "rb_name": props.get("name"),
        "vendor": props.get("vendor"),
        "af": props.get("af"),
        "default_action": props.get("default_action"),
        "default_action_unknown": props.get("default_action_unknown"),
        "global_state_policy": props.get("global_state_policy"),
        "state_policy_basis": props.get("state_policy_basis"),
        "established_default_unknown": props.get("established_default_unknown"),
        "match_context": props.get("match_context"),
        "chain": props.get("chain"),
        "approximate": False,
        **extra,
    }


def test_the_layer_records_its_implicit_cleanup_action():
    raw = _estate(
        layers=[
            _layer("net", "Network", "Drop"),
            _layer("app", "Application", "accept"),
            _layer("other", "Other", None),
        ]
    )
    props = _rulebase_props(_batch(raw))
    assert (props["Network"]["default_action"], props["Network"]["default_action_unknown"]) == ("drop", False)
    assert (props["Application"]["default_action"], props["Application"]["default_action_unknown"]) == (
        "accept",
        False,
    )
    assert props["Other"].get("default_action") is None and props["Other"]["default_action_unknown"] is True


def test_the_gate_falls_through_to_the_cleanup_action_and_an_unstated_one_is_undecided():
    """An Application layer with cleanup accept permits a flow its explicit rules miss."""
    raw = _estate(layers=[_layer("net", "Network", "drop"), _layer("app", "Application", "accept")])
    props = _rulebase_props(_batch(raw))
    assert classify_action(fw._default_action_result(_rb_row(props["Application"]), [])["action"]) == PERMIT
    assert classify_action(fw._default_action_result(_rb_row(props["Network"]), [])["action"]) == DENY
    unstated = _rulebase_props(_batch(_estate(layers=[_layer("net", "Network", None)])))["Network"]
    result = fw._default_action_result(_rb_row(unstated), [])
    assert classify_action(result["action"]) == INDETERMINATE


def test_an_inline_layer_records_its_own_implicit_cleanup_action():
    """An inline layer (Apply Layer) has its own cleanup action, read
    as an ordered layer's is."""
    raw = _estate(
        layers=[
            _layer("net", "Network", "drop"),
            _layer("app", "Application", "accept"),
            _layer("inl", "Inline", "accept"),
        ]
    )
    raw["rulebases"]["net"][0]["rulebase"].append(
        _cp_rule("r2", 2, "accept", destination=["web"], **{"inline-layer": "inl"})
    )
    raw["rulebases"]["inl"] = [{"rulebase": [], "objects-dictionary": OBJECTS}]
    props = _rulebase_props(_batch(raw))
    assert (props["Inline"]["default_action"], props["Inline"]["default_action_unknown"]) == ("accept", False)


def test_layers_are_read_with_full_details(monkeypatch):
    """implicit-cleanup-action and meta-info come with details-level full."""
    transport, calls = make_mock()
    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: transport)
    CpCollector(_cfg(), Settings(_env_file=None)).fetch()
    (body,) = [body for cmd, body in calls["cmds"] if cmd == "show-access-layers"]
    assert body["details-level"] == "full"


# --- the meta-info revision and the replay key --------------------------------------


def test_the_policy_revision_is_read_from_meta_info():
    assert (
        _policy_revision({"meta-info": {"last-modify-time": {"posix": 5}, "last-modifier": "bob"}}) == "5|bob"
    )
    # a reply that carries the fields at the top level reads the same
    assert _policy_revision({"last-modify-time": {"posix": 5}, "last-modifier": "bob"}) == "5|bob"
    assert _policy_revision({"meta-info": {"creator": "bob"}}) is None
    raw = _estate(package_revisions={})
    assert _rulebase_props(_batch(raw))["Network"]["configured_revision"] == "100|admin"


def _replaying(transport, published: dict[str, str]):
    """make_mock's handler with the layer's revision under meta-info and the
    published session taken from `published`."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("show-last-published-session"):
            return httpx.Response(200, json={"uid": published["uid"]})
        response = transport.handler(request)
        if request.url.path.endswith("show-access-layers"):
            data = response.json()
            data["access-layers"][0]["meta-info"] = {
                "last-modify-time": {"posix": 111},
                "last-modifier": "admin",
            }
            return httpx.Response(200, json=data)
        return response

    return handler


def test_a_meta_info_revision_replays_and_a_new_publish_refetches(monkeypatch, tmp_path):
    """The replay key is the published session with the layer's own
    revision: an object edit publishes a new session without touching the
    layer's revision, and must not be served from the cache."""
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())
    transport, _calls = make_mock()
    published = {"uid": "pub-1"}
    monkeypatch.setattr(
        "hst.collectors.checkpoint._transport",
        lambda config: httpx.MockTransport(_replaying(transport, published)),
    )
    collector = CpCollector(_cfg(), settings)
    assert collector.fetch()["replayed_layers"] == []
    assert collector.fetch()["replayed_layers"] == ["lay-1"]
    published["uid"] = "pub-2"
    out = collector.fetch()
    assert out["replayed_layers"] == []
    assert out["published_session"] == "pub-2"


# --- releases, implied rules and installation evidence ------------------------------


def test_the_releases_come_from_the_gateway_objects_and_qualify_the_package():
    """CheckpointProfile needs the management, gateway and API releases."""
    batch = _batch(_estate())
    (package,) = [n.props for n in batch.nodes if n.label == "CpPolicyPackage"]
    assert (package["management_release"], package["gateway_release"], package["api_version"]) == (
        "R81.20",
        "R81.20",
        "1.9",
    )
    assert package["implied_complete"] is True
    graph = _inventory(batch)
    context = ExecutionContext("estate", "manager", "domain", _device(graph, "gw-a"), "vrf", 4)
    rulebases = tuple(u for u in graph.labels["FwRulebase"] if graph.nodes[u].props.get("kind") == "access")
    assert checkpoint_policy(graph, rulebases, context, Constant(True)) is not None


def test_a_package_across_gateway_releases_has_no_gateway_release():
    raw = _estate(gateways=[_gateway("gw-a", "fw-a"), {**_gateway("gw-b", "fw-b"), "version": "R82"}, MGMT])
    (package,) = [n.props for n in _batch(raw).nodes if n.label == "CpPolicyPackage"]
    assert package.get("gateway_release") is None
    assert package["management_release"] == "R81.20"


def test_implied_rules_are_complete_only_when_read_and_every_switch_is_off():
    assert _implied_rules_complete({"firewall": {"accept-control-connections": False, "accept-icmp": False}})
    assert not _implied_rules_complete({"firewall": {"accept-control-connections": True}})
    assert not _implied_rules_complete({"firewall": {"accept-control-connections": "yes"}})
    assert not _implied_rules_complete({"firewall": {}})
    assert not _implied_rules_complete({})


def test_fetch_records_the_api_version_published_session_and_implied_rule_coverage(monkeypatch):
    transport, _calls = make_mock()
    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: transport)
    out = CpCollector(_cfg(), Settings(_env_file=None)).fetch()
    assert out["api_version"] == "1.9"
    assert out["published_session"] == "pub-1"
    # the mock enables the control-connections implied rule
    assert out["implied_rules_complete"] is False


def _cisco_acl(bindings: list[dict[str, str]]):
    b = GraphBuilder()
    b.node("Device", "dev:r1", hostname="r1", role="router")
    inter = {"interfaces": [{"name": "Gi1"}], "acl": {"lists": {"EDGE": []}, "bindings": bindings}}
    acl_stage(b, inter, dev="dev:r1", scope="cisco:r1")
    return b.batch("cisco", "cisco:r1")


def test_a_cisco_access_list_binding_carries_installation_evidence_the_model_accepts():
    context = ExecutionContext("estate", "graph", "graph", "dev:r1", "vrf", 4)
    batch = _cisco_acl([{"interface": "Gi1", "direction": "in", "acl": "EDGE"}])
    (edge,) = [r.props for r in batch.rels if r.rel_type == "ENFORCES"]
    assert edge["installed"] is True and edge["coverage"] == "complete" and edge["installed_revision"]
    assert _bindings(_inventory(batch), context, None, None, 4)[1] == Constant(True)
    # a binding to an interface the device did not report: not proven
    partial = _cisco_acl([{"interface": "Gi9", "direction": "in", "acl": "EDGE"}])
    assert _bindings(_inventory(partial), context, None, None, 4)[1] != Constant(True)


def test_a_binding_unreported_elsewhere_does_not_hide_the_installation_on_the_packets_interfaces():
    """An interface ACL installed and read, partial only because one of
    its bindings names an interface the device did not report, is installed
    on a packet whose own interfaces the graph names otherwise. A packet on a
    side the walk does not know, or on an interface of the unreported name,
    stays unproven."""
    from hst.core import uid as uids

    gi1, gi2 = uids.interface("dev:r1", "Gi1"), uids.interface("dev:r1", "Gi2")

    def graph(gi1_name: str = "Gi1"):
        b = GraphBuilder()
        b.node("Device", "dev:r1", hostname="r1", role="router")
        b.node("Interface", gi1, name=gi1_name)
        b.node("Interface", gi2, name="Gi2")
        inter = {
            "interfaces": [{"name": "Gi1"}, {"name": "Gi2"}],
            "acl": {
                "lists": {"EDGE": []},
                "bindings": [
                    {"interface": "Gi1", "direction": "in", "acl": "EDGE"},
                    {"interface": "Gi9", "direction": "in", "acl": "EDGE"},
                ],
            },
        }
        acl_stage(b, inter, dev="dev:r1", scope="cisco:r1")
        batch = b.batch("cisco", "cisco:r1")
        for relation in batch.rels:
            if relation.rel_type == "ENFORCES":
                # as a collector that read the list records it: installed,
                # partial only for the unreported binding
                relation.props["installed"] = True
        return _inventory(batch)

    context = ExecutionContext("estate", "graph", "graph", "dev:r1", "vrf", 4)
    assert _bindings(graph(), context, gi1, gi2, 4)[1] == Constant(True)
    assert _bindings(graph(), context, None, gi2, 4)[1] != Constant(True)
    assert _bindings(graph("gi9"), context, gi1, gi2, 4)[1] != Constant(True)


def test_a_unifi_zone_policy_carries_installation_evidence_and_a_classic_ruleset_its_interface_binding():
    policy = {
        "_id": "p1",
        "name": "allow",
        "index": 30000,
        "action": "ALLOW",
        "enabled": True,
        "protocol": "all",
        "source": {"zone_id": "z2", "matching_target": "ANY"},
        "destination": {"zone_id": "z1", "matching_target": "ANY"},
    }
    classic = {
        "_id": "c1",
        "ruleset": "LAN_IN",
        "rule_index": 2000,
        "name": "c1",
        "action": "accept",
        "enabled": True,
        "protocol": "all",
    }
    batch = _gw_batch(firewall_zones=ZONES, firewall_policies=[policy], firewall_rules=[classic])
    nodes = {n.uid: n.props for n in batch.nodes}
    assert _node_installed(nodes["unifi:default:fw:zone:z2:z1"])
    zones = [p for p in nodes.values() if p.get("name") in ("Internal", "Hotspot") and "installed" in p]
    assert len(zones) == 2 and all(_node_installed(p) for p in zones)
    (edge,) = [r for r in batch.rels if r.rel_type == "ENFORCES" and r.end_uid == "unifi:default:fw:lan_in"]
    assert edge.props["installed"] is True
    # LAN_IN is an interface ACL: its PROTECTED_BY edges carry the inbound
    # binding to each LAN network's gateway interface, and the edge applies on
    # every interface, as an IOS-XE access list's does
    assert edge.props["ingress_interface_uid"] == "*" and edge.props["egress_interface_uid"] == "*"
    bound = {(r.start_uid, r.props["direction"]) for r in batch.rels if r.rel_type == "PROTECTED_BY"}
    assert bound == {("dev:gateway/if/br1", "in"), ("dev:gateway/if/br30", "in")}


# --- group objects in NAT columns ---------------------------------------------------


def _packet(
    source: str, destination: str = "203.0.113.9", protocol: int = 6, port: int = 443
) -> dict[str, int]:
    return {
        "source_address": int(ipaddress.ip_address(source)),
        "destination_address": int(ipaddress.ip_address(destination)),
        "protocol": protocol,
        "source_port": 40000,
        "destination_port": port,
    }


def _truth(predicate: Any, packet: dict[str, int], objects: dict[Any, Any] | None = None) -> bool | None:
    """Three-valued truth of a policy predicate on one packet; None when an
    Unknown term decides it."""
    if isinstance(predicate, Constant):
        return predicate.value
    if isinstance(predicate, Unknown):
        return None
    if isinstance(predicate, Ref):
        definition = (objects or {}).get(predicate.key)
        return None if definition is None else _truth(definition.predicate, packet, objects)
    if isinstance(predicate, Atom):
        value = packet[predicate.field]
        if predicate.operation == "eq":
            return value == predicate.value
        if predicate.operation == "range":
            return predicate.value <= value <= int(predicate.other or 0)
        return value & int(predicate.other or 0) == predicate.value & int(predicate.other or 0)
    if isinstance(predicate, Not):
        inner = _truth(predicate.term, packet, objects)
        return None if inner is None else not inner
    values = [_truth(term, packet, objects) for term in predicate.terms]
    if isinstance(predicate, AllOf):
        return False if False in values else None if None in values else True
    assert isinstance(predicate, AnyOf)
    return True if True in values else None if None in values else False


def _nat_graph(raw: dict[str, Any]):
    graph = _inventory(_batch(raw))
    (rulebase,) = [
        graph.nodes[u] for u in graph.labels["FwRulebase"] if graph.nodes[u].props.get("kind") == "nat"
    ]
    (rule,) = graph.targets(rulebase.uid, "HAS_RULE")
    return graph, rulebase, rule


def test_a_group_original_source_matches_its_members_only():
    """The group carries its addresses as RESOLVES_TO edges."""
    graph, rulebase, rule = _nat_graph(_estate())
    row = nat_row(graph, rulebase, rule, False, {"gw-a", "gw-b"})
    assert row["orig_src_addrs"] and not row["orig_src_opaque"]
    (snat,) = _nat_stage_rules([row], "snat", None)
    assert not snat["opaque"]
    assert snat["match_src"] == path._intervals(["10.1.0.0/24"])
    specs = normalize_nat_rules(
        graph, _device(graph, "gw-a"), ingress_interface_uid=None, egress_interface_uid=None, address_family=4
    )
    (spec,) = [s for s in specs if s.stage == "snat"]
    assert spec.gap_code is None
    assert _truth(spec.predicate, _packet("10.1.0.5")) is True
    assert _truth(spec.predicate, _packet("172.16.9.9")) is False


def test_the_nat_query_reads_each_columns_closure_ranges_and_opacity():
    for alias in ("orig_src", "orig_dst", "xlate_src", "xlate_dst"):
        assert f"AS {alias}_addrs" in _NAT_RULES_QUERY_STRICT
        assert f"AS {alias}_opaque" in _NAT_RULES_QUERY_STRICT
    assert _NAT_RULES_QUERY_STRICT.count(":RESOLVES_TO]") == 4
    assert "collect(DISTINCT ost.ranges)" in _NAT_RULES_QUERY_STRICT
    assert "collect(DISTINCT ost.ip6)" in _NAT_RULES_QUERY_STRICT


def test_a_group_resolved_only_in_part_leaves_the_rule_unresolved_not_narrowed():
    """A member without an address makes the group opaque: the resolved part
    is not the whole group, so the rule claims its packets as undecided."""
    unknown = {"uid": "dyn", "name": "dyn", "type": "dynamic-object", "domain": DOMAIN}
    raw = _estate()
    objects = [*OBJECTS[:-3], {**LANS, "members": ["lan1", "dyn"]}, HIDE, SSH, unknown]
    raw["nat"]["Policy"][0]["objects-dictionary"] = objects
    graph, rulebase, rule = _nat_graph(raw)
    row = nat_row(graph, rulebase, rule, False, {"gw-a", "gw-b"})
    assert row["orig_src_opaque"] is True
    (snat,) = _nat_stage_rules([row], "snat", None)
    assert snat["opaque"] is True and snat["match_src"] == []
    specs = normalize_nat_rules(
        graph, _device(graph, "gw-a"), ingress_interface_uid=None, egress_interface_uid=None, address_family=4
    )
    (spec,) = [s for s in specs if s.stage == "snat"]
    assert spec.gap_code == "NAT_MATCH_OBJECT_UNRESOLVED"


def test_a_dual_stack_original_object_contributes_both_addresses():
    dual = {
        "uid": "lan1",
        "name": "lan1",
        "type": "network",
        "domain": DOMAIN,
        "subnet4": "10.1.0.0",
        "mask-length4": 24,
        "subnet6": "2001:db8::",
        "mask-length6": 64,
    }
    raw = _estate()
    raw["nat"]["Policy"][0]["objects-dictionary"] = [o for o in OBJECTS if o["uid"] != "lan1"] + [dual]
    graph, rulebase, rule = _nat_graph(raw)
    row = nat_row(graph, rulebase, rule, False, set())
    families = {version for version, _lo, _hi in path._intervals(row["orig_src_addrs"])}
    assert families == {4, 6}


def test_change_simulation_carries_the_column_opacity_and_a_restated_column_clears_it():
    for alias in ("orig_src", "orig_dst", "xlate_src", "xlate_dst"):
        assert _NAT_ROW_DEFAULTS[f"{alias}_opaque"] is False
    changes = changeset(
        [
            {
                "kind": "nat_rule.modify",
                "params": {"device": "dev:fw1", "rule": "nat:10", "orig_src": "10.5.0.0/24"},
            }
        ]
    )
    collected = overlay_nat_row("nat:10", 10, orig_src_opaque=True, orig_src_present=True)
    (out,) = changes.rewrite(NAT_QUERY, {"dev": "dev:fw1"}, [collected])
    assert out["orig_src_opaque"] is False and out["orig_src_addrs"] == ["10.5.0.0/24"]


# --- the reply of a permitted flow --------------------------------------------------


def test_a_checkpoint_layer_records_the_vendors_stateful_behaviour():
    props = _rulebase_props(_batch(_estate()))
    for name in ("Network", "Application"):
        assert props[name]["global_state_policy"] == VENDOR_STATE_POLICY
        assert props[name]["state_policy_basis"] == "vendor-default"
    text = fw.state_policy_text(VENDOR_STATE_POLICY, "vendor-default")
    assert "the vendor's fixed stateful behaviour, not a collected setting" in text


def test_the_analysis_model_admits_an_established_packet_and_leaves_a_virtual_system_to_its_rules():
    graph = _inventory(_batch(_estate()))
    device = _device(graph, "gw-a")
    context = ExecutionContext("estate", "manager", "domain", device, "vrf", 4)
    rulebases = _bindings(graph, context, None, None, 4)[0]
    assert _state_admission(graph, context, rulebases, "established") == "permit"
    assert _state_admission(graph, context, rulebases, "new") is None
    instance = GraphNode("fi:vs1", frozenset({"FirewallInstance"}), {"gateway_object_uid": "gw-a"})
    with_vs = _rebuild(graph, {**graph.nodes, instance.uid: instance}, list(_relations(graph)))
    vs_context = ExecutionContext("estate", "manager", "domain", "fi:vs1", "vrf", 4)
    assert _state_admission(with_vs, vs_context, rulebases, "established") is None


def _relations(graph):
    seen = set()
    for relations in graph.outgoing.values():
        for relation in relations:
            if relation.uid not in seen:
                seen.add(relation.uid)
                yield relation


class _Marker:
    def __init__(self, name: str) -> None:
        self.name = name

    def apply(self, region):
        return [(region, self.name)]


def test_impact_reads_the_state_policy_with_the_rulebase_credit(monkeypatch):
    asked: list[str] = []

    def fake_read(session, query, **params):
        asked.append(query)
        return [{"uid": "cp:net", "global_state_policy": VENDOR_STATE_POLICY}]

    monkeypatch.setattr(path, "_read", fake_read)
    established = _StatePolicyFilter(None, "dev:a", "established", _Marker("rules"), _Marker("acls"))
    assert established.apply("region") == [("region", "acls")]
    assert established.state_credits == ["cp:net"]
    assert "RETURN uid, global_state_policy ORDER BY uid" in asked[0]
    new = _StatePolicyFilter(None, "dev:a", "new", _Marker("rules"), _Marker("acls"))
    assert new.apply("region") == [("region", "rules")]


def test_a_unifi_reply_no_listed_rule_decides_is_undecided():
    """The controller does not report the gateway's predefined
    established/related rules, so a reply that falls through is not a
    confident block; a new flow still takes the default."""
    batch = _gw_batch(firewall_zones=ZONES, firewall_policies=[], firewall_rules=[])
    zones = [n.props for n in batch.nodes if n.label == "Zone" and n.props.get("established_default_unknown")]
    assert zones
    row = _rb_row(
        {
            "name": "LAN_IN",
            "vendor": "ubiquiti",
            "default_action": "drop",
            "established_default_unknown": True,
        }
    )
    assert classify_action(fw._default_action_result(row, [], "established")["action"]) == INDETERMINATE
    assert classify_action(fw._default_action_result(row, [], "new")["action"]) == DENY


def test_unifi_rulebases_and_zones_state_their_default_action_is_unknown():
    """The controller returns no default action for a zone or a zone
    pair. Each states default_action_unknown, so a flow no listed rule
    matches is undecided. A classic ruleset is bound to its direction
    and states that direction's documented default."""
    policy = {
        "_id": "p1",
        "name": "allow",
        "index": 1,
        "action": "ALLOW",
        "enabled": True,
        "protocol": "all",
        "source": {"zone_id": "z2", "matching_target": "ANY"},
        "destination": {"zone_id": "z1", "matching_target": "ANY"},
    }
    classic = {"_id": "r1", "ruleset": "LAN_IN", "rule_index": 2000, "action": "drop", "enabled": True}
    batch = _gw_batch(firewall_zones=ZONES, firewall_policies=[policy], firewall_rules=[classic])
    zones = [n.props for n in batch.nodes if n.label == "Zone"]
    rulebases = [n.props for n in batch.nodes if n.label == "FwRulebase"]
    assert zones and {props.get("default_action_unknown") for props in zones} == {True}
    assert {props.get("kind") for props in rulebases} >= {"zone", "access"}
    for props in rulebases:
        if props.get("kind") == "zone":
            assert props.get("default_action") is None and props.get("default_action_unknown") is True
    lan_in = next(props for props in rulebases if props.get("name") == "LAN_IN")
    assert lan_in.get("default_action") == "accept" and lan_in.get("default_action_unknown") is False
    result = fw._default_action_result(_rb_row(lan_in), [], "new")
    assert result["action"] == "accept" and result["indeterminate_reason"] is None
    assert _state_rules_default("deny", {"established_default_unknown": True}, "established") == "unknown"
    assert _state_rules_default("deny", {"established_default_unknown": True}, "new") == "deny"
    assert _state_rules_default("permit", {"established_default_unknown": True}, "related") == "permit"


# fw-unifi-cp


def test_a_firewall_instance_without_an_authority_joins_no_virtual_system():
    """Cypher's null = null joins nothing; the in-memory join must not either."""
    graph = _inventory(_batch(_estate()))
    instance = GraphNode("fi:vs1", frozenset({"FirewallInstance"}), {"gateway_object_uid": "gw-a"})
    graph = _rebuild(graph, {**graph.nodes, instance.uid: instance}, list(_relations(graph)))
    context = ExecutionContext("estate", "manager", "domain", "fi:vs1", "vrf", 4)
    rulebases = tuple(u for u in graph.labels["FwRulebase"] if graph.nodes[u].props.get("kind") == "access")
    policy = checkpoint_policy(graph, rulebases, context, Constant(True))
    assert policy is not None
    (rule,) = [r for layer in policy.layers for r in layer.rules if r.uid.endswith("r1")]
    assert _truth(rule.predicate, _packet("10.1.0.5", "10.9.1.1", port=22), _objects(policy)) is False


def _objects(policy) -> dict[Any, Any]:
    return {definition.key: definition for definition in policy.objects}


def test_install_on_is_a_semantic_field_and_is_not_regenerated_as_an_overlay_add():
    assert {"install_on", "install_on_unresolved"} <= set(SEMANTIC_FIELDS)
    row = {"uid": "r1", "pos": 1, "action": "accept", "src_any": True, "dst_any": True, "svc_any": True}
    assert rule_as_add("rb", row)["kind"] == "fw_rule.add"
    try:
        rule_as_add("rb", {**row, "install_on": ["gw-a"]})
    except ValueError as exc:
        assert "install_on" in str(exc)
    else:
        raise AssertionError("a rule scoped by install-on was regenerated without its scope")


def test_the_policy_catalog_rows_carry_install_on_as_the_gate_rows_do():
    batch = _batch(_estate())
    projection = project_catalogs(_inventory(batch), manifest=None)
    rows = [row for rows in projection.catalogs["firewall"].values() for row in rows]
    (r1,) = [row for row in rows if str(row["uid"]).endswith("r1")]
    assert tuple(r1["install_on"]) == ("gw-a",) and r1["install_on_unresolved"] is False
    gate = {row["uid"]: row for row in _rows(batch, next(u for u in _uids(batch, "Network")))}
    assert list(gate[r1["uid"]]["install_on"]) == list(r1["install_on"])


def _uids(batch, name: str) -> list[str]:
    return [n.uid for n in batch.nodes if n.label == "FwRulebase" and n.props.get("name") == name]


def test_the_rules_query_counts_an_application_inside_a_service_group():
    """An application held as a NetObject member of a service group counts as an unmodeled member."""
    assert "(r)-[:SVC]->(:SvcObject)<-[:MEMBER_OF*1..16]-(x)" in fw._RULEBASE_RULES
    assert "WHERE NOT x:SvcObject AND NOT x:Retired" in fw._RULEBASE_RULES


# --- the estate through both engines ------------------------------------------------


def _gate_rows(batch, device_raw_uid: str) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    """The candidate rows of one gateway and the rule rows of each of its
    rulebases, in the shapes the gate's queries return."""
    devices = {n.uid: n.props for n in batch.nodes if n.label == "Device"}
    props = {n.uid: dict(n.props, uid=n.uid) for n in batch.nodes if n.label == "FwRulebase"}
    candidates = [
        _rb_row(props[r.end_uid], approximate=bool(r.props.get("approximate")), owner_raw_uid=device_raw_uid)
        for r in batch.rels
        if r.rel_type == "ENFORCES"
        and devices.get(r.start_uid, {}).get("cp_raw_uid") == device_raw_uid
        and props[r.end_uid].get("kind") == "access"
    ]
    return candidates, {uid: _rows(batch, uid) for uid in props}


def _tracer(monkeypatch, batch, device_raw_uid: str, source: str, destination: str, port: int) -> str:
    candidates, rules = _gate_rows(batch, device_raw_uid)

    def fake_read(session, query, **params):
        if "HAS_RULE" in query and "FwRule" in query:
            return copy.deepcopy(rules.get(params.get("rb"), []))
        if "ENFORCES" in query and "owner_raw_uid" in query:
            return copy.deepcopy(candidates)
        return []

    monkeypatch.setattr(path, "_read", fake_read)
    monkeypatch.setattr(path, "_read_one", lambda session, query, **params: None)
    verdict = path._device_rulebase_verdict(
        None,
        f"dev:{device_raw_uid}",
        "if:in",
        "if:out",
        path._intervals([source]),
        path._intervals([destination]),
        port,
        "tcp",
        4,
    )
    return classify_action(verdict["action"])


def _layer_outcome(policy, uid: str, packet: dict[str, int], objects) -> str:
    layer = next(item for item in policy.layers if item.uid == uid)
    for rule in layer.rules:
        if not rule.enabled:
            continue
        if rule.install_targets and policy.context.firewall_instance not in rule.install_targets:
            continue
        matched = _truth(rule.predicate, packet, objects)
        if matched is False:
            continue
        if matched is None:
            return "unknown"
        if rule.action == "call":
            called = _layer_outcome(policy, str(rule.called_layer), packet, objects)
            if called == "return":
                continue
            return called
        return rule.action
    return layer.default


def _symbolic(policy, packet: dict[str, int]) -> str:
    """The policy's layers' outcome on one packet: every ordered layer must
    permit. The installation guard is left out."""
    objects = _objects(policy)
    outcomes = [_layer_outcome(policy, uid, packet, objects) for uid in policy.ordered_layers]
    if "deny" in outcomes:
        return DENY
    if "unknown" in outcomes or "return" in outcomes:
        return INDETERMINATE
    return PERMIT


def test_the_tracer_and_the_symbolic_policy_agree_on_the_estate(monkeypatch):
    """ssh from the LAN to web: gw-a has the install-on rule, and the
    Application layer's cleanup accepts; gw-b does not have the rule, so the
    Network cleanup drops. Traffic to `blocked` is dropped on both. The
    group NAT rule hides the LAN and nothing else, and the reply of the
    permitted flow through gw-a is admitted from session state by both."""
    batch = _batch(_estate())
    graph = _inventory(batch)
    access = tuple(u for u in graph.labels["FwRulebase"] if graph.nodes[u].props.get("kind") == "access")
    cases = [
        ("gw-a", "10.1.0.5", "10.9.1.1", 22, PERMIT),
        ("gw-b", "10.1.0.5", "10.9.1.1", 22, DENY),
        ("gw-a", "10.1.0.5", "10.9.9.9", 22, DENY),
        ("gw-a", "10.1.0.5", "10.9.1.1", 443, DENY),
    ]
    for gateway, source, destination, port, expected in cases:
        device = _device(graph, gateway)
        context = ExecutionContext("estate", "manager", "domain", device, "vrf", 4)
        policy = checkpoint_policy(graph, access, context, Constant(True))
        assert policy is not None
        symbolic = _symbolic(policy, _packet(source, destination, port=port))
        tracer = _tracer(monkeypatch, batch, gateway, source, destination, port)
        assert (tracer, symbolic) == (expected, expected), (gateway, destination, port)

    # NAT: both engines hide the LAN group and leave a source outside it alone
    nat_rulebase = next(
        graph.nodes[u] for u in graph.labels["FwRulebase"] if graph.nodes[u].props.get("kind") == "nat"
    )
    (nat_rule,) = graph.targets(nat_rulebase.uid, "HAS_RULE")
    (traced,) = _nat_stage_rules([nat_row(graph, nat_rulebase, nat_rule, False, {"gw-a"})], "snat", None)
    (spec,) = [
        s
        for s in normalize_nat_rules(
            graph,
            _device(graph, "gw-a"),
            ingress_interface_uid=None,
            egress_interface_uid=None,
            address_family=4,
        )
        if s.stage == "snat"
    ]
    for source, claimed in (("10.1.0.5", True), ("172.16.9.9", False)):
        in_tracer = bool(path._intersect(traced["match_src"], path._intervals([source])))
        assert (in_tracer, _truth(spec.predicate, _packet(source))) == (claimed, claimed), source
    assert not traced["opaque"] and spec.gap_code is None
    assert dict(spec.rewrites)["source_address"] == int(ipaddress.ip_address("198.51.100.1"))

    # the reply of the permitted flow through gw-a
    device = _device(graph, "gw-a")
    state = {"global_state_policy": VENDOR_STATE_POLICY, "state_policy_basis": "vendor-default"}
    candidates, rules = _gate_rows(batch, "gw-a")

    def fake_read(session, query, **params):
        if "HAS_RULE" in query and "FwRule" in query:
            return copy.deepcopy(rules.get(params.get("rb"), []))
        if "ENFORCES" in query and "owner_raw_uid" in query:
            return copy.deepcopy(candidates)
        return []

    monkeypatch.setattr(path, "_read", fake_read)
    monkeypatch.setattr(
        path, "_read_one", lambda session, query, **params: state if "global_state_policy" in query else None
    )
    trail = path._Trail()
    trail.device_gate_state[device] = {"policy": VENDOR_STATE_POLICY, "permit": True}
    leg: dict[str, Any] = {}
    traced_reply = fw._apply_firewall_reply(
        None,
        trail,
        leg,
        {"dev_uid": device, "dev_name": "fw-a", "if_uid": "if:out"},
        "if:in",
        path._intervals(["10.9.1.1"]),
        path._intervals(["10.1.0.5"]),
        None,
        None,
        "10.9.1.1",
        "eth0",
    )
    context = ExecutionContext("estate", "manager", "domain", device, "vrf", 4)
    reply_policy = _access_policy(graph, context, device, None, None, 4, "established")
    reply_packet = _packet("10.9.1.1", "10.1.0.5", port=40000)
    assert (traced_reply, _symbolic(reply_policy, reply_packet)) == (PERMIT, PERMIT)
    assert any("not a collected setting" in note for note in trail.notes)


def test_a_cisco_access_list_partial_only_for_an_unreported_binding_is_installed_on_other_interfaces():
    """The collector writes a read list with an unreported binding as
    installed and partial. A spelling that shares its number with a reported
    interface and that the resolver did not map stays unproven."""
    from hst.core import uid as uids

    gi1, gi2 = uids.interface("dev:r1", "Gi1"), uids.interface("dev:r1", "Gi2")

    def batch(other: str):
        b = GraphBuilder()
        b.node("Device", "dev:r1", hostname="r1", role="router")
        b.node("Interface", gi1, name="Gi1")
        b.node("Interface", gi2, name="Gi2")
        inter = {
            "interfaces": [{"name": "Gi1"}, {"name": "Gi2"}],
            "acl": {
                "lists": {"EDGE": []},
                "bindings": [
                    {"interface": "Gi1", "direction": "in", "acl": "EDGE"},
                    {"interface": other, "direction": "in", "acl": "EDGE"},
                ],
            },
        }
        acl_stage(b, inter, dev="dev:r1", scope="cisco:r1")
        return b.batch("cisco", "cisco:r1")

    context = ExecutionContext("estate", "graph", "graph", "dev:r1", "vrf", 4)
    elsewhere = batch("Gi9")
    (edge,) = [r.props for r in elsewhere.rels if r.rel_type == "ENFORCES"]
    assert edge["installed"] is True and edge["coverage"] == "partial"
    assert _bindings(_inventory(elsewhere), context, gi1, gi2, 4)[1] == Constant(True)
    # "Xy1" shares the number of Gi1 and the resolver did not map it: not ruled out
    uncertain = batch("Xy1")
    (edge,) = [r.props for r in uncertain.rels if r.rel_type == "ENFORCES"]
    assert edge["installed"] is False and edge["coverage"] == "partial"
    assert _bindings(_inventory(uncertain), context, gi1, gi2, 4)[1] != Constant(True)
