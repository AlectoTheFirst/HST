from __future__ import annotations

from pathlib import Path

from hst import demo
from hst.core.fixtures import load_fixture

FIXTURES = Path(__file__).parents[1] / "fixtures"
EQUINIX_KEYS = ("equinix-hsrp-core", "equinix-vsx-context", "equinix-asr-egress", "equinix-fabric-circuit")


def _batch():
    return load_fixture(FIXTURES / "equinix-site.yaml")


def _ends(batch, rel_type):
    return {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == rel_type}


def test_equinix_fixture_loads_and_validates():
    batch = _batch()
    assert batch.source == "fixture"
    assert batch.scope == "fixture:equinix-site"
    assert len(batch.nodes) > 40
    assert len(batch.rels) > 40


def test_equinix_fixture_shares_no_uid_with_the_other_fixtures():
    """Loaded third, after mini-dc and mini-enterprise: a shared uid would re-scope
    a node the earlier fixture owns."""
    ours = {n.uid for n in _batch().nodes}
    for name in ("mini-dc.yaml", "mini-enterprise.yaml"):
        theirs = {n.uid for n in load_fixture(FIXTURES / name).nodes}
        assert not (ours & theirs), name


def test_the_equinix_scenarios_are_registered_with_the_demo_suite():
    keys = {sc["key"] for sc in demo.SCENARIOS}
    assert set(EQUINIX_KEYS) <= keys


def test_the_hsrp_scenario_pattern_holds_in_the_fixture():
    batch = _batch()
    nodes = {n.uid: n for n in batch.nodes}
    groups = [n for n in batch.nodes if n.label == "FhrpGroup" and n.props.get("kind") == "hsrp"]
    assert len(groups) == 1
    group = groups[0]
    members = [r for r in batch.rels if r.rel_type == "MEMBER_OF" and r.end_uid == group.uid]
    assert len(members) == 2
    assert {r.props["state"] for r in members} == {"active", "standby"}
    on, member_of = _ends(batch, "ON"), _ends(batch, "MEMBER_OF")
    vpc = {n.uid for n in batch.nodes if n.label == "RedundancyGroup" and n.props.get("kind") == "vpc"}
    for member in members:
        devices = {d for i, d in on if i == member.start_uid}
        assert devices, member.start_uid
        assert any((d, g) in member_of for d in devices for g in vpc)
    vip = {ip for g, ip in _ends(batch, "HAS_IP") if g == group.uid}
    assert len(vip) == 1
    prefixes = {p for g, p in _ends(batch, "GATEWAY_FOR") if g == group.uid}
    assert {p for ip, p in _ends(batch, "IN") if ip in vip} == prefixes
    assert nodes[next(iter(vip))].props["ip"] == group.props["vip"]


def test_the_vsx_scenario_pattern_holds_in_the_fixture():
    batch = _batch()
    nodes = {n.uid: n for n in batch.nodes}
    instances = [n for n in batch.nodes if n.label == "FirewallInstance"]
    assert len(instances) == 2
    in_context, runs_on, enforces, has_rule = (
        _ends(batch, "IN_CONTEXT"),
        _ends(batch, "RUNS_ON"),
        _ends(batch, "ENFORCES"),
        _ends(batch, "HAS_RULE"),
    )
    for fi in instances:
        interfaces = {i for i, f in in_context if f == fi.uid and nodes[i].label == "Interface"}
        assert len(interfaces) == 2, fi.uid
        appliances = {d for f, d in runs_on if f == fi.uid}
        assert {nodes[d].props["platform"] for d in appliances} == {"checkpoint-gaia"}
        gateway_object_uid = fi.props["gateway_object_uid"]
        vs_devices = [
            n for n in batch.nodes if n.label == "Device" and n.props.get("cp_raw_uid") == gateway_object_uid
        ]
        assert len(vs_devices) == 1, fi.uid
        vs_uid = vs_devices[0].uid
        rulebases = {rb for d, rb in enforces if d == vs_uid and nodes[rb].props.get("kind") == "access"}
        assert len(rulebases) == 1
        assert any(rb in rulebases for rb, _ in has_rule)


def test_the_asr_scenario_pattern_holds_in_the_fixture():
    batch = _batch()
    nodes = {n.uid: n for n in batch.nodes}
    asrs = [n for n in batch.nodes if n.label == "Device" and n.props.get("platform") == "iosxe"]
    assert len(asrs) == 2
    enforces, has_rule, xlate, orig, resolves = (
        _ends(batch, "ENFORCES"),
        _ends(batch, "HAS_RULE"),
        _ends(batch, "XLATE_SRC"),
        _ends(batch, "ORIG_SRC"),
        _ends(batch, "RESOLVES_TO"),
    )
    on, in_vrf = _ends(batch, "ON"), _ends(batch, "IN_VRF")
    statics = {
        (r.start_uid, r.end_uid)
        for r in batch.rels
        if r.rel_type == "ORIGINATES"
        and r.props.get("proto") == "static"
        and nodes[r.end_uid].props["kind"] == "default"
    }
    for asr in asrs:
        vrfs = {v for i, v in in_vrf if any(i2 == i and d == asr.uid for i2, d in on)}
        assert any(v in vrfs for v, _ in statics), asr.uid
        rulebases = {rb for d, rb in enforces if d == asr.uid and nodes[rb].props.get("kind") == "nat"}
        rules = {n for rb, n in has_rule if rb in rulebases and nodes[n].props.get("kind") == "snat"}
        assert len(rules) == 1, asr.uid
        rule = next(iter(rules))
        assert {nodes[x].label for n, x in xlate if n == rule} == {"IpAddress"}
        objects = {o for n, o in orig if n == rule}
        assert any(nodes[p].label == "Prefix" for o, p in resolves if o in objects)


def test_the_fabric_scenario_pattern_holds_in_the_fixture():
    batch = _batch()
    nodes = {n.uid: n for n in batch.nodes}
    circuits = [n for n in batch.nodes if n.label == "VirtualCircuit"]
    assert len(circuits) == 1
    vc = circuits[0].uid
    a_end = {p for c, p in _ends(batch, "A_END") if c == vc}
    z_end = {p for c, p in _ends(batch, "Z_END") if c == vc}
    located = _ends(batch, "LOCATED_IN")
    assert len(a_end) == 1 and len(z_end) == 1
    a_sites = {s for p, s in located if p in a_end}
    z_sites = {s for p, s in located if p in z_end}
    assert a_sites and z_sites and a_sites != z_sites
    ports = {p for f, p in _ends(batch, "REALIZED_BY") if f in a_end and nodes[p].label == "Port"}
    assert len(ports) == 1
    assert any(p in ports for p, _ in _ends(batch, "ON"))
