"""The symbolic engine's PBR edges read each rule as the trace's PBR stage does.

`analysis_model.gates._pbr_edges` builds one edge per PBR rule. Its address
side is `gates/pbr.partition_rules`' reading: a negated side, a clause the
collector could not model, an unresolved address object, the policy's
address family, a disabled rule and the order of the policies. These tests
read the predicates at model construction, without the native backend, with
a small three-valued evaluator over one concrete header.
"""

import ipaddress
from types import MappingProxyType
from typing import Any

from hst.analysis_model.gates import _pbr_rule_row, _rule_predicate, expand_device_gates
from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.analysis_model.model import StateKey
from hst.path.addrsets import _intervals
from hst.path.gates import pbr
from hst.policy.ir import AllOf, AnyOf, Atom, Constant, ExecutionContext, Not, Unknown


def _inventory(nodes: list[GraphNode], relations: list[GraphRelation]) -> GraphInventory:
    catalog = {n.uid: n for n in nodes}
    outgoing: dict[Any, list[GraphRelation]] = {}
    incoming: dict[Any, list[GraphRelation]] = {}
    labels: dict[str, list[str]] = {}
    for n in nodes:
        for label in n.labels:
            labels.setdefault(label, []).append(n.uid)
    for r in relations:
        outgoing.setdefault((r.start, r.kind), []).append(r)
        incoming.setdefault((r.end, r.kind), []).append(r)
    return GraphInventory(
        "a" * 64,
        "b" * 64,
        MappingProxyType(catalog),
        MappingProxyType({k: tuple(v) for k, v in labels.items()}),
        MappingProxyType({k: tuple(v) for k, v in outgoing.items()}),
        MappingProxyType({k: tuple(v) for k, v in incoming.items()}),
        True,
        (),
        0,
    )


def _node(uid: str, labels: list[str], **props: Any) -> GraphNode:
    return GraphNode(uid, frozenset(labels), MappingProxyType({"uid": uid, **props}))


_count = iter(range(10**6))


def _rel(kind: str, start: str, end: str) -> GraphRelation:
    return GraphRelation(f"r{next(_count)}", kind, start, end, MappingProxyType({}))


def _ctx(af: int = 4) -> ExecutionContext:
    return ExecutionContext("estate", "graph", "domain", "dev", "vrf", af)


def _ev(p: Any, h: dict[str, int]) -> bool | None:
    """Three-valued: None where an Unknown decides."""
    if isinstance(p, Constant):
        return p.value
    if isinstance(p, Atom):
        v = h[p.field]
        return p.value <= v <= p.other if p.operation == "range" else v == p.value
    if isinstance(p, Unknown):
        return None
    if isinstance(p, Not):
        x = _ev(p.term, h)
        return None if x is None else not x
    vals = [_ev(t, h) for t in p.terms]
    if isinstance(p, AllOf):
        return False if False in vals else (None if None in vals else True)
    assert isinstance(p, AnyOf)
    return True if True in vals else (None if None in vals else False)


def _h(src: str, dst: str = "198.51.100.10", proto: int = 6, port: int = 443) -> dict[str, int]:
    return {
        "source_address": int(ipaddress.ip_address(src)),
        "destination_address": int(ipaddress.ip_address(dst)),
        "protocol": proto,
        "destination_port": port,
    }


def _unknowns(p: Any) -> list[Unknown]:
    if isinstance(p, Unknown):
        return [p]
    if isinstance(p, Not):
        return _unknowns(p.term)
    if isinstance(p, (AllOf, AnyOf)):
        return [u for t in p.terms for u in _unknowns(t)]
    return []


class _Estate:
    """One device, one ingress interface, PBR policies of PBR rules."""

    def __init__(self) -> None:
        self.nodes = [_node("dev", ["Device"]), _node("in", ["Interface"]), _node("wg", ["VrfInstance"])]
        self.rels: list[GraphRelation] = []

    def policy(self, uid: str, name: str, **props: Any) -> str:
        self.nodes.append(_node(uid, ["PbrPolicy"], name=name, **props))
        self.rels.append(_rel("ENFORCES", "in", uid))
        return uid

    def obj(self, uid: str, specs: list[str] | None = None, **props: Any) -> str:
        """A NetObject resolving to one Prefix/IpAddress per spec."""
        self.nodes.append(_node(uid, ["NetObject"], **props))
        for i, spec in enumerate(specs or []):
            member = f"{uid}:m{i}"
            key = "cidr" if "/" in spec else "ip"
            self.nodes.append(_node(member, ["Prefix" if key == "cidr" else "IpAddress"], **{key: spec}))
            self.rels.append(_rel("RESOLVES_TO", uid, member))
        return uid

    def rule(self, policy: str, uid: str, pos: int, src=(), dst=(), table="wg", **props: Any) -> str:
        self.nodes.append(_node(uid, ["FwRule"], position=pos, enabled=props.pop("enabled", True), **props))
        self.rels.append(_rel("HAS_RULE", policy, uid))
        self.rels.extend(_rel("SRC", uid, o) for o in src)
        self.rels.extend(_rel("DST", uid, o) for o in dst)
        if table:
            self.rels.append(_rel("REDIRECTS_VIA", uid, table))
        return uid

    def graph(self) -> GraphInventory:
        return _inventory(self.nodes, self.rels)

    def edges(self, af: int = 4) -> dict[str, Any]:
        ctx = _ctx(af)
        expansion = expand_device_gates(
            self.graph(),
            ctx,
            "dev",
            "in",
            None,
            StateKey("routing:default", ctx),
            phases=("pbr",),
            routing_targets={"wg": StateKey("routing:wg", ctx)},
        )
        entry = next(n for n in expansion.nodes if n.key == expansion.entry)
        return {e.uid: e for e in entry.edges}


def _rule_alone(e: _Estate, rule: str, af: int = 4) -> Any:
    g = e.graph()
    policy = next(n for n in g.nodes.values() if rule in [t.uid for t in g.targets(n.uid, "HAS_RULE")])
    return _rule_predicate(g, g.nodes[rule], af, policy)


def test_a_negated_source_claims_what_its_addresses_exclude() -> None:
    e = _Estate()
    pol = e.policy("pol", "LAN", af=4)
    e.rule("pol", "r10", 10, src=[e.obj("lan", ["10.10.0.0/24"])], src_negate=True)
    pred = _rule_alone(e, "r10")
    assert _ev(pred, _h("10.10.0.5")) is False
    assert _ev(pred, _h("10.20.0.5")) is True
    assert pol


def test_a_states_opaque_rule_is_an_unknown_predicate_with_its_reason() -> None:
    e = _Estate()
    e.policy("pol", "LAN", af=4)
    e.rule(
        "pol",
        "r10",
        10,
        src=[e.obj("lan", ["10.10.0.0/24"])],
        states_opaque=True,
        states_opaque_reason="the rule matches only connection states new",
    )
    pred = _rule_alone(e, "r10")
    assert _ev(pred, _h("10.10.0.5")) is None
    # the address side stays decided: a flow outside it is a miss
    assert _ev(pred, _h("10.20.0.5")) is False
    (unknown,) = _unknowns(pred)
    assert unknown.code == "PBR_RULE_MATCH_UNKNOWN"
    assert "connection states" in unknown.evidence[0]


def test_an_unresolved_address_object_is_an_unknown_predicate_with_its_reason() -> None:
    e = _Estate()
    e.policy("pol", "LAN", af=4)
    obj = e.obj("grp", ["10.30.0.0/24"], opaque_reason="address group IOT_HOSTS is not defined")
    e.rule("pol", "r10", 10, src=[obj])
    pred = _rule_alone(e, "r10")
    assert _ev(pred, _h("10.30.0.5")) is None
    assert any("IOT_HOSTS" in u.evidence[0] for u in _unknowns(pred))


def test_a_side_with_objects_and_no_address_is_unknown_not_any() -> None:
    e = _Estate()
    e.policy("pol", "LAN", af=4)
    e.rule("pol", "r10", 10, src=[e.obj("empty", [])])
    pred = _rule_alone(e, "r10")
    assert _ev(pred, _h("10.40.0.5")) is None


def test_a_policy_of_the_other_family_claims_nothing() -> None:
    e = _Estate()
    e.policy("pol6", "VPN-PBR6", af=6)
    e.rule("pol6", "r10", 10, src=[e.obj("hosts6", ["fd00:18:10::/64"])])
    assert _rule_alone(e, "r10", af=4) == Constant(False)
    e.policy("any6", "ANY6", af=6)
    e.rule("any6", "r20", 10)
    assert _rule_alone(e, "r20", af=4) == Constant(False)


def test_a_disabled_rule_is_left_out_and_policies_go_by_name() -> None:
    e = _Estate()
    # created in reverse name order, so graph order is not name order
    e.policy("pz", "Z-POL", af=4)
    e.policy("pa", "A-POL", af=4)
    e.rule("pz", "z10", 10, src=[e.obj("all", ["10.0.0.0/8"])])
    e.rule("pa", "a10", 10, src=[e.obj("lan", ["10.10.0.0/24"])], enabled=False)
    e.rule("pa", "a20", 20, src=[e.obj("lan2", ["10.20.0.0/24"])], table=None)
    edges = e.edges()
    assert "a10" not in edges
    assert list(edges) == ["a20", "z10", "pbr:default"]
    # a20 (A-POL) is first, so 10.20.0.5 is not claimed by z10
    assert _ev(edges["a20"].predicate, _h("10.20.0.5")) is True
    assert _ev(edges["z10"].predicate, _h("10.20.0.5")) is False
    assert _ev(edges["z10"].predicate, _h("10.10.0.5")) is True


def _owner() -> _Estate:
    """The shapes of the owner's VyOS router policy: local traffic
    (destination 192.168.0.0/16) kept in main, then a source address group,
    source hosts, or one source range into a WireGuard table."""
    e = _Estate()
    e.nodes.append(_node("main", ["VrfInstance"]))
    for name, specs in (
        ("PBR-GUEST", ["192.168.20.0/24", "10.20.0.0/24"]),
        ("PBR-IOT", None),
        ("PBR-LAN", ["192.168.10.0/24", "192.168.11.5"]),
    ):
        pol = e.policy(f"p:{name}", name, af=4)
        e.rule(pol, f"{name}:10", 10, dst=[e.obj(f"{name}:local", ["192.168.0.0/16"])], table="main")
        if specs is None:
            src = e.obj(f"{name}:range", ranges=["192.168.30.10-192.168.30.20"])
        else:
            src = e.obj(f"{name}:grp", specs, kind="group")
        e.rule(pol, f"{name}:20", 20, src=[src])
    return e


def test_the_owner_router_rules_read_as_address_predicates() -> None:
    e = _owner()
    g = e.graph()
    p = lambda uid: _rule_predicate(g, g.nodes[uid], 4, g.nodes["p:" + uid.split(":")[0]])  # noqa: E731
    assert p("PBR-GUEST:10") == AllOf(
        (AnyOf((Atom("destination_address", "range", 0xC0A80000, 0xC0A8FFFF),)),)
    )
    assert p("PBR-IOT:20") == AllOf((AnyOf((Atom("source_address", "range", 0xC0A81E0A, 0xC0A81E14),)),))
    lan = p("PBR-LAN:20")
    assert not _unknowns(lan)
    assert _ev(lan, _h("192.168.10.7")) is True
    assert _ev(lan, _h("192.168.11.5")) is True
    assert _ev(lan, _h("192.168.11.6")) is False
    guest = p("PBR-GUEST:20")
    assert _ev(guest, _h("10.20.0.9")) is True and _ev(guest, _h("10.21.0.9")) is False
    edges = e.edges()
    assert list(edges) == [
        "PBR-GUEST:10",
        "PBR-GUEST:20",
        "PBR-IOT:10",
        "PBR-IOT:20",
        "PBR-LAN:10",
        "PBR-LAN:20",
        "pbr:default",
    ]


def _tracer(e: _Estate, rule: str, src: str, proto: str = "tcp", port: int = 443) -> bool | None:
    """The trace's reading of the same rule for one flow: True a decided
    claim, None an undecided claim, False no claim."""
    g = e.graph()
    node = g.nodes[rule]
    policy = next(n for n in g.nodes.values() if rule in [t.uid for t in g.targets(n.uid, "HAS_RULE")])
    row = _pbr_rule_row(g, node, policy)
    services = g.targets(rule, "SVC")
    row.update(
        svc_obj_count=len(services),
        svc_protos=[s.props.get("proto") for s in services],
        svc_port_specs=[s.props.get("ports") for s in services],
        svc_opaque=any(s.props.get("opaque") is True for s in services),
        svc_opaque_reasons=[s.props["opaque_reason"] for s in services if s.props.get("opaque_reason")],
        svc_src_port=any(str(s.props.get("src_port") or "") for s in services),
        svc_src_ports=[s.props.get("src_port") for s in services],
    )
    flow = _intervals([src])
    groups = pbr.partition_rules([row], flow, _intervals(["198.51.100.10"]), None, port=port, proto=proto)
    claim = next((x for x in groups if x["rule_uid"]), None)
    return False if claim is None else (None if claim["opaque"] else True)


def _svc(e: _Estate, rule: str, uid: str, **props: Any) -> None:
    e.nodes.append(_node(uid, ["SvcObject"], **props))
    e.rels.append(_rel("SVC", rule, uid))


def test_a_side_with_an_unreadable_target_reads_as_the_trace_reads_it() -> None:
    for name, extra in (
        ("empty group", {}),
        ("undefined group", {"opaque_reason": "address-group X is not defined"}),
    ):
        e = _Estate()
        e.policy("pol", "LAN", af=4)
        e.rule("pol", "r10", 10, src=[e.obj("good", ["10.10.0.0/24"]), e.obj("other", [], **extra)])
        pred = _rule_alone(e, "r10")
        for src in ("10.10.0.5", "10.99.0.5"):
            assert _ev(pred, _h(src)) == _tracer(e, "r10", src), (name, src)
        # outside the readable target the trace decides a miss; inside it the
        # undefined group leaves the claim undecided, the empty one does not
        assert _ev(pred, _h("10.99.0.5")) is False
        assert _ev(pred, _h("10.10.0.5")) is (None if extra else True)


def test_a_source_port_scope_leaves_a_matching_service_undecided() -> None:
    e = _Estate()
    e.policy("pol", "LAN", af=4)
    e.rule("pol", "r10", 10, src=[e.obj("lan", ["10.10.0.0/24"])])
    _svc(e, "r10", "svc", proto="tcp", ports=None, src_port="5000")
    pred = _rule_alone(e, "r10")
    assert _ev(pred, _h("10.10.0.5")) is None
    assert _ev(pred, _h("10.10.0.5", proto=17)) is False
    assert _tracer(e, "r10", "10.10.0.5") is None
    assert _tracer(e, "r10", "10.10.0.5", proto="udp") is False
    assert any(u.code == "RULE_SERVICE_SOURCE_PORT_UNKNOWN" for u in _unknowns(pred))


def test_an_unmapped_service_member_leaves_a_miss_of_the_known_members_undecided() -> None:
    e = _Estate()
    e.policy("pol", "LAN", af=4)
    e.rule("pol", "r10", 10, src=[e.obj("lan", ["10.10.0.0/24"])])
    _svc(e, "r10", "ssh", proto="tcp", ports=22)
    # a member the collector flagged opaque, though it also wrote a protocol
    # and a port: a miss of the members is not one the trace stands behind
    _svc(e, "r10", "odd", proto="tcp", ports=8080, opaque=True, opaque_reason="service X is not modelled")
    pred = _rule_alone(e, "r10")
    for port, expected in ((22, True), (443, None)):
        assert _ev(pred, _h("10.10.0.5", port=port)) is expected
        assert _tracer(e, "r10", "10.10.0.5", port=port) is expected


def test_a_plain_service_rule_keeps_its_predicate() -> None:
    e = _Estate()
    e.policy("pol", "LAN", af=4)
    e.rule("pol", "r10", 10, src=[e.obj("lan", ["10.10.0.0/24"])])
    _svc(e, "r10", "https", proto="tcp", ports=443)
    assert _rule_alone(e, "r10") == AllOf(
        (
            AnyOf((Atom("source_address", "range", 0x0A0A0000, 0x0A0A00FF),)),
            AnyOf((AllOf((Atom("protocol", "eq", 6), Atom("destination_port", "eq", 443))),)),
        )
    )


# --- a VyOS policy-route service as the collector writes it ---------------------------------


def _unknown_codes(predicate: Any) -> set[str]:
    if isinstance(predicate, Unknown):
        return {predicate.code}
    if isinstance(predicate, (AllOf, AnyOf)):
        return {code for term in predicate.terms for code in _unknown_codes(term)}
    if isinstance(predicate, Not):
        return _unknown_codes(predicate.term)
    return set()


def _vyos_pbr_predicates() -> dict[str, Any]:
    """Each rule of one VyOS `policy route` through the collector and the
    inventory the analysis model loads (`ports` frozen to a tuple), read by
    `_rule_predicate` as the PBR stage reads it."""
    from tests.test_symbolic_vyos_service_ports import VERSION
    from tests.test_symbolic_vyos_service_ports import _inventory as _frozen

    from hst.collectors.vyos import normalize_vyos

    table = {"set": {"table": "100"}}
    rules = {
        "10": {"protocol": "tcp_udp", "destination": {"port": "53"}, **table},
        "20": {"protocol": "tcp", "destination": {"port": "80,443"}, **table},
        "30": {"protocol": "tcp", "destination": {"port": "!80"}, **table},
        "40": {"protocol": "all", "destination": {"port": "8080"}, **table},
    }
    cfg = {
        "system": {"host-name": "gw"},
        "interfaces": {
            "ethernet": {"eth0": {"address": ["203.0.113.2/30"]}, "eth1": {"address": ["10.0.0.1/24"]}}
        },
        "policy": {"route": {"P": {"interface": ["eth1"], "rule": rules}}},
    }
    graph = _frozen(normalize_vyos({"config": cfg, "version_text": VERSION, "links": []}, l3dom="dc1"))
    policy = graph.nodes["vyos:gw:pbr:P"]
    return {pos: _rule_predicate(graph, graph.nodes[f"vyos:gw:pbr:P:{pos}"], 4, policy) for pos in rules}


def _atoms(predicate: Any, field: str) -> set[tuple[int, int]]:
    if isinstance(predicate, Atom):
        return {(predicate.value, predicate.other or predicate.value)} if predicate.field == field else set()
    if isinstance(predicate, (AllOf, AnyOf)):
        return {item for term in predicate.terms for item in _atoms(term, field)}
    return set()


def test_a_vyos_policy_route_service_is_read_as_the_tracer_reads_it():
    """The collector writes `tcp_udp` and a list of port tokens."""
    found = _vyos_pbr_predicates()
    for pos in ("10", "20", "40"):
        assert _unknown_codes(found[pos]) == set(), pos
    assert _atoms(found["10"], "protocol") == {(6, 6), (17, 17)}
    assert _atoms(found["10"], "destination_port") == {(53, 53)}
    assert _atoms(found["20"], "protocol") == {(6, 6)}
    assert _atoms(found["20"], "destination_port") == {(80, 80), (443, 443)}
    # `all` is every protocol and adds no protocol term.
    assert _atoms(found["40"], "protocol") == set()
    assert _atoms(found["40"], "destination_port") == {(8080, 8080)}


def test_a_negated_policy_route_port_stays_not_decided():
    assert "RULE_SERVICE_UNKNOWN" in _unknown_codes(_vyos_pbr_predicates()["30"])
