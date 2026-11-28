"""One ACI filter-entry reading for the collector, the trace gate, the symbolic
gate and the analysis-model gate (core/aci_filter.py).

APIC writes well-known ports by name ("https"); an entry for a non-IP ether type
matches no IP packet; an unenforced VRF permits before contracts; a flow with one
ACI endpoint is unknown in the model as in the trace.
"""

from __future__ import annotations

import ipaddress
from types import MappingProxyType

import pytest

import hst.path as path
from hst.analysis_model.gates import expand_aci_contracts, expand_aci_reply_redirects
from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.analysis_model.model import StateKey
from hst.collectors.apic import normalize_apic
from hst.path.addrsets import _intervals, _ports
from hst.path.gates import aci_symbolic
from hst.path.gates.aci_symbolic import AciTransition
from hst.path.state import FlowRegion
from hst.path.verdict import DENY, INDETERMINATE, PERMIT
from hst.policy.ir import AllOf, AnyOf, Atom, Constant, ExecutionContext, Not

# --- collector ---------------------------------------------------------------------------


def _entry_props(**attrs):
    raw = {"vzEntry": [{"vzEntry": {"attributes": {"dn": "uni/tn-t/flt-web/e-1", "name": "e1", **attrs}}}]}
    batch = normalize_apic(raw, fabric="f1", l3dom="global")
    (entry,) = [n for n in batch.nodes if n.label == "FilterEntry"]
    return entry.props


def test_the_collector_stores_a_named_port_as_its_number():
    props = _entry_props(prot="tcp", etherT="ip", dFromPort="https", dToPort="https")
    assert (props["d_from_port"], props["d_to_port"]) == ("443", "443")


def test_the_collector_stores_the_source_ports():
    props = _entry_props(
        prot="tcp",
        etherT="ip",
        sFromPort="unspecified",
        sToPort="unspecified",
        dFromPort="dns",
        dToPort="dns",
    )
    assert (props["s_from_port"], props["s_to_port"]) == ("unspecified", "unspecified")
    assert props["d_from_port"] == "53"


# --- trace gate --------------------------------------------------------------------------


# The fields apic.py writes on every vzEntry besides the ones a test sets.
# The trace reads an entry without them as unknown.
_COLLECTED_ENTRY = {
    "s_from_port": "unspecified",
    "s_to_port": "unspecified",
    "tcp_rules": "unspecified",
    "apply_to_frag": "no",
}


def _as_collected(contracts):
    return [
        {**row, "entries": [{**_COLLECTED_ENTRY, **entry} for entry in row.get("entries") or ()]}
        for row in contracts
    ]


@pytest.fixture()
def aci(monkeypatch):
    state = {"ends": [], "contracts": []}

    def fake_read(session, query, **params):
        if "IN_EPG" in query:
            return state["ends"]
        if "CONSUMES" in query:
            return _as_collected(state["contracts"])
        return []

    monkeypatch.setattr(path, "_read", fake_read)
    return state


def _ends():
    return [
        {
            "ip": ip,
            "epg_uid": epg,
            "epg_name": epg,
            "vrf_uid": "vrf:one",
            "pc_enf_pref": "enforced",
            "contract_bypass": "",
        }
        for ip, epg in (("10.0.0.5", "epg:web"), ("10.9.9.5", "epg:db"))
    ]


def _contract(*entries):
    return [{"uid": "k1", "name": "web", "entries": list(entries)}]


def _trace(port=443, proto="tcp"):
    return path.aci_contract_verdict(None, "10.0.0.5", "10.9.9.5", port, proto)


def test_a_named_https_entry_permits_tcp_443_in_the_trace(aci):
    aci["ends"] = _ends()
    aci["contracts"] = _contract({"proto": "tcp", "from_port": "https", "to_port": "https", "ether": "ip"})
    assert _trace()["action"] == PERMIT


def test_an_unreadable_port_name_is_indeterminate_not_a_deny(aci):
    aci["ends"] = _ends()
    aci["contracts"] = _contract(
        {"proto": "tcp", "from_port": "web-ports", "to_port": "web-ports", "ether": "ip"}
    )
    assert _trace()["action"] == INDETERMINATE


def test_an_arp_entry_does_not_permit_an_ip_flow_in_the_trace(aci):
    aci["ends"] = _ends()
    aci["contracts"] = _contract(
        {"proto": "unspecified", "from_port": "unspecified", "to_port": "unspecified", "ether": "arp"}
    )
    assert _trace()["action"] == DENY


def test_a_protocol_scoped_entry_does_not_decide_a_protocol_less_question(aci):
    aci["ends"] = _ends()
    aci["contracts"] = _contract(
        {"proto": "icmp", "from_port": "unspecified", "to_port": "unspecified", "ether": "ip"}
    )
    assert _trace(port=None, proto=None)["action"] == INDETERMINATE


# --- symbolic gate -----------------------------------------------------------------------


def _symbolic(monkeypatch, entry):
    endpoints = [
        {
            "ip": ip,
            "epg_uid": epg,
            "epg_name": epg,
            "vrf_uid": "vrf:one",
            "pc_enf_pref": "enforced",
            "contract_bypass": "",
        }
        for ip, epg in (("10.0.0.1", "epg:src"), ("10.0.0.2", "epg:dst"))
    ]
    row = {
        "src_epg": "epg:src",
        "dst_epg": "epg:dst",
        "contract_uid": "contract:web",
        "contract_name": "web",
        "subject_uid": "subject:web",
        "entry_uid": "entry:1",
        "action": "permit",
        "directives": None,
        "graph_uid": None,
        "graph_name": None,
        "s_from_port": "unspecified",
        "s_to_port": "unspecified",
        "tcp_rules": "unspecified",
        "apply_to_frag": "no",
        **entry,
    }

    def read(_session, query, **_params):
        if query == aci_symbolic._ENDPOINTS:
            return endpoints
        if query == aci_symbolic._CONTRACTS:
            return [row]
        raise AssertionError("unexpected query")

    monkeypatch.setattr(aci_symbolic._path, "_read", read)
    region = FlowRegion.from_query(
        _intervals(["10.0.0.1"]), _intervals(["10.0.0.2"]), frozenset({6}), _ports("443"), _ports("1000")
    )
    return {effect.kind for _region, effect in AciTransition(None).apply(region)}


def test_an_ip_ether_entry_with_a_named_port_permits_in_the_symbolic_gate(monkeypatch):
    entry = {"proto": "tcp", "ether_type": "ip", "d_from_port": "https", "d_to_port": "https"}
    assert _symbolic(monkeypatch, entry) == {"permit"}


def test_an_arp_entry_claims_nothing_in_the_symbolic_gate(monkeypatch):
    entry = {
        "proto": "unspecified",
        "ether_type": "arp",
        "d_from_port": "unspecified",
        "d_to_port": "unspecified",
    }
    assert _symbolic(monkeypatch, entry) == {"deny"}


# --- analysis-model gate -----------------------------------------------------------------


def _inventory(nodes, relations):
    catalog = {
        uid: GraphNode(uid, frozenset(labels), MappingProxyType(props)) for uid, labels, props in nodes
    }
    labels: dict[str, list[str]] = {}
    outgoing: dict[tuple[str, str], list[GraphRelation]] = {}
    incoming: dict[tuple[str, str], list[GraphRelation]] = {}
    for uid, node_labels, _props in nodes:
        for label in node_labels:
            labels.setdefault(label, []).append(uid)
    for index, (kind, start, end) in enumerate(relations):
        relation = GraphRelation(f"r{index}", kind, start, end, MappingProxyType({}))
        outgoing.setdefault((start, kind), []).append(relation)
        incoming.setdefault((end, kind), []).append(relation)
    return GraphInventory(
        "0" * 64,
        "f",
        MappingProxyType(catalog),
        MappingProxyType({key: tuple(value) for key, value in labels.items()}),
        MappingProxyType({key: tuple(value) for key, value in outgoing.items()}),
        MappingProxyType({key: tuple(value) for key, value in incoming.items()}),
        True,
        (),
        0,
    )


def _fabric(pref="enforced", entry=None, *, bypass="", reverse=False):
    nodes = [
        ("ep-a", {"Endpoint"}, {}),
        ("ep-b", {"Endpoint"}, {}),
        ("ip-a", {"IpAddress"}, {"ip": "10.1.1.10"}),
        ("ip-b", {"IpAddress"}, {"ip": "10.1.2.10"}),
        ("epg-a", {"Epg"}, {}),
        ("epg-b", {"Epg"}, {}),
        ("bd", {"BridgeDomain"}, {}),
        ("vrf", {"VrfInstance"}, {"pc_enf_pref": pref, "contract_bypass": bypass}),
    ]
    relations = [
        ("HAS_IP", "ep-a", "ip-a"),
        ("HAS_IP", "ep-b", "ip-b"),
        ("IN_EPG", "ep-a", "epg-a"),
        ("IN_EPG", "ep-b", "epg-b"),
        ("IN_BD", "epg-a", "bd"),
        ("IN_BD", "epg-b", "bd"),
        ("IN_VRF", "bd", "vrf"),
    ]
    if entry is not None:
        nodes += [
            ("ct", {"Contract"}, {}),
            ("subj", {"ContractSubject"}, {}),
            ("flt", {"AciFilter"}, {}),
            ("ent", {"FilterEntry"}, entry),
        ]
        relations += [
            ("CONSUMES", "epg-a", "ct"),
            ("PROVIDES", "epg-b", "ct"),
            ("HAS", "ct", "subj"),
            ("USES_FILTER", "subj", "flt"),
            ("HAS", "flt", "ent"),
        ]
    if reverse:
        # the destination EPG consumes a contract the source EPG provides
        nodes.append(("ct-back", {"Contract"}, {}))
        relations += [("CONSUMES", "epg-b", "ct-back"), ("PROVIDES", "epg-a", "ct-back")]
    return _inventory(nodes, relations)


def _holds(predicate, packet):
    if isinstance(predicate, Constant):
        return predicate.value
    if isinstance(predicate, Atom):
        value = packet[predicate.field]
        if predicate.operation == "eq":
            return value == predicate.value
        return predicate.value <= value <= predicate.other
    if isinstance(predicate, AllOf):
        return all(_holds(term, packet) for term in predicate.terms)
    if isinstance(predicate, AnyOf):
        return any(_holds(term, packet) for term in predicate.terms)
    if isinstance(predicate, Not):
        return not _holds(predicate.term, packet)
    raise TypeError(predicate)


def _model(graph, destination="10.1.2.10", port=443):
    context = ExecutionContext("e", "graph", "graph", "leaf1", "vrf", 4)
    downstream = StateKey("downstream", context)
    expansion = expand_aci_contracts(graph, context, downstream)
    nodes = {node.key: node for node in expansion.nodes}
    packet = {
        "source_address": int(ipaddress.ip_address("10.1.1.10")),
        "destination_address": int(ipaddress.ip_address(destination)),
        "protocol": 6,
        "source_port": 1000,
        "destination_port": port,
    }
    return {
        "pass" if edge.target == downstream else nodes[edge.target].terminal
        for edge in nodes[expansion.entry].edges
        if _holds(edge.predicate, packet)
    }


_IP_ENTRY = {
    "ether_type": "ip",
    "s_from_port": "unspecified",
    "s_to_port": "unspecified",
    "tcp_rules": "unspecified",
    "apply_to_frag": "no",
}


def test_an_unenforced_vrf_without_a_contract_passes_the_model_gate():
    assert _model(_fabric(pref="unenforced")) == {"pass"}


def test_an_arp_entry_does_not_permit_an_ip_flow_in_the_model():
    entry = {**_IP_ENTRY, "ether_type": "arp", "proto": "unspecified", "d_from_port": "unspecified"}
    assert _model(_fabric(entry=entry)) == {"deny"}


def test_a_named_https_entry_permits_tcp_443_in_the_model():
    entry = {**_IP_ENTRY, "proto": "tcp", "d_from_port": "https", "d_to_port": "https"}
    assert _model(_fabric(entry=entry)) == {"pass"}
    assert _model(_fabric(entry=entry), port=80) == {"deny"}


def test_an_entry_without_a_protocol_is_unknown_in_the_model():
    entry = {**_IP_ENTRY, "d_from_port": "443", "d_to_port": "443"}
    assert _model(_fabric(entry=entry)) == {"unknown"}


def test_a_reverse_orientation_contract_is_unknown_not_denied_in_the_model():
    """The provider-to-consumer direction of a contract is not evaluated."""
    assert _model(_fabric(reverse=True)) == {"unknown"}
    entry = {**_IP_ENTRY, "proto": "tcp", "d_from_port": "443", "d_to_port": "443"}
    assert _model(_fabric(entry=entry, reverse=True)) == {"pass"}
    assert _model(_fabric(entry=entry, reverse=True), port=80) == {"unknown"}


def test_a_vrf_using_vzany_preferred_group_or_esg_is_unknown_not_denied_in_the_model():
    """Inputs no gate evaluates may permit the pair; not collected is the same."""
    for bypass in ("vzany", "preferred-group", "esg", "not-collected", None):
        assert _model(_fabric(bypass=bypass)) == {"unknown"}
    entry = {**_IP_ENTRY, "proto": "tcp", "d_from_port": "443", "d_to_port": "443"}
    assert _model(_fabric(entry=entry, bypass="vzany")) == {"pass"}
    assert _model(_fabric(entry=entry, bypass="vzany"), port=80) == {"unknown"}


def test_a_flow_with_one_aci_endpoint_is_unknown_in_the_model():
    assert _model(_fabric(), destination="198.51.100.7") == {"unknown"}


# --- filters under vzInTerm/vzOutTerm, tcpRules, source ports ----------------------------


def _contract_raw(*term_attachments, subject_dn="uni/tn-t/brc-web/subj-s", **entry):
    """An APIC reply with one contract, one subject and filters attached under
    the subject's terms (vzRsFiltAtt)."""
    filters = sorted({tdn for _term, tdn in term_attachments})
    return {
        "vzBrCP": [{"vzBrCP": {"attributes": {"dn": "uni/tn-t/brc-web", "name": "web"}}}],
        "vzSubj": [{"vzSubj": {"attributes": {"dn": subject_dn, "name": "s"}}}],
        "vzFilter": [{"vzFilter": {"attributes": {"dn": tdn, "name": tdn}}} for tdn in filters],
        "vzEntry": [
            {"vzEntry": {"attributes": {"dn": f"{tdn}/e-1", "name": "e1", "prot": "tcp", **entry}}}
            for tdn in filters
        ],
        "vzRsFiltAtt": [
            {
                "vzRsFiltAtt": {
                    "attributes": {
                        "dn": f"{subject_dn}/{term}/rsfiltAtt-{tdn.rsplit('-', 1)[-1]}",
                        "tDn": tdn,
                        "action": "permit",
                    }
                }
            }
            for term, tdn in term_attachments
        ],
    }


def _uses_filter(batch):
    return sorted(
        (r.start_uid, r.end_uid, r.key.get("direction"), r.props.get("action"))
        for r in batch.rels
        if r.rel_type == "USES_FILTER"
    )


def test_the_collector_fetches_term_filter_attachments():
    from hst.collectors.apic import CLASSES

    assert "vzRsFiltAtt" in CLASSES


def test_the_collector_attaches_in_and_out_term_filters_with_their_direction():
    raw = _contract_raw(("intmnl", "uni/tn-t/flt-in"), ("outtmnl", "uni/tn-t/flt-out"))
    batch = normalize_apic(raw, fabric="f1", l3dom="global")
    subject = "aci:f1:uni/tn-t/brc-web/subj-s"
    assert _uses_filter(batch) == [
        (subject, "aci:f1:uni/tn-t/flt-in", "in", "permit"),
        (subject, "aci:f1:uni/tn-t/flt-out", "out", "permit"),
    ]


def test_the_collector_keeps_one_filter_under_both_terms_as_two_attachments():
    raw = _contract_raw(("intmnl", "uni/tn-t/flt-web"), ("outtmnl", "uni/tn-t/flt-web"))
    batch = normalize_apic(raw, fabric="f1", l3dom="global")
    assert [direction for _s, _f, direction, _a in _uses_filter(batch)] == ["in", "out"]


def test_the_collector_skips_a_term_filter_of_a_subject_it_did_not_keep():
    raw = _contract_raw(("intmnl", "uni/tn-t/flt-in"), subject_dn="uni/tn-t/oobbrc-x/subj-s")
    batch = normalize_apic(raw, fabric="f1", l3dom="global")
    assert _uses_filter(batch) == []


def test_the_collector_stores_tcp_rules_fragment_matching_and_stateful():
    props = _entry_props(prot="tcp", etherT="ip", tcpRules="est", applyToFrag="yes", stateful="yes")
    assert (props["tcp_rules"], props["apply_to_frag"], props["stateful"]) == ("est", "yes", "yes")


def test_the_collector_writes_the_vzentry_defaults_apic_omits():
    props = _entry_props(prot="tcp", dFromPort="443", dToPort="443")
    assert props["ether_type"] == "unspecified"
    assert (props["s_from_port"], props["s_to_port"]) == ("unspecified", "unspecified")
    assert (props["tcp_rules"], props["apply_to_frag"]) == ("unspecified", "no")


def test_a_source_port_entry_is_indeterminate_in_the_trace_not_a_permit(aci):
    aci["ends"] = _ends()
    aci["contracts"] = _contract(
        {
            "proto": "tcp",
            "from_port": "unspecified",
            "to_port": "unspecified",
            "ether": "ip",
            "s_from_port": "1024",
            "s_to_port": "2048",
        }
    )
    assert _trace()["action"] == INDETERMINATE


def test_an_entry_without_collected_source_ports_is_indeterminate_in_the_trace(aci):
    aci["ends"] = _ends()
    aci["contracts"] = _contract(
        {"proto": "tcp", "from_port": "443", "to_port": "443", "ether": "ip", "s_from_port": None}
    )
    assert _trace()["action"] == INDETERMINATE


def test_an_established_only_entry_does_not_permit_a_new_flow_in_the_trace(aci):
    aci["ends"] = _ends()
    aci["contracts"] = _contract(
        {"proto": "tcp", "from_port": "443", "to_port": "443", "ether": "ip", "tcp_rules": "est"}
    )
    assert _trace()["action"] == INDETERMINATE


def test_a_fragment_only_entry_does_not_permit_in_the_trace(aci):
    aci["ends"] = _ends()
    aci["contracts"] = _contract(
        {"proto": "tcp", "from_port": "443", "to_port": "443", "ether": "ip", "apply_to_frag": "yes"}
    )
    assert _trace()["action"] == INDETERMINATE


def test_an_out_term_filter_does_not_permit_the_consumer_to_provider_flow(aci):
    aci["ends"] = _ends()
    entry = {"proto": "tcp", "from_port": "443", "to_port": "443", "ether": "ip"}
    aci["contracts"] = _contract({**entry, "direction": "out"})
    assert _trace()["action"] == DENY
    aci["contracts"] = _contract({**entry, "direction": "in"})
    assert _trace()["action"] == PERMIT


def test_the_trace_passes_the_contexts_of_its_legs_to_the_aci_gate(monkeypatch):
    import importlib
    from types import SimpleNamespace

    # hst.path re-exports a `trace` function under the module's name
    trace = importlib.import_module("hst.path.trace")
    seen = {}

    def verdict(session, src_ip, dst_ip, port, proto, contexts=()):
        seen["contexts"] = list(contexts)

    monkeypatch.setattr(trace, "aci_contract_verdict", verdict)
    monkeypatch.setattr(path, "_read", lambda *_args, **_kwargs: [])
    legs = [{"context_uid": "vrf:b"}, {"context_uid": "vrf:a"}, {"context_uid": "vrf:a"}, {}]
    trail = SimpleNamespace(notes=[], hops=[], dst_seen=[], orig_dst=None)
    trace._flow_gates(None, trail, legs, "permitted", "10.0.0.5", "10.9.9.5", 443, "tcp")
    assert seen["contexts"] == ["vrf:a", "vrf:b"]


def test_an_established_only_entry_is_indeterminate_in_the_symbolic_gate(monkeypatch):
    entry = {"proto": "tcp", "ether_type": "ip", "d_from_port": "443", "d_to_port": "443", "tcp_rules": "est"}
    assert _symbolic(monkeypatch, entry) == {"indeterminate"}


def test_a_source_port_entry_claims_only_its_ports_in_the_symbolic_gate(monkeypatch):
    entry = {
        "proto": "tcp",
        "ether_type": "ip",
        "d_from_port": "443",
        "d_to_port": "443",
        "s_from_port": "2000",
        "s_to_port": "2000",
    }
    # the region's source port is 1000: the entry claims none of it
    assert _symbolic(monkeypatch, entry) == {"deny"}


def test_an_out_term_filter_claims_nothing_in_the_symbolic_gate(monkeypatch):
    entry = {"proto": "tcp", "ether_type": "ip", "d_from_port": "443", "d_to_port": "443", "direction": "out"}
    assert _symbolic(monkeypatch, entry) == {"deny"}


def _graph(nodes, relations):
    """`_inventory` with relationship properties: (kind, start, end[, props])."""
    catalog = {
        uid: GraphNode(uid, frozenset(labels), MappingProxyType(props)) for uid, labels, props in nodes
    }
    labels: dict[str, list[str]] = {}
    outgoing: dict[tuple[str, str], list[GraphRelation]] = {}
    incoming: dict[tuple[str, str], list[GraphRelation]] = {}
    for uid, node_labels, _props in nodes:
        for label in node_labels:
            labels.setdefault(label, []).append(uid)
    for index, (kind, start, end, *rest) in enumerate(relations):
        relation = GraphRelation(f"r{index}", kind, start, end, MappingProxyType(rest[0] if rest else {}))
        outgoing.setdefault((start, kind), []).append(relation)
        incoming.setdefault((end, kind), []).append(relation)
    return GraphInventory(
        "0" * 64,
        "f",
        MappingProxyType(catalog),
        MappingProxyType({key: tuple(value) for key, value in labels.items()}),
        MappingProxyType({key: tuple(value) for key, value in outgoing.items()}),
        MappingProxyType({key: tuple(value) for key, value in incoming.items()}),
        True,
        (),
        0,
    )


_TCP_443 = {**_IP_ENTRY, "proto": "tcp", "d_from_port": "443", "d_to_port": "443"}


def _contracted_fabric(entry=_TCP_443, filter_props=None):
    """epg-a (10.1.1.10) consumes and epg-b (10.1.2.10) provides one contract,
    both in the enforced VRF "vrf"."""
    nodes = [
        ("ep-a", {"Endpoint"}, {}),
        ("ep-b", {"Endpoint"}, {}),
        ("ip-a", {"IpAddress"}, {"ip": "10.1.1.10"}),
        ("ip-b", {"IpAddress"}, {"ip": "10.1.2.10"}),
        ("epg-a", {"Epg"}, {}),
        ("epg-b", {"Epg"}, {}),
        ("bd", {"BridgeDomain"}, {}),
        ("vrf", {"VrfInstance"}, {"pc_enf_pref": "enforced", "contract_bypass": ""}),
        ("ct", {"Contract"}, {}),
        ("subj", {"ContractSubject"}, {}),
        ("flt", {"AciFilter"}, {}),
        ("ent", {"FilterEntry"}, entry),
    ]
    relations = [
        ("HAS_IP", "ep-a", "ip-a"),
        ("HAS_IP", "ep-b", "ip-b"),
        ("IN_EPG", "ep-a", "epg-a"),
        ("IN_EPG", "ep-b", "epg-b"),
        ("IN_BD", "epg-a", "bd"),
        ("IN_BD", "epg-b", "bd"),
        ("IN_VRF", "bd", "vrf"),
        ("CONSUMES", "epg-a", "ct"),
        ("PROVIDES", "epg-b", "ct"),
        ("HAS", "ct", "subj"),
        ("USES_FILTER", "subj", "flt", filter_props or {}),
        ("HAS", "flt", "ent"),
    ]
    return nodes, relations


def test_an_established_only_entry_is_unknown_in_the_model():
    assert _model(_graph(*_contracted_fabric({**_TCP_443, "tcp_rules": "est"}))) == {"unknown"}


def test_a_source_port_entry_permits_only_its_source_ports_in_the_model():
    graph = _graph(*_contracted_fabric({**_TCP_443, "s_from_port": "1000", "s_to_port": "1000"}))
    assert _model(graph) == {"pass"}
    graph = _graph(*_contracted_fabric({**_TCP_443, "s_from_port": "2000", "s_to_port": "2000"}))
    assert _model(graph) == {"deny"}


def test_an_out_term_filter_does_not_permit_in_the_model():
    assert _model(_graph(*_contracted_fabric(filter_props={"direction": "out"}))) == {"deny"}
    assert _model(_graph(*_contracted_fabric(filter_props={"direction": "in"}))) == {"pass"}


# --- one EPG index per graph and request scoping ------------------------------------------


def _model_in(graph, vrf, *, source="10.1.1.10", destination="10.1.2.10", port=443, **request):
    context = ExecutionContext("e", "graph", "graph", "leaf1", vrf, 4)
    downstream = StateKey("downstream", context)
    expansion = expand_aci_contracts(graph, context, downstream, **request)
    nodes = {node.key: node for node in expansion.nodes}
    packet = {
        "source_address": int(ipaddress.ip_address(source)),
        "destination_address": int(ipaddress.ip_address(destination)),
        "protocol": 6,
        "source_port": 1000,
        "destination_port": port,
    }
    outcomes = set()
    pending = [expansion.entry]
    while pending:
        # an edge to the gate of the next scope is followed (`external_scopes`)
        for edge in nodes[pending.pop()].edges:
            if not _holds(edge.predicate, packet):
                continue
            if edge.target == downstream:
                outcomes.add("pass")
            elif nodes[edge.target].terminal is None:
                pending.append(edge.target)
            else:
                outcomes.add(nodes[edge.target].terminal)
    return outcomes, expansion


def _span(*networks):
    return tuple(
        (4, int(ipaddress.ip_network(n).network_address), int(ipaddress.ip_network(n).broadcast_address))
        for n in networks
    )


def test_the_aci_index_is_built_once_per_graph(monkeypatch):
    from hst.analysis_model import gates

    built = []
    original = gates._AciIndex.__init__

    def counting(self, graph, af):
        built.append(af)
        original(self, graph, af)

    monkeypatch.setattr(gates._AciIndex, "__init__", counting)
    graph = _graph(*_contracted_fabric())
    for _ in range(3):
        assert _model_in(graph, "vrf")[0] == {"pass"}
    assert built == [4]


def test_a_request_outside_the_endpoint_space_does_not_expand_the_gate():
    graph = _graph(*_contracted_fabric())
    context = ExecutionContext("e", "graph", "graph", "leaf1", "vrf", 4)
    expansion = expand_aci_contracts(
        graph,
        context,
        StateKey("downstream", context),
        sources=_span("192.0.2.0/24"),
        destinations=_span("198.51.100.0/24"),
    )
    assert expansion.nodes == ()
    assert expansion.entry == StateKey("downstream", context)
    assert expansion.complete


def test_a_request_meeting_the_endpoint_space_expands_the_gate():
    graph = _graph(*_contracted_fabric())
    for sources, destinations in (
        (_span("10.1.1.0/24"), _span("198.51.100.0/24")),
        (_span("192.0.2.0/24"), _span("10.1.2.10/32")),
    ):
        context = ExecutionContext("e", "graph", "graph", "leaf1", "vrf", 4)
        expansion = expand_aci_contracts(
            graph, context, StateKey("downstream", context), sources=sources, destinations=destinations
        )
        assert expansion.nodes


def _wide_fabric(groups, members):
    """`groups` EPGs of `members` endpoints each in one enforced VRF, no contracts."""
    nodes = [
        ("bd", {"BridgeDomain"}, {}),
        ("vrf", {"VrfInstance"}, {"pc_enf_pref": "enforced", "contract_bypass": ""}),
    ]
    relations = [("IN_VRF", "bd", "vrf")]
    for group in range(groups):
        nodes.append((f"epg-{group}", {"Epg"}, {}))
        relations.append(("IN_BD", f"epg-{group}", "bd"))
        for member in range(members):
            name = f"{group}-{member}"
            nodes += [
                (f"ep-{name}", {"Endpoint"}, {}),
                (f"ip-{name}", {"IpAddress"}, {"ip": f"10.{group}.{member}.10"}),
            ]
            relations += [("HAS_IP", f"ep-{name}", f"ip-{name}"), ("IN_EPG", f"ep-{name}", f"epg-{group}")]
    return _graph(nodes, relations)


def _distinct_atoms(predicates):
    """The atoms of `predicates`, a composite shared by identity counted once."""
    seen: set[int] = set()
    atoms = 0
    pending = list(predicates)
    while pending:
        term = pending.pop()
        if id(term) in seen:
            continue
        seen.add(id(term))
        if isinstance(term, Atom):
            atoms += 1
        elif isinstance(term, (AllOf, AnyOf)):
            pending.extend(term.terms)
        elif isinstance(term, Not):
            pending.append(term.term)
    return atoms


def test_the_gate_shares_one_address_set_per_epg():
    groups, members = 30, 4
    _outcomes, expansion = _model_in(_wide_fabric(groups, members), "vrf", source="10.0.0.10")
    gate = next(node for node in expansion.nodes if node.key == expansion.entry)
    endpoints = groups * members
    assert _distinct_atoms(edge.predicate for edge in gate.edges) <= 4 * endpoints
    assert len(gate.edges) <= 2 * groups + 3


def test_an_uncontracted_pair_denies_and_an_external_destination_stays_unknown():
    graph = _wide_fabric(3, 1)
    assert _model_in(graph, "vrf", source="10.0.0.10", destination="10.1.0.10")[0] == {"deny"}
    assert _model_in(graph, "vrf", source="10.0.0.10", destination="198.51.100.7")[0] == {"unknown"}


class _Set:
    """A finite packet set for the predicate compiler, without the native backend."""

    def __init__(self, values):
        self.values = frozenset(values)

    def intersect(self, other):
        return _Set(self.values & other.values)

    def union(self, other):
        return _Set(self.values | other.values)

    def subtract(self, other):
        return _Set(self.values - other.values)

    def is_empty(self):
        return not self.values


def _counting_compiler(share_identical):
    from hst.policy.bounds import Bounds
    from hst.policy.predicates import CompiledPredicate, PredicateCompiler

    class Manager:
        schema = type("Schema", (), {"canonical_field": staticmethod(lambda field: field)})()

        def universe(self, known_fields):
            return _Set(range(64))

    class Counting(PredicateCompiler):
        calls = 0

        def _compile(self, predicate, stack, depth):
            Counting.calls += 1
            return super()._compile(predicate, stack, depth)

        def _atom(self, atom):
            values = _Set(range(atom.value, atom.other + 1))
            return CompiledPredicate(Bounds(self.universe, values, values))

    return Counting(Manager(), frozenset({"source_address"}), share_identical=share_identical), Counting


def test_a_model_compiler_compiles_a_shared_address_set_once():
    shared = AnyOf(tuple(Atom("source_address", "range", value, value) for value in range(40)))
    edges = [AllOf((shared, Atom("source_address", "range", low, 63))) for low in range(4)]
    for share, last_compile in ((True, 3), (False, 43)):
        compiler, counting = _counting_compiler(share)
        results = [compiler.compile(edge) for edge in edges]
        before = counting.calls
        compiler.compile(edges[-1])
        assert counting.calls - before == last_compile
        assert [sorted(r.bounds.lower.values) for r in results] == [list(range(low, 40)) for low in range(4)]


def test_the_model_build_uses_a_sharing_compiler_and_policies_do_not():
    import inspect

    from hst.analysis_model import compile as model_compile
    from hst.policy import compile as policy_compile

    assert "share_identical=True" in inspect.getsource(model_compile.compile_model)
    assert "share_identical" not in inspect.getsource(policy_compile.PolicyCompiler.__init__)


# --- endpoints scoped to the entry VRF ----------------------------------------------------


def _reused_address_fabric(*, second_epg_vrf):
    """10.1.1.10 is an endpoint of epg-a (VRF "vrf") and of epg-x (VRF
    `second_epg_vrf`); epg-a may reach epg-b on tcp/443, epg-x has no contract."""
    nodes, relations = _contracted_fabric()
    nodes += [
        ("ep-x", {"Endpoint"}, {}),
        ("ip-x", {"IpAddress"}, {"ip": "10.1.1.10"}),
        ("epg-x", {"Epg"}, {}),
    ]
    relations += [("HAS_IP", "ep-x", "ip-x"), ("IN_EPG", "ep-x", "epg-x")]
    if second_epg_vrf == "vrf":
        relations.append(("IN_BD", "epg-x", "bd"))
    else:
        nodes += [
            ("bd-x", {"BridgeDomain"}, {}),
            (second_epg_vrf, {"VrfInstance"}, {"pc_enf_pref": "enforced", "contract_bypass": ""}),
        ]
        relations += [("IN_BD", "epg-x", "bd-x"), ("IN_VRF", "bd-x", second_epg_vrf)]
    return _graph(nodes, relations)


def test_an_address_another_vrf_reuses_is_the_entry_vrfs_endpoint():
    graph = _reused_address_fabric(second_epg_vrf="vrf-other")
    assert _model_in(graph, "vrf")[0] == {"pass"}
    # entering in the other VRF, the address is epg-x's, whose VRF holds no 10.1.2.10
    assert _model_in(graph, "vrf-other")[0] == {"unknown"}


def test_an_address_two_epgs_of_one_vrf_hold_is_unknown_not_a_pick():
    graph = _reused_address_fabric(second_epg_vrf="vrf")
    outcomes, expansion = _model_in(graph, "vrf")
    assert outcomes == {"unknown"}
    assert "ACI_ENDPOINT_IDENTITY_UNKNOWN" in expansion.gaps


def test_a_flow_entering_outside_every_fabric_has_no_aci_source():
    graph = _graph(*_contracted_fabric())
    assert _model_in(graph, "campus-vrf")[0] == {"unknown"}
    assert _model_in(graph, "campus-vrf", source="192.0.2.1", destination="198.51.100.7")[0] == {"pass"}


def test_a_destination_in_a_vrf_of_the_same_fabric_is_an_endpoint():
    """A destination endpoint of another VRF on the same fabric is an EPG pair
    whose enforcement is unknown, not a flow with one ACI endpoint."""
    nodes = [
        ("fabric", {"Fabric"}, {}),
        ("leaf", {"Device"}, {}),
        ("if-a", {"Interface"}, {}),
        ("if-c", {"Interface"}, {}),
        ("ep-a", {"Endpoint"}, {}),
        ("ep-c", {"Endpoint"}, {}),
        ("ip-a", {"IpAddress"}, {"ip": "10.1.1.10"}),
        ("ip-c", {"IpAddress"}, {"ip": "10.3.3.10"}),
        ("epg-a", {"Epg"}, {}),
        ("epg-c", {"Epg"}, {}),
        ("bd-a", {"BridgeDomain"}, {}),
        ("bd-c", {"BridgeDomain"}, {}),
        ("vrf", {"VrfInstance"}, {"pc_enf_pref": "enforced", "contract_bypass": ""}),
        ("vrf-c", {"VrfInstance"}, {"pc_enf_pref": "enforced", "contract_bypass": ""}),
    ]
    relations = [
        ("MEMBER_OF", "leaf", "fabric"),
        ("ON", "if-a", "leaf"),
        ("ON", "if-c", "leaf"),
        ("IN_VRF", "if-a", "vrf"),
        ("IN_VRF", "if-c", "vrf-c"),
        ("HAS_IP", "ep-a", "ip-a"),
        ("HAS_IP", "ep-c", "ip-c"),
        ("IN_EPG", "ep-a", "epg-a"),
        ("IN_EPG", "ep-c", "epg-c"),
        ("IN_BD", "epg-a", "bd-a"),
        ("IN_BD", "epg-c", "bd-c"),
        ("IN_VRF", "bd-a", "vrf"),
        ("IN_VRF", "bd-c", "vrf-c"),
    ]
    outcomes, expansion = _model_in(_graph(nodes, relations), "vrf", destination="10.3.3.10")
    assert outcomes == {"unknown"}
    assert "ACI_VRF_ENFORCEMENT_UNKNOWN" in expansion.gaps
    # without the shared fabric the other VRF's endpoint is no destination of this entry
    unlinked = [r for r in relations if r[0] not in ("MEMBER_OF", "ON")]
    outcomes, expansion = _model_in(_graph(nodes, unlinked), "vrf", destination="10.3.3.10")
    assert outcomes == {"unknown"}
    assert "ACI_VRF_ENFORCEMENT_UNKNOWN" not in expansion.gaps


# --- external EPGs ---------------------------------------------------------------------------


def _external_fabric(*, consumes=("ct",), provides=(), subnets=("10.9.0.0/16",), part_of=False, more=()):
    """`_contracted_fabric` with the L3Out "out" of the VRF "vrf" and its external
    EPG "ext", which matches `subnets`. epg-a consumes and epg-b provides the
    contract "ct" on tcp/443. `more` holds (uid, subnet) of more external EPGs
    of the L3Out, with no contract."""
    nodes, relations = _contracted_fabric()
    nodes.append(("out", {"L3Out"}, {}))
    relations.append(("IN_VRF", "out", "vrf"))
    for uid, matched in (("ext", subnets), *((uid, (subnet,)) for uid, subnet in more)):
        nodes.append((uid, {"ExtEpg"}, {}))
        relations.append(("PART_OF", uid, "out") if part_of else ("HAS", "out", uid))
        for index, subnet in enumerate(matched):
            nodes.append((f"pfx-{uid}-{index}", {"Prefix"}, {"cidr": subnet}))
            relations.append(("MATCHES", uid, f"pfx-{uid}-{index}"))
    relations += [("CONSUMES", "ext", contract) for contract in consumes]
    relations += [("PROVIDES", "ext", contract) for contract in provides]
    return _graph(nodes, relations)


OUTSIDE = {"source": "10.9.1.1", "destination": "10.1.2.10"}


@pytest.mark.parametrize("part_of", [False, True], ids=["l3out-has", "part-of-l3out"])
def test_a_packet_from_outside_has_the_external_epg_of_its_source(part_of):
    graph = _external_fabric(part_of=part_of)
    assert _model_in(graph, "outside", **OUTSIDE)[0] == {"pass"}
    assert _model_in(graph, "outside", **OUTSIDE, port=80)[0] == {"deny"}


def test_an_external_epg_with_no_contract_to_the_epg_is_denied_in_an_enforced_vrf():
    assert _model_in(_external_fabric(consumes=()), "outside", **OUTSIDE)[0] == {"deny"}


def test_a_source_that_no_external_epg_matches_is_unknown():
    graph = _external_fabric()
    assert _model_in(graph, "outside", source="192.0.2.1", destination="10.1.2.10")[0] == {"unknown"}


def test_a_packet_from_outside_to_no_endpoint_passes():
    graph = _external_fabric()
    assert _model_in(graph, "outside", source="10.9.1.1", destination="10.9.2.2")[0] == {"pass"}


def test_the_longest_subnet_of_the_vrf_classifies_the_address():
    graph = _external_fabric(more=(("ext-2", "10.9.1.0/24"),))
    assert _model_in(graph, "outside", **OUTSIDE)[0] == {"deny"}
    assert _model_in(graph, "outside", source="10.9.2.1", destination="10.1.2.10")[0] == {"pass"}


def test_an_address_of_2_external_epgs_with_the_same_subnet_is_unknown():
    graph = _external_fabric(more=(("ext-2", "10.9.0.0/16"),))
    assert _model_in(graph, "outside", **OUTSIDE)[0] == {"unknown"}


def test_an_endpoint_address_inside_the_subnet_stays_the_address_of_its_epg():
    graph = _external_fabric(subnets=("10.1.0.0/16",))
    # 10.1.1.10 is the endpoint of epg-a, also for a packet from outside
    assert _model_in(graph, "outside", source="10.1.1.10", destination="10.1.2.10")[0] == {"unknown"}
    assert _model_in(graph, "vrf")[0] == {"pass"}


def test_a_packet_from_an_epg_has_the_external_epg_of_its_destination():
    to_outside = {"source": "10.1.1.10", "destination": "10.9.1.1"}
    provided = _external_fabric(consumes=(), provides=("ct",))
    assert _model_in(provided, "vrf", **to_outside)[0] == {"pass"}
    assert _model_in(provided, "vrf", **to_outside, port=80)[0] == {"deny"}
    assert _model_in(_external_fabric(consumes=()), "vrf", **to_outside)[0] == {"deny"}
    # no external EPG matches the destination
    assert _model_in(provided, "vrf", source="10.1.1.10", destination="192.0.2.1")[0] == {"unknown"}


def test_an_external_epg_without_a_subnet_or_with_2_vrfs_classifies_no_address():
    assert _model_in(_external_fabric(subnets=()), "outside", **OUTSIDE)[0] == {"unknown"}
    nodes, relations = _contracted_fabric()
    nodes += [
        ("out", {"L3Out"}, {}),
        ("ext", {"ExtEpg"}, {}),
        ("pfx", {"Prefix"}, {"cidr": "10.9.0.0/16"}),
        ("vrf-2", {"VrfInstance"}, {"pc_enf_pref": "enforced", "contract_bypass": ""}),
    ]
    relations += [
        ("IN_VRF", "out", "vrf"),
        ("IN_VRF", "out", "vrf-2"),
        ("HAS", "out", "ext"),
        ("MATCHES", "ext", "pfx"),
        ("CONSUMES", "ext", "ct"),
    ]
    assert _model_in(_graph(nodes, relations), "outside", **OUTSIDE)[0] == {"unknown"}


def test_a_packet_to_an_endpoint_of_another_fabric_has_the_gate_of_that_fabric():
    """The entry VRF "vrf-1" holds epg-s, and the fabric of "vrf" holds epg-b. The
    packet passes the gate of the entry VRF as a packet to its external EPG, and
    the gate of the other fabric as a packet from its external EPG."""
    nodes, relations = _contracted_fabric()
    nodes += [
        ("out", {"L3Out"}, {}),
        ("ext", {"ExtEpg"}, {}),
        ("pfx", {"Prefix"}, {"cidr": "10.0.0.0/8"}),
        ("ep-s", {"Endpoint"}, {}),
        ("ip-s", {"IpAddress"}, {"ip": "10.5.1.10"}),
        ("epg-s", {"Epg"}, {}),
        ("bd-1", {"BridgeDomain"}, {}),
        ("vrf-1", {"VrfInstance"}, {"pc_enf_pref": "enforced", "contract_bypass": ""}),
        ("out-1", {"L3Out"}, {}),
        ("ext-1", {"ExtEpg"}, {}),
        ("ct-1", {"Contract"}, {}),
        ("subj-1", {"ContractSubject"}, {}),
    ]
    relations += [
        ("IN_VRF", "out", "vrf"),
        ("HAS", "out", "ext"),
        ("MATCHES", "ext", "pfx"),
        ("HAS_IP", "ep-s", "ip-s"),
        ("IN_EPG", "ep-s", "epg-s"),
        ("IN_BD", "epg-s", "bd-1"),
        ("IN_VRF", "bd-1", "vrf-1"),
        ("IN_VRF", "out-1", "vrf-1"),
        ("HAS", "out-1", "ext-1"),
        ("MATCHES", "ext-1", "pfx"),
        ("CONSUMES", "epg-s", "ct-1"),
        ("PROVIDES", "ext-1", "ct-1"),
        ("HAS", "ct-1", "subj-1"),
        ("USES_FILTER", "subj-1", "flt"),
    ]
    flow = {"source": "10.5.1.10", "destination": "10.1.2.10"}
    # the external EPG of the second fabric consumes no contract of epg-b
    assert _model_in(_graph(nodes, relations), "vrf-1", **flow)[0] == {"deny"}
    relations.append(("CONSUMES", "ext", "ct"))
    graph = _graph(nodes, relations)
    assert _model_in(graph, "vrf-1", **flow)[0] == {"pass"}
    assert _model_in(graph, "vrf-1", **flow, port=80)[0] == {"deny"}


@pytest.mark.parametrize("shape", ["bridge-domain-subnet", "connected-prefix-of-the-vrf"])
def test_an_address_of_a_subnet_of_the_fabric_has_no_external_epg(shape):
    """10.1.2.99 is in the subnet 10.1.2.0/24 of the fabric and is no endpoint.
    The external EPG matches 10.0.0.0/8 and provides the contract."""
    nodes, relations = _contracted_fabric()
    nodes += [
        ("out", {"L3Out"}, {}),
        ("ext", {"ExtEpg"}, {}),
        ("pfx-ext", {"Prefix"}, {"cidr": "10.0.0.0/8"}),
        ("pfx-bd", {"Prefix"}, {"cidr": "10.1.2.0/24"}),
    ]
    relations += [
        ("IN_VRF", "out", "vrf"),
        ("HAS", "out", "ext"),
        ("MATCHES", "ext", "pfx-ext"),
        ("PROVIDES", "ext", "ct"),
        ("CONSUMES", "ext", "ct"),
        ("IN", "pfx-bd", "bd")
        if shape == "bridge-domain-subnet"
        else ("ORIGINATES", "vrf", "pfx-bd", {"proto": "connected"}),
    ]
    graph = _graph(nodes, relations)
    assert _model_in(graph, "vrf", source="10.1.1.10", destination="10.1.2.99")[0] == {"unknown"}
    assert _model_in(graph, "outside", source="10.1.2.99", destination="10.1.2.10")[0] == {"unknown"}
    # an address outside the subnets of the fabric has the external EPG
    assert _model_in(graph, "vrf", source="10.1.1.10", destination="10.7.0.1")[0] == {"pass"}
    assert _model_in(graph, "outside", source="10.7.0.1", destination="10.1.2.10")[0] == {"pass"}


# --- a contract with a service graph ------------------------------------------------------

_FIREWALL = StateKey("firewall", ExecutionContext("e", "graph", "graph", "fw", "fw-vrf", 4))
_REDIRECT_TARGETS = {"10.9.9.1": _FIREWALL}


def _graph_fabric(*, connectors=("consumer", "provider"), graph_nodes=1, destinations=1, plain_subject=False):
    """`_contracted_fabric` whose subject applies the graph "sg". The device
    selection binds each connector of `connectors` to the redirect policy "pbr"."""
    nodes, relations = _contracted_fabric()
    nodes += [("sg", {"ServiceGraphTemplate"}, {"name": "fw"}), ("pbr", {"PbrPolicy"}, {})]
    nodes += [(f"node{index}", {"ServiceNode"}, {"name": f"N{index}"}) for index in range(graph_nodes)]
    nodes += [(f"dest{index}", {"PbrDest"}, {"ip": f"10.9.9.{index + 1}"}) for index in range(destinations)]
    relations += [("APPLIES_GRAPH", "subj", "sg")]
    relations += [("HAS_NODE", "sg", f"node{index}") for index in range(graph_nodes)]
    relations += [("HAS_DEST", "pbr", f"dest{index}") for index in range(destinations)]
    relations += [
        ("REDIRECTS_VIA", "ct", "pbr", {"graph": "sg", "node": "N0", "connector": connector})
        for connector in connectors
    ]
    if plain_subject:
        nodes += [("subj2", {"ContractSubject"}, {})]
        relations += [("HAS", "ct", "subj2"), ("USES_FILTER", "subj2", "flt")]
    return _graph(nodes, relations)


def _outcomes(expansion, downstream, packet):
    nodes = {node.key: node for node in expansion.nodes}
    return {
        "pass"
        if edge.target == downstream
        else "redirect"
        if edge.target == _FIREWALL
        else nodes[edge.target].terminal
        for edge in nodes[expansion.entry].edges
        if _holds(edge.predicate, packet)
    }


def _forward(graph, port=443, targets=_REDIRECT_TARGETS):
    context = ExecutionContext("e", "graph", "graph", "leaf1", "vrf", 4)
    downstream = StateKey("downstream", context)
    expansion = expand_aci_contracts(graph, context, downstream, redirect_targets=targets)
    packet = {
        "source_address": int(ipaddress.ip_address("10.1.1.10")),
        "destination_address": int(ipaddress.ip_address("10.1.2.10")),
        "protocol": 6,
        "source_port": 1000,
        "destination_port": port,
    }
    return _outcomes(expansion, downstream, packet)


def _reply(graph, targets=_REDIRECT_TARGETS):
    context = ExecutionContext("e", "graph", "graph", "leaf1", "vrf", 4)
    downstream = StateKey("downstream", context)
    expansion = expand_aci_reply_redirects(graph, context, downstream, targets)
    packet = {
        "source_address": int(ipaddress.ip_address("10.1.2.10")),
        "destination_address": int(ipaddress.ip_address("10.1.1.10")),
        "protocol": 6,
        "source_port": 443,
        "destination_port": 1000,
    }
    if expansion.entry == downstream:
        return {"pass"}
    return _outcomes(expansion, downstream, packet)


def test_a_contract_with_a_service_graph_redirects_the_packets_of_its_filter():
    assert _forward(_graph_fabric()) == {"redirect"}
    assert _forward(_graph_fabric(), port=80) == {"deny"}


@pytest.mark.parametrize(
    "fabric",
    [
        {"connectors": ("consumer",)},
        {"connectors": ()},
        {"graph_nodes": 2},
        {"graph_nodes": 0},
        {"destinations": 2},
        {"destinations": 0},
        {"plain_subject": True},
    ],
)
def test_a_service_graph_with_no_established_redirect_is_unknown(fabric):
    assert _forward(_graph_fabric(**fabric)) == {"unknown"}
    assert _reply(_graph_fabric(**fabric)) == {"pass"}


def test_a_redirect_destination_with_no_state_is_unknown():
    assert _forward(_graph_fabric(), targets={}) == {"unknown"}
    assert _forward(_graph_fabric(), targets=None) == {"unknown"}


def test_the_reply_of_a_contract_with_a_service_graph_goes_to_the_redirect_destination():
    assert _reply(_graph_fabric()) == {"redirect"}
    assert _reply(_graph_fabric(), targets={}) == {"pass"}


def test_a_contract_with_no_service_graph_has_no_reply_redirect():
    assert _reply(_graph(*_contracted_fabric())) == {"pass"}
