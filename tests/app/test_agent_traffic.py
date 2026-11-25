"""Traffic-question reference cases: resolution, full sets, evidence and scope."""

# ruff: noqa: F811 -- shared scripted graph fixture

from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from tests.app.test_ai_api import _db_seam, _FakeGraphSession
from tests.test_impact_evaluate import _firewall, graph  # noqa: F401
from tests.test_path_nat import _dnat_row
from tests.test_path_trace import _rule

from hst import path
from hst.app.agent import registry, tools, traffic
from hst.app.agent.budget import AskBudget, current_budget
from hst.app.ai.registry import Principal, ToolContext
from hst.assessment import evaluation
from hst.core import Settings
from hst.core import db as dbmod
from hst.impact.evaluate import GraphGates, Interface, Network, Service
from hst.path.addrsets import _intersect, _intervals, _ports, _subtract
from hst.path.state import FlowRegion
from hst.simul import rib

EDGE, CTX = "dev:edge", "vrf:edge"
DEST = "10.10.0.128/25"


def _addresses(*specs):
    return traffic.resolve(None, traffic.AddressSelector(kind="addresses", addresses=list(specs)))


def _network():
    return Network(
        rib.RibInput(
            contexts=[{"uid": CTX, "device_uid": EDGE, "name": "default", "platform": "nxos"}],
            connected=[
                {"context_uid": CTX, "prefix": "192.0.2.0/24", "interface": "wan"},
                {"context_uid": CTX, "prefix": "10.10.0.0/24", "interface": "lan"},
            ],
            platform="nxos",
        ),
        (
            Interface(EDGE, "if:wan", "wan", CTX, ("192.0.2.0/24",), ("192.0.2.1",)),
            Interface(EDGE, "if:lan", "lan", CTX, ("10.10.0.0/24",), ("10.10.0.1",)),
        ),
        GraphGates(None),
    )


def _services(proto=frozenset(range(256)), port="any"):
    return Service(proto, tuple(_ports(port)), tuple(_ports("any")))


def _bucket_region(bucket):
    region = FlowRegion()
    for row in bucket["items"]:
        region = region.union(
            FlowRegion.from_query(
                _intervals(row["sources"]),
                _intervals(row["destinations"]),
                frozenset(row["protocols"]),
                _ports(row["destination_ports"]),
                _ports(row["source_ports"]),
            )
        )
    return region


def _assert_partition(result, src, dst, svc):
    allowed, denied, unknown = (_bucket_region(result[k]) for k in ("allowed", "denied", "not_established"))
    requested = FlowRegion.from_query(src.addresses, dst.addresses, svc.proto, svc.dport, svc.sport)
    assert not allowed.intersect(denied)
    assert not allowed.intersect(unknown)
    assert not denied.intersect(unknown)
    union = allowed.union(denied).union(unknown)
    assert not requested.subtract(union)
    assert not union.subtract(requested)
    return allowed, denied, unknown


def test_non_rfc1918_is_the_exact_ipv4_complement_including_reserved_addresses():
    resolved = traffic.resolve(None, traffic.AddressSelector(kind="non-rfc1918"))
    private = _intervals(list(traffic.RFC1918))
    assert not _intersect(list(resolved.addresses), private)
    assert not _subtract(_intervals(["0.0.0.0/0"]), [*resolved.addresses, *private])
    for addr in ("127.0.0.1", "100.64.0.1", "192.0.2.10", "224.0.0.1", "172.32.0.1"):
        assert _intersect(list(resolved.addresses), _intervals([addr]))
    assert {af for af, _, _ in resolved.addresses} == {4}


def test_exclusions_preserve_exact_holes_without_host_enumeration():
    result = traffic.resolve(
        None,
        traffic.AddressSelector(
            kind="addresses",
            addresses=["10.0.0.0/24", "10.0.0.128/25"],
            exclude=["10.0.0.40-10.0.0.59"],
        ),
    )
    assert sum(hi - lo + 1 for _, lo, hi in result.addresses) == 236
    assert not _intersect(list(result.addresses), _intervals(["10.0.0.40-10.0.0.59"]))


@pytest.mark.parametrize("spec", ["not-an-address", "10.0.0.9-10.0.0.2", "10.0.0.1-::1"])
def test_invalid_members_are_rejected(spec):
    with pytest.raises(ValueError, match="invalid address"):
        traffic.resolve(None, traffic.AddressSelector(kind="addresses", addresses=["10.0.0.1", spec]))


def _resolution_graph(monkeypatch, networks, prefixes, groups=()):
    def read(session, query, **params):
        if query == traffic._NETWORKS:
            return networks
        if query == traffic._NETWORK_PREFIXES:
            return prefixes.get(params["uid"], [])
        if query == traffic._GROUPS:
            return list(groups)
        raise AssertionError(query)

    monkeypatch.setattr(path, "_read", read)


def test_vlan_reuse_requires_a_broadcast_domain_or_vrf_choice(monkeypatch):
    _resolution_graph(
        monkeypatch,
        [{"uid": "bd:a", "name": "users"}, {"uid": "bd:b", "name": "users"}],
        {
            "bd:a": [{"cidr": "10.10.0.0/24", "context": "vrf:a"}],
            "bd:b": [{"cidr": "10.10.0.0/24", "context": "vrf:b"}],
        },
    )
    src = {"kind": "non-rfc1918"}
    dst = {"kind": "vlan", "value": "10"}
    result = traffic.query(None, source=src, destination=dst)
    assert result["status"] == "needs_clarification"
    assert not result["coverage"]["entire_request_evaluated"]
    assert len(result["plan"]["destination"]["candidates"]) == 2
    scoped = traffic.resolve(None, traffic.AddressSelector(**dst, context="vrf:b"))
    assert not scoped.issues and scoped.context == "vrf:b"


@pytest.mark.parametrize("opaque,unresolved", [(True, 0), (False, 1)])
def test_partly_resolved_group_does_not_become_a_complete_population(monkeypatch, opaque, unresolved):
    _resolution_graph(
        monkeypatch,
        [],
        {},
        groups=[
            {
                "uid": "obj:group",
                "name": "external",
                "addresses": ["192.0.2.0/24"],
                "ranges": [],
                "opaque": opaque,
                "unresolved": unresolved,
            }
        ],
    )
    result = traffic.query(
        None,
        source={"kind": "group", "value": "external"},
        destination={"kind": "addresses", "addresses": [DEST]},
    )
    assert result["status"] == "not_established"
    assert not result["coverage"]["entire_request_evaluated"]
    assert "allowed" not in result


def test_group_reads_materialized_membership_and_ranges(monkeypatch):
    _resolution_graph(
        monkeypatch,
        [],
        {},
        groups=[
            {
                "uid": "obj:group",
                "name": "external",
                "addresses": ["192.0.2.0/25"],
                "ranges": ["192.0.2.128-192.0.2.255"],
                "opaque": False,
                "unresolved": 0,
            }
        ],
    )
    resolved = traffic.resolve(None, traffic.AddressSelector(kind="group", value="external"))
    assert resolved.addresses == tuple(_intervals(["192.0.2.0/24"]))


def test_original_question_evaluates_every_service_and_keeps_unattached_sources_unknown(graph):
    src = traffic.resolve(None, traffic.AddressSelector(kind="non-rfc1918"))
    dst = _addresses(DEST)
    _firewall(
        graph,
        EDGE,
        "rb:edge",
        [
            _rule(
                uid="rule:https",
                svc_any=False,
                protos=["tcp"],
                ports=["443"],
            )
        ],
        default_action="drop",
    )
    svc = _services()
    result = traffic.evaluate(_network(), src, dst, svc)
    allowed, denied, unknown = _assert_partition(result, src, dst, svc)
    assert allowed and denied and unknown
    assert result["status"] == "partial"
    assert result["coverage"]["entire_request_evaluated"]
    assert not result["coverage"]["entire_request_decided"]
    assert any("no interface" in reason for reason in result["missing_evidence"])
    assert all(r.proto == {6} and r.dport == tuple(_ports(443)) for r in allowed)
    assert "rule:https" in json.dumps(result["evidence"])


def test_explicit_ingress_evaluates_external_sources_as_forwarded_traffic(graph):
    src = traffic.resolve(None, traffic.AddressSelector(kind="non-rfc1918"))
    dst, svc = _addresses(DEST), _services()
    _firewall(
        graph,
        EDGE,
        "rb:edge",
        [
            _rule(
                uid="rule:https",
                in_if="wan",
                svc_any=False,
                protos=["tcp"],
                ports=["443"],
            )
        ],
        default_action="drop",
    )
    graph.iface_names["if:wan"] = "wan"
    result = traffic.evaluate(_network(), src, dst, svc, ingress_interface="if:wan")
    allowed, denied, unknown = _assert_partition(result, src, dst, svc)
    assert allowed and denied and not unknown
    assert result["status"] == "complete"
    assert "traffic arrives on declared ingress interface if:wan" in result["assumptions"]
    assert any(a.startswith("flows spread over the equal-cost paths") for a in result["assumptions"])
    assert not _subtract(list(src.addresses), [i for r in allowed for i in r.src])


def test_negated_group_rule_preserves_protocol_port_correlation(graph):
    src, dst, svc = _addresses("192.0.2.0/24"), _addresses(DEST), _services()
    _firewall(
        graph,
        EDGE,
        "rb:edge",
        [
            _rule(
                uid="rule:except",
                src_any=False,
                src_cidrs=["192.0.2.0/25"],
                src_negate=True,
                svc_any=False,
                protos=["tcp", "udp"],
                ports=["443", "53"],
            )
        ],
        default_action="drop",
    )
    result = traffic.evaluate(_network(), src, dst, svc)
    allowed, _, unknown = _assert_partition(result, src, dst, svc)
    assert allowed and not unknown
    for proto, port, expected in ((6, 443, True), (17, 53, True), (6, 53, False), (17, 443, False)):
        sample = FlowRegion.from_query(
            _intervals(["192.0.2.128/25"]), dst.addresses, frozenset({proto}), _ports(port), _ports("any")
        )
        assert bool(allowed.intersect(sample)) is expected
    assert not any(_intersect(list(r.src), _intervals(["192.0.2.0/25"])) for r in allowed)


def test_overlapping_destination_in_another_vrf_is_not_proven(graph):
    src, dst = _addresses("192.0.2.128/25"), _addresses(DEST)
    dst.context = "vrf:other"
    result = traffic.evaluate(_network(), src, dst, _services())
    assert result["allowed"]["count"] == result["denied"]["count"] == 0
    assert result["not_established"]["count"] > 0
    assert any("destination context" in m for m in result["missing_evidence"])


def test_dnat_outputs_are_keyed_by_the_original_destination(graph):
    src, dst, svc = (
        _addresses("192.0.2.128/25"),
        _addresses("198.51.100.10"),
        _services(frozenset({6}), "443"),
    )
    graph.nat = [
        _dnat_row(
            orig_dst_raw="198.51.100.10",
            orig_dst_addrs=["198.51.100.10"],
            translation="10.10.0.130",
            xlate_dst_addrs=["10.10.0.130"],
            uid="nat:web",
        )
    ]
    result = traffic.evaluate(_network(), src, dst, svc)
    allowed, _, unknown = _assert_partition(result, src, dst, svc)
    assert allowed and not unknown
    assert all(r.dst == dst.addresses for r in allowed)
    assert "nat:web" in json.dumps(result["evidence"])


def test_missing_routing_observations_do_not_become_denied_traffic(graph):
    network = _network()
    network = replace(network, routing=replace(network.routing, rib_coverage={CTX: "not-captured"}))
    result = traffic.evaluate(network, _addresses("192.0.2.128/25"), _addresses(DEST), _services())
    assert result["allowed"]["count"] == result["denied"]["count"] == 0
    assert result["not_established"]["count"]


def test_evidence_truncation_is_visible_without_changing_the_calculation(graph, monkeypatch):
    monkeypatch.setattr(traffic, "RESULT_CAP", 1)
    _firewall(
        graph,
        EDGE,
        "rb:edge",
        [_rule(svc_any=False, protos=["tcp", "udp"], ports=["443", "53"])],
        default_action="drop",
    )
    result = traffic.evaluate(_network(), _addresses("192.0.2.128/25"), _addresses(DEST), _services())
    assert result["coverage"]["entire_request_decided"]
    assert result["coverage"]["output_truncated"]
    assert result["allowed"]["count"] == 2
    assert len(result["allowed"]["items"]) == 1


def test_tool_pins_all_readers_and_reaches_the_evaluator_once(monkeypatch):
    from hst.app.agent import traffic as traffic_mod

    session = _FakeGraphSession(lambda q: [], current=4000)
    monkeypatch.setattr(dbmod, "session", _db_seam(session))
    calls = []

    def query(pinned, **kwargs):
        calls.append((pinned, kwargs))
        return {"status": "partial"}

    monkeypatch.setattr(traffic_mod, "query", query)
    tool = _groups_tool(Settings(_env_file=None))
    result = json.loads(
        tools.unframe(
            AskBudget()
            .invoke(
                [tool],
                tool.name,
                {
                    "mode": "groups",
                    "source": {"kind": "non-rfc1918"},
                    "destination": {"kind": "vlan", "value": "10"},
                    "snapshot": "3000",
                },
            )
            .result
        )
    )
    assert result["snapshot"]["id"] == "3000"
    assert len(calls) == 1 and calls[0][0].cts == 3000
    for reader in ("rib_source", "bgp_source", "ospf_source"):
        assert calls[0][1][reader] is not None
    assert callable(calls[0][1]["checkpoint"])
    assert current_budget.get() is None


def _groups_tool(settings) -> tools.Tool:
    """`reach_trace`, whose groups mode evaluates the traffic between two selectors."""
    ctx = ToolContext(settings=settings, principal=Principal.for_role("viewer"), surface="drawer")
    return next(t for t in tools.offered_tools(ctx) if t.name == "reach_trace")


def test_traffic_tool_is_graph_read_and_custom_prompts_are_preserved():
    ctx = ToolContext(settings=None, principal=Principal.for_role("viewer"), surface="drawer")
    available = tools.offered_tools(ctx)
    assert any(t.name == "reach_trace" and t.permission == "graph.read" for t in available)
    assert not any(t.name == "query_cypher" for t in available)
    assert registry.merged({"system_prompt": "custom"})["system_prompt"] == "custom"
    assert "Use `reach_trace` with mode groups FIRST" in registry.DEFAULT_SYSTEM_PROMPT


def test_checkpoint_interrupts_a_symbolic_walk(graph):
    seen = []

    def checkpoint():
        seen.append("checkpoint")
        raise TimeoutError("cancelled")

    with pytest.raises(TimeoutError, match="cancelled"):
        traffic.evaluate(
            replace(_network(), checkpoint=checkpoint),
            _addresses("192.0.2.128/25"),
            _addresses(DEST),
            _services(),
        )
    assert seen == ["checkpoint"]


def test_original_question_runs_resolution_and_full_evaluation_once(graph, monkeypatch):
    from hst.app import simul_read
    from hst.app.routes import impact

    network = _network()
    read = path._read
    compilations = []

    def query_read(session, query, **params):
        if query == traffic._NETWORKS:
            return [{"uid": "bd:vlan10", "name": "users"}]
        if query == traffic._NETWORK_PREFIXES:
            return [{"cidr": DEST, "context": CTX}]
        if query == evaluation._CONTEXT_DOMAINS_QUERY:
            return [{"uid": CTX, "declared": ["estate"], "realized": [], "stamped": []}]
        return read(session, query, **params)

    def compile_network(session, **kwargs):
        compilations.append(kwargs)
        return SimpleNamespace(input=network.routing, errors=SimpleNamespace(as_dicts=lambda: []))

    monkeypatch.setattr(path, "_read", query_read)
    monkeypatch.setattr(impact, "_model_interfaces", lambda session: network.interfaces)
    monkeypatch.setattr(simul_read, "read_rib_input", compile_network)
    _firewall(
        graph, EDGE, "rb:edge", [_rule(svc_any=False, protos=["tcp"], ports=["443"])], default_action="drop"
    )
    result = traffic.query(
        None,
        source={"kind": "non-rfc1918"},
        destination={"kind": "vlan", "value": "10"},
        ingress_interface="if:wan",
    )
    assert len(compilations) == 1
    assert result["status"] == "complete"
    assert result["allowed"]["count"] > 0
    assert result["denied"]["count"] > 0
    assert not result["not_established"]["count"]
    assert result["plan"]["destination"]["context"] == CTX
    assert result["plan"]["ports"] == result["plan"]["source_ports"] == "any"


def test_missing_network_bindings_are_reported_without_guessing_a_prefix(monkeypatch):
    _resolution_graph(monkeypatch, [{"uid": "bd:users", "name": "VLAN 10"}], {})
    resolved = traffic.resolve(None, traffic.AddressSelector(kind="vlan", value="10"))
    assert resolved.issues and not resolved.addresses


def test_empty_source_after_exclusions_does_not_compile_a_network(monkeypatch):
    result = traffic.query(
        None,
        source={"kind": "addresses", "addresses": ["10.0.0.0/24"], "exclude": ["10.0.0.0/8"]},
        destination={"kind": "addresses", "addresses": [DEST]},
    )
    assert result["status"] == "empty"


def test_unknown_ingress_keeps_the_entire_request_unresolved(graph):
    result = traffic.evaluate(
        _network(),
        _addresses("203.0.113.0/24"),
        _addresses(DEST),
        _services(),
        ingress_interface="if:missing",
    )
    assert result["not_established"]["count"] > 0
    assert result["allowed"]["count"] == result["denied"]["count"] == 0


def test_ipv4_question_resolves_a_dual_stack_vlan_to_its_ipv4_traffic(graph):
    src = traffic.resolve(None, traffic.AddressSelector(kind="non-rfc1918"))
    dst = _addresses(DEST, "2001:db8:10::/64", "fd00:10::/64")
    result = traffic.evaluate(_network(), src, dst, _services(), ingress_interface="if:wan")
    assert result["status"] == "complete"
    assert result["family_scope"]["evaluated"] == [4]
    assert result["family_scope"]["unpaired_destination_families"] == [6]
    assert all(":" not in address for row in result["allowed"]["items"] for address in row["destinations"])


def test_dual_stack_populations_retain_unresolved_ipv6_without_losing_ipv4(graph):
    src, dst = _addresses("192.0.2.128/25", "2001:db8:1::/64"), _addresses(DEST, "2001:db8:10::/64")
    result = traffic.evaluate(_network(), src, dst, _services())
    assert result["status"] == "partial"
    assert result["family_scope"]["evaluated"] == [4, 6]
    assert result["allowed"]["count"] and result["not_established"]["count"]
    assert any(":" in address for row in result["not_established"]["items"] for address in row["sources"])


def test_response_size_limit_preserves_counts_and_valid_json(graph, monkeypatch):
    _firewall(
        graph,
        EDGE,
        "rb:edge",
        [_rule(svc_any=False, protos=["tcp", "udp"], ports=["443", "53"])],
        default_action="drop",
    )
    result = traffic.evaluate(_network(), _addresses("192.0.2.128/25"), _addresses(DEST), _services())
    counts = {k: result[k]["count"] for k in ("allowed", "denied", "not_established", "evidence")}
    monkeypatch.setattr(traffic, "MAX_RESULT_CHARS", 2500)
    compact = traffic.bounded_result(result)
    assert len(json.dumps(compact)) <= 2500
    assert compact["coverage"]["output_truncated"]
    assert {k: compact[k]["count"] for k in counts} == counts


def test_soft_deadline_returns_the_unevaluated_space_as_unknown(graph):
    src, dst, svc = _addresses("192.0.2.128/25"), _addresses(DEST), _services()
    result = traffic.evaluate(replace(_network(), checkpoint=lambda: False), src, dst, svc)
    allowed, denied, unknown = _assert_partition(result, src, dst, svc)
    assert not allowed and not denied and unknown
    assert any("budget exhausted" in reason for reason in result["missing_evidence"])


def test_network_resolution_limit_is_not_treated_as_a_complete_prefix_list(monkeypatch):
    _resolution_graph(
        monkeypatch,
        [{"uid": "bd:large", "name": "large"}],
        {
            "bd:large": [
                {"cidr": f"10.0.{i}.0/24", "context": CTX} for i in range(traffic.MAX_SELECTORS + 1)
            ],
        },
    )
    result = traffic.resolve(None, traffic.AddressSelector(kind="vlan", value="10"))
    assert result.issues and not result.addresses


def test_same_segment_delivery_checks_the_requested_context(graph):
    src, dst = _addresses("192.0.2.128/26"), _addresses("192.0.2.192/26")
    src.context = dst.context = CTX
    assert traffic.evaluate(_network(), src, dst, _services())["status"] == "complete"
    dst.context = "vrf:other"
    assert traffic.evaluate(_network(), src, dst, _services())["status"] == "partial"


# --- site, zone and application-group selectors ----------------------------------------------


def _reads(monkeypatch, answers):
    """`path._read` answered by query text; every read is recorded with its parameters."""
    seen = []

    def read(session, query, **params):
        seen.append((query, params))
        if query not in answers:
            raise AssertionError(query)
        answer = answers[query]
        return answer(params) if callable(answer) else answer

    monkeypatch.setattr(path, "_read", read)
    return seen


_SITE_ROWS = [{"cidr": "10.1.0.0/24", "context": "vrf:a"}, {"cidr": "10.2.0.0/24", "context": "vrf:b"}]


def test_a_site_selects_the_connected_prefixes_of_its_devices(monkeypatch):
    seen = _reads(
        monkeypatch,
        {
            traffic._SITES: [{"uid": "site:dc1", "code": "DC1", "name": "Frankfurt"}],
            traffic._SITE_PREFIXES: lambda p: [r for r in _SITE_ROWS if p["context"] in (None, r["context"])],
        },
    )

    whole = traffic.resolve(None, traffic.AddressSelector(kind="site", value="DC1"))
    scoped = traffic.resolve(None, traffic.AddressSelector(kind="site", value="DC1", context="vrf:b"))

    assert not whole.issues and whole.context is None
    assert whole.addresses == tuple(_intervals(["10.1.0.0/24", "10.2.0.0/24"]))
    assert whole.candidates == [
        {"uid": "site:dc1", "code": "DC1", "name": "Frankfurt", "contexts": ["vrf:a", "vrf:b"]}
    ]
    assert seen[0][1] == {"value": "DC1", "slug": "site:dc1"}
    assert seen[1][1] == {"uid": "site:dc1", "context": None}
    assert scoped.addresses == tuple(_intervals(["10.2.0.0/24"])) and scoped.context == "vrf:b"


def test_a_site_with_no_connected_prefix_is_not_established(monkeypatch):
    _reads(monkeypatch, {traffic._SITES: [{"uid": "site:dc1", "code": "DC1"}], traffic._SITE_PREFIXES: []})

    result = traffic.query(None, source={"kind": "site", "value": "dc1"}, destination={"kind": "rfc1918"})

    assert result["status"] == "not_established"
    assert result["missing_evidence"] == ["no connected prefix is recorded for this site"]


def test_a_site_name_two_sites_share_returns_both_as_candidates(monkeypatch):
    _reads(
        monkeypatch,
        {
            traffic._SITES: [
                {"uid": "site:fra1", "code": "FRA1", "name": "Frankfurt"},
                {"uid": "site:fra2", "code": "FRA2", "name": "Frankfurt"},
            ]
        },
    )

    result = traffic.query(
        None, source={"kind": "site", "value": "Frankfurt"}, destination={"kind": "rfc1918"}
    )

    assert result["status"] == "needs_clarification"
    assert [c["uid"] for c in result["plan"]["source"]["candidates"]] == ["site:fra1", "site:fra2"]
    assert not result["coverage"]["entire_request_evaluated"]


def test_a_zone_resolves_to_the_prefixes_of_its_interfaces(monkeypatch):
    _reads(
        monkeypatch,
        {
            traffic._ZONES: [{"uid": "zone:fw1:dmz", "name": "DMZ", "devices": ["dev:fw1"]}],
            traffic._ZONE_PREFIXES: [{"cidr": "192.0.2.0/25", "context": CTX}],
        },
    )

    resolved = traffic.resolve(None, traffic.AddressSelector(kind="zone", value="dmz"))

    assert not resolved.issues and resolved.context == CTX
    assert resolved.addresses == tuple(_intervals(["192.0.2.0/25"]))


def test_a_zone_name_on_two_firewalls_returns_both_as_candidates(monkeypatch):
    zones = [
        {"uid": "zone:fw1:dmz", "name": "DMZ", "devices": ["dev:fw1"]},
        {"uid": "zone:fw2:dmz", "name": "DMZ", "devices": ["dev:fw2"]},
    ]
    prefixes = {"zone:fw1:dmz": "192.0.2.0/25", "zone:fw2:dmz": "198.51.100.0/25"}
    _reads(
        monkeypatch,
        {
            traffic._ZONES: zones,
            traffic._ZONE_PREFIXES: lambda p: [{"cidr": prefixes[p["uid"]], "context": CTX}],
        },
    )

    result = traffic.query(None, source={"kind": "zone", "value": "DMZ"}, destination={"kind": "rfc1918"})

    assert result["status"] == "needs_clarification"
    candidates = result["plan"]["source"]["candidates"]
    assert [(c["uid"], c["devices"], c["addresses"]) for c in candidates] == [
        ("zone:fw1:dmz", ["dev:fw1"], ["192.0.2.0/25"]),
        ("zone:fw2:dmz", ["dev:fw2"], ["198.51.100.0/25"]),
    ]


_SHOP = {
    "id": "shop",
    "name": "Shop",
    "groups": [
        {
            "id": "web",
            "name": "Web",
            "members": [{"id": "w1", "address": "10.1.0.10"}, {"id": "w2", "address": "10.1.0.11"}],
        },
        {
            "id": "db",
            "name": "Database",
            "members": [
                {"id": "d1", "address": "10.2.0.5", "context": "vrf:a"},
                {"id": "d2", "address": "10.2.0.6", "context": "vrf:b"},
            ],
        },
        {
            "id": "app",
            "name": "App",
            "members": [{"id": "a1", "inventory": {"kind": "ip", "uid": "ip:10.3.0.7"}}],
        },
    ],
}


def _catalog():
    reads = []

    def lookup(application_id):
        reads.append(application_id)
        return SimpleNamespace(definition=_SHOP, revision=3) if application_id == "shop" else None

    return lookup, reads


def _app_group(value, *, context=None, session=None):
    lookup, reads = _catalog()
    selector = traffic.AddressSelector(kind="app_group", value=value, context=context)
    pinned = session if session is not None else SimpleNamespace(cts=4000)
    return traffic.resolve(pinned, selector, applications=lookup), reads


def test_an_application_group_resolves_its_members_through_the_catalog():
    resolved, reads = _app_group("shop/web")

    assert reads == ["shop"]
    assert not resolved.issues and resolved.context is None
    assert resolved.addresses == tuple(_intervals(["10.1.0.10", "10.1.0.11"]))
    assert resolved.candidates == [
        {"application": "shop", "group": "web", "name": "Web", "value": "shop/web"}
    ]


def test_an_inventory_member_of_an_application_group_resolves_at_the_pinned_run(monkeypatch):
    from hst.applications import resolution

    seen = _reads(
        monkeypatch,
        {
            resolution._GRAPH_REFERENCE: [
                {
                    "uid": "ip:10.3.0.7",
                    "labels": ["Obj", "IpAddress"],
                    "bindings": [{"address": "10.3.0.7", "context": "vrf:a"}],
                    "binding_count": 1,
                    "evidence": None,
                }
            ]
        },
    )

    resolved, _ = _app_group("shop/app")

    assert seen == [(resolution._GRAPH_REFERENCE, {"uid": "ip:10.3.0.7", "snap": 4000})]
    assert not resolved.issues and resolved.context == "vrf:a"
    assert resolved.addresses == tuple(_intervals(["10.3.0.7"]))


def test_an_application_group_resolves_from_a_revision_with_a_choice_scope():
    stored = {
        **_SHOP,
        "connections": [
            {
                "id": "web-to-db",
                "name": "Web to database",
                "source": "web",
                "destination": "db",
                "protocol": "tcp",
                "destination_ports": [5432],
                "destination_condition": {"kind": "member", "member": "d1"},
                "choice_scope": "unspecified",
            }
        ],
    }
    selector = traffic.AddressSelector(kind="app_group", value="shop/web")

    resolved = traffic.resolve(
        SimpleNamespace(cts=4000),
        selector,
        applications=lambda _id: SimpleNamespace(definition=stored, revision=3),
    )

    assert not resolved.issues
    assert resolved.addresses == tuple(_intervals(["10.1.0.10", "10.1.0.11"]))


def test_an_application_id_alone_offers_its_groups_as_candidates():
    resolved, _ = _app_group("shop")

    assert resolved.ambiguous and resolved.issues
    assert [c["value"] for c in resolved.candidates] == ["shop/web", "shop/db", "shop/app"]
    assert not resolved.addresses


def test_an_application_group_across_two_contexts_needs_a_context():
    ambiguous, _ = _app_group("shop/db")
    chosen, _ = _app_group("shop/db", context="vrf:b")

    assert ambiguous.ambiguous
    assert [(c["context"], c["addresses"]) for c in ambiguous.candidates] == [
        ("vrf:a", ["10.2.0.5"]),
        ("vrf:b", ["10.2.0.6"]),
    ]
    assert not chosen.issues and chosen.context == "vrf:b"
    assert chosen.addresses == tuple(_intervals(["10.2.0.6"]))


@pytest.mark.parametrize(
    ("value", "issue"),
    [
        ("nope/web", "no Business Application nope is in the catalog"),
        ("shop/cache", "application shop declares no group cache"),
    ],
)
def test_an_application_group_the_catalog_does_not_hold_is_not_established(value, issue):
    resolved, _ = _app_group(value)

    assert resolved.issues == [issue] and not resolved.ambiguous and not resolved.addresses


def test_an_application_group_needs_a_pinned_run():
    resolved, _ = _app_group("shop/web", session=SimpleNamespace())

    assert resolved.issues and "no run is published" in resolved.issues[0]


def test_an_application_group_selector_without_the_catalog_is_refused():
    with pytest.raises(ValueError, match="Business Application catalog"):
        traffic.resolve(
            SimpleNamespace(cts=4000), traffic.AddressSelector(kind="app_group", value="shop/web")
        )
    with pytest.raises(ValueError, match="application id"):
        _app_group("Shop Web")


@pytest.mark.parametrize(
    "selector",
    [
        {"kind": "site", "value": "DC1"},
        {"kind": "zone", "value": "dmz", "context": "vrf:edge"},
        {"kind": "app_group", "value": "shop/web"},
    ],
)
def test_reach_trace_groups_accepts_site_zone_and_application_group_selectors(monkeypatch, selector):
    session = _FakeGraphSession(lambda q: [], current=4000)
    monkeypatch.setattr(dbmod, "session", _db_seam(session))
    calls = []

    def query(pinned, **kwargs):
        calls.append(kwargs)
        return {"status": "partial"}

    monkeypatch.setattr(traffic, "query", query)
    tool = _groups_tool(Settings(_env_file=None))

    outcome = tools.dispatch(
        [tool], "reach_trace", {"mode": "groups", "source": selector, "destination": {"kind": "rfc1918"}}
    )

    assert outcome.is_error is False, outcome.result
    assert {key: calls[0]["source"][key] for key in selector} == selector
    assert callable(calls[0]["applications"])


# --- bucket paging past RESULT_CAP ---------------------------------------------------------


def test_a_bucket_pages_past_the_result_cap_through_the_offset(graph, monkeypatch):
    _firewall(
        graph,
        EDGE,
        "rb:edge",
        [_rule(svc_any=False, protos=["tcp", "udp"], ports=["443", "53"])],
        default_action="drop",
    )
    src, dst = _addresses("192.0.2.128/25"), _addresses(DEST)
    whole = traffic.evaluate(_network(), src, dst, _services())
    count = whole["allowed"]["count"]
    monkeypatch.setattr(traffic, "RESULT_CAP", 1)

    pages = [traffic.evaluate(_network(), src, dst, _services(), offset=offset) for offset in range(count)]

    assert count > 1
    assert [page["allowed"]["items"] for page in pages] == [[item] for item in whole["allowed"]["items"]]
    assert [page["allowed"]["truncated"] for page in pages] == [True] * (count - 1) + [False]
    assert all(page["allowed"]["count"] == count for page in pages)


def test_an_offset_pages_through_both_address_families_in_order(graph, monkeypatch):
    # sources with no recorded attachment leave both families not established
    src, dst = _addresses("203.0.113.0/24", "2001:db8:1::/64"), _addresses(DEST, "2001:db8:10::/64")
    whole = traffic.evaluate(_network(), src, dst, _services())
    count = whole["not_established"]["count"]
    monkeypatch.setattr(traffic, "RESULT_CAP", 1)

    pages = [
        traffic.evaluate(_network(), src, dst, _services(), offset=offset) for offset in range(count + 1)
    ]

    assert whole["family_scope"]["evaluated"] == [4, 6] and count > 1
    assert [item for page in pages for item in page["not_established"]["items"]] == whole["not_established"][
        "items"
    ]
    assert pages[-1]["not_established"]["items"] == [] and not pages[-1]["not_established"]["truncated"]


def test_the_network_prefix_read_takes_the_in_edge_and_the_within_edge():
    """A prefix is IN its bridge domain in schema v0.31.0 and up, and WITHIN it
    in snapshots below v0.31.0."""
    assert (
        "(p:Prefix)-[w:IN|WITHIN]->(bd:BridgeDomain:Obj {uid: $uid, collection_ts: $snap})"
        in traffic._NETWORK_PREFIXES
    )
