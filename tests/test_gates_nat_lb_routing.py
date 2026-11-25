"""Gate cases over NAT, routing and load balancer rows: interface binding of VyOS NAT rules,
a translation pool, the load balancer source, and two routing readings.

The NAT rows are built by the VyOS collector (`normalize_vyos`) and read the
way `_NAT_RULES_QUERY` returns them, so the gate sees what a loaded snapshot
gives it.
"""

import pytest
from tests.test_vyos_match_clauses import _batch, _forward, _nat_rows, _rows, _snat

from hst.path.addrsets import _intervals, _ports, _protoset, _to_cidrs
from hst.path.gates import _Trail
from hst.path.gates import lb as lb_gate
from hst.path.gates import nat as nat_gate
from hst.path.gates.nat import NatTransition, _apply_snat, _nat_partition, _nat_stage_rules
from hst.path.gates.pbr import partition_rules
from hst.path.gates.routing import _host_prefixes, _next_hop_adjacent, _route_partition
from hst.path.state import FlowRegion


def _vyos_nat(source: dict | None = None, static: dict | None = None, destination: dict | None = None):
    nat: dict = {}
    if source:
        nat["source"] = {"rule": source}
    if static:
        nat["static"] = {"rule": static}
    if destination:
        nat["destination"] = {"rule": destination}
    return _batch(
        _forward({}),
        interfaces={
            "ethernet": {"eth0": {"address": ["203.0.113.2/30"]}, "eth1": {"address": ["10.9.0.1/24"]}},
        },
        nat=nat,
    )


# --- nat.py: the keyword `any` binds no interface ----------------------------------------


@pytest.mark.parametrize("bound", ["any", {"name": "any"}])
def test_a_source_rule_bound_to_any_translates_on_every_egress(bound):
    batch = _vyos_nat(
        {
            "100": {
                "outbound-interface": bound,
                "source": {"address": "10.1.0.0/24"},
                "translation": {"address": "masquerade"},
            }
        }
    )
    assert _snat(batch, "eth0", "10.1.0.5") == [(100, False)]
    assert _snat(batch, "eth1", "10.1.0.5") == [(100, False)]


def test_a_destination_rule_bound_to_any_translates_on_every_ingress():
    batch = _vyos_nat(
        destination={
            "10": {
                "inbound-interface": "any",
                "protocol": "tcp",
                "destination": {"port": "443"},
                "translation": {"address": "10.9.0.10"},
            }
        }
    )
    rules = _nat_stage_rules(_nat_rows(batch), "dnat", "eth0")
    [part] = [
        p
        for p in _nat_partition(rules, _intervals(["8.8.8.8"]), _intervals(["203.0.113.2"]), 443, "tcp")
        if p["rule"]
    ]
    assert _to_cidrs(part["new_dst"]) == ["10.9.0.10/32"]


# --- nat.py: a VyOS static rule translates the source on its own interface only ------------


def _static_batch():
    return _vyos_nat(
        static={
            "1": {
                "inbound-interface": {"name": "eth0"},
                "destination": {"address": "203.0.113.10"},
                "translation": {"address": "10.9.0.10"},
            }
        }
    )


def test_a_static_rule_translates_the_source_only_when_leaving_by_its_interface():
    rows = _nat_rows(_static_batch())
    on_wan = _nat_stage_rules(rows, "snat", "eth0")
    [part] = _nat_partition(on_wan, _intervals(["10.9.0.10"]), _intervals(["8.8.8.8"]), 443, "tcp")
    assert part["rule"] and _to_cidrs(part["new_src"]) == ["203.0.113.10/32"]
    # a flow from the real host to another LAN leaves by eth1: no translation
    assert _nat_stage_rules(rows, "snat", "eth1") == []
    # the inbound direction is unchanged
    assert len(_nat_stage_rules(rows, "dnat", "eth0")) == 1
    assert _nat_stage_rules(rows, "dnat", "eth1") == []


# --- nat.py: a bound sNAT rule on a leg whose egress is not resolved ----------------------


def _wan_rows():
    return _nat_rows(
        _vyos_nat(
            {
                "5": {
                    "outbound-interface": {"name": "eth0"},
                    "source": {"address": "10.1.0.0/24"},
                    "translation": {"address": "masquerade"},
                },
                "10": {
                    "outbound-interface": {"name": "eth0"},
                    "source": {"address": "10.2.0.0/24"},
                    "translation": {"address": "203.0.113.7"},
                },
                "20": {"source": {"address": "10.3.0.0/24"}, "translation": {"address": "198.51.100.9"}},
            }
        )
    )


def _snat_leg(rows, egress_uid, egress_name, src):
    leg: dict = {"indeterminate": False}
    trail = _Trail()
    out = _apply_snat(
        None,
        trail,
        leg,
        rows,
        egress_uid,
        egress_name,
        _intervals([src]),
        _intervals(["8.8.8.8"]),
        443,
        "tcp",
        "x",
    )
    return leg, trail, out


def test_a_bound_fixed_address_rule_on_an_unresolved_egress_is_undecided():
    leg, trail, out = _snat_leg(_wan_rows(), None, None, "10.2.0.5")
    assert leg["indeterminate"] is True
    assert "snat" not in leg
    # the flow leaves untranslated or translated: both stay possible downstream
    assert _to_cidrs(out) == ["10.2.0.5/32", "203.0.113.7/32"]
    assert any("bound to egress interface eth0" in w for w in trail.warnings)


def test_a_bound_masquerade_on_an_unresolved_egress_names_the_binding():
    leg, trail, out = _snat_leg(_wan_rows(), None, None, "10.1.0.5")
    assert leg["indeterminate"] is True
    assert _to_cidrs(out) == ["0.0.0.0/0"]
    assert any("egress interface of this leg is not resolved" in w for w in trail.warnings)


def test_an_unbound_rule_on_an_unresolved_egress_stays_decided():
    leg, _trail, out = _snat_leg(_wan_rows(), None, None, "10.3.0.5")
    assert not leg["indeterminate"]
    assert _to_cidrs(out) == ["198.51.100.9/32"]


def test_the_wan_masquerade_on_a_resolved_egress_stays_decided(monkeypatch):
    monkeypatch.setattr(nat_gate._path, "_read_one", lambda *_a, **_k: {"ip": "203.0.113.2"})
    leg, _trail, out = _snat_leg(_wan_rows(), "if:eth0", "eth0", "10.1.0.5")
    assert not leg["indeterminate"]
    assert _to_cidrs(out) == ["203.0.113.2/32"]
    assert leg["snat"][0]["to"] == "203.0.113.2"
    # and a flow leaving by the LAN interface is not translated by it
    leg_lan, _trail, out_lan = _snat_leg(_wan_rows(), "if:eth1", "eth1", "10.1.0.5")
    assert not leg_lan["indeterminate"] and _to_cidrs(out_lan) == ["10.1.0.5/32"]


def test_a_caller_with_no_interface_and_no_flag_keeps_bound_rules_decided():
    """The analysis model and the assessment pass no interface and decide the
    binding themselves; the rules they get are not made undecided."""
    rules = _nat_stage_rules(_wan_rows(), "snat", None)
    assert [r["pos"] for r in rules] == [5, 10, 20]
    assert not any(r["opaque"] for r in rules)
    assert not any("binding_unresolved" in r for r in rules)


# --- nat.py: a translation range is a pool, not a one-to-one map --------------------------


def test_a_source_range_of_the_same_size_leaves_as_any_address_of_the_range():
    batch = _vyos_nat(
        {
            "20": {
                "outbound-interface": {"name": "eth0"},
                "source": {"address": "10.0.0.0/30"},
                "translation": {"address": "203.0.113.1-203.0.113.4"},
            }
        }
    )
    rules = _nat_stage_rules(_nat_rows(batch), "snat", "eth0")
    [part] = _nat_partition(rules, _intervals(["10.0.0.2"]), _intervals(["1.1.1.1"]), 443, "tcp")
    assert _to_cidrs(part["new_src"]) == ["203.0.113.1/32", "203.0.113.2/31", "203.0.113.4/32"]
    # the strict engine continues the flow from the whole source pool
    [(region, effect)] = NatTransition(rules, complete_service=True).apply(
        FlowRegion.from_query(
            _intervals(["10.0.0.2"]), _intervals(["1.1.1.1"]), _protoset(["tcp"]), _ports(443)
        )
    )
    assert effect.kind == "rewrite"
    [rect] = region
    assert _to_cidrs(list(rect.src)) == ["203.0.113.1/32", "203.0.113.2/31", "203.0.113.4/32"]


def test_a_prefix_translation_and_a_static_rule_keep_the_offset_mapping():
    batch = _vyos_nat(
        {
            "30": {
                "outbound-interface": {"name": "eth0"},
                "source": {"address": "10.0.0.0/30"},
                "translation": {"address": "203.0.113.0/30"},
            }
        },
        static={
            "1": {
                "inbound-interface": {"name": "eth0"},
                "destination": {"address": "203.0.113.8/30"},
                "translation": {"address": "10.9.0.8/30"},
            }
        },
    )
    rules = _nat_stage_rules(_nat_rows(batch), "snat", "eth0")
    parts = _nat_partition(rules, _intervals(["10.0.0.2", "10.9.0.10"]), _intervals(["1.1.1.1"]), 443, "tcp")
    mapped = {_to_cidrs(p["sources"])[0]: _to_cidrs(p["new_src"]) for p in parts if p["rule"]}
    assert mapped == {"10.0.0.2/32": ["203.0.113.2/32"], "10.9.0.10/32": ["203.0.113.10/32"]}


# --- lb.py: two or more SNIP or SNAT_FROM candidates ------------------------------------


_CLIENT = _intervals(["10.0.0.5"])


def _vs(mode: str) -> dict:
    return {"uid": "ns:lb:vs", "name": "vs", "snat_mode": mode}


def test_two_snip_candidates_give_both_addresses_undecided(monkeypatch):
    rows = [
        {"ip": "10.0.10.1", "if_uid": "if:a", "if_name": "a", "cidr": "10.0.10.0/24"},
        {"ip": "10.0.10.2", "if_uid": "if:b", "if_name": "b", "cidr": "10.0.10.0/24"},
    ]
    monkeypatch.setattr(lb_gate._path, "_read", lambda *_a, **_k: rows)
    src, note, indeterminate = lb_gate._lb_snat(None, _vs("snip"), "dev:lb", "10.0.10.5", _CLIENT)
    assert indeterminate is True
    assert _to_cidrs(src) == ["10.0.10.1/32", "10.0.10.2/32"]
    assert "10.0.10.1, 10.0.10.2" in note and "not determined" in note


def test_one_snip_candidate_listed_twice_stays_decided(monkeypatch):
    row = {"ip": "10.0.10.1", "if_uid": "if:a", "if_name": "a", "cidr": "10.0.10.0/24"}
    monkeypatch.setattr(lb_gate._path, "_read", lambda *_a, **_k: [row, dict(row, cidr="10.0.10.0/25")])
    src, _note, indeterminate = lb_gate._lb_snat(None, _vs("snip"), "dev:lb", "10.0.10.5", _CLIENT)
    assert indeterminate is False and _to_cidrs(src) == ["10.0.10.1/32"]


def test_two_snat_from_addresses_give_both_undecided_and_are_read_once(monkeypatch):
    calls: list[str] = []

    def read(_session, query, **_params):
        calls.append(query)
        return [{"ip": "192.0.2.1"}, {"ip": "192.0.2.2"}]

    monkeypatch.setattr(lb_gate._path, "_read", read)
    memo: dict = {}
    for _member in range(2):
        src, note, indeterminate = lb_gate._lb_snat(
            None, _vs("snat_from"), "dev:lb", "10.0.10.5", _CLIENT, memo=memo
        )
        assert indeterminate is True
        assert _to_cidrs(src) == ["192.0.2.1/32", "192.0.2.2/32"]
        assert "SNAT_FROM" in note
    assert len(calls) == 1


def test_one_snat_from_address_stays_decided(monkeypatch):
    monkeypatch.setattr(lb_gate._path, "_read", lambda *_a, **_k: [{"ip": "192.0.2.1"}])
    src, note, indeterminate = lb_gate._lb_snat(None, _vs("snat_from"), "dev:lb", "10.0.10.5", _CLIENT)
    assert indeterminate is False and _to_cidrs(src) == ["192.0.2.1/32"]
    assert note == "SNAT to 192.0.2.1 (SNAT_FROM)"


# --- routing.py -------------------------------------------------------------------------------


def _route(cidr, kind, nh=None, ifname=None, egress=None, discard=None):
    return {
        "uid": f"p{cidr}",
        "cidr": cidr,
        "kind": kind,
        "next_hop": nh,
        "ifname": ifname,
        "egress_uid": egress and f"if:{egress}",
        "egress_name": egress,
        "derived": None,
        "via_rt": None,
        "rib": None,
        "next_hop_vrf": None,
        "discard": discard,
    }


def test_a_discard_host_route_is_not_evidence_of_adjacency():
    rows = [_route("10.9.9.9/32", "STATIC_ROUTE", discard="blackhole")]
    assert _host_prefixes(rows) == []
    assert _next_hop_adjacent("10.9.9.9", ["192.0.2.0/30", *_host_prefixes(rows)]) is False
    assert _host_prefixes([_route("10.9.9.8/32", "STATIC_ROUTE", ifname="wg0", egress="wg0")]) == [
        "10.9.9.8/32"
    ]


def test_an_interface_route_with_no_via_edge_and_its_rib_row_are_one_route():
    rows = [_route("0.0.0.0/0", "LEARNED_ROUTE", ifname="pppoe0")]
    store = [{"prefix": "0.0.0.0/0", "next_hop": None, "interface": "pppoe0", "protocol": "static"}]
    lookup = (lambda _probe: store, lambda *_a: [])
    [(_dst, winners)] = _route_partition(rows, _intervals(["8.8.8.8"]), lookup, [], observed=True)
    assert len(winners) == 1
    assert winners[0]["kind"] == "LEARNED_ROUTE" and winners[0]["rib"] is True


# --- pbr.py: an empty address group is not "any address" ---------------------------------


def test_a_policy_route_on_an_empty_address_group_claims_undecided():
    batch = _batch(
        {"group": {"address-group": {"VPN-CLIENTS": {}}}},
        interfaces={"ethernet": {"eth0": {"address": ["10.0.0.1/24"]}}},
        policy={
            "route": {
                "VPN": {
                    "interface": "eth0",
                    "rule": {
                        "10": {"source": {"group": {"address-group": "VPN-CLIENTS"}}, "set": {"table": "100"}}
                    },
                }
            }
        },
        protocols={"static": {"table": {"100": {"route": {"0.0.0.0/0": {"next-hop": {"10.0.0.254": {}}}}}}}},
    )
    groups = partition_rules(
        _rows(batch, "vyos:gw:pbr:VPN"), _intervals(["10.0.0.5"]), _intervals(["198.51.100.9"]), None
    )
    claimed = [g for g in groups if g["rule_uid"]]
    assert claimed and all(g["opaque"] for g in claimed)


# --- policy/nat.py: the analysis model reads the binding and a pool as the tracer does -----


def _model(batch, egress: str | None, ingress: str | None = None):
    from tests.test_firewall_rule_scope import _inventory

    from hst.core import uid
    from hst.policy.nat import normalize_nat_rules

    return normalize_nat_rules(
        _inventory(batch),
        "dev:gw",
        ingress_interface_uid=uid.interface("dev:gw", ingress) if ingress else None,
        egress_interface_uid=uid.interface("dev:gw", egress) if egress else None,
        address_family=4,
    )


def test_the_model_reads_an_any_binding_as_every_interface():
    from hst.policy.ir import Constant

    batch = _vyos_nat(
        {
            "100": {
                "outbound-interface": "any",
                "source": {"address": "10.1.0.0/24"},
                "translation": {"address": "198.51.100.7"},
            }
        }
    )
    for egress in ("eth0", "eth1"):
        [spec] = [s for s in _model(batch, egress) if s.stage == "snat"]
        assert spec.predicate != Constant(False) and spec.gap_code is None
        assert spec.rewrites == (("source_address", 0xC6336407),)


def test_the_model_binds_a_static_rule_source_translation_to_its_interface():
    from hst.policy.ir import Constant

    batch = _static_batch()
    [on_wan] = [s for s in _model(batch, "eth0") if s.stage == "snat"]
    assert on_wan.predicate != Constant(False)
    assert on_wan.rewrites == (("source_address", 0xCB00710A),)
    [on_lan] = [s for s in _model(batch, "eth1") if s.stage == "snat"]
    assert on_lan.predicate == Constant(False)


def test_the_model_reads_a_same_size_range_as_a_pool_and_a_prefix_by_offset():
    batch = _vyos_nat(
        {
            "20": {
                "outbound-interface": {"name": "eth0"},
                "source": {"address": "10.0.0.0/30"},
                "translation": {"address": "203.0.113.1-203.0.113.4"},
            },
            "30": {
                "outbound-interface": {"name": "eth0"},
                "source": {"address": "10.0.1.0/30"},
                "translation": {"address": "203.0.113.8/30"},
            },
        }
    )
    specs = {s.position: s for s in _model(batch, "eth0") if s.stage == "snat"}
    assert specs[20].gap_code == "NAT_POOL_ALLOCATION_UNKNOWN" and not specs[20].ranges
    assert specs[30].gap_code is None and len(specs[30].ranges) == 1


# --- the realization comparison sees one range the same in both of its forms ---------------


def _range_rule(translation: str = "203.0.113.1-203.0.113.4") -> dict:
    batch = _vyos_nat(
        {
            "20": {
                "outbound-interface": {"name": "eth0"},
                "source": {"address": "10.0.0.0/30"},
                "translation": {"address": translation},
            }
        }
    )
    [row] = _nat_rows(batch)
    return row


def _restated(row: dict, xlate: str) -> dict:
    """The row as `nat_rule.modify` restating `xlate_src` leaves it: the raw
    translation cleared and the range in the resolved column."""
    return dict(
        row, uid="nat:rule:proposed:1", translation=None, xlate_src_addrs=[xlate], xlate_src_present=True
    )


def test_a_proposed_range_and_the_collected_range_compare_equal():
    from hst.assessment.service import _nat_semantics

    collected = _range_rule()
    proposed = _restated(collected, "203.0.113.1-203.0.113.4")
    assert _nat_semantics([proposed]) == _nat_semantics([collected])
    # both forms are read as a pool by the tracer
    for row in (collected, proposed):
        [rule] = _nat_stage_rules([row], "snat", "eth0")
        assert rule.get("xlate_pool") is True


def test_a_proposed_prefix_differs_from_a_collected_range():
    from hst.assessment.service import _nat_semantics

    collected = _range_rule()
    assert _nat_semantics([_restated(collected, "203.0.113.0/30")]) != _nat_semantics([collected])
