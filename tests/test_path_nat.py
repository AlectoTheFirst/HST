"""NAT as forwarding semantics: the trace rewrites the flow tuple."""

# ruff: noqa: F811

import pytest
from tests.test_path_trace import (  # noqa: F401
    GW,
    FakeGraph,
    _FakeRib,
    _route,
    _rule,
    _src_row,
    graph,
    record_reads,
)

from hst import path
from hst.path.addrsets import _PORT_FAMILY, _ports, _protoset
from hst.path.gates.nat import _nat_partition


def _nat_row(**kw):
    """One row in the shape path._NAT_RULES_QUERY returns."""
    base = {
        "rb_uid": "rb:nat",
        "rb_name": "nat-source",
        "approximate": False,
        # Check Point's Automatic NAT marker, and the ORIG_SRC/ORIG_DST object state
        "auto_generated": None,
        "orig_src_present": False,
        "orig_dst_present": False,
        "uid": "nat:r10",
        "pos": 10,
        "kind": "snat",
        "method": None,
        "enabled": True,
        "exclude": False,
        "translation": None,
        "translation_port": None,
        "orig_src_raw": None,
        "orig_dst_raw": None,
        "orig_src_port": None,
        "orig_dst_port": None,
        "orig_port": None,
        "xlate_port": None,
        "protocol": None,
        "in_if": None,
        "out_if": None,
        "translation_interface": None,
        "xlate_src_original": False,
        "xlate_dst_original": False,
        "rule_approximate": False,
        "direction": None,
        "static_flag": False,
        "orig_src_addrs": [],
        "orig_dst_addrs": [],
        "xlate_src_addrs": [],
        "xlate_dst_addrs": [],
    }
    base.update(kw)
    return base


# --- source NAT at egress ----------------------------------------------------------------


def test_masquerade_records_the_translation_on_the_leg(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_nat_row(translation="masquerade", out_if="eth0")]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["snat"] == [{"sources": ["10.0.0.5/32"], "to": "address of eth0", "rule_uid": "nat:r10"}]
    # The egress interface carries no collected address.
    assert leg["indeterminate"]
    assert any("whose address was not collected" in w for w in result["warnings"])
    snat_hops = [h for h in result["hops"] if h["kind"] == "NatRule"]
    assert [h["note"] for h in snat_hops] == ["→ address of eth0"]


def test_masquerade_with_a_collected_egress_address_is_decided(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.iface_addrs = {"if:eth0": "203.0.113.7"}
    graph.nat = [_nat_row(translation="masquerade", out_if="eth0")]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["snat"] == [{"sources": ["10.0.0.5/32"], "to": "203.0.113.7", "rule_uid": "nat:r10"}]
    assert not leg["indeterminate"]


def test_snat_bound_to_another_interface_does_not_apply(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_nat_row(translation="masquerade", out_if="pppoe9")]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    assert "snat" not in result["legs"][0]


def test_snat_partitions_the_source_range_and_names_each_part(graph):
    """One rule claims part of the source /24; the rest leaves untranslated."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [
        _nat_row(orig_src_raw="10.0.0.0/25", translation="203.0.113.7", xlate_src_addrs=["203.0.113.7"])
    ]
    result = path.trace(None, "10.0.0.0/24", "8.8.8.8", gateways=[GW])
    leg = result["legs"][0]
    assert leg["snat"] == [{"sources": ["10.0.0.0/25"], "to": "203.0.113.7", "rule_uid": "nat:r10"}]


def test_static_nat_translates_the_source_outbound(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [
        _nat_row(
            kind="static",
            orig_src_raw="10.0.0.5",
            orig_src_addrs=["10.0.0.5"],
            translation="203.0.113.5",
            xlate_src_addrs=["203.0.113.5"],
        )
    ]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    assert result["legs"][0]["snat"][0]["to"] == "203.0.113.5"


# --- destination NAT before routing ------------------------------------------------------


def _dnat_row(**kw):
    base = _nat_row(
        rb_uid="rb:dnat",
        rb_name="nat-destination",
        uid="dnat:r10",
        kind="dnat",
        orig_dst_raw="203.0.113.10",
        orig_dst_addrs=["203.0.113.10"],
        translation="10.0.0.99",
        xlate_dst_addrs=["10.0.0.99"],
    )
    base.update(kw)
    return base


def test_dnat_routes_on_the_translated_destination(graph):
    graph.sources = [_src_row()]
    # only the inside prefix is routable; the public address has no route
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_dnat_row(translation_port="8443")]
    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["cidr"] == "10.0.0.0/24"
    assert leg["dnat"] == [{"to": ["10.0.0.99/32"], "port": 8443, "rule_uid": "dnat:r10"}]
    dnat_hops = [h for h in result["hops"] if h["kind"] == "NatRule"]
    assert [h["note"] for h in dnat_hops] == ["→ 10.0.0.99:8443"]
    assert "no route found" not in result["verdict"]


def test_dnat_bound_to_another_ingress_does_not_apply(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": []}
    graph.nat = [_dnat_row(in_if="eth9")]  # GW ingress is eth1
    result = path.trace(None, "10.0.0.5", "203.0.113.10", gateways=[GW])
    assert result["legs"][0]["verdict"] == "no route found"


def test_dnat_claims_part_of_the_destination_set_and_the_rest_falls_through(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2"), _route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_dnat_row()]
    result = path.trace(None, "10.0.0.5", "203.0.113.10/31", gateways=[GW])

    by_cidr = {leg["cidr"]: leg for leg in result["legs"]}
    assert set(by_cidr) == {"10.0.0.0/24", "0.0.0.0/0"}
    assert "dnat" in by_cidr["10.0.0.0/24"]
    assert "dnat" not in by_cidr["0.0.0.0/0"]


def test_pbr_reads_its_rules_once_for_all_destination_nat_parts(graph):
    """The two destination NAT parts are partitioned by the same PBR rules on
    the same ingress interface, so the rules and the default table are read
    for the first part only."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2"), _route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_dnat_row()]
    reads = record_reads(graph)

    result = path.trace(None, "10.0.0.5", "203.0.113.10/31", gateways=[GW])

    assert len(result["legs"]) == 2
    assert [p for q, p in reads if "(pol:PbrPolicy)" in q and "if_uid" in p] == [{"if_uid": GW["if_uid"]}]
    assert [p for q, p in reads if "IN_VRF]-(i:Interface {uid: $if_uid})" in q] == [{"if_uid": GW["if_uid"]}]


def test_static_nat_translates_the_destination_inbound(graph):
    """Hairpin/inbound direction of a one-to-one rule: traffic to the public
    address routes to the real host behind it."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [
        _nat_row(
            rb_uid="rb:static",
            rb_name="nat-static",
            uid="static:r1",
            kind="static",
            orig_src_raw="10.0.0.99",
            orig_src_addrs=["10.0.0.99"],
            translation="203.0.113.5",
            xlate_src_addrs=["203.0.113.5"],
        )
    ]
    result = path.trace(None, "10.0.0.5", "203.0.113.5", gateways=[GW])
    leg = result["legs"][0]
    assert leg["cidr"] == "10.0.0.0/24"
    assert leg["dnat"][0]["to"] == ["10.0.0.99/32"]


def test_an_exclude_rule_claims_without_translating(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_dnat_row(exclude=True), _dnat_row(uid="dnat:r20", pos=20)]
    result = path.trace(None, "10.0.0.5", "203.0.113.10", gateways=[GW])
    # rule 10 excludes the flow, so rule 20 does not translate it
    leg = result["legs"][0]
    assert "dnat" not in leg
    assert leg["cidr"] == "0.0.0.0/0"


# --- the destination-duplicate notes after a translation ---------------------------------


def _dnat_delivery(graph):
    """A port-forward that ends on the inside host, with the public address
    and the inside host both attached in the gateway's own context."""
    graph.sources = [_src_row()]
    graph.sources_by_ip = {
        "10.0.0.5": [_src_row()],
        "10.0.0.99": [_src_row(ip="10.0.0.99") | {"ep_uid": "ep:web", "ep_name": "web-1"}],
        "203.0.113.10": [_src_row(ip="203.0.113.10")],
    }
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.nat = [_dnat_row()]


def test_after_a_dnat_the_duplicate_notes_key_on_the_address_the_flow_was_sent_to(graph):
    """The reported instances are instances of the queried address."""
    _dnat_delivery(graph)
    graph.dst_instances = {
        "203.0.113.10": [
            {"uid": "ip:home:203.0.113.10", "anchor": None, "l3dom": "home"},
            {"uid": "ip:lab:203.0.113.10", "anchor": None, "l3dom": "lab"},
        ]
    }

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])

    dupes = [n for n in result["notes"] if "also exists" in n]
    # the instance this lane landed on is not reported as another one
    assert not any("also exists in home" in n for n in dupes)
    # a different instance is reported
    assert any("also exists in lab" in n for n in dupes)


def test_a_dnat_lane_reports_every_other_instance_of_the_queried_address(graph):
    """The gateway's own context holds no instance of the public address."""
    _dnat_delivery(graph)
    graph.sources_by_ip["203.0.113.10"] = []
    graph.dst_instances = {
        "203.0.113.10": [
            {"uid": "ip:lab:203.0.113.10", "anchor": None, "l3dom": "lab"},
            {"uid": "ip:dmz:203.0.113.10", "anchor": None, "l3dom": "dmz"},
        ]
    }

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])

    dupes = [n for n in result["notes"] if "also exists" in n]
    assert len(dupes) == 2


def _two_instances_of_the_destination(graph):
    """The destination address exists twice in the gateway's own context."""
    graph.sources = [_src_row()]
    graph.sources_by_ip = {
        "10.0.0.5": [_src_row()],
        "203.0.113.10": [
            _src_row(ip="203.0.113.10"),
            _src_row(ip="203.0.113.10")
            | {
                "ip_uid": "ip:dmz:203.0.113.10",
                "anchor": "seg:dmz",
                "seg_uid": "seg:dmz",
                "ep_uid": "ep:web",
            },
        ],
    }
    graph.iface_segments = {"if:eth2": ["seg:dmz"]}
    graph.routes = {"vrf:main": [_route("203.0.113.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.dst_instances = {
        "203.0.113.10": [
            {"uid": "ip:home:203.0.113.10", "anchor": None, "l3dom": "home"},
            {"uid": "ip:dmz:203.0.113.10", "anchor": None, "l3dom": "dmz"},
        ]
    }


def test_an_exclude_rule_leaves_the_destination_pin_where_the_lane_landed(graph):
    """An exclude rule claims the flow and translates nothing."""
    _two_instances_of_the_destination(graph)
    graph.nat = [_dnat_row(xlate_dst_original=True)]

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])

    dupes = [n for n in result["notes"] if "also exists" in n]
    assert not any("also exists in dmz" in n for n in dupes)
    assert any("also exists in home" in n for n in dupes)


def test_an_ingress_source_rewrite_leaves_the_destination_pin_alone(graph):
    """`ip nat outside source` rewrites the source at ingress."""
    _two_instances_of_the_destination(graph)
    graph.iface_roles = {"if:eth1": "outside"}
    graph.nat = [
        _nat_row(
            kind="dnat",
            direction="outside-source",
            orig_src_addrs=["10.0.0.5"],
            xlate_src_addrs=["10.0.0.77"],
        )
    ]

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])

    assert [h["kind"] for h in result["hops"] if h["kind"] == "NatRule"] == ["NatRule"]
    dupes = [n for n in result["notes"] if "also exists" in n]
    assert not any("also exists in dmz" in n for n in dupes)
    assert any("also exists in home" in n for n in dupes)


# --- where the filter sits relative to destination NAT -----------------------------------
#
# The netfilter forwarding path translates the destination before the filter
# sees it; a Check Point gateway matches its access policy on the original
# packet. The engine derives which one applies from the vendor the device's
# access rulebase was collected with, and says so when that vendor is missing.


def _cp_rb(**kw):
    base = {
        "rb_uid": "rb:cp",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": None,
        "approximate": False,
    }
    base.update(kw)
    return base


def test_a_checkpoint_policy_is_evaluated_on_the_original_destination(graph):
    """The port-forward rule is written on the public address."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_dnat_row()]
    graph.rb = _cp_rb()
    graph.rules = [_rule(uid="cp:10", pos=10, action="accept", dst_any=False, dst_ips=["203.0.113.10"])]

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["filter_view"] == "original"
    assert not leg["blocked"]
    assert "accept by rule 10" in leg["firewall"]


def test_a_netfilter_policy_is_evaluated_on_the_translated_destination(graph):
    """The other side of the same registry: a VyOS chain sees the packet after
    PREROUTING, so a rule written on the public address does not govern it and
    the chain default decides."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_dnat_row()]
    graph.rb = _cp_rb(rb_uid="rb:vyos", rb_name="ipv4-forward", vendor="vyos", default_action="drop")
    graph.rules = [_rule(uid="fw:10", pos=10, action="accept", dst_any=False, dst_ips=["203.0.113.10"])]

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["filter_view"] == "translated"
    assert leg["blocked"]
    assert "drop by default-action" in leg["firewall"]


def test_an_access_rulebase_with_no_vendor_leaves_the_pipeline_order_undecided(graph):
    """The engine evaluates the translated destination."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_dnat_row()]
    graph.rb = _cp_rb(vendor=None, default_action="accept")
    graph.rules = []

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["indeterminate"]
    assert "filter_view" not in leg
    assert any("carries no vendor" in w for w in result["warnings"])
    assert "accept by default-action" in leg["firewall"]


def test_a_checkpoint_policy_view_split_across_routes_is_undecided(graph):
    """The translated destinations of a one-to-one range translation route separately."""
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [_route("10.0.0.99/32", egress="eth2"), _route("10.0.0.100/32", egress="eth3")]
    }
    graph.nat = [
        _dnat_row(
            orig_dst_raw="203.0.113.10-203.0.113.11",
            orig_dst_addrs=[],
            translation="10.0.0.99-10.0.0.100",
            xlate_dst_addrs=[],
        )
    ]
    graph.rb = _cp_rb()
    graph.rules = [_rule(uid="cp:10", pos=10, action="accept", dst_any=False, dst_ips=["203.0.113.10"])]

    result = path.trace(None, "10.0.0.5", "203.0.113.10/31", port=443, proto="tcp", gateways=[GW])
    assert len(result["legs"]) == 2
    assert all(leg["indeterminate"] for leg in result["legs"])
    assert all("filter_view" not in leg for leg in result["legs"])
    assert any("split across more than one route" in w for w in result["warnings"])


def test_no_access_rulebase_at_all_says_nothing_about_the_pipeline_order(graph):
    """There is no filter for the destination NAT to be ordered against, so
    there is nothing to derive and nothing to warn about."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_dnat_row()]

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert not leg["indeterminate"]
    assert "filter_view" not in leg
    assert not result["warnings"]


def test_a_unifi_zone_bound_rulebase_device_takes_the_translated_view_by_derivation(graph):
    """A UniFi 9.x zone-firewall gateway's only policy is FROM_ZONE/TO_ZONE bound."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_dnat_row()]
    # No ENFORCES-bound rulebase exists on this device.
    graph.access_vendors = ["ubiquiti"]

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["filter_view"] == "translated"


def test_a_checkpoint_policy_is_evaluated_on_the_original_port_too(graph):
    """The access rule is written on the public address and port."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_dnat_row(orig_dst_port="8443", translation_port="443")]
    graph.rb = _cp_rb()
    graph.rules = [
        _rule(
            uid="cp:10",
            pos=10,
            action="accept",
            dst_any=False,
            dst_ips=["203.0.113.10"],
            svc_any=False,
            protos=["tcp"],
            ports=["8443"],
        )
    ]

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=8443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert not leg["blocked"]
    assert "accept by rule 10" in leg["firewall"]
    # the view rides on the translation it describes as well as on the leg, so
    # it survives the fold into a far leg
    assert leg["filter_view"] == "original"
    assert leg["dnat"] == [
        {
            "to": ["10.0.0.99/32"],
            "port": 443,
            "rule_uid": "dnat:r10",
            "filter_view": "original",
        }
    ]


def test_a_pbr_rule_claiming_part_of_the_translated_set_leaves_the_view_undecided(graph):
    """PBR runs on the translated destination."""
    graph.sources = [_src_row()]
    graph.pbr = [
        {
            "pol_uid": "pol:1",
            "pol_name": "steer",
            "rule_uid": "pbr:10",
            "pos": 10,
            "rule_name": None,
            "src_cidrs": [],
            "src_ips": [],
            "src_ranges": [],
            "dst_cidrs": ["10.0.0.99/32"],
            "dst_ips": [],
            "dst_ranges": [],
            "table_uid": "vrf:100",
            "table_name": "100",
        }
    ]
    graph.routes = {
        "vrf:100": [_route("10.0.0.0/24", egress="wg0")],
        "vrf:main": [_route("10.0.0.0/24", egress="eth2")],
    }
    graph.nat = [
        _dnat_row(
            orig_dst_raw="203.0.113.10-203.0.113.11",
            orig_dst_addrs=[],
            translation="10.0.0.99-10.0.0.100",
            xlate_dst_addrs=[],
        )
    ]
    graph.rb = _cp_rb()
    graph.rules = [_rule(uid="cp:10", pos=10, action="accept", dst_any=False, dst_ips=["203.0.113.10"])]

    result = path.trace(None, "10.0.0.5", "203.0.113.10/31", port=443, proto="tcp", gateways=[GW])
    assert len(result["legs"]) == 2
    assert all(leg["indeterminate"] for leg in result["legs"])
    assert all("filter_view" not in leg for leg in result["legs"])
    assert any("a PBR rule claims only part of the translated destination" in w for w in result["warnings"])


def test_a_vendor_the_registry_does_not_know_leaves_the_pipeline_order_undecided(graph):
    """The registry is closed over the vendors the collectors write."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_dnat_row()]
    graph.rb = _cp_rb(rb_uid="rb:other", vendor="paloalto", default_action="accept")
    graph.rules = []

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["indeterminate"]
    assert "filter_view" not in leg
    warned = [w for w in result["warnings"] if "the filter's address view for this vendor is not known" in w]
    assert warned and "paloalto" in warned[0]


def test_access_rulebases_from_two_vendors_that_disagree_leave_the_order_undecided(graph):
    """The two vendors sit on opposite sides of the device's destination NAT."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_dnat_row()]
    graph.rb = _cp_rb(default_action="accept")
    graph.rules = []
    # the vendor read sees both rulebases; only one of them is the row the
    # filter itself evaluates
    graph.access_vendors = ["checkpoint", "vyos"]

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["indeterminate"]
    assert "filter_view" not in leg
    warned = [w for w in result["warnings"] if "do not agree on which destination they match" in w]
    assert warned and "checkpoint" in warned[0] and "vyos" in warned[0]


# --- honesty and the gate catch-all ------------------------------------------------------


def test_an_evaluated_nat_rulebase_leaves_the_unevaluated_gate_set(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_nat_row(translation="masquerade")]
    # The egress address is collected.
    graph.iface_addrs = {"if:eth0": "203.0.113.7"}
    graph.gates = [{"uid": "rb:nat", "name": "nat-source", "kind": "FwRulebase"}]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    assert "gate(s) not evaluated" not in result["verdict"]
    assert not result["indeterminate"]


def test_a_rule_matching_on_source_port_is_indeterminate_not_guessed(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_nat_row(translation="masquerade", orig_src_port="1024-2048")]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    assert result["indeterminate"]
    assert any("translation not determinable" in n for n in result["notes"])


# --- the pure partition ------------------------------------------------------------------


def test_translate_set_maps_one_to_one_ranges_by_offset():
    claimed = path._intervals(["10.0.0.4-10.0.0.5"])
    match = path._intervals(["10.0.0.0/24"])
    xlate = path._intervals(["198.51.100.0/24"])
    assert path._translate_set(claimed, match, xlate) == path._intervals(["198.51.100.4-198.51.100.5"])


def test_translate_set_collapses_many_to_one():
    claimed = path._intervals(["10.0.0.0/24"])
    match, xlate = path._intervals(["10.0.0.0/8"]), path._intervals(["203.0.113.7"])
    assert path._translate_set(claimed, match, xlate) == xlate


def test_nat_match_set_negation_is_the_family_complement():
    out = path._nat_match_set("!10.0.0.0/8", [])
    assert path._intersect(out, path._intervals(["10.1.2.3"])) == []
    assert path._intersect(out, path._intervals(["192.0.2.1"])) == path._intervals(["192.0.2.1"])


def test_vyos_style_static_translates_both_directions(graph):
    """VyOS `nat static` encodes the public and the real address on the destination side."""
    rule = _nat_row(
        rb_uid="rb:static",
        rb_name="nat-static",
        uid="static:v1",
        kind="static",
        orig_dst_raw="203.0.113.5",
        orig_dst_addrs=["203.0.113.5"],
        translation="10.0.0.99",
        xlate_dst_addrs=["10.0.0.99"],
    )
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2"), _route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [rule]

    inbound = path.trace(None, "10.0.0.5", "203.0.113.5", gateways=[GW])
    assert inbound["legs"][0]["cidr"] == "10.0.0.0/24"
    assert inbound["legs"][0]["dnat"][0]["to"] == ["10.0.0.99/32"]

    outbound = path.trace(None, "10.0.0.99", "8.8.8.8", gateways=[GW])
    assert outbound["legs"][0]["snat"][0]["to"] == "203.0.113.5"

    # a different source is not claimed by the one-to-one rule
    other = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    assert "snat" not in other["legs"][0]


def test_cisco_static_flag_is_bidirectional(graph):
    """`ip nat inside source static tcp 10.0.0.99 443 203.0.113.5 8443` lands as kind=snat, static=True."""
    rule = _nat_row(
        kind="snat",
        static_flag=True,
        orig_src_raw=None,
        orig_src_addrs=["10.0.0.99"],
        translation="203.0.113.5",
        xlate_src_addrs=["203.0.113.5"],
        orig_port="443",
        translation_port="8443",
    )
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2"), _route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [rule]

    inbound = path.trace(None, "10.0.0.5", "203.0.113.5", port=8443, proto="tcp", gateways=[GW])
    leg = inbound["legs"][0]
    assert leg["dnat"] == [{"to": ["10.0.0.99/32"], "port": 443, "rule_uid": "nat:r10"}]

    # the wrong public port is not claimed by the mapping
    miss = path.trace(None, "10.0.0.5", "203.0.113.5", port=80, proto="tcp", gateways=[GW])
    assert "dnat" not in miss["legs"][0]

    outbound = path.trace(None, "10.0.0.99", "8.8.8.8", gateways=[GW])
    assert outbound["legs"][0]["snat"][0]["to"] == "203.0.113.5"


def test_checkpoint_automatic_static_nat_translates_both_directions(graph):
    rule = _nat_row(
        rb_uid="rb:static",
        rb_name="nat-static",
        uid="cp:auto:1",
        kind=None,
        method="static",
        auto_generated=True,
        orig_src_addrs=["10.0.0.99"],
        orig_src_present=True,
        xlate_src_addrs=["203.0.113.5"],
    )
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2"), _route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [rule]

    inbound = path.trace(None, "10.0.0.5", "203.0.113.5", gateways=[GW])
    assert inbound["legs"][0]["cidr"] == "10.0.0.0/24"
    assert inbound["legs"][0]["dnat"][0]["to"] == ["10.0.0.99/32"]

    outbound = path.trace(None, "10.0.0.99", "8.8.8.8", gateways=[GW])
    assert outbound["legs"][0]["snat"][0]["to"] == "203.0.113.5"


def test_checkpoint_manual_static_nat_is_applied_in_one_direction_only(graph):
    """Only Automatic NAT (auto_generated) is bidirectional."""
    rule = _nat_row(
        rb_uid="rb:static",
        rb_name="nat-static",
        uid="cp:manual:1",
        kind=None,
        method="static",
        auto_generated=False,
        orig_dst_addrs=["203.0.113.5"],
        orig_dst_present=True,
        xlate_dst_addrs=["10.0.0.99"],
    )
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2"), _route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [rule]

    # the direction the rule is written for applies
    inbound = path.trace(None, "10.0.0.5", "203.0.113.5", gateways=[GW])
    assert inbound["legs"][0]["dnat"][0]["to"] == ["10.0.0.99/32"]

    # the reverse is not inferred from the same rule
    outbound = path.trace(None, "10.0.0.99", "8.8.8.8", gateways=[GW])
    assert "snat" not in outbound["legs"][0]

    # and the auto-generated form of the same row is the bidirectional case
    graph.nat = [dict(rule, auto_generated=True)]
    auto = path.trace(None, "10.0.0.99", "8.8.8.8", gateways=[GW])
    assert auto["legs"][0]["snat"][0]["to"] == "203.0.113.5"


def test_a_nat_object_with_no_resolvable_address_is_opaque_not_any(graph):
    """An ORIG_DST object that the collector could not resolve has an unknown scope."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2"), _route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_dnat_row(orig_dst_raw=None, orig_dst_addrs=[], orig_dst_present=True)]

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    assert result["indeterminate"]
    assert result["legs"][0]["indeterminate"]
    assert any("translation not determinable" in n for n in result["notes"])
    assert any(h["note"] == "match undecidable" for h in result["hops"] if h["kind"] == "NatRule")


def test_the_same_nat_object_decides_the_rule_once_it_carries_an_address(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2"), _route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_dnat_row(orig_dst_raw=None, orig_dst_present=True)]

    result = path.trace(None, "10.0.0.5", "203.0.113.10", gateways=[GW])
    assert not result["indeterminate"]
    assert result["legs"][0]["dnat"][0]["to"] == ["10.0.0.99/32"]


def test_cisco_outside_source_rewrites_the_source_at_ingress(graph):
    """The rule binds on the ingress interface's collected nat_role='outside'."""
    rule = _nat_row(
        kind="dnat",
        direction="outside-source",
        orig_src_addrs=["10.0.0.5"],
        xlate_src_addrs=["10.0.0.77"],
    )
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [rule]
    graph.iface_roles = {"if:eth1": "outside"}
    result = path.trace(None, "10.0.0.5", "192.0.2.9", gateways=[GW])
    # the flow routes normally; the NatRule hop records the source rewrite
    hops = [h for h in result["hops"] if h["kind"] == "NatRule"]
    assert hops and "10.0.0.77" in hops[0]["note"]
    # and a non-matching source is untouched
    graph.nat = [dict(rule, orig_src_addrs=["10.0.0.99"])]
    other = path.trace(None, "10.0.0.5", "192.0.2.9", gateways=[GW])
    assert not [h for h in other["hops"] if h["kind"] == "NatRule"]


def test_cisco_outside_source_is_a_decided_non_match_on_a_known_inside_ingress(graph):
    rule = _nat_row(
        kind="dnat",
        direction="outside-source",
        orig_src_addrs=["10.0.0.5"],
        xlate_src_addrs=["10.0.0.77"],
    )
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [rule]
    graph.iface_roles = {"if:eth1": "inside"}
    result = path.trace(None, "10.0.0.5", "192.0.2.9", gateways=[GW])
    assert not [h for h in result["hops"] if h["kind"] == "NatRule"]
    assert not result["indeterminate"]


def test_cisco_outside_source_is_indeterminate_when_the_ingress_role_was_never_collected(graph):
    rule = _nat_row(
        kind="dnat",
        direction="outside-source",
        orig_src_addrs=["10.0.0.5"],
        xlate_src_addrs=["10.0.0.77"],
    )
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [rule]
    result = path.trace(None, "10.0.0.5", "192.0.2.9", gateways=[GW])
    leg = result["legs"][0]
    assert leg["indeterminate"] is True
    assert any("NAT role not collected" in n for n in result["notes"])
    # no fabricated source rewrite reaches the downstream leg or hops
    assert not [h for h in result["hops"] if h["kind"] == "NatRule" and "10.0.0.77" in h.get("note", "")]


def test_cisco_inside_source_applies_only_when_ingress_is_inside_and_egress_is_outside(graph):
    """`ip nat inside source ...` is an egress sNAT."""
    rule = _nat_row(
        direction="inside-source",
        orig_src_raw="10.0.0.0/24",
        orig_src_addrs=["10.0.0.0/24"],
        translation="203.0.113.7",
        xlate_src_addrs=["203.0.113.7"],
    )
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [rule]
    graph.iface_roles = {"if:eth1": "inside", "if:eth0": "outside"}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    leg = result["legs"][0]
    assert leg["snat"] == [{"sources": ["10.0.0.5/32"], "to": "203.0.113.7", "rule_uid": "nat:r10"}]
    assert not leg["indeterminate"]


def test_cisco_inside_source_is_a_decided_non_match_when_the_roles_do_not_pair(graph):
    """Both roles are collected and known, but not as an inside-to-outside
    pair: a confident non-match, not an indeterminate one."""
    rule = _nat_row(
        direction="inside-source",
        orig_src_raw="10.0.0.0/24",
        orig_src_addrs=["10.0.0.0/24"],
        translation="203.0.113.7",
        xlate_src_addrs=["203.0.113.7"],
    )
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [rule]
    graph.iface_roles = {"if:eth1": "outside", "if:eth0": "inside"}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    leg = result["legs"][0]
    assert "snat" not in leg
    assert not leg["indeterminate"]


def test_cisco_inside_source_is_a_decided_non_match_when_ingress_role_disproves_it(graph):
    """The ingress role is collected as 'outside': inside-source cannot apply
    no matter what the egress role turns out to be, so an uncollected egress
    role does not make the leg indeterminate."""
    rule = _nat_row(
        direction="inside-source",
        orig_src_raw="10.0.0.0/24",
        orig_src_addrs=["10.0.0.0/24"],
        translation="203.0.113.7",
        xlate_src_addrs=["203.0.113.7"],
    )
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [rule]
    graph.iface_roles = {"if:eth1": "outside"}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    leg = result["legs"][0]
    assert "snat" not in leg
    assert not leg["indeterminate"]


def test_cisco_inside_source_is_indeterminate_when_ingress_is_inside_and_egress_is_uncollected(graph):
    """The ingress role is collected as 'inside', which does not disprove the
    pairing; the egress role was never collected, so the rule cannot be
    decided and the leg is indeterminate."""
    rule = _nat_row(
        direction="inside-source",
        orig_src_raw="10.0.0.0/24",
        orig_src_addrs=["10.0.0.0/24"],
        translation="203.0.113.7",
        xlate_src_addrs=["203.0.113.7"],
    )
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [rule]
    graph.iface_roles = {"if:eth1": "inside"}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    leg = result["legs"][0]
    assert leg["indeterminate"] is True
    assert any("NAT role not collected" in n for n in result["notes"])
    assert "snat" not in leg


def test_cisco_inside_source_is_indeterminate_when_a_role_was_never_collected(graph):
    rule = _nat_row(
        direction="inside-source",
        orig_src_raw="10.0.0.0/24",
        orig_src_addrs=["10.0.0.0/24"],
        translation="203.0.113.7",
        xlate_src_addrs=["203.0.113.7"],
    )
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [rule]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    leg = result["legs"][0]
    assert leg["indeterminate"] is True
    assert any("NAT role not collected" in n for n in result["notes"])
    assert "snat" not in leg


def test_the_hop_order_matches_the_packet_path(graph):
    """POSTROUTING runs while the packet is on the box."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.wan = {"uid": "wan:1", "name": "1und1"}
    graph.rb = {
        "rb_uid": "rb:fw",
        "rb_name": "LAN-WAN",
        "vendor": "vyos",
        "default_action": "accept",
        "approximate": False,
    }
    graph.rules = [_rule(pos=1)]
    graph.nat = [
        _nat_row(translation="masquerade", out_if="eth0"),
        _dnat_row(
            orig_dst_raw="8.8.8.8",
            orig_dst_addrs=["8.8.8.8"],
            translation="8.8.4.4",
            xlate_dst_addrs=["8.8.4.4"],
        ),
    ]

    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])

    stages = [h["stage"] for h in sorted(result["hops"], key=lambda h: h["rank"])]
    assert stages == [
        "INGRESS_IF",
        "DEVICE",
        "DNAT",
        "VRF",
        "ROUTE",
        "FILTER_RB",
        "FILTER_RULE",
        "SNAT",
        "EGRESS_IF",
        "LINK",
    ]


def test_rank_is_derived_from_the_pipeline_not_from_call_order(graph):
    """The lane without a PBR policy leaves the PBR column empty."""
    graph.sources = [_src_row()]
    graph.pbr = [
        {
            "pol_uid": "pol:1",
            "pol_name": "PBR",
            "rule_uid": "pol:1:10",
            "pos": 10,
            "rule_name": None,
            "src_cidrs": ["10.0.0.0/25"],
            "src_ips": [],
            "dst_cidrs": [],
            "dst_ips": [],
            "src_ranges": [],
            "dst_ranges": [],
            "table_uid": "vrf:t100",
            "table_name": "table100",
        }
    ]
    graph.routes = {
        "vrf:main": [_route("0.0.0.0/0", egress="eth0")],
        "vrf:t100": [_route("0.0.0.0/0", egress="wg0")],
    }
    result = path.trace(None, "10.0.0.0/24", "8.8.8.8", gateways=[GW])

    by_stage: dict[str, set[int]] = {}
    for h in result["hops"]:
        by_stage.setdefault(h["stage"], set()).add(h["rank"])
    # one column per stage, whichever lane the hop is in
    assert all(len(ranks) == 1 for ranks in by_stage.values()), by_stage
    col = {stage: ranks.pop() for stage, ranks in by_stage.items()}
    assert col["PBR_POLICY"] < col["VRF"] < col["ROUTE"] < col["EGRESS_IF"]
    # both lanes put their egress in that one column, PBR detour or not
    egress = [h for h in result["hops"] if h["stage"] == "EGRESS_IF"]
    assert {h["label"] for h in egress} == {"wg0", "eth0"}
    assert {h["lane"] for h in egress} == {0, 1}


# --- the carrier: what the WAN link carries ----------------------------------------------


def _tunnel(graph, **props):
    """A tunnel on the egress interface, plus its carrier endpoint row."""
    graph.tunnel = {"uid": "tun:wg0", "name": "us-streaming", "encap": "wireguard"}
    graph.tunnel_props = {
        "endpoint": "203.0.113.9",
        "endpoint_port": "51820",
        "carrier_proto": "udp",
        "local_address": None,
        "encap": "wireguard",
        **props,
    }


def test_the_encapsulated_packet_gets_its_own_route_and_egress(graph):
    """A tunnel egress emits a new packet to the peer endpoint on udp/51820."""
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("0.0.0.0/0", egress="wg0"),
            _route("203.0.113.0/24", egress="pppoe0"),
        ]
    }
    graph.iface_addrs = {"if:pppoe0": "198.51.100.181"}
    _tunnel(graph)

    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])

    carrier = result["legs"][0]["carrier"]
    assert carrier["endpoint"] == "203.0.113.9"
    assert carrier["port"] == 51820 and carrier["proto"] == "udp"
    assert carrier["cidr"] == "203.0.113.0/24"
    assert carrier["egress"] == "pppoe0"
    assert carrier["src"] == "198.51.100.181"

    stages = [h["stage"] for h in sorted(result["hops"], key=lambda h: h["rank"])]
    # the carrier's own route and egress sit between the tunnel and the link
    assert stages.index("ENCAP") < stages.index("CARRIER_ROUTE")
    assert stages.index("CARRIER_ROUTE") < stages.index("CARRIER_EGRESS_IF")


def test_the_carrier_reads_its_tunnel_and_far_end_count_in_one_read(graph):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [_route("0.0.0.0/0", egress="wg0"), _route("203.0.113.0/24", egress="pppoe0")]
    }
    _tunnel(graph)
    reads = record_reads(graph)

    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])

    assert result["legs"][0]["carrier"]["egress"] == "pppoe0"
    tunnel_reads = [q for q, p in reads if p.get("uid") == "tun:wg0"]
    assert len(tunnel_reads) == 1
    assert "AS far_ends" in tunnel_reads[0]


def test_the_carrier_snat_takes_the_ingress_role_the_egress_stage_read(graph):
    """The ingress interface's NAT role is read by destination NAT and by the
    inner flow's source NAT. The carrier's source NAT on the same device takes
    the role the source NAT stage read."""
    _carrier_graph(graph)
    graph.nat = [_carrier_snat_rule(orig_dst_port="51820")]
    reads = record_reads(graph)

    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])

    assert result["legs"][0]["carrier"]["snat"] == "203.0.113.77"
    role_reads = [p["u"] for q, p in reads if "RETURN i.nat_role AS nat_role" in q]
    assert role_reads.count(GW["if_uid"]) == 2


def test_carrier_trace_selects_the_local_table_by_is_global_not_by_name(graph):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [_route("0.0.0.0/0", egress="wg0")],
        "vrf:dev:r1:inet.0": [_route("203.0.113.0/24", egress="pppoe0")],
    }
    graph.iface_addrs = {"if:pppoe0": "198.51.100.181"}
    graph.local_vrf = {"vrf_uid": "vrf:dev:r1:inet.0", "vrf_name": "inet.0"}
    _tunnel(graph)

    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])

    carrier = result["legs"][0]["carrier"]
    assert carrier["egress"] == "pppoe0"
    assert carrier["cidr"] == "203.0.113.0/24"


def test_an_uncollected_peer_endpoint_warns(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="wg0")]}
    _tunnel(graph, endpoint=None)

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    assert "carrier" not in result["legs"][0]
    assert any("peer endpoint not collected" in w for w in result["warnings"])


def test_a_peer_routed_back_into_its_own_tunnel_is_recursive_routing(graph):
    """The default route egresses the tunnel itself."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="wg0")]}
    _tunnel(graph)

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    leg = result["legs"][0]
    assert leg["carrier"]["verdict"] == "recursive routing via wg0"
    assert leg["indeterminate"]
    assert any("recursive routing" in w for w in result["warnings"])


def test_no_route_to_the_peer_at_all_is_a_warning(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/8", egress="wg0")]}
    _tunnel(graph)

    result = path.trace(None, "10.0.0.5", "10.1.2.3", gateways=[GW])
    assert result["legs"][0]["carrier"]["verdict"] == "no route to peer"
    assert any("no route to peer" in w for w in result["warnings"])


def test_a_terminates_on_zscalerdc_draws_a_boundary_hop_not_a_warning(graph):
    """A ZIA GRE/IPsec tunnel's far end is a TERMINATES_ON relationship."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="wg0")]}
    _tunnel(
        graph,
        endpoint=None,
        far_ip=None,
        far_uid="zia:acme:dc:fra4",
        far_name="fra4",
        far_kind="ZscalerDc",
    )

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    leg = result["legs"][0]
    assert leg.get("boundary") is True
    assert not any("peer endpoint not collected" in w for w in result["warnings"])
    dc_hops = [h for h in result["hops"] if h["kind"] == "ZscalerDc"]
    assert [h["uid"] for h in dc_hops] == ["zia:acme:dc:fra4"]


def test_a_terminates_on_sdwangateway_with_no_address_is_a_boundary_too(graph):
    """No address property is collected for SdwanGateway."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="wg0")]}
    _tunnel(
        graph,
        endpoint=None,
        far_ip=None,
        far_uid="vco:acme:gw:fra-gw1",
        far_name="fra-gw1",
        far_kind="SdwanGateway",
    )

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    leg = result["legs"][0]
    assert leg.get("boundary") is True
    assert not any("peer endpoint not collected" in w for w in result["warnings"])
    gw_hops = [h for h in result["hops"] if h["kind"] == "SdwanGateway"]
    assert [h["uid"] for h in gw_hops] == ["vco:acme:gw:fra-gw1"]


def test_a_zia_style_tunnel_is_found_by_source_ip_when_no_endpoint_edge_exists(graph):
    """A ZIA GRE/IPsec tunnel has no ENDPOINT edge."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="gre1")]}
    # no ENDPOINT edge for this tunnel: only the source_ip join finds it
    graph.tunnel = None
    graph.iface_addrs = {"if:gre1": "172.31.255.1"}
    graph.iface_kinds = {"if:gre1": "tunnel"}
    graph.tunnel_by_source_ip = {
        "172.31.255.1": {"uid": "zia:acme:gre:5001", "name": "zia-gre", "encap": "gre"}
    }
    graph.tunnel_props = {
        "endpoint": "104.129.194.38",
        "endpoint_port": None,
        "carrier_proto": "gre",
        "local_address": None,
        "encap": "gre",
    }

    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])

    encap_hops = [h for h in result["hops"] if h["stage"] == "ENCAP"]
    assert [h["uid"] for h in encap_hops] == ["zia:acme:gre:5001"]


def test_a_zia_gre_source_address_on_a_physical_interface_draws_no_tunnel(graph):
    """The GRE sourceIp is the customer's public address, which the
    physical WAN interface holds. A flow routed out of that interface is not
    encapsulated into the tunnel, so no ENCAP hop and no ZIA boundary."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("8.8.8.0/24", egress="eth0")]}
    graph.tunnel = None
    graph.iface_addrs = {"if:eth0": "198.51.100.20"}
    graph.iface_kinds = {"if:eth0": "physical"}
    graph.tunnel_by_source_ip = {
        "198.51.100.20": {"uid": "zia:acme:gre:5001", "name": "zia-gre", "encap": "gre"}
    }

    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])

    assert not [h for h in result["hops"] if h["kind"] == "Tunnel"]
    assert not [h for h in result["hops"] if h["stage"] == "ENCAP"]
    assert not result["legs"][0].get("indeterminate")
    assert any("eth0 sources tunnel zia-gre" in n for n in result["notes"])


def test_a_zia_ipsec_source_address_on_a_physical_interface_is_undecided(graph):
    """A crypto map on the physical interface can encrypt the flow."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("8.8.8.0/24", egress="eth0")]}
    graph.tunnel = None
    graph.iface_addrs = {"if:eth0": "198.51.100.20"}
    graph.iface_kinds = {"if:eth0": "physical"}
    graph.tunnel_by_source_ip = {
        "198.51.100.20": {"uid": "zia:acme:ipsec:7001", "name": "zia-ipsec", "encap": "ipsec"}
    }

    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert not [h for h in result["hops"] if h["stage"] == "ENCAP"]
    assert leg["indeterminate"] is True
    assert "sources tunnel zia-ipsec" in leg["indeterminate_reason"]
    assert any("sources tunnel zia-ipsec" in w for w in result["warnings"])


def test_a_source_ip_tunnel_with_no_far_end_warns_of_an_uncollected_peer(graph):
    """A type-IP ZIA VPN credential (no fqdn) has no far end."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="gre1")]}
    graph.tunnel = None
    graph.iface_addrs = {"if:gre1": "198.51.100.20"}
    graph.iface_kinds = {"if:gre1": "tunnel"}
    graph.tunnel_by_source_ip = {
        "198.51.100.20": {"uid": "zia:acme:ipsec:7001", "name": "zia-ipsec", "encap": "ipsec"}
    }
    graph.tunnel_props = {
        "endpoint": None,
        "endpoint_port": None,
        "carrier_proto": None,
        "local_address": None,
        "encap": "ipsec",
    }

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    assert any("peer endpoint not collected" in w for w in result["warnings"])
    assert not any("recursive routing" in w for w in result["warnings"])
    assert "carrier" not in result["legs"][0]


def test_a_tunnel_whose_source_ip_is_not_the_egress_address_is_not_found(graph):
    """The source_ip property must match the interface's own address."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="gre1")]}
    graph.tunnel = None
    graph.iface_addrs = {"if:gre1": "172.31.255.9"}
    graph.tunnel_by_source_ip = {
        "172.31.255.1": {"uid": "zia:acme:gre:5001", "name": "zia-gre", "encap": "gre"}
    }

    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])

    assert not [h for h in result["hops"] if h["stage"] == "ENCAP"]


def test_a_side_store_carrier_route_gets_its_own_hop_uid(graph):
    """`_Trail.hop` dedupes on (uid, lane)."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="wg0")]}
    _tunnel(graph)  # endpoint 203.0.113.9, no graph route covers it
    fake_rib = _FakeRib(lpm_rows=[{"prefix": "203.0.113.0/24", "next_hop": None, "interface": None}])

    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW], rib=fake_rib)

    tunnel_hops = [h for h in result["hops"] if h["kind"] == "Tunnel"]
    route_hops = [h for h in result["hops"] if h["stage"] == "CARRIER_ROUTE"]
    assert len(tunnel_hops) == 1
    assert len(route_hops) == 1
    assert route_hops[0]["uid"] != tunnel_hops[0]["uid"]
    assert route_hops[0]["uid"] == f"{tunnel_hops[0]['uid']}#carrier:203.0.113.0/24"


def test_the_carrier_is_judged_by_the_output_chain_and_can_block_the_leg(graph):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("0.0.0.0/0", egress="wg0"),
            _route("203.0.113.0/24", egress="pppoe0"),
        ]
    }
    graph.iface_addrs = {"if:pppoe0": "198.51.100.181"}
    _tunnel(graph)
    # Only the output chain has a rulebase.
    graph.rb_by_chain = {
        "output": {
            "rb_uid": "rb:out",
            "rb_name": "ipv4-output",
            "vendor": "vyos",
            "default_action": "drop",
            "approximate": False,
        }
    }
    graph.rules = []

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    leg = result["legs"][0]
    assert leg["blocked"]
    assert leg["carrier"]["verdict"].startswith("BLOCKED by ipv4-output")
    assert any("carrier blocked" in w for w in result["warnings"])


def test_dnat_before_an_ecmp_fork_is_drawn_on_every_lane(graph):
    """The translation happens once, before the routing decision."""
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("10.9.9.0/24", egress="eth2", next_hop="10.9.9.1"),
            _route("10.9.9.0/24", egress="eth3", next_hop="10.9.9.2"),
        ]
    }
    graph.nat = [_dnat_row(translation="10.9.9.99", xlate_dst_addrs=["10.9.9.99"])]
    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])

    lanes = sorted({leg["lane"] for leg in result["legs"]})
    assert len(lanes) == 2
    assert all(ll["dnat"][0]["rule_uid"] == "dnat:r10" for ll in result["legs"])

    dnat_hops = [h for h in result["hops"] if h["uid"] == "dnat:r10"]
    assert sorted(h["lane"] for h in dnat_hops) == lanes
    assert len({h["rank"] for h in dnat_hops}) == 1
    assert {h["note"] for h in dnat_hops} == {"→ 10.9.9.99"}


# --- a NAT rule scoped to a dimension the flow tuple does not carry ----------------------


def test_an_snat_rule_scoped_to_a_protocol_is_undecidable_on_a_protocol_less_flow(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_nat_row(translation="masquerade", out_if="eth0", protocol="tcp")]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    assert result["indeterminate"]
    assert any("translation not determinable" in n for n in result["notes"])


def test_the_same_snat_rule_translates_once_the_flow_carries_that_protocol(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.iface_addrs = {"if:eth0": "203.0.113.7"}
    graph.nat = [_nat_row(translation="masquerade", out_if="eth0", protocol="tcp")]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    assert not result["indeterminate"]
    assert result["legs"][0]["snat"][0]["to"] == "203.0.113.7"


def test_the_same_snat_rule_is_a_confident_miss_on_another_protocol(graph):
    """A known protocol that the rule does not name is a skip."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_nat_row(translation="masquerade", out_if="eth0", protocol="tcp")]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="udp", gateways=[GW])
    assert "snat" not in result["legs"][0]
    assert not result["indeterminate"]


def test_a_dnat_rule_scoped_to_a_port_is_undecidable_on_a_port_less_flow(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2"), _route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_dnat_row(orig_dst_port="443")]
    result = path.trace(None, "10.0.0.5", "203.0.113.10", gateways=[GW])
    assert result["indeterminate"]
    assert any("translation not determinable" in n for n in result["notes"])
    assert any(h["note"] == "match undecidable" for h in result["hops"] if h["kind"] == "NatRule")


def test_the_same_dnat_rule_translates_once_the_flow_carries_that_port(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_dnat_row(orig_dst_port="443")]
    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["dnat"] == [{"to": ["10.0.0.99/32"], "port": 443, "rule_uid": "dnat:r10"}]
    assert not result["indeterminate"]


def _carrier_snat_rule(**kw):
    """A POSTROUTING rule on the real WAN interface the carrier packet leaves by."""
    return _nat_row(
        uid="nat:carrier",
        pos=20,
        translation="203.0.113.77",
        xlate_src_addrs=["203.0.113.77"],
        out_if="pppoe0",
        **kw,
    )


def _carrier_graph(graph, **tunnel_props):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("0.0.0.0/0", egress="wg0"),
            _route("203.0.113.0/24", egress="pppoe0"),
        ]
    }
    graph.iface_addrs = {"if:pppoe0": "198.51.100.181"}
    _tunnel(graph, **tunnel_props)
    return graph


def test_carrier_snat_records_the_translation_on_the_carrier(graph):
    _carrier_graph(graph)
    graph.nat = [_carrier_snat_rule(orig_dst_port="51820")]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["carrier"]["snat"] == "203.0.113.77"
    assert not leg["indeterminate"]


def test_carrier_snat_scoped_to_a_port_the_tunnel_never_recorded_is_undecidable(graph):
    """A tunnel whose endpoint port was not collected gives the carrier packet no destination port."""
    _carrier_graph(graph, endpoint_port=None)
    graph.nat = [_carrier_snat_rule(orig_dst_port="51820")]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["indeterminate"]
    assert "snat" not in leg["carrier"]
    assert any("carrier sNAT rule 20 not determinable" in w for w in result["warnings"])


# --- (proto, port) rectangles: `_nat_partition` claims a range, not a scalar test -------
# `_service_regions` decides a rule's protocol and port scope on the range algebra.


def test_a_port_range_match_with_a_scalar_translation_claims_the_range(graph):
    """The rule's own match scope is a range; `translation_port` is a single
    port, not a same-size pool, so `_translate_port` falls back to
    `_translate_set`'s 'anything else' branch and every address the range
    claims leaves on that one port, whatever the query's own port was."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_dnat_row(orig_dst_port="1000-2000", translation_port="8443")]
    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=1500, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["dnat"] == [{"to": ["10.0.0.99/32"], "port": 8443, "rule_uid": "dnat:r10"}]
    assert not result["indeterminate"]


def test_a_ranged_pat_translation_offset_maps_the_claimed_port(graph):
    """A same-size static range pair is a PAT pool."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [
        _nat_row(
            rb_uid="rb:static",
            rb_name="nat-static",
            uid="static:pat",
            kind="static",
            orig_src_raw="10.0.0.99",
            orig_src_addrs=["10.0.0.99"],
            translation="203.0.113.5",
            xlate_src_addrs=["203.0.113.5"],
            orig_port="8000-8002",
            translation_port="9000-9002",
        )
    ]
    result = path.trace(None, "10.0.0.5", "203.0.113.5", port=9001, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["dnat"] == [{"to": ["10.0.0.99/32"], "port": 8001, "rule_uid": "static:pat"}]
    assert not result["indeterminate"]


def test_a_protocol_list_covering_every_protocol_is_a_confident_match_not_opaque():
    """`_protoset(['!tcp', 'tcp'])` resolves to the full protocol range."""
    dst = path._intervals(["203.0.113.10/32"])
    src = path._intervals(["10.0.0.0/24"])
    rule = {
        "uid": "nat:full-range",
        "rb_name": "nat-destination",
        "pos": 10,
        "protos": ["!tcp", "tcp"],
        "port_spec": None,
        "match_src": [],
        "match_dst": dst,
        "exclude": False,
        "xlate": path._intervals(["10.0.0.99"]),
        "rewrite": "dst",
    }
    parts = _nat_partition([rule], src, dst, None, None)
    assert len(parts) == 1
    assert parts[0]["rule"]["uid"] == "nat:full-range"
    assert not parts[0]["rule"].get("opaque")


def test_an_address_only_rule_matches_a_query_with_and_without_a_protocol():
    """A rule naming no protocol and no port constrains neither dimension."""
    dst = path._intervals(["203.0.113.10/32"])
    src = path._intervals(["10.0.0.0/24"])
    rule = {
        "uid": "nat:addr-only",
        "rb_name": "nat-destination",
        "pos": 10,
        "protos": [],
        "port_spec": None,
        "match_src": [],
        "match_dst": dst,
        "exclude": False,
        "xlate": path._intervals(["10.0.0.99"]),
        "rewrite": "dst",
    }
    with_proto = _nat_partition([rule], src, dst, None, "tcp")
    without_proto = _nat_partition([rule], src, dst, None, None)
    assert with_proto[0]["rule"]["uid"] == "nat:addr-only" and not with_proto[0]["rule"].get("opaque")
    assert without_proto[0]["rule"]["uid"] == "nat:addr-only" and not without_proto[0]["rule"].get("opaque")


# --- the rectangle the rule claims, and the remainder it leaves -------------------------
# A rule claims the overlap between its own scope and the query set.


def _range_rule(**kw):
    """A hand-built dNAT rule in the shape `_nat_stage_rules` resolves."""
    rule = {
        "uid": "nat:ranged",
        "rb_name": "nat-destination",
        "pos": 10,
        "protos": [],
        "port_spec": None,
        "match_src": [],
        "match_dst": path._intervals(["203.0.113.10/32"]),
        "exclude": False,
        "xlate": path._intervals(["10.0.0.99"]),
        "rewrite": "dst",
    }
    rule.update(kw)
    return rule


def test_a_port_range_the_query_only_partly_covers_claims_the_overlap():
    """The rule is scoped to 1000-2000 and the query asks about 500-1500."""
    src = path._intervals(["10.0.0.0/24"])
    dst = path._intervals(["203.0.113.10/32"])
    parts = _nat_partition(
        [_range_rule(port_spec="1000-2000")], src, dst, None, None, port_ivals=_ports("500-1500")
    )
    assert len(parts) == 2
    claimed, remainder = parts
    assert claimed["rule"]["uid"] == "nat:ranged"
    assert claimed["port_subset"] == [(_PORT_FAMILY, 1000, 1500)]
    assert claimed["new_dst"] == path._intervals(["10.0.0.99"])
    assert not claimed["rule"].get("opaque")
    assert remainder["rule"] is None
    assert remainder["port_subset"] == [(_PORT_FAMILY, 500, 999)]
    assert remainder["new_dst"] == dst
    assert not remainder.get("opaque")


def test_a_protocol_the_query_only_partly_covers_claims_the_overlap():
    """The same split on the protocol dimension: a tcp-scoped rule against a
    tcp-and-udp query claims tcp and hands udp on untranslated."""
    src = path._intervals(["10.0.0.0/24"])
    dst = path._intervals(["203.0.113.10/32"])
    parts = _nat_partition(
        [_range_rule(protos=["tcp"])], src, dst, None, None, proto_set=_protoset(["tcp", "udp"])
    )
    assert len(parts) == 2
    claimed, remainder = parts
    assert claimed["proto_subset"] == frozenset({6})
    assert claimed["new_dst"] == path._intervals(["10.0.0.99"])
    assert not claimed["rule"].get("opaque")
    assert remainder["rule"] is None and remainder["proto_subset"] == frozenset({17})


def test_a_scalar_query_states_its_own_point_in_both_service_dimensions():
    """The acceptance property in the part dict: a caller stating a scalar
    gets the one-element set that scalar names, so one rule claims one part."""
    src = path._intervals(["10.0.0.0/24"])
    dst = path._intervals(["203.0.113.10/32"])
    parts = _nat_partition([_range_rule(protos=["tcp"], port_spec="443")], src, dst, 443, "tcp")
    assert len(parts) == 1
    assert parts[0]["proto_subset"] == frozenset({6})
    assert parts[0]["port_subset"] == [(_PORT_FAMILY, 443, 443)]


def test_a_query_protocol_this_grammar_cannot_read_reaches_the_caller(graph):
    """A protocol the query names that resolves to nothing is a caller error."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_dnat_row(protocol="tcp")]
    with pytest.raises(ValueError):
        path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcpp", gateways=[GW])


# --- ranged PAT pools the engine cannot map --------------------------------------------
# A pool other than a same-size range pair or a single port leaves the leg not determinable.


def test_a_pat_pool_that_does_not_match_the_matched_range_is_not_determinable(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_dnat_row(orig_dst_port="1000-2000", translation_port="8000-8500")]
    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=1500, proto="tcp", gateways=[GW])
    assert result["indeterminate"]
    assert any(
        "translation port pool 8000-8500 does not map onto matched ports 1000-2000" in w
        for w in result["warnings"]
    )


def test_a_pat_pool_of_more_than_one_range_is_not_determinable(graph):
    """'80,443' rewritten to '8080,8443' is two mappings written as one row:
    which of the two the box picks is not in the collected rows."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_dnat_row(orig_dst_port="80,443", translation_port="8080,8443")]
    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])
    assert result["indeterminate"]
    assert any(
        "translation port pool 8080,8443 does not map onto matched ports 80,443" in w
        for w in result["warnings"]
    )


def test_the_dnat_hop_records_a_ranged_pat_translated_port(graph):
    """A ranged pool does not fill the scalar `xlate_port` column."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [
        _nat_row(
            rb_uid="rb:static",
            rb_name="nat-static",
            uid="static:pat",
            kind="static",
            orig_src_raw="10.0.0.99",
            orig_src_addrs=["10.0.0.99"],
            translation="203.0.113.5",
            xlate_src_addrs=["203.0.113.5"],
            orig_port="8000-8002",
            translation_port="9000-9002",
        )
    ]
    result = path.trace(None, "10.0.0.5", "203.0.113.5", port=9001, proto="tcp", gateways=[GW])
    assert result["legs"][0]["dnat"] == [{"to": ["10.0.0.99/32"], "port": 8001, "rule_uid": "static:pat"}]
    assert any(h["note"] == "→ 10.0.0.99:8001" for h in result["hops"] if h["kind"] == "NatRule")


# --- port_subset holds the claim, new_port_subset the translation ---------------------


def test_a_ranged_pat_rewrite_with_no_single_port_leaves_the_scalar_unset():
    src = path._intervals(["10.0.0.0/24"])
    dst = path._intervals(["203.0.113.10/32"])
    rule = _range_rule(port_spec="1000-2000", xlate_port_spec="9000-10000")
    parts = _nat_partition([rule], src, dst, None, None, port_ivals=_ports("1000-1005"))
    assert len(parts) == 1
    part = parts[0]
    assert part["rule"]["uid"] == "nat:ranged"
    assert not part["rule"].get("opaque")
    assert part["port"] is None
    assert part["port_translated"]
    assert part["port_subset"] == [(_PORT_FAMILY, 1000, 1005)]
    assert part["new_port_subset"] == [(_PORT_FAMILY, 9000, 9005)]


def test_port_subset_holds_the_claim_and_new_port_subset_the_translation():
    """`port_subset` is the claimed pre-translation rectangle on every part,
    including the untranslated `rule=None` remainder; `new_port_subset` is
    the region after the rule's own port rewrite, mirroring `dst`/`new_dst`.
    A translated part carries both; the remainder carries the same region
    in both since nothing translated it."""
    src = path._intervals(["10.0.0.0/24"])
    dst = path._intervals(["203.0.113.10/32"])
    rule = _range_rule(port_spec="1000-2000", xlate_port_spec="9000-10000")
    parts = _nat_partition([rule], src, dst, None, None, port_ivals=_ports("500-1500"))
    assert len(parts) == 2
    claimed, remainder = parts
    assert claimed["rule"]["uid"] == "nat:ranged"
    assert claimed["port_subset"] == [(_PORT_FAMILY, 1000, 1500)]
    assert claimed["new_port_subset"] == [(_PORT_FAMILY, 9000, 9500)]
    assert remainder["rule"] is None
    assert remainder["port_subset"] == [(_PORT_FAMILY, 500, 999)]
    assert remainder["new_port_subset"] == [(_PORT_FAMILY, 500, 999)]


def test_the_dnat_hop_prints_the_range_when_the_translated_port_has_no_single_value():
    """`_record_dnat_hop` prints the translated scalar only when one exists."""
    from hst.path.gates import _Trail
    from hst.path.trace import _record_dnat_hop

    rule = _range_rule(
        uid="nat:ranged-hop",
        port_spec="1000-2000",
        xlate_port_spec="9000-10000",
    )
    nat_part = {
        "new_src": path._intervals(["10.0.0.0/24"]),
        "new_dst": path._intervals(["10.0.0.99/32"]),
        "port": None,
        "port_translated": True,
        "port_subset": [(_PORT_FAMILY, 1000, 1005)],
        "new_port_subset": [(_PORT_FAMILY, 9000, 9005)],
        "rule": rule,
    }
    trail = _Trail()
    _record_dnat_hop(trail, nat_part, "10.0.0.5")
    dnat_hops = [h for h in trail.hops if h["kind"] == "NatRule"]
    assert [h["note"] for h in dnat_hops] == ["→ 10.0.0.99:9000-9005"]


def test_nat_partition_range_dimensions_are_keyword_only():
    src = path._intervals(["10.0.0.0/24"])
    dst = path._intervals(["203.0.113.10/32"])
    with pytest.raises(TypeError):
        _nat_partition([_range_rule()], src, dst, None, None, frozenset({6}))


# --- the ordered, replay-ready translation record ---------------------------------------


def test_a_multi_hop_dnat_then_snat_trace_exposes_the_ordered_translation_list(graph):
    """r1 destination-translates the public address to the real host behind
    r2; r2 source-translates (masquerades) before delivering. The final,
    folded leg carries both translations, in visit order, as a list a later
    reply walk can undo without re-matching either rule."""
    r2_if = {"dev_uid": "dev:r2", "dev_name": "r2", "if_uid": "if:r2-eth0", "if_name": "r2-eth0"}
    graph.sources = [_src_row()]
    graph.default_tables = {
        GW["if_uid"]: {"uid": "vrf:r1"},
        r2_if["if_uid"]: {"uid": "vrf:r2"},
    }
    graph.routes = {
        "vrf:r1": [_route("10.0.0.0/24", egress="eth0", next_hop="10.0.12.2")],
        "vrf:r2": [_route("10.0.0.0/24", egress="r2-eth5")],
    }
    graph.next_hop_devs = {"10.0.12.2": r2_if}
    graph.nat_by_dev = {
        "dev:r1": [_dnat_row()],
        "dev:r2": [_nat_row(translation="10.0.12.1", xlate_src_addrs=["10.0.12.1"], out_if="r2-eth5")],
    }

    result = path.trace(None, "10.0.0.5", "203.0.113.10", gateways=[GW])
    leg = result["legs"][0]
    assert leg["dnat"] == [{"to": ["10.0.0.99/32"], "port": None, "rule_uid": "dnat:r10"}]
    assert leg["snat"] == [{"sources": ["10.0.0.5/32"], "to": "10.0.12.1", "rule_uid": "nat:r10"}]
    assert leg["nat_chain"] == [
        {
            "device": "dev:r1",
            "context_uid": "vrf:r1",
            "direction": "dnat",
            "rule_uid": "dnat:r10",
            "pre": {"src": ["10.0.0.5/32"], "dst": ["203.0.113.10/32"]},
            "post": {"src": ["10.0.0.5/32"], "dst": ["10.0.0.99/32"]},
        },
        {
            "device": "dev:r2",
            "context_uid": "vrf:r2",
            "direction": "snat",
            "rule_uid": "nat:r10",
            "pre": {"src": ["10.0.0.5/32"], "dst": ["10.0.0.99/32"]},
            "post": {"src": ["10.0.12.1/32"], "dst": ["10.0.0.99/32"]},
        },
    ]


# --- an interface ACL sits where its binding direction puts it ---------------------------
#
# IOS-XE runs an inbound access list before every translation and an outbound
# list after every translation (the IOS order of operations). The filter stage
# therefore judges the inbound list on the packet as it arrived, and the
# outbound list is judged after source NAT, at its own stage, on the packet as
# it leaves. NX-OS shares the shape.


def _cisco_acl_rb(uid, name, bindings):
    return {
        "rb_uid": uid,
        "rb_name": name,
        "vendor": "cisco",
        "match_context": "interface-acl",
        "default_action": "deny",
        "approximate": False,
        # [interface name, direction] per PROTECTED_BY edge
        "acl_bindings": bindings,
    }


def _ios_static_nat(local="10.0.0.99", public="203.0.113.10"):
    """`ip nat inside source static <local> <public>`: kind=snat + static, both directions."""
    return _nat_row(
        kind="snat",
        static_flag=True,
        direction="inside-source",
        orig_src_addrs=[local],
        translation=public,
        xlate_src_addrs=[public],
    )


def test_an_inbound_interface_acl_is_judged_on_the_original_destination(graph):
    """IOS-XE checks an inbound interface ACL before the outside-to-inside translation."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_ios_static_nat()]
    graph.iface_names = {"if:eth1": "eth1", "if:eth2": "eth2"}
    graph.iface_roles = {"if:eth1": "outside", "if:eth2": "inside"}
    graph.rb = _cisco_acl_rb("cisco:wan-in", "WAN-IN", [["eth1", "in"]])
    graph.rules = [
        _rule(
            uid="acl:10",
            pos=10,
            action="permit",
            src_any=True,
            dst_any=False,
            dst_ips=["203.0.113.10"],
            svc_any=True,
        )
    ]

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["filter_view"] == "original"
    assert not leg["blocked"]
    assert not leg.get("indeterminate")
    assert leg["firewall"] == "WAN-IN (in on eth1) (cisco) permit by rule 10"
    assert leg["dnat"][0]["to"] == ["10.0.0.99/32"]


def test_an_outbound_interface_acl_is_judged_after_source_nat(graph):
    """`ip access-group WAN-OUT out` on the outside interface, written on the
    translated (global) source: IOS-XE translates inside-to-outside before
    the output list runs, so the rule matches. The list is not a candidate at
    the filter stage, where only the untranslated source is known; it is
    judged after source NAT at its own stage, after the NAT station and
    before the egress interface."""
    graph.sources = [_src_row(ip="10.0.0.99")]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2"), _route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_ios_static_nat()]
    graph.iface_names = {"if:eth1": "eth1", "if:eth0": "eth0"}
    graph.iface_roles = {"if:eth1": "inside", "if:eth0": "outside"}
    graph.rb = _cisco_acl_rb("cisco:wan-out", "WAN-OUT", [["eth0", "out"]])
    graph.rules = [
        _rule(
            uid="acl:10",
            pos=10,
            action="permit",
            src_any=False,
            src_ips=["203.0.113.10"],
            dst_any=True,
            svc_any=True,
        )
    ]

    result = path.trace(None, "10.0.0.99", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert not leg["blocked"]
    assert not leg.get("indeterminate")
    assert leg["snat"][0]["to"] == "203.0.113.10"
    assert leg["egress_firewall"] == "WAN-OUT (out on eth0) (cisco) permit by rule 10"
    # no filter-stage verdict precedes it: the list was not a candidate there
    assert leg["firewall"] == leg["egress_firewall"]
    kinds = [h["kind"] for h in result["hops"]]
    egress_hop = max(i for i, k in enumerate(kinds) if k == "Interface")
    assert kinds.index("NatRule") < kinds.index("FwRulebase") < egress_hop


def test_an_outbound_interface_acl_deny_after_source_nat_blocks_the_leg(graph):
    """The same list with no rule for the translated source: the implicit deny
    blocks the flow after source NAT, and the egress interface is not drawn
    because the packet never leaves by it."""
    graph.sources = [_src_row(ip="10.0.0.99")]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2"), _route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_ios_static_nat()]
    graph.iface_names = {"if:eth1": "eth1", "if:eth0": "eth0"}
    graph.iface_roles = {"if:eth1": "inside", "if:eth0": "outside"}
    graph.rb = _cisco_acl_rb("cisco:wan-out", "WAN-OUT", [["eth0", "out"]])
    graph.rules = [
        _rule(
            uid="acl:10",
            pos=10,
            action="permit",
            src_any=False,
            src_ips=["198.51.100.7"],
            dst_any=True,
            svc_any=True,
        )
    ]

    result = path.trace(None, "10.0.0.99", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["blocked"]
    assert leg["verdict"] == "BLOCKED by WAN-OUT (out on eth0) default-action"
    assert leg["egress_firewall"] == "WAN-OUT (out on eth0) (cisco) deny by default-action"
    assert leg["snat"][0]["to"] == "203.0.113.10"
    assert [h["kind"] for h in result["hops"]].count("Interface") == 1


def test_checkpoint_manual_twice_nat_keeps_one_rule_across_both_stages(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [
        _nat_row(
            uid="cp:twice",
            kind=None,
            method="static",
            auto_generated=False,
            orig_src_addrs=["10.0.0.0/24"],
            orig_dst_addrs=["203.0.113.5"],
            xlate_src_addrs=["198.51.100.0/24"],
            xlate_dst_addrs=["10.0.0.99"],
        ),
        _nat_row(uid="cp:later", pos=20, translation="192.0.2.8"),
    ]
    result = path.trace(None, "10.0.0.5", "203.0.113.5", gateways=[GW])
    leg = result["legs"][0]
    assert leg["dnat"][0]["to"] == ["10.0.0.99/32"]
    assert leg["snat"][0]["to"] == "198.51.100.5"
    assert [step["rule_uid"] for step in leg["nat_chain"]] == ["cp:twice", "cp:twice"]


def test_checkpoint_manual_original_blocks_later_nat_in_both_stages(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [
        _nat_row(
            uid="cp:original",
            kind=None,
            method="static",
            auto_generated=False,
            xlate_src_original=True,
            xlate_dst_original=True,
        ),
        _nat_row(uid="cp:later", pos=20, translation="192.0.2.8"),
    ]
    leg = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])["legs"][0]
    assert not leg.get("snat")
    assert not leg.get("dnat")


def test_checkpoint_manual_source_only_preserves_original_destination_selection(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [
        _nat_row(
            uid="cp:source",
            kind=None,
            method="hide",
            auto_generated=False,
            orig_dst_addrs=["8.8.8.8"],
            xlate_src_addrs=["192.0.2.8"],
            xlate_dst_original=True,
        ),
        _nat_row(
            uid="cp:destination",
            pos=20,
            kind=None,
            method="static",
            orig_dst_addrs=["8.8.8.8"],
            xlate_dst_addrs=["9.9.9.9"],
        ),
    ]
    leg = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])["legs"][0]
    assert not leg.get("dnat")
    assert leg["snat"][0]["to"] == "192.0.2.8"


def test_the_zia_boundary_hop_names_the_role_and_the_vip(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="wg0")]}
    _tunnel(
        graph,
        endpoint=None,
        far_ip=None,
        far_uid="zia:acme:dc:fra4",
        far_name="fra4",
        far_kind="ZscalerDc",
        far_role="primary",
        far_vip="104.129.194.38",
    )
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    [hop] = [h for h in result["hops"] if h["kind"] == "ZscalerDc"]
    assert "primary data center" in hop["note"] and "VIP 104.129.194.38" in hop["note"]
    assert "—" not in hop["note"]


# --- address family, opaque exclude, Cisco static role binding --------------------------


def _family_rules(stage, iface, **kw):
    from hst.path.gates.nat import _nat_stage_rules

    return _nat_stage_rules([_nat_row(**kw)], stage, iface)


def _iv(*addrs):
    from hst.path.addrsets import _intervals

    return _intervals(list(addrs))


_V4_PORT_FORWARD = {
    "kind": "dnat",
    "rb_uid": "vyos:r1:nat:destination",
    "in_if": "pppoe0",
    "protocol": "tcp",
    "orig_dst_port": "443",
    "translation": "192.168.1.10",
    "xlate_dst_addrs": ["192.168.1.10"],
}


@pytest.mark.parametrize("af", [4, None])
def test_a_v4_port_forward_with_no_destination_address_does_not_claim_an_ipv6_flow(af):
    """VyOS `nat destination` on a dynamic uplink states no destination address."""
    rules = _family_rules("dnat", "pppoe0", af=af, **_V4_PORT_FORWARD)
    v6 = _nat_partition(rules, _iv("2606:4700::1111"), _iv("2001:db8:1::10"), 443, "tcp")
    assert [p["rule"] for p in v6] == [None]
    v4 = _nat_partition(rules, _iv("8.8.8.8"), _iv("203.0.113.1"), 443, "tcp")
    assert [p["rule"]["uid"] for p in v4 if p["rule"]] == ["nat:r10"]
    assert path.addrsets._to_cidrs(v4[0]["new_dst"]) == ["192.168.1.10/32"]


def test_a_nat66_masquerade_with_no_prefix_does_not_claim_an_ipv4_flow():
    """`nat66 source` with no source prefix, af=6 from the collector: it never
    claims an IPv4 flow, so the IPv4 rules behind it are read."""
    from hst.path.gates.nat import _nat_stage_rules

    rows = [
        _nat_row(uid="s66", rb_uid="vyos:r1:nat66:source", af=6, translation="masquerade", out_if="pppoe0"),
        _nat_row(uid="s4", rb_uid="vyos:r1:nat:source", af=4, translation="203.0.113.7", out_if="pppoe0"),
    ]
    rules = _nat_stage_rules(rows, "snat", "pppoe0")
    v4 = _nat_partition(rules, _iv("192.168.1.10"), _iv("1.1.1.1"), 443, "tcp")
    assert [p["rule"]["uid"] for p in v4] == ["s4"]
    v6 = _nat_partition(rules, _iv("2001:db8:1::10"), _iv("2606:4700::1111"), 443, "tcp")
    assert [p["rule"]["uid"] for p in v6] == ["s66"]


def test_a_masquerade_row_with_no_family_and_no_address_keeps_claiming_both_families():
    rules = _family_rules("snat", "pppoe0", translation="masquerade", out_if="pppoe0")
    for src, dst in (("192.168.1.10", "1.1.1.1"), ("2001:db8:1::10", "2606:4700::1111")):
        parts = _nat_partition(rules, _iv(src), _iv(dst), 443, "tcp")
        assert parts[0]["rule"]["masquerade"]


def test_a_v4_source_rule_leaves_an_ipv6_flow_untranslated_and_decided():
    from hst.path.gates import _Trail
    from hst.path.gates.nat import _apply_snat

    row = _nat_row(af=4, translation="203.0.113.7", xlate_src_addrs=["203.0.113.7"], out_if="pppoe0")
    leg: dict = {"indeterminate": False}
    src = _iv("2001:db8:1::10")
    out = _apply_snat(
        None, _Trail(), leg, [row], "if:pppoe0", "pppoe0", src, _iv("2606:4700::1"), 443, "tcp", "x"
    )
    assert out == src
    assert "snat" not in leg
    assert not leg["indeterminate"]
    # the same rule translates an IPv4 flow
    leg4: dict = {"indeterminate": False}
    out4 = _apply_snat(
        None,
        _Trail(),
        leg4,
        [row],
        "if:pppoe0",
        "pppoe0",
        _iv("192.168.1.10"),
        _iv("1.1.1.1"),
        443,
        "tcp",
        "x",
    )
    assert path.addrsets._to_cidrs(out4) == ["203.0.113.7/32"]
    assert not leg4["indeterminate"]


_NEGATED = "the rule's source group address-group !SERVERS is negated, which is not modeled"


def _exclude_then_translate(**exclude_kw):
    return [
        _nat_row(
            uid="nat:r10",
            pos=10,
            out_if="eth0",
            exclude=True,
            orig_dst_raw="8.8.8.0/24",
            orig_dst_present=True,
            **exclude_kw,
        ),
        _nat_row(
            uid="nat:r100",
            pos=100,
            out_if="eth0",
            translation="203.0.113.7",
            xlate_src_addrs=["203.0.113.7"],
        ),
    ]


def test_an_exclude_rule_whose_match_is_not_decided_makes_the_leg_indeterminate(graph):
    """The collector marks the rule approximate."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = _exclude_then_translate(rule_approximate=True, approximate_reason=_NEGATED)
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["indeterminate"] is True
    assert any(_NEGATED in w for w in result["warnings"])


def test_an_exclude_rule_that_matches_for_certain_excludes_with_no_mark(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = _exclude_then_translate()
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert "snat" not in leg
    assert not leg["indeterminate"]
    # outside the exclude scope rule 100 translates, decided
    other = path.trace(None, "10.0.0.5", "9.9.9.9", port=443, proto="tcp", gateways=[GW])
    assert other["legs"][0]["snat"][0]["to"] == "203.0.113.7"
    assert not other["legs"][0]["indeterminate"]


def _cisco_static():
    """`ip nat inside source static 10.0.0.5 203.0.113.5` as the collector writes it."""
    return _nat_row(
        direction="inside-source",
        static_flag=True,
        orig_src_addrs=["10.0.0.5"],
        orig_src_present=True,
        translation="203.0.113.5",
        xlate_src_addrs=["203.0.113.5"],
    )


def test_cisco_static_inside_source_translates_inside_to_outside(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_cisco_static()]
    graph.iface_roles = {"if:eth1": "inside", "if:eth0": "outside"}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    leg = result["legs"][0]
    assert leg["snat"][0]["to"] == "203.0.113.5"
    assert not leg["indeterminate"]


def test_cisco_static_inside_source_does_not_translate_inside_to_inside(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.1.0/24", egress="eth2"), _route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_cisco_static()]
    graph.iface_roles = {"if:eth1": "inside", "if:eth2": "inside", "if:eth0": "outside"}
    result = path.trace(None, "10.0.0.5", "10.0.1.20", gateways=[GW])
    leg = result["legs"][0]
    assert "snat" not in leg
    assert not leg["indeterminate"]


def test_cisco_static_inside_source_is_indeterminate_when_the_roles_were_not_collected(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_cisco_static()]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    leg = result["legs"][0]
    assert leg["indeterminate"] is True
    assert "snat" not in leg
    assert any("NAT role not collected" in n for n in result["notes"])


@pytest.mark.parametrize(
    ("role", "claimed", "opaque"),
    [("outside", True, False), ("inside", False, False), (None, True, True)],
)
def test_cisco_static_inside_source_inbound_is_bound_to_an_outside_ingress(role, claimed, opaque):
    from hst.path.gates.nat import _nat_stage_rules

    rules = _nat_stage_rules([_cisco_static()], "dnat", "eth0", ingress_role=role)
    assert bool(rules) is claimed
    if rules:
        assert bool(rules[0]["opaque"]) is opaque
        parts = _nat_partition(rules, _iv("8.8.8.8"), _iv("203.0.113.5"), None, None)
        assert path.addrsets._to_cidrs(parts[0]["new_dst"]) == ["10.0.0.5/32"]
