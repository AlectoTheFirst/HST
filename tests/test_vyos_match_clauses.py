"""VyOS match clauses the gate does not model, negation, and zone membership."""

from tests.test_firewall_rule_scope import _inventory

from hst.collectors.vyos import normalize_vyos
from hst.core import uid
from hst.path.addrsets import _intervals
from hst.path.gates import firewall
from hst.path.gates.firewall import _first_match_point
from hst.path.gates.nat import _nat_partition, _nat_stage_rules
from hst.path.gates.pbr import partition_rules
from hst.path.verdict import INDETERMINATE
from hst.policy.ir import Constant
from hst.policy.nat import normalize_nat_rules

VERSION = "Version:          VyOS 1.4.0\nHardware S/N:     0000"


def _batch(firewall: dict | None = None, interfaces: dict | None = None, **extra):
    cfg = {
        "system": {"host-name": "gw"},
        "interfaces": interfaces or {"ethernet": {"eth0": {"address": ["203.0.113.2/30"]}}},
        "firewall": firewall or {},
        **extra,
    }
    return normalize_vyos({"config": cfg, "version_text": VERSION, "links": []}, l3dom="dc1")


def _forward(rules: dict, default: str = "drop", groups: dict | None = None) -> dict:
    fw: dict = {"ipv4": {"forward": {"filter": {"default-action": default, "rule": rules}}}}
    if groups:
        fw["group"] = groups
    return fw


def _rows(batch, parent_uid: str) -> list[dict]:
    """The rule rows the gate reads for one rulebase or PBR policy, off a batch.

    The columns are the ones `_RULEBASE_RULES` projects, the address sides
    included: each SRC/DST NetObject's RESOLVES_TO targets, ranges and opacity.
    """
    props = {(n.label, n.uid): dict(n.props) for n in batch.nodes}
    rels = list(batch.rels)

    def ends(start: str, rtype: str) -> list[str]:
        return [r.end_uid for r in rels if r.rel_type == rtype and r.start_uid == start]

    def side(rule_uid: str, rtype: str) -> dict:
        objs = [props[("NetObject", u)] | {"uid": u} for u in ends(rule_uid, rtype)]
        targets = [
            props.get(("Prefix", t)) or props.get(("IpAddress", t))
            for o in objs
            for t in ends(o["uid"], "RESOLVES_TO")
        ]
        return {
            "cidrs": [t["cidr"] for t in targets if t and "cidr" in t],
            "ips": [t["ip"] for t in targets if t and "ip" in t],
            "ranges": [o["ranges"] for o in objs if o.get("ranges")],
            "count": len(objs),
            "opaque": any(o.get("opaque") for o in objs),
            "reasons": [o["opaque_reason"] for o in objs if o.get("opaque_reason")],
        }

    rows = []
    for rule_uid in ends(parent_uid, "HAS_RULE"):
        p = props[("FwRule", rule_uid)]
        svcs = [props[("SvcObject", s)] for s in ends(rule_uid, "SVC")]
        src, dst = side(rule_uid, "SRC"), side(rule_uid, "DST")
        rows.append(
            {
                "uid": rule_uid,
                "rule_uid": rule_uid,
                "pos": p["position"],
                "action": p.get("action"),
                "name": p.get("name"),
                "jump_target": p.get("jump_target"),
                "out_if": p.get("out_interface"),
                "in_if": p.get("in_interface"),
                "out_if_group": p.get("out_interface_group"),
                "in_if_group": p.get("in_interface_group"),
                "states": p.get("states", []),
                "states_opaque": p.get("states_opaque", False),
                "states_opaque_reason": p.get("states_opaque_reason"),
                "src_any": p.get("src_any", False),
                "dst_any": p.get("dst_any", False),
                "svc_any": False,
                "src_negate": p.get("src_negate", False),
                "dst_negate": p.get("dst_negate", False),
                "svc_negate": False,
                "src_cidrs": src["cidrs"],
                "src_ips": src["ips"],
                "src_ranges": src["ranges"],
                "src_obj_count": src["count"],
                "src_opaque": src["opaque"],
                "src_opaque_reasons": src["reasons"],
                "dst_cidrs": dst["cidrs"],
                "dst_ips": dst["ips"],
                "dst_ranges": dst["ranges"],
                "dst_obj_count": dst["count"],
                "dst_opaque": dst["opaque"],
                "dst_opaque_reasons": dst["reasons"],
                "addr_opaque_reasons": src["reasons"] + dst["reasons"],
                "protos": [s.get("proto") for s in svcs],
                "ports": [s.get("ports") for s in svcs],
                "svc_protos": [s.get("proto") for s in svcs],
                "svc_port_specs": [s.get("ports") for s in svcs],
                "svc_obj_count": len(svcs),
                "svc_opaque": any(s.get("opaque") for s in svcs),
                "svc_opaque_reasons": [s["opaque_reason"] for s in svcs if s.get("opaque_reason")],
                "svc_src_port": any(s.get("src_port") for s in svcs),
                "src_ports": [s.get("src_port") for s in svcs],
                "svc_src_ports": [s.get("src_port") for s in svcs],
                "pol_uid": parent_uid,
                "pol_name": parent_uid,
            }
        )
    return sorted(rows, key=lambda r: r["pos"])


def _decide(batch, src: str, dst: str, port: int = 22, proto: str = "tcp"):
    """(rule uid, action) the forward chain decides for one flow, None on a fall-through."""
    hit = _first_match_point(
        _rows(batch, "vyos:gw:fw:ipv4-forward"), None, None, _intervals([src]), _intervals([dst]), port, proto
    )
    return None if hit is None else (hit[0]["uid"], hit[0]["action"])


def _rule(batch, num: int = 10) -> dict:
    return next(
        n.props for n in batch.nodes if n.label == "FwRule" and n.uid == f"vyos:gw:fw:ipv4-forward:{num}"
    )


# --- clauses the gate does not model ---


def test_an_accept_rule_matching_on_ipsec_is_undecided_not_an_unconditional_accept():
    """`ipsec match-ipsec` is how VyOS admits policy-based IPsec traffic."""
    batch = _batch(_forward({"10": {"action": "accept", "ipsec": {"match-ipsec": {}}}}))
    assert "ipsec" in _rule(batch)["states_opaque_reason"]
    assert _decide(batch, "198.51.100.9", "10.20.30.40") == ("vyos:gw:fw:ipv4-forward:10", INDETERMINATE)
    plain = _batch(
        _forward({"10": {"action": "accept", "protocol": "tcp", "log": {}, "destination": {"port": "22"}}})
    )
    assert "states_opaque" not in _rule(plain)
    assert _decide(plain, "198.51.100.9", "10.20.30.40") == ("vyos:gw:fw:ipv4-forward:10", "accept")


def test_connection_status_time_and_icmp_type_are_named_as_unmodelled():
    batch = _batch(
        _forward(
            {
                "10": {
                    "action": "accept",
                    "connection-status": {"nat": "destination"},
                    "time": {"weekdays": "Mon"},
                    "protocol": "icmp",
                    "icmp": {"type-name": "echo-request"},
                }
            }
        )
    )
    reason = _rule(batch)["states_opaque_reason"]
    assert all(k in reason for k in ("connection-status", "time", "icmp"))
    assert _decide(batch, "198.51.100.9", "10.20.30.40", None, "icmp")[1] == INDETERMINATE


def test_a_side_matched_by_fqdn_geoip_mac_or_domain_group_is_undecided():
    for side in (
        {"fqdn": "vpn.partner.example"},
        {"geoip": {"country-code": ["nl"]}},
        {"mac-address": "00:11:22:33:44:55"},
        {"group": {"domain-group": "PARTNERS"}},
        {"group": {"mac-group": "PRINTERS"}},
    ):
        batch = _batch(_forward({"10": {"action": "accept", "destination": side}}))
        assert _rule(batch)["states_opaque"] is True, side
        assert _decide(batch, "198.51.100.9", "10.20.30.40")[1] == INDETERMINATE, side


def test_an_unmodelled_clause_does_not_stop_a_plain_address_miss_from_being_skipped():
    """VyOS ANDs a rule's clauses, so a rule whose address misses the flow does
    not govern it whatever the unmodelled clause says: a later rule decides."""
    batch = _batch(
        _forward(
            {
                "10": {
                    "action": "accept",
                    "source": {"address": "192.0.2.0/24"},
                    "ipsec": {"match-ipsec": {}},
                },
                "20": {"action": "drop"},
            },
            default="accept",
        )
    )
    assert _decide(batch, "198.51.100.9", "10.20.30.40") == ("vyos:gw:fw:ipv4-forward:20", "drop")
    assert _decide(batch, "192.0.2.7", "10.20.30.40")[1] == INDETERMINATE


def test_a_source_port_group_is_undecided_not_read_as_any_source_port():
    """Only the destination port group is read into the service."""
    batch = _batch(
        _forward(
            {
                "10": {
                    "action": "accept",
                    "protocol": "tcp",
                    "destination": {"port": "22"},
                    "source": {"group": {"port-group": "P"}},
                }
            },
            groups={"port-group": {"P": {"port": "1024"}}},
        )
    )
    assert "source group port-group" in _rule(batch)["states_opaque_reason"]
    assert _decide(batch, "203.0.113.9", "10.20.30.40") == ("vyos:gw:fw:ipv4-forward:10", INDETERMINATE)
    dst = _batch(
        _forward(
            {"10": {"action": "accept", "protocol": "tcp", "destination": {"group": {"port-group": "P"}}}},
            groups={"port-group": {"P": {"port": "22"}}},
        )
    )
    assert "states_opaque" not in _rule(dst)
    assert _decide(dst, "203.0.113.9", "10.20.30.40") == ("vyos:gw:fw:ipv4-forward:10", "accept")


# --- negation ---


def test_a_negated_address_is_read_as_its_complement():
    """`!10.0.0.0/8` and `10.0.0.0/8` are two objects, and no Prefix carries the `!`."""
    batch = _batch(
        _forward(
            {
                "10": {
                    "action": "accept",
                    "source": {"address": "10.0.0.0/8"},
                    "destination": {"address": "10.9.9.9"},
                },
                "20": {"action": "drop", "source": {"address": "!10.0.0.0/8"}},
            },
            default="accept",
        )
    )
    assert _rule(batch, 20)["src_negate"] is True
    assert "src_negate" not in _rule(batch, 10)
    assert _decide(batch, "192.0.2.1", "10.9.9.9") == ("vyos:gw:fw:ipv4-forward:20", "drop")
    assert _decide(batch, "10.1.1.1", "10.9.9.9") == ("vyos:gw:fw:ipv4-forward:10", "accept")
    assert _decide(batch, "10.1.1.1", "10.8.8.8") is None  # the default decides
    cidrs = [n.props.get("cidr") for n in batch.nodes if n.label == "Prefix"]
    assert not any(str(c).startswith("!") for c in cidrs)


def test_a_negated_group_reference_points_at_the_group_and_negates_the_rule():
    groups = {"address-group": {"TRUSTED": {"address": ["10.0.0.5"]}}}
    batch = _batch(
        _forward(
            {
                "10": {"action": "drop", "source": {"group": {"address-group": "!TRUSTED"}}},
                "99": {"action": "accept"},
            },
            groups=groups,
        )
    )
    src = [r.end_uid for r in batch.rels if r.rel_type == "SRC" and r.start_uid.endswith(":10")]
    assert src == ["vyos:gw:grp:addr:TRUSTED"]
    assert _decide(batch, "192.0.2.66", "10.20.30.40") == ("vyos:gw:fw:ipv4-forward:10", "drop")
    assert _decide(batch, "10.0.0.5", "10.20.30.40") == ("vyos:gw:fw:ipv4-forward:99", "accept")


def test_a_side_mixing_negated_and_plain_matches_is_undecided():
    groups = {"network-group": {"LAN": {"network": ["10.0.0.0/8"]}}}
    batch = _batch(
        _forward(
            {
                "10": {
                    "action": "accept",
                    "source": {"address": "!10.1.0.0/16", "group": {"network-group": "LAN"}},
                }
            },
            groups=groups,
        )
    )
    assert "mixes negated and plain" in _rule(batch)["states_opaque_reason"]
    assert _decide(batch, "10.2.0.1", "10.20.30.40")[1] == INDETERMINATE


def test_a_v6_host_and_a_v6_prefix_with_the_same_digits_are_two_objects():
    fw = {
        "ipv6": {
            "forward": {
                "filter": {
                    "default-action": "accept",
                    "rule": {
                        "10": {"action": "drop", "destination": {"address": "2001:db8::32"}},
                        "20": {"action": "drop", "destination": {"address": "2001:db8::/32"}},
                    },
                }
            }
        }
    }
    batch = _batch(fw)
    dst = {r.start_uid: r.end_uid for r in batch.rels if r.rel_type == "DST"}
    assert dst["vyos:gw:fw:ipv6-forward:10"] != dst["vyos:gw:fw:ipv6-forward:20"]


# --- groups ---


def test_a_reference_to_an_undefined_group_is_undecided_not_a_rule_matching_nothing():
    batch = _batch(
        _forward(
            {
                "10": {"action": "drop", "source": {"group": {"address-group": "GHOST"}}},
                "99": {"action": "accept"},
            }
        )
    )
    ghost = next(n.props for n in batch.nodes if n.uid == "vyos:gw:grp:addr:GHOST")
    assert ghost["opaque"] is True and "GHOST" in ghost["opaque_reason"]
    assert _decide(batch, "192.0.2.66", "10.20.30.40")[1] == INDETERMINATE


def test_a_group_include_adds_the_included_members():
    groups = {
        "address-group": {
            "ALL-ADMINS": {"address": ["10.0.0.5"], "include": ["NOC"]},
            "NOC": {"address": ["10.0.0.6"]},
        }
    }
    batch = _batch(
        _forward(
            {"10": {"action": "accept", "source": {"group": {"address-group": "ALL-ADMINS"}}}}, groups=groups
        )
    )
    assert _decide(batch, "10.0.0.6", "10.20.30.40") == ("vyos:gw:fw:ipv4-forward:10", "accept")
    assert _decide(batch, "10.0.0.7", "10.20.30.40") is None


def test_a_negated_or_undefined_port_group_does_not_read_as_every_port():
    for ref in ("!WEB", "NOPE"):
        batch = _batch(
            _forward(
                {
                    "10": {
                        "action": "accept",
                        "protocol": "tcp",
                        "destination": {"group": {"port-group": ref}},
                    }
                },
                groups={"port-group": {"WEB": {"port": ["80", "443"]}}},
            )
        )
        assert _decide(batch, "198.51.100.9", "10.20.30.40", 22)[1] == INDETERMINATE, ref


# --- policy routes ---


def _pbr_batch(rule: dict):
    return _batch(
        interfaces={"ethernet": {"eth0": {"address": ["10.0.0.1/24"]}}},
        policy={"route": {"PBR": {"interface": "eth0", "rule": {"10": {**rule, "set": {"table": "100"}}}}}},
        protocols={"static": {"table": {"100": {"route": {"0.0.0.0/0": {"next-hop": {"10.0.0.254": {}}}}}}}},
    )


def test_a_policy_route_matching_on_an_unmodelled_clause_claims_the_flow_undecided():
    batch = _pbr_batch({"source": {"address": "10.0.0.0/24"}, "ipsec": {"match-ipsec": {}}})
    groups = partition_rules(
        _rows(batch, "vyos:gw:pbr:PBR"), _intervals(["10.0.0.5"]), _intervals(["198.51.100.9"]), None
    )
    claimed = [g for g in groups if g["rule_uid"]]
    assert claimed and claimed[0]["opaque"] is True
    assert "ipsec" in claimed[0]["opaque_reason"]


def test_a_policy_route_matching_on_a_source_port_group_claims_the_flow_undecided():
    batch = _pbr_batch({"source": {"address": "10.0.0.0/24", "group": {"port-group": "P"}}})
    groups = partition_rules(
        _rows(batch, "vyos:gw:pbr:PBR"), _intervals(["10.0.0.5"]), _intervals(["198.51.100.9"]), None
    )
    claimed = [g for g in groups if g["rule_uid"]]
    assert claimed and claimed[0]["opaque"] is True
    assert "source group port-group" in claimed[0]["opaque_reason"]


def test_a_negated_policy_route_source_claims_the_complement():
    batch = _pbr_batch({"source": {"address": "!10.0.0.0/25"}})
    groups = partition_rules(
        _rows(batch, "vyos:gw:pbr:PBR"), _intervals(["10.0.0.0/24"]), _intervals(["198.51.100.9"]), None
    )
    claimed = next(g for g in groups if g["rule_uid"])
    assert claimed["sources"] == _intervals(["10.0.0.128/25"])
    assert claimed["opaque"] is False


# --- zone membership ---


def _zone_contains(batch) -> set[tuple[str, str]]:
    return {(r.start_uid.rsplit(":", 1)[1], r.end_uid) for r in batch.rels if r.rel_type == "CONTAINS"}


def test_vyos_1_4_zone_interface_syntax_assigns_interfaces_to_zones():
    """1.4 writes `zone LAN interface eth1`; 1.5 writes it under `member`."""
    batch = _batch(
        {
            "zone": {
                "WAN": {"interface": "eth0", "default-action": "drop"},
                "LAN": {"interface": ["eth1"], "default-action": "drop"},
            }
        },
        interfaces={
            "ethernet": {"eth0": {"address": ["203.0.113.2/30"]}, "eth1": {"address": ["10.0.0.1/24"]}}
        },
    )
    contains = _zone_contains(batch)
    names = {z for z, _ in contains}
    assert names == {"WAN", "LAN"}
    assert len(contains) == 2


def test_zone_members_by_vrf_and_by_wildcard_are_read():
    batch = _batch(
        {
            "zone": {
                "BLUE": {"member": {"vrf": "BLUE"}},
                "LEGACY-BLUE": {"interface": "BLUE"},
                "ETH": {"member": {"interface": "eth*"}},
            }
        },
        interfaces={
            "ethernet": {
                "eth0": {"address": ["203.0.113.2/30"]},
                "eth1": {"address": ["10.0.0.1/24"], "vrf": "BLUE"},
            }
        },
        vrf={"name": {"BLUE": {"table": "100"}}},
    )
    contains = _zone_contains(batch)
    by_zone: dict[str, set[str]] = {}
    for zone, iface in contains:
        by_zone.setdefault(zone, set()).add(iface)
    assert len(by_zone["BLUE"]) == 1
    assert by_zone["BLUE"] == by_zone["LEGACY-BLUE"]
    assert len(by_zone["ETH"]) == 2


# --- a NAT rule's groups and interface scope -------------------------------------------


def _nat_rows(batch) -> list[dict]:
    """The NAT rule rows the gate reads (`_NAT_RULES_QUERY`), off a batch: each
    ORIG/XLATE column's addresses, a group's through its RESOLVES_TO targets."""
    props = {(n.label, n.uid): dict(n.props) for n in batch.nodes}
    rels = list(batch.rels)

    def column(rule_uid: str, rtype: str) -> tuple[list[str], bool, bool]:
        addrs: list[str] = []
        present = opaque = False
        for r in rels:
            if r.rel_type != rtype or r.start_uid != rule_uid:
                continue
            present = True
            target = props.get((r.end_label, r.end_uid)) or {}
            if r.end_label == "NetObject":
                opaque = opaque or bool(target.get("opaque"))
                for m in rels:
                    if m.rel_type == "RESOLVES_TO" and m.start_uid == r.end_uid:
                        t = props.get((m.end_label, m.end_uid)) or {}
                        addrs.append(t.get("cidr") or t.get("ip"))
                addrs += target.get("ranges") or []
            else:
                addrs.append(target.get("cidr") or target.get("ip"))
        return [a for a in addrs if a], present, opaque

    rows = []
    for n in batch.nodes:
        if n.label != "NatRule":
            continue
        p = n.props
        rb = n.uid.rsplit(":", 1)[0]
        row = {
            "rb_uid": rb,
            "rb_name": rb,
            "approximate": False,
            "owners": [],
            "install_on": [],
            "install_on_unresolved": False,
            "auto_generated": None,
            "uid": n.uid,
            "pos": p["position"],
            "kind": p["kind"],
            "method": None,
            "enabled": p.get("enabled", True),
            "exclude": p.get("exclude", False),
            "translation": p.get("translation"),
            "translation_port": p.get("translation_port"),
            "direction": None,
            "static_flag": False,
            "orig_src_raw": p.get("orig_src"),
            "orig_dst_raw": p.get("orig_dst"),
            "orig_src_port": p.get("orig_src_port"),
            "orig_dst_port": p.get("orig_dst_port"),
            "orig_port": None,
            "xlate_port": None,
            "protocol": p.get("protocol"),
            "in_if": p.get("in_if"),
            "out_if": p.get("out_if"),
            "translation_interface": None,
            "xlate_src_original": False,
            "xlate_dst_original": False,
            "rule_approximate": bool(p.get("approximate")),
            "approximate_reason": p.get("approximate_reason"),
        }
        for col, rtype in (
            ("orig_src", "ORIG_SRC"),
            ("orig_dst", "ORIG_DST"),
            ("xlate_src", "XLATE_SRC"),
            ("xlate_dst", "XLATE_DST"),
        ):
            row[f"{col}_addrs"], row[f"{col}_present"], row[f"{col}_opaque"] = column(n.uid, rtype)
        rows.append(row)
    return sorted(rows, key=lambda r: (r["rb_uid"], r["pos"]))


def _nat_batch(source_rules: dict, destination_rules: dict | None = None):
    nat: dict = {"source": {"rule": source_rules}}
    if destination_rules:
        nat["destination"] = {"rule": destination_rules}
    return _batch(
        _forward(
            {},
            groups={
                "network-group": {"LAN": {"network": ["10.1.0.0/24"]}},
                "port-group": {"WEB": {"port": ["80", "443"]}},
            },
        ),
        interfaces={
            "ethernet": {"eth0": {"address": ["203.0.113.2/30"]}, "eth1": {"address": ["10.9.0.1/24"]}},
        },
        nat=nat,
    )


def _snat(batch, egress: str, src: str) -> list[tuple[int | None, bool]]:
    """(rule position, opaque) of each part the sNAT stage on `egress` cuts the
    source into, None for the untranslated remainder."""
    rules = _nat_stage_rules(_nat_rows(batch), "snat", egress)
    parts = _nat_partition(rules, _intervals([src]), _intervals(["8.8.8.8"]), 443, "tcp")
    return [
        (p["rule"]["pos"] if p["rule"] else None, bool(p["rule"] and p["rule"].get("opaque"))) for p in parts
    ]


def test_a_nat_source_group_scopes_the_rule_to_its_members():
    batch = _nat_batch(
        {
            "10": {
                "outbound-interface": {"name": "eth0"},
                "source": {"group": {"network-group": "LAN"}},
                "translation": {"address": "masquerade"},
            }
        }
    )
    orig = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ORIG_SRC"}
    assert orig == {("vyos:gw:nat:source:10", "vyos:gw:grp:net:LAN")}
    assert _snat(batch, "eth0", "10.1.0.5") == [(10, False)]
    assert _snat(batch, "eth0", "192.168.50.10") == [(None, False)]


def test_a_nat_interface_group_leaves_the_rule_undecided():
    batch = _nat_batch(
        {
            "20": {
                "outbound-interface": {"group": "WAN"},
                "source": {"address": "10.2.0.0/24"},
                "translation": {"address": "198.51.100.7"},
            }
        }
    )
    [rule] = [n.props for n in batch.nodes if n.label == "NatRule"]
    assert rule["approximate"] is True
    assert rule["approximate_reason"] == "the rule's outbound-interface group WAN is not collected"
    assert _snat(batch, "eth0", "10.2.0.5") == [(20, True)]
    assert _snat(batch, "eth0", "10.3.0.5") == [(None, False)]
    [stage_rule] = _nat_stage_rules(_nat_rows(batch), "snat", "eth0")
    assert stage_rule["role_note"] == "the rule's outbound-interface group WAN is not collected"


def test_a_rule_without_an_unmodeled_scope_writes_it_as_false():
    """The loader's SET only adds."""
    batch = _nat_batch(
        {"10": {"source": {"address": "10.2.0.0/24"}, "translation": {"address": "masquerade"}}}
    )
    [rule] = [n.props for n in batch.nodes if n.label == "NatRule"]
    assert rule["approximate"] is False and rule["approximate_reason"] == ""


def test_a_negated_or_combined_nat_group_leaves_the_rule_undecided():
    batch = _nat_batch(
        {
            "10": {"source": {"group": {"network-group": "!LAN"}}, "translation": {"address": "masquerade"}},
            "11": {
                "source": {"address": "10.1.0.0/25", "group": {"network-group": "LAN"}},
                "translation": {"address": "masquerade"},
            },
            "12": {"source": {"group": {"domain-group": "CDN"}}, "translation": {"address": "masquerade"}},
        }
    )
    rules = {n.props["position"]: n.props for n in batch.nodes if n.label == "NatRule"}
    assert all(rules[pos]["approximate"] for pos in (10, 11, 12))
    assert "negated" in rules[10]["approximate_reason"]
    assert "more than one address constraint" in rules[11]["approximate_reason"]
    assert "domain-group CDN is not modeled" in rules[12]["approximate_reason"]


def test_a_nat_destination_port_group_is_the_rule_port():
    batch = _nat_batch(
        {},
        {
            "10": {
                "inbound-interface": {"name": "eth0"},
                "protocol": "tcp",
                "destination": {"group": {"port-group": "WEB"}},
                "translation": {"address": "10.9.0.10"},
            }
        },
    )
    [rule] = [n.props for n in batch.nodes if n.label == "NatRule"]
    assert rule["orig_dst_port"] == "80,443" and rule["approximate"] is False


def test_a_wildcard_or_negated_nat_interface_is_matched_as_the_firewall_matches_it():
    batch = _nat_batch(
        {
            "30": {
                "outbound-interface": {"name": "!eth1"},
                "source": {"address": "10.3.0.0/24"},
                "translation": {"address": "masquerade"},
            },
            "40": {
                "outbound-interface": {"name": "eth*"},
                "source": {"address": "10.4.0.0/24"},
                "translation": {"address": "masquerade"},
            },
        }
    )
    assert _snat(batch, "eth0", "10.3.0.5") == [(30, False)]
    assert _snat(batch, "eth1", "10.3.0.5") == [(None, False)]
    assert _snat(batch, "eth0", "10.4.0.5") == [(40, False)]
    assert _snat(batch, "ppp0", "10.4.0.5") == [(None, False)]


def test_the_analysis_model_binds_a_wildcard_nat_interface_as_the_gate_does():
    batch = _nat_batch(
        {
            "30": {
                "outbound-interface": {"name": "!eth1"},
                "source": {"address": "10.3.0.0/24"},
                "translation": {"address": "198.51.100.7"},
            }
        }
    )
    graph = _inventory(batch)

    def specs(egress: str):
        return normalize_nat_rules(
            graph,
            "dev:gw",
            ingress_interface_uid=None,
            egress_interface_uid=uid.interface("dev:gw", egress),
            address_family=4,
        )

    [on_eth0] = specs("eth0")
    assert on_eth0.predicate != Constant(False) and on_eth0.rewrites
    [on_eth1] = specs("eth1")
    assert on_eth1.predicate == Constant(False)


# --- `action jump` evaluates the named ruleset it names ---------------------------------


def _jump_batch(rules: dict, named: dict, default: str = "accept"):
    fw = _forward(rules, default)
    fw["ipv4"]["name"] = named
    return _batch(
        fw,
        interfaces={
            "ethernet": {"eth0": {"address": ["203.0.113.2/30"]}, "eth1": {"address": ["10.0.0.1/24"]}}
        },
    )


def _serve_rules(monkeypatch, batch) -> None:
    """Answer the gate's rule and jump-target reads off `batch`."""
    rulebases = {n.uid: n.props for n in batch.nodes if n.label == "FwRulebase"}

    def read(session, query, **params):
        if query == firewall._JUMP_TARGET:
            p = rulebases.get(params["rb"])
            if p is None:
                return []
            return [
                {
                    "rb_uid": params["rb"],
                    "rb_name": p.get("name"),
                    "default_action": p.get("default_action"),
                    "default_action_unknown": bool(p.get("default_action_unknown")),
                    "default_jump_target": p.get("default_jump_target"),
                }
            ]
        if query == firewall._RULEBASE_RULES:
            return _rows(batch, params["rb"]) if params["rb"] in rulebases else []
        raise AssertionError(query)

    monkeypatch.setattr(firewall._path, "_read", read)


def _jump_decide(
    batch, dst: str, in_name: str = "eth0", port: int = 22
) -> tuple[str, str, str | None] | None:
    """(rule uid, action, undecided reason) the forward chain decides, jumps
    expanded, None on a fall-through."""
    rows = firewall._rule_rows(None, "vyos:gw:fw:ipv4-forward")
    hit = _first_match_point(
        rows, in_name, None, _intervals(["198.51.100.1"]), _intervals([dst]), port, "tcp"
    )
    return None if hit is None else (hit[0]["uid"], hit[0]["action"], hit[0].get("indeterminate_reason"))


WAN_IN_SSH = {"action": "accept", "protocol": "tcp", "destination": {"address": "10.0.0.5", "port": "22"}}
JUMP_ETH0 = {"action": "jump", "jump-target": "WAN-IN", "inbound-interface": {"name": "eth0"}}


def test_a_jump_rule_evaluates_its_target_ruleset(monkeypatch):
    batch = _jump_batch(
        {"10": JUMP_ETH0, "20": {"action": "drop"}},
        {"WAN-IN": {"default-action": "drop", "rule": {"10": WAN_IN_SSH}}},
    )
    rule = _rule(batch)
    assert rule["action"] == "jump" and rule["jump_target"] == "vyos:gw:fw:WAN-IN"
    _serve_rules(monkeypatch, batch)
    # a rule of the target decides
    assert _jump_decide(batch, "10.0.0.5") == ("vyos:gw:fw:WAN-IN:10", "accept", None)
    # the target's default action decides what none of its rules match
    assert _jump_decide(batch, "10.0.0.6") == ("vyos:gw:fw:ipv4-forward:10", "drop", None)
    # a flow the jump rule does not match continues in the chain
    assert _jump_decide(batch, "10.0.0.5", in_name="eth1") == ("vyos:gw:fw:ipv4-forward:20", "drop", None)


def test_a_target_default_of_return_continues_after_the_jump(monkeypatch):
    batch = _jump_batch(
        {"10": JUMP_ETH0, "20": {"action": "accept"}},
        {"WAN-IN": {"default-action": "return", "rule": {"10": {**WAN_IN_SSH, "action": "drop"}}}},
    )
    _serve_rules(monkeypatch, batch)
    assert _jump_decide(batch, "10.0.0.5") == ("vyos:gw:fw:WAN-IN:10", "drop", None)
    assert _jump_decide(batch, "10.0.0.6") == ("vyos:gw:fw:ipv4-forward:20", "accept", None)


def test_a_target_with_no_recorded_default_is_undecided(monkeypatch):
    batch = _jump_batch(
        {"10": JUMP_ETH0, "20": {"action": "accept"}}, {"WAN-IN": {"rule": {"10": WAN_IN_SSH}}}
    )
    _serve_rules(monkeypatch, batch)
    assert _jump_decide(batch, "10.0.0.6") == (
        "vyos:gw:fw:ipv4-forward:10",
        INDETERMINATE,
        "the default action of jumped ruleset WAN-IN is not recorded",
    )


def test_a_target_stating_no_default_and_no_marker_is_undecided_not_a_drop(monkeypatch):
    monkeypatch.setattr(
        firewall._path, "_read_one", lambda s, q, **p: {"rb_name": "WAN-IN", "default_action": None}
    )
    monkeypatch.setattr(firewall._path, "_read", lambda s, q, **p: [])
    jump = {"uid": "fw:10", "pos": 10, "action": "jump", "name": None}
    rows = firewall._jumped(None, jump, "vyos:gw:fw:WAN-IN", ("vyos:gw:fw:ipv4-forward",), "q")
    assert len(rows) == 1
    assert rows[0]["action"] == "jump" and rows[0]["states_opaque"] is True
    assert rows[0]["states_opaque_reason"] == (
        "the collection states neither the default action nor that it is unrecorded"
    )


def test_a_target_default_jump_is_followed(monkeypatch):
    batch = _jump_batch(
        {"10": JUMP_ETH0},
        {
            "WAN-IN": {"default-action": "jump", "default-jump-target": "LAST", "rule": {"10": WAN_IN_SSH}},
            "LAST": {"default-action": "reject"},
        },
    )
    _serve_rules(monkeypatch, batch)
    assert _jump_decide(batch, "10.0.0.6") == ("vyos:gw:fw:ipv4-forward:10", "reject", None)


def test_a_return_rule_in_the_target(monkeypatch):
    """A return that matches every flow ends the target for all of them; one
    scoped to some flows ends it only for those, which no first-match row
    expresses, so the flows it matches are undecided."""
    batch = _jump_batch(
        {"10": JUMP_ETH0, "20": {"action": "accept"}},
        {
            "WAN-IN": {
                "default-action": "drop",
                "rule": {"5": {"action": "return", "destination": {"address": "10.0.0.7"}}, "10": WAN_IN_SSH},
            },
        },
    )
    _serve_rules(monkeypatch, batch)
    uid_, action, reason = _jump_decide(batch, "10.0.0.7")
    assert (uid_, action) == ("vyos:gw:fw:WAN-IN:5", INDETERMINATE)
    assert reason == "rule 5 of jumped ruleset WAN-IN returns on a match, which is not modeled"
    assert _jump_decide(batch, "10.0.0.5") == ("vyos:gw:fw:WAN-IN:10", "accept", None)
    every = _jump_batch(
        {"10": JUMP_ETH0, "20": {"action": "accept"}},
        {"WAN-IN": {"default-action": "drop", "rule": {"5": {"action": "return"}, "10": WAN_IN_SSH}}},
    )
    _serve_rules(monkeypatch, every)
    assert _jump_decide(every, "10.0.0.5") == ("vyos:gw:fw:ipv4-forward:20", "accept", None)


def test_a_jump_loop_or_an_undefined_target_is_undecided(monkeypatch):
    loop = _jump_batch(
        {"10": JUMP_ETH0, "20": {"action": "accept"}},
        {"WAN-IN": {"default-action": "drop", "rule": {"10": {"action": "jump", "jump-target": "WAN-IN"}}}},
    )
    _serve_rules(monkeypatch, loop)
    _uid, action, reason = _jump_decide(loop, "10.0.0.5")
    assert action == INDETERMINATE and reason and "loop" in reason
    missing = _jump_batch({"10": {**JUMP_ETH0, "jump-target": "GHOST"}, "20": {"action": "accept"}}, {})
    _serve_rules(monkeypatch, missing)
    assert _jump_decide(missing, "10.0.0.5") == (
        "vyos:gw:fw:ipv4-forward:10",
        INDETERMINATE,
        "the rule jumps to ruleset vyos:gw:fw:GHOST, which is not collected",
    )


def test_a_dimension_both_the_jump_and_the_target_rule_match_on_is_undecided(monkeypatch):
    batch = _jump_batch(
        {"10": {**JUMP_ETH0, "destination": {"address": "10.0.0.0/24"}}, "20": {"action": "accept"}},
        {"WAN-IN": {"default-action": "drop", "rule": {"10": WAN_IN_SSH}}},
    )
    _serve_rules(monkeypatch, batch)
    uid_, action, reason = _jump_decide(batch, "10.0.0.5")
    assert (uid_, action) == ("vyos:gw:fw:WAN-IN:10", INDETERMINATE)
    assert reason == (
        "the jump rule and rule 10 of ruleset WAN-IN both match on destination addresses, "
        "which is not modeled"
    )
    assert _jump_decide(batch, "10.9.0.1") == ("vyos:gw:fw:ipv4-forward:20", "accept", None)
    assert _jump_decide(batch, "10.0.0.9", port=80) == ("vyos:gw:fw:ipv4-forward:10", "drop", None)


def _port_forward_specs(af, address_family):
    """A VyOS `nat destination` port forward with no destination address."""
    batch = _nat_batch(
        {},
        {
            "10": {
                "inbound-interface": {"name": "eth0"},
                "protocol": "tcp",
                "destination": {"port": "443"},
                "translation": {"address": "10.1.0.10"},
            }
        },
    )
    for node in batch.nodes:
        if node.label == "NatRule":
            node.props["af"] = af
    return normalize_nat_rules(
        _inventory(batch),
        "dev:gw",
        ingress_interface_uid=uid.interface("dev:gw", "eth0"),
        egress_interface_uid=None,
        address_family=address_family,
    )


def test_the_analysis_model_never_applies_an_ipv4_nat_rule_to_an_ipv6_model():
    [dnat] = [s for s in _port_forward_specs(4, 6) if s.stage == "dnat"]
    assert dnat.predicate == Constant(False)
    assert not dnat.rewrites


def test_the_analysis_model_keeps_a_rule_of_the_model_family_and_a_row_with_no_family():
    same = _port_forward_specs(4, 4)
    assert same == _port_forward_specs(None, 4)
    [dnat] = [s for s in same if s.stage == "dnat"]
    assert dnat.predicate != Constant(False) and dnat.rewrites
    assert _port_forward_specs(None, 6) == _port_forward_specs(4, 6)


def test_the_analysis_model_derives_the_family_of_a_row_without_af_as_the_tracer_does():
    [dnat] = [s for s in _port_forward_specs(None, 6) if s.stage == "dnat"]
    assert dnat.predicate == Constant(False)
    batch = _nat_batch(
        {"10": {"outbound-interface": {"name": "eth0"}, "translation": {"address": "masquerade"}}}
    )
    for node in batch.nodes:
        if node.label == "NatRule":
            node.props["af"] = None  # a row without the property
    for family in (4, 6):
        [snat] = normalize_nat_rules(
            _inventory(batch),
            "dev:gw",
            ingress_interface_uid=None,
            egress_interface_uid=uid.interface("dev:gw", "eth0"),
            address_family=family,
        )
        assert snat.predicate != Constant(False)
