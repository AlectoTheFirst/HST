"""The address family of a VyOS policy route and NAT rule."""

from tests.test_vyos_match_clauses import _rows

from hst.collectors.vyos import normalize_vyos
from hst.path.addrsets import _intervals
from hst.path.gates.firewall import _NO_ADDRESS_REASON
from hst.path.gates.pbr import partition_rules

VERSION = "Version:          VyOS 1.4.0\nHardware S/N:     0000"
TABLE = {"100": {"route": {"0.0.0.0/0": {"next-hop": {"10.0.0.254": {}}}}}}


def _batch(policy: dict, nat: dict | None = None, groups: dict | None = None):
    cfg = {
        "system": {"host-name": "gw"},
        "interfaces": {"ethernet": {"eth0": {"address": ["10.0.0.1/24", "2001:db8::1/64"]}}},
        "firewall": {"group": groups} if groups else {},
        "policy": policy,
        "protocols": {"static": {"table": TABLE}},
        **({"nat": nat} if nat else {}),
    }
    return normalize_vyos({"config": cfg, "version_text": VERSION, "links": []}, l3dom="dc1")


def _policy_rows(batch, *, with_af: bool = True) -> list[dict]:
    """The rows `_INTERFACE_POLICY_RULES` returns for eth0, in policy name and
    rule position order."""
    props = {n.uid: dict(n.props) for n in batch.nodes if n.label == "PbrPolicy"}
    rows = []
    for pol_uid in sorted(props, key=lambda u: props[u]["name"]):
        for row in _rows(batch, pol_uid):
            row["pol_name"] = props[pol_uid]["name"]
            row["pol_af"] = props[pol_uid].get("af") if with_af else None
            rows.append(row)
    return sorted(rows, key=lambda r: (r["pol_name"], r["pos"]))


def _catch_all(table: str = "100") -> dict:
    return {"interface": "eth0", "rule": {"10": {"set": {"table": table}}}}


def _claims(groups: list[dict]) -> list[tuple[str, list]]:
    return [(g["pol_name"], g["sources"]) for g in groups if g["rule_uid"]]


V4_SRC, V4_DST = _intervals(["10.0.0.5"]), _intervals(["198.51.100.9"])
V6_SRC, V6_DST = _intervals(["2001:db8::5"]), _intervals(["2001:db8:1::9"])


def test_a_policy_route_and_a_policy_route6_of_one_name_are_two_policies_with_their_family():
    batch = _batch({"route": {"VPN": _catch_all()}, "route6": {"VPN": _catch_all()}})
    policies = {n.uid: n.props.get("af") for n in batch.nodes if n.label == "PbrPolicy"}
    assert policies == {"vyos:gw:pbr:VPN": 4, "vyos:gw:pbr:ipv6:VPN": 6}
    rules = sorted(n.uid for n in batch.nodes if n.label == "FwRule")
    assert rules == ["vyos:gw:pbr:VPN:10", "vyos:gw:pbr:ipv6:VPN:10"]


def test_a_catch_all_policy_route_claims_no_ipv6_flow():
    batch = _batch({"route": {"VPN": _catch_all()}})
    groups = partition_rules(_policy_rows(batch), V6_SRC, V6_DST, "vrf:main")
    assert _claims(groups) == []
    assert [g["table_uid"] for g in groups] == ["vrf:main"]
    groups = partition_rules(_policy_rows(batch), V4_SRC, V4_DST, "vrf:main")
    assert _claims(groups) == [("VPN", V4_SRC)]
    assert not groups[0]["opaque"]


def test_a_catch_all_policy_route6_read_first_claims_no_ipv4_flow():
    # "A6" sorts before "B4", so the route6 rule is read before the IPv4 one
    batch = _batch({"route": {"B4": _catch_all()}, "route6": {"A6": _catch_all()}})
    groups = partition_rules(_policy_rows(batch), V4_SRC, V4_DST, "vrf:main")
    assert _claims(groups) == [("B4", V4_SRC)]
    groups = partition_rules(_policy_rows(batch), V6_SRC, V6_DST, "vrf:main")
    assert _claims(groups) == [("A6", V6_SRC)]


def test_a_flow_set_of_both_families_is_split_by_the_policy_family():
    batch = _batch({"route": {"VPN": _catch_all()}})
    groups = partition_rules(_policy_rows(batch), V4_SRC + V6_SRC, V4_DST + V6_DST, "vrf:main")
    claimed = [g for g in groups if g["rule_uid"]]
    assert [(g["sources"], g["dst"]) for g in claimed] == [(V4_SRC, V4_DST)]
    rest = [s for g in groups if not g["rule_uid"] for s in g["sources"]]
    assert V6_SRC[0] in rest


def test_data_without_af_keeps_the_catch_all_reading():
    batch = _batch({"route": {"VPN": _catch_all()}})
    groups = partition_rules(_policy_rows(batch, with_af=False), V6_SRC, V6_DST, "vrf:main")
    assert _claims(groups) == [("VPN", V6_SRC)]


def test_data_without_af_scopes_a_stated_address_match_by_its_family():
    policy = {
        "interface": "eth0",
        "rule": {"10": {"source": {"address": "!10.9.0.0/16"}, "set": {"table": "100"}}},
    }
    batch = _batch({"route": {"VPN": policy}})
    rows = _policy_rows(batch, with_af=False)
    assert _claims(partition_rules(rows, V6_SRC, V6_DST, "vrf:main")) == []
    assert _claims(partition_rules(rows, V4_SRC, V4_DST, "vrf:main")) == [("VPN", V4_SRC)]


def test_nat_and_nat66_rules_carry_their_family():
    nat = {
        "source": {
            "rule": {"10": {"outbound-interface": {"name": "eth0"}, "translation": {"address": "masquerade"}}}
        }
    }
    batch = normalize_vyos(
        {
            "config": {
                "system": {"host-name": "gw"},
                "interfaces": {"ethernet": {"eth0": {"address": ["10.0.0.1/24"]}}},
                "nat": nat,
                "nat66": nat,
            },
            "version_text": VERSION,
            "links": [],
        },
        l3dom="dc1",
    )
    rules = {n.uid: n.props.get("af") for n in batch.nodes if n.label == "NatRule"}
    assert rules == {"vyos:gw:nat:source:10": 4, "vyos:gw:nat66:source:10": 6}


def test_a_policy_route_on_an_address_group_with_no_member_claims_undecided():
    """The group is defined and has no address: the router's set is empty, so
    the rule is not "any source". The firewall gate reads it undecided."""
    policy = {
        "interface": "eth0",
        "rule": {"10": {"source": {"group": {"address-group": "EMPTY"}}, "set": {"table": "100"}}},
    }
    batch = _batch({"route": {"VPN": policy}}, groups={"address-group": {"EMPTY": {}}})
    groups = partition_rules(_policy_rows(batch), V4_SRC, V4_DST, "vrf:main")
    claimed = [g for g in groups if g["rule_uid"]]
    assert claimed and claimed[0]["opaque"] is True
    assert claimed[0]["opaque_reason"] == _NO_ADDRESS_REASON


def test_a_policy_route_on_an_address_group_with_members_stays_decided():
    policy = {
        "interface": "eth0",
        "rule": {"10": {"source": {"group": {"address-group": "LAN"}}, "set": {"table": "100"}}},
    }
    batch = _batch({"route": {"VPN": policy}}, groups={"address-group": {"LAN": {"address": ["10.0.0.5"]}}})
    groups = partition_rules(_policy_rows(batch), V4_SRC, V4_DST, "vrf:main")
    assert _claims(groups) == [("VPN", V4_SRC)]
    assert groups[0]["opaque"] is False


def test_a_policy_route_address_the_gate_cannot_parse_claims_undecided():
    row = {
        "pol_uid": "pbr:X",
        "pol_name": "X",
        "pol_af": 4,
        "rule_uid": "pbr:X:10",
        "pos": 10,
        "src_ips": ["not-an-address"],
        "src_obj_count": 1,
        "table_uid": "vrf:100",
    }
    groups = partition_rules([row], V4_SRC, V4_DST, "vrf:main")
    claimed = [g for g in groups if g["rule_uid"]]
    assert claimed and claimed[0]["opaque_reason"] == _NO_ADDRESS_REASON
