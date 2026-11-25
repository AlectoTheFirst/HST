"""An object of a proposed rule that does not resolve to what it names is refused (`ProposalError`)."""

from typing import Any

import pytest

from hst.path.gates.firewall import _RULEBASE_RULES, _first_match
from hst.simul.fw_overlay import Catalog, ChangeSet, ProposalError, parse_intents

_SRC = [(4, 0x0A000005, 0x0A000005)]  # 10.0.0.5
_DST = [(4, 0xC0A80223, 0xC0A80223)]  # 192.168.2.35


def _svc(uid: str, name: str, **fields: Any) -> dict[str, Any]:
    return {"uid": uid, "name": name, "protos": [], "ports": [], "members": [], **fields}


CATALOG = Catalog(
    net_objects={
        "no:fqdn": {"uid": "no:fqdn", "name": "FQDN-GROUP", "addrs": ["10.4.0.1"], "members": ["no:dyn"]},
        "no:dyn": {
            "uid": "no:dyn",
            "name": "DYN",
            "addrs": [],
            "members": [],
            "opaque": True,
            "opaque_reason": "an FQDN object",
        },
        "no:opaque_group": {
            "uid": "no:opaque_group",
            "name": "OPAQUE-GROUP",
            "addrs": ["10.4.0.2"],
            "members": [],
            "opaque": True,
            "opaque_reason": "a member is an FQDN object",
        },
        "no:dangling": {
            "uid": "no:dangling",
            "name": "DANGLING",
            "addrs": ["10.4.0.3"],
            "members": ["no:gone"],
        },
        "no:fine": {"uid": "no:fine", "name": "FINE", "addrs": ["10.4.0.4"], "members": []},
    },
    svc_objects={
        "so:ssh": _svc("so:ssh", "SSH", protos=["tcp"], ports=["22"]),
        "so:https": _svc("so:https", "HTTPS", protos=["tcp"], ports=["443"]),
        "so:dns": _svc("so:dns", "DNS", protos=["udp"], ports=["53"]),
        "so:web": _svc("so:web", "Web_Services", members=["so:https", "so:inner"]),
        "so:inner": _svc("so:inner", "Inner", members=["so:dns", "so:ssh"]),
        "so:cycle_a": _svc("so:cycle_a", "CycleA", members=["so:cycle_b"], protos=["tcp"], ports=["1"]),
        "so:cycle_b": _svc("so:cycle_b", "CycleB", members=["so:cycle_a"], protos=["tcp"], ports=["2"]),
        "so:empty": _svc("so:empty", "Empty"),
        "so:app": _svc("so:app", "App", opaque=True, opaque_reason="matched by application control"),
        "so:range": _svc(
            "so:range",
            "Range",
            protos=["tcp"],
            ports=[">1023"],
            opaque=True,
            opaque_reason="relational port spec",
        ),
        "so:mixed": _svc("so:mixed", "Mixed", members=["so:https", "so:app"]),
        "so:dangling": _svc("so:dangling", "Dangling", members=["so:https", "so:gone"]),
        "so:sport": _svc("so:sport", "FromHigh", protos=["tcp"], ports=["80"], src_port="1024-65535"),
        "so:sport_only": _svc("so:sport_only", "SportOnly", src_port="53"),
    },
)

PERMIT = {"rulebase": "fw:LAN", "position": 10, "action": "accept", "source": "any", "destination": "any"}


def _rows(params: dict[str, Any], collected: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    intents = [{"kind": "fw_rule.add", "params": params}]
    changes = ChangeSet(intents=parse_intents(intents, CATALOG), catalog=CATALOG)
    return changes.rewrite(_RULEBASE_RULES, {"rb": "fw:LAN"}, collected or [])


def test_a_service_group_is_the_union_of_its_members_not_every_service():
    (row,) = _rows({**PERMIT, "services": "Web_Services"})
    assert row["svc_any"] is False
    assert sorted(zip(row["protos"], row["ports"], strict=True)) == [
        ("tcp", "22"),
        ("tcp", "443"),
        ("udp", "53"),
    ]


@pytest.mark.parametrize(
    ("port", "proto", "matched"), [(22, "tcp", True), (53, "udp", True), (3306, "tcp", False)]
)
def test_the_gate_matches_the_groups_members_and_no_other_port(port, proto, matched):
    (row,) = _rows({**PERMIT, "services": "Web_Services"})
    assert (_first_match([row], None, None, _SRC, _DST, port, proto) is not None) is matched


@pytest.mark.parametrize("service", ["Empty", "App", "Range", "Mixed", "Dangling", "SportOnly"])
def test_a_service_that_does_not_resolve_to_protocols_and_ports_in_full_is_refused(service):
    with pytest.raises(ProposalError, match="does not resolve to protocols and ports"):
        _rows({**PERMIT, "services": service})


def test_the_refusal_names_why_the_service_does_not_resolve():
    with pytest.raises(ProposalError, match="matched by application control"):
        _rows({**PERMIT, "services": "Mixed"})
    with pytest.raises(ProposalError, match="relational port spec"):
        _rows({**PERMIT, "services": "Range"})
    with pytest.raises(ProposalError, match="scoped to a source port only"):
        _rows({**PERMIT, "services": "SportOnly"})


def test_a_service_membership_cycle_is_cut():
    (row,) = _rows({**PERMIT, "services": "CycleA"})
    assert sorted(row["ports"]) == ["1", "2"]


def test_a_service_scoped_to_a_source_port_carries_it_beside_its_destination_port():
    (row,) = _rows({**PERMIT, "services": "FromHigh", "ports": "8080", "protocols": "udp"})
    assert list(zip(row["protos"], row["ports"], row["src_ports"], strict=True)) == [
        ("udp", "8080", None),
        ("tcp", "80", "1024-65535"),
    ]
    assert row["svc_src_port"] is True


def test_a_modified_rule_naming_a_group_takes_its_members_and_an_opaque_one_is_refused():
    base = {"uid": "r:10", "pos": 10, "action": "accept", "svc_any": True, "protos": [], "ports": []}

    def modify(service: str) -> list[dict[str, Any]]:
        intent = {
            "kind": "fw_rule.modify",
            "params": {"rulebase": "fw:LAN", "rule": "r:10", "services": service},
        }
        changes = ChangeSet(intents=parse_intents([intent], CATALOG), catalog=CATALOG)
        return changes.rewrite(_RULEBASE_RULES, {"rb": "fw:LAN"}, [base])

    (row,) = modify("Web_Services")
    assert row["svc_any"] is False
    assert sorted(row["ports"]) == ["22", "443", "53"]
    with pytest.raises(ProposalError, match="matched by application control"):
        modify("Mixed")


@pytest.mark.parametrize(
    ("token", "why"),
    [
        ("FQDN-GROUP", "an FQDN object"),
        ("OPAQUE-GROUP", "a member is an FQDN object"),
        ("DANGLING", "not in this snapshot"),
    ],
)
def test_a_netobject_group_that_resolves_only_in_part_is_refused(token, why):
    params = {"rulebase": "fw:LAN", "position": 10, "action": "drop", "source": "any", "destination": token}
    with pytest.raises(ProposalError, match=why):
        _rows(params)


def test_a_netobject_that_resolves_in_full_is_proposed():
    params = {"rulebase": "fw:LAN", "position": 10, "action": "drop", "source": "any", "destination": "FINE"}
    (row,) = _rows(params)
    assert row["dst_cidrs"] == ["10.4.0.4"]
