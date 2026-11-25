"""Strict symbolic ZPA and load-balancer choices remain correlated and complete."""

# ruff: noqa: F811 -- imported graph is the shared scripted graph fixture

from tests.test_path_trace import graph  # noqa: F401

from hst.path.addrsets import _intervals, _ports
from hst.path.gates.lb import LbTransition, _lb_snat, _member_regions
from hst.path.gates.zpa import ZpaTransition
from hst.path.state import FlowRegion

TCP = frozenset({6})


def _region(*, port="443", proto=TCP):
    return FlowRegion.from_query(
        _intervals(["10.0.0.5"]),
        _intervals(["198.51.100.10"]),
        proto,
        None if port is None else _ports(port),
    )


def _vs(uid="vs:web", *, port=443, snat_mode="none"):
    return {
        "uid": uid,
        "name": uid,
        "kind": "lb",
        "proto": "tcp",
        "port": port,
        "snat_mode": snat_mode,
    }


def _member(uid, ip, state="up"):
    return {"uid": uid, "name": uid, "port": 8443, "state": state, "ip": ip}


def _prepare_zpa(graph):
    segment, identity = "seg:web", "idg:staff"
    graph.segment_ports[segment] = {"tcp": ["443", "443"], "udp": None}
    graph.access_rules[(identity, segment)] = [
        {
            "uid": "rule:allow",
            "name": "allow",
            "position": 1,
            "action": "ALLOW",
            "applies_to_all_identities": False,
            "conditions": None,
            "identity_named": True,
        }
    ]
    graph.segment_resolution[segment] = [{"addr": "10.1.0.5"}, {"addr": "10.1.0.6"}]
    return segment, identity


def test_strict_zpa_enumerates_connector_addresses_and_destinations(graph):
    segment, identity = _prepare_zpa(graph)
    graph.zpa_connectors[segment] = [
        {"uid": "conn:up", "name": "up", "health": "UP"},
        {"uid": "conn:mystery", "name": "mystery", "health": "WARMING"},
    ]
    graph.connector_address["conn:up"] = [
        {"host_uid": "host:1", "ip": "192.0.2.10"},
        {"host_uid": "host:1", "ip": "192.0.2.11"},
    ]

    out = ZpaTransition(None, identity, segment, all_connectors=True).apply(_region())
    brokered = [(r.rects[0], e) for r, e in out if e.kind == "broker"]
    unknown = [e for _r, e in out if e.kind == "indeterminate"]

    assert len(brokered) == 4
    assert {(e.data["address"], e.data["destination"]) for _r, e in brokered} == {
        ("192.0.2.10", "10.1.0.5"),
        ("192.0.2.10", "10.1.0.6"),
        ("192.0.2.11", "10.1.0.5"),
        ("192.0.2.11", "10.1.0.6"),
    }
    assert len(unknown) == 1 and "health is not recognized" in unknown[0].reason


def test_strict_zpa_all_recorded_connectors_down_is_terminal(graph):
    segment, identity = _prepare_zpa(graph)
    graph.zpa_connectors[segment] = [
        {"uid": "conn:a", "name": "a", "health": "down"},
        {"uid": "conn:b", "name": "b", "health": "unhealthy"},
    ]
    out = ZpaTransition(None, identity, segment, all_connectors=True).apply(_region())
    assert [(e.kind, e.terminal) for _r, e in out] == [("deny", True)]


def test_strict_zpa_counts_a_disabled_connector_as_down(graph):
    segment, identity = _prepare_zpa(graph)
    graph.zpa_connectors[segment] = [{"uid": "conn:a", "name": "a", "health": "up", "enabled": False}]
    out = ZpaTransition(None, identity, segment, all_connectors=True).apply(_region())
    assert [(e.kind, e.terminal) for _r, e in out] == [("deny", True)]


def test_strict_zpa_does_not_test_an_unstated_service(graph):
    segment, identity = _prepare_zpa(graph)
    out = ZpaTransition(None, identity, segment, all_connectors=True).apply(_region(port=None, proto=None))
    assert len(out) == 1
    assert out[0][1].kind == "indeterminate"
    assert out[0][1].unknown == frozenset({"proto", "dport"})


def test_strict_lb_keeps_unknown_health_as_a_separate_successor(graph):
    vs = _vs()
    graph.pool_members[vs["uid"]] = [
        _member("member:up", "10.2.0.5"),
        _member("member:unknown", "10.2.0.6", "starting"),
    ]
    out = LbTransition(None, "dev:lb", [vs], "198.51.100.10", require_known_health=True).apply(_region())
    assert [e.kind for _r, e in out] == ["relate", "indeterminate"]
    assert out[1][0].rects[0].dst == tuple(_intervals(["10.2.0.6"]))


def test_strict_lb_all_members_down_is_terminal(graph):
    vs = _vs()
    graph.pool_members[vs["uid"]] = [
        _member("member:a", "10.2.0.5", "down"),
        _member("member:b", "10.2.0.6", "down"),
    ]
    out = LbTransition(None, "dev:lb", [vs], "198.51.100.10", require_known_health=True).apply(_region())
    assert [(e.kind, e.terminal) for _r, e in out] == [("deny", True)]


def test_strict_lb_splits_exclusive_and_overlapping_service_regions(graph):
    left, right = _vs("vs:left", port="80-90"), _vs("vs:right", port="85-95")
    graph.pool_members[left["uid"]] = [_member("member:left", "10.2.0.5")]
    graph.pool_members[right["uid"]] = [_member("member:right", "10.2.0.6")]
    out = LbTransition(None, "dev:lb", [left, right], "198.51.100.10", require_known_health=True).apply(
        _region(port="80-95")
    )

    related_ports = {r.rects[0].request.dport for r, e in out if e.kind == "relate"}
    ambiguous = [r.rects[0] for r, e in out if e.kind == "indeterminate" and "multiple" in e.reason]
    assert related_ports == {tuple(_ports("80-84")), tuple(_ports("91-95"))}
    assert [r.dport for r in ambiguous] == [tuple(_ports("85-90"))]


def test_strict_lb_rejects_ambiguous_snat_candidates(monkeypatch):
    monkeypatch.setattr(
        "hst.path.gates.lb._path._read",
        lambda *_args, **_kwargs: [{"ip": "192.0.2.1"}, {"ip": "192.0.2.2"}],
    )
    source = list(_intervals(["10.0.0.5"]))
    actual, reason, unknown = _lb_snat(
        None,
        _vs(snat_mode="snat_from"),
        "dev:lb",
        "10.2.0.5",
        source,
        require_unique=True,
    )
    assert unknown and actual == source
    assert "multiple SNAT_FROM" in reason


def test_strict_member_partition_reports_known_and_unknown_choices():
    up = _member("member:up", "10.2.0.5")
    unknown = _member("member:unknown", "10.2.0.6", None)
    regions = _member_regions([up, unknown], require_known_health=True)
    assert regions.members == [up]
    assert regions.unknown == (unknown,)
