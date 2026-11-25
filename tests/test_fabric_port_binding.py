"""The reasoner's fabric-port-from-description decision
(`resolve_fabric_port_bindings`): which device Port realizes which Equinix
FabricPort, from the port description and the Fabric port's cross-connect
ids. Every name and id here is made up."""

from __future__ import annotations

from tests.support.cputime import cpu_time

from hst import reasoner
from hst.reasoner import resolve_fabric_port_bindings

FP_PRI = "eqx:port:pri"
FP_SEC = "eqx:port:sec"
SWC_ETH3 = "dev:xx-swc-02/port/eth1-3"
SWC_ETH4 = "dev:xx-swc-02/port/eth1-4"
SWC_PO10 = "dev:xx-swc-02/port/port-channel10"


def _fp(uid: str, name: str, cables: list[str] | None = None, bound: str | None = None) -> dict:
    return {"uid": uid, "name": name, "cross_connect_ids": cables, "bound_port_uid": bound}


def _port(uid: str, description: str) -> dict:
    return {"uid": uid, "description": description}


FABRIC = [
    _fp(FP_PRI, "ACME-XX1-EXT-PRI-01", ["21000001"]),
    _fp(FP_SEC, "ACME-XX1-EXT-SEC-01", ["21000002"]),
]


def test_a_description_with_the_name_and_the_cable_id_binds_the_port():
    report = resolve_fabric_port_bindings(
        FABRIC,
        [
            _port(SWC_ETH3, "TO EQUINIX FABRIC - ACME-XX1-EXT-PRI-01 - CABLE ID : 21000001 - 10 GBPS"),
            _port(SWC_ETH4, "to equinix fabric - acme-xx1-ext-sec-01 - cable id: 21000002"),
        ],
    )
    assert report["edges"] == [
        {"fabric_port": FP_PRI, "port": SWC_ETH3, "evidence": "name+cable"},
        {"fabric_port": FP_SEC, "port": SWC_ETH4, "evidence": "name+cable"},
    ]
    assert report["conflicts"] == [] and report["ambiguous"] == []


def test_a_description_with_the_name_and_no_cable_id_binds_on_the_name():
    report = resolve_fabric_port_bindings(FABRIC, [_port(SWC_ETH3, "ACME-XX1-EXT-PRI-01")])
    assert report["edges"] == [{"fabric_port": FP_PRI, "port": SWC_ETH3, "evidence": "name"}]


def test_a_different_cable_id_is_a_conflict_and_binds_nothing():
    report = resolve_fabric_port_bindings(
        FABRIC, [_port(SWC_ETH3, "ACME-XX1-EXT-PRI-01 - CABLE ID : 29999999")]
    )
    assert report["edges"] == []
    assert report["conflicts"] == [
        {"fabric_port": FP_PRI, "port": SWC_ETH3, "stated": ["29999999"], "cross_connect_ids": ["21000001"]}
    ]


def test_the_name_matches_only_as_a_whole_word():
    report = resolve_fabric_port_bindings(
        FABRIC,
        [_port(SWC_ETH3, "ACME-XX1-EXT-PRI-010"), _port(SWC_ETH4, "XACME-XX1-EXT-PRI-01")],
    )
    assert report == {"edges": [], "conflicts": [], "ambiguous": []}


def test_a_fabric_port_two_ports_name_is_ambiguous_and_binds_nothing():
    report = resolve_fabric_port_bindings(
        FABRIC,
        [
            _port(SWC_ETH3, "ACME-XX1-EXT-PRI-01 CABLE ID: 21000001"),
            _port(SWC_PO10, "ACME-XX1-EXT-PRI-01"),
        ],
    )
    assert report["edges"] == []
    assert report["ambiguous"] == [{"fabric_port": FP_PRI, "ports": [SWC_ETH3, SWC_PO10]}]


def test_a_port_that_names_two_fabric_ports_is_ambiguous_and_binds_nothing():
    report = resolve_fabric_port_bindings(
        FABRIC, [_port(SWC_PO10, "ACME-XX1-EXT-PRI-01 / ACME-XX1-EXT-SEC-01")]
    )
    assert report["edges"] == []
    assert report["ambiguous"] == [{"port": SWC_PO10, "fabric_ports": [FP_PRI, FP_SEC]}]


def test_an_operator_binding_is_left_to_the_operator():
    fabric = [_fp(FP_PRI, "ACME-XX1-EXT-PRI-01", ["21000001"], bound=SWC_ETH4)]
    report = resolve_fabric_port_bindings(
        fabric, [_port(SWC_ETH3, "ACME-XX1-EXT-PRI-01 CABLE ID : 21000001")]
    )
    assert report == {"edges": [], "conflicts": [], "ambiguous": []}


def test_a_ccid_label_counts_as_a_cable_id():
    report = resolve_fabric_port_bindings(FABRIC, [_port(SWC_ETH3, "ACME-XX1-EXT-PRI-01 CCID 21000001")])
    assert report["edges"][0]["evidence"] == "name+cable"


def test_the_rule_runs_before_the_circuit_rule_that_reads_its_edges():
    names = [name for name, _query in reasoner.RULES]
    assert names.index(reasoner.FABRIC_PORT_RULE) < names.index("cable-from-fabric-circuit")


def test_an_ended_circuit_draws_no_cable_and_no_stretch_observation():
    circuit_rule = dict(reasoner.RULES)["cable-from-fabric-circuit"]
    assert "$ended_circuit_states" in circuit_rule
    assert "$active_circuit_states" in reasoner.FETCH_BOUND_CIRCUITS
    assert {"DEPROVISIONED", "DELETED"} <= set(reasoner.ENDED_CIRCUIT_STATES)


def test_a_device_link_draws_a_cable_but_is_no_stretch_observation():
    circuit_rule = dict(reasoner.RULES)["cable-from-fabric-circuit"]
    assert "DEVICE_LINK" not in circuit_rule
    assert "coalesce(vc.type, '') <> 'DEVICE_LINK'" in reasoner.FETCH_BOUND_CIRCUITS


def test_a_port_that_names_an_operator_bound_and_an_unbound_fabric_port_is_ambiguous():
    fps = [_fp(FP_PRI, "ACME-XX1-EXT-PRI-01", bound=SWC_ETH3), _fp(FP_SEC, "ACME-XX1-EXT-SEC-01")]
    report = reasoner.resolve_fabric_port_bindings(
        fps, [_port(SWC_PO10, "ACME-XX1-EXT-PRI-01 / ACME-XX1-EXT-SEC-01")]
    )
    assert report["edges"] == []
    assert report["ambiguous"] == [{"port": SWC_PO10, "fabric_ports": sorted([FP_PRI, FP_SEC])}]


def test_a_port_the_operator_bound_realizes_no_other_fabric_port():
    fps = [_fp(FP_PRI, "ACME-XX1-EXT-PRI-01", bound=SWC_ETH3), _fp(FP_SEC, "ACME-XX1-EXT-SEC-01")]
    report = reasoner.resolve_fabric_port_bindings(fps, [_port(SWC_ETH3, "ACME-XX1-EXT-SEC-01 spare")])
    assert report == {"edges": [], "conflicts": [], "ambiguous": []}


def test_the_word_index_names_the_same_fabric_ports_as_the_whole_word_pattern():
    import re

    names = ["ACME-XX1-EXT-PRI-01", "acme-xx1-ext-sec-01", "Port A 1", "xx1/eth 2"]
    fps = [_fp(f"fp:{i}", n) for i, n in enumerate(names)]
    matcher = reasoner._fabric_port_matcher(fps)
    descriptions = [
        "to ACME-XX1-EXT-PRI-01-010",
        "XACME-XX1-EXT-PRI-01",
        "ACME-XX1-EXT-PRI-01/acme-xx1-ext-sec-01",
        "(ACME-XX1-EXT-SEC-01)",
        "ACME-XX1-EXT-PRI-01_x",
        "acme-xx1-ext-sec-01.",
        "ACME-XX1-EXT-PRI-01-",
        "éACME-XX1-EXT-PRI-01",
        "uplink port a 1 here",
        "xx1/eth 2",
    ]
    for text in descriptions:
        reference = sorted(
            fp["uid"]
            for fp in fps
            if re.search(rf"(?<![A-Z0-9-]){re.escape(fp['name'])}(?![A-Z0-9-])", text, re.IGNORECASE)
        )
        assert [fp["uid"] for fp in matcher(text)] == reference, text


def test_the_rule_resolves_600_fabric_ports_by_2000_ports_in_seconds():
    fps = [_fp(f"fp:{i}", f"ACME-XX1-EXT-P{i:04d}") for i in range(600)]
    ports = [_port(f"port:{i}", f"to ACME-XX1-EXT-P{i % 900:04d} cable") for i in range(2000)]
    with cpu_time() as spent:
        reasoner.resolve_fabric_port_bindings(fps, ports)
    assert spent.seconds < 5


def test_only_an_active_circuit_draws_a_cable_or_a_stretch_observation():
    circuit_rule = dict(reasoner.RULES)["cable-from-fabric-circuit"]
    predicate = "toUpper(coalesce(vc.state, '')) IN $active_circuit_states"
    assert predicate in circuit_rule
    assert predicate in reasoner.FETCH_BOUND_CIRCUITS
    assert reasoner.ACTIVE_CIRCUIT_STATES == ["ACTIVE", "PROVISIONED"]
    assert not set(reasoner.ACTIVE_CIRCUIT_STATES) & set(reasoner.ENDED_CIRCUIT_STATES)


def test_an_unbound_fabric_port_gets_the_first_issue_that_names_it():
    fabric = [
        _fp("fp:conflict", "ACME-C-01", ["111"]),
        _fp("fp:several", "ACME-S-01", ["222"]),
        _fp("fp:across", "ACME-A-01", ["333"]),
        _fp("fp:bound", "ACME-B-01", ["444"], bound="port:op"),
        _fp("fp:edge", "ACME-E-01", ["555"]),
    ]
    report = {
        "edges": [{"fabric_port": "fp:edge", "port": "port:e", "evidence": "name"}],
        "conflicts": [
            {"fabric_port": "fp:conflict", "port": "port:c", "stated": ["999"], "cross_connect_ids": ["111"]}
        ],
        "ambiguous": [
            {"fabric_port": "fp:several", "ports": ["port:s2", "port:s1"]},
            {"port": "port:x", "fabric_ports": ["fp:across", "fp:other"]},
            {"fabric_port": "fp:bound", "ports": ["port:b1", "port:b2"]},
        ],
    }
    assert reasoner.fabric_port_issues(fabric, report) == [
        {"fabric_port": "fp:across", "issue": "several-fabric-ports", "ports": ["port:x"]},
        {"fabric_port": "fp:conflict", "issue": "cable-conflict", "ports": ["port:c"]},
        {"fabric_port": "fp:several", "issue": "several-ports", "ports": ["port:s1", "port:s2"]},
    ]


def test_the_rule_warns_once_per_conflict_and_ambiguity():
    report = {
        "edges": [],
        "conflicts": [
            {"fabric_port": "fp:c", "port": "port:c", "stated": ["999"], "cross_connect_ids": ["111"]}
        ],
        "ambiguous": [
            {"fabric_port": "fp:s", "ports": ["port:1", "port:2"]},
            {"port": "port:x", "fabric_ports": ["fp:a", "fp:b"]},
        ],
    }
    assert reasoner.fabric_port_warnings(report) == [
        "fabric-port-from-description: port port:c names Fabric port fp:c with cable id 999; "
        "the Fabric port has 111; no binding",
        "fabric-port-from-description: 2 ports name Fabric port fp:s (port:1, port:2); no binding",
        "fabric-port-from-description: port port:x names 2 Fabric ports (fp:a, fp:b); no binding",
    ]
