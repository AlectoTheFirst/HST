"""The reasoner's `edge-devices` check: which binding an unbound Network Edge
device can take (`edge_device_candidates`), and the warnings
`check_edge_devices` reports. Every name and address here is made up."""

from __future__ import annotations

from typing import Any

from hst import reasoner
from hst.reasoner import check_edge_devices, edge_device_candidates, resolve_edge_device_bindings

EDGE_HUB = "eqx:device:hub"
EDGE_ROUTER = "eqx:device:router"
VCO_HUB = "vco:ent-1:edge:hub"
CISCO_ROUTER = "dev:xx-ld1-rti-01"


def _edge(uid: str, names: list[str], ip: str | None = None) -> dict[str, Any]:
    return {"uid": uid, "edge_device_uuid": uid.rsplit(":", 1)[-1], "management_ip": ip, "names": names}


def _device(
    uid: str, hostname: str, platform: str | None, wan_ips: list[str] | None = None
) -> dict[str, Any]:
    return {"uid": uid, "hostname": hostname, "platform": platform, "wan_ips": wan_ips or []}


DEVICES = [
    _device(VCO_HUB, "XX-LD1-RTH-01", "velocloud-edge", ["192.0.2.10", "198.51.100.7"]),
    _device(CISCO_ROUTER, "XX-LD1-RTI-01.example.net", "iosxe"),
]


def test_a_velocloud_edge_with_the_hostname_and_the_management_address_is_proposed():
    report = edge_device_candidates([_edge(EDGE_HUB, ["XX-LD1-RTH-01"], "192.0.2.10")], DEVICES)
    assert report["proposed"] == [{"edge_device": EDGE_HUB, "edge_device_uuid": "hub", "device": VCO_HUB}]
    assert report["conflicts"] == [] and report["ambiguous"] == []


def test_a_velocloud_edge_without_the_management_address_is_a_conflict():
    report = edge_device_candidates([_edge(EDGE_HUB, ["XX-LD1-RTH-01"], "203.0.113.9")], DEVICES)
    assert report["proposed"] == []
    assert report["conflicts"] == [
        {
            "edge_device": EDGE_HUB,
            "device": VCO_HUB,
            "management_ip": "203.0.113.9",
            "wan_ips": ["192.0.2.10", "198.51.100.7"],
        }
    ]


def test_another_source_matches_on_the_short_hostname_in_any_case():
    # the Network Edge host name differs from its device name; either matches
    report = edge_device_candidates([_edge(EDGE_ROUTER, ["XX-LD1-RTI-01", "xx-ld1-rti-01-new"])], DEVICES)
    assert report["proposed"] == [
        {"edge_device": EDGE_ROUTER, "edge_device_uuid": "router", "device": CISCO_ROUTER}
    ]


def test_two_devices_with_the_hostname_are_ambiguous():
    devices = [*DEVICES, _device("dev:xx-ld1-rti-01-a1b2", "xx-ld1-rti-01", "iosxe")]
    report = edge_device_candidates([_edge(EDGE_ROUTER, ["XX-LD1-RTI-01"])], devices)
    assert report["proposed"] == []
    assert report["ambiguous"] == [
        {"edge_device": EDGE_ROUTER, "devices": [CISCO_ROUTER, "dev:xx-ld1-rti-01-a1b2"]}
    ]


def test_a_device_with_no_match_is_not_reported():
    report = edge_device_candidates([_edge(EDGE_HUB, ["XX-SP3-RTH-02"], "192.0.2.10")], DEVICES)
    assert report == {"proposed": [], "conflicts": [], "ambiguous": []}


class _Tx:
    def __init__(self, answers: dict[str, list[dict[str, Any]]]):
        self.answers = answers

    def run(self, query: str, **_params: Any):
        rows = self.answers.get(query, [])
        return type("Result", (), {"data": lambda _self: rows})()


class _Session:
    def __init__(self, answers: dict[str, list[dict[str, Any]]]):
        self.tx = _Tx(answers)

    def execute_read(self, work):
        return work(self.tx)


def test_the_check_reports_a_proposal_and_a_refused_binding():
    session = _Session(
        {
            reasoner.FETCH_EDGE_DEVICES: [_edge(EDGE_HUB, ["XX-LD1-RTH-01"], "192.0.2.10")],
            reasoner.FETCH_EDGE_CANDIDATES: DEVICES,
            reasoner.FETCH_EDGE_BINDINGS_REFUSED: [{"uid": EDGE_ROUTER, "bound_device_uid": "dev:gone"}],
        }
    )
    report = check_edge_devices(session, collection_ts=1)
    assert report["proposed"] == [{"edge_device": EDGE_HUB, "edge_device_uuid": "hub", "device": VCO_HUB}]
    assert report["warnings"] == [
        f"network edge device {EDGE_HUB} has the hostname of {VCO_HUB}; "
        f"proposed edge_device_bindings line: hub, {VCO_HUB}",
        f"equinix edge device binding refused: {EDGE_ROUTER} names device dev:gone, which is not in this run",
    ]


def test_an_estate_without_network_edge_reports_nothing():
    assert check_edge_devices(_Session({}), collection_ts=1) == {"proposed": [], "warnings": []}


def test_finalize_records_the_edge_device_warnings_after_the_derivations():
    from hst.core import finalize
    from hst.core.config import Settings
    from hst.core.model import RunManifest

    class _RouteTargets:
        def execute(self, session: Any, settings: Any, collection_ts: int | None = None) -> RunManifest:
            return RunManifest(run_id="rt-i", source="reasoner", scope="rt-imports")

        def execute_rt_domains(
            self, session: Any, settings: Any, collection_ts: int | None = None
        ) -> RunManifest:
            return RunManifest(run_id="rt-d", source="reasoner", scope="rt-domains")

        def execute_link_speed(
            self, session: Any, settings: Any, collection_ts: int | None = None
        ) -> RunManifest:
            return RunManifest(run_id="ls", source="reasoner", scope="link-speed")

    class _Cycle:
        def apply_site_assignments(self, session: Any, assigned: Any, cts: int | None = None) -> int:
            return 0

    warning = f"network edge device {EDGE_HUB} is probably {VCO_HUB}"

    class _Rules:
        def __init__(self, report: dict[str, Any]) -> None:
            self.report = report
            self.calls: list[int] = []

        def run(self, session: Any, collection_ts: int | None = None) -> list[dict]:
            return []

        def check_edge_devices(self, session: Any, *, collection_ts: int) -> dict[str, Any]:
            self.calls.append(collection_ts)
            return self.report

    settings = Settings(_env_file=None, hst_secret_key="finalize-edge-devices-wiring-test-key-32-bytes")
    rules = _Rules({"proposed": [{"edge_device": EDGE_HUB}], "warnings": [warning]})
    findings = finalize.RunFindings()
    details = finalize.finalize_derivations(
        object(),
        settings,
        4242,
        {},
        rules=rules,
        route_targets=_RouteTargets(),
        cycle=_Cycle(),
        findings=findings,
    )
    assert rules.calls == [4242]
    assert details[-2:] == ["edge-devices: 1 proposed binding(s), 1 warning(s)", f"warning: {warning}"]
    assert findings.warnings == [warning]

    quiet = _Rules({"proposed": [], "warnings": []})
    details = finalize.finalize_derivations(
        object(), settings, 4242, {}, rules=quiet, route_targets=_RouteTargets(), cycle=_Cycle()
    )
    assert not [line for line in details if line.startswith("edge-devices")]


# --- edge-device-from-binding ------------------------------------------------------------

CISCO_GI1 = "dev:xx-ld1-rti-01/port/gigabitethernet1"
EDGE_IF = "eqx:device:router/if/eth0"
EDGE_PORT = "eqx:device:router/port/eth0"


def _binding(edge: str, device: str, ports: list[tuple[str, str]] = ()) -> dict[str, Any]:
    return {"edge_device": edge, "device": device, "device_ports": [{"uid": u, "mac": m} for u, m in ports]}


def _iface(edge: str, name: str, mac: str | None) -> dict[str, Any]:
    return {
        "edge_device": edge,
        "interface": f"{edge}/if/{name}",
        "port": f"{edge}/port/{name}",
        "mac": mac,
    }


def test_an_interface_with_the_mac_of_one_port_of_the_bound_device_realizes_that_port():
    report = resolve_edge_device_bindings(
        [_binding(EDGE_ROUTER, CISCO_ROUTER, [(CISCO_GI1, "00:00:5e:00:53:01")])],
        [_iface(EDGE_ROUTER, "eth0", "00:00:5e:00:53:01")],
    )
    assert report["same_as"] == [{"edge_device": EDGE_ROUTER, "device": CISCO_ROUTER}]
    assert report["realized"] == [{"interface": EDGE_IF, "port": CISCO_GI1}]
    # no duplicate interface and port on the Cisco device
    assert report["on"] == [] and report["ambiguous"] == 0


def test_an_interface_without_a_mac_match_goes_on_the_bound_device_with_its_port():
    report = resolve_edge_device_bindings(
        [_binding(EDGE_HUB, VCO_HUB)], [_iface(EDGE_HUB, "eth0", "00:00:5e:00:53:02")]
    )
    assert report["realized"] == []
    assert report["on"] == [
        {"node": f"{EDGE_HUB}/if/eth0", "device": VCO_HUB},
        {"node": f"{EDGE_HUB}/port/eth0", "device": VCO_HUB},
    ]


def test_a_mac_on_two_ports_of_the_bound_device_is_ambiguous_and_takes_the_port_of_its_own():
    ports = [(CISCO_GI1, "00:00:5e:00:53:01"), ("dev:xx-ld1-rti-01/port/port-channel1", "00:00:5e:00:53:01")]
    report = resolve_edge_device_bindings(
        [_binding(EDGE_ROUTER, CISCO_ROUTER, ports)], [_iface(EDGE_ROUTER, "eth0", "00:00:5e:00:53:01")]
    )
    assert report["realized"] == [] and report["ambiguous"] == 1
    assert [row["node"] for row in report["on"]] == [EDGE_IF, EDGE_PORT]


def test_an_interface_without_a_mac_never_matches_a_port_without_one():
    report = resolve_edge_device_bindings(
        [_binding(EDGE_ROUTER, CISCO_ROUTER, [(CISCO_GI1, "00:00:5e:00:53:01")])],
        [_iface(EDGE_ROUTER, "eth7", None)],
    )
    assert report["realized"] == [] and len(report["on"]) == 2


def test_the_interfaces_of_an_unbound_device_are_left_alone():
    report = resolve_edge_device_bindings([], [_iface(EDGE_HUB, "eth0", None)])
    assert report == {"same_as": [], "on": [], "realized": [], "ambiguous": 0}


class _WriteTx:
    def __init__(self, bindings: list[dict[str, Any]], interfaces: list[dict[str, Any]]):
        self.answers = {reasoner.FETCH_EDGE_BINDINGS: bindings, reasoner.FETCH_EDGE_INTERFACES: interfaces}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def run(self, query: str, **params: Any):
        self.calls.append((query, params))
        rows = self.answers.get(query, [{"n": len(params.get("rows", []))}] if "MERGE" in query else [])
        return type("Result", (), {"data": lambda _self: rows})()


def test_the_rule_writes_same_as_on_and_realized_by_with_the_resolved_rows():
    tx = _WriteTx(
        [_binding(EDGE_HUB, VCO_HUB)],
        [_iface(EDGE_HUB, "eth0", None), _iface(EDGE_HUB, "eth1", None)],
    )
    result = reasoner._run_edge_device_rule(tx, ts=1, cts=2)
    assert result == {"edges": 1, "on": 4, "realized": 0, "ambiguous": 0}
    queries = [q for q, _ in tx.calls]
    assert queries[:2] == [reasoner.FETCH_EDGE_BINDINGS, reasoner.FETCH_EDGE_INTERFACES]
    assert tx.calls[1][1]["edge_devices"] == [EDGE_HUB]
    assert reasoner.EDGE_SAME_AS_WRITE in queries and reasoner.EDGE_ON_WRITE in queries
    # nothing to realize: that write is not issued
    assert reasoner.EDGE_REALIZED_WRITE not in queries


def test_without_a_bound_device_the_rule_reads_once_and_writes_nothing():
    tx = _WriteTx([], [])
    assert reasoner._run_edge_device_rule(tx, ts=1, cts=2) == {
        "edges": 0,
        "on": 0,
        "realized": 0,
        "ambiguous": 0,
    }
    assert [q for q, _ in tx.calls] == [reasoner.FETCH_EDGE_BINDINGS]


def test_the_rule_runs_after_the_bindings_and_before_the_circuit_rule():
    names = [name for name, _query in reasoner.RULES]
    assert names.index(reasoner.FABRIC_PORT_RULE) < names.index(reasoner.EDGE_DEVICE_RULE)
    assert names.index(reasoner.EDGE_DEVICE_RULE) < names.index("cable-from-fabric-circuit")


def test_the_derived_edges_are_reasoner_owned_and_cleared_each_run():
    for query in (reasoner.EDGE_SAME_AS_WRITE, reasoner.EDGE_ON_WRITE, reasoner.EDGE_REALIZED_WRITE):
        assert "r._scope = 'reasoner'" in query and "r.derived = true" in query
        assert "r.rule = 'edge-device-from-binding'" in query


def test_the_check_states_facts_and_gives_the_line_as_data():
    devices = [*DEVICES, _device("dev:xx-ld1-rti-01-a1b2", "xx-ld1-rti-01", "iosxe")]
    session = _Session(
        {
            reasoner.FETCH_EDGE_DEVICES: [
                _edge(EDGE_HUB, ["XX-LD1-RTH-01"], "192.0.2.10"),
                _edge("eqx:device:hub2", ["XX-LD1-RTH-01"], "203.0.113.9"),
                _edge(EDGE_ROUTER, ["XX-LD1-RTI-01"]),
            ],
            reasoner.FETCH_EDGE_CANDIDATES: devices,
            reasoner.FETCH_EDGE_BINDINGS_REFUSED: [{"uid": EDGE_ROUTER, "bound_device_uid": "dev:gone"}],
        }
    )
    warnings = check_edge_devices(session, collection_ts=1)["warnings"]
    assert len(warnings) == 4
    assert not [w for w in warnings if "`" in w or " add " in f" {w} "]
    assert warnings[0].endswith(f"proposed edge_device_bindings line: hub, {VCO_HUB}")
