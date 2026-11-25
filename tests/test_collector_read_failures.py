"""A read a collector could not make never reaches the graph as clean data.

Each case is a read that failed, was refused or never happened: the section
or table it feeds must say so (failed, unauthorized, malformed, partial or
not-captured), not `ok` or `complete-empty`, the claim that the
device answered and holds nothing. The cases: an unknown refusal on
a required text read, a privilege refusal of the running-config,
tables fed by a failed read, UniFi policy bound to nothing, refused
VeloCloud reads, Equinix Network Edge circuits, VyOS 1.3 configuration
and the ARP cable rule's side-store read.

The payloads are synthetic; nothing here was captured from real
infrastructure.
"""

from __future__ import annotations

import copy
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from tests.conftest import FakeSshSession
from tests.enterprise.test_velocloud import _overlay_raw
from tests.enterprise.test_velocloud_poll import Fleet
from tests.test_iosxe import RAW as IOSXE_RAW
from tests.test_iosxe import _collector as _iosxe_collector
from tests.test_reasoner_unit import _edge_addr
from tests.test_unifi import CLASSIC_RULES, GROUPS, POLICIES, UDM
from tests.test_unifi import RAW as UNIFI_RAW

from hst.collectors import base as collectors_base
from hst.collectors import iosxr, nxos, ssh, vyos
from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.collectors.cli_collector import classify_command_failure, effective_outcomes
from hst.collectors.iosxe import (
    CMD_ARP,
    CMD_BGP,
    CMD_INTERFACE_CONFIG,
    CMD_INTERFACES,
    CMD_NAT,
    CMD_OSPF,
    CMD_ROUTE,
    IosxeCollector,
)
from hst.collectors.unifi import UnifiCollector, normalize_unifi, policy_gaps
from hst.collectors.velocloud import PORTAL_READ_PATHS, VeloCloudCollector, normalize_velocloud
from hst.core import Settings, uid
from hst.core.identity import MemoryResolver
from hst.core.model import Batch, SectionOutcome, TableOutcome, section_verdict

# What IOS-XE answers a privilege-1 account for a command its parser does not
# accept at that level: the words a missing feature gets.
PRIV1_REFUSAL = "% Invalid input detected at '^' marker."


def _refusing(refused: dict[str, str]):
    """FakeSshSession outputs: the golden IOS-XE answers, with each command
    of `refused` rejected by the device in the given words."""

    def outputs(cmd: str) -> str:
        if cmd in refused:
            raise ssh.CommandFailed(f"{cmd!r} rejected by device: {refused[cmd]}")
        return IOSXE_RAW[cmd]

    return outputs


def _fetch(monkeypatch, outputs) -> tuple[IosxeCollector, dict[str, Any]]:
    FakeSshSession(outputs).install(monkeypatch)
    collector = _iosxe_collector()
    return collector, collector.fetch()


# --- a privilege refusal of the running-config -------------------------------------------


def test_a_privilege_refused_running_config_reads_unauthorized_and_the_device_partial(monkeypatch):
    """`show running-config` exists on every IOS-XE release, so its refusal
    is a permission the account lacks."""
    denied = (CMD_INTERFACE_CONFIG, CMD_NAT, CMD_BGP)
    collector, raw = _fetch(monkeypatch, _refusing(dict.fromkeys(denied, PRIV1_REFUSAL)))
    sections = collector.normalize(raw).sections
    for name in ("interface_config", "nat", "bgp"):
        assert sections[name].status == "unauthorized", name
        assert "exists on every release" in sections[name].detail
    assert section_verdict(sections, IosxeCollector.AUTHORITATIVE_SECTIONS) == "partial"


def test_a_refused_feature_command_stays_unsupported(monkeypatch):
    """A command a box without the feature refuses is not a permission
    problem: `show ip ospf` on a router with no OSPF stays `unsupported`."""
    collector, raw = _fetch(monkeypatch, _refusing({CMD_OSPF: PRIV1_REFUSAL}))
    assert collector.sections(raw)["ospf"].status == "unsupported"


def test_a_payload_that_recorded_the_refusal_unsupported_replays_as_unauthorized(monkeypatch):
    collector, raw = _fetch(monkeypatch, IOSXE_RAW)
    raw[RAW_OUTCOMES_KEY][CMD_INTERFACE_CONFIG] = {"status": "unsupported", "detail": PRIV1_REFUSAL}
    assert collector.sections(raw)["interface_config"].status == "unauthorized"


def test_every_cisco_family_names_its_running_config_reads_always_present():
    assert CMD_INTERFACE_CONFIG in IosxeCollector.ALWAYS_PRESENT_COMMANDS
    assert iosxr.CMD_ROUTE_POLICY in iosxr.IosxrCollector.ALWAYS_PRESENT_COMMANDS
    assert nxos.CMD_INTERFACE_CONFIG in nxos.NxosCollector.ALWAYS_PRESENT_COMMANDS
    # a feature-scoped NX-OS extract is refused by a box without the feature
    assert nxos.CMD_NAT not in nxos.NxosCollector.ALWAYS_PRESENT_COMMANDS
    failure = ssh.CommandFailed(f"{CMD_NAT!r} rejected by device: {PRIV1_REFUSAL}")
    assert classify_command_failure(failure)[0] == "unsupported"
    status, _detail = classify_command_failure(
        failure, command=CMD_NAT, always_present=IosxeCollector.ALWAYS_PRESENT_COMMANDS
    )
    assert status == "unauthorized"


def test_the_xr_interface_bindings_and_the_nxos_access_lists_are_always_present_reads():
    """The reads the gates are built from exist on every release, so a refusal of one
    is a permission and the device goes partial, not `ok` with no filter bindings."""
    xr = iosxr.IosxrCollector.ALWAYS_PRESENT_COMMANDS
    nx = nxos.NxosCollector.ALWAYS_PRESENT_COMMANDS
    assert iosxr.CMD_INTERFACE_CONFIG in xr
    assert {nxos.CMD_ACL, nxos.CMD_VLAN_FILTER} <= nx
    for command, present in (
        (iosxr.CMD_INTERFACE_CONFIG, xr),
        (nxos.CMD_ACL, nx),
        (nxos.CMD_VLAN_FILTER, nx),
    ):
        failure = ssh.CommandFailed(f"{command!r} rejected by device: {PRIV1_REFUSAL}")
        assert classify_command_failure(failure, command=command)[0] == "unsupported"
        assert classify_command_failure(failure, command=command, always_present=present)[0] == "unauthorized"
    # the feature-scoped OSPF reads of NX-OS stay refusals of a missing feature
    assert nxos.CMD_OSPF not in nx


# --- a required text read answered with words the transport did not know -----------------


def test_an_unknown_refusal_of_show_interfaces_is_malformed_and_fails_the_device(monkeypatch):
    """The answer is not blank and parses to no interfaces. It is no empty
    table: every box has interfaces."""
    collector, raw = _fetch(monkeypatch, {**IOSXE_RAW, CMD_INTERFACES: "Access refused by site policy.\n"})
    sections = collector.sections(raw)
    assert sections["interfaces"].status == "malformed"
    assert "Access refused by site policy." in sections["interfaces"].detail
    assert section_verdict(sections, IosxeCollector.AUTHORITATIVE_SECTIONS) == "failed"


def test_a_rib_answer_without_any_routing_table_words_is_malformed():
    """A routing table the parse read no route from is `empty` only when the
    answer carries the table's own words; anything else is not its answer."""
    from hst.collectors.cisco_common import RIB_EMPTY_ANSWER
    from hst.collectors.cli_collector import Section, build_sections

    specs = {"rib": Section(CMD_ROUTE, "rib", empty_answer=RIB_EMPTY_ANSWER)}
    outcomes = {RAW_OUTCOMES_KEY: {CMD_ROUTE: {"status": "ok"}}}
    refused = build_sections({CMD_ROUTE: "Access refused by site policy.\n", **outcomes}, {"rib": []}, specs)
    assert refused["rib"].status == "malformed"
    assert "Access refused by site policy." in refused["rib"].detail
    blank = build_sections({CMD_ROUTE: "", **outcomes}, {"rib": []}, specs)
    assert blank["rib"].status == "empty"


def test_an_empty_routing_table_reads_empty(monkeypatch):
    empty = "Codes: L - local, C - connected, S - static\n\nGateway of last resort is not set\n\n"
    collector, raw = _fetch(monkeypatch, {**IOSXE_RAW, CMD_ROUTE: empty})
    assert collector.sections(raw)["rib"].status == "empty"


def test_the_refusal_banner_is_returned_alone_whatever_its_line_break():
    assert ssh.opening_rejection("Command authorization failed.\rrest of the answer") == (
        "Command authorization failed."
    )


# --- a table whose feeding read failed ---------------------------------------------------


class _StubCollector:
    """The collector surface `_write_side_tables` reads, for one RIB table
    fed by the `routes` section."""

    SIDE_TABLES = ("rib",)
    TABLE_SECTIONS = {"rib": ("routes",)}

    def __init__(self, settings: Settings, rows: list[dict[str, Any]], stated: dict[str, TableOutcome]):
        self.settings = settings
        self._rows = rows
        self._stated = stated

    def side_tables(self, raw):
        return {"rib": self._rows}

    def table_outcomes(self, raw):
        return self._stated

    def table_feeds(self, raw):
        return self.TABLE_SECTIONS


def _written(tmp_path, routes: str, rows=(), stated=None) -> TableOutcome:
    pytest.importorskip("pyarrow")
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    collector = _StubCollector(settings, list(rows), stated or {})
    outcomes = collectors_base._write_side_tables(
        collector,
        {},
        "src",
        "router-1",
        run_id="1700000000000-aaaaaaaa",
        collection_ts=1_700_000_000_000,
        on_write=None,
        sections={"routes": SectionOutcome(status=routes)},
    )
    return outcomes["rib"]


_ROW = {"device_uid": "dev:r1", "vrf": "default", "prefix": "10.0.0.0/24", "next_hop": "10.0.0.1"}


def test_an_empty_table_whose_feeding_read_failed_is_failed(tmp_path):
    outcome = _written(tmp_path, "failed")
    assert outcome.status == "failed"
    assert "routes=failed" in outcome.detail


def test_an_empty_table_whose_feeding_read_answered_is_complete_empty(tmp_path):
    assert _written(tmp_path, "empty").status == "complete-empty"


def test_a_written_table_whose_feeding_read_failed_is_partial(tmp_path):
    outcome = _written(tmp_path, "unauthorized", rows=[_ROW])
    assert (outcome.status, outcome.row_count) == ("partial", 1)
    assert outcome.path


def test_a_written_table_the_collector_states_failed_is_partial(tmp_path):
    stated = {"rib": TableOutcome(status="failed", detail="route table not read for one enterprise")}
    outcome = _written(tmp_path, "ok", rows=[_ROW], stated=stated)
    assert outcome.status == "partial"
    assert "one enterprise" in outcome.detail


def test_a_refused_arp_read_leaves_the_arp_table_failed_and_the_mac_table_not_captured(monkeypatch):
    from hst.collectors.offline import parse_report

    collector, raw = _fetch(monkeypatch, _refusing({CMD_ARP: "% Permission denied"}))
    sections = collector.sections(raw)
    assert sections["arp"].status == "unauthorized"
    assert collectors_base.unread_table_feeds(collector, raw, sections) == {"arp": "arp=unauthorized"}
    assert collector.table_outcomes(raw)["mac"].status == "not-captured"
    # the offline parse report records what the load would
    report = parse_report(collector, raw, path="capture.json")
    assert report.outcomes["arp"].status == "failed"
    assert report.outcomes["mac"].status == "not-captured"


def test_a_failed_nxos_ospf_command_states_the_database_failed():
    raw = {RAW_OUTCOMES_KEY: {command: {"status": "ok"} for command in nxos.OSPF_FEATURE_COMMANDS}}
    raw[RAW_OUTCOMES_KEY][nxos.OSPF_FEATURE_COMMANDS[0]] = {"status": "failed", "detail": "timed out"}
    outcome = nxos.ospf_table_outcomes(raw)[nxos.OSPF_LSDB_TABLE]
    assert outcome.status == "failed"


def test_the_vyos_rib_stands_on_every_routing_table_read():
    collector = vyos.VyosCollector(
        vyos.VyosConfig(host="synthetic", auth={"method": "password", "username": "ro", "password": "x"}),
        None,
    )
    raw = {"routes_tables": {"10": {}}, "config": {}}
    feeds = collector.table_feeds(raw)
    assert feeds["rib"] == ("routes", "routes6", "routes_table_10")
    sections = {
        "routes": SectionOutcome(status="ok"),
        "routes6": SectionOutcome(status="ok"),
        "routes_table_10": SectionOutcome(status="failed", detail="timed out"),
    }
    assert collectors_base.unread_table_feeds(collector, raw, sections) == {"rib": "routes_table_10=failed"}


def test_refused_velocloud_route_table_and_bgp_reads_state_their_tables_failed():
    raw = _overlay_raw()
    raw["enterprises"][0]["route_table"] = None
    raw["enterprises"][0]["bgp_sessions"] = {"_capability": {"status": "unavailable", "operation": "x"}}
    collector = VeloCloudCollector.__new__(VeloCloudCollector)
    outcomes = collector.table_outcomes(raw)
    assert outcomes["rib"].status == "failed"
    assert outcomes["bgp_sessions"].status == "failed"


# --- refused VeloCloud configuration reads -----------------------------------------------


def _gap(operation: str) -> dict[str, Any]:
    return {"_capability": {"status": "unavailable", "operation": operation}}


def test_a_refused_profile_read_fails_the_configuration_and_profile_segments_sections():
    from hst.app import runs_exec

    raw = _overlay_raw()
    raw["enterprises"][0].setdefault("gaps", []).append(_gap(PORTAL_READ_PATHS["enterprise_configurations"]))
    batch = normalize_velocloud(raw)
    assert batch.sections["configuration"].status == "failed"
    assert batch.sections["profile_segments"].status == "failed"
    # neither is authoritative, so the source still loads and the objects carry
    assert section_verdict(batch.sections, VeloCloudCollector.AUTHORITATIVE_SECTIONS) == "partial"
    collector = VeloCloudCollector.__new__(VeloCloudCollector)
    labels = runs_exec._failed_section_labels(collector, batch.sections)
    assert {"SdwanSegment", "VrfInstance", "SdwanBusinessPolicy"} <= set(labels)


def test_a_refused_edge_module_read_fails_the_configuration_section():
    raw = _overlay_raw()
    raw["enterprises"][0]["edge_details"]["e-br"]["modules"] = _gap(
        PORTAL_READ_PATHS["configuration_modules"]
    )
    batch = normalize_velocloud(raw)
    assert batch.sections["configuration"].status == "failed"
    assert "profile_segments" not in batch.sections


def test_a_velocloud_poll_with_every_read_answered_records_no_degraded_section():
    batch = normalize_velocloud(_overlay_raw())
    assert "configuration" not in batch.sections and "profile_segments" not in batch.sections


# --- an edge listing the APIv2 fallback answered -----------------------------------------


def _fallback_poll(monkeypatch, *, fail=None, aggregates=None, empty_listing=False):
    """A real fetch against the synthetic orchestrator, with one Portal read
    refused, answered without the enterprise, or answered empty."""
    fleet = Fleet(monkeypatch)
    fleet.fail.update(fail or {})
    answer = fleet.reply

    def reply(request):
        operation = request.url.path.rsplit("/", 1)[-1]
        if aggregates is not None and operation == "getAggregates" and operation not in fleet.fail:
            fleet.calls[operation] += 1
            return httpx.Response(200, json={"enterprises": aggregates})
        if empty_listing and operation == "getEnterpriseEdges":
            fleet.calls[operation] += 1
            return httpx.Response(200, json=[])
        return answer(request)

    fleet.reply = reply
    raw = fleet.poll()
    return fleet, raw, normalize_velocloud(raw)


@pytest.mark.parametrize(
    ("case", "kwargs", "path"),
    [
        ("edge listing refused", {"fail": {"getEnterpriseEdges": 403}}, "enterprise_edges"),
        ("edge listing empty", {"empty_listing": True}, "enterprise_edges"),
        ("aggregates refused", {"fail": {"getAggregates": 403}}, "aggregates"),
        ("no numeric enterprise id", {"aggregates": [{"logicalId": "other", "id": 9}]}, "aggregates"),
    ],
)
def test_edges_read_from_the_apiv2_fallback_leave_the_edges_section_partial(monkeypatch, case, kwargs, path):
    fleet, raw, batch = _fallback_poll(monkeypatch, **kwargs)
    body = raw["enterprises"][0]
    # the fetch took the APIv2 route and the edges are there
    assert fleet.calls["edges"] == 1
    assert body["edges"]
    assert any(g["_capability"]["operation"] == PORTAL_READ_PATHS[path] for g in body["gaps"])
    assert len([n for n in batch.nodes if n.label == "Device"]) == 2
    edges = batch.sections["edges"]
    assert edges.status == "partial", case
    assert "APIv2 fallback" in (edges.detail or "")
    # the profiles are bound through the listing, so configuration fails too
    assert batch.sections["configuration"].status == "failed"
    assert batch.sections["profile_segments"].status == "failed"


def test_a_poll_with_the_portal_edge_listing_leaves_the_edges_section_clean(monkeypatch):
    fleet, raw, batch = _fallback_poll(monkeypatch)
    assert fleet.calls["edges"] == 0
    assert not raw["enterprises"][0]["gaps"]
    assert "edges" not in batch.sections


def test_a_refused_profile_read_with_the_portal_listing_does_not_mark_the_edges_partial():
    raw = _overlay_raw()
    raw["enterprises"][0].setdefault("gaps", []).append(_gap(PORTAL_READ_PATHS["enterprise_configurations"]))
    assert "edges" not in normalize_velocloud(raw).sections


# --- UniFi policy bound to nothing -------------------------------------------------------


def _ha_raw(**extra: Any) -> dict[str, Any]:
    second = {**UDM, "mac": "aa:bb:cc:00:00:04", "serial": "UDM0002", "name": "Gateway-2"}
    return {**UNIFI_RAW, "devices": UNIFI_RAW["devices"] + [UDM, second], **extra}


def test_a_gateway_ha_pair_enforces_the_classic_rulebases_from_its_redundancy_group():
    batch = normalize_unifi(
        _ha_raw(firewall_rules=CLASSIC_RULES, firewall_groups=GROUPS),
        site_code="home",
        l3dom="home",
        unifi_site="default",
    )
    groups = [n.uid for n in batch.nodes if n.label == "RedundancyGroup"]
    assert len(groups) == 1
    members = {r.start_uid for r in batch.rels if r.rel_type == "MEMBER_OF" and r.end_uid == groups[0]}
    assert len(members) == 2
    enforces = [(r.start_label, r.start_uid) for r in batch.rels if r.rel_type == "ENFORCES"]
    assert enforces and set(enforces) == {("RedundancyGroup", groups[0])}


def _unifi_collector(monkeypatch) -> UnifiCollector:
    collector = object.__new__(UnifiCollector)
    collector.config = SimpleNamespace(
        site_code="site",
        effective_routing_scope="site",
        site="default",
        include_clients=False,
        source_name="campus",
        l2fabric=None,
    )
    collector.settings = SimpleNamespace(l2fabric_of=lambda *_args: "default")
    collector.identity = MemoryResolver()
    monkeypatch.setattr(
        "hst.collectors.unifi.normalize_unifi",
        lambda *_args, **_kwargs: Batch(source="unifi", scope="unifi:default"),
    )
    return collector


def test_a_gateway_ha_pair_reads_its_policy_section_partial(monkeypatch):
    batch = _unifi_collector(monkeypatch).normalize(_ha_raw(firewall_rules=CLASSIC_RULES))
    policy = batch.sections["policy"]
    assert policy.status == "partial"
    assert "2 gateway devices" in policy.detail
    assert any("2 gateway devices" in w for w in batch.warnings)


def test_zone_policies_naming_zones_that_were_not_collected_read_partial(monkeypatch):
    """A 400 or 404 on the zones read is an empty list, and every zone policy
    is then skipped."""
    raw = {**UNIFI_RAW, "devices": UNIFI_RAW["devices"] + [UDM], "firewall_policies": POLICIES}
    raw["firewall_zones"] = []
    gaps = policy_gaps(raw)
    assert any("zone policies name zones that were not collected" in gap for gap in gaps)
    assert _unifi_collector(monkeypatch).normalize(raw).sections["policy"].status == "partial"


# --- Equinix Network Edge circuits -------------------------------------------------------


def test_a_refused_virtual_device_circuit_search_fails_connections(monkeypatch):
    import json

    import httpx
    from tests.test_equinix_network_edge import EDGE_DEVICE, _config, _transport

    from hst.collectors import equinix
    from hst.collectors.equinix import EquinixCollector

    transport, _calls = _transport([EDGE_DEVICE])

    def handler(request):
        body = json.loads(request.content) if request.content else None
        if (
            body
            and "filter" in body
            and body["filter"]["or"][0]["property"] == equinix.A_SIDE_VIRTUAL_DEVICE_PROPERTY
        ):
            return httpx.Response(403, json={})
        return transport.handle_request(request)

    monkeypatch.setattr(equinix, "_transport", lambda config: httpx.MockTransport(handler))
    collector = EquinixCollector(_config(network_edge=True), None)
    batch = collector.normalize(collector.fetch())
    assert batch.sections["network_edge_connections"].status == "unauthorized"
    assert batch.sections["connections"].status == "failed"
    assert section_verdict(batch.sections, EquinixCollector.AUTHORITATIVE_SECTIONS) == "failed"


# --- VyOS 1.3 configuration --------------------------------------------------------------


_VYOS13_CONFIG: dict[str, Any] = {
    "system": {"host-name": "edge13"},
    "interfaces": {
        "ethernet": {"eth0": {"address": ["192.0.2.1/24"], "firewall": {"in": {"name": "WAN-IN"}}}}
    },
    "firewall": {"name": {"WAN-IN": {"default-action": "drop", "rule": {"10": {"action": "accept"}}}}},
    "protocols": {"bgp": {"65001": {"neighbor": {"192.0.2.2": {"remote-as": "65002"}}}}},
}


def _vyos_raw(config: dict[str, Any], version: str) -> dict[str, Any]:
    return {
        "config": copy.deepcopy(config),
        "version_text": f"Version: VyOS {version}\n",
        RAW_OUTCOMES_KEY: {"config": {"status": "ok"}, "version": {"status": "ok"}},
    }


def test_a_vyos_13_firewall_is_a_rulebase_that_decides_nothing():
    batch = vyos.normalize_vyos(_vyos_raw(_VYOS13_CONFIG, "1.3.8"), l3dom="lab", source_name="lab")
    rulebases = [n for n in batch.nodes if n.label == "FwRulebase" and n.uid.endswith("fw:unread-legacy")]
    assert len(rulebases) == 1
    props = rulebases[0].props
    assert props["default_action_unknown"] is True and props.get("default_action") is None
    assert any(r.rel_type == "ENFORCES" and r.end_uid == rulebases[0].uid for r in batch.rels)


def test_a_vyos_13_configuration_reads_its_config_section_partial():
    sections = vyos.section_outcomes(_vyos_raw(_VYOS13_CONFIG, "1.3.8"))
    config = sections["config"]
    assert config.status == "partial"
    for part in ("firewall name", "interfaces ethernet eth0 firewall", "protocols bgp <asn>", "VyOS 1.3"):
        assert part in config.detail, part


def test_a_vyos_13_bgp_process_is_written_with_a_session_gap():
    """1.3 `protocols bgp <asn>` is not read, but the process is in the
    graph with its ASN and a session gap the simulation reports."""
    config = copy.deepcopy(_VYOS13_CONFIG)
    config["vrf"] = {"name": {"RED": {"table": "100"}}}
    config["protocols"]["vrf"] = {
        "RED": {"bgp": {"65009": {"neighbor": {"10.9.0.2": {"remote-as": "65010"}}}}}
    }
    batch = vyos.normalize_vyos(_vyos_raw(config, "1.3.8"), l3dom="lab", source_name="lab")
    procs = {
        n.uid: n.props for n in batch.nodes if n.label == "RoutingProcess" and n.props.get("proto") == "bgp"
    }
    assert sorted(p["asn"] for p in procs.values()) == [65001, 65009]
    for props in procs.values():
        assert props["session_gaps"] and "VyOS 1.3" in props["session_gaps"][0]
    assert not [n for n in batch.nodes if n.label == "BgpSession"]
    in_vrf = {r.start_uid for r in batch.rels if r.rel_type == "IN_VRF" and r.start_uid in procs}
    assert in_vrf == set(procs)


def test_a_vyos_14_bgp_process_carries_no_session_gap():
    config = {
        "system": {"host-name": "edge14"},
        "protocols": {"bgp": {"system-as": "65001", "neighbor": {"192.0.2.2": {"remote-as": "65002"}}}},
    }
    batch = vyos.normalize_vyos(_vyos_raw(config, "1.4.0"), l3dom="lab", source_name="lab")
    [proc] = [n for n in batch.nodes if n.label == "RoutingProcess" and n.props.get("proto") == "bgp"]
    assert proc.props["asn"] == 65001 and not proc.props.get("session_gaps")
    assert [n for n in batch.nodes if n.label == "BgpSession"]


@pytest.mark.parametrize(
    "protocols",
    [
        {"static": {"interface-route": {"10.20.0.0/16": {"next-hop-interface": {"vti0": {}}}}}},
        {"vrf": {"RED": {"static": {"route": {"10.30.0.0/16": {"next-hop": {"10.9.0.1": {}}}}}}}},
        {"bgp": {"65001": {"neighbor": {"192.0.2.2": {"remote-as": "65002"}}}}},
    ],
)
def test_unread_vyos_13_routing_makes_a_trace_across_the_device_undecided(monkeypatch, protocols):
    """The unread 1.3 routing marks the `config` section partial,
    and the trace's coverage check (`policy_evidence`) reads that section of
    the pinned run, so a leg across the device is undecided and names it."""
    import importlib

    from hst.path.gates import Stage, _Trail

    trace = importlib.import_module("hst.path.trace")
    config = {"system": {"host-name": "edge13"}, "protocols": protocols}
    sections = vyos.section_outcomes(_vyos_raw(config, "1.3.8"))
    assert sections["config"].status == "partial"
    entry = SimpleNamespace(
        host="edge13", source="lab", outcome="ok", carried=False, effective_run="run-1", sections=sections
    )
    manifest = SimpleNamespace(devices=[entry], sources=[SimpleNamespace(name="lab", type="vyos")])
    session = SimpleNamespace(snapshot=SimpleNamespace(manifest=manifest))
    monkeypatch.setattr(trace, "aci_contract_verdict", lambda *_args: None)
    monkeypatch.setattr(trace, "unevaluated_gates", lambda *_args: [])
    monkeypatch.setattr(
        "hst.path._read",
        lambda _session, query, **_params: (
            [{"host": "edge13", "source": "lab", "scope": "lab:edge13"}]
            if "RETURN d.hostname AS host" in query
            else []
        ),
    )
    trail = _Trail()
    trail.hop("dev:edge13", "Device", "edge13", stage=Stage.DEVICE)
    legs: list[dict[str, Any]] = [{"verdict": "forwarded", "blocked": False}]
    verdict = trace._flow_gates(session, trail, legs, "a → b: forwarded", "10.0.0.1", "10.20.0.5", 443, "tcp")
    assert legs[0]["indeterminate"] is True
    assert "config=partial" in legs[0]["indeterminate_reason"]
    assert "not collected completely" in verdict


def test_a_vyos_13_policy_route_binding_leaves_the_interface_undecided():
    """A 1.3 `interfaces ... policy route` binding is not read, so the
    interface holds a policy whose one rule claims every flow undecided."""
    from hst.path.gates.pbr import partition_rules

    config = copy.deepcopy(_VYOS13_CONFIG)
    config["interfaces"]["ethernet"]["eth0"]["vif"] = {"10": {"policy": {"route": "STEER"}}}
    batch = vyos.normalize_vyos(_vyos_raw(config, "1.3.8"), l3dom="lab", source_name="lab")
    policies = [n for n in batch.nodes if n.label == "PbrPolicy" and "unread-legacy" in n.uid]
    assert len(policies) == 1
    bound = {r.start_uid for r in batch.rels if r.rel_type == "ENFORCES" and r.end_uid == policies[0].uid}
    assert uid.interface("dev:edge13", "eth0.10") in bound
    rules = [r.end_uid for r in batch.rels if r.rel_type == "HAS_RULE" and r.start_uid == policies[0].uid]
    rule = next(n for n in batch.nodes if n.label == "FwRule" and n.uid == rules[0])
    assert rule.props["states_opaque"] is True
    assert "policy route STEER on eth0.10" in rule.props["states_opaque_reason"]
    assert not [r for r in batch.rels if r.start_uid == rule.uid and r.rel_type in ("SRC", "DST", "SVC")]
    row = {
        "pol_uid": policies[0].uid,
        "pol_name": policies[0].props["name"],
        "rule_uid": rule.uid,
        "pos": 1,
        "states_opaque": True,
        "states_opaque_reason": rule.props["states_opaque_reason"],
    }
    groups = partition_rules([row], [(4, 1, 2)], [(4, 3, 4)], "vrf:dev:edge13:default")
    assert [g["opaque"] for g in groups] == [True]


def test_a_vyos_15_configuration_is_read_in_full():
    config = {"system": {"host-name": "edge15"}, "interfaces": {"ethernet": {"eth0": {}}}}
    raw = _vyos_raw(config, "1.5-rolling-202410")
    assert vyos.section_outcomes(raw)["config"].status == "ok"
    batch = vyos.normalize_vyos(raw, l3dom="lab", source_name="lab")
    assert not any(n.uid.endswith("fw:unread-legacy") for n in batch.nodes)


def test_a_refusal_recorded_ok_on_a_vyos_read_replays_as_the_refusal():
    raw = _vyos_raw({"system": {"host-name": "edge15"}}, "1.5-rolling-202410")
    raw["link_speeds"] = "% Permission denied\n"
    raw[RAW_OUTCOMES_KEY]["link_speeds"] = {"status": "ok"}
    assert effective_outcomes(raw, {})["link_speeds"].status == "unauthorized"
    assert vyos.section_outcomes(raw)["link_speeds"].status == "unauthorized"


# --- the ARP cable rule's side-store read ------------------------------------------------


def test_an_unreadable_side_store_costs_the_arp_cable_rule_with_a_warning(monkeypatch, tmp_path):
    from hst import reasoner
    from hst.core import sidestore

    class _Session:
        def run(self, query, **params):
            rows = (
                [_edge_addr("10.9.9.1")] if query == reasoner.FETCH_SDWAN_ADDRESSES else [{"uid": "dev:sw1"}]
            )

            class _R:
                def data(self_inner):
                    return rows

            return _R()

    def broken(_store, _sql):
        raise RuntimeError("parquet file is truncated")

    monkeypatch.setattr(sidestore, "query", broken)
    report = reasoner.derive_arp_cables(_Session(), collection_ts=1, sidestore_dir=tmp_path)
    assert report["edges"] == 0
    assert report["not_evaluated"] == 1
    assert "unresolved" not in report
    assert report["warnings"] and "side store not read (RuntimeError)" in report["warnings"][0]
