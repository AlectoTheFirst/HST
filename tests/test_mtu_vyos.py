"""VyOS MTU evidence: synthetic payloads, never estate captures."""

import copy
import json
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.conftest import FakeSshSession
from tests.test_mtu_budget import request as size_request
from tests.test_mtu_snapshot import row

from hst import path
from hst.collectors.auth import SshPassword
from hst.collectors.base import RAW_OUTCOMES_KEY, raw_sha
from hst.collectors.vyos import VyosCollector, VyosConfig, normalize_vyos, section_outcomes
from hst.core import uid
from hst.core.mtu import (
    MTU_NORMALIZATION_VERSION,
    MtuContext,
    MtuCoverage,
    MtuObservation,
    MtuRequest,
    MtuStage,
)
from hst.core.mtu_read import resolve_constraints
from hst.path.gates import _Trail
from hst.path.mtu import constraint_budget, evaluate_stage
from hst.path.mtu_topology import TOPOLOGY_QUERY, _tag_depth_from_name, crossing, mtu_request, trace_scope

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures/mtu/vyos/netdevice.json"
# minted by the in-memory registry from the host-name in the fixture
DEV = "dev:mtu-fixture"
SNAP = 42


def payload():
    return json.loads(FIXTURE.read_text())


def collector():
    return VyosCollector(VyosConfig(host="synthetic", auth=SshPassword(username="ro", password="fake")), None)


def observations(raw, name="eth0"):
    batch = normalize_vyos(raw, l3dom="fixture", source_name="fixture")
    batch.validate_registry()
    return [
        MtuObservation(uid=n.uid, **n.props)
        for n in batch.nodes
        if n.label == "MtuObservation" and n.props["subject_uid"] == uid.interface(DEV, name)
    ]


def test_operational_mtu_survives_bad_mac_and_config_drift():
    obs = observations(payload())
    resolved = resolve_constraints(obs, MtuContext(af=4))
    assert [c.value_bytes for c in resolved.constraints] == [1500]
    assert [c.value_bytes for c in resolved.configured] == [9000]
    assert any(f.code == "MTU_POLICY_DRIFT" for f in resolved.findings)
    assert {o.raw_value_json for o in obs if o.af == 4} == {'"9000"', "1500"}


def test_receive_is_a_ceiling_and_ipv6_protocol_is_independent_unknown():
    obs = observations(payload())
    receive = resolve_constraints(obs, MtuContext(af=4, direction="rx"))
    assert receive.constraints[0].bound_kind == "ceiling"
    assert receive.constraints[0].value_bytes == 1500
    netdevice = [o for o in obs if o.enforcement_key == "netdevice"]
    assert netdevice and all(o.direction == "both" and o.bound_kind == "ceiling" for o in netdevice)
    ipv6 = [o for o in obs if o.af == 6 and o.assertion_kind == "operational"]
    assert {(o.enforcement_key, o.direction, o.normalized_value) for o in ipv6} == {
        ("netdevice", "both", 1500),
        ("ipv6_protocol", "tx", None),
    }
    assert "MTU_NOT_CAPTURED" in next(o for o in ipv6 if o.enforcement_key == "ipv6_protocol").gaps
    configured = [o for o in obs if o.enforcement_key == "netdevice" and o.assertion_kind == "configured"]
    assert configured and all(o.direction == "both" and o.bound_kind == "ceiling" for o in configured)
    configured_rx = resolve_constraints(
        [o for o in obs if o.assertion_kind == "configured"], MtuContext(af=4, direction="rx")
    )
    assert configured_rx.constraints[0].bound_kind == "ceiling"
    assert configured_rx.constraints[0].value_bytes == 9000


@pytest.mark.parametrize(
    "name,budget", [("eth0.10", 1500), ("bond0", 9000), ("br0", 9000), ("wg0", 1420), ("tun0", 1476)]
)
def test_logical_interfaces_without_mac_keep_subject_and_budget(name, budget):
    obs = observations(payload(), name)
    actual = next(o for o in obs if o.af == 4 and o.direction == "both" and o.assertion_kind == "operational")
    assert actual.normalized_value == budget
    assert actual.subject_uid == uid.interface(DEV, name)
    if name in {"wg0", "tun0"}:
        assert actual.enforcement == "tunnel"


def test_parent_and_aggregate_evidence_does_not_invent_active_members():
    child = json.loads(observations(payload(), "eth0.10")[0].selector_json)
    assert child["parent_subject_uid"] == uid.interface(DEV, "eth0")
    bond = json.loads(observations(payload(), "bond0")[0].selector_json)
    assert bond["configured_member_uids"] == [uid.interface(DEV, "eth1"), uid.interface(DEV, "eth2")]
    assert bond["master_subject_uid"] == uid.interface(DEV, "br0")
    assert bond["member_eligibility"] == "unknown"
    member = json.loads(observations(payload(), "eth2")[0].selector_json)
    assert member["master_subject_uid"] == uid.interface(DEV, "bond0")
    assert member["operstate"] == "DOWN"


@pytest.mark.parametrize("status", ["failed", "malformed", "unauthorized", "unsupported", "not-captured"])
def test_failed_optional_outcome_vetoes_stale_operational_bytes(status):
    raw = payload()
    raw[RAW_OUTCOMES_KEY] = {"links": {"status": status}}
    actual = [o for o in observations(raw) if o.assertion_kind == "operational"]
    assert all(o.normalized_value is None for o in actual)
    assert all("MTU_NOT_CAPTURED" in o.gaps for o in actual)
    assert section_outcomes(raw)["links"].status == ("unknown" if status == "not-captured" else status)


@pytest.mark.parametrize("value", [True, 0, -1, "inherit", {}, [1500], 1500.5, float("nan")])
def test_malformed_mtu_preserved_without_normalized_ceiling(value):
    raw = payload()
    raw["links"][0]["mtu"] = value
    actual = [o for o in observations(raw) if o.assertion_kind == "operational"]
    assert all(o.normalized_value is None for o in actual)
    assert all("MTU_SEMANTICS_UNKNOWN" in o.gaps for o in actual)


def test_duplicate_identity_is_not_last_row_wins():
    raw = payload()
    raw["links"].append({"ifname": "eth0", "mtu": 9000})
    actual = [
        o for o in observations(raw) if o.enforcement_key == "netdevice" and o.assertion_kind == "operational"
    ]
    assert all(o.resolution_state == "conflict" and o.normalized_value is None for o in actual)


def test_raw_without_mtu_yields_no_observation_and_no_default():
    raw = {"version_text": payload()["version_text"], "config": {"interfaces": {"ethernet": {"eth0": {}}}}}
    assert observations(raw) == []
    raw[RAW_OUTCOMES_KEY] = {"links": {"status": "empty"}}
    assert all(o.normalized_value is None for o in observations(raw))


def test_hash_includes_mtu_and_optional_outcomes():
    raw = payload()
    source = collector()
    # stored payloads re-derive their read-failure outcomes; "firewall"
    # marks the rulesets' installation evidence, then jump targets and
    # NAT group scope, then intra-zone filtering;
    # "read-failures" 2 the 1.3 policy bindings; "static", "tunnel", "bgp" and "serial"
    # mark the floating static forms, the 1.3+ tunnel keys, the BGP peer-group
    # inheritance and the placeholder serials; "bgp_session_filters" the
    # BgpSession's route-reflector-client and filter settings;
    # "link_local" the interfaces' IPv6 link-local addresses
    # "bgp" 3 the session's cluster id and the process's unwritten neighbors;
    # "static" 2 the 1.4 `vrf` leak of a static route;
    # "bgp_multipath" the process's maximum-paths and multipath-relax;
    # "bgp_peer_router_id" the session's peer router id; "static" 3 a
    # next hop's own interface and dhcp-interface routes, "tunnel" 2
    # the WireGuard uid with its interface, "bgp" 4 the listen-range
    # peers, "membership" the bonds and bridge members,
    # "family" the address family of a PbrPolicy and a NatRule and
    # "rib_mirror" a VrfInstance's `rib_mirrored` and "static_uplink" the
    # WanLink of a statically addressed uplink
    assert source.NORMALIZATION_VERSIONS == {
        "mtu": MTU_NORMALIZATION_VERSION,
        "read-failures": "2",
        "iface_uid": uid.IFACE_UID_VERSION,
        "firewall": "3",
        "static": "3",
        "tunnel": "2",
        "link_local": "1",
        "bgp": "4",
        "serial": "1",
        "bgp_session_filters": "1",
        "bgp_multipath": "1",
        "bgp_peer_router_id": "1",
        "membership": "1",
        "family": "1",
        "rib_mirror": "1",
        "static_uplink": "1",
    }
    assert "links" not in source.VOLATILE_RAW_KEYS
    assert "links" not in source.OBSERVATION_RAW_KEYS
    changed = copy.deepcopy(raw)
    changed["links"][0]["mtu"] = 9000
    assert raw_sha(source, raw) != raw_sha(source, changed)
    raw[RAW_OUTCOMES_KEY] = {"links": {"status": "ok"}}
    changed = copy.deepcopy(raw)
    changed[RAW_OUTCOMES_KEY]["links"]["status"] = "failed"
    assert raw_sha(source, raw) != raw_sha(source, changed)


def test_optional_link_shape_error_is_recorded_and_fetch_continues(monkeypatch):
    def output(command):
        if "show configuration json" in command:
            return "{}"
        if "show version" in command:
            return payload()["version_text"]
        if "link show" in command:
            return '{"mtu":1500}'
        if "addr show" in command:
            return "[]"
        return "{}"

    FakeSshSession(output).install(monkeypatch)
    raw = collector().fetch()
    assert raw["links"] == []
    assert section_outcomes(raw)["links"].status == "malformed"


def test_foreign_namespace_parent_never_resolves_against_local_index():
    raw = payload()
    raw["links"][1].pop("link")
    raw["links"][1].update(link_index=2, link_netnsid=0)
    obs = observations(raw, "eth0.10")
    context = json.loads(obs[0].selector_json)
    assert context["parent_subject_uid"] is None
    assert context["configured_parent_subject_uid"] == uid.interface(DEV, "eth0")
    assert "MTU_PATH_COVERAGE_INCOMPLETE" in obs[0].gaps


def test_qinq_mtu_retains_two_tag_identity_without_flattened_vlan_claim():
    raw = payload()
    raw["config"]["interfaces"]["ethernet"]["eth0"]["vif-s"] = {
        "100": {"mtu": "1500", "vif-c": {"200": {"mtu": "1496"}}}
    }
    raw["links"].extend(
        [
            {"ifname": "eth0.100", "link": "eth0", "mtu": 1500},
            {"ifname": "eth0.100.200", "link": "eth0.100", "mtu": 1496},
        ]
    )
    obs = observations(raw, "eth0.100.200")
    actual = next(o for o in obs if o.assertion_kind == "operational" and o.af == 4 and o.direction == "both")
    assert actual.normalized_value == 1496  # Linux MTU excludes tags
    context = json.loads(actual.selector_json)
    assert context["configured_tag_depth"] == 2
    assert context["parent_subject_uid"] == uid.interface(DEV, "eth0.100")
    assert context["qinq_carriage_unmodeled"]
    assert "MTU_PATH_COVERAGE_INCOMPLETE" in actual.gaps


def test_links_error_note_vetoes_operational_mtu_without_reserved_outcome():
    raw = payload()
    raw["links_error"] = "CommandFailed: synthetic failure"
    actual = [o for o in observations(raw) if o.assertion_kind == "operational"]
    assert all(o.normalized_value is None for o in actual)
    assert all("MTU_NOT_CAPTURED" in o.gaps for o in actual)


# --- the ethernet port's L2 frame ceiling ----------------------------------------------


def port_observations(raw, name="eth0"):
    batch = normalize_vyos(raw, l3dom="fixture", source_name="fixture")
    batch.validate_registry()
    return [
        MtuObservation(uid=n.uid, **n.props)
        for n in batch.nodes
        if n.label == "MtuObservation" and n.props["subject_uid"] == uid.port(DEV, name)
    ]


def _l2_stage(port_uid, constraint, *, direction="tx", tag_depth):
    return MtuStage(
        stage_id="port",
        egress_subject_uid=port_uid if direction == "tx" else None,
        ingress_subject_uid=port_uid if direction == "rx" else None,
        enforcement="l2",
        context=MtuContext(af=4, direction=direction, tag_depth=tag_depth),
        constraints=[constraint],
        selection="selected",
        coverage=MtuCoverage(
            complete=True, candidate_set_complete=True, constraints_complete=True, exact_path_known=True
        ),
    )


def test_port_eth0_frame_ceiling_carries_a_four_byte_tag_allowance():
    port_uid = uid.port(DEV, "eth0")
    frame = next(o for o in port_observations(payload(), "eth0") if o.metric == "l2_max_frame_bytes")
    assert frame.subject_uid == port_uid
    assert frame.raw_basis == "ethernet_frame_excluding_fcs"
    assert frame.normalized_value == 1518  # 1500 MTU + 14 header, plus the 4-byte tag allowance
    assert frame.tag_accounting == "extra_allowance"
    assert frame.tag_allowance_bytes == 4
    assert frame.bound_kind == "ceiling" and frame.direction == "both"


def test_a_1500_byte_packet_on_the_vif_passes_the_port_stage():
    port_uid = uid.port(DEV, "eth0")
    frame = next(o for o in port_observations(payload(), "eth0") if o.metric == "l2_max_frame_bytes")
    constraint = resolve_constraints([frame], MtuContext(af=4, enforcement="l2", tag_depth=1)).constraints[0]
    stage = _l2_stage(port_uid, constraint, tag_depth=1)
    assert evaluate_stage(stage, size_request(1500)).outcome == "pass"
    assert constraint_budget(constraint, stage) == (1500, [])


def test_a_1500_byte_packet_on_a_qinq_vif_passes_the_port_stage_at_depth_two():
    """Linux allows the VLAN overhead above the MTU for each tag."""
    port_uid = uid.port(DEV, "eth0")
    frame = next(o for o in port_observations(payload(), "eth0") if o.metric == "l2_max_frame_bytes")
    constraint = resolve_constraints([frame], MtuContext(af=4, enforcement="l2", tag_depth=2)).constraints[0]
    stage = _l2_stage(port_uid, constraint, tag_depth=2)
    assert constraint_budget(constraint, stage) == (1500, [])
    assert evaluate_stage(stage, size_request(1500)).outcome == "pass"


def test_a_low_parent_mtu_fails_the_port_stage_for_a_vif_packet():
    raw = payload()
    eth0 = next(row for row in raw["links"] if row["ifname"] == "eth0")
    eth0["mtu"] = 1400
    port_uid = uid.port(DEV, "eth0")
    frame = next(o for o in port_observations(raw, "eth0") if o.metric == "l2_max_frame_bytes")
    assert frame.normalized_value == 1418  # 1400 + 14 + the 4-byte tag allowance
    constraint = resolve_constraints([frame], MtuContext(af=4, enforcement="l2", tag_depth=1)).constraints[0]
    stage = _l2_stage(port_uid, constraint, tag_depth=1)
    assert constraint_budget(constraint, stage) == (1400, [])
    result = evaluate_stage(stage, size_request(1500))
    assert result.outcome == "fail"
    assert port_uid in result.findings[0].subject_uids


def test_port_frame_ceiling_stays_unknown_when_the_operational_read_fails():
    raw = payload()
    raw["links_error"] = "CommandFailed: synthetic failure"
    frame = next(o for o in port_observations(raw, "eth0") if o.metric == "l2_max_frame_bytes")
    assert frame.normalized_value is None
    assert "MTU_NOT_CAPTURED" in frame.gaps


@pytest.mark.parametrize(
    "name,depth",
    [("eth0", 0), ("eth0.10", 1), ("eth0.100.200", 2), ("GigabitEthernet0/0/0/0.20", 1), (None, None)],
)
def test_tag_depth_from_name_reads_the_dot_suffixed_vlan_id(name, depth):
    assert _tag_depth_from_name(name) == depth


# --- the trace clones an l2 stage for a VLAN subinterface's port -----------------------


def test_a_vif_crossing_yields_an_l2_stage_on_its_physical_port(monkeypatch):
    raw = payload()
    batch = normalize_vyos(raw, l3dom="fixture", source_name="fixture")
    batch.validate_registry()
    vif_uid = uid.interface(DEV, "eth0.10")
    port_uid = uid.port(DEV, "eth0")
    assert any(
        r.rel_type == "REALIZED_BY" and r.start_uid == vif_uid and r.end_uid == port_uid for r in batch.rels
    )
    by_subject: dict[str, list[MtuObservation]] = defaultdict(list)
    for n in batch.nodes:
        if n.label == "MtuObservation":
            obs = MtuObservation(uid=n.uid, **n.props)
            by_subject[obs.subject_uid].append(obs)
    topology = {
        vif_uid: [
            {
                "subject_uid": vif_uid,
                "subject": {"name": "eth0.10"},
                "carrier_uid": port_uid,
                "carrier_is_lag": False,
                "member_uid": None,
                "eligible": None,
            }
        ]
    }

    def fake_read(session, query, **params):
        if "HAS_MTU" in query:
            rows = []
            for subject in params["subject_uids"]:
                rows.extend(row(o, SNAP) for o in by_subject.get(subject, []))
            return rows
        if query == TOPOLOGY_QUERY:
            return [r for subject in params["subject_uids"] for r in topology.get(subject, [])]
        return []

    monkeypatch.setattr(path, "_read", fake_read)

    @trace_scope()
    def walk(session):
        crossing(_Trail(), vif_uid, enforcement="l3")
        return {}

    with mtu_request(MtuRequest(mode="unfragmented", ip_packet_bytes=1500), 4):
        result = walk(SimpleNamespace(cts=SNAP))["mtu"]

    l2_stages = [s for s in result["stages"] if s["enforcement"] == "l2"]
    assert len(l2_stages) == 1
    stage = l2_stages[0]
    assert stage["egress_subject_uid"] == port_uid
    assert stage["context"]["tag_depth"] == 1
    assert "MTU_NOT_CAPTURED" not in stage["coverage"]["gaps"]
    frame_values = {c["value_bytes"] for c in stage["constraints"] if c["metric"] == "l2_max_frame_bytes"}
    assert frame_values == {1518}


def _vif_trace(monkeypatch, raw, ip_packet_bytes, ipv4_df):
    """The wiring of the l2-clone test above in `packet` mode."""
    batch = normalize_vyos(raw, l3dom="fixture", source_name="fixture")
    batch.validate_registry()
    vif_uid = uid.interface(DEV, "eth0.10")
    port_uid = uid.port(DEV, "eth0")
    by_subject: dict[str, list[MtuObservation]] = defaultdict(list)
    for n in batch.nodes:
        if n.label == "MtuObservation":
            obs = MtuObservation(uid=n.uid, **n.props)
            by_subject[obs.subject_uid].append(obs)
    topology = {
        vif_uid: [
            {
                "subject_uid": vif_uid,
                "subject": {"name": "eth0.10"},
                "carrier_uid": port_uid,
                "carrier_is_lag": False,
                "member_uid": None,
                "eligible": None,
            }
        ]
    }

    def fake_read(session, query, **params):
        if "HAS_MTU" in query:
            rows = []
            for subject in params["subject_uids"]:
                rows.extend(row(o, SNAP) for o in by_subject.get(subject, []))
            return rows
        if query == TOPOLOGY_QUERY:
            return [r for subject in params["subject_uids"] for r in topology.get(subject, [])]
        return []

    monkeypatch.setattr(path, "_read", fake_read)

    @trace_scope()
    def walk(session):
        crossing(_Trail(), vif_uid, enforcement="l3")
        return {}

    with mtu_request(MtuRequest(mode="packet", ip_packet_bytes=ip_packet_bytes, ipv4_df=ipv4_df), 4):
        return walk(SimpleNamespace(cts=SNAP))["mtu"]


def test_egress_port_clone_does_not_re_fail_an_already_fragmented_packet(monkeypatch):
    result = _vif_trace(monkeypatch, payload(), ip_packet_bytes=1600, ipv4_df=False)
    assert result["outcome"] == "fragmentation_required"
    deficits = [f for f in result["findings"] if f["code"] == "MTU_CAPACITY_DEFICIT"]
    port_uid = uid.port(DEV, "eth0")
    assert not any(port_uid in f["subject_uids"] for f in deficits)
    assert any(s["enforcement"] == "l2" for s in result["stages"])


def test_a_vif_mtu_set_above_its_port_capacity_fails(monkeypatch):
    """The router's IP stack does not see the narrower physical port."""
    raw = payload()
    eth0 = next(row for row in raw["links"] if row["ifname"] == "eth0")
    eth0["mtu"] = 1400  # port frame ceiling 1400+14+4=1418, budget 1400 at depth 1
    # eth0.10 keeps its 1500 mtu entry from the fixture, above the port's capacity.
    result = _vif_trace(monkeypatch, raw, ip_packet_bytes=1450, ipv4_df=False)
    assert result["outcome"] == "fail"
    deficits = [f for f in result["findings"] if f["code"] == "MTU_CAPACITY_DEFICIT"]
    assert any(uid.port(DEV, "eth0") in f["subject_uids"] for f in deficits)


def test_a_qinq_crossing_is_realized_by_the_same_physical_port():
    raw = payload()
    raw["config"]["interfaces"]["ethernet"]["eth0"]["vif-s"] = {
        "100": {"mtu": "1500", "vif-c": {"200": {"mtu": "1496"}}}
    }
    batch = normalize_vyos(raw, l3dom="fixture", source_name="fixture")
    batch.validate_registry()
    port_uid = uid.port(DEV, "eth0")
    vif_s_uid = uid.interface(DEV, "eth0.100")
    vif_c_uid = uid.interface(DEV, "eth0.100.200")
    realized = {
        r.start_uid
        for r in batch.rels
        if r.rel_type == "REALIZED_BY" and r.end_uid == port_uid and r.start_label == "Interface"
    }
    assert {vif_s_uid, vif_c_uid} <= realized
    assert _tag_depth_from_name("eth0.100.200") == 2
