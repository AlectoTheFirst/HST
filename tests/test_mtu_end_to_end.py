"""MTU acceptance cases over the synthetic estate fixture."""

from __future__ import annotations

import copy
import json
from collections import defaultdict
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.app.conftest import app, client, login, seeded, store  # noqa: F401
from tests.test_mtu_apic import observations as batch_observations
from tests.test_mtu_assessment import network as assessment_network
from tests.test_mtu_assessment import request as assessment_request
from tests.test_mtu_assessment import wire as assessment_wire
from tests.test_mtu_budget import request as size_request
from tests.test_mtu_budget import stage as pure_stage
from tests.test_mtu_contract import observation
from tests.test_mtu_encap import encap, esp, vxlan
from tests.test_mtu_feedback import hop, quoted
from tests.test_mtu_snapshot import row
from tests.test_path_trace import FakeGraph, _lb_member, _lb_vs, _route, _src_row

from hst import path
from hst.app.routes import path as path_route
from hst.assessment.mtu import audit_members, audit_neighbors
from hst.assessment.resilience import apply_failures
from hst.assessment.store import input_digest
from hst.collectors.apic import normalize_apic
from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.collectors.cisco_common import MTU_COMMANDS, normalize_cisco, parse_mtu
from hst.collectors.iosxe import CMD_INTERFACE_CONFIG as XE_CONFIG_COMMAND
from hst.collectors.mtu_import import parse_mtu_import
from hst.collectors.vyos import normalize_vyos
from hst.core import uid
from hst.core.mtu import (
    MtuContext,
    MtuCoverage,
    MtuPolicyApplication,
    MtuRequest,
    MtuResult,
    MtuStage,
    mtu_fingerprint,
)
from hst.core.mtu_audit_read import audit_mtu
from hst.core.mtu_profiles import observation_from_raw
from hst.core.mtu_read import read_mtu, resolve_constraints
from hst.impact.evaluate import MtuRequirement, answer
from hst.path.mtu import constraint_budget, evaluate_stage, evaluate_stages
from hst.path.mtu_encap import inner_budget
from hst.path.mtu_feedback import build_feedback_packet, evaluate_feedback, request_for_connection
from hst.path.mtu_topology import MAX_STAGES, TOPOLOGY_QUERY, expand_stages
from hst.path.session import GATEWAYS

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures/mtu/estate/estate.json"
FIXTURE = json.loads(FIXTURE_PATH.read_text())
SNAP = FIXTURE["snapshot"]
OTHER_SNAP = FIXTURE["other_snapshot"]
ADDR = FIXTURE["addresses"]
DEVICES = FIXTURE["devices"]
FABRIC = DEVICES["aci"]["fabric"]

# minted by the in-memory registry from the hostnames in the fixture
DEV_XE = f"dev:{DEVICES['access']['hostname']}"
DEV_XR = f"dev:{DEVICES['core']['hostname']}"
DEV_PROXY = DEVICES["proxy"]["uid"]
DEV_ACI = f"dev:{DEVICES['aci']['hostname']}"
DEV_HOST = f"dev:{DEVICES['host']['hostname']}"

IF_XE_VLAN10 = uid.interface(DEV_XE, "Vlan10")
IF_XE_PO1 = uid.interface(DEV_XE, "Port-channel1")
LAG_XE_PO1 = uid.lag(DEV_XE, "Port-channel1")
PORT_XE_GI1 = uid.port(DEV_XE, "GigabitEthernet1/0/1")
PORT_XE_GI2 = uid.port(DEV_XE, "GigabitEthernet1/0/2")
PORT_XE_GI3 = uid.port(DEV_XE, "GigabitEthernet1/0/3")
PORT_XE_GI10 = uid.port(DEV_XE, "GigabitEthernet1/0/10")
IF_XE_GI1 = uid.interface(DEV_XE, "GigabitEthernet1/0/1")
IF_XR_GI0 = uid.interface(DEV_XR, "GigabitEthernet0/0/0/0")
IF_XR_GI0_20 = uid.interface(DEV_XR, "GigabitEthernet0/0/0/0.20")
IF_XR_GI1 = uid.interface(DEV_XR, "GigabitEthernet0/0/0/1")
IF_XR_GI2 = uid.interface(DEV_XR, "GigabitEthernet0/0/0/2")
IF_XR_NVE1 = uid.interface(DEV_XR, "nve1")
PORT_XR_GI0 = uid.port(DEV_XR, "GigabitEthernet0/0/0/0")
PORT_XR_GI1 = uid.port(DEV_XR, "GigabitEthernet0/0/0/1")
PORT_XR_GI2 = uid.port(DEV_XR, "GigabitEthernet0/0/0/2")
IF_PROXY_ETH0 = uid.interface(DEV_PROXY, "eth0")
IF_PROXY_ETH1 = uid.interface(DEV_PROXY, "eth1")
IF_PROXY_ETH2 = uid.interface(DEV_PROXY, "eth2")
L3OUT_DN = FIXTURE["apic"]["l3extRsPathL3OutAtt"][0]["l3extRsPathL3OutAtt"]["attributes"]["dn"]
IF_ACI_L3OUT = uid.aci(FABRIC, L3OUT_DN)
PORT_ACI_ETH1_1 = f"{DEV_ACI}/port/{uid.slug('eth1/1')}"
PORT_ACI_ETH1_2 = f"{DEV_ACI}/port/{uid.slug('eth1/2')}"
IF_ACI_BD = FIXTURE["topology"]["stretch_without_evidence"]["aci_bridge_domain_interface"]
IF_HOST_ETH0 = uid.interface(DEV_HOST, "eth0")
EP_CLIENT = FIXTURE["import"]["observations"][0]["subject_uid"]
VRF_XE, VRF_XR, VRF_PROXY, VRF_ACI = (
    "vrf:estate-access",
    "vrf:estate-core",
    "vrf:estate-proxy",
    "vrf:estate-aci",
)
VIP = FIXTURE["trace"]["vip_service"]
TUNNEL = FIXTURE["trace"]["vxlan_tunnel"]
GATEWAY = {
    "cidr": ADDR["client_prefix"],
    "l3dom": "estate",
    "if_uid": IF_XE_VLAN10,
    "if_name": "Vlan10",
    "dev_uid": DEV_XE,
    "dev_name": DEVICES["access"]["hostname"],
}


# --- collector normalization over the fixture -------------------------------------------


def cisco_batch(family, *, raw=None):
    spec = FIXTURE["cisco"][family]
    inter = copy.deepcopy(spec["intermediate"])
    raw = dict(spec["raw"]) if raw is None else raw
    config = XE_CONFIG_COMMAND if family == "iosxe" else MTU_COMMANDS["iosxr"]["config"]
    parse_mtu(raw, inter, family=family, config_command=config)
    return normalize_cisco(inter, source=family, scope=f"estate:{family}", l3dom="estate")


def vyos_batch(raw=None):
    return normalize_vyos(
        copy.deepcopy(FIXTURE["vyos"]) if raw is None else raw, l3dom="estate", source_name="estate-host"
    )


def apic_batch(raw=None):
    return normalize_apic(
        copy.deepcopy(FIXTURE["apic"]) if raw is None else raw, fabric=FABRIC, l3dom="estate"
    )


def imported_observations():
    imported = parse_mtu_import(json.dumps(FIXTURE["import"]))
    return [entry.observation("estate-import") for entry in imported.observations]


def synthetic_observations():
    rows = []
    for member in FIXTURE["synthetic"]["access_member_ports"]:
        rows.append(
            observation_from_raw(
                subject_uid=uid.port(DEV_XE, member["port"]),
                source="synthetic-estate",
                source_target="fixtures/mtu/estate/estate.json",
                source_field="port_ip_payload_ceiling",
                raw_value=member["ip_payload_bytes"],
                profile_id="ip_packet",
                metric="ipv4_mtu_bytes",
                direction="tx",
                bound_kind="ceiling",
                enforcement="l2",
                enforcement_key="port",
                assertion_kind="operational",
                raw_evidence_ref="synthetic.access_member_ports",
                collector_version="fixture",
            )
        )
    for iface in FIXTURE["synthetic"]["proxy_interfaces"]:
        rows.append(
            observation_from_raw(
                subject_uid=uid.interface(DEV_PROXY, iface["name"]),
                source="synthetic-proxy",
                source_target=DEV_PROXY,
                source_field="interface_ip_mtu",
                raw_value=iface["ip_bytes"],
                profile_id="ip_packet",
                metric="ipv4_mtu_bytes",
                direction="tx",
                bound_kind="ceiling",
                enforcement="l3",
                assertion_kind="configured",
                raw_evidence_ref="synthetic.proxy_interfaces",
                collector_version="fixture",
            )
        )
    return rows


def estate_observations():
    rows = []
    for family in ("iosxe", "iosxr"):
        rows.extend(batch_observations(cisco_batch(family)))
    rows.extend(batch_observations(vyos_batch()))
    rows.extend(batch_observations(apic_batch()))
    rows.extend(imported_observations())
    rows.extend(synthetic_observations())
    return rows


def topology_rows():
    """Rows a pinned TOPOLOGY_QUERY read would return, derived from the collector batches."""
    rows = defaultdict(list)
    batch = cisco_batch("iosxe")
    members = [
        (rel.start_uid, rel.props.get("eligible"))
        for rel in batch.rels
        if rel.rel_type == "MEMBER_OF" and rel.end_uid == LAG_XE_PO1
    ]
    realized = {
        rel.start_uid: rel.end_uid
        for rel in batch.rels
        if rel.rel_type == "REALIZED_BY" and rel.start_label == "Interface" and rel.end_label == "Lag"
    }
    for member, eligible in sorted(members):
        rows[IF_XE_PO1].append(
            {
                "subject_uid": IF_XE_PO1,
                "subject": {},
                "carrier_uid": realized[IF_XE_PO1],
                "carrier_is_lag": True,
                "member_uid": member,
                "eligible": eligible,
            }
        )
    core = cisco_batch("iosxr")
    for rel in core.rels:
        if rel.rel_type == "REALIZED_BY" and rel.start_label == "Interface" and rel.end_label == "Port":
            rows[rel.start_uid].append(
                {
                    "subject_uid": rel.start_uid,
                    "subject": {},
                    "carrier_uid": rel.end_uid,
                    "carrier_is_lag": False,
                    "member_uid": None,
                    "eligible": None,
                }
            )
    l3out = next(n for n in apic_batch().nodes if n.uid == IF_ACI_L3OUT)
    rows[IF_ACI_L3OUT].append(
        {
            "subject_uid": IF_ACI_L3OUT,
            "subject": dict(l3out.props),
            "carrier_uid": None,
            "carrier_is_lag": None,
            "member_uid": None,
            "eligible": None,
        }
    )
    return rows


def _pinned(cidr, egress_uid, egress_name, **fields):
    return {**_route(cidr, egress=egress_name, **fields), "egress_uid": egress_uid}


def script_graph(graph):
    graph.sources = [
        _src_row("estate", ADDR["client"])
        | {
            "ep_uid": EP_CLIENT,
            "ep_name": "client-a",
            "att_uid": PORT_XE_GI10,
            "att_is_port": True,
            "att_name": "GigabitEthernet1/0/10",
            "sw_uid": DEV_XE,
            "sw_name": DEVICES["access"]["hostname"],
        }
    ]
    graph.sources_by_ip[ADDR["server"]] = [
        _src_row("estate", ADDR["server"])
        | {
            "ep_uid": IF_HOST_ETH0,
            "ep_name": DEVICES["host"]["hostname"],
            "att_uid": PORT_ACI_ETH1_1,
            "att_is_port": True,
            "att_name": "eth1/1",
            "sw_uid": DEV_ACI,
            "sw_name": DEVICES["aci"]["hostname"],
        }
    ]
    graph.default_tables = {
        IF_XE_VLAN10: {"uid": VRF_XE},
        IF_XE_PO1: {"uid": VRF_XE},
        IF_XR_GI0: {"uid": VRF_XR},
        IF_XR_GI1: {"uid": VRF_XR},
        IF_PROXY_ETH0: {"uid": VRF_PROXY},
        IF_PROXY_ETH1: {"uid": VRF_PROXY},
        IF_ACI_L3OUT: {"uid": VRF_ACI},
        IF_ACI_BD: {"uid": VRF_ACI},
    }
    reverse = ADDR["reverse_next_hops"]
    graph.routes = {
        VRF_XE: [
            _pinned(ADDR["client_prefix"], IF_XE_VLAN10, "Vlan10", kind="ORIGINATES"),
            _pinned(ADDR["access_core_link"], IF_XE_PO1, "Port-channel1", kind="ORIGINATES"),
            _pinned(ADDR["server_prefix"], IF_XE_PO1, "Port-channel1", next_hop=ADDR["access_core_next_hop"]),
            _pinned(ADDR["vip_prefix"], IF_XE_PO1, "Port-channel1", next_hop=ADDR["access_core_next_hop"]),
            _pinned(ADDR["remote_prefix"], IF_XE_PO1, "Port-channel1", next_hop=ADDR["access_core_next_hop"]),
        ],
        VRF_XR: [
            _pinned(ADDR["access_core_link"], IF_XR_GI0, "GigabitEthernet0/0/0/0", kind="ORIGINATES"),
            _pinned(ADDR["core_proxy_link"], IF_XR_GI1, "GigabitEthernet0/0/0/1", kind="ORIGINATES"),
            _pinned(ADDR["vxlan_underlay"], IF_XR_GI2, "GigabitEthernet0/0/0/2", kind="ORIGINATES"),
            _pinned(
                ADDR["server_prefix"],
                IF_XR_GI1,
                "GigabitEthernet0/0/0/1",
                next_hop=ADDR["core_proxy_next_hop"],
            ),
            _pinned(
                ADDR["vip_prefix"], IF_XR_GI1, "GigabitEthernet0/0/0/1", next_hop=ADDR["core_proxy_next_hop"]
            ),
            _pinned(ADDR["remote_prefix"], IF_XR_NVE1, "nve1"),
            _pinned(
                ADDR["client_prefix"], IF_XR_GI0, "GigabitEthernet0/0/0/0", next_hop=reverse["core_to_access"]
            ),
        ],
        VRF_PROXY: [
            _pinned(ADDR["core_proxy_link"], IF_PROXY_ETH0, "eth0", kind="ORIGINATES"),
            _pinned(ADDR["proxy_aci_link"], IF_PROXY_ETH1, "eth1", kind="ORIGINATES"),
            _pinned(ADDR["vip_prefix"], IF_PROXY_ETH2, "eth2", kind="ORIGINATES"),
            _pinned(ADDR["server_prefix"], IF_PROXY_ETH1, "eth1", next_hop=ADDR["proxy_aci_next_hop"]),
            _pinned(ADDR["client_prefix"], IF_PROXY_ETH0, "eth0", next_hop=reverse["proxy_to_core"]),
        ],
        VRF_ACI: [
            _pinned(ADDR["proxy_aci_link"], IF_ACI_L3OUT, "l3-port", kind="ORIGINATES"),
            _pinned(ADDR["server_prefix"], IF_ACI_BD, "BD-server", kind="ORIGINATES"),
            _pinned(ADDR["client_prefix"], IF_ACI_L3OUT, "l3-port", next_hop=reverse["aci_to_proxy"]),
        ],
    }
    graph.next_hop_devs = {
        ADDR["access_core_next_hop"]: {
            "dev_uid": DEV_XR,
            "dev_name": DEVICES["core"]["hostname"],
            "if_uid": IF_XR_GI0,
            "if_name": "GigabitEthernet0/0/0/0",
        },
        ADDR["core_proxy_next_hop"]: {
            "dev_uid": DEV_PROXY,
            "dev_name": DEVICES["proxy"]["hostname"],
            "if_uid": IF_PROXY_ETH0,
            "if_name": "eth0",
        },
        ADDR["proxy_aci_next_hop"]: {
            "dev_uid": DEV_ACI,
            "dev_name": DEVICES["aci"]["hostname"],
            "if_uid": IF_ACI_L3OUT,
            "if_name": "l3-port",
        },
        reverse["core_to_access"]: {
            "dev_uid": DEV_XE,
            "dev_name": DEVICES["access"]["hostname"],
            "if_uid": IF_XE_PO1,
            "if_name": "Port-channel1",
        },
        reverse["proxy_to_core"]: {
            "dev_uid": DEV_XR,
            "dev_name": DEVICES["core"]["hostname"],
            "if_uid": IF_XR_GI1,
            "if_name": "GigabitEthernet0/0/0/1",
        },
        reverse["aci_to_proxy"]: {
            "dev_uid": DEV_PROXY,
            "dev_name": DEVICES["proxy"]["hostname"],
            "if_uid": IF_PROXY_ETH1,
            "if_name": "eth1",
        },
    }
    service = _lb_vs(
        uid=VIP["uid"],
        name=VIP["name"],
        port=VIP["port"],
        proto=VIP["proto"],
        ip_uid=f"ip:estate:{ADDR['vip']}",
    )
    graph.vip[(ADDR["vip"], DEV_PROXY)] = service
    graph.pool_members[VIP["uid"]] = [
        _lb_member(
            uid=VIP["member_uid"],
            name=f"{ADDR['server']}:{VIP['member_port']}",
            pool_uid=VIP["pool_uid"],
            pool_name="web",
            port=VIP["member_port"],
            ip=ADDR["server"],
        )
    ]
    graph.iface_addrs[IF_XR_NVE1] = ADDR["vxlan_local"]
    graph.iface_kinds[IF_XR_NVE1] = "tunnel"
    graph.tunnel_by_source_ip[ADDR["vxlan_local"]] = {
        "uid": TUNNEL["uid"],
        "name": TUNNEL["name"],
        "encap": TUNNEL["encap"],
    }
    graph.tunnel_props = {
        "endpoint": ADDR["vxlan_peer"],
        "endpoint_port": TUNNEL["endpoint_port"],
        "carrier_proto": TUNNEL["carrier_proto"],
        "local_address": ADDR["vxlan_local"],
        "encap": TUNNEL["encap"],
    }
    graph.local_vrf = {"vrf_uid": VRF_XR, "vrf_name": "default"}


class Estate:
    """One fake read seam: MTU evidence, topology expansion, gateways and the scripted graph."""

    def __init__(self):
        self.graph = FakeGraph()
        script_graph(self.graph)
        self.observations = estate_observations()
        self.by_subject = defaultdict(list)
        for obs in self.observations:
            self.by_subject[obs.subject_uid].append(obs)
        stretch = FIXTURE["topology"]["stretch_without_evidence"]
        self.decoys = {
            IF_ACI_BD: [
                row(
                    observation(stretch["decoy_other_snapshot_bytes"], subject_uid=IF_ACI_BD, source="older"),
                    OTHER_SNAP,
                ),
                row(
                    observation(stretch["decoy_retired_bytes"], subject_uid=IF_ACI_BD, source="retired"),
                    SNAP,
                    _retired_at=OTHER_SNAP,
                ),
            ]
        }
        self.topology = topology_rows()
        self.gateways = [GATEWAY]
        self.evidence_reads = []
        self.topology_reads = []

    def session(self):
        return SimpleNamespace(cts=SNAP)

    def read(self, session, query, **params):
        if "HAS_MTU" in query:
            self.evidence_reads.append(params)
            rows = []
            for subject in params["subject_uids"]:
                rows.extend(row(o, SNAP) for o in self.by_subject.get(subject, []))
                rows.extend(self.decoys.get(subject, []))
            return rows
        if query == TOPOLOGY_QUERY:
            self.topology_reads.append(params)
            return [r for subject in params["subject_uids"] for r in self.topology.get(subject, [])]
        if query == GATEWAYS:
            return list(self.gateways)
        return self.graph.read(query, **params)

    def read_one(self, session, query, **params):
        return self.graph.read_one(query, **params)

    def trace(self, dst=None, *, mtu, reply=False, src=None, port=443, proto="tcp"):
        return path.trace(
            self.session(),
            src or ADDR["client"],
            dst or ADDR["server"],
            port=port,
            proto=proto,
            gateways=self.gateways,
            reply=reply,
            mtu=mtu,
        )


@pytest.fixture
def estate(monkeypatch):
    estate = Estate()
    monkeypatch.setattr(path, "_read", estate.read)
    monkeypatch.setattr(path, "_read_one", estate.read_one)
    return estate


def stages_by_subject(result):
    grouped = defaultdict(list)
    for stage in result["stages"]:
        grouped[stage["egress_subject_uid"] or stage["ingress_subject_uid"]].append(stage)
    return grouped


def constraint_values(stage):
    return sorted(c["value_bytes"] for c in stage["constraints"] if c["value_bytes"] is not None)


def unfragmented(size):
    return {"mode": "unfragmented", "ip_packet_bytes": size}


# --- shared pure-layer helpers over fixture evidence ----------------------------------


_EVIDENCE = None


def evidence(subject):
    global _EVIDENCE
    if _EVIDENCE is None:
        _EVIDENCE = defaultdict(list)
        for obs in estate_observations():
            _EVIDENCE[obs.subject_uid].append(obs)
    return list(_EVIDENCE[subject])


def resolved_stage(
    stage_id,
    subject,
    *,
    af=4,
    flow="tx",
    enforcement="l3",
    resolve_enforcement=None,
    tag_depth=None,
    **fields,
):
    """A complete-coverage stage whose constraints come from the estate evidence."""
    context = MtuContext(af=af, direction=flow, enforcement=enforcement, tag_depth=tag_depth)
    resolution = resolve_constraints(
        evidence(subject), context.model_copy(update={"enforcement": resolve_enforcement or enforcement})
    )
    values = {
        "stage_id": stage_id,
        "enforcement": enforcement,
        "context": context,
        "constraints": resolution.constraints,
        "selection": "selected",
        "egress_subject_uid": subject if flow == "tx" else None,
        "ingress_subject_uid": subject if flow == "rx" else None,
        "coverage": MtuCoverage(
            complete=not resolution.gaps,
            candidate_set_complete=True,
            constraints_complete=not resolution.gaps,
            exact_path_known=True,
            gaps=resolution.gaps,
        ),
    }
    values.update(fields)
    return MtuStage(**values)


def missing_stage(stage_id, subject, **fields):
    values = {
        "stage_id": stage_id,
        "egress_subject_uid": subject,
        "enforcement": "l3",
        "context": MtuContext(af=4),
        "selection": "unknown",
        "coverage": MtuCoverage(),
    }
    values.update(fields)
    return MtuStage(**values)


def fixture_encapsulation(name):
    spec = FIXTURE["encapsulation"][name]
    return encap(spec["kind"], spec["outer_af"], **spec["parameters"]), spec


def finding_codes(result):
    return sorted({(f["code"], f["severity"]) for f in result["findings"]})


# --- coordinates ---------------------------------------------------------------


def test_xr_media_and_xe_ip_budgets_agree_in_explicit_untagged_context():
    core = resolve_constraints(evidence(PORT_XR_GI0) + evidence(IF_XR_GI0), MtuContext(af=4, tag_depth=0))
    peer = resolve_constraints(evidence(IF_XE_PO1), MtuContext(af=4, tag_depth=0))
    by_metric = {c.metric: c for c in core.constraints if c.value_bytes is not None}
    assert by_metric["l2_max_frame_bytes"].value_bytes == 1514
    assert by_metric["ipv4_mtu_bytes"].value_bytes == 1500
    point = pure_stage()
    point.context.tag_depth = 0
    budgets = {constraint_budget(c, point)[0] for c in by_metric.values()}
    assert budgets == {1500}
    assert [c.value_bytes for c in peer.constraints] == [1500]
    codes = {f.code for f in audit_neighbors(core, peer)}
    assert "MTU_NORMALIZED_DIFFERENCE" not in codes
    assert "MTU_ADJACENCY_DISCREPANCY" not in codes


def test_untagged_media_ceiling_applies_at_the_core_egress_crossing(estate):
    result = estate.trace(mtu=unfragmented(1500))["mtu"]
    port_stage = stages_by_subject(result)[PORT_XR_GI1][0]
    assert constraint_values(port_stage) == [1514]
    # The configured raw media value stays a separate unknown-basis observation.
    media = [c for c in port_stage["constraints"] if c["value_bytes"] == 1514]
    assert media and all(not c["gaps"] for c in media)


def test_untagged_media_ceiling_is_comparable_in_the_link_audit(estate, monkeypatch):
    original = estate.read

    def read(session, query, **params):
        if "CONNECTED_TO" in query:
            return [{"subject_uid": PORT_XR_GI0, "peer_uid": PORT_XE_GI1}]
        return original(session, query, **params)

    monkeypatch.setattr(path, "_read", read)
    page = audit_mtu(estate.session(), scope="link", subject_uid=PORT_XR_GI0)
    core = page.items[0].resolutions[0]
    frames = [c for c in core.constraints if c.metric == "l2_max_frame_bytes"]
    assert [c.value_bytes for c in frames if c.value_bytes is not None] == [1514]
    # The resolution-level gap belongs to the configured raw media observation.
    assert all(not c.gaps for c in frames if c.value_bytes is not None)


def _t02_vectors():
    cases = json.loads((FIXTURE_PATH.parents[1] / "conformance.json").read_text())["cases"]
    return [c for c in cases if "T02" in c["acceptance_ids"] and "raw_frame_bytes" in c["input"]]


def _t02_observation(given):
    return observation(
        given["raw_frame_bytes"],
        metric="l2_max_frame_bytes",
        enforcement="l2",
        profile_id="ethernet_frame_including_fcs"
        if given.get("fcs_in_raw")
        else "ethernet_frame_excluding_fcs",
        tag_depth=given["tag_depth"],
        tag_accounting=given["tag_accounting"],
        tag_allowance_bytes=given.get("extra_tag_allowance_bytes"),
    )


def test_tag_accounting_vectors_and_qinq_never_blind_subtract():
    checked = 0
    for case in _t02_vectors():
        expected = case["expected"]
        if expected.get("original_ip_budget_bytes") is None:
            continue
        obs = _t02_observation(case["input"])
        assert obs.normalized_value == expected["l2_max_frame_bytes"]
        point = pure_stage()
        point.context.tag_depth = case["input"]["tag_depth"]
        constraint = resolve_constraints([obs], point.context).constraints[0]
        assert constraint_budget(constraint, point) == (expected["original_ip_budget_bytes"], [])
        checked += 1
    assert checked == 5
    subif = resolve_constraints(evidence(IF_XR_GI0_20), MtuContext(af=4))
    assert [c.value_bytes for c in subif.constraints] == [1500]
    assert [c.value_bytes for c in subif.configured] == [1450]


def test_unknown_tag_accounting_yields_no_budget():
    [case] = [c for c in _t02_vectors() if c["expected"].get("original_ip_budget_bytes") is None]
    obs = _t02_observation(case["input"])
    assert obs.normalized_value is None
    assert case["expected"]["gap"] in obs.gaps


# --- bridged segments and receivers ---------------------------------------------


def test_jumbo_bridging_with_1500_hosts_passes_and_the_svi_is_not_applied():
    source = resolved_stage("client", EP_CLIENT, enforcement="unknown")
    bridged = resolved_stage("uplink", PORT_XE_GI1, enforcement="l2")
    svi = resolved_stage("svi", IF_XE_VLAN10, applicability="not_applicable")
    receiver = resolved_stage("host", IF_HOST_ETH0, flow="rx", enforcement="unknown")
    assert [c.value_bytes for c in source.constraints] == [1500]
    assert [c.value_bytes for c in bridged.constraints] == [9000]
    # The host's VyOS interface MTU is a ceiling in both directions.
    assert receiver.constraints[0].bound_kind == "ceiling"
    result = evaluate_stages([source, bridged, svi, receiver], size_request(1500))
    assert result.outcome == "pass"
    assert result.guaranteed_bytes == 1500
    assert result.coverage.complete
    assert "svi" not in result.bottleneck_stage_ids


def test_receiver_exact_ceiling_fails_and_lower_bounds_cannot_prove_rejection(estate):
    sender = resolved_stage("sender", IF_XE_GI1)
    assert [c.value_bytes for c in sender.constraints] == [9000]
    exact = observation(
        1514,
        subject_uid=IF_HOST_ETH0,
        source="synthetic-receiver",
        metric="l2_max_frame_bytes",
        profile_id="ethernet_frame_excluding_fcs",
        direction="rx",
        enforcement="l2",
        tag_depth=0,
    )
    receiver = MtuStage(
        stage_id="receiver",
        ingress_subject_uid=IF_HOST_ETH0,
        enforcement="l2",
        context=MtuContext(af=4, direction="rx", enforcement="l2", tag_depth=0),
        constraints=resolve_constraints([exact], MtuContext(af=4, direction="rx", tag_depth=0)).constraints,
        selection="selected",
        coverage=MtuCoverage(complete=True, candidate_set_complete=True, constraints_complete=True),
    )
    failed = evaluate_stages([sender, receiver], size_request(9000))
    assert failed.outcome == "fail"
    deficit = next(f for f in failed.findings if f.code == "MTU_CAPACITY_DEFICIT")
    assert (deficit.observed_bytes, deficit.deficit_bytes) == (1514, 7500)
    assert failed.known_ceiling_bytes == 1500
    # The host's VyOS interface MTU is a ceiling in both directions.
    entry_ceiling = resolved_stage("host", IF_HOST_ETH0, flow="rx", enforcement="unknown")
    entry_fail = evaluate_stages([sender, entry_ceiling], size_request(1501))
    assert entry_fail.outcome == "fail"
    assert any(f.code == "MTU_CAPACITY_DEFICIT" for f in entry_fail.findings)
    traced = stages_by_subject(estate.trace(mtu=unfragmented(1501))["mtu"])
    destination = traced[IF_HOST_ETH0][0]
    assert destination["constraints"][0]["bound_kind"] == "ceiling"
    assert "MTU_RECEIVE_LIMIT_UNKNOWN" not in destination["coverage"]["gaps"]
    # Cisco emits the SVI's interface MTU with direction "both".
    ingress = traced[IF_XE_VLAN10][0]
    assert ingress["constraints"] != []
    assert "MTU_RECEIVE_LIMIT_UNKNOWN" not in ingress["coverage"]["gaps"]


# --- policy resolution and drift --------------------------------------------------


def test_port_override_is_not_minimized_and_unstated_class_keeps_alternatives():
    spec = FIXTURE["synthetic"]["class_alternatives"]
    default = observation(
        spec["system_default_bytes"],
        subject_uid=DEV_XE,
        source_field="system",
        scope="device",
        assertion_kind="configured",
    )
    override = observation(
        spec["port_override_bytes"],
        subject_uid=IF_XE_GI1,
        assertion_kind="configured",
        enforcement_key="protocol",
    )
    application = MtuPolicyApplication(
        observation_uid=default.uid,
        subject_uid=IF_XE_GI1,
        enforcement_key="protocol",
        precedence=-1,
        profile_id="synthetic-system-default",
        evidence_uids=[default.uid],
    )
    result = resolve_constraints(
        [default, override, *evidence(IF_XE_GI1)], MtuContext(af=4), applications=[application]
    )
    assert [c.value_bytes for c in result.constraints] == [9000]
    assert [c.value_bytes for c in result.configured] == [9000]
    assert not result.findings
    classes = [
        observation(size, subject_uid=IF_XE_GI1, traffic_class=name) for name, size in spec["classes"].items()
    ]
    unstated = resolve_constraints(classes, MtuContext(af=4))
    assert sorted(c.value_bytes for c in unstated.constraints) == [1500, 9000]
    assert "MTU_CLASS_UNKNOWN" in unstated.gaps
    stated = resolve_constraints(classes, MtuContext(af=4, traffic_class="storage"))
    assert [c.value_bytes for c in stated.constraints] == [9000]
    assert "MTU_CLASS_UNKNOWN" not in stated.gaps


def test_operational_drift_is_reported_with_all_evidence_retained(estate):
    host = resolve_constraints(evidence(IF_HOST_ETH0), MtuContext(af=4))
    assert [c.value_bytes for c in host.constraints] == [1500]
    assert [c.value_bytes for c in host.configured] == [9000]
    drift = next(f for f in host.findings if f.code == "MTU_POLICY_DRIFT")
    assert (drift.observed_bytes, drift.required_bytes, drift.severity) == (1500, 9000, "risk")
    subif = resolve_constraints(evidence(IF_XR_GI0_20), MtuContext(af=4))
    xr_drift = next(f for f in subif.findings if f.code == "MTU_POLICY_DRIFT")
    assert (xr_drift.observed_bytes, xr_drift.required_bytes) == (1500, 1450)
    from hst.path.gates import _Trail
    from hst.path.mtu_topology import crossing, mtu_request, trace_scope

    @trace_scope()
    def walk(session):
        crossing(_Trail(), IF_HOST_ETH0, enforcement="l3")
        return {"hops": []}

    with mtu_request(MtuRequest(mode="unfragmented", ip_packet_bytes=1501), 4):
        result = walk(estate.session())["mtu"]
    assert result["known_ceiling_bytes"] == 1500
    assert result["outcome"] == "fail"
    assert ("MTU_POLICY_DRIFT", "risk") in finding_codes(result)
    assert {json.loads(o["raw_value_json"]) for o in result["observations"] if o["af"] == 4} == {"9000", 1500}


# --- aggregates and alternatives -----------------------------------------------


def test_lag_members_yield_eligible_guarantee_and_inactive_member_is_readiness_only(estate):
    batch = cisco_batch("iosxe")
    eligibility = {
        rel.start_uid: rel.props.get("eligible")
        for rel in batch.rels
        if rel.rel_type == "MEMBER_OF" and rel.end_uid == LAG_XE_PO1
    }
    assert eligibility == {PORT_XE_GI1: True, PORT_XE_GI2: True, PORT_XE_GI3: False}
    members = [
        resolved_stage(
            port, port, enforcement="l2", candidate_set_id=LAG_XE_PO1, candidate_id=port, selection="eligible"
        )
        for port, eligible in sorted(eligibility.items())
        if eligible
    ]
    result = evaluate_stages(members, size_request(9000))
    assert result.outcome == "conditional"
    assert result.guaranteed_bytes == 1500
    assert result.known_ceiling_bytes == 9000
    assert sorted(c.known_ceiling_bytes for c in result.candidates) == [1500, 9000]
    assert evaluate_stages(members, size_request(1500)).outcome == "pass"
    readiness = audit_members(
        [
            (port, eligible, resolve_constraints(evidence(port), MtuContext(af=4, enforcement="l2")))
            for port, eligible in sorted(eligibility.items())
        ]
    )
    scopes = {(tuple(f.subject_uids), f.scope) for f in readiness if f.code == "MTU_LAG_INCONSISTENCY"}
    assert ((PORT_XE_GI1, PORT_XE_GI2), "active_members") in scopes
    assert all(scope == "member_readiness" for subjects, scope in scopes if PORT_XE_GI3 in subjects)
    traced = estate.trace(mtu=unfragmented(1500))["mtu"]
    chosen = {
        frozenset(s["candidate_id"] for s in c["stages"] if s["candidate_id"]) for c in traced["candidates"]
    }
    assert chosen == {frozenset({PORT_XE_GI1}), frozenset({PORT_XE_GI2})}
    grouped = stages_by_subject(traced)
    assert set(grouped) & {PORT_XE_GI1, PORT_XE_GI2, PORT_XE_GI3} == {PORT_XE_GI1, PORT_XE_GI2}
    assert constraint_values(grouped[PORT_XE_GI1][0]) == [9000]
    assert constraint_values(grouped[PORT_XE_GI2][0]) == [1500]
    assert len(traced["candidates"]) == 2
    assert all(c["known_ceiling_bytes"] == 1500 for c in traced["candidates"])
    assert 1400 not in {v for stage in traced["stages"] for v in constraint_values(stage)}


def test_eligible_alternatives_are_not_lldp_possibilities(estate):
    eligible = [
        resolved_stage(
            "a",
            PORT_XE_GI1,
            enforcement="l2",
            candidate_set_id="ecmp",
            candidate_id="a",
            selection="eligible",
        ),
        resolved_stage(
            "b",
            PORT_XE_GI2,
            enforcement="l2",
            candidate_set_id="ecmp",
            candidate_id="b",
            selection="eligible",
        ),
    ]
    known = evaluate_stages(eligible, size_request(1500))
    assert (known.outcome, known.guaranteed_bytes, known.known_ceiling_bytes) == ("pass", 1500, 9000)
    lldp = resolved_stage("cable", PORT_XE_GI3, enforcement="l2", selection="possible")
    assert constraint_values(lldp.model_dump()) == [1400]
    possible = evaluate_stages([*eligible, lldp], size_request(1500))
    assert possible.outcome == "unknown"
    assert possible.guaranteed_bytes is None
    assert "MTU_PATH_COVERAGE_INCOMPLETE" in possible.coverage.gaps
    assert all(f.severity != "failure" for f in possible.findings)
    estate.graph.routes[VRF_XR].append(
        _pinned(ADDR["server_prefix"], IF_XR_GI2, "GigabitEthernet0/0/0/2", next_hop=ADDR["vxlan_peer"])
    )
    traced = estate.trace(mtu=unfragmented(1500))["mtu"]
    assert traced["outcome"] == "unknown"
    # The connection ceiling is the largest lane ceiling: an upper bound only.
    assert traced["known_ceiling_bytes"] == max(c["known_ceiling_bytes"] for c in traced["lanes"])
    assert traced["guaranteed_bytes"] is None
    assert not traced["connections"]
    assert {c["lane"] for c in traced["lanes"]} == {"0", "1"}
    for lane in traced["lanes"]:
        assert {s["lane"] for s in lane["stages"]} == {lane["lane"]}
        # The access switch's Port-channel1 LAG members are proven eligible.
        assert all(
            s["coverage"]["candidate_set_complete"] == (s.get("candidate_set_id") is not None)
            for s in lane["stages"]
        )
        assert lane["outcome"] == "unknown"
    # Lane 0 carries the LLDP-only cable.
    selections_by_lane = {
        lane["lane"]: {s["selection"] for s in lane["stages"] if s["depth"] > 0} for lane in traced["lanes"]
    }
    assert selections_by_lane == {"0": {"eligible", "possible", "unknown"}, "1": {"eligible"}}


# --- fits_known_limits: a pass needs complete coverage ---------------------------------------


def test_client_packet_that_fits_every_known_limit_is_fits_known_limits_not_unknown():
    source = missing_stage("client-source", EP_CLIENT, enforcement="source", selection="eligible")
    device = resolved_stage("core-egress", IF_XR_GI1)
    beyond_twin = missing_stage(
        "beyond-twin", None, enforcement="unknown", selection="possible", applicability="unknown"
    )
    result = evaluate_stages([source, device, beyond_twin], size_request(1300, mode="packet", ipv4_df=True))
    assert result.outcome == "fits_known_limits"
    assert result.coverage.uncovered == ["path-beyond-twin", "source-endpoint"]
    assert result.coverage.complete is False
    assert result.guaranteed_bytes is None


def test_two_lanes_one_deficit_at_1400_bytes_is_conditional_not_unknown():
    source = missing_stage("client-source", EP_CLIENT, enforcement="source", selection="eligible", lane="0")
    device = resolved_stage("core-egress", IF_XR_GI1, lane="0")
    beyond_twin = missing_stage(
        "beyond-twin", None, enforcement="unknown", selection="possible", applicability="unknown", lane="0"
    )
    deficit_lane = pure_stage(1300, lane="1", stage_id="lane1-device")
    result = evaluate_stages(
        [source, device, beyond_twin, deficit_lane], size_request(1400, mode="packet", ipv4_df=True)
    )
    by_lane = {lane.lane: lane for lane in result.lanes}
    assert by_lane["0"].outcome == "fits_known_limits"
    assert by_lane["1"].outcome == "fail"
    assert result.outcome == "conditional"


def test_estate_pipeline_client_packet_is_fits_known_limits_not_unknown(estate):
    """read_mtu's evidence-wide gap stays off the resolved device stage."""
    from hst.path.gates import _Trail
    from hst.path.mtu_topology import boundary, crossing, mtu_request, trace_scope

    unresolved_client = "ep:estate:mobile-guest"

    @trace_scope()
    def walk(session):
        trail = _Trail()
        crossing(trail, unresolved_client, enforcement="source")
        trail.depth += 1
        crossing(trail, IF_HOST_ETH0, enforcement="l3")
        trail.depth += 1
        boundary(trail)
        return {}

    with mtu_request(MtuRequest(mode="packet", ip_packet_bytes=1300, ipv4_df=True), 4):
        result = walk(estate.session())["mtu"]
    device = stages_by_subject(result)[IF_HOST_ETH0][0]
    assert device["selection"] == "eligible"
    assert device["coverage"]["constraints_complete"] is True
    assert "MTU_NOT_CAPTURED" not in device["coverage"]["gaps"]
    assert "MTU_PATH_COVERAGE_INCOMPLETE" not in device["coverage"]["gaps"]
    source = stages_by_subject(result)[unresolved_client][0]
    assert "MTU_NOT_CAPTURED" in source["coverage"]["gaps"]
    assert result["outcome"] == "fits_known_limits"
    assert result["coverage"]["uncovered"] == ["path-beyond-twin", "source-endpoint"]
    assert result["coverage"]["complete"] is False
    assert result["guaranteed_bytes"] is None


# --- mtu-l2-path-coverage: a single-host trace judges its own L2 chain -----------------------


def test_estate_wired_client_switch_hop_resolves_with_stated_cabling_and_carriage(estate):
    """The access-switch hop of a wired client carries the flow's VLAN untagged."""
    from importlib import import_module

    from hst.path.gates import Stage, _Trail
    from hst.path.mtu_topology import boundary, crossing, mtu_request, trace_scope

    trace_module = import_module("hst.path.trace")

    switch_port = "dev:estate-access-sw/port/uplink"
    unresolved_client = "ep:estate:wired-new"
    estate.by_subject[switch_port].append(
        observation_from_raw(
            subject_uid=switch_port,
            source="estate-fixture",
            source_target="estate-access-sw",
            source_field="device.frame_ceiling",
            raw_value=1518,
            profile_id="ethernet_frame_including_fcs",
            metric="l2_max_frame_bytes",
            direction="both",
            bound_kind="ceiling",
            enforcement="l2",
            enforcement_key="netdevice",
            assertion_kind="configured",
            tag_accounting="extra_allowance",
            tag_allowance_bytes=4,
            collector_version="fixture",
            raw_evidence_ref="estate-fixture.device.frame_ceiling",
        )
    )
    estate.graph.iface_segments[IF_XE_VLAN10] = ["bd:vlan:fab0:10"]

    @trace_scope()
    def walk(session):
        trail = _Trail()
        crossing(trail, unresolved_client, enforcement="source")
        trail.depth += 1
        trace_module._draw_l2_chain(
            trail,
            session,
            [
                {
                    "uid": switch_port,
                    "is_port": True,
                    "label": "Uplink",
                    "dev": "estate-access-sw",
                    "lag": None,
                    "native_bds": ["bd:vlan:fab0:10"],
                    "tagged_bds": [],
                    "conn_source": "nautobot-cable",
                }
            ],
            IF_XE_VLAN10,
            stage=Stage.L2_FABRIC,
        )
        trail.depth += 1
        boundary(trail)
        return {}

    with mtu_request(MtuRequest(mode="packet", ip_packet_bytes=1300, ipv4_df=True), 4):
        result = walk(estate.session())["mtu"]
    switch_stages = stages_by_subject(result)[switch_port]
    assert len(switch_stages) == 2
    assert all(s["selection"] == "eligible" for s in switch_stages)
    assert all(s["context"]["tag_depth"] == 0 for s in switch_stages)
    assert all(s["coverage"]["constraints_complete"] for s in switch_stages)
    assert all("MTU_PATH_COVERAGE_INCOMPLETE" not in s["coverage"]["gaps"] for s in switch_stages)
    assert result["outcome"] == "fits_known_limits"
    assert result["coverage"]["uncovered"] == ["path-beyond-twin", "source-endpoint"]
    assert result["coverage"]["complete"] is False


def test_estate_access_point_port_without_evidence_lists_in_unresolved_subjects(estate):
    """The controller holds no MTU for an access point."""
    from hst.path.gates import _Trail
    from hst.path.mtu_topology import crossing, mtu_request, trace_scope

    ap_port = "dev:estate-ap/port/port0"

    @trace_scope()
    def walk(session):
        trail = _Trail()
        crossing(trail, ap_port, enforcement="l2", possible=True)
        crossing(trail, ap_port, enforcement="l2", direction="rx", possible=True)
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        result = walk(estate.session())["mtu"]
    assert ap_port in result["unresolved_subjects"]
    for s in stages_by_subject(result)[ap_port]:
        assert ap_port in s["coverage"]["unresolved_subjects"]
        assert s["constraints"] == []


def test_estate_wireless_client_behind_access_point_with_no_port_evidence_reads_unknown(estate):
    """mtu_topology._uncovered_code returns None for the access point's uplink port."""
    from hst.path.gates import _Trail
    from hst.path.mtu_topology import boundary, crossing, mtu_request, trace_scope

    ap_port = "dev:estate-ap/port/port0"
    unresolved_client = "ep:estate:wireless-guest"

    @trace_scope()
    def walk(session):
        trail = _Trail()
        crossing(trail, unresolved_client, enforcement="source")
        trail.depth += 1
        crossing(trail, ap_port, enforcement="l2")
        trail.depth += 1
        boundary(trail)
        return {}

    with mtu_request(MtuRequest(mode="packet", ip_packet_bytes=1300, ipv4_df=True), 4):
        result = walk(estate.session())["mtu"]
    assert result["outcome"] == "unknown"
    assert result["outcome"] != "fits_known_limits"
    assert ap_port in result["coverage"]["unresolved_subjects"]
    ap_stage = stages_by_subject(result)[ap_port][0]
    assert ap_port in ap_stage["coverage"]["unresolved_subjects"]


# --- partial evidence -------------------------------------------------------


def test_known_limit_with_missing_hop_gives_upper_bound_only(estate):
    known = resolved_stage("core-egress", IF_XR_GI1)
    missing = missing_stage("bd", IF_ACI_BD)
    result = evaluate_stages([known, missing], size_request(1500))
    assert result.outcome == "unknown"
    assert result.known_ceiling_bytes == 1500
    assert result.guaranteed_bytes is None
    assert {"MTU_NOT_CAPTURED", "MTU_PATH_COVERAGE_INCOMPLETE"} <= set(result.coverage.gaps)
    traced = estate.trace(mtu=unfragmented(1500))["mtu"]
    assert traced["outcome"] == "unknown"
    assert traced["guaranteed_bytes"] is None
    assert traced["coverage"]["complete"] is False
    assert [c["known_ceiling_bytes"] for c in traced["candidates"]] == [1500, 1500]
    stretch = stages_by_subject(traced)[IF_ACI_BD][0]
    assert stretch["constraints"] == []
    assert "MTU_NOT_CAPTURED" in stretch["coverage"]["gaps"]


def test_common_stage_evidence_survives_incomplete_candidate_sets():
    common = pure_stage(1500, stage_id="common", selection="eligible")
    members = [
        pure_stage(
            9000,
            stage_id=name,
            candidate_set_id="lag",
            candidate_id=name,
            selection="eligible",
            coverage=MtuCoverage(constraints_complete=True),
        )
        for name in ("a", "b")
    ]
    bounded = evaluate_stages([common, *members], size_request(1500))
    assert bounded.known_ceiling_bytes == 1500
    failed = evaluate_stages([common, *members], size_request(1501))
    assert failed.outcome == "fail"


def test_local_deficit_is_proven_without_fabricating_the_first_drop(estate):
    missing = missing_stage("unknown-transit", IF_ACI_BD)
    known = resolved_stage("core-egress", IF_XR_GI1)
    result = evaluate_stages([missing, known], size_request(1501))
    assert result.outcome == "fail"
    assert result.guaranteed_bytes is None
    assert result.known_ceiling_bytes == 1500
    deficit = next(f for f in result.findings if f.code == "MTU_CAPACITY_DEFICIT")
    assert (deficit.deficit_bytes, deficit.subject_uids) == (1, [IF_XR_GI1])
    assert result.bottleneck_stage_ids == ["core-egress"]
    traced = estate.trace(mtu=unfragmented(1501))["mtu"]
    deficits = [f for f in traced["findings"] if f["code"] == "MTU_CAPACITY_DEFICIT"]
    assert {f["severity"] for f in deficits} == {"failure"}
    assert {IF_XE_PO1, IF_XR_GI1, IF_PROXY_ETH1} <= {u for f in deficits for u in f["subject_uids"]}
    assert all(c["outcome"] == "fail" for c in traced["candidates"])
    assert traced["guaranteed_bytes"] is None
    assert IF_ACI_BD not in {u for f in deficits for u in f["subject_uids"]}


def test_traced_common_stage_deficit_is_reported_as_fail(estate):
    assert estate.trace(mtu=unfragmented(1501))["mtu"]["outcome"] == "fail"


def test_missing_current_evidence_ignores_other_snapshot_and_retired_rows(estate):
    current = read_mtu(estate.session(), [IF_ACI_BD])
    assert current.by_subject[IF_ACI_BD] == []
    assert current.unresolved_subjects == [IF_ACI_BD]
    assert current.gaps == ["MTU_NOT_CAPTURED"]
    older = read_mtu(SimpleNamespace(cts=OTHER_SNAP), [IF_ACI_BD])
    assert [o.normalized_value for o in older.by_subject[IF_ACI_BD]] == [9000]
    traced = estate.trace(mtu=unfragmented(1500))["mtu"]
    stretch = stages_by_subject(traced)[IF_ACI_BD][0]
    assert stretch["constraints"] == []
    decoy_uids = {r["observation_uid"] for r in estate.decoys[IF_ACI_BD]}
    assert not decoy_uids & {o["uid"] for o in traced["observations"]}
    assert not {1500, 9000} & {c["value_bytes"] for c in stretch["constraints"]}
    assert traced["outcome"] == "unknown"


def _approved_neo4j():
    """A transaction on the approved disposable Neo4j, never the live twin. The
    caller rolls it back, so nothing it writes stays."""
    import os

    from neo4j import GraphDatabase

    from hst.core.config import Settings

    uri = os.environ["NEO4J_TEST_URI"]
    if uri == Settings(_env_file=None).neo4j_uri:
        pytest.fail("refusing live twin URI")
    driver = GraphDatabase.driver(
        uri, auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"])
    )
    return driver, driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j"))


_NEO4J_APPROVED = pytest.mark.skipif(
    __import__("os").environ.get("HST_MTU_TEST_NEO4J_APPROVED") != "1",
    reason="requires approved disposable Neo4j and HST_MTU_TEST_NEO4J_APPROVED=1",
)


@pytest.mark.db
@_NEO4J_APPROVED
def test_graph_snapshot_pin_requires_neo4j():
    """read_mtu on a real graph reads only the pinned run's subject, edge and
    observation; another run's copies of the same uids stay out."""
    from hst.path.session import CycleSession

    driver, session = _approved_neo4j()
    with driver, session, session.begin_transaction() as tx:
        subject = "mtu:t11:synthetic-db-only"
        for cts, mtu in ((42, 1500), (41, 9000)):
            obs = observation(mtu, subject_uid=subject)
            tx.run(
                "CREATE (s:Obj:Interface {uid:$subject, collection_ts:$cts}) "
                "CREATE (o:Obj:MtuObservation) SET o=$props "
                "CREATE (s)-[:HAS_MTU {collection_ts:$cts}]->(o)",
                subject=subject,
                cts=cts,
                props=dict(obs.graph_props(), uid=obs.uid, collection_ts=cts),
            ).consume()
        adapter = SimpleNamespace(execute_read=lambda work: work(tx))
        current = read_mtu(CycleSession(adapter, 42), [subject])
        older = read_mtu(CycleSession(adapter, 41), [subject])
        assert [o.normalized_value for o in current.by_subject[subject]] == [1500]
        assert [o.normalized_value for o in older.by_subject[subject]] == [9000]
        assert read_mtu(CycleSession(adapter, 40), [subject]).unresolved_subjects == [subject]
        tx.rollback()


# --- encapsulation -------------------------------------------------------


def test_vxlan_outer_ipv4_1500_permits_inner_1450(estate):
    tunnel, spec = fixture_encapsulation("vxlan_outer_ipv4")
    assert inner_budget(spec["outer_ip_budget"], [tunnel], original_af=4) == (spec["original_ip_budget"], [])
    carrier = resolved_stage("underlay", IF_XR_GI2, encapsulation=[tunnel])
    assert [c.value_bytes for c in carrier.constraints] == [1500]
    assert evaluate_stage(carrier, size_request(1450)).outcome == "pass"
    over = evaluate_stage(carrier, size_request(1451))
    assert over.outcome == "fail"
    assert over.findings[0].deficit_bytes == 1
    traced = estate.trace(ADDR["remote_host"], mtu=unfragmented(1450))["mtu"]
    grouped = stages_by_subject(traced)
    underlay = grouped[IF_XR_GI2][0]
    # The underlay's Tunnel row carries VXLAN evidence.
    assert [e["kind"] for e in underlay["encapsulation"]] == ["vxlan"]
    assert "MTU_ENCAP_UNKNOWN" not in underlay["coverage"]["gaps"]
    assert constraint_values(underlay) == [1500]
    assert "MTU_NOT_CAPTURED" in grouped[IF_XR_NVE1][0]["coverage"]["gaps"]
    assert grouped[IF_XR_NVE1][0]["enforcement"] == "tunnel"
    # NVE1 has no direct MTU evidence in this fixture.
    assert traced["outcome"] == "unknown"


def test_outer_ipv6_retained_tags_and_decapsulation_count_overhead_once():
    tagged, spec = fixture_encapsulation("vxlan_outer_ipv6_tagged")
    assert inner_budget(spec["outer_ip_budget"], [tagged], original_af=4) == (spec["original_ip_budget"], [])
    inner, outer = vxlan(4), vxlan(6)
    nested = [inner, outer]
    assert inner_budget(1500, nested, original_af=4) == (1380, [])
    removed = [*nested, outer.model_copy(update={"operation": "decapsulate"})]
    assert inner_budget(1500, removed, original_af=4) == (1450, [])
    assert inner_budget(1500, [outer.model_copy(update={"operation": "decapsulate"})], original_af=4) == (
        None,
        ["MTU_ENCAP_UNKNOWN"],
    )


def test_ipsec_known_options_versus_unknown_algorithm():
    tunnel, spec = fixture_encapsulation("esp_gcm_tunnel")
    assert inner_budget(spec["outer_ip_budget"], [tunnel], original_af=4) == (spec["original_ip_budget"], [])
    assert inner_budget(1500, [esp(nat_t=True)], original_af=4) == (1438, [])
    assert inner_budget(1500, [esp(cipher="chacha20_poly1305")], original_af=4) == (
        None,
        ["MTU_ENCAP_UNKNOWN"],
    )
    carrier = resolved_stage("ipsec", IF_XR_GI2, encapsulation=[esp(cipher="chacha20_poly1305")])
    result = evaluate_stage(carrier, size_request(1400))
    assert result.outcome == "unknown"
    assert "MTU_ENCAP_UNKNOWN" in result.coverage.gaps
    assert result.known_ceiling_bytes is None


# --- ACI ---------------------------------------------------------------------------


def test_aci_stages_are_distinct_and_the_l3out_is_the_traversed_bottleneck(estate):
    l3out = resolved_stage("l3out", IF_ACI_L3OUT)
    [expanded] = [s for s in expand_stages(estate.session(), [l3out]) if s.stage_id == "l3out"]
    assert expanded.fragmentation_supported is False
    assert [c.value_bytes for c in expanded.constraints] == [1500]
    fabric = resolved_stage("fabric", uid.fabric(FABRIC), enforcement="fabric", resolve_enforcement="unknown")
    assert fabric.constraints == []
    assert "MTU_POLICY_UNRESOLVED" in fabric.coverage.gaps
    access = resolved_stage("access", PORT_ACI_ETH1_2, enforcement="l2")
    assert [c.value_bytes for c in access.constraints] == [None]
    assert "MTU_SEMANTICS_UNKNOWN" in access.coverage.gaps
    result = evaluate_stages([access, fabric, expanded], size_request(1500))
    assert result.outcome == "unknown"
    assert result.known_ceiling_bytes == 1500
    assert result.bottleneck_stage_ids == ["l3out"]
    for df in (True, False, None):
        dropped = evaluate_stage(expanded, size_request(1501, mode="packet", ipv4_df=df))
        assert dropped.outcome == "fail"
        assert "MTU_FRAGMENTATION_UNMODELED" not in dropped.coverage.gaps
    values = {o.normalized_value for o in batch_observations(apic_batch())}
    assert not values & {9150, 9216, 9366}
    traced = stages_by_subject(estate.trace(mtu=unfragmented(1500))["mtu"])
    assert traced[IF_ACI_L3OUT][0]["fragmentation_supported"] is False
    assert traced[PORT_ACI_ETH1_1][0]["selection"] == "possible"


def test_known_fabric_policy_is_labeled_and_physical_coverage_stays_incomplete():
    policy = [o for o in evidence(uid.fabric(FABRIC)) if o.af == 4]
    assert [(o.normalized_value, o.assertion_kind, o.scope) for o in policy] == [
        (9000, "configured", "fabric-l3out-default")
    ]
    unresolved = resolve_constraints(policy, MtuContext(af=4))
    assert unresolved.constraints == []
    assert "MTU_POLICY_UNRESOLVED" in unresolved.gaps
    application = MtuPolicyApplication(
        observation_uid=policy[0].uid,
        subject_uid="dev:estate-aci-spine-201/if/eth1-1",
        enforcement_key="fabric",
        precedence=0,
        profile_id="aci-fabric-default",
        evidence_uids=[policy[0].uid],
    )
    applied = resolve_constraints(policy, MtuContext(af=4), applications=[application])
    assert [c.value_bytes for c in applied.constraints] == [9000]
    assert applied.constraints[0].evidence_quality == ["configured", "inherited"]
    spine = MtuStage(
        stage_id="spine",
        egress_subject_uid=application.subject_uid,
        enforcement="fabric",
        context=MtuContext(af=4),
        constraints=applied.constraints,
        selection="unknown",
        coverage=MtuCoverage(constraints_complete=True, exact_path_known=False),
    )
    result = evaluate_stage(spine, size_request(1500))
    assert result.outcome == "unknown"
    assert result.known_ceiling_bytes == 9000
    assert result.guaranteed_bytes is None
    assert "MTU_PATH_COVERAGE_INCOMPLETE" in result.coverage.gaps


# --- packets and feedback ---------------------------------------------


@pytest.mark.parametrize(
    ("df", "outcome", "gap"),
    [
        (True, "fail", None),
        (False, "fragmentation_required", "MTU_FRAGMENTATION_UNMODELED"),
        (None, "conditional", None),
    ],
)
def test_ipv4_oversize_outcomes_by_df(estate, df, outcome, gap):
    point = resolved_stage("core-egress", IF_XR_GI1)
    result = evaluate_stage(point, size_request(1501, mode="packet", ipv4_df=df))
    assert result.outcome == outcome
    assert (gap in result.coverage.gaps) is (gap is not None)
    if df is not False:
        assert result.feedback[0].outcome == "unknown"
        assert result.feedback[0].gaps == ["MTU_PMTUD_FEEDBACK_UNKNOWN"]
    else:
        assert result.feedback == []
    traced = estate.trace(mtu={"mode": "packet", "ip_packet_bytes": 1501, "ipv4_df": df})["mtu"]
    assert ("MTU_FRAGMENTATION_UNMODELED" in traced["coverage"]["gaps"]) is (df is False)
    assert ("MTU_CAPACITY_DEFICIT", "failure") in finding_codes(traced)


def test_t17b_exit_fragmentation_does_not_double_fail_the_matching_next_entry(estate):
    """The xe-access-1 to xr-core-1 link has one MTU (1500) on both ends."""
    traced = estate.trace(mtu={"mode": "packet", "ip_packet_bytes": 1501, "ipv4_df": False})["mtu"]
    by_subject = stages_by_subject(traced)
    xr_core_entry = next(s for s in by_subject[IF_XR_GI0] if s["context"]["direction"] == "rx")
    assert not any(
        f["stage_ids"] == [xr_core_entry["stage_id"]] and f["code"] == "MTU_CAPACITY_DEFICIT"
        for f in traced["findings"]
    )


def test_ipv6_router_oversize_and_jumbogram_rejection(estate):
    point = resolved_stage("core-ingress-v6", IF_XR_GI0, af=6)
    assert [(c.metric, c.value_bytes) for c in point.constraints] == [("ipv6_mtu_bytes", 1500)]
    dropped = evaluate_stage(point, size_request(1501, mode="packet"))
    assert dropped.outcome == "fail"
    assert dropped.feedback[0].outcome == "unknown"
    packet = build_feedback_packet(
        point, size_request(1501, mode="packet"), dropped, router_ip="2001:db8::1", quoted_flow=quoted(6)
    )
    assert (packet.icmp_type, packet.icmp_code, packet.advertised_mtu_bytes) == (2, 0, 1500)
    with pytest.raises(ValueError, match="jumbograms unsupported"):
        estate.trace(
            mtu={"mode": "packet", "ip_packet_bytes": 65576}, src=ADDR["ipv6_client"], dst=ADDR["ipv6_server"]
        )
    with pytest.raises(ValueError, match="IPv4 DF"):
        MtuRequest(mode="packet", ip_packet_bytes=1500, ipv4_df=True).validate_af(6)


def test_l2_drop_has_no_router_error_and_feedback_path_is_independent():
    switch = resolved_stage("member", PORT_XE_GI2, enforcement="l2")
    req = size_request(1600, mode="packet", ipv4_df=True)
    dropped = evaluate_stage(switch, req)
    assert dropped.outcome == "fail"
    assert dropped.feedback == []
    assert build_feedback_packet(switch, req, dropped, router_ip="198.51.100.2", quoted_flow=quoted()) is None
    router = resolved_stage("core-egress", IF_XR_GI1)
    result = evaluate_stage(router, req)
    packet = build_feedback_packet(router, req, result, router_ip="198.51.100.5", quoted_flow=quoted())
    assert packet.advertised_mtu_bytes == 1500
    permitted = evaluate_feedback(packet, [hop()], path_complete=True, generation="modeled")
    assert permitted.outcome == "permitted"
    blocked = evaluate_feedback(
        packet, [hop(policy_outcome="blocked")], path_complete=True, generation="modeled"
    )
    assert blocked.outcome == "blocked"
    from hst.path.mtu_feedback import feedback_findings

    assert [f.code for f in feedback_findings(blocked, stage_id="core-egress")] == [
        "MTU_PMTUD_BLACKHOLE_RISK"
    ]
    assert evaluate_feedback(packet, [hop()], path_complete=True).outcome == "unknown"


@pytest.mark.parametrize(
    "changes",
    [{"icmp_type_code_complete": False}, {"quoted_flow_complete": False}, {"stateful": True}],
)
def test_bare_icmp_permission_is_not_pmtud_feedback_proof(changes):
    router = resolved_stage("core-egress", IF_XR_GI1)
    req = size_request(1600, mode="packet", ipv4_df=True)
    packet = build_feedback_packet(
        router, req, evaluate_stage(router, req), router_ip="198.51.100.5", quoted_flow=quoted()
    )
    result = evaluate_feedback(packet, [hop(**changes)], path_complete=True, generation="modeled")
    assert result.outcome == "unknown"
    assert result.gaps == ["MTU_PMTUD_FEEDBACK_UNKNOWN"]


def test_client_9000_byte_packet_fails_at_the_first_entry_ceiling(estate):
    """The client sends a 9000-byte packet into the access switch's 1500-byte
    VLAN10 SVI. The entry-side ceiling fails the packet at that first rx
    crossing in every DF state, with no fragmentation attempted there."""
    for df in (True, False):
        result = estate.trace(mtu={"mode": "packet", "ip_packet_bytes": 9000, "ipv4_df": df})["mtu"]
        assert result["outcome"] == "fail"
        entry = next(
            s
            for s in result["stages"]
            if s["ingress_subject_uid"] == IF_XE_VLAN10 and s["context"]["direction"] == "rx"
        )
        assert entry["depth"] == 0
        assert [c["value_bytes"] for c in entry["constraints"]] == [1500]
        assert entry["stage_id"] in result["bottleneck_stage_ids"]
        deficit = next(f for f in result["findings"] if f["stage_ids"] == [entry["stage_id"]])
        assert deficit["code"] == "MTU_CAPACITY_DEFICIT"
        assert deficit["detail"] == (
            "Requested complete IP packet exceeds the entry interface MTU; "
            "the interface drops it in every DF state."
        )
        # The entry stage alone neither fragments nor feeds back.
        entry_result = evaluate_stage(
            MtuStage.model_validate(entry), MtuRequest(mode="packet", ip_packet_bytes=9000, ipv4_df=df)
        )
        assert entry_result.outcome == "fail"
        assert "MTU_FRAGMENTATION_UNMODELED" not in entry_result.coverage.gaps
        assert entry_result.feedback == []


# --- directions, connections and regions --------------------------------------


def test_forward_and_reverse_have_independent_budgets(estate):
    forward = resolved_stage("core-egress", IF_XR_GI1, direction="forward")
    reverse = resolved_stage("l3out-egress", IF_ACI_L3OUT, direction="reverse", fragmentation_supported=False)
    req = MtuRequest(mode="packet", ip_packet_bytes=1500, reply_ip_packet_bytes=1600, ipv4_df=True)
    result = evaluate_stages([forward, reverse], req)
    legs = {leg.direction: leg for leg in result.connections}
    assert (legs["forward"].requested_bytes, legs["forward"].outcome) == (1500, "pass")
    assert (legs["reverse"].requested_bytes, legs["reverse"].outcome) == (1600, "fail")
    assert legs["reverse"].bottleneck_stage_ids == ["l3out-egress"]
    assert legs["forward"].bottleneck_stage_ids == ["core-egress"]
    assert result.known_ceiling_bytes is None
    traced = estate.trace(
        mtu={"mode": "packet", "ip_packet_bytes": 1500, "reply_ip_packet_bytes": 1400}, reply=True
    )
    assert traced["forward"]["mtu"]["direction"] == "forward"
    assert traced["forward"]["mtu"]["requested_bytes"] == 1500
    assert traced["reply"]["legs"][0]["verdict"] == "egress via Vlan10"


def test_traced_reply_carries_its_own_reverse_result(estate):
    traced = estate.trace(
        mtu={"mode": "packet", "ip_packet_bytes": 1500, "reply_ip_packet_bytes": 1400}, reply=True
    )
    reverse = traced["reply"]["mtu"]
    assert reverse["direction"] == "reverse"
    assert reverse["requested_bytes"] == 1400


def test_proxy_reorigination_ordinary_nat_and_unsupported_nat64(estate):
    traced = estate.trace(ADDR["vip"], mtu=unfragmented(1500))["mtu"]
    legs = {leg["connection_id"]: leg for leg in traced["connections"]}
    assert "original" in legs and len(legs) == 2
    backend = next(leg for cid, leg in legs.items() if cid != "original")
    assert backend["connection_id"].startswith("original/backend/")
    assert all(s["connection_reset"] for s in backend["stages"])
    assert backend["requested_bytes"] is None
    assert backend["outcome"] == "unknown"
    assert "MTU_LENGTH_UNSUPPORTED" in backend["coverage"]["gaps"]
    assert backend["known_ceiling_bytes"] == 1500
    assert {s["egress_subject_uid"] or s["ingress_subject_uid"] for s in backend["stages"]} >= {
        IF_PROXY_ETH1,
        IF_HOST_ETH0,
    }
    original = legs["original"]
    assert original["requested_bytes"] == 1500
    assert not any(s["connection_reset"] for s in original["stages"])
    assert traced["known_ceiling_bytes"] is None
    req = MtuRequest(mode="packet", ip_packet_bytes=1500, ipv4_df=True)
    nat, gaps = request_for_connection(req, connection_reset=False)
    assert (nat.ip_packet_bytes, nat.ipv4_df, gaps) == (1500, True, [])
    proxy, gaps = request_for_connection(req, connection_reset=True)
    assert (proxy, gaps) == (None, ["MTU_LENGTH_UNSUPPORTED"])
    with pytest.raises(ValueError, match="address family"):
        estate.trace(mtu=unfragmented(1500), src=ADDR["ipv6_client"])
    router = resolved_stage("core-egress", IF_XR_GI1)
    with pytest.raises(ValueError, match="connection and AF"):
        build_feedback_packet(
            router,
            size_request(1600, mode="packet", ipv4_df=True),
            evaluate_stage(router, size_request(1600, mode="packet", ipv4_df=True)),
            router_ip="198.51.100.5",
            quoted_flow=quoted(6),
        )


def test_source_range_keeps_size_context_per_region(estate):
    traced = estate.trace(mtu=unfragmented(1500), src="192.0.2.0/28")
    assert traced["mtu"]["mode"] == "unfragmented"
    assert traced["mtu"]["requested_bytes"] == 1500
    assert traced["mtu"]["af"] == 4
    assert {s["region"] for s in traced["mtu"]["stages"]} == {"all"}
    assert stages_by_subject(traced["mtu"])[IF_XE_PO1][0]["constraints"][0]["value_bytes"] == 1500


# --- compatibility and lifecycle ----------------------------------------------------


def test_off_and_inventory_modes_preserve_the_plain_trace(estate):
    plain = path.trace(
        estate.session(), ADDR["client"], ADDR["server"], port=443, proto="tcp", gateways=estate.gateways
    )
    assert "mtu" not in plain
    assert estate.trace(mtu={"mode": "off"}) == plain
    inventory = estate.trace(mtu={"mode": "inventory"})
    assert {k: v for k, v in inventory.items() if k != "mtu"} == plain
    assert inventory["mtu"]["outcome"] == "not_assessed"
    assert inventory["mtu"]["requested_bytes"] is None
    # Common stages bound every candidate: the access SVI limit is a known upper bound.
    assert inventory["mtu"]["known_ceiling_bytes"] == 1500
    # Each VyOS interface MTU is one "both"-direction ceiling observation.
    assert len(inventory["mtu"]["observations"]) == 25
    assert MtuResult.model_validate({"outcome": "unknown", "coverage": {"complete": False}}).mode == "off"
    assert MtuResult().outcome == "not_assessed"
    assert MtuRequest().mode == "off"


def test_identity_freshness_failure_and_replay(estate, monkeypatch):
    baseline = {o.uid: o for o in batch_observations(cisco_batch("iosxe"))}
    changed_raw = dict(FIXTURE["cisco"]["iosxe"]["raw"])
    changed_raw["show ip interface"] = changed_raw["show ip interface"].replace(
        "Port-channel1 is up, line protocol is up\n  MTU is 1500",
        "Port-channel1 is up, line protocol is up\n  MTU is 1492",
    )
    changed = {o.uid: o for o in batch_observations(cisco_batch("iosxe", raw=changed_raw))}
    assert set(baseline) == set(changed)
    moved = [u for u in baseline if baseline[u].normalized_value != changed[u].normalized_value]
    assert [(baseline[u].subject_uid, changed[u].normalized_value) for u in moved] == [(IF_XE_PO1, 1492)]
    assert mtu_fingerprint([o.model_dump() for o in baseline.values()]) != mtu_fingerprint(
        [o.model_dump() for o in changed.values()]
    )
    replay = {o.uid: o.model_dump() for o in batch_observations(cisco_batch("iosxe"))}
    assert replay == {u: o.model_dump() for u, o in baseline.items()}
    carried = evidence(IF_XE_PO1)[0]
    original = estate.read

    def read(session, query, **params):
        if "HAS_MTU" in query and carried.subject_uid in params["subject_uids"]:
            return [row(carried, SNAP, carried=True, collected_at=OTHER_SNAP, _run_id="run-41")]
        return original(session, query, **params)

    monkeypatch.setattr(path, "_read", read)
    fresh = read_mtu(estate.session(), [IF_XE_PO1])
    assert fresh.carried_observation_uids == [carried.uid]
    assert fresh.provenance[carried.uid] == {
        "collection_ts": SNAP,
        "collected_at": OTHER_SNAP,
        "carried": True,
        "_run_id": "run-41",
    }
    assert fresh.by_subject[IF_XE_PO1][0].observed_at_ms is None
    failed = copy.deepcopy(FIXTURE["vyos"])
    failed[RAW_OUTCOMES_KEY] = {"links": {"status": "failed", "detail": "synthetic ssh failure"}}
    operational = [o for o in batch_observations(vyos_batch(failed)) if o.assertion_kind == "operational"]
    assert operational and all(o.normalized_value is None for o in operational)
    assert all("MTU_NOT_CAPTURED" in o.gaps for o in operational)
    configured = [o for o in batch_observations(vyos_batch(failed)) if o.assertion_kind == "configured"]
    assert {o.normalized_value for o in configured} == {9000}
    imported = imported_observations()[0]
    assert imported.observed_at_ms == FIXTURE["import"]["observations"][0]["observed_at_ms"]


# --- saved assessments and resilience --------------------------------------------


def test_saved_requirement_keeps_mtu_and_regression_sees_the_changed_constraint(monkeypatch):
    assessment_wire(monkeypatch)
    before = assessment_network({"if:r1-eth1": 1500})
    after = assessment_network({"if:r1-eth1": 9000})
    requirement = assessment_request(1501)
    first = answer(before, requirement)
    second = answer(after, requirement)
    assert not first.upper
    assert second.upper and not second.lower

    def ceilings(result):
        return {
            s.data["mtu"]["known_ceiling_bytes"]
            for member in result.members.values()
            for explanation in member.explanations
            for s in explanation.steps
            if "mtu" in s.data
        }

    assert ceilings(first) - {None} == {1500}
    assert ceilings(second) - {None} == {9000}
    mtu = {"mode": "unfragmented", "ip_packet_bytes": 1501, "ipv4_df": None, "reply_ip_packet_bytes": None}
    refs = [{"snapshot": str(SNAP), "manifest_sha256": "synthetic-estate-manifest"}]
    values = {
        "assessment_id": "estate-mtu",
        "assessment_revision": 1,
        "kind": "evaluate",
        "inputs": {"definition": {"request": {"mtu": mtu}}, "snapshot_refs": refs},
        "snapshot_refs": refs,
        "engine_version": "mtu-v1",
        "limits": {},
        "input_schema_version": 1,
    }
    changed = copy.deepcopy(values)
    changed["inputs"]["definition"]["request"]["mtu"]["ip_packet_bytes"] = 1500
    assert input_digest(values) != input_digest(changed)
    from hst.assessment import package

    run = {
        **values,
        "input_digest": input_digest(values),
        "id": "estate-mtu-run",
        "state": "completed",
        "result": {"mtu": {"outcome": "fail", "known_ceiling_bytes": 1500}},
    }
    document = package.export_document(run)
    assert document["run"]["inputs"]["definition"]["request"]["mtu"] == mtu
    assert package._validate_document(document) == document
    assert MtuRequirement(**mtu).as_request() == MtuRequest(mode="unfragmented", ip_packet_bytes=1501)


def test_member_failure_recomputes_the_path_minimum(monkeypatch):
    assessment_wire(monkeypatch)
    before = assessment_network({"if:r1-eth1": 9000, "if:r1-eth2": 1500})
    requirement = assessment_request(1600)
    baseline = answer(before, requirement)
    assert baseline.upper and not baseline.lower
    changed = apply_failures(before, [{"kind": "interface", "uid": "if:r1-eth1"}])
    result = answer(changed, requirement)
    assert not result.upper
    exceeded = [
        s.data["mtu"]["known_ceiling_bytes"]
        for member in result.members.values()
        for explanation in member.explanations
        for s in explanation.steps
        if s.kind == "packet-exceeds-limit"
    ]
    assert exceeded and set(exceeded) == {1500}
    assert changed.interfaces == before.interfaces


# --- bounded work ---------------------------------------------------------------------------


def test_audit_pagination_deduplication_and_candidate_truncation(estate, monkeypatch):
    original = estate.read
    links = [
        {"subject_uid": PORT_XE_GI1, "peer_uid": PORT_XR_GI0},
        {"subject_uid": PORT_XR_GI1, "peer_uid": IF_PROXY_ETH0},
    ]

    def read(session, query, **params):
        if "CONNECTED_TO" in query:
            remaining = [
                r for r in links if (r["subject_uid"], r["peer_uid"]) > (params["after_a"], params["after_b"])
            ]
            return remaining[: params["row_limit"]]
        if "HAS_MTU" in query:
            rows = original(session, query, **params)
            return rows + rows
        return original(session, query, **params)

    monkeypatch.setattr(path, "_read", read)
    first = audit_mtu(estate.session(), limit=1)
    assert first.truncated and first.next_cursor
    assert [(i.subject_uid, i.peer_uid) for i in first.items] == [(PORT_XE_GI1, PORT_XR_GI0)]
    assert first.query_count == 2
    duplicated = first.items[0].resolutions[0]
    assert [o.uid for o in duplicated.observations] == sorted({o.uid for o in duplicated.observations})
    second = audit_mtu(estate.session(), limit=1, cursor=first.next_cursor)
    assert [(i.subject_uid, i.peer_uid) for i in second.items] == [(PORT_XR_GI1, IF_PROXY_ETH0)]
    assert not second.truncated and second.next_cursor is None
    with pytest.raises(ValueError, match="cursor"):
        audit_mtu(SimpleNamespace(cts=OTHER_SNAP), limit=1, cursor=first.next_cursor)
    bundles = [
        pure_stage(
            1500,
            stage_id=f"{bundle}-{member}",
            candidate_set_id=f"lag:{bundle}",
            candidate_id=f"member:{member}",
            selection="eligible",
        )
        for bundle in range(8)
        for member in range(2)
    ]
    exhausted = evaluate_stages(bundles, size_request(1400))
    assert len(exhausted.candidates) == 128
    assert exhausted.coverage.truncated and "MTU_PATH_COVERAGE_INCOMPLETE" in exhausted.coverage.gaps
    assert exhausted.outcome == "unknown" and exhausted.guaranteed_bytes is None
    from hst.path.gates import _Trail
    from hst.path.mtu_topology import crossing, mtu_request, trace_scope

    @trace_scope()
    def walk(session):
        trail = _Trail()
        for i in range(MAX_STAGES + 1):
            crossing(trail, f"if:estate-scale/{i}", enforcement="l3")
        return {}

    before = len(estate.evidence_reads)
    with mtu_request(MtuRequest(mode="inventory"), 4):
        capped = walk(estate.session())["mtu"]
    assert len(capped["stages"]) == MAX_STAGES
    assert capped["coverage"]["truncated"] is True
    assert len(estate.evidence_reads) - before == 8 and all(
        len(p["subject_uids"]) <= 256 for p in estate.evidence_reads
    )


@pytest.mark.db
@_NEO4J_APPROVED
def test_server_side_distinct_and_keyset_order_require_neo4j():
    """The link audit on a real graph: DISTINCT folds a link drawn in both
    directions into one row, and the keyset cursor pages in uid order."""
    from hst.path.session import CycleSession

    driver, session = _approved_neo4j()
    with driver, session, session.begin_transaction() as tx:
        a, b, c = "mtu:t28:a", "mtu:t28:b", "mtu:t28:c"
        tx.run(
            "CREATE (a:Obj:Interface {uid:$a, collection_ts:42}) "
            "CREATE (b:Obj:Interface {uid:$b, collection_ts:42}) "
            "CREATE (c:Obj:Interface {uid:$c, collection_ts:42}) "
            "CREATE (a)-[:CONNECTED_TO {collection_ts:42}]->(b) "
            "CREATE (b)-[:CONNECTED_TO {collection_ts:42}]->(a) "
            "CREATE (b)-[:CONNECTED_TO {collection_ts:42}]->(c) "
            "CREATE (b)-[:CONNECTED_TO {collection_ts:41}]->(c)",
            a=a,
            b=b,
            c=c,
        ).consume()
        adapter = SimpleNamespace(execute_read=lambda work: work(tx))
        pinned = CycleSession(adapter, 42)
        first = audit_mtu(pinned, subject_uid=b, limit=1)
        assert [(i.subject_uid, i.peer_uid) for i in first.items] == [(a, b)]
        assert first.truncated and first.next_cursor
        second = audit_mtu(pinned, subject_uid=b, limit=1, cursor=first.next_cursor)
        assert [(i.subject_uid, i.peer_uid) for i in second.items] == [(b, c)]
        assert not second.truncated and second.next_cursor is None
        whole = audit_mtu(pinned, subject_uid=b, limit=10)
        assert [(i.subject_uid, i.peer_uid) for i in whole.items] == [(a, b), (b, c)]
        tx.rollback()


# --- entry-point parity -----------------------------------------------------------------


def _pin_entrypoints(monkeypatch, estate):
    from hst.core import cycle as cyclemod
    from hst.core import db as dbmod
    from hst.core import ribsource
    from hst.core import snapshot as snapshotmod

    monkeypatch.setattr(dbmod, "session", lambda *a, **k: nullcontext(object()))
    monkeypatch.setattr(path_route, "_session", lambda *a: nullcontext(object()))
    monkeypatch.setattr(snapshotmod, "resolve", lambda *a: SimpleNamespace(cts=SNAP))
    monkeypatch.setattr(ribsource, "for_snapshot", lambda *a: None)
    monkeypatch.setattr(cyclemod, "run_status", lambda *a: {"ts_ms": SNAP})
    monkeypatch.setattr(path, "pinned", lambda s, snap: estate.session())


async def test_http_cli_and_ask_ai_agree_with_the_engine(client, estate, monkeypatch):  # noqa: F811
    from typer.testing import CliRunner

    from hst import cli
    from hst.app.agent.tools import agent_registry
    from hst.app.ai.registry import Principal, ToolContext
    from hst.core import snapshot as snapshotmod

    _pin_entrypoints(monkeypatch, estate)
    direct = path.trace(
        estate.session(), ADDR["client"], ADDR["server"], port=443, proto="tcp", mtu=unfragmented(1501)
    )["mtu"]
    assert direct["fingerprint"] == estate.trace(mtu=unfragmented(1501))["mtu"]["fingerprint"]
    await login(client, "vera")
    query = f"/api/path?src={ADDR['client']}&dst={ADDR['server']}&port=443&proto=tcp"
    response = await client.get(query + "&mtu_mode=unfragmented&mtu_ip_packet_bytes=1501")
    assert response.status_code == 200, response.text
    served = response.json()["mtu"]
    assert served["fingerprint"] == direct["fingerprint"]
    assert served["outcome"] == direct["outcome"]
    assert ("MTU_CAPACITY_DEFICIT", "failure") in finding_codes(served)
    assert served["observations"] == direct["observations"]
    off = await client.get(query)
    assert off.status_code == 200 and "mtu" not in off.json()
    rejected = await client.get(
        f"/api/path?src={ADDR['ipv6_client']}&dst={ADDR['ipv6_server']}&mtu_mode=packet&mtu_ip_packet_bytes=65576"
    )
    assert rejected.status_code == 400
    assert "jumbograms unsupported" in rejected.text, rejected.text
    # reach_trace resolves the whole run through snapshot.resolve
    monkeypatch.setattr(snapshotmod, "resolve", lambda *a: snapshotmod.Snapshot(SNAP, SimpleNamespace()))
    ctx = ToolContext(settings=SimpleNamespace(), principal=Principal.for_role("viewer"), surface="drawer")
    outcome = agent_registry().invoke(
        ctx,
        "reach_trace",
        {
            "mode": "path",
            "flow": {"src": ADDR["client"], "dst": ADDR["server"], "port": 443},
            "mtu": unfragmented(1501),
        },
    )
    assert not outcome.is_error, outcome.ui_text
    asked = json.loads(outcome.ui_text)["result"]
    assert asked["mtu"]["fingerprint"] == direct["fingerprint"]
    printed = []
    monkeypatch.setattr(cli.console, "print_json", lambda data: printed.append(data))
    result = CliRunner().invoke(
        cli.app,
        [
            "path",
            ADDR["client"],
            ADDR["server"],
            "--port",
            "443",
            "--proto",
            "tcp",
            "--mtu-mode",
            "unfragmented",
            "--mtu-ip-packet-bytes",
            "1501",
        ],
    )
    assert result.exit_code == 0, result.output
    assert printed[-1]["mtu"]["fingerprint"] == direct["fingerprint"]
