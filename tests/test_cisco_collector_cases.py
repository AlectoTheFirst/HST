"""Cisco collector cases: the RIB paths that do not forward, the ARP table of
every VRF, the OSPF process identity and VRF, the IOS-XR hostname and a static
NAT translation to an interface address."""

from __future__ import annotations

from typing import Any

from tests.conftest import FakeSshSession
from tests.test_iosxe import RAW as IOSXE_RAW
from tests.test_iosxe import _collector as _iosxe_collector
from tests.test_iosxr import RAW as IOSXR_RAW
from tests.test_iosxr import _collector as _iosxr_collector

from hst.collectors import iosxe, iosxr, nxos, ssh
from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.collectors.cisco_common import (
    _nat_rule,
    normalize_cisco,
    ospf_side_rows,
    parse_nat_config,
    parse_ospf_process_text,
    stamp_ospf_vrfs,
)
from hst.core import uid
from hst.core.normalize import IfNameResolver
from hst.path.gates.nat import _nat_stage_rules

SCOPE = "iosxe:r1"


def _inter(**extra: Any) -> dict[str, Any]:
    return {
        "device": {"hostname": "r1", "serial": "FDO1", "platform": "iosxe", "os_version": "17"},
        "interfaces": [
            {
                "name": "GigabitEthernet0/0",
                "kind": "phys",
                "mac": None,
                "admin_up": True,
                "ips": [{"ip": "203.0.113.2", "prefixlen": 30, "vrf": ""}],
                "vlan": None,
            },
            {
                "name": "GigabitEthernet0/1",
                "kind": "phys",
                "mac": None,
                "admin_up": True,
                "ips": [{"ip": "10.0.0.1", "prefixlen": 24, "vrf": ""}],
                "vlan": None,
            },
            {
                "name": "GigabitEthernet0/2",
                "kind": "phys",
                "mac": None,
                "admin_up": True,
                "ips": [],
                "vlan": None,
            },
        ],
        "neighbors": [],
        "vlans": [],
        "vrfs": [{"name": "CUST", "rd": None, "rt_import": [], "rt_export": []}],
        "rib": [],
        "mac_table": [],
        "arp": [],
        **extra,
    }


def _batch(inter: dict[str, Any], **kw: Any):
    return normalize_cisco(inter, source="iosxe", scope=SCOPE, l3dom="corp", **kw)


def _nodes(batch, label: str) -> dict[str, dict[str, Any]]:
    return {n.uid: n.props for n in batch.nodes if n.label == label}


def _rels(batch, rel_type: str) -> list:
    return [r for r in batch.rels if r.rel_type == rel_type]


def _device(batch) -> str:
    return next(n.uid for n in batch.nodes if n.label == "Device")


# --- paths that do not forward -------------------------------------------------------------


def _nxos_prefix(*paths: dict[str, Any]) -> dict[str, Any]:
    return {"ipprefix": "10.9.0.0/24", "TABLE_path": {"ROW_path": list(paths)}}


def test_an_nxos_path_that_is_not_the_unicast_best_has_no_rib_record():
    prefix = _nxos_prefix(
        {"ipnexthop": "10.1.2.2", "ifname": "Eth1/1", "clientname": "static", "ubest": "true"},
        {"ipnexthop": "10.1.3.3", "ifname": "Eth1/2", "clientname": "ospf-1", "ubest": "false"},
        {"ipnexthop": "10.1.4.4", "ifname": "Eth1/3", "clientname": "ospf-1", "ubest": False},
    )
    assert [r["next_hop"] for r in nxos._rib_path_records("default", prefix)] == ["10.1.2.2"]


def test_an_nxos_path_without_ubest_keeps_its_record():
    prefix = _nxos_prefix(
        {"ipnexthop": "10.1.2.2", "ifname": "Eth1/1", "clientname": "ospf-1"},
        {"ipnexthop": "10.1.3.3", "ifname": "Eth1/2", "clientname": "ospf-1", "ubest": True},
    )
    assert [r["next_hop"] for r in nxos._rib_path_records("default", prefix)] == ["10.1.2.2", "10.1.3.3"]


XR_ROUTES = """\
VRF: default

Codes: C - connected, S - static, O - OSPF

Gateway of last resort is not set

O    10.9.0.0/24 [110/2] via 10.1.2.2, 1d00h, GigabitEthernet0/0/0/0
                 [110/0] via 10.1.3.3, 1d00h, GigabitEthernet0/0/0/1 (!)
O    10.8.0.0/24 [110/2] via 10.1.2.2, 1d00h, GigabitEthernet0/0/0/0
                 [110/2] via 10.1.3.3, 1d00h, GigabitEthernet0/0/0/1
"""


def test_an_iosxr_backup_path_has_no_rib_row_and_ecmp_paths_keep_theirs():
    rib = iosxr.parse({**IOSXR_RAW, iosxr.CMD_ROUTE: XR_ROUTES})["rib"]
    by_prefix: dict[str, list[str]] = {}
    for row in rib:
        by_prefix.setdefault(row["prefix"], []).append(row["next_hop"])
    assert by_prefix == {"10.9.0.0/24": ["10.1.2.2"], "10.8.0.0/24": ["10.1.2.2", "10.1.3.3"]}


# --- the ARP table of every VRF ------------------------------------------------------------

IOSXE_VRFS = """\
  Name                             Default RD            Protocols   Interfaces
  CUST                             65000:1               ipv4        Gi2
  Mgmt-intf                        <not set>             ipv4,ipv6   Gi1
"""

IOSXE_VRF_ARP = """\
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.9.0.7               12   0011.2233.4466  ARPA   GigabitEthernet1/0/2
"""


def test_iosxe_derives_one_arp_command_per_vrf():
    assert iosxe.arp_vrf_commands(IOSXE_VRFS) == ["show ip arp vrf CUST", "show ip arp vrf Mgmt-intf"]
    assert iosxe.arp_vrf_commands("") == []


def test_iosxe_reads_the_vrf_names_behind_a_login_banner_and_skips_an_unreadable_answer():
    # during the fetch an exec channel's answer still carries the banner
    banner = "CCCC\n*** Authorised access only ***\nUnauthorised use is prohibited.\n"
    assert iosxe.arp_vrf_commands(banner + IOSXE_VRFS) == iosxe.arp_vrf_commands(IOSXE_VRFS)
    assert iosxe.arp_vrf_commands("% Invalid input detected at '^' marker.\n") == []
    assert iosxe.arp_vrf_commands(IOSXE_VRFS + "a line no template reads\n") == []


def test_iosxe_stamps_each_vrf_arp_row_with_the_vrf_of_its_command():
    inter = iosxe.parse({**IOSXE_RAW, "show ip arp vrf mgmt": IOSXE_VRF_ARP})
    [row] = [r for r in inter["arp"] if r["ip"] == "10.9.0.7"]
    assert row["vrf"] == "mgmt"


def test_iosxe_observation_pattern_matches_the_arp_and_bgp_keys():
    assert iosxe.OBSERVATION_KEY_RE.fullmatch("show ip arp vrf CUST")
    assert iosxe.OBSERVATION_KEY_RE.fullmatch("show ip bgp summary")
    assert not iosxe.OBSERVATION_KEY_RE.fullmatch(iosxe.CMD_ARP)


def test_iosxe_sends_one_arp_command_per_vrf_after_the_static_commands(monkeypatch):
    fake = FakeSshSession(lambda cmd: IOSXE_RAW.get(cmd, "")).install(monkeypatch)
    raw = _iosxe_collector().fetch()
    assert [c for c in fake.commands if c.startswith("show ip arp vrf")] == ["show ip arp vrf mgmt"]
    assert raw[RAW_OUTCOMES_KEY]["show ip arp vrf mgmt"] == {"status": "ok"}


def test_a_refused_vrf_arp_read_makes_the_arp_section_partial(monkeypatch):
    def outputs(cmd: str) -> str:
        if cmd == "show ip arp vrf mgmt":
            raise ssh.CommandFailed(f"{cmd!r} exited 1: % Permission denied")
        return IOSXE_RAW.get(cmd, "")

    FakeSshSession(outputs).install(monkeypatch)
    c = _iosxe_collector()
    arp = c.sections(c.fetch())["arp"]
    assert arp.status == "partial"
    assert "mgmt" in arp.detail


def test_iosxr_reads_the_arp_table_of_every_vrf():
    assert iosxr.CMD_ARP == "show arp vrf all"


def test_an_iosxr_payload_under_the_show_arp_key_reads_its_arp_rows_and_section():
    raw = {k: v for k, v in IOSXR_RAW.items() if k != iosxr.CMD_ARP}
    raw["show arp"] = IOSXR_RAW[iosxr.CMD_ARP]
    raw[RAW_OUTCOMES_KEY] = {"show arp": {"status": "ok"}}
    assert iosxr.parse(raw)["arp"] == iosxr.parse(IOSXR_RAW)["arp"]
    c = _iosxr_collector()
    arp = c.sections(raw)["arp"]
    assert arp.status in ("ok", "empty")
    assert arp.row_count == len(iosxr.parse(IOSXR_RAW)["arp"])


# --- OSPF process identity and VRF ---------------------------------------------------------

OSPF_TEXT = """\
 Routing Process "ospf 1" with ID 10.0.0.1
 Area BACKBONE(0)
 Routing Process "ospf 10" with ID 192.168.0.1
 Connected to MPLS VPN Superbackbone, VRF CUST
 Area 1
 Routing Process "ospf 20" with ID 192.168.0.2
 Area 2
"""


def test_the_process_block_names_its_vrf():
    procs = {p["process"]: p for p in parse_ospf_process_text(OSPF_TEXT)}
    assert procs["10"]["vrf"] == "CUST"
    assert "vrf" not in procs["1"]


def _ospf_shape() -> dict[str, Any]:
    return {
        "processes": parse_ospf_process_text(OSPF_TEXT),
        "interfaces": [
            {"process": "1", "name": "Gi0/0", "area": "0"},
            {"process": "10", "name": "Gi0/1", "area": "1"},
            {"process": "20", "name": "Gi0/2", "area": "2"},
        ],
        # read from a table with no process column: stamped with the first process
        "adjacencies": [
            {"process": "1", "local_interface": "GigabitEthernet0/2", "neighbor_router_id": "9.9.9.9"},
        ],
        "lsdb": [{"process": "10", "lsa_type": "router"}, {"process": "20", "lsa_type": "router"}],
    }


def test_stamp_ospf_vrfs_gives_each_row_the_vrf_of_its_process():
    ospf = _ospf_shape()
    names = ["GigabitEthernet0/0", "GigabitEthernet0/1", "GigabitEthernet0/2"]
    resolve = IfNameResolver(names)
    # process 20 prints no VRF line (capability vrf-lite): its interface's VRF is used
    vrf_by_if = {resolve.slug("GigabitEthernet0/1"): "CUST", resolve.slug("GigabitEthernet0/2"): "LITE"}
    stamp_ospf_vrfs(ospf, vrf_by_if, resolve)
    assert {p["process"]: p["vrf"] for p in ospf["processes"]} == {"1": None, "10": "CUST", "20": "LITE"}
    assert [i["vrf"] for i in ospf["interfaces"]] == [None, "CUST", "LITE"]
    [adj] = ospf["adjacencies"]
    assert (adj["process"], adj["vrf"]) == ("20", "LITE")
    assert [lsa["vrf"] for lsa in ospf["lsdb"]] == ["CUST", "LITE"]


def test_two_processes_in_one_vrf_are_two_routing_processes():
    ospf = {
        "processes": [
            {"process": "1", "router_id": "10.0.0.1", "areas": [], "redistribute": []},
            {"process": "2", "router_id": "10.0.0.2", "areas": [], "redistribute": []},
        ],
        "interfaces": [],
        "adjacencies": [],
        "lsdb": [],
    }
    batch = _batch(_inter(ospf=ospf))
    dev = _device(batch)
    procs = {u: p for u, p in _nodes(batch, "RoutingProcess").items() if p.get("proto") == "ospf"}
    assert procs.keys() == {
        uid.routing_process(dev, "default", "ospf-1"),
        uid.routing_process(dev, "default", "ospf-2"),
    }
    assert {p["router_id"] for p in procs.values()} == {"10.0.0.1", "10.0.0.2"}


def test_the_lsa_rows_of_a_vrf_process_carry_the_vrf_context():
    ospf = {"processes": [], "interfaces": [], "adjacencies": [], "lsdb": [{"process": "10", "vrf": "CUST"}]}
    [row] = ospf_side_rows({"ospf": ospf}, "dev:r1")["ospf_lsdb"]
    assert row["context_uid"] == uid.vrf("dev:r1", "CUST")


# --- the IOS-XR hostname -------------------------------------------------------------------


def test_iosxr_reads_the_hostname_from_the_running_config():
    raw = {**IOSXR_RAW, iosxr.CMD_HOSTNAME: "Thu Oct 30 10:00:00.000 UTC\nhostname R1\n"}
    assert iosxr.parse(raw)["device"]["hostname"] == "R1"


def test_iosxr_without_a_hostname_answer_has_no_hostname():
    raw = {k: v for k, v in IOSXR_RAW.items() if k != iosxr.CMD_HOSTNAME}
    assert iosxr.parse(raw)["device"]["hostname"] is None
    assert iosxr.parse({**raw, iosxr.CMD_HOSTNAME: ""})["device"]["hostname"] is None


def test_a_box_without_a_hostname_is_named_by_its_host_and_states_no_identity():
    inter = _inter()
    inter["device"] = {**inter["device"], "hostname": None}
    device = next(iter(_nodes(_batch(inter, target_host="198.51.100.9"), "Device").values()))
    assert device["hostname"] == "198.51.100.9"
    assert device["identities"] == []


def test_a_box_with_a_hostname_keeps_it_as_its_identity():
    device = next(iter(_nodes(_batch(_inter(), target_host="198.51.100.9"), "Device").values()))
    assert device["hostname"] == "r1"
    assert device["identities"] == ["r1"]


# --- static NAT to an interface address ----------------------------------------------------


def test_a_static_translation_to_an_interface_is_parsed():
    rule = _nat_rule("inside", ["source", "static", "tcp", "10.0.0.5", "8080", "interface", "Gi0/0", "80"])
    assert rule is not None
    assert (rule["local"], rule["local_port"]) == ("10.0.0.5", 8080)
    assert (rule["global"], rule["global_port"], rule["interface"]) == (None, 80, "Gi0/0")
    assert _nat_rule("outside", ["source", "static", "interface", "Gi0/0", "10.0.0.5"]) is None


def _nat_batch(line: str):
    nat = parse_nat_config([line])
    nat["acls"] = {}
    return _batch(_inter(nat=nat))


def _nat_rules(batch) -> dict[str, dict[str, Any]]:
    return _nodes(batch, "NatRule")


def test_the_interface_address_is_the_translation():
    batch = _nat_batch("ip nat inside source static tcp 10.0.0.5 8080 interface Gi0/0 80")
    [(rule_uid, rule)] = _nat_rules(batch).items()
    assert rule["translation"] == "203.0.113.2"
    assert rule["translation_interface"] == "Gi0/0"
    assert rule["approximate"] is False
    assert [r for r in _rels(batch, "XLATE_SRC") if r.start_uid == rule_uid]
    assert [r for r in _rels(batch, "ORIG_SRC") if r.start_uid == rule_uid]


def test_an_interface_without_one_address_leaves_the_rule_approximate():
    batch = _nat_batch("ip nat inside source static tcp 10.0.0.5 8080 interface Gi0/2 80")
    [(rule_uid, rule)] = _nat_rules(batch).items()
    assert rule["translation"] == "interface"
    assert rule["approximate"] is True
    assert not [r for r in _rels(batch, "XLATE_SRC") if r.start_uid == rule_uid]


def _gate_row(**kw: Any) -> dict[str, Any]:
    base = {
        "rb_uid": "r1:nat",
        "rb_name": "NAT:inside-source",
        "approximate": False,
        "owners": ["dev:r1"],
        "install_on": [],
        "install_on_unresolved": False,
        "auto_generated": None,
        "orig_src_present": True,
        "orig_dst_present": False,
        "xlate_src_present": False,
        "xlate_dst_present": False,
        "uid": "r1:nat:inside-source:1",
        "pos": 1,
        "kind": "snat",
        "method": None,
        "enabled": True,
        "exclude": False,
        "translation": "interface",
        "translation_port": 80,
        "direction": "inside-source",
        "static_flag": True,
        "orig_src_raw": None,
        "orig_dst_raw": None,
        "orig_src_port": None,
        "orig_dst_port": None,
        "orig_port": 8080,
        "xlate_port": None,
        "protocol": "tcp",
        "in_if": None,
        "out_if": None,
        "translation_interface": "Gi0/2",
        "xlate_src_original": False,
        "xlate_dst_original": False,
        "rule_approximate": True,
        "orig_src_addrs": ["10.0.0.5"],
        "orig_dst_addrs": [],
        "xlate_src_addrs": [],
        "xlate_dst_addrs": [],
    }
    return {**base, **kw}


def test_the_gate_keeps_an_unresolved_interface_translation_opaque_in_both_stages():
    for stage in ("dnat", "snat"):
        [rule] = _nat_stage_rules([_gate_row()], stage, None)
        assert rule["opaque"] is True
        assert rule["role_note"] == "the static translation's interface address was not resolved"
    [dnat] = _nat_stage_rules([_gate_row()], "dnat", None)
    assert dnat["port_spec"] == 80
    [snat] = _nat_stage_rules([_gate_row()], "snat", None)
    assert snat["match_src"]


def test_the_gate_drops_a_static_rule_with_no_public_side_and_no_interface():
    assert _nat_stage_rules([_gate_row(translation=None, rule_approximate=False)], "dnat", None) == []
