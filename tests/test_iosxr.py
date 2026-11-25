"""ntc-templates has no template for the `detail` variant of `show arp`."""

import json

from tests.conftest import FakeSshSession

from hst import reasoner
from hst.collectors import iosxr, iosxr_bgp
from hst.collectors.auth import SshPassword
from hst.collectors.iosxr import (
    CMD_ARP,
    CMD_BGP,
    CMD_BGP_SESSIONS,
    CMD_CDP,
    CMD_HSRP,
    CMD_INTERFACES,
    CMD_INVENTORY,
    CMD_LLDP,
    CMD_OSPF,
    CMD_OSPF_CONFIG,
    CMD_OSPF_DB_ASBR_SUMMARY,
    CMD_OSPF_DB_EXTERNAL,
    CMD_OSPF_DB_NETWORK,
    CMD_OSPF_DB_NSSA_EXTERNAL,
    CMD_OSPF_DB_ROUTER,
    CMD_OSPF_DB_SUMMARY,
    CMD_OSPF_IF,
    CMD_OSPF_NBR,
    CMD_PREFIX_SET,
    CMD_ROUTE,
    CMD_ROUTE_POLICY,
    CMD_VERSION,
    CMD_VRF,
    OSPF_COMMANDS,
    IosxrCollector,
    IosxrConfig,
)
from hst.core import manifest, uid
from hst.core.l3domain import DEFAULT_VRF

HOST, USER = "xr1", "ro"
# `show version` carries no serial (iosxr.py's module docstring)
SERIAL = "FOX2140XR01"
# the in-memory registry names the box by the host the collector reached it at
DEV = "dev:xr1"

VERSION_TEXT = """\
Cisco IOS XR Software, Version 7.3.2
Copyright (c) 2013-2021 by Cisco Systems, Inc.

ROM: GRUB, Version 1.99(0), predownload

sw1 uptime is 2 weeks, 3 days, 4 hours, 5 minutes
System image file is "bootflash:disk0/xrv9k-mini-x-7.3.2/mbixrv9k-rp.vm"

cisco IOS-XRv 9000 () processor
"""

# Three interfaces with IPs: a phys interface (default vrf), a loopback (mgmt vrf,
# stamped below via the "show vrf all detail" fixture's interfaces list) and a
# second phys interface (default vrf) that the OSPF fixture below puts in a stub area.
INTERFACES_TEXT = """\
GigabitEthernet0/0/0/0 is up, line protocol is up
  Interface state transitions: 1
  Hardware is GigabitEthernet, address is aabb.ccdd.ee01 (bia aabb.ccdd.ee01)
  Internet address is 10.0.0.1/24
  MTU 1514 bytes, BW 1000000 Kbit
  reliability 255/255, txload 0/255, rxload 0/255
  Encapsulation ARPA,
  Full-duplex, 1000Mb/s, SR, link type is force-up
  Last input never, output never
  Last clearing of "show interface" counters never
Loopback0 is up, line protocol is up
  Interface state transitions: 1
  Hardware is Loopback
  Internet address is 10.255.0.1/32
  MTU 1500 bytes, BW 0 Kbit
  reliability 255/255, txload 0/255, rxload 0/255
  Encapsulation Loopback,
  Last input never, output never
  Last clearing of "show interface" counters never
GigabitEthernet0/0/0/2 is up, line protocol is up
  Interface state transitions: 1
  Hardware is GigabitEthernet, address is aabb.ccdd.ee02 (bia aabb.ccdd.ee02)
  Internet address is 10.0.2.1/24
  MTU 1514 bytes, BW 1000000 Kbit
  reliability 255/255, txload 0/255, rxload 0/255
  Encapsulation ARPA,
  Full-duplex, 1000Mb/s, SR, link type is force-up
  Last input never, output never
  Last clearing of "show interface" counters never
GigabitEthernet0/0/0/9 is up, line protocol is up
  Interface state transitions: 1
  Hardware is GigabitEthernet, address is aabb.ccdd.ee09 (bia aabb.ccdd.ee09)
  Internet address is 10.0.9.1/24
  MTU 1514 bytes, BW 1000000 Kbit
  reliability 255/255, txload 0/255, rxload 0/255
  Encapsulation ARPA,
  Auto-duplex, Auto-speed, SR, link type is force-up
  Last input never, output never
  Last clearing of "show interface" counters never
"""

# 1 lldp neighbor off the phys interface
LLDP_TEXT = """\
------------------------------------------------
Local Interface: GigabitEthernet0/0/0/0
Chassis id: aabb.ccdd.ef01
Port id: GigabitEthernet2/0/1
Port Description: GigabitEthernet2/0/1
System Name: core1

Time remaining: 100 seconds
Hold Time: 120 seconds
System Capabilities: B,R
Enabled Capabilities: B,R
IPv4 address: 10.0.0.254


Total entries displayed: 1
"""

# 1 cdp neighbor, same local port; CDP carries no peer MAC
CDP_TEXT = """\
-------------------------
Device ID: core1.example.com
Entry address(es):
  IPv4 address: 10.0.0.254
Platform: cisco ASR9006, Capabilities: Router
Interface: GigabitEthernet0/0/0/0
Port ID (outgoing port): GigabitEthernet2/0/1
Holdtime : 150 sec

Version :
Cisco IOS XR Software

advertisement version: 2
Duplex: full

Total cdp entries displayed : 1
"""

# iosxr.py's _chassis_serial() reads the "Rack 0" entry
INVENTORY_TEXT = """\
NAME: "Rack 0", DESCR: "Cisco IOS-XRv 9000 Centralized Virtual Router"
PID: R-IOSXRV9000-CC   , VID: V01, SN: FOX2140XR01

NAME: "module 0/RP0/CPU0", DESCR: "Cisco IOS-XRv 9000 Route Processor"
PID: R-IOSXRV9000-RP    , VID: V01, SN: FOX2140XR02
"""

# non-default vrf "mgmt" claims Loopback0; adapted command, see module docstring.
# The template captures RTs only when Import precedes Export, as in "CUST" below.
VRF_TEXT = """\
VRF mgmt; RD 1:100; VPN ID not set
  VRF mode: Regular
  Description not set
  Interfaces:
    Loopback0
  Address family IPV4 Unicast
    Export VPN route-target communities:
    Import VPN route-target communities:
    No import route policy
    No export route policy
VRF CUST; RD 1:200; VPN ID not set
  VRF mode: Regular
  Description not set
  Address family IPV4 Unicast
    Import VPN route-target communities:
      65000:100
    Export VPN route-target communities:
      65000:200
    No import route policy
    No export route policy
"""

# 2 routes incl. one non-default vrf; adapted command (needs an explicit "ipv4" and
# an explicit "VRF: default" header even for the default vrf's own section, see
# iosxr.py's docstring)
ROUTE_TEXT = """\
Codes: C - connected, S - static, R - RIP, B - BGP, (>) - Diversion path

VRF: default

Gateway of last resort is not set

S    10.0.0.0/24 [1/0] via 10.0.0.254, 00:10:00, GigabitEthernet0/0/0/0

VRF: mgmt

S    10.255.0.0/32 [1/0] via 10.255.0.2, 00:10:00, Loopback0
"""

# 2 arp entries: one off the default-vrf phys interface, one off the mgmt-vrf
# loopback; bare `show arp`, the form ntc-templates parses (module docstring)
ARP_TEXT = """\
Address         Age        Hardware Addr   State      Type  Interface
10.0.0.5        00:05:00   aabb.ccdd.efaa  Dynamic    ARPA  GigabitEthernet0/0/0/0
10.255.0.2      -          aabb.ccdd.efbb  Interface  ARPA  Loopback0
"""

# BGP process with a templated neighbor (192.0.2.1, remote-as/route-policies
# inherited via neighbor-group NG-CUST -> af-group AF-CUST), a plain neighbor with
# no route-policy at all (192.0.2.3), one resolvable redistribution
# (PL_REDIST) and one dangling one (PL_MISSING, warns, no edge).
BGP_TEXT = """\
router bgp 65000
 bgp router-id 10.0.0.1
 af-group AF-CUST address-family ipv4 unicast
  route-policy PL_CUST_IN in
  route-policy PL_CUST_OUT out
 !
 neighbor-group NG-CUST
  remote-as 65100
  address-family ipv4 unicast
   use af-group AF-CUST
  !
 !
 neighbor 192.0.2.1
  use neighbor-group NG-CUST
  address-family ipv4 unicast
  !
 !
 neighbor 192.0.2.3
  remote-as 65300
  address-family ipv4 unicast
  !
 !
 redistribute connected route-policy PL_REDIST
 redistribute static route-policy PL_MISSING
!
"""

# PFX_CUSTOMERS: exact (no ge/le/eq -> [16,16]), le (-> [8,24]) and eq
# (-> [24,24], overriding any ge/le) entries.
PREFIX_SET_TEXT = """\
prefix-set PFX_CUSTOMERS
 10.0.0.0/8 le 24,
 172.16.0.0/12 eq 24,
 192.168.0.0/16
end-set
!
prefix-set PFX_PARTNERS
 198.51.100.0/24
end-set
!
"""

# PL_CUST_IN: if/elseif/else with pass/apply/done/drop, incl. one resolvable
# apply (PL_PARTNER_EXTRA). PL_DANGLING_APPLY holds one dangling apply
# (PL_DOES_NOT_EXIST is never defined) and no if/elseif chain.
ROUTE_POLICY_TEXT = """\
route-policy PL_CUST_IN
 if destination in PFX_CUSTOMERS then
  set local-preference 150
  pass
 elseif destination in PFX_PARTNERS then
  apply PL_PARTNER_EXTRA
  done
 else
  drop
 endif
end-policy
!
route-policy PL_CUST_OUT
 pass
end-policy
!
route-policy PL_PARTNER_EXTRA
 set med 50
 done
end-policy
!
route-policy PL_REDIST
 done
end-policy
!
route-policy PL_DANGLING_APPLY
 apply PL_DOES_NOT_EXIST
 done
end-policy
!
"""

# The OSPF backbone/stub area ids, dotted.
AREA_0 = "0.0.0.0"  # noqa: S104 - an OSPF area id
AREA_10 = "0.0.0.10"

# --- OSPF: FIRST CONTACT, no field name below is confirmed against a live IOS-XR box.
# Every LSA type here goes through `cisco_common.ospf_lsa_detail_rows`.
OSPF_TEXT = """\
 Routing Process "ospf 1" with ID 10.0.0.1
 Supports only single TOS(TOS0) routes
 Number of areas in this router is 2. 1 normal 1 stub 0 nssa
 Area BACKBONE(0)
        Number of interfaces in this area is 1
        Area has no authentication
 Area 10
        Number of interfaces in this area is 1
        It is a stub area, no summary LSA in this area
        Area has no authentication
"""

OSPF_IF_TEXT = """\
GigabitEthernet0/0/0/0 is up, line protocol is up
  Internet Address 10.0.0.1/24, Area 0, Attached via Network Statement
  Process ID 1, Router ID 10.0.0.1, Network Type BROADCAST, Cost: 1
  Transmit Delay is 1 sec, State DR, Priority 1
GigabitEthernet0/0/0/2 is up, line protocol is up
  Internet Address 10.0.2.1/24, Area 10, Attached via Network Statement
  Process ID 1, Router ID 10.0.0.1, Network Type BROADCAST, Cost: 10
  No Hellos (Passive interface)
"""

# `cisco_xr_show_ospf_neighbor` records on the "Neighbor is up for ..." line
OSPF_NBR_TEXT = """\
Neighbors for OSPF 1

Neighbor ID     Pri   State           Dead Time   Address         Interface
10.0.0.2          1   FULL/BDR        00:00:33    10.0.0.2        GigabitEthernet0/0/0/0
    Neighbor is up for 00:10:12
"""

# One router LSA and one network LSA in the backbone.
OSPF_DB_ROUTER_TEXT = """\
            OSPF Router with ID (10.0.0.1) (Process ID 1)

                Router Link States (Area 0)

  LS age: 120
  Options: (No TOS-capability, DC)
  LS Type: Router Links
  Link State ID: 10.0.0.1
  Advertising Router: 10.0.0.1
  LS Seq Number: 80000005
  Checksum: 0x1234
  Length: 48
  Number of Links: 2

    Link connected to: another Router (point-to-point)
     (Link ID) Neighboring Router ID: 10.0.0.2
     (Link Data) Router Interface address: 10.0.0.1
      Number of MTID metrics: 0
       TOS 0 Metrics: 1

    Link connected to: a Stub Network
     (Link ID) Network/subnet number: 10.0.0.0
     (Link Data) Network Mask: 255.255.255.0
      Number of MTID metrics: 0
       TOS 0 Metrics: 1

"""

OSPF_DB_NETWORK_TEXT = """\
            OSPF Router with ID (10.0.0.1) (Process ID 1)

                Net Link States (Area 0)

  LS age: 130
  Options: (No TOS-capability, DC)
  LS Type: Network Links
  Link State ID: 10.0.0.2 (address of Designated Router)
  Advertising Router: 10.0.0.2
  LS Seq Number: 80000003
  Checksum: 0x5678
  Length: 32
  Network Mask: 255.255.255.0
        Attached Router: 10.0.0.1
        Attached Router: 10.0.0.2

"""

# Summary and nssa-external sit in the stub area; asbr-summary sits in the backbone;
# external belongs to no area (flooded domain-wide).
OSPF_DB_SUMMARY_TEXT = """\
       OSPF Router with ID (10.0.0.1) (Process ID 1)

                Summary Net Link States (Area 10)

  LS age: 200
  Options: (No TOS-capability, DC)
  LS Type: Summary Links(Network)
  Link State ID: 10.10.10.0 (summary Network Number)
  Advertising Router: 10.0.0.2
  LS Seq Number: 80000002
  Checksum: 0x5678
  Length: 28
  Network Mask: /24
        TOS: 0  Metric: 20
"""

OSPF_DB_ASBR_SUMMARY_TEXT = """\
       OSPF Router with ID (10.0.0.1) (Process ID 1)

                Summary ASB Link States (Area 0)

  LS age: 250
  Options: (No TOS-capability, DC)
  LS Type: Summary Links(AS Boundary Router)
  Link State ID: 10.0.0.3 (AS Boundary Router address)
  Advertising Router: 10.0.0.2
  LS Seq Number: 80000001
  Checksum: 0x1357
  Length: 28
        TOS: 0  Metric: 30
"""

OSPF_DB_EXTERNAL_TEXT = """\
       OSPF Router with ID (10.0.0.1) (Process ID 1)

                Type-5 AS External Link States

  LS age: 300
  Options: (No TOS-capability, DC, Upward)
  LS Type: AS External Link
  Link State ID: 192.0.2.0 (External Network Number )
  Advertising Router: 10.0.0.3
  LS Seq Number: 80000001
  Checksum: 0x9ABC
  Length: 36
  Network Mask: /24
        Metric Type: 2 (Larger than any link state path)
        MTID: 0
        Metric: 100
        Forward Address: 10.0.0.2
        External Route Tag: 0
"""

OSPF_DB_NSSA_EXTERNAL_TEXT = """\
       OSPF Router with ID (10.0.0.1) (Process ID 1)

                NSSA-External Link States (Area 10)

  LS age: 150
  Options: (No TOS-capability, Type 7/5 translation, DC)
  LS Type: AS External Link
  Link State ID: 203.0.113.0 (External Network Number )
  Advertising Router: 10.0.0.4
  LS Seq Number: 80000001
  Checksum: 0xDEF0
  Length: 36
  Network Mask: /24
        Metric Type: 2 (Larger than any link state path)
        MTID: 0
        Metric: 50
        Forward Address: 0.0.0.0
        External Route Tag: 0
"""

# The redistribute line of `router ospf` names the route-policy `PL_REDIST`.
OSPF_CONFIG_TEXT = """\
router ospf 1
 router-id 10.0.0.1
 redistribute static route-policy PL_REDIST
!
"""
# --- the BGP observation capture ---------------------------------------------------------
#
# FIRST CONTACT: no field name below is confirmed against a capture.
#
# 192.0.2.1 is an Established templated peer without soft reconfiguration inbound.
# 192.0.2.3 is an Idle plain peer with soft reconfiguration inbound.

# `show bgp summary`. No ntc-template matches this command (iosxr.py's own
# FIRST CONTACT note), so `_BGP_SESSION_ROW_RE` reads it directly.
BGP_SESSIONS_TEXT = """\
BGP router identifier 10.0.0.1, local AS number 65000
BGP table state: Active
BGP main routing table version 12

Neighbor        Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down  St/PfxRcd
192.0.2.1         0 65100     120     118       12    0    0 01:02:03          1
192.0.2.3         0 65300      10       8       12    0    0 00:00:00 Idle
"""

# The line a box with no soft reconfiguration inbound answers with: a zero
# exit status and no rejection banner, so the fetch keeps it as output and
# the direction reads not-captured on the text alone.
BGP_NO_SOFT_RECONFIG_TEXT = "% Inbound soft reconfiguration not configured for this neighbor\n"

# 192.0.2.1, the templated eBGP peer: one accepted path for 10.20.0.0/24 that
# the inbound route-policy (PL_CUST_IN) raised the local preference of and
# the device marked best, and one self-originated advertised prefix.
BGP_ACCEPTED_192_0_2_1_TEXT = """\
BGP table version is 12, local router ID is 10.0.0.1
Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,
Origin codes: i - IGP, e - EGP, ? - incomplete

   Network            Next Hop            Metric LocPrf Weight Path
*>  10.20.0.0/24      192.0.2.1                 0    150      0 65100 i
"""
BGP_ADVERTISED_192_0_2_1_TEXT = """\
BGP table version is 12, local router ID is 10.0.0.1
Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,
Origin codes: i - IGP, e - EGP, ? - incomplete

   Network            Next Hop            Metric LocPrf Weight Path
*>  10.0.0.0/24       10.0.0.1                  0    100      0 i
"""

# 192.0.2.3 sent two prefixes, and 10.20.0.0/24 also arrives from 192.0.2.1.
BGP_RECEIVED_192_0_2_3_TEXT = """\
BGP table version is 12, local router ID is 10.0.0.1
Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,
Origin codes: i - IGP, e - EGP, ? - incomplete

   Network            Next Hop            Metric LocPrf Weight Path
 *  10.20.0.0/24      192.0.2.3               100      0      0 65300 i
 *  198.51.100.0/24   192.0.2.3                 0      0      0 65300 64600 e
"""


def _bgp_capture_raw():
    """The observation commands the base fixture's fetch issues, and what the
    box answers each with."""
    out = {CMD_BGP_SESSIONS: BGP_SESSIONS_TEXT}
    answers = {
        ("192.0.2.1", "received"): BGP_NO_SOFT_RECONFIG_TEXT,
        ("192.0.2.1", "accepted"): BGP_ACCEPTED_192_0_2_1_TEXT,
        ("192.0.2.1", "advertised"): BGP_ADVERTISED_192_0_2_1_TEXT,
        ("192.0.2.3", "received"): BGP_RECEIVED_192_0_2_3_TEXT,
        ("192.0.2.3", "accepted"): "",
        ("192.0.2.3", "advertised"): "",
    }
    for (peer_ip, direction), text in answers.items():
        out[iosxr.bgp_route_command(peer_ip, direction)] = text
    return out


RAW = {
    CMD_VERSION: VERSION_TEXT,
    CMD_INTERFACES: INTERFACES_TEXT,
    CMD_LLDP: LLDP_TEXT,
    CMD_VRF: VRF_TEXT,
    CMD_ROUTE: ROUTE_TEXT,
    CMD_ARP: ARP_TEXT,
    CMD_CDP: CDP_TEXT,
    CMD_INVENTORY: INVENTORY_TEXT,
    CMD_BGP: BGP_TEXT,
    CMD_PREFIX_SET: PREFIX_SET_TEXT,
    CMD_ROUTE_POLICY: ROUTE_POLICY_TEXT,
    # the OSPF commands answer empty, as the OPTIONAL_COMMANDS stand-ins do
    CMD_OSPF: "",
    CMD_OSPF_IF: "",
    CMD_OSPF_NBR: "",
    CMD_OSPF_DB_ROUTER: "",
    CMD_OSPF_DB_NETWORK: "",
    CMD_OSPF_DB_SUMMARY: "",
    CMD_OSPF_DB_ASBR_SUMMARY: "",
    CMD_OSPF_DB_EXTERNAL: "",
    CMD_OSPF_DB_NSSA_EXTERNAL: "",
    CMD_OSPF_CONFIG: "",
    # HSRP: empty in the base fixture, a box with no group configured, the
    # same as the collector's own OPTIONAL_COMMANDS stand-in. `FHRP_RAW`
    # below is the variant with groups configured.
    CMD_HSRP: "",
    # interface filter bindings: none in the base fixture
    iosxr.CMD_INTERFACE_CONFIG: "",
    # the hostname: the name the collector reaches the box by, so the
    # Device uid is the one a box without the answer mints from its host
    iosxr.CMD_HOSTNAME: f"hostname {HOST}\n",
}

# These commands are derived from the BGP running-config above, so they join the payload here.
RAW.update(_bgp_capture_raw())
# the neighbor detail answers without a router id; test_bgp_peer_router_id.py
# covers the answered case
RAW[iosxr.CMD_BGP_NEIGHBORS] = ""
RAW[iosxr.CMD_BGP_VRF_NEIGHBORS] = ""

# the same box with the OSPF capture the base fixture leaves empty
OSPF_RAW = {
    **RAW,
    CMD_OSPF: OSPF_TEXT,
    CMD_OSPF_IF: OSPF_IF_TEXT,
    CMD_OSPF_NBR: OSPF_NBR_TEXT,
    CMD_OSPF_DB_ROUTER: OSPF_DB_ROUTER_TEXT,
    CMD_OSPF_DB_NETWORK: OSPF_DB_NETWORK_TEXT,
    CMD_OSPF_DB_SUMMARY: OSPF_DB_SUMMARY_TEXT,
    CMD_OSPF_DB_ASBR_SUMMARY: OSPF_DB_ASBR_SUMMARY_TEXT,
    CMD_OSPF_DB_EXTERNAL: OSPF_DB_EXTERNAL_TEXT,
    CMD_OSPF_DB_NSSA_EXTERNAL: OSPF_DB_NSSA_EXTERNAL_TEXT,
    CMD_OSPF_CONFIG: OSPF_CONFIG_TEXT,
}

# The interface filter bindings, as `show running-config interface` filtered to
# the stanza lines and the access-group lines prints them.
# Lab-invented, not captured from a device.
BINDING_CONFIG_TEXT = """\
interface GigabitEthernet0/0/0/0
 ipv4 access-group EDGE-IN ingress
 ipv6 access-group EDGE6-OUT egress
interface GigabitEthernet0/0/0/2
interface GigabitEthernet0/0/0/9
 ipv4 access-group EDGE-IN egress hardware-count
"""
BINDING_RAW = {**RAW, iosxr.CMD_INTERFACE_CONFIG: BINDING_CONFIG_TEXT}


def test_the_interface_filter_bindings_are_read():
    """Each ACL binding is read, ingress and egress as in and out."""
    assert iosxr.parse(BINDING_RAW)["acl"] == {
        "lists": {},
        "bindings": [
            {"interface": "GigabitEthernet0/0/0/0", "direction": "in", "acl": "EDGE-IN"},
            {"interface": "GigabitEthernet0/0/0/0", "direction": "out", "acl": "EDGE6-OUT", "family": "ipv6"},
            {"interface": "GigabitEthernet0/0/0/9", "direction": "out", "acl": "EDGE-IN"},
        ],
    }
    assert "acl" not in iosxr.parse(RAW)


def test_a_bound_list_is_an_opaque_rulebase_on_its_interface():
    """No list body is collected on IOS-XR, so each bound list is the opaque
    placeholder the gate reports undecided, bound where the device applies it."""
    batch = _collector().normalize(BINDING_RAW)
    rulebases = {n.uid: n.props for n in batch.nodes if n.label == "FwRulebase"}
    v4 = next(u for u, p in rulebases.items() if p["name"] == "EDGE-IN")
    v6 = next(u for u, p in rulebases.items() if p["name"] == "EDGE6-OUT")
    assert (rulebases[v4]["af"], rulebases[v6]["af"]) == (4, 6)
    names = {n.uid: n.props.get("name") for n in batch.nodes if n.label == "Interface"}
    edges = {
        (names[r.start_uid], r.end_uid, r.props["direction"])
        for r in batch.rels
        if r.rel_type == "PROTECTED_BY"
    }
    assert edges == {
        ("GigabitEthernet0/0/0/0", v4, "in"),
        ("GigabitEthernet0/0/0/0", v6, "out"),
        ("GigabitEthernet0/0/0/9", v4, "out"),
    }
    reasons = {
        n.props["opaque_reason"] for n in batch.nodes if n.label == "NetObject" and n.props.get("opaque")
    }
    assert reasons == {
        "the access list this interface is bound to was not collected (EDGE-IN)",
        "IPv6 access lists are not collected (EDGE6-OUT)",
    }


def test_the_bindings_are_a_policy_section_of_their_own():
    sections = _collector().normalize(BINDING_RAW).sections
    assert "interface_config" in sections


def _collector():
    return IosxrCollector(
        IosxrConfig(host=HOST, auth=SshPassword(username=USER, password="pw"), site_code="hq", l3dom="corp"),
        None,
    )


# SSH transport plumbing (auth/pin forwarding, observed host keys, one-transport-per-fetch,
# probe) is shared by every CLI collector and is exercised once, parametrized over vendors,
# in test_ssh_transport_conformance.py.


def test_arp_failure_degrades_to_empty_rows(monkeypatch, caplog):
    """A credential that may not read ARP costs the ARP side-rows."""
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd == CMD_ARP:
            raise ssh.CommandFailed("'show arp' exited 1: %% This command is not authorized")
        return RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    inter = iosxr.parse(raw)
    assert inter["arp"] == []
    assert inter["interfaces"] and inter["rib"]
    assert "show arp" in caplog.text and "continuing without it" in caplog.text


# --- section outcomes: what each command produced ---------------------------------------


def _sections(monkeypatch, outputs):
    """`Batch.sections` for one fetched payload."""
    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    return c.normalize(c.fetch()).sections


def test_a_failed_arp_read_reads_as_a_failed_section(monkeypatch):
    """Only the recorded outcome separates the empty stand-in from an empty ARP table."""
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd == CMD_ARP:
            raise ssh.CommandFailed(f"{CMD_ARP!r} exited 1")
        return RAW[cmd]

    sections = _sections(monkeypatch, outputs)
    assert sections["arp"].status == "failed"
    assert sections["interfaces"].status == "ok"


def test_a_table_the_box_returned_with_no_rows_reads_empty(monkeypatch):
    sections = _sections(monkeypatch, {**RAW, CMD_ARP: ""})
    assert sections["arp"].status == "empty"
    assert sections["arp"].row_count == 0


def test_a_collected_table_reads_ok_with_its_row_count(monkeypatch):
    sections = _sections(monkeypatch, RAW)
    assert sections["arp"].status == "ok" and sections["arp"].row_count
    assert sections["rib"].status == "ok"


def test_a_payload_with_no_recorded_outcomes_reads_unknown():
    """A raw file sealed without recorded outcomes claims nothing."""
    c = _collector()
    assert {s.status for s in c.normalize(dict(RAW)).sections.values()} == {"unknown"}


# --- _chassis_serial: pure ------------------------------------------------------------------


def test_chassis_serial_reads_the_rack_0_entry():
    rows = [
        {"name": "Rack 0", "sn": "FOX2140XR01", "descr": "chassis"},
        {"name": "module 0/RP0/CPU0", "sn": "FOX2140XR02"},
    ]
    assert iosxr._chassis_serial(rows) == "FOX2140XR01"


def test_chassis_serial_missing_rack_0_entry_returns_none():
    assert iosxr._chassis_serial([{"name": "module 0/RP0/CPU0", "sn": "FOX2140XR02"}]) is None
    assert iosxr._chassis_serial([]) is None


def test_chassis_serial_rack_0_entry_without_sn_returns_none():
    # TextFSM never omits a field: an FRU line without a serial captures `sn` as ""
    assert iosxr._chassis_serial([{"name": "Rack 0", "sn": "", "pid": "x"}]) is None


# --- residual gap: inventory has no usable serial either -> scope-keyed fallback ----------


def test_normalize_falls_back_to_scope_keyed_uid_when_inventory_has_no_serial(monkeypatch):
    # show inventory parsed, but with no "Rack 0" entry and no sn
    bare_inter = {
        "device": {"hostname": None, "serial": None, "platform": "iosxr", "os_version": "7.3.2"},
        "interfaces": [],
        "neighbors": [],
        "vlans": [],
        "vrfs": [],
        "rib": [],
        "mac_table": [],
        "arp": [],
    }
    monkeypatch.setattr(iosxr, "parse", lambda raw: bare_inter)
    c = _collector()
    batch = c.normalize(RAW)
    dev = next(n for n in batch.nodes if n.label == "Device")
    # the registry keys a box without serial and hostname by its scope
    assert c.scope == "iosxr:xr1"
    assert dev.uid == c.identity.resolve_device("ref", "iosxr:xr1:unknown", None)
    rows = c.side_tables(RAW)
    assert rows == {"rib": [], "mac": [], "arp": []}


# --- parse/normalize/side_tables against the fixture texts ----------------------------------


class TestParsed:
    def test_parse_device_has_its_hostname_and_a_serial(self):
        # `show version` carries no hostname; `show running-config hostname`
        # does. The serial comes from `show inventory`'s "Rack 0"
        # chassis entry.
        inter = iosxr.parse(RAW)
        assert inter["device"] == {
            "hostname": HOST,
            "serial": SERIAL,
            "platform": "iosxr",
            "os_version": "7.3.2",
        }

    def test_parse_phys_interface_has_mac_ip_and_default_vrf(self):
        inter = iosxr.parse(RAW)
        eth = next(i for i in inter["interfaces"] if i["name"] == "GigabitEthernet0/0/0/0")
        assert eth["kind"] == "phys"
        assert eth["mac"] == "aabbccddee01"
        assert eth["admin_up"] is True
        assert eth["ips"] == [{"ip": "10.0.0.1", "prefixlen": 24, "vrf": ""}]

    def test_parse_loopback_has_ip_and_non_default_vrf(self):
        inter = iosxr.parse(RAW)
        lo = next(i for i in inter["interfaces"] if i["name"] == "Loopback0")
        assert lo["kind"] == "loopback"
        assert lo["mac"] is None
        assert lo["ips"] == [{"ip": "10.255.0.1", "prefixlen": 32, "vrf": "mgmt"}]

    def test_parse_lldp_neighbor(self):
        inter = iosxr.parse(RAW)
        lldp = [n for n in inter["neighbors"] if n["proto"] == "lldp"]
        assert lldp == [
            {
                "local_port": "GigabitEthernet0/0/0/0",
                "name": "core1",
                "mac": "aabbccddef01",
                "port": "GigabitEthernet2/0/1",
                "proto": "lldp",
            }
        ]

    def test_parse_cdp_neighbor_has_no_mac(self):
        inter = iosxr.parse(RAW)
        cdp = [n for n in inter["neighbors"] if n["proto"] == "cdp"]
        assert cdp == [
            {
                "local_port": "GigabitEthernet0/0/0/0",
                "name": "core1.example.com",
                "mac": None,
                "port": "GigabitEthernet2/0/1",
                "proto": "cdp",
            }
        ]

    def test_parse_rib_rows_include_non_default_vrf(self):
        inter = iosxr.parse(RAW)
        assert inter["rib"] == [
            {
                "vrf": "default",
                "prefix": "10.0.0.0/24",
                "next_hop": "10.0.0.254",
                "next_hop_vrf": None,
                "interface": "GigabitEthernet0/0/0/0",
                "protocol": "static",
                "metric": 0,
            },
            {
                "vrf": "mgmt",
                "prefix": "10.255.0.0/32",
                "next_hop": "10.255.0.2",
                "next_hop_vrf": None,
                "interface": "Loopback0",
                "protocol": "static",
                "metric": 0,
            },
        ]

    def test_parse_arp_rows_derive_vrf_from_show_vrf_membership(self):
        inter = iosxr.parse(RAW)
        assert inter["arp"] == [
            {
                "vrf": "default",
                "ip": "10.0.0.5",
                "mac": "aabbccddefaa",
                "interface_name": "GigabitEthernet0/0/0/0",
            },
            {"vrf": "mgmt", "ip": "10.255.0.2", "mac": "aabbccddefbb", "interface_name": "Loopback0"},
        ]

    def test_parse_no_mac_table_for_a_router(self):
        assert iosxr.parse(RAW)["mac_table"] == []

    def test_parse_vrf_dicts_carry_rd_and_rt_import_export(self):
        inter = iosxr.parse(RAW)
        by_name = {v["name"]: v for v in inter["vrfs"]}
        assert by_name["mgmt"] == {"name": "mgmt", "rd": "1:100", "rt_import": [], "rt_export": []}
        assert by_name["CUST"] == {
            "name": "CUST",
            "rd": "1:200",
            "rt_import": ["65000:100"],
            "rt_export": ["65000:200"],
        }

    def test_normalize_emits_route_target_nodes_and_directional_rels_for_a_vrf_with_rts(self):
        batch = _collector().normalize(RAW)
        cust_vrf = uid.vrf(DEV, "CUST")
        mgmt_vrf = uid.vrf(DEV, "mgmt")
        rt_import, rt_export = uid.route_target("65000:100"), uid.route_target("65000:200")
        assert any(n.uid == rt_import and n.label == "RouteTarget" for n in batch.nodes)
        assert any(n.uid == rt_export and n.label == "RouteTarget" for n in batch.nodes)
        assert (cust_vrf, rt_import) in [
            (r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IMPORTS"
        ]
        assert (cust_vrf, rt_export) in [
            (r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "EXPORTS"
        ]
        cust_node = next(n for n in batch.nodes if n.uid == cust_vrf)
        assert cust_node.props["rd"] == "1:200"
        # mgmt's RT sections are empty in the fixture: no IMPORTS/EXPORTS for it
        assert not [r for r in batch.rels if r.rel_type in ("IMPORTS", "EXPORTS") and r.start_uid == mgmt_vrf]

    def test_normalize_serial_uid_and_vendor(self):
        batch = _collector().normalize(RAW)
        dev = next(n for n in batch.nodes if n.label == "Device")
        assert dev.uid == DEV
        assert dev.props["vendor"] == "cisco"
        assert dev.props["serial"] == SERIAL

    def test_normalize_stamps_role_so_the_gateway_rule_can_see_the_box(self):
        """reasoner.py's gateway-from-router-interface rule keys on Device.role."""
        batch = _collector().normalize(RAW)
        dev = next(n for n in batch.nodes if n.label == "Device")
        assert dev.props["role"] in reasoner.GATEWAY_ROLES

    def test_normalize_loopback_in_vrf_toward_the_non_default_vrf(self):
        batch = _collector().normalize(RAW)
        iu = uid.interface(DEV, "Loopback0")
        vru = uid.vrf(DEV, "mgmt")
        assert any(r.rel_type == "IN_VRF" and r.start_uid == iu and r.end_uid == vru for r in batch.rels)
        assert any(
            n.uid == vru and n.label == "VrfInstance" and n.props["name"] == "mgmt" for n in batch.nodes
        )

    def test_normalize_lldp_and_cdp_hints_land_on_the_port(self):
        batch = _collector().normalize(RAW)
        pu = uid.port(DEV, "GigabitEthernet0/0/0/0")
        port = next(n for n in batch.nodes if n.uid == pu)
        assert port.props["lldp_neighbor_name"] == "core1"
        assert port.props["lldp_neighbor_mac"] == "aabbccddef01"
        assert port.props["cdp_neighbor_name"] == "core1.example.com"
        assert "cdp_neighbor_mac" not in port.props

    def test_side_tables_device_uid_matches_normalized_device_and_no_mac_table(self):
        c = _collector()
        batch = c.normalize(RAW)
        dev = next(n for n in batch.nodes if n.label == "Device")
        rows = c.side_tables(RAW)
        assert rows["mac"] == []
        # side_tables' fallback derives the same uid normalize_cisco used for the Device node
        assert rows["rib"] and all(r["device_uid"] == dev.uid for r in rows["rib"])
        assert rows["arp"] and all(r["device_uid"] == dev.uid for r in rows["arp"])
        assert {r["vrf"] for r in rows["rib"]} == {"default", "mgmt"}
        assert {r["vrf"] for r in rows["arp"]} == {"default", "mgmt"}

    # --- Link speed: duplex/speed/BW off `show interfaces` onto the Port -----------

    def test_normalize_known_speed_and_duplex_land_on_the_port(self):
        batch = _collector().normalize(RAW)
        port = next(n for n in batch.nodes if n.uid == uid.port(DEV, "GigabitEthernet0/0/0/0"))
        assert port.props["speed_mbps"] == 1000
        assert port.props["duplex"] == "full"
        assert port.props["speed_source"] == "iosxr:show interfaces"
        assert port.props["bandwidth_kbit"] == 1000000

    def test_normalize_auto_speed_and_duplex_give_nulls_and_no_source(self):
        batch = _collector().normalize(RAW)
        port = next(n for n in batch.nodes if n.uid == uid.port(DEV, "GigabitEthernet0/0/0/9"))
        assert "speed_mbps" not in port.props
        assert "duplex" not in port.props
        assert "speed_source" not in port.props
        # the MTU/BW line is on its own and still parses independently
        assert port.props["bandwidth_kbit"] == 1000000

    def test_normalize_no_duplex_speed_line_gives_nulls_and_no_source(self):
        """Loopback0's fixture text carries no `Full-duplex, ...` line."""
        ifc = next(i for i in iosxr.parse(RAW)["interfaces"] if i["name"] == "Loopback0")
        assert ifc["speed_mbps"] is None
        assert ifc["duplex"] is None
        assert ifc["speed_source"] is None
        assert ifc["bandwidth_kbit"] == 0


# --- BGP process, prefix-set, route-policy (RPL), redistribution --------------------------


class TestParsedBgp:
    def test_parse_bgp_process(self):
        inter = iosxr.parse(RAW)
        assert inter["xr_bgp"] == {"asn": 65000, "router_id": "10.0.0.1"}

    def test_parse_templated_neighbor_inherits_remote_as_and_route_policies(self):
        """192.0.2.1 sets neither remote-as nor route-policy directly."""
        inter = iosxr.parse(RAW)
        sess = next(s for s in inter["xr_bgp_sessions"] if s["peer_ip"] == "192.0.2.1")
        assert sess["peer_asn"] == 65100
        assert sess["local_asn"] == 65000
        assert sess["afi_safi"] == ["ipv4-unicast"]
        assert sess["import_policy_name"] == "PL_CUST_IN"
        assert sess["import_policy_kind"] == "rpl"
        assert sess["export_policy_name"] == "PL_CUST_OUT"
        assert sess["export_policy_kind"] == "rpl"

    def test_parse_neighbor_without_any_route_policy(self):
        inter = iosxr.parse(RAW)
        sess = next(s for s in inter["xr_bgp_sessions"] if s["peer_ip"] == "192.0.2.3")
        assert sess["peer_asn"] == 65300
        assert sess["import_policy_name"] is None
        assert sess["export_policy_name"] is None

    def test_parse_redistribute_entries(self):
        inter = iosxr.parse(RAW)
        assert inter["xr_bgp_redistribute"] == [
            {"protocol": "connected", "policy_name": "PL_REDIST"},
            {"protocol": "static", "policy_name": "PL_MISSING"},
        ]

    def test_parse_prefix_set_mixed_length_ranges(self):
        inter = iosxr.parse(RAW)
        pl = next(p for p in inter["xr_prefix_lists"] if p["name"] == "PFX_CUSTOMERS")
        by_prefix = {e["prefix"]: e for e in pl["entries"]}
        assert by_prefix["10.0.0.0/8"]["le"] == 24
        assert by_prefix["10.0.0.0/8"]["min_len"] == 8 and by_prefix["10.0.0.0/8"]["max_len"] == 24
        assert by_prefix["172.16.0.0/12"]["eq"] == 24
        assert by_prefix["172.16.0.0/12"]["min_len"] == 24 and by_prefix["172.16.0.0/12"]["max_len"] == 24
        # no ge/le/eq -> exact-length-only, the standalone default
        assert by_prefix["192.168.0.0/16"]["ge"] is None and by_prefix["192.168.0.0/16"]["le"] is None
        assert by_prefix["192.168.0.0/16"]["min_len"] == 16 and by_prefix["192.168.0.0/16"]["max_len"] == 16
        assert all(e["action"] == "permit" for e in pl["entries"])

    def test_parse_route_policy_if_elseif_else_chain(self):
        inter = iosxr.parse(RAW)
        rp = next(p for p in inter["xr_route_policies"] if p["name"] == "PL_CUST_IN")
        entries = {e["seq"]: e for e in rp["entries"]}
        assert len(entries) == 3
        assert entries[1]["match_prefix_lists"] == ["PFX_CUSTOMERS"]
        assert entries[1]["set_local_pref"] == 150
        assert entries[1]["continues"] is True and entries[1]["continue_seq"] == 2
        assert "action" not in entries[1]  # pass: no terminal action of its own
        assert entries[2]["match_prefix_lists"] == ["PFX_PARTNERS"]
        assert entries[2]["calls_policy"] == "PL_PARTNER_EXTRA"
        assert entries[2]["action"] == "permit"  # done
        assert entries[2]["continues"] is True and entries[2]["continue_seq"] == 3
        assert entries[3]["action"] == "deny"  # else -> drop
        assert "continues" not in entries[3]

    def test_parse_route_policy_keeps_guards_it_cannot_read(self):
        """A guard with `not`/`or` is stored whole as `match_expr`, naming the
        set it reads, and an atom the engine cannot evaluate is kept verbatim,
        so neither branch is stored as one with no guard."""
        text = (
            "route-policy RP\n"
            " if not destination in BOGONS then\n  pass\n else\n  drop\n endif\n"
            " if destination in PFX and rib-has-route in (10.0.0.0/8) then\n  drop\n endif\n"
            "end-policy\n"
        )
        (rp,) = iosxr_bgp.parse_route_policies(text)
        entries = {e["seq"]: e for e in rp["entries"]}
        assert json.loads(entries[1]["match_expr"]) == {"not": {"prefix_list": "BOGONS"}}
        assert entries[1]["match_prefix_lists"] == ["BOGONS"]
        assert "match_unsupported" not in entries[1]
        assert entries[3]["match_prefix_lists"] == ["PFX"]
        assert entries[3]["match_unsupported"] == ["rib-has-route in (10.0.0.0/8)"]

    def test_compiled_pass_branch_with_an_unread_guard_reports_it(self):
        """The parsed `pass`-only branch adds no statement, so its unread guard
        is reported against the policy, not skipped."""
        from hst.simul import platforms
        from hst.simul.compile import compile_policies
        from hst.simul.errors import ErrorSink

        text = (
            "route-policy RP\n if rib-has-route in (10.0.0.0/8) then\n  pass\n else\n  drop\n endif\n"
            "end-policy\n"
        )
        errors = ErrorSink()
        compile_policies(iosxr_bgp.parse_route_policies(text), platforms.IOSXR, errors)
        assert [(e.kind, e.subject) for e in errors.errors] == [("unsupported-match", "RP")]


class TestNormalizeBgp:
    def test_normalize_routing_process(self):
        batch = _collector().normalize(RAW)
        rp_uid = uid.routing_process(DEV, DEFAULT_VRF, "bgp")
        rp = next(n for n in batch.nodes if n.uid == rp_uid)
        assert rp.label == "RoutingProcess"
        assert rp.props["proto"] == "bgp"
        assert rp.props["asn"] == 65000
        assert rp.props["router_id"] == "10.0.0.1"
        assert any(
            r.rel_type == "IN_VRF" and r.start_uid == rp_uid and r.end_uid == uid.vrf(DEV, "default")
            for r in batch.rels
        )

    def test_normalize_templated_neighbor_bgp_session_carries_resolved_values(self):
        batch = _collector().normalize(RAW)
        rp_uid = uid.routing_process(DEV, DEFAULT_VRF, "bgp")
        su = uid.bgp_session(rp_uid, "192.0.2.1", DEFAULT_VRF)
        sess = next(n for n in batch.nodes if n.uid == su)
        assert sess.label == "BgpSession"
        assert sess.props["local_asn"] == 65000
        assert sess.props["peer_asn"] == 65100
        assert sess.props["afi_safi"] == ["ipv4-unicast"]
        assert sess.props["import_policy_name"] == "PL_CUST_IN"
        assert sess.props["export_policy_name"] == "PL_CUST_OUT"
        assert any(r.rel_type == "HAS" and r.start_uid == rp_uid and r.end_uid == su for r in batch.rels)

    def test_normalize_neighbor_without_route_policy_emits_bgp_session(self):
        """The session holds no policy name. The engine applies the default drop of IOS-XR."""
        batch = _collector().normalize(RAW)
        rp_uid = uid.routing_process(DEV, DEFAULT_VRF, "bgp")
        su = uid.bgp_session(rp_uid, "192.0.2.3", DEFAULT_VRF)
        sess = next(n for n in batch.nodes if n.uid == su)
        assert sess.props["peer_asn"] == 65300
        assert sess.props.get("import_policy_name") is None
        assert sess.props.get("export_policy_name") is None
        assert not [r for r in batch.rels if r.rel_type == "FILTERED_BY" and r.start_uid == su]

    def test_normalize_bgp_session_filtered_by_resolved_route_policy(self):
        batch = _collector().normalize(RAW)
        rp_uid = uid.routing_process(DEV, DEFAULT_VRF, "bgp")
        su = uid.bgp_session(rp_uid, "192.0.2.1", DEFAULT_VRF)
        pl_in = uid.route_policy(DEV, "rpl", "PL_CUST_IN")
        pl_out = uid.route_policy(DEV, "rpl", "PL_CUST_OUT")
        edges = {(r.rel_type, r.end_uid, r.key.get("direction")) for r in batch.rels if r.start_uid == su}
        assert ("FILTERED_BY", pl_in, "in") in edges
        assert ("FILTERED_BY", pl_out, "out") in edges

    def test_normalize_route_policy_entries_and_has_rule_edges(self):
        batch = _collector().normalize(RAW)
        pu = uid.route_policy(DEV, "rpl", "PL_CUST_IN")
        policy = next(n for n in batch.nodes if n.uid == pu)
        assert policy.label == "RoutePolicy" and policy.props["kind"] == "rpl"
        entry_uids = [uid.route_policy_entry(pu, s) for s in (1, 2, 3)]
        for eu in entry_uids:
            entry = next(n for n in batch.nodes if n.uid == eu)
            assert entry.label == "RoutePolicyEntry" and entry.props["kind"] == "statement"
            assert any(r.rel_type == "HAS_RULE" and r.start_uid == pu and r.end_uid == eu for r in batch.rels)

    def test_normalize_prefix_set_entries_and_has_rule_edges(self):
        batch = _collector().normalize(RAW)
        pu = uid.route_policy(DEV, "prefix-list", "PFX_CUSTOMERS")
        policy = next(n for n in batch.nodes if n.uid == pu)
        assert policy.label == "RoutePolicy" and policy.props["kind"] == "prefix-list"
        entries = [n for n in batch.nodes if n.label == "PrefixListEntry" and n.uid.startswith(f"{pu}/line/")]
        assert len(entries) == 3
        for e in entries:
            assert e.props["action"] == "permit"
            assert any(r.rel_type == "HAS_RULE" and r.end_uid == e.uid for r in batch.rels)

    def test_normalize_resolvable_apply_gets_a_references_edge(self):
        batch = _collector().normalize(RAW)
        pu = uid.route_policy(DEV, "rpl", "PL_CUST_IN")
        eu = uid.route_policy_entry(pu, 2)  # elseif branch: apply PL_PARTNER_EXTRA
        target = uid.route_policy(DEV, "rpl", "PL_PARTNER_EXTRA")
        assert any(
            r.rel_type == "REFERENCES"
            and r.start_uid == eu
            and r.end_uid == target
            and r.key.get("kind") == "call"
            for r in batch.rels
        )

    def test_normalize_resolvable_prefix_list_match_gets_a_references_edge(self):
        batch = _collector().normalize(RAW)
        pu = uid.route_policy(DEV, "rpl", "PL_CUST_IN")
        eu = uid.route_policy_entry(pu, 1)  # if branch: destination in PFX_CUSTOMERS
        target = uid.route_policy(DEV, "prefix-list", "PFX_CUSTOMERS")
        assert any(
            r.rel_type == "REFERENCES"
            and r.start_uid == eu
            and r.end_uid == target
            and r.key.get("kind") == "prefix-list"
            for r in batch.rels
        )

    def test_normalize_dangling_apply_warns_records_the_name_and_writes_no_edge(self, caplog):
        batch = _collector().normalize(RAW)
        pu = uid.route_policy(DEV, "rpl", "PL_DANGLING_APPLY")
        eu = uid.route_policy_entry(pu, 1)
        entry = next(n for n in batch.nodes if n.uid == eu)
        assert entry.props["calls_policy"] == "PL_DOES_NOT_EXIST"
        assert not [r for r in batch.rels if r.rel_type == "REFERENCES" and r.start_uid == eu]
        assert "PL_DOES_NOT_EXIST" in caplog.text and "undefined" in caplog.text

    def test_normalize_dangling_redistribution_policy_warns_and_writes_no_edge(self, caplog):
        batch = _collector().normalize(RAW)
        rp_uid = uid.routing_process(DEV, DEFAULT_VRF, "bgp")
        assert not [
            r
            for r in batch.rels
            if r.rel_type == "FILTERED_BY" and r.start_uid == rp_uid and r.key.get("protocol") == "static"
        ]
        assert "PL_MISSING" in caplog.text

    def test_normalize_resolvable_redistribution_policy_gets_filtered_by_edge(self):
        batch = _collector().normalize(RAW)
        rp_uid = uid.routing_process(DEV, DEFAULT_VRF, "bgp")
        target = uid.route_policy(DEV, "rpl", "PL_REDIST")
        assert any(
            r.rel_type == "FILTERED_BY"
            and r.start_uid == rp_uid
            and r.end_uid == target
            and r.key.get("protocol") == "connected"
            for r in batch.rels
        )


def test_bgp_extracts_degrade_to_no_bgp_nodes_when_nothing_is_configured(monkeypatch):
    """A box with no `router bgp`, no prefix-sets and no route-policies does not fail the inventory."""
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd in (CMD_BGP, CMD_PREFIX_SET, CMD_ROUTE_POLICY):
            raise ssh.CommandFailed(f"{cmd!r} exited 1")
        if cmd == CMD_BGP_SESSIONS:
            return ""
        return RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    inter = iosxr.parse(raw)
    assert inter["xr_route_policies"] == [] and inter["xr_prefix_lists"] == []
    assert "bgp" not in inter and "bgp_sessions" not in inter
    batch = c.normalize(raw)
    assert not [n for n in batch.nodes if n.label in ("RoutingProcess", "BgpSession", "RoutePolicy")]


# --- OSPF: parse/normalize/side_tables against the fixture texts ----------------------------


class TestOspf:
    def test_parse_process_router_id_and_two_areas(self):
        ospf = iosxr.parse(OSPF_RAW)["ospf"]
        proc = ospf["processes"][0]
        assert proc["process"] == "1"
        assert proc["router_id"] == "10.0.0.1"
        areas = {a["area_id"]: a["type"] for a in proc["areas"]}
        assert areas == {AREA_0: "normal", AREA_10: "stub"}

    def test_parse_redistribute_carries_route_map_from_the_config_extract(self):
        proc = iosxr.parse(OSPF_RAW)["ospf"]["processes"][0]
        assert proc["redistribute"] == [{"protocol": "static", "route_map": "PL_REDIST"}]

    def test_parse_interfaces_carry_area_cost_network_type_and_passive(self):
        by_name = {i["name"]: i for i in iosxr.parse(OSPF_RAW)["ospf"]["interfaces"]}
        backbone = by_name["GigabitEthernet0/0/0/0"]
        assert (backbone["area"], backbone["cost"], backbone["network_type"], backbone["passive"]) == (
            AREA_0,
            1,
            "broadcast",
            False,
        )
        stub_if = by_name["GigabitEthernet0/0/0/2"]
        assert (stub_if["area"], stub_if["cost"], stub_if["passive"]) == (AREA_10, 10, True)

    def test_parse_adjacency_from_the_neighbor_template(self):
        adjacencies = iosxr.parse(OSPF_RAW)["ospf"]["adjacencies"]
        assert len(adjacencies) == 1
        adj = adjacencies[0]
        assert adj["local_interface"] == "GigabitEthernet0/0/0/0"
        assert adj["neighbor_router_id"] == "10.0.0.2"
        assert adj["neighbor_ip"] == "10.0.0.2"
        assert adj["state"] == "FULL/BDR"
        # the area comes from the interface table, not the neighbor table
        assert adj["area"] == AREA_0

    def test_parse_router_lsa_through_the_fixture_first_parser_carries_its_links(self):
        """ntc-templates has no `cisco_xr` router-LSA template."""
        lsa = next(r for r in iosxr.parse(OSPF_RAW)["ospf"]["lsdb"] if r["lsa_type"] == "router")
        assert (lsa["area"], lsa["lsid"], lsa["adv_router"]) == (AREA_0, "10.0.0.1", "10.0.0.1")
        assert (lsa["age"], lsa["seq"]) == (120, 0x80000005)
        assert lsa["metric"] is None
        assert lsa["links"] == [
            {"link_type": "point-to-point", "link_id": "10.0.0.2", "link_data": "10.0.0.1", "metric": 1},
            {"link_type": "stub", "link_id": "10.0.0.0", "link_data": "255.255.255.0", "metric": 1},
        ]

    def test_parse_network_lsa_through_the_fixture_first_parser_carries_attached_routers(self):
        lsa = next(r for r in iosxr.parse(OSPF_RAW)["ospf"]["lsdb"] if r["lsa_type"] == "network")
        assert lsa["area"] == AREA_0
        assert lsa["attached_routers"] == ["10.0.0.1", "10.0.0.2"]
        assert lsa["mask"] == "255.255.255.0"

    def test_parse_summary_lsa(self):
        lsa = next(r for r in iosxr.parse(OSPF_RAW)["ospf"]["lsdb"] if r["lsa_type"] == "summary")
        assert (lsa["area"], lsa["lsid"], lsa["mask"], lsa["metric"]) == (
            AREA_10,
            "10.10.10.0",
            "255.255.255.0",
            20,
        )

    def test_parse_asbr_summary_lsa_carries_the_asbr_router_id_as_its_lsid(self):
        lsa = next(r for r in iosxr.parse(OSPF_RAW)["ospf"]["lsdb"] if r["lsa_type"] == "asbr-summary")
        assert (lsa["area"], lsa["lsid"], lsa["metric"]) == (AREA_0, "10.0.0.3", 30)
        assert lsa["mask"] is None

    def test_parse_external_lsa_belongs_to_no_area(self):
        """A type-5 AS-external LSA is flooded domain-wide."""
        lsa = next(r for r in iosxr.parse(OSPF_RAW)["ospf"]["lsdb"] if r["lsa_type"] == "external")
        assert lsa["area"] is None
        assert lsa["forwarding_address"] == "10.0.0.2"
        assert lsa["metric_type"] == 2
        assert lsa["metric"] == 100

    def test_parse_nssa_external_lsa_belongs_to_its_own_area(self):
        """A type-7 NSSA-external LSA floods only within its own (NSSA) area."""
        lsa = next(r for r in iosxr.parse(OSPF_RAW)["ospf"]["lsdb"] if r["lsa_type"] == "nssa-external")
        assert lsa["area"] == AREA_10
        assert lsa["forwarding_address"] == AREA_0
        assert lsa["metric_type"] == 2
        assert lsa["metric"] == 50

    def test_parse_absent_for_a_payload_that_predates_the_capture(self):
        """A raw file sealed without the OSPF commands has no `ospf` key."""
        older = {k: v for k, v in RAW.items() if k not in OSPF_COMMANDS}
        assert iosxr.parse_ospf(older) is None
        assert "ospf" not in iosxr.parse(older)

    def test_normalize_ospf_process_is_a_routing_process_in_its_vrf(self):
        batch = _collector().normalize(OSPF_RAW)
        proc = uid.routing_process(DEV, "default", "ospf-1")
        node = next(n for n in batch.nodes if n.uid == proc)
        assert node.label == "RoutingProcess"
        assert node.props["proto"] == "ospf"
        assert node.props["process_id"] == "1"
        assert node.props["router_id"] == "10.0.0.1"
        assert (proc, uid.vrf(DEV, "default")) in [
            (r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IN_VRF" and r.start_uid == proc
        ]

    def test_normalize_areas_and_in_area_edges_on_both_interfaces(self):
        batch = _collector().normalize(OSPF_RAW)
        proc = uid.routing_process(DEV, "default", "ospf-1")
        area0 = uid.ospf_area(proc, AREA_0)
        area10 = uid.ospf_area(proc, AREA_10)
        area_nodes = {n.uid: n for n in batch.nodes if n.label == "OspfArea"}
        assert area_nodes[area0].props["type"] == "normal"
        assert area_nodes[area10].props["type"] == "stub"
        in_area = {(r.start_uid, r.end_uid): r for r in batch.rels if r.rel_type == "IN_AREA"}
        gi0 = uid.interface(DEV, "GigabitEthernet0/0/0/0")
        gi2 = uid.interface(DEV, "GigabitEthernet0/0/0/2")
        assert (gi0, area0) in in_area and (gi2, area10) in in_area
        assert in_area[(gi0, area0)].props == {"cost": 1, "network_type": "broadcast", "passive": False}
        assert in_area[(gi2, area10)].props == {"cost": 10, "network_type": "broadcast", "passive": True}

    def test_normalize_adjacency_endpoints_its_local_interface(self):
        batch = _collector().normalize(OSPF_RAW)
        proc = uid.routing_process(DEV, "default", "ospf-1")
        iu = uid.interface(DEV, "GigabitEthernet0/0/0/0")
        adju = uid.ospf_adjacency(proc, iu, "10.0.0.2")
        adj = next(n for n in batch.nodes if n.uid == adju)
        assert adj.props["state"] == "FULL/BDR"
        assert adj.props["neighbor_ip"] == "10.0.0.2"
        assert any(r.rel_type == "ENDPOINT" and r.start_uid == adju and r.end_uid == iu for r in batch.rels)
        assert any(r.rel_type == "HAS" and r.start_uid == proc and r.end_uid == adju for r in batch.rels)

    def test_normalize_redistribute_resolves_to_the_shared_bgp_route_policy(self):
        """Both redistributions resolve to the one RoutePolicy node the BGP capture defines."""
        batch = _collector().normalize(OSPF_RAW)
        proc = uid.routing_process(DEV, "default", "ospf-1")
        pl_redist = uid.route_policy(DEV, "rpl", "PL_REDIST")
        filtered = [(r.start_uid, r.end_uid, r.key) for r in batch.rels if r.rel_type == "FILTERED_BY"]
        assert (proc, pl_redist, {"direction": "redistribute", "protocol": "static"}) in filtered

    def test_side_tables_carry_the_lsdb_rows_keyed_to_the_device_and_context(self):
        tables = _collector().side_tables(OSPF_RAW)
        assert "ospf_lsdb" in tables
        rows = tables["ospf_lsdb"]
        assert {r["lsa_type"] for r in rows} == {
            "router",
            "network",
            "summary",
            "asbr-summary",
            "external",
            "nssa-external",
        }
        assert {r["device_uid"] for r in rows} == {DEV}
        assert {r["context_uid"] for r in rows} == {uid.vrf(DEV, "default")}
        assert {r["process"] for r in rows} == {"1"}

    def test_the_lsdb_table_is_declared_so_a_run_accounts_for_it(self):
        assert "ospf_lsdb" in IosxrCollector.SIDE_TABLES

    def test_a_device_with_no_router_ospf_process_reports_the_lsdb_table_unsupported(self):
        """IOS-XR never refuses an OSPF command for lack of the feature."""
        c = _collector()
        outcome = c.table_outcomes(RAW)["ospf_lsdb"]
        assert outcome.status == "unsupported"
        assert outcome.detail
        assert c.side_tables(RAW)["ospf_lsdb"] == []

    def test_a_device_that_answered_the_ospf_commands_reports_no_unsupported_table(self):
        """A configured process with an empty database is a table that was read
        and came back empty, never an absent feature."""
        c = _collector()
        assert "ospf_lsdb" not in c.table_outcomes(OSPF_RAW)

    def test_a_failed_ospf_command_never_reads_as_unsupported(self, monkeypatch):
        """A failed command that came back empty does not read as a box with no OSPF process."""
        from hst.collectors import ssh

        def outputs(cmd):
            if cmd == CMD_OSPF:
                raise ssh.CommandFailed(f"{CMD_OSPF!r} exited 1")
            return OSPF_RAW[cmd]

        FakeSshSession(outputs).install(monkeypatch)
        c = _collector()
        raw = c.fetch()
        # Nor as a complete-empty database: the table the command would have
        # read is stated failed, naming the command.
        outcome = c.table_outcomes(raw)["ospf_lsdb"]
        assert outcome.status == "failed"
        assert CMD_OSPF in outcome.detail

    def test_a_payload_with_no_recorded_outcomes_claims_nothing_about_the_feature(self):
        assert "ospf_lsdb" not in _collector().table_outcomes(dict(OSPF_RAW))

    def test_ospf_sections_report_what_each_command_produced(self, monkeypatch):
        sections = _sections(monkeypatch, OSPF_RAW)
        assert sections["ospf"].status == "ok"
        assert sections["ospf_neighbors"].status == "ok"
        assert sections["ospf_lsdb_router"].status == "ok"
        assert sections["ospf_config"].status == "ok"


# --- BGP session and path observations: the per-neighbor capture ----------------------------


def _bgp_collector(capture="all"):
    return IosxrCollector(
        IosxrConfig(
            host=HOST,
            auth=SshPassword(username=USER, password="pw"),
            site_code="hq",
            l3dom="corp",
            capture_bgp=capture,
        ),
        None,
    )


def _session_uid(peer_ip):
    """The BgpSession uid an observed row of this peer joins the graph through."""
    return uid.bgp_session(uid.routing_process(DEV, DEFAULT_VRF, "bgp"), peer_ip, DEFAULT_VRF)


def _fetch(monkeypatch, capture="all", failures=()):
    """One fetch of the base fixture under the given capture setting; every
    command in `failures` is refused by the device with the given words."""
    from hst.collectors import ssh

    refusals = dict(failures)

    def outputs(cmd):
        if cmd in refusals:
            raise ssh.CommandFailed(refusals[cmd])
        return RAW[cmd]

    fake = FakeSshSession(outputs).install(monkeypatch)
    collector = _bgp_collector(capture)
    return collector, collector.fetch(), fake


def _directions(collector, raw):
    """(session_uid, direction) -> outcome, as the snapshot manifest carries them."""
    return manifest.bgp_direction_outcomes(collector.table_outcomes(raw))


class TestBgpObservations:
    def test_capture_all_reads_the_session_table_and_three_directions_per_peer(self, monkeypatch):
        """The per-neighbor commands are derived from the BGP running-config
        this same fetch read, so the command set is per fetch and not per
        class."""
        _c, raw, fake = _fetch(monkeypatch)
        assert fake.commands[: len(iosxr.COMMANDS)] == list(iosxr.COMMANDS)
        derived = fake.commands[len(iosxr.COMMANDS) :]
        assert derived[0] == CMD_BGP_SESSIONS
        assert derived[1:3] == [iosxr.CMD_BGP_NEIGHBORS, iosxr.CMD_BGP_VRF_NEIGHBORS]
        assert derived[3:6] == [
            iosxr.bgp_route_command("192.0.2.1", d) for d in ("received", "accepted", "advertised")
        ]
        assert len(derived) == 3 + 3 * 2  # the session and neighbor tables, then two peers
        assert CMD_BGP_SESSIONS in raw

    def test_capture_none_asks_the_device_for_nothing_beyond_the_static_commands(self, monkeypatch):
        collector, raw, fake = _fetch(monkeypatch, capture="none")
        assert fake.commands == list(iosxr.COMMANDS)
        assert CMD_BGP_SESSIONS not in raw
        outcomes = collector.table_outcomes(raw)
        assert outcomes["bgp_sessions"].status == "not-captured"
        assert outcomes["bgp_session_routes"].status == "not-captured"
        assert "capture_bgp setting is none" in outcomes["bgp_session_routes"].detail
        # every direction of every configured session is stated too
        directions = _directions(collector, raw)
        assert len(directions) == 6
        assert {o.status for o in directions.values()} == {"not-captured"}

    def test_capture_sessions_reads_state_only_and_states_the_paths_not_captured(self, monkeypatch):
        collector, raw, fake = _fetch(monkeypatch, capture="sessions")
        assert fake.commands == [
            *iosxr.COMMANDS,
            CMD_BGP_SESSIONS,
            iosxr.CMD_BGP_NEIGHBORS,
            iosxr.CMD_BGP_VRF_NEIGHBORS,
        ]
        outcomes = collector.table_outcomes(raw)
        # the session table was read, so this run states nothing about it and
        # the write's own outcome stands; only the path table was left out
        assert "bgp_sessions" not in outcomes
        assert outcomes["bgp_session_routes"].status == "not-captured"
        tables = collector.side_tables(raw)
        assert [r["peer_ip"] for r in tables["bgp_sessions"]] == ["192.0.2.1", "192.0.2.3"]
        assert tables["bgp_session_routes"] == []

    def test_parse_bgp_sessions_carries_the_device_word_for_each_state(self):
        sessions = iosxr.parse(RAW)["bgp_observed"]["sessions"]
        assert [(s["peer_ip"], s["state"], s["prefixes_received"]) for s in sessions] == [
            ("192.0.2.1", "Established", 1),
            ("192.0.2.3", "Idle", None),
        ]
        # this command reports no advertised count or capabilities
        assert all(
            s["established_since_ms"] is None
            and s["prefixes_advertised"] is None
            and s["capabilities"] is None
            for s in sessions
        )

    def test_parse_bgp_paths_carries_attributes_and_the_best_marking(self):
        routes = iosxr.parse(RAW)["bgp_observed"]["routes"]
        accepted = [r for r in routes if r["peer_ip"] == "192.0.2.1" and r["direction"] == "accepted"]
        assert len(accepted) == 1
        row = accepted[0]
        assert row["prefix"] == "10.20.0.0/24"
        assert row["next_hop"] == "192.0.2.1"
        assert (row["local_pref"], row["med"], row["origin"]) == (150, 0, "i")
        assert row["best"] is True
        assert row["path_id"] is None
        assert row["communities"] is None

    def test_a_received_direction_is_pre_decision_and_carries_no_best_marking(self):
        routes = iosxr.parse(RAW)["bgp_observed"]["routes"]
        received = [r for r in routes if r["peer_ip"] == "192.0.2.3" and r["direction"] == "received"]
        assert sorted(r["prefix"] for r in received) == ["10.20.0.0/24", "198.51.100.0/24"]
        assert all(r["best"] is None for r in received)

    def test_side_tables_join_observations_to_the_session_node_and_its_context(self):
        collector = _bgp_collector()
        tables = collector.side_tables(RAW)
        batch = collector.normalize(RAW)
        nodes = {n.uid for n in batch.nodes if n.label == "BgpSession"}
        context_uid = uid.vrf(DEV, DEFAULT_VRF)
        for table in ("bgp_sessions", "bgp_session_routes"):
            assert tables[table]
            for row in tables[table]:
                assert row["device_uid"] == DEV
                assert row["context_uid"] == context_uid
        # every observed session that is also configured joins a node of this run
        assert {r["session_uid"] for r in tables["bgp_sessions"]} <= nodes
        assert _session_uid("192.0.2.1") in nodes

    def test_observed_path_rows_carry_the_interval_columns_and_the_stage(self):
        rows = _bgp_collector().side_tables(RAW)["bgp_session_routes"]
        row = next(r for r in rows if r["direction"] == "advertised" and r["peer_ip"] == "192.0.2.1")
        assert (row["rib_type"], row["policy_stage"], row["safi"]) == (
            "adj-rib-out",
            "post-export",
            "unicast",
        )
        assert (row["af"], row["prefixlen"]) == (4, 24)
        assert row["lo"] and row["hi"]
        assert row["next_hop_context_uid"] is None
        received = next(r for r in rows if r["direction"] == "received")
        assert (received["rib_type"], received["policy_stage"]) == ("adj-rib-in", "pre-import")
        accepted = next(r for r in rows if r["direction"] == "accepted")
        assert (accepted["rib_type"], accepted["policy_stage"]) == ("loc-rib", "post-import")

    def test_a_received_direction_without_soft_reconfiguration_reports_not_captured(self, monkeypatch):
        """The box does not retain the pre-policy table and says so with a zero
        exit status. The direction is `not-captured`."""
        collector, raw, _fake = _fetch(monkeypatch)
        directions = _directions(collector, raw)
        outcome = directions[(_session_uid("192.0.2.1"), "received")]
        assert outcome.status == "not-captured"
        assert "soft reconfiguration" in outcome.detail
        assert outcome.row_count is None
        # the same session's other two directions were captured
        assert directions[(_session_uid("192.0.2.1"), "accepted")].status == "complete"
        assert directions[(_session_uid("192.0.2.1"), "advertised")].status == "complete"

    def test_a_direction_the_box_answered_with_nothing_is_empty_not_uncaptured(self, monkeypatch):
        collector, raw, _fake = _fetch(monkeypatch)
        down = _directions(collector, raw)[(_session_uid("192.0.2.3"), "accepted")]
        assert (down.status, down.row_count) == ("complete-empty", 0)

    def test_a_box_without_bgp_reads_unsupported_not_failed(self, monkeypatch):
        """`classify_command_failure` reads the device's own rejection banner."""
        command = iosxr.bgp_route_command("192.0.2.1", "accepted")
        collector, raw, _fake = _fetch(
            monkeypatch, failures={command: f"{command!r} rejected by device: % Invalid input detected"}
        )
        outcome = _directions(collector, raw)[(_session_uid("192.0.2.1"), "accepted")]
        assert outcome.status == "not-captured"
        assert "Invalid input" in outcome.detail

    def test_a_box_without_bgp_states_the_session_table_not_captured(self, monkeypatch):
        """The session table has no per-direction statement."""
        collector, raw, _fake = _fetch(
            monkeypatch,
            failures={CMD_BGP_SESSIONS: f"{CMD_BGP_SESSIONS!r} rejected by device: % Invalid input detected"},
        )
        outcomes = collector.table_outcomes(raw)
        assert outcomes["bgp_sessions"].status == "not-captured"
        assert "Invalid input" in outcomes["bgp_sessions"].detail
        assert collector.side_tables(raw)["bgp_sessions"] == []

    def test_a_session_table_the_box_answered_leaves_the_write_outcome_alone(self, monkeypatch):
        collector, raw, _fake = _fetch(monkeypatch)
        assert "bgp_sessions" not in collector.table_outcomes(raw)

    def test_a_direction_refused_for_a_fixable_reason_reads_failed(self, monkeypatch):
        command = iosxr.bgp_route_command("192.0.2.1", "advertised")
        collector, raw, _fake = _fetch(
            monkeypatch, failures={command: f"{command!r} exited 1: Permission denied"}
        )
        assert _directions(collector, raw)[(_session_uid("192.0.2.1"), "advertised")].status == "failed"

    def test_the_session_table_is_volatile_so_its_timers_never_defeat_the_skip(self):
        assert CMD_BGP_SESSIONS in IosxrCollector.VOLATILE_RAW_KEYS

    def test_a_listen_range_neighbor_is_not_a_capture_target(self):
        """A neighbor address that does not parse as a single IP names no
        single address to query."""
        bgp = {"neighbors": [{"addr": "10.1.0.0/16"}, {"addr": "10.1.1.2"}]}
        assert iosxr.bgp_capture_targets(bgp) == ["10.1.1.2"]

    def test_coverage_report_every_session_direction_is_captured_or_not_captured_with_a_reason(
        self, monkeypatch
    ):
        """Every (session, direction) pair ends as `complete`, `complete-empty`,
        `failed` or `not-captured`."""
        collector, raw, _fake = _fetch(monkeypatch)
        directions = _directions(collector, raw)
        assert len(directions) == 6
        for (_session, _direction), outcome in directions.items():
            assert outcome.status in ("complete", "complete-empty", "failed", "not-captured")
            if outcome.status == "not-captured":
                assert outcome.detail


# --- first-hop redundancy (HSRP) -----------------------------------------------------
#
# `show hsrp` in the column form the ntc-templates `cisco_xr_show_hsrp` template
# parses. The interface column is abbreviated the way the box prints it.

HSRP_TEXT = """\
IPv4 Groups:
   P indicates configured to preempt.
   |
Interface            Grp  Pri P State   Active addr     Standby addr    Group addr
Gi0/0/0/0            1    110 P Active  local           10.0.0.3        10.0.0.254
Gi0/0/0/2            2    90    Standby 10.0.2.2        local           10.0.2.254
"""

FHRP_RAW = {**RAW, CMD_HSRP: HSRP_TEXT}


def _fhrp_rels(batch, rel_type, start, end):
    return [r for r in batch.rels if r.rel_type == rel_type and r.start_uid == start and r.end_uid == end]


def test_hsrp_command_is_optional_and_joins_the_command_set():
    assert CMD_HSRP in iosxr.COMMANDS
    assert IosxrCollector.OPTIONAL_COMMANDS[CMD_HSRP] == ""
    assert iosxr.SECTIONS["hsrp"].command == CMD_HSRP


def test_parse_show_hsrp_into_fhrp_rows_with_the_printed_interface_names():
    inter = iosxr.parse(FHRP_RAW)
    assert inter["fhrp"] == [
        {
            # as `show hsrp` prints it; the stage resolves it against the interface table
            "interface": "Gi0/0/0/0",
            "kind": "hsrp",
            "group": 1,
            "vip": "10.0.0.254",
            "priority": 110,
            "state": "Active",
            "virtual_mac": None,
        },
        {
            "interface": "Gi0/0/0/2",
            "kind": "hsrp",
            "group": 2,
            "vip": "10.0.2.254",
            "priority": 90,
            "state": "Standby",
            "virtual_mac": None,
        },
    ]
    assert iosxr.parse(RAW)["fhrp"] == []
    old = {k: v for k, v in RAW.items() if k != CMD_HSRP}
    assert iosxr.parse(old)["fhrp"] == []


def test_normalize_hsrp_virtual_address_joins_the_member_prefix():
    batch = _collector().normalize(FHRP_RAW)
    iu = uid.interface(DEV, "GigabitEthernet0/0/0/0")
    vru = uid.vrf(DEV, DEFAULT_VRF)
    vip = uid.ip(vru, "10.0.0.254")
    (edge,) = _fhrp_rels(batch, "HAS_IP", iu, vip)
    assert edge.props == {"fhrp": "hsrp", "group": 1, "state": "active"}
    prefixes = [n for n in batch.nodes if n.label == "Prefix" and n.props.get("cidr") == "10.0.0.0/24"]
    assert [n.uid for n in prefixes] == [uid.prefix(vru, "10.0.0.0/24")]
    assert _fhrp_rels(batch, "IN", vip, prefixes[0].uid)


def test_normalize_emits_one_fhrp_group_per_virtual_address_with_member_priority():
    batch = _collector().normalize(FHRP_RAW)
    groups = {n.props["vip"]: n for n in batch.nodes if n.label == "FhrpGroup"}
    assert set(groups) == {"10.0.0.254", "10.0.2.254"}
    assert {g.props["kind"] for g in groups.values()} == {"hsrp"}
    gi0 = uid.interface(DEV, "GigabitEthernet0/0/0/0")
    (active,) = _fhrp_rels(batch, "MEMBER_OF", gi0, groups["10.0.0.254"].uid)
    assert active.props == {"priority": 110, "state": "active"}
    gi2 = uid.interface(DEV, "GigabitEthernet0/0/0/2")
    (standby,) = _fhrp_rels(batch, "MEMBER_OF", gi2, groups["10.0.2.254"].uid)
    assert standby.props == {"priority": 90, "state": "standby"}
    vru = uid.vrf(DEV, DEFAULT_VRF)
    for vip, group in groups.items():
        assert _fhrp_rels(batch, "HAS_IP", group.uid, uid.ip(vru, vip))


def test_the_base_fixture_emits_no_fhrp_group():
    batch = _collector().normalize(RAW)
    assert not [n for n in batch.nodes if n.label == "FhrpGroup"]


def test_a_box_that_rejects_show_hsrp_records_the_section_unsupported(monkeypatch):
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd == CMD_HSRP:
            raise ssh.CommandFailed(f"{cmd!r} exited 1: % Invalid input detected at '^' marker.")
        return FHRP_RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    batch = c.normalize(c.fetch())
    assert batch.sections["hsrp"].status == "unsupported"
    assert not [n for n in batch.nodes if n.label == "FhrpGroup"]
    assert batch.sections["interfaces"].status == "ok"


def test_hsrp_section_reads_empty_on_the_base_fixture_and_ok_with_groups(monkeypatch):
    assert _sections(monkeypatch, RAW)["hsrp"].status == "empty"
    full = _sections(monkeypatch, FHRP_RAW)
    assert full["hsrp"].status == "ok" and full["hsrp"].detail == ""


def test_normalize_aggregate_route_policy_is_the_attribute_policy_on_the_edge():
    """`aggregate-address ... route-policy NAME` is the aggregate's attribute
    policy: raw on the ORIGINATES edge, and a
    FILTERED_BY {redistribute, aggregate} edge when NAME resolves."""
    raw = dict(
        RAW,
        **{
            CMD_BGP: BGP_TEXT.replace(
                " redistribute connected route-policy PL_REDIST\n",
                " aggregate-address 10.0.0.0/8 summary-only route-policy PL_REDIST\n"
                " aggregate-address 10.1.0.0/16 route-policy PL_MISSING\n"
                " redistribute connected route-policy PL_REDIST\n",
            )
        },
    )
    batch = _collector().normalize(raw)
    rp_uid = uid.routing_process(DEV, DEFAULT_VRF, "bgp")
    vru = uid.vrf(DEV, DEFAULT_VRF)
    originates = {r.end_uid: r.props for r in batch.rels if r.rel_type == "ORIGINATES" and r.start_uid == vru}
    assert originates[uid.prefix(vru, "10.0.0.0/8")] == {
        "proto": "aggregate",
        "summary_only": True,
        "as_set": False,
        "attribute_map": "PL_REDIST",
        "unsupported_options": [],
    }
    assert originates[uid.prefix(vru, "10.1.0.0/16")]["attribute_map"] == "PL_MISSING"
    aggregate_filters = {
        r.end_uid
        for r in batch.rels
        if r.rel_type == "FILTERED_BY" and r.start_uid == rp_uid and r.key.get("protocol") == "aggregate"
    }
    assert aggregate_filters == {uid.route_policy(DEV, "rpl", "PL_REDIST")}


# --- RPL guard expressions, if/else chains, nesting, community and AS-path sets ----------

_BOGON_PREFIX_SET = "prefix-set BOGONS\n  10.0.0.0/8 le 32,\n  192.168.0.0/16 le 32\nend-set\n"
_BOGON_POLICY = (
    "route-policy EDGE-IN\n if not destination in BOGONS then\n  pass\n else\n  drop\n endif\nend-policy\n"
)


def _xr_policies(inter):
    return [
        *inter["xr_route_policies"],
        *inter["xr_prefix_lists"],
        *inter.get("xr_community_lists", []),
        *inter.get("xr_as_path_lists", []),
    ]


def _xr_evaluate(inter, name, route):
    from hst.simul import platforms
    from hst.simul import policy as policymod
    from hst.simul.compile import compile_policies
    from hst.simul.errors import ErrorSink

    errors = ErrorSink()
    compiled, lists = compile_policies(_xr_policies(inter), platforms.IOSXR, errors)
    env = policymod.Environment(
        original_route=route, output_route=route, policies=compiled, prefix_lists=lists, errors=errors
    )
    return policymod.process(compiled[name], env), env.output_route, errors.as_dicts()


def test_a_parsed_not_guard_drops_only_bogons_in_simulation():
    """The `else` drop applies only when the guard does not match, so a
    route outside BOGONS is accepted through the `pass`."""
    from hst.simul.route import Route

    inter = iosxr_bgp.parse(None, _BOGON_PREFIX_SET, _BOGON_POLICY)
    accepted, _route, errors = _xr_evaluate(inter, "EDGE-IN", Route(prefix="8.8.8.0/24"))
    assert accepted is True
    assert errors == []
    accepted, _route, _errors = _xr_evaluate(inter, "EDGE-IN", Route(prefix="10.1.0.0/16"))
    assert accepted is False


def test_a_nested_if_is_parsed_into_its_branch():
    text = (
        "route-policy RP\n"
        " if destination in A then\n"
        "  set local-preference 200\n"
        "  if med ge 50 then\n   set weight 7\n  endif\n"
        "  done\n"
        " elseif destination in B then\n  drop\n"
        " endif\n"
        "end-policy\n"
    )
    (rp,) = iosxr_bgp.parse_route_policies(text)
    entries = {e["seq"]: e for e in rp["entries"]}
    assert entries[1]["match_prefix_lists"] == ["A"]
    assert entries[1]["continue_seq"] == 5
    assert "set_local_pref" not in entries[1]
    assert entries[2] == {"seq": 2, "kind": "statement", "set_local_pref": 200, "parent_seq": 1}
    assert json.loads(entries[3]["match_expr"]) == {"compare": "med", "op": "ge", "value": 50}
    assert entries[3]["set_weight"] == 7 and entries[3]["parent_seq"] == 1
    assert entries[4] == {"seq": 4, "kind": "statement", "action": "permit", "parent_seq": 1}
    assert entries[5]["match_prefix_lists"] == ["B"] and entries[5]["action"] == "deny"
    assert "parent_seq" not in entries[5]


def test_a_set_name_with_a_keyword_inside_is_not_an_operator():
    """`PL-not-used` holds `not` between hyphens; it is a name, not a `not`."""
    (rp,) = iosxr_bgp.parse_route_policies(
        "route-policy RP\n if destination in PL-not-used then\n  done\n endif\nend-policy\n"
    )
    (entry,) = rp["entries"]
    assert entry["match_prefix_lists"] == ["PL-not-used"]
    assert "match_expr" not in entry and "match_unsupported" not in entry


def test_the_same_kind_twice_is_anded_not_ored():
    """The flat fields OR the names of one kind; RPL ANDs two `destination in`
    terms, so that guard is stored as an expression."""
    (rp,) = iosxr_bgp.parse_route_policies(
        "route-policy RP\n if destination in A and destination in B then\n  done\n endif\nend-policy\n"
    )
    (entry,) = rp["entries"]
    assert json.loads(entry["match_expr"]) == {"and": [{"prefix_list": "A"}, {"prefix_list": "B"}]}
    assert entry["match_prefix_lists"] == ["A", "B"]


def test_community_and_as_path_sets_are_parsed_and_evaluated():
    from hst.simul.route import Route

    community_sets = "community-set CS\n  65000:*,\n  ios-regex '^65001:1..$',\n  dfa-regex '1'\nend-set\n"
    as_path_sets = "as-path-set AP\n  neighbor-is '3356',\n  length ge 4\nend-set\n"
    policy = (
        "route-policy RP\n"
        " if community matches-any CS and not as-path in AP then\n"
        "  set local-preference 300\n  done\n endif\n"
        " drop\n"
        "end-policy\n"
    )
    inter = iosxr_bgp.parse(None, "", policy, community_sets, as_path_sets)
    (cs,) = inter["xr_community_lists"]
    assert cs["kind"] == "community-list"
    assert [(e["match_type"], e["value"]) for e in cs["entries"]] == [
        ("wildcard", "65000:*"),
        ("ios-regex", "^65001:1..$"),
        ("unsupported", "dfa-regex '1'"),
    ]
    (ap,) = inter["xr_as_path_lists"]
    assert [(e["action"], e["match_type"], e["value"]) for e in ap["entries"]] == [
        ("permit", "neighbor-is", "3356"),
        ("permit", "length", "ge 4"),
    ]
    accepted, route, errors = _xr_evaluate(
        inter, "RP", Route(prefix="8.8.8.0/24", communities=frozenset({"65000:9"}), as_path=(174, 1))
    )
    assert accepted is True and route.local_pref == 300
    assert [e["kind"] for e in errors] == ["unsupported-list-entry"]
    accepted, _route, _errors = _xr_evaluate(
        inter, "RP", Route(prefix="8.8.8.0/24", communities=frozenset({"65000:9"}), as_path=(3356, 1))
    )
    assert accepted is False


def test_statement_lines_without_a_field_are_kept_and_set_community_resolves_its_set():
    community_sets = "community-set TAGS\n  65000:10,\n  65000:20\nend-set\n"
    policy = (
        "route-policy RP\n"
        " # tag the route\n"
        " set community TAGS additive\n"
        " set community (65000:30, 65000:*)\n"
        " set next-hop self\n"
        " unsuppress-route\n"
        " delete community in TAGS\n"
        " done\n"
        " set local-preference 999\n"
        "end-policy\n"
    )
    (rp,) = iosxr_bgp.parse_route_policies(policy, iosxr_bgp.parse_community_sets(community_sets))
    (entry,) = rp["entries"]
    assert entry["set_communities"] == ["65000:10", "65000:20"]
    assert entry["set_communities_additive"] is True
    assert entry["set_unsupported"] == [
        "set community (65000:30, 65000:*)",
        "set next-hop self",
        "unsuppress-route",
    ]
    assert entry["set_comm_list_delete"] == "TAGS"
    assert entry["passes"] is True
    assert entry["action"] == "permit"
    assert "set_local_pref" not in entry  # after `done`, nothing in the run runs


def test_a_set_line_after_an_apply_runs_after_it():
    (rp,) = iosxr_bgp.parse_route_policies(
        "route-policy RP\n set med 10\n apply SUB\n set local-preference 200\n done\nend-policy\n"
    )
    entries = {e["seq"]: e for e in rp["entries"]}
    assert entries[1]["set_metric"] == 10 and entries[1]["calls_policy"] == "SUB"
    assert entries[2]["set_local_pref"] == 200 and entries[2]["action"] == "permit"


def test_the_sets_are_read_only_when_a_policy_names_one(monkeypatch):
    from hst.collectors.iosxr import CMD_AS_PATH_SET, CMD_COMMUNITY_SET

    assert iosxr_bgp.names_a_set(ROUTE_POLICY_TEXT) is False
    policy = (
        ROUTE_POLICY_TEXT
        + "route-policy RP_CS\n if community matches-any CS then\n  done\n endif\nend-policy\n"
    )
    assert iosxr_bgp.names_a_set(policy) is True
    answers = {
        **RAW,
        CMD_ROUTE_POLICY: policy,
        CMD_COMMUNITY_SET: "community-set CS\n  65000:1\nend-set\n",
        CMD_AS_PATH_SET: "",
    }
    fake = FakeSshSession(lambda cmd: answers.get(cmd, "")).install(monkeypatch)
    collector = _bgp_collector("none")
    raw = collector.fetch()
    assert fake.commands[-2:] == [CMD_COMMUNITY_SET, CMD_AS_PATH_SET]
    batch = collector.normalize(raw)
    cs = uid.route_policy(DEV, "community-list", "CS")
    line = next(n for n in batch.nodes if n.uid == uid.match_list_entry(cs, 1))
    assert line.label == "MatchListEntry"
    assert (line.props["action"], line.props["match_type"], line.props["value"]) == (
        "permit",
        "standard",
        "65000:1",
    )
    entry = uid.route_policy_entry(uid.route_policy(DEV, "rpl", "RP_CS"), 1)
    assert any(
        r.rel_type == "REFERENCES"
        and r.start_uid == entry
        and r.end_uid == cs
        and r.key.get("kind") == "community-list"
        for r in batch.rels
    )

    plain = FakeSshSession(lambda cmd: RAW.get(cmd, "")).install(monkeypatch)
    _bgp_collector("none").fetch()
    assert CMD_COMMUNITY_SET not in plain.commands and CMD_AS_PATH_SET not in plain.commands


# --- origins under the process address family; route-reflector-client -----------------

_AF_BGP_TEXT = """\
router bgp 65000
 bgp router-id 10.255.0.1
 address-family ipv4 unicast
  network 10.10.0.0/16
  aggregate-address 10.0.0.0/8 summary-only
  redistribute connected
  redistribute isis CORE route-policy PL_REDIST
 !
 address-family ipv6 unicast
  network 2001:db8::/32
 !
 af-group AF-RR address-family ipv4 unicast
  route-reflector-client
 !
 neighbor-group NG-RR
  remote-as 65000
  address-family ipv4 unicast
   use af-group AF-RR
  !
 !
 neighbor 10.0.0.2
  use neighbor-group NG-RR
 !
 neighbor 10.0.0.3
  remote-as 65000
  address-family ipv4 unicast
   route-reflector-client
  !
 !
 neighbor 10.0.0.4
  use neighbor-group NG-RR
  address-family ipv4 unicast
   route-reflector-client inheritance-disable
  !
 !
 neighbor 10.0.0.5
  remote-as 65000
  address-family ipv4 unicast
  !
  address-family ipv6 unicast
   route-reflector-client
  !
 !
 neighbor 10.0.0.6
  remote-as 65000
  use neighbor-group NG-MISSING
 !
 vrf CUST
  rd auto
  address-family ipv4 unicast
   network 172.16.0.0/16
   redistribute static
  !
 !
!
"""


def test_origins_under_the_process_address_family_are_read_in_every_vrf():
    """IOS-XR takes network, aggregate-address and redistribute only in the
    process's address-family block."""
    processes = {p["vrf"]: p for p in iosxr_bgp.parse_bgp(_AF_BGP_TEXT)["processes"]}
    default, cust = processes[""], processes["CUST"]
    assert [n["prefix"] for n in default["networks"]] == ["10.10.0.0/16"]
    assert [a["prefix"] for a in default["aggregates"]] == ["10.0.0.0/8"]
    # every protocol is kept, the ones the engine has no routes for included
    assert default["redistribute"] == [
        {"protocol": "connected", "policy_name": None},
        {"protocol": "isis", "policy_name": "PL_REDIST"},
    ]
    # the IPv6 origin is a named gap, not silence
    assert default["origin_context_gaps"] == [
        "address-family ipv6 unicast 'network 2001:db8::/32' is not recorded"
    ]
    assert [n["prefix"] for n in cust["networks"]] == ["172.16.0.0/16"]
    assert cust["redistribute"] == [{"protocol": "static", "policy_name": None}]


def test_origins_under_the_address_family_become_originates_edges():
    batch = _collector().normalize(dict(RAW, **{CMD_BGP: _AF_BGP_TEXT}))
    vru, cust = uid.vrf(DEV, DEFAULT_VRF), uid.vrf(DEV, "CUST")
    originates = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ORIGINATES"}
    assert (vru, uid.prefix(vru, "10.10.0.0/16")) in originates
    assert (vru, uid.prefix(vru, "10.0.0.0/8")) in originates
    assert (cust, uid.prefix(cust, "172.16.0.0/16")) in originates
    procs = {n.uid: n.props for n in batch.nodes if n.label == "RoutingProcess"}
    assert procs[uid.routing_process(DEV, DEFAULT_VRF, "bgp")]["redistribute_protocols"] == [
        "connected",
        "isis",
    ]
    assert procs[uid.routing_process(DEV, "CUST", "bgp")]["redistribute_protocols"] == ["static"]


def test_route_reflector_client_is_stated_on_every_session():
    """True when the neighbor or a group it uses states it, false when
    none does (an IPv6-only setting and `inheritance-disable` included), and
    absent when a group the neighbor uses is undefined."""
    batch = _collector().normalize(dict(RAW, **{CMD_BGP: _AF_BGP_TEXT}))
    rp = uid.routing_process(DEV, DEFAULT_VRF, "bgp")
    sessions = {
        n.props["peer_ip"]: n.props
        for n in batch.nodes
        if n.label == "BgpSession" and n.uid == uid.bgp_session(rp, n.props["peer_ip"], DEFAULT_VRF)
    }
    assert sessions["10.0.0.2"]["route_reflector_client"] is True
    assert sessions["10.0.0.3"]["route_reflector_client"] is True
    assert sessions["10.0.0.4"]["route_reflector_client"] is False
    assert sessions["10.0.0.5"]["route_reflector_client"] is False
    assert "route_reflector_client" not in sessions["10.0.0.6"]


# --- a leaked route's next-hop VRF, Null0 and connected rows --------------------------

_LEAK_ROUTE_TEXT = """\
Codes: C - connected, S - static, R - RIP, B - BGP, (>) - Diversion path

VRF: CUST

B    0.0.0.0/0 [200/0] via 10.0.0.1 (nexthop in vrf default), 00:01:02
B    10.20.0.0/24 [200/0] via 192.0.2.1 (nexthop in vrf SHARED), 00:01:02
                  [200/0] via 192.0.2.2 (nexthop in vrf SHARED), 00:01:02
S    10.128.0.0/9 is directly connected, 1d02h, Null0
C    10.30.0.0/24 is directly connected, 1d02h, GigabitEthernet0/0/0/0
"""


def test_a_leaked_routes_next_hop_vrf_and_a_null0_route_reach_the_side_rows():
    """`(nexthop in vrf X)` names the table the next hop resolves in,
    on the route line and on a further path, never an interface. A
    Null0 route is a discard route, and an interface route has no next hop
    (the template's word `connected` is not one)."""
    raw = dict(RAW, **{CMD_ROUTE: _LEAK_ROUTE_TEXT})
    rows = {(r["prefix"], r["next_hop"]): r for r in _collector().side_tables(raw)["rib"]}
    default, shared = uid.vrf(DEV, DEFAULT_VRF), uid.vrf(DEV, "SHARED")
    leak = rows[("0.0.0.0/0", "10.0.0.1")]
    assert (leak["next_hop_context_uid"], leak["interface"], leak["discard"]) == (default, None, None)
    assert rows[("10.20.0.0/24", "192.0.2.1")]["next_hop_context_uid"] == shared
    assert rows[("10.20.0.0/24", "192.0.2.2")]["next_hop_context_uid"] == shared
    null = rows[("10.128.0.0/9", None)]
    assert (null["discard"], null["interface"], null["next_hop_context_uid"]) == ("blackhole", "Null0", None)
    connected = rows[("10.30.0.0/24", None)]
    assert (connected["discard"], connected["interface"]) == (None, "GigabitEthernet0/0/0/0")


# --- the cluster id; a neighbor written as no session ------------------------------------

_CLUSTER_BGP_TEXT = """\
router bgp 65000
 bgp router-id 10.255.0.1
 bgp cluster-id 10.255.255.255
 neighbor-group NG-RR
  remote-as 65000
  cluster-id 10.9.9.9
 !
 neighbor 10.0.0.2
  remote-as 65000
 !
 neighbor 10.0.0.3
  use neighbor-group NG-RR
 !
 neighbor 10.0.0.4
  use neighbor-group NG-MISSING
 !
 vrf CUST
  neighbor 192.0.2.2
   remote-as 65099
  !
 !
!
"""


def test_every_session_carries_the_cluster_id_and_a_neighbor_its_own():
    """`bgp cluster-id` is the process's, its VRFs' included; a neighbor's own
    `cluster-id`, here from its neighbor-group, takes its place."""
    batch = _collector().normalize(dict(RAW, **{CMD_BGP: _CLUSTER_BGP_TEXT}))
    sessions = {n.props["peer_ip"]: n.props for n in batch.nodes if n.label == "BgpSession"}
    assert sessions["10.0.0.2"]["cluster_id"] == "10.255.255.255"
    assert sessions["10.0.0.3"]["cluster_id"] == "10.9.9.9"
    assert sessions["192.0.2.2"]["cluster_id"] == "10.255.255.255"


def test_a_neighbor_written_as_no_session_is_recorded_on_its_process():
    """The neighbor whose neighbor-group is not in the capture has no
    remote-as and writes no session; its process names it, so the simulation
    does not read it as absent."""
    batch = _collector().normalize(dict(RAW, **{CMD_BGP: _CLUSTER_BGP_TEXT}))
    process = next(n for n in batch.nodes if n.uid == uid.routing_process(DEV, DEFAULT_VRF, "bgp"))
    assert process.props["session_gaps"] == [
        "neighbor 10.0.0.4 has no resolvable remote-as (undefined neighbor-group NG-MISSING)"
    ]
