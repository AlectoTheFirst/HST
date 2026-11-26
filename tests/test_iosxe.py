"""ntc-templates is a base dependency, so no test here skips."""

from tests.conftest import FakeSshSession

from hst import reasoner
from hst.collectors import iosxe
from hst.collectors.auth import SshPassword
from hst.collectors.iosxe import (
    CMD_ACL,
    CMD_ARP,
    CMD_BGP,
    CMD_BGP_SESSIONS,
    CMD_CDP,
    CMD_INTERFACE_CONFIG,
    CMD_INTERFACES,
    CMD_LLDP,
    CMD_NAT,
    CMD_NAT_STATS,
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
    CMD_PREFIX_LIST,
    CMD_ROUTE,
    CMD_ROUTE_MAP,
    CMD_STANDBY,
    CMD_VERSION,
    CMD_VRF,
    CMD_VRF_DETAIL,
    CMD_VRRP,
    OSPF_COMMANDS,
    IosxeCollector,
    IosxeConfig,
)
from hst.core import manifest, uid
from hst.simul import prefixlist

HOST, USER = "sw1x", "ro"
SERIAL = "FCW2140L0GH"
# minted by the in-memory registry from the hostname in RAW's show version
DEV = "dev:sw1"
# routed addressing (connected/NAT) anchors on the owning VrfInstance uid; every NAT
# rule fixture below carries no `vrf` clause, so it's the device's default table
DEFAULT_VRF_UID = uid.vrf(DEV, "default")

VERSION_TEXT = """\
Cisco IOS XE Software, Version 17.03.04a
Cisco IOS Software [Amsterdam], IOSXE Software (C9K), Version 17.3.4a, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2021 by Cisco Systems, Inc.
Compiled Thu 25-Feb-21 21:32 by mcpre

sw1 uptime is 2 weeks, 3 days, 4 hours, 5 minutes
System image file is "flash:packages.conf"

cisco C9300-24T (X86) processor with 1621276K/6147K bytes of memory.
Processor board ID FCW2140L0GH
Configuration register is 0x102
"""

# Three interfaces w/ ips: a phys interface (default vrf), an SVI (mgmt vrf, stamped
# below via the "show vrf" fixture's interfaces list) and a second phys interface
# (default vrf) the OSPF fixture below puts in a stub area.
INTERFACES_TEXT = """\
GigabitEthernet1/0/1 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is aabb.ccdd.ee01 (bia aabb.ccdd.ee01)
  Internet address is 10.0.0.1/24
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input 00:00:01, output 00:00:02, output hang never
  Last clearing of "show interface" counters never
     1000 packets input, 100000 bytes, 0 no buffer
     1000 packets output, 100000 bytes, 0 underruns
Vlan10 is up, line protocol is up
  Hardware is EtherSVI, address is aabb.ccdd.ee10 (bia aabb.ccdd.ee10)
  Internet address is 10.10.10.1/24
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input never, output never, output hang never
  Last clearing of "show interface" counters never
     0 packets input, 0 bytes, 0 no buffer
     0 packets output, 0 bytes, 0 underruns
GigabitEthernet1/0/3 is up, line protocol is up
  Hardware is Gigabit Ethernet, address is aabb.ccdd.ee03 (bia aabb.ccdd.ee03)
  Internet address is 10.0.3.1/24
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input never, output never, output hang never
  Last clearing of "show interface" counters never
     0 packets input, 0 bytes, 0 no buffer
     0 packets output, 0 bytes, 0 underruns
GigabitEthernet1/0/9 is up, line protocol is up
  Hardware is Gigabit Ethernet, address is aabb.ccdd.ee09 (bia aabb.ccdd.ee09)
  Internet address is 10.0.9.1/24
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Auto-duplex, Auto-speed, media type is 10/100/1000BaseTX
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input never, output never, output hang never
  Last clearing of "show interface" counters never
     0 packets input, 0 bytes, 0 no buffer
     0 packets output, 0 bytes, 0 underruns
"""

# 1 lldp neighbor off Gi1/0/1
LLDP_TEXT = """\
------------------------------------------------
Local Intf: Gi1/0/1
Chassis id: aabb.ccdd.ef01
Port id: Gi2/0/1
Port Description: Gi2/0/1
System Name: core1

Time remaining: 100 seconds
System Capabilities: B,R
Enabled Capabilities: B,R
Management Addresses:
    IP: 10.0.0.254


Total entries displayed: 1
"""

# 1 cdp neighbor, same local port; CDP carries no peer MAC
CDP_TEXT = """\
-------------------------
Device ID: core1.example.com
Entry address(es):
  IP address: 10.0.0.254
Platform: cisco WS-C3850-24,  Capabilities: Router Switch IGMP
Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet2/0/1
Holdtime : 150 sec

Version :
Cisco IOS Software, C3850 Software

advertisement version: 2
Duplex: full

Total cdp entries displayed : 1
"""

# non-default vrf "mgmt" claims Vlan10 (an interface with an IP, for IN_VRF) and
# GigabitEthernet1/0/2 (no IP, only read via ARP).
# `show vrf` prints its members abbreviated, as the device does, where `show
# interfaces` and `show ip arp` spell them in full.
VRF_TEXT = """\
  Name                             Default RD            Protocols   Interfaces
  mgmt                             <not set>             ipv4        Vl10
                                                                       Gi1/0/2
"""

# The golden payloads (tests/support/synthetic_payloads.py `fixture_raw`) spell the members in full.
FULL_NAME_VRF_TEXT = """\
  Name                             Default RD            Protocols   Interfaces
  mgmt                             <not set>             ipv4        Vlan10
                                                                       GigabitEthernet1/0/2
"""

# `show vrf detail` rows merge onto the `show vrf` rows above by VRF name.
# This template's state machine reads Rt_Export before Rt_Import.
VRF_DETAIL_TEXT = """\
VRF mgmt (VRF Id = 1); default RD 1:100; default VPNID <not set>
  Interfaces:
    Vlan10
    GigabitEthernet1/0/2
  Address family ipv4 unicast (Table ID = 1) :
  Export VPN route-target communities
    RT:65000:100
  Import VPN route-target communities
    RT:65000:200
  No import route-map
  No export route-map
"""

# 2 routes incl. one non-default vrf: a connected default-vrf route (no next-hop)
# and a static mgmt-vrf route (with one)
ROUTE_TEXT = """\
Routing Table: default
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP

Gateway of last resort is not set

      10.0.0.0/24 is subnetted, 1 subnets
C        10.0.0.0/24 is directly connected, GigabitEthernet1/0/1

Routing Table: mgmt
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP

Gateway of last resort is not set

      10.255.0.0/32 is subnetted, 1 subnets
S        10.255.0.0/32 [1/0] via 10.255.0.2, GigabitEthernet1/0/2
"""

# 2 arp entries: one off the default-vrf phys interface, one off the mgmt-vrf member
ARP_TEXT = """\
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.0.0.5                 5   aabb.ccdd.efaa  ARPA   GigabitEthernet1/0/1
Internet  10.255.0.2               -   aabb.ccdd.efbb  ARPA   GigabitEthernet1/0/2
"""

# `show running-config | include ^ip nat`: one pool per netmask/prefix-length
# spelling, a list->pool overload, a static with ports, an interface-overload,
# an inside-destination and a route-map rule: one of each grammar branch
NAT_TEXT = """\
ip nat pool WEB-POOL 203.0.113.10 203.0.113.20 netmask 255.255.255.0
ip nat pool DST-POOL 10.99.0.0 10.99.0.255 prefix-length 24
ip nat inside source list NAT-INSIDE pool WEB-POOL overload
ip nat inside source static tcp 10.0.0.5 8080 203.0.113.5 80
ip nat inside source list 7 interface GigabitEthernet1/0/1 overload
ip nat inside destination list DST-ACL pool DST-POOL
ip nat inside source route-map RM-NAT pool WEB-POOL
"""

# the tests read only the Inside/Outside interface lines
NAT_STATS_TEXT = """\
Total active translations: 3 (1 static, 2 dynamic; 2 extended)
Outside interfaces:
  GigabitEthernet1/0/1
Inside interfaces:
  Vlan10
Hits: 100  Misses: 5
Expired translations: 0
"""

# NAT-INSIDE carries a deny (exercises `approximate`); 7 is a standard ACL
# (wildcard form); DST-ACL matches by destination for the inside-destination rule.
# EDGE-IN and MGMT-OUT are the two interface filters: one extended list bound
# inbound (a port-scoped permit, an `established` ACE, an object-group ACE whose
# `log` keyword is dropped, and an explicit deny) and one standard list bound
# outbound. UNCOLLECTED-ACL is absent from this output and the interface config
# below binds it.
ACL_TEXT = """\
Extended IP access list NAT-INSIDE
    10 permit ip 10.10.10.0 0.0.0.255 any
    20 deny ip host 10.10.10.99 any
Standard IP access list 7
    10 permit 10.0.0.0, wildcard bits 0.0.0.255
Extended IP access list DST-ACL
    10 permit tcp any host 203.0.113.80
Extended IP access list EDGE-IN
    10 permit tcp 10.0.0.0 0.0.0.255 host 203.0.113.10 eq 443
    20 permit tcp any host 203.0.113.10 established
    30 permit ip object-group PARTNERS any log
    40 deny ip any any
Standard IP access list MGMT-OUT
    10 permit 10.10.10.0, wildcard bits 0.0.0.255
"""

# `show running-config | section ^interface`. The base fixture binds no access
# group; ACL_BINDING_CONFIG_TEXT is the variant the interface-ACL tests use.
INTERFACE_CONFIG_TEXT = """\
interface GigabitEthernet1/0/1
 description uplink
 ip address 10.0.0.1 255.255.255.0
!
interface GigabitEthernet1/0/2
 no ip address
!
interface Vlan10
 ip address 10.10.10.1 255.255.255.0
!
"""

# the access-group bindings: Gi1/0/1 carries an inbound filter, Vlan10 an
# outbound one, and Gi1/0/2 binds a list this capture's `show ip access-lists`
# never printed: the fail-visible case.
ACL_BINDING_CONFIG_TEXT = """\
interface GigabitEthernet1/0/1
 description uplink
 ip address 10.0.0.1 255.255.255.0
 ip access-group EDGE-IN in
!
interface GigabitEthernet1/0/2
 no ip address
 ip access-group UNCOLLECTED-ACL in
!
interface Vlan10
 ip address 10.10.10.1 255.255.255.0
 ip access-group MGMT-OUT out
!
"""

# `show running-config | section ^router bgp`: one process, two neighbors; 10.0.0.2
# is iBGP (remote-as == the process asn), 192.0.2.1 is eBGP (remote-as differs). One
# neighbor attaches a route-map inbound, the other a prefix-list inbound (both
# resolvable), and the address-family redistributes static via a route-map.
BGP_TEXT = """\
router bgp 65001
 bgp router-id 10.255.255.1
 bgp log-neighbor-changes
 neighbor 10.0.0.2 remote-as 65001
 neighbor 10.0.0.2 description iBGP to RR1
 neighbor 10.0.0.2 route-map RM-IN in
 neighbor 192.0.2.1 remote-as 65010
 neighbor 192.0.2.1 description eBGP to ISP-A
 neighbor 192.0.2.1 prefix-list PL-CUSTOMER-IN in
 !
 address-family ipv4
  neighbor 10.0.0.2 activate
  neighbor 192.0.2.1 activate
  redistribute static route-map RM-STATIC-TO-BGP
 exit-address-family
!
"""

# `show running-config | include ^ip prefix-list`: one list, two lines; seq 10 has
# `le` only (ge defaults to the base prefix's own length), seq 20 has both `ge`/`le`
PREFIX_LIST_TEXT = """\
ip prefix-list PL-CUSTOMER-IN seq 10 permit 10.1.0.0/16 le 24
ip prefix-list PL-CUSTOMER-IN seq 20 permit 10.2.0.0/16 ge 25 le 32
"""

# `show running-config | section ^route-map`: RM-IN has two clauses (a `continue` off
# clause 10, a `set community ... additive` + `set weight` on clause 20) and resolves
# its prefix-list match; RM-STATIC-TO-BGP backs the redistribution above; RM-DANGLING
# matches a prefix-list this capture never defines, for the dangling-reference
# warning and the missing REFERENCES edge
ROUTE_MAP_TEXT = """\
route-map RM-IN permit 10
 match ip address prefix-list PL-CUSTOMER-IN
 set local-preference 150
 continue 20
route-map RM-IN permit 20
 set community 65001:100 additive
 set weight 100
!
route-map RM-STATIC-TO-BGP permit 10
 match tag 100
 set origin incomplete
!
route-map RM-DANGLING permit 10
 match ip address prefix-list PL-GHOST
 set local-preference 200
!
"""

# The OSPF backbone/stub area ids, dotted.
AREA_0 = "0.0.0.0"  # noqa: S104 - an OSPF area id
AREA_10 = "0.0.0.10"

# --- OSPF: FIRST CONTACT, no field name below is confirmed against an IOS-XE capture.
OSPF_TEXT = """\
 Routing Process "ospf 1" with ID 10.255.255.1
 Start time: 00:00:03.256, Time elapsed: 2w3d
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
GigabitEthernet1/0/1 is up, line protocol is up
  Internet Address 10.0.0.1/24, Area 0, Attached via Network Statement
  Process ID 1, Router ID 10.255.255.1, Network Type BROADCAST, Cost: 1
  Transmit Delay is 1 sec, State DR, Priority 1
GigabitEthernet1/0/3 is up, line protocol is up
  Internet Address 10.0.3.1/24, Area 10, Attached via Network Statement
  Process ID 1, Router ID 10.255.255.1, Network Type BROADCAST, Cost: 10
  No Hellos (Passive interface)
"""

OSPF_NBR_TEXT = """\
Neighbor ID     Pri   State           Dead Time   Address         Interface
10.255.0.2        1   FULL/BDR        00:00:33    10.0.0.2        GigabitEthernet1/0/1
"""

# `detail`: router and network go through ntc-templates
# (cisco_ios_show_ip_ospf_database_router/_network); one router LSA (self, two links:
# one point-to-point neighbor, one stub network) and one network LSA (two attached
# routers) in the backbone.
OSPF_DB_ROUTER_TEXT = """\
            OSPF Router with ID (10.255.255.1) (Process ID 1)

                Router Link States (Area 0)

  LS age: 120
  Options: (No TOS-capability, DC)
  LS Type: Router Links
  Link State ID: 10.255.255.1
  Advertising Router: 10.255.255.1
  LS Seq Number: 80000005
  Checksum: 0x1234
  Length: 48
  Number of Links: 2

    Link connected to: another Router (point-to-point)
     (Link ID) Neighboring Router ID: 10.255.0.2
     (Link Data) Router Interface address: 10.0.0.1
      Number of MTID metrics: 0
       TOS 0 Metrics: 40

    Link connected to: a Stub Network
     (Link ID) Network/subnet number: 10.0.0.0
     (Link Data) Network Mask: 255.255.255.0
      Number of MTID metrics: 0
       TOS 0 Metrics: 40

"""

OSPF_DB_NETWORK_TEXT = """\
            OSPF Router with ID (10.255.255.1) (Process ID 1)

                Net Link States (Area 0)

  LS age: 130
  Options: (No TOS-capability, DC)
  LS Type: Network Links
  Link State ID: 10.0.0.2 (address of Designated Router)
  Advertising Router: 10.255.255.2
  LS Seq Number: 80000003
  Checksum: 0x5678
  Length: 32
  Network Mask: 255.255.255.0
        Attached Router: 10.255.255.1
        Attached Router: 10.255.255.2

"""

# ntc-templates carries no template for any of the four LSA types below; all four go
# through `cisco_common.ospf_lsa_detail_rows`. Summary and nssa-external sit in the
# stub area; asbr-summary sits in the backbone; external belongs to no area (flooded
# domain-wide).
OSPF_DB_SUMMARY_TEXT = """\
       OSPF Router with ID (10.255.255.1) (Process ID 1)

                Summary Net Link States (Area 10)

  LS age: 200
  Options: (No TOS-capability, DC)
  LS Type: Summary Links(Network)
  Link State ID: 10.10.10.0 (summary Network Number)
  Advertising Router: 10.255.255.2
  LS Seq Number: 80000002
  Checksum: 0x5678
  Length: 28
  Network Mask: /24
        TOS: 0  Metric: 20
"""

OSPF_DB_ASBR_SUMMARY_TEXT = """\
       OSPF Router with ID (10.255.255.1) (Process ID 1)

                Summary ASB Link States (Area 0)

  LS age: 250
  Options: (No TOS-capability, DC)
  LS Type: Summary Links(AS Boundary Router)
  Link State ID: 10.255.255.3 (AS Boundary Router address)
  Advertising Router: 10.255.255.2
  LS Seq Number: 80000001
  Checksum: 0x1357
  Length: 28
        TOS: 0  Metric: 30
"""

OSPF_DB_EXTERNAL_TEXT = """\
       OSPF Router with ID (10.255.255.1) (Process ID 1)

                Type-5 AS External Link States

  LS age: 300
  Options: (No TOS-capability, DC, Upward)
  LS Type: AS External Link
  Link State ID: 192.0.2.0 (External Network Number )
  Advertising Router: 10.255.255.3
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
       OSPF Router with ID (10.255.255.1) (Process ID 1)

                NSSA-External Link States (Area 10)

  LS age: 150
  Options: (No TOS-capability, Type 7/5 translation, DC)
  LS Type: AS External Link
  Link State ID: 203.0.113.0 (External Network Number )
  Advertising Router: 10.255.255.4
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

# The redistribute line of `router ospf` names the route-map the BGP redistribution above resolves.
OSPF_CONFIG_TEXT = """\
router ospf 1
 router-id 10.255.255.1
 redistribute static route-map RM-STATIC-TO-BGP
!
"""
# --- the BGP observation capture ---------------------------------------------------------
#
# FIRST CONTACT: no field name below is confirmed against a capture.
#
# 10.0.0.2 is an Established iBGP peer without soft reconfiguration inbound.
# 192.0.2.1 is an Idle eBGP peer with soft reconfiguration inbound.

# `show ip bgp summary`. First-contact field naming: BGP_NEIGHBOR (bgp_neighbor)
# and STATE_OR_PREFIXES_RECEIVED (state_or_prefixes_received) come from the
# ntc-templates `cisco_ios_show_ip_bgp_summary` template.
BGP_SESSIONS_TEXT = """\
BGP router identifier 10.255.255.1, local AS number 65001
BGP table version is 12, main routing table version 12
2 network entries using 456 bytes of memory

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.2        4        65001     120     118       12    0    0 01:02:03        1
192.0.2.1       4        65010      10       8       12    0    0 00:00:00 Idle
"""

# The line a box with no soft reconfiguration inbound answers with: a zero
# exit status and no rejection banner, so the fetch keeps it as output and
# the direction reads not-captured on the text alone.
BGP_NO_SOFT_RECONFIG_TEXT = "% BGP is not configured with soft-reconfiguration inbound for this neighbor\n"

# 10.0.0.2, the iBGP peer: one accepted path for 10.20.0.0/24 that the inbound
# route-map raised the local preference of and the device marked best, and
# one self-originated advertised prefix.
BGP_ACCEPTED_10_0_0_2_TEXT = """\
BGP table version is 12, local router ID is 10.255.255.1
Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,
Origin codes: i - IGP, e - EGP, ? - incomplete

     Network          Next Hop            Metric LocPrf Weight Path
*>i  10.20.0.0/24     10.0.0.2                 0    150      0 i
"""
BGP_ADVERTISED_10_0_0_2_TEXT = """\
BGP table version is 12, local router ID is 10.255.255.1
Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,
Origin codes: i - IGP, e - EGP, ? - incomplete

     Network          Next Hop            Metric LocPrf Weight Path
*>   10.0.0.0/24      10.255.255.1             0    100      0 i
"""

# 192.0.2.1 sent two prefixes, and 10.20.0.0/24 also arrives from 10.0.0.2.
BGP_RECEIVED_192_0_2_1_TEXT = """\
BGP table version is 12, local router ID is 10.255.255.1
Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,
Origin codes: i - IGP, e - EGP, ? - incomplete

     Network          Next Hop            Metric LocPrf Weight Path
 *   10.20.0.0/24     192.0.2.1                100      0      0 65010 i
 *   198.51.100.0/24  192.0.2.1                  0      0      0 65010 64500 e
"""


def _bgp_capture_raw():
    """The observation commands the base fixture's fetch issues, and what the
    box answers each with."""
    out = {CMD_BGP_SESSIONS: BGP_SESSIONS_TEXT}
    answers = {
        ("10.0.0.2", "received"): BGP_NO_SOFT_RECONFIG_TEXT,
        ("10.0.0.2", "accepted"): BGP_ACCEPTED_10_0_0_2_TEXT,
        ("10.0.0.2", "advertised"): BGP_ADVERTISED_10_0_0_2_TEXT,
        ("192.0.2.1", "received"): BGP_RECEIVED_192_0_2_1_TEXT,
        ("192.0.2.1", "accepted"): "",
        ("192.0.2.1", "advertised"): "",
    }
    for (peer_ip, direction), text in answers.items():
        out[iosxe.bgp_route_command(peer_ip, direction)] = text
    return out


RAW = {
    CMD_VERSION: VERSION_TEXT,
    CMD_INTERFACES: INTERFACES_TEXT,
    CMD_LLDP: LLDP_TEXT,
    CMD_VRF: VRF_TEXT,
    CMD_VRF_DETAIL: VRF_DETAIL_TEXT,
    CMD_ROUTE: ROUTE_TEXT,
    CMD_ARP: ARP_TEXT,
    CMD_CDP: CDP_TEXT,
    CMD_NAT: NAT_TEXT,
    CMD_NAT_STATS: NAT_STATS_TEXT,
    CMD_ACL: ACL_TEXT,
    CMD_BGP: BGP_TEXT,
    CMD_PREFIX_LIST: PREFIX_LIST_TEXT,
    CMD_ROUTE_MAP: ROUTE_MAP_TEXT,
    CMD_INTERFACE_CONFIG: INTERFACE_CONFIG_TEXT,
    # no VLAN access map in the base fixture
    iosxe.CMD_VLAN_FILTER: "",
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
    # HSRP and VRRP: empty in the base fixture, a box with no group configured,
    # the same as the collector's own OPTIONAL_COMMANDS stand-ins. `FHRP_RAW`
    # below is the variant with groups configured.
    CMD_STANDBY: "",
    CMD_VRRP: "",
}

# These commands are derived from the BGP running-config above, so they join the payload here.
RAW.update(_bgp_capture_raw())
# the neighbor detail answers without a router id; test_bgp_peer_router_id.py
# covers the answered case
RAW[iosxe.CMD_BGP_NEIGHBORS] = ""
# the ARP table of the one VRF `show vrf` names, derived per fetch;
# empty here, test_cisco_collector_cases.py covers the answered case
RAW[iosxe.CMD_ARP_VRF.format(vrf="mgmt")] = ""

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

# the same box with the access-group lines the base fixture leaves out
ACL_RAW = {**RAW, CMD_INTERFACE_CONFIG: ACL_BINDING_CONFIG_TEXT}

# A single-ACE list with the `syn` TCP flag, which lands as service opacity.
QUALIFIER_ACL_TEXT = """\
Extended IP access list SYN-IN
    10 permit tcp any host 203.0.113.10 eq 22 syn
"""

QUALIFIER_BINDING_CONFIG_TEXT = """\
interface GigabitEthernet1/0/1
 description uplink
 ip address 10.0.0.1 255.255.255.0
 ip access-group SYN-IN in
!
"""

QUALIFIER_RAW = {**RAW, CMD_ACL: QUALIFIER_ACL_TEXT, CMD_INTERFACE_CONFIG: QUALIFIER_BINDING_CONFIG_TEXT}


def _collector():
    return IosxeCollector(
        IosxeConfig(host=HOST, auth=SshPassword(username=USER, password="pw"), site_code="hq", l3dom="corp"),
        None,
    )


# SSH transport plumbing (auth/pin forwarding, observed host keys, one-transport-per-fetch,
# probe) is shared by every CLI collector and is exercised once, parametrized over vendors,
# in test_ssh_transport_conformance.py.


# --- section outcomes: what each command produced -----------------------------------------


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
    """A raw file with no recorded outcomes claims nothing."""
    c = _collector()
    assert {s.status for s in c.normalize(dict(RAW)).sections.values()} == {"unknown"}


# --- parse/normalize/side_tables against the fixture texts ----------------------------------


class TestParsed:
    def test_parse_device_hostname_serial_platform_os_version(self):
        inter = iosxe.parse(RAW)
        assert inter["device"] == {
            "hostname": "sw1",
            "serial": SERIAL,
            "platform": "iosxe",
            "os_version": "17.3.4a",
        }

    def test_parse_phys_interface_has_mac_ip_and_default_vrf(self):
        inter = iosxe.parse(RAW)
        eth = next(i for i in inter["interfaces"] if i["name"] == "GigabitEthernet1/0/1")
        assert eth["kind"] == "phys"
        assert eth["mac"] == "aabbccddee01"
        assert eth["admin_up"] is True
        assert eth["ips"] == [{"ip": "10.0.0.1", "prefixlen": 24, "vrf": ""}]
        assert eth["vlan"] is None

    def test_parse_svi_has_vlan_ip_and_non_default_vrf(self):
        inter = iosxe.parse(RAW)
        svi = next(i for i in inter["interfaces"] if i["name"] == "Vlan10")
        assert svi["kind"] == "svi"
        assert svi["mac"] == "aabbccddee10"
        assert svi["vlan"] == 10
        assert svi["ips"] == [{"ip": "10.10.10.1", "prefixlen": 24, "vrf": "mgmt"}]

    def test_parse_lldp_neighbor(self):
        inter = iosxe.parse(RAW)
        lldp = [n for n in inter["neighbors"] if n["proto"] == "lldp"]
        assert lldp == [
            {
                # as the device prints them; the graph stage resolves the local
                # port against the interface table
                "local_port": "Gi1/0/1",
                "name": "core1",
                "mac": "aabbccddef01",
                "port": "Gi2/0/1",
                "proto": "lldp",
            }
        ]

    def test_parse_cdp_neighbor_has_no_mac(self):
        inter = iosxe.parse(RAW)
        cdp = [n for n in inter["neighbors"] if n["proto"] == "cdp"]
        assert cdp == [
            {
                "local_port": "GigabitEthernet1/0/1",
                "name": "core1.example.com",
                "mac": None,
                "port": "GigabitEthernet2/0/1",
                "proto": "cdp",
            }
        ]

    def test_parse_cdp_neighbor_of_a_nexus_gives_the_name_and_the_serial(self):
        device_id = "core2.example.com(FDO12345678)"
        inter = iosxe.parse({**RAW, CMD_CDP: CDP_TEXT.replace("core1.example.com", device_id)})
        [cdp] = [n for n in inter["neighbors"] if n["proto"] == "cdp"]
        assert (cdp["name"], cdp["serial"]) == ("core2.example.com", "FDO12345678")

    def test_parse_rib_rows_include_non_default_vrf(self):
        inter = iosxe.parse(RAW)
        assert inter["rib"] == [
            {
                "vrf": "default",
                "prefix": "10.0.0.0/24",
                "next_hop": None,
                "next_hop_vrf": None,
                "interface": "GigabitEthernet1/0/1",
                "protocol": "connected",
                "metric": None,
            },
            {
                "vrf": "mgmt",
                "prefix": "10.255.0.0/32",
                "next_hop": "10.255.0.2",
                "next_hop_vrf": None,
                "interface": "GigabitEthernet1/0/2",
                "protocol": "static",
                "metric": 0,
            },
        ]

    def test_parse_arp_rows_derive_vrf_from_show_vrf_membership(self):
        inter = iosxe.parse(RAW)
        assert inter["arp"] == [
            {
                "vrf": "default",
                "ip": "10.0.0.5",
                "mac": "aabbccddefaa",
                "interface_name": "GigabitEthernet1/0/1",
            },
            {
                "vrf": "mgmt",
                "ip": "10.255.0.2",
                "mac": "aabbccddefbb",
                "interface_name": "GigabitEthernet1/0/2",
            },
        ]

    def test_parse_no_mac_table_for_a_router(self):
        assert iosxe.parse(RAW)["mac_table"] == []

    def test_parse_vrf_detail_yields_rd_and_rt_import_export(self):
        inter = iosxe.parse(RAW)
        assert inter["vrfs"] == [
            {"name": "mgmt", "rd": "1:100", "rt_import": ["65000:200"], "rt_export": ["65000:100"]}
        ]

    def test_parse_tolerates_a_raw_dict_without_the_vrf_detail_key(self):
        """A raw dict with no `show vrf detail` key parses without a KeyError."""
        raw = {k: v for k, v in RAW.items() if k != CMD_VRF_DETAIL}
        inter = iosxe.parse(raw)
        assert inter["vrfs"] == [{"name": "mgmt", "rd": None, "rt_import": [], "rt_export": []}]

    def test_normalize_emits_route_target_nodes_and_directional_rels(self):
        batch = _collector().normalize(RAW)
        mgmt_vrf = uid.vrf(DEV, "mgmt")
        rt_export, rt_import = uid.route_target("65000:100"), uid.route_target("65000:200")
        assert any(n.uid == rt_export and n.label == "RouteTarget" for n in batch.nodes)
        assert any(n.uid == rt_import and n.label == "RouteTarget" for n in batch.nodes)
        assert (mgmt_vrf, rt_export) in [
            (r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "EXPORTS"
        ]
        assert (mgmt_vrf, rt_import) in [
            (r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IMPORTS"
        ]
        vrf_node = next(n for n in batch.nodes if n.uid == mgmt_vrf)
        assert vrf_node.props["rd"] == "1:100"

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

    def test_normalize_svi_in_vrf_toward_the_non_default_vrf(self):
        batch = _collector().normalize(RAW)
        iu = uid.interface(DEV, "Vlan10")
        vru = uid.vrf(DEV, "mgmt")
        assert any(r.rel_type == "IN_VRF" and r.start_uid == iu and r.end_uid == vru for r in batch.rels)
        assert any(
            n.uid == vru and n.label == "VrfInstance" and n.props["name"] == "mgmt" for n in batch.nodes
        )

    def test_normalize_lldp_and_cdp_hints_land_on_the_port(self):
        batch = _collector().normalize(RAW)
        pu = uid.port(DEV, "GigabitEthernet1/0/1")
        port = next(n for n in batch.nodes if n.uid == pu)
        assert port.props["lldp_neighbor_name"] == "core1"
        assert port.props["lldp_neighbor_mac"] == "aabbccddef01"
        assert port.props["cdp_neighbor_name"] == "core1.example.com"
        assert "cdp_neighbor_mac" not in port.props

    def test_side_tables_device_uid_stamped_and_no_mac_table(self):
        rows = _collector().side_tables(RAW)
        assert rows["mac"] == []
        assert rows["rib"] and all(r["device_uid"] == DEV for r in rows["rib"])
        assert rows["arp"] and all(r["device_uid"] == DEV for r in rows["arp"])
        assert {r["vrf"] for r in rows["rib"]} == {"default", "mgmt"}
        assert {r["vrf"] for r in rows["arp"]} == {"default", "mgmt"}

    # --- Link speed: duplex/speed/BW off `show interfaces` onto the Port -----------

    def test_normalize_known_speed_and_duplex_land_on_the_port(self):
        batch = _collector().normalize(RAW)
        port = next(n for n in batch.nodes if n.uid == uid.port(DEV, "GigabitEthernet1/0/1"))
        assert port.props["speed_mbps"] == 1000
        assert port.props["duplex"] == "full"
        assert port.props["speed_source"] == "iosxe:show interfaces"
        assert port.props["bandwidth_kbit"] == 1000000

    def test_normalize_auto_speed_and_duplex_give_nulls_and_no_source(self):
        batch = _collector().normalize(RAW)
        port = next(n for n in batch.nodes if n.uid == uid.port(DEV, "GigabitEthernet1/0/9"))
        assert "speed_mbps" not in port.props
        assert "duplex" not in port.props
        assert "speed_source" not in port.props
        # the MTU/BW line is on its own and still parses independently
        assert port.props["bandwidth_kbit"] == 1000000

    def test_normalize_no_duplex_speed_line_gives_nulls_and_no_source(self):
        """Vlan10's fixture text carries no `Full-duplex, ...` line."""
        ifc = next(i for i in iosxe.parse(RAW)["interfaces"] if i["name"] == "Vlan10")
        assert ifc["speed_mbps"] is None
        assert ifc["duplex"] is None
        assert ifc["speed_source"] is None
        assert ifc["bandwidth_kbit"] == 1000000


# --- fallback formula: side_tables' device_uid must match normalize()'s ---------------------


def test_side_tables_fallback_uid_matches_normalize_when_no_serial_or_hostname(monkeypatch):
    # side_tables() and normalize() give a serial-less, hostname-less box the same uid
    bare_inter = {
        "device": {"hostname": None, "serial": None, "platform": "iosxe", "os_version": "17.3.4a"},
        "interfaces": [],
        "neighbors": [],
        "vlans": [],
        "vrfs": [],
        "rib": [
            {
                "vrf": "default",
                "prefix": "10.0.0.0/24",
                "next_hop": None,
                "protocol": "connected",
                "metric": None,
            }
        ],
        "mac_table": [],
        "arp": [],
    }
    monkeypatch.setattr(iosxe, "parse", lambda raw: bare_inter)
    c = _collector()
    batch = c.normalize(RAW)
    dev = next(n for n in batch.nodes if n.label == "Device")
    # the registry keys a box without serial and hostname by its scope
    assert c.scope == "iosxe:sw1x"
    assert dev.uid == c.identity.resolve_device("ref", "iosxe:sw1x:unknown", None)
    rows = c.side_tables(RAW)
    assert rows["rib"][0]["device_uid"] == dev.uid


# --- NAT: parse and normalize against the fixture texts -------------------------------------


class TestNat:
    def test_parse_if_roles_come_from_nat_statistics(self):
        nat = iosxe.parse(RAW)["nat"]
        assert nat["if_roles"] == {"GigabitEthernet1/0/1": "outside", "Vlan10": "inside"}

    def test_parse_pools_carry_range_and_cidr_when_reducible(self):
        pools = iosxe.parse(RAW)["nat"]["pools"]
        # .10-.20 is not a whole block, so no cidr; .0-.255 is the /24
        assert pools["WEB-POOL"]["start"] == "203.0.113.10"
        assert pools["WEB-POOL"]["end"] == "203.0.113.20"
        assert pools["WEB-POOL"]["cidr"] is None
        assert pools["DST-POOL"]["cidr"] == "10.99.0.0/24"

    def test_parse_rules_keep_config_order(self):
        rules = iosxe.parse(RAW)["nat"]["rules"]
        assert [(r["direction"], r.get("acl") or r.get("route_map") or r.get("local")) for r in rules] == [
            ("inside-source", "NAT-INSIDE"),
            ("inside-source", "10.0.0.5"),
            ("inside-source", "7"),
            ("inside-destination", "DST-ACL"),
            ("inside-source", "RM-NAT"),
        ]

    def test_parse_acls_shared_ace_shape(self):
        acls = iosxe.parse(RAW)["nat"]["acls"]
        assert acls["NAT-INSIDE"] == [
            {"action": "permit", "src": "10.10.10.0/24", "dst": "any"},
            {"action": "deny", "src": "10.10.10.99", "dst": "any"},
        ]
        assert acls["7"] == [{"action": "permit", "src": "10.0.0.0/24", "dst": None}]
        assert acls["DST-ACL"] == [{"action": "permit", "src": "any", "dst": "203.0.113.80"}]

    def test_normalize_rulebases_and_positions(self):
        batch = _collector().normalize(RAW)
        rbs = {n.uid: n for n in batch.nodes if n.label == "FwRulebase"}
        assert set(rbs) == {"iosxe:sw1x:nat:inside-source", "iosxe:sw1x:nat:inside-destination"}
        for rb in rbs.values():
            assert rb.props["kind"] == "nat" and rb.props["vendor"] == "cisco"
        assert all(
            (DEV, u) in [(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENFORCES"]
            for u in rbs
        )
        rules = {n.uid: n for n in batch.nodes if n.label == "NatRule"}
        inside = sorted(u for u in rules if ":inside-source:" in u)
        assert inside == [f"iosxe:sw1x:nat:inside-source:{i}" for i in (1, 2, 3, 4)]
        # the uid keeps the configuration ordinal; position is the order the
        # device evaluates in, the static (configured second) ahead of the
        # dynamic rules
        assert [rules[u].props["position"] for u in inside] == [2, 1, 3, 4]
        has_rule = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "HAS_RULE"}
        assert all(("iosxe:sw1x:nat:inside-source", u) in has_rule for u in inside)

    def test_normalize_list_pool_overload_rule(self):
        batch = _collector().normalize(RAW)
        nu = "iosxe:sw1x:nat:inside-source:1"
        rule = next(n for n in batch.nodes if n.uid == nu)
        assert rule.props["kind"] == "snat"
        assert rule.props["static"] is False and rule.props["overload"] is True
        assert rule.props["match_acl"] == "NAT-INSIDE" and rule.props["pool"] == "WEB-POOL"
        assert rule.props["pool_start"] == "203.0.113.10" and rule.props["pool_end"] == "203.0.113.20"
        # the deny ACE makes the resolution approximate; the permit still lands
        assert rule.props["approximate"] is True and rule.props["src_any"] is False
        edges = {(r.rel_type, r.end_uid) for r in batch.rels if r.start_uid == nu}
        assert ("ORIG_SRC", uid.prefix(DEFAULT_VRF_UID, "10.10.10.0/24")) in edges
        # pool range is not cidr-reducible, so the start address stands in
        assert ("XLATE_SRC", uid.ip(DEFAULT_VRF_UID, "203.0.113.10")) in edges
        assert rule.props["translation"] == "203.0.113.10"

    def test_normalize_static_rule_with_ports(self):
        batch = _collector().normalize(RAW)
        nu = "iosxe:sw1x:nat:inside-source:2"
        rule = next(n for n in batch.nodes if n.uid == nu)
        assert rule.props["static"] is True and rule.props["protocol"] == "tcp"
        assert rule.props["orig_port"] == 8080 and rule.props["translation_port"] == 80
        assert rule.props["translation"] == "203.0.113.5"
        assert rule.props["approximate"] is False
        edges = {(r.rel_type, r.end_uid) for r in batch.rels if r.start_uid == nu}
        assert ("ORIG_SRC", uid.ip(DEFAULT_VRF_UID, "10.0.0.5")) in edges
        assert ("XLATE_SRC", uid.ip(DEFAULT_VRF_UID, "203.0.113.5")) in edges

    def test_normalize_interface_overload_rule_has_no_xlate_edge(self):
        batch = _collector().normalize(RAW)
        nu = "iosxe:sw1x:nat:inside-source:3"
        rule = next(n for n in batch.nodes if n.uid == nu)
        assert rule.props["translation"] == "interface"
        assert rule.props["translation_interface"] == "GigabitEthernet1/0/1"
        assert rule.props["overload"] is True
        edges = [r for r in batch.rels if r.start_uid == nu and r.rel_type.startswith("XLATE")]
        assert edges == []
        # the ACL resolved; its /24 joins the connected prefix node
        orig = [r.end_uid for r in batch.rels if r.start_uid == nu and r.rel_type == "ORIG_SRC"]
        assert orig == [uid.prefix(DEFAULT_VRF_UID, "10.0.0.0/24")]

    def test_normalize_route_map_rule_is_approximate_with_no_address_edges(self):
        batch = _collector().normalize(RAW)
        nu = "iosxe:sw1x:nat:inside-source:4"
        rule = next(n for n in batch.nodes if n.uid == nu)
        assert rule.props["match_route_map"] == "RM-NAT" and rule.props["pool"] == "WEB-POOL"
        assert rule.props["approximate"] is True
        assert not [r for r in batch.rels if r.start_uid == nu and r.rel_type in ("ORIG_SRC", "XLATE_SRC")]

    def test_normalize_inside_destination_rule(self):
        batch = _collector().normalize(RAW)
        nu = "iosxe:sw1x:nat:inside-destination:1"
        rule = next(n for n in batch.nodes if n.uid == nu)
        assert rule.props["kind"] == "dnat" and rule.props["match_acl"] == "DST-ACL"
        edges = {(r.rel_type, r.end_uid) for r in batch.rels if r.start_uid == nu}
        assert ("ORIG_DST", uid.ip(DEFAULT_VRF_UID, "203.0.113.80")) in edges
        assert ("XLATE_DST", uid.prefix(DEFAULT_VRF_UID, "10.99.0.0/24")) in edges
        pool = next(n for n in batch.nodes if n.uid == uid.prefix(DEFAULT_VRF_UID, "10.99.0.0/24"))
        assert pool.props["kind"] == "nat-pool"

    def test_normalize_nat_roles_land_on_the_interfaces(self):
        batch = _collector().normalize(RAW)
        gi = next(n for n in batch.nodes if n.uid == uid.interface(DEV, "GigabitEthernet1/0/1"))
        svi = next(n for n in batch.nodes if n.uid == uid.interface(DEV, "Vlan10"))
        assert gi.props["nat_role"] == "outside"
        assert svi.props["nat_role"] == "inside"


# --- Interface ACLs: access-group bindings and the filter rulebase they mint ---------------


class TestInterfaceAcl:
    def test_base_fixture_binds_no_access_group_and_mints_no_acl_rulebase(self):
        """The un-bound fixture (RAW) has no FwRulebase with match_context='interface-acl'."""
        assert iosxe.parse(RAW)["acl"]["bindings"] == []
        batch = _collector().normalize(RAW)
        assert not [n for n in batch.nodes if n.props.get("match_context") == "interface-acl"]

    def test_parse_access_group_bindings_in_config_order(self):
        assert iosxe.parse(ACL_RAW)["acl"]["bindings"] == [
            {"interface": "GigabitEthernet1/0/1", "direction": "in", "acl": "EDGE-IN"},
            {"interface": "GigabitEthernet1/0/2", "direction": "in", "acl": "UNCOLLECTED-ACL"},
            {"interface": "Vlan10", "direction": "out", "acl": "MGMT-OUT"},
        ]

    def test_parse_extended_acl_carries_protocol_ports_and_opaque_reasons(self):
        aces = iosxe.parse(ACL_RAW)["acl"]["lists"]["EDGE-IN"]
        assert [a["action"] for a in aces] == ["permit", "permit", "permit", "deny"]
        assert aces[0]["proto"] == "tcp" and aces[0]["ports"] == "443" and aces[0]["dst"] == "203.0.113.10"
        # `established` is Cisco's own connection-state keyword and carries a
        # definite answer, so it lands on `states` and leaves no other TCP
        # flag behind to name in `qualifier_reason`.
        assert aces[1]["states"] == ["established"]
        assert aces[1]["qualifier_reason"] is None
        assert aces[2]["src_opaque_reason"] == (
            "the ACE matches object-group 'PARTNERS', which is not collected"
        )
        assert aces[3]["src_any"] is True and aces[3]["dst_any"] is True

    def test_parse_standard_acl_is_source_only_with_an_implicit_any_destination(self):
        aces = iosxe.parse(ACL_RAW)["acl"]["lists"]["MGMT-OUT"]
        assert aces == [
            {
                "action": "permit",
                "src_any": False,
                "src": "10.10.10.0/24",
                "src_opaque_reason": None,
                "dst_any": True,
                "dst": None,
                "dst_opaque_reason": None,
                "proto": None,
                "ports": None,
                "src_port": None,
                "svc_opaque_reason": None,
                "qualifier_reason": None,
            }
        ]

    def test_normalize_mints_one_rulebase_per_acl_name_enforced_by_the_device(self):
        batch = _collector().normalize(ACL_RAW)
        rbs = {
            n.uid: n
            for n in batch.nodes
            if n.label == "FwRulebase" and n.props.get("match_context") == "interface-acl"
        }
        assert set(rbs) == {
            "iosxe:sw1x:acl:edge-in~f89b1a37",
            "iosxe:sw1x:acl:uncollected-acl~6bc82fe0",
            "iosxe:sw1x:acl:mgmt-out~bf66d13c",
        }
        for rb in rbs.values():
            assert rb.props["kind"] == "access" and rb.props["vendor"] == "cisco"
            assert rb.props["default_action"] == "deny" and rb.props["af"] == 4
        enforces = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENFORCES"}
        assert all((DEV, u) in enforces for u in rbs)
        # each binding is a PROTECTED_BY edge from the interface, in its direction;
        # GigabitEthernet1/0/2 is not in `show interfaces`, so it has no node to bind from
        assert {
            (r.start_uid, r.end_uid, r.props["direction"]) for r in batch.rels if r.rel_type == "PROTECTED_BY"
        } == {
            (uid.interface(DEV, "GigabitEthernet1/0/1"), "iosxe:sw1x:acl:edge-in~f89b1a37", "in"),
            (uid.interface(DEV, "Vlan10"), "iosxe:sw1x:acl:mgmt-out~bf66d13c", "out"),
        }

    def test_normalize_ace_position_action_and_no_interface_on_any_rule(self):
        batch = _collector().normalize(ACL_RAW)
        rb_uid = "iosxe:sw1x:acl:edge-in~f89b1a37"
        rules = sorted(
            (n for n in batch.nodes if n.label == "FwRule" and n.uid.startswith(rb_uid + ":")),
            key=lambda n: n.props["position"],
        )
        assert [r.props["position"] for r in rules] == [1, 2, 3, 4]
        assert [r.props["action"] for r in rules] == ["permit", "permit", "permit", "deny"]
        # every rule of an inbound binding carries in_interface, never out_interface,
        # and log (a side effect, not a match criterion) leaves no property behind
        for r in rules:
            assert "in_interface" not in r.props
            assert "out_interface" not in r.props
            assert "log" not in r.props

    def test_normalize_established_ace_carries_a_definite_state_not_an_opaque_one(self):
        """`established` is Cisco's own connection-state scoping."""
        batch = _collector().normalize(ACL_RAW)
        rule = next(n for n in batch.nodes if n.uid == "iosxe:sw1x:acl:edge-in~f89b1a37:2")
        assert rule.props["states"] == ["established"]
        assert not rule.props.get("states_opaque")

    def test_normalize_syn_flag_ace_carries_an_opaque_service_not_a_definite_state(self):
        """The traced flow's tuple has no column for the `syn` TCP flag."""
        batch = _collector().normalize(QUALIFIER_RAW)
        rule_uid = "iosxe:sw1x:acl:syn-in~03c130c1:1"
        rule = next(n for n in batch.nodes if n.uid == rule_uid)
        assert not rule.props.get("states")
        svc = next(n for n in batch.nodes if n.uid == f"{rule_uid}:svc")
        assert svc.props["opaque"] is True
        assert "syn" in svc.props["opaque_reason"]

    def test_normalize_object_group_ace_mints_an_opaque_net_object_not_a_silent_any(self):
        batch = _collector().normalize(ACL_RAW)
        rule_uid = "iosxe:sw1x:acl:edge-in~f89b1a37:3"
        rule = next(n for n in batch.nodes if n.uid == rule_uid)
        assert rule.props["src_any"] is False
        src = next(n for n in batch.nodes if n.uid == f"{rule_uid}:src")
        assert src.props["opaque"] is True
        assert "PARTNERS" in src.props["opaque_reason"]
        assert any(
            r.rel_type == "SRC" and r.start_uid == rule_uid and r.end_uid == src.uid for r in batch.rels
        )

    def test_normalize_outbound_binding_is_an_out_edge_not_a_rule_property(self):
        batch = _collector().normalize(ACL_RAW)
        rule = next(n for n in batch.nodes if n.uid == "iosxe:sw1x:acl:mgmt-out~bf66d13c:1")
        assert "out_interface" not in rule.props
        assert "in_interface" not in rule.props
        assert {
            (r.start_uid, r.props["direction"])
            for r in batch.rels
            if r.rel_type == "PROTECTED_BY" and r.end_uid == "iosxe:sw1x:acl:mgmt-out~bf66d13c"
        } == {(uid.interface(DEV, "Vlan10"), "out")}

    def test_normalize_uncollected_acl_binding_is_fail_visible_not_silent(self):
        """UNCOLLECTED-ACL is bound but never appears in `show ip access-lists`."""
        batch = _collector().normalize(ACL_RAW)
        rb_uid = "iosxe:sw1x:acl:uncollected-acl~6bc82fe0"
        rb = next(n for n in batch.nodes if n.uid == rb_uid)
        assert rb.props["default_action"] == "deny"
        enforces = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENFORCES"}
        assert (DEV, rb_uid) in enforces
        rule = next(n for n in batch.nodes if n.uid == f"{rb_uid}:1")
        src = next(n for n in batch.nodes if n.uid == f"{rb_uid}:1:src")
        assert src.props["opaque"] is True
        assert "UNCOLLECTED-ACL" in src.props["opaque_reason"]
        # the bound interface is not in `show interfaces`: no node, so no binding edge
        assert "in_interface" not in rule.props
        assert not [r for r in batch.rels if r.rel_type == "PROTECTED_BY" and r.end_uid == rb_uid]
        # the binding stays on the rulebase, in the config spelling
        assert rb.props["unreported_bindings"] == ["GigabitEthernet1/0/2 in"]


def test_nat_failure_degrades_to_no_nat_nodes(monkeypatch):
    """A NAT-less box refuses all three NAT commands."""
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd in (CMD_NAT, CMD_NAT_STATS, CMD_ACL):
            raise ssh.CommandFailed(f"{cmd!r} exited 1")
        return RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    inter = iosxe.parse(raw)
    assert inter["nat"] == {"if_roles": {}, "pools": {}, "rules": [], "acls": {}}
    batch = c.normalize(raw)
    assert not [n for n in batch.nodes if n.label in ("FwRulebase", "NatRule")]
    assert inter["interfaces"] and inter["rib"]


def test_acl_failure_leaves_nat_rules_approximate(monkeypatch):
    """NAT config collected but the ACLs refused: the rules land, marked approximate with no ORIG edges."""
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd == CMD_ACL:
            raise ssh.CommandFailed(f"{CMD_ACL!r} exited 1")
        return RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    batch = c.normalize(c.fetch())
    rule = next(n for n in batch.nodes if n.uid == "iosxe:sw1x:nat:inside-source:1")
    assert rule.props["approximate"] is True
    assert not [r for r in batch.rels if r.start_uid == rule.uid and r.rel_type == "ORIG_SRC"]


def test_cdp_failure_degrades_to_lldp_only_neighbors(monkeypatch, caplog):
    """A box with CDP disabled refuses the command."""
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd == CMD_CDP:
            raise ssh.CommandFailed("'show cdp neighbors detail' exited 1: CDP is not enabled")
        return RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    inter = iosxe.parse(raw)
    assert [n["proto"] for n in inter["neighbors"]] == ["lldp"]
    assert inter["interfaces"] and inter["rib"]
    assert "show cdp neighbors detail" in caplog.text and "continuing without it" in caplog.text


# --- BGP / route-policy: parse and normalize against the fixture texts ----------------------


class TestBgpRoutePolicy:
    def test_parse_bgp_process_asn_and_router_id(self):
        bgp = iosxe.parse(RAW)["routing"]["bgp"]
        assert bgp["asn"] == 65001
        assert bgp["router_id"] == "10.255.255.1"

    def test_parse_two_neighbors_one_ibgp_one_ebgp_by_asn(self):
        bgp = iosxe.parse(RAW)["routing"]["bgp"]
        by_ip = {n["peer_ip"]: n for n in bgp["neighbors"]}
        # remote-as equals the process's own asn for iBGP
        assert by_ip["10.0.0.2"]["remote_as"] == 65001 == bgp["asn"]
        assert by_ip["192.0.2.1"]["remote_as"] == 65010 != bgp["asn"]
        assert by_ip["10.0.0.2"]["route_map_in"] == "RM-IN"
        assert by_ip["192.0.2.1"]["prefix_list_in"] == "PL-CUSTOMER-IN"

    def test_parse_neighbor_shutdown_line_sets_shutdown_flag(self):
        """`neighbor <ip> shutdown` sets a flag on the neighbor dict."""
        text = BGP_TEXT.replace(
            "neighbor 10.0.0.2 description iBGP to RR1",
            "neighbor 10.0.0.2 description iBGP to RR1\n neighbor 10.0.0.2 shutdown",
        )
        bgp = iosxe.parse_bgp_config(text)
        by_ip = {n["peer_ip"]: n for n in bgp["neighbors"]}
        assert by_ip["10.0.0.2"]["shutdown"] is True
        assert "shutdown" not in by_ip["192.0.2.1"]

    def test_parse_redistribute_carries_route_map(self):
        bgp = iosxe.parse(RAW)["routing"]["bgp"]
        assert bgp["redistribute"] == [{"protocol": "static", "route_map": "RM-STATIC-TO-BGP"}]

    def test_parse_prefix_list_le_only_and_ge_le(self):
        entries = iosxe.parse(RAW)["routing"]["prefix_lists"]["PL-CUSTOMER-IN"]
        assert entries == [
            {"seq": 10, "action": "permit", "prefix": "10.1.0.0/16", "ge": None, "le": 24, "eq": None},
            {"seq": 20, "action": "permit", "prefix": "10.2.0.0/16", "ge": 25, "le": 32, "eq": None},
        ]

    def test_parse_route_map_two_clauses_continue_and_set(self):
        clauses = iosxe.parse(RAW)["routing"]["route_maps"]["RM-IN"]
        assert [c["seq"] for c in clauses] == [10, 20]
        first, second = clauses
        assert first["match_prefix_lists"] == ["PL-CUSTOMER-IN"]
        assert first["set_local_pref"] == 150
        assert first["continues"] is True and first["continue_seq"] == 20
        assert second["set_weight"] == 100
        assert second["set_communities"] == ["65001:100"]
        assert second["set_communities_additive"] is True

    def test_route_map_match_line_without_a_field_is_kept_on_the_entry(self):
        """`match ip address <acl>` and `match interface` have no match_* field."""
        text = ROUTE_MAP_TEXT + "route-map RM-ACL deny 10\n match ip address 10\n match interface Gi1\n"
        clause = iosxe.parse_route_maps(text)["RM-ACL"][0]
        assert clause["match_unsupported"] == ["match ip address 10", "match interface Gi1"]
        batch = _collector().normalize({**RAW, CMD_ROUTE_MAP: text})
        rm_acl = uid.route_policy(DEV, "route-map", "RM-ACL")
        entry = next(n for n in batch.nodes if n.uid == uid.route_policy_entry(rm_acl, 10))
        assert entry.props["match_unsupported"] == ["match ip address 10", "match interface Gi1"]
        rm_in = uid.route_policy(DEV, "route-map", "RM-IN")
        read = next(n for n in batch.nodes if n.uid == uid.route_policy_entry(rm_in, 10))
        assert "match_unsupported" not in read.props

    def test_normalize_routing_process_and_vrf(self):
        batch = _collector().normalize(RAW)
        proc = uid.routing_process(DEV, "default", "bgp")
        node = next(n for n in batch.nodes if n.uid == proc)
        assert node.label == "RoutingProcess"
        assert node.props["proto"] == "bgp"
        assert node.props["asn"] == 65001
        assert node.props["router_id"] == "10.255.255.1"
        assert (proc, uid.vrf(DEV, "default")) in [
            (r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IN_VRF" and r.start_uid == proc
        ]

    def test_normalize_bgp_sessions_local_and_peer_asn(self):
        batch = _collector().normalize(RAW)
        proc = uid.routing_process(DEV, "default", "bgp")
        ibgp = next(n for n in batch.nodes if n.uid == uid.bgp_session(proc, "10.0.0.2", "default"))
        ebgp = next(n for n in batch.nodes if n.uid == uid.bgp_session(proc, "192.0.2.1", "default"))
        assert ibgp.props["local_asn"] == ebgp.props["local_asn"] == 65001
        assert ibgp.props["peer_asn"] == 65001
        assert ebgp.props["peer_asn"] == 65010
        assert ibgp.props["import_policy_name"] == "RM-IN" and ibgp.props["import_policy_kind"] == "route-map"
        assert (
            ebgp.props["import_policy_name"] == "PL-CUSTOMER-IN"
            and ebgp.props["import_policy_kind"] == "prefix-list"
        )
        has_edges = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "HAS"}
        assert (proc, ibgp.uid) in has_edges and (proc, ebgp.uid) in has_edges

    def test_normalize_bgp_session_shutdown_neighbor_gets_state_shutdown(self):
        """The shutdown flag lands on BgpSession.state."""
        raw = dict(
            RAW,
            **{
                CMD_BGP: BGP_TEXT.replace(
                    "neighbor 10.0.0.2 description iBGP to RR1",
                    "neighbor 10.0.0.2 description iBGP to RR1\n neighbor 10.0.0.2 shutdown",
                )
            },
        )
        batch = _collector().normalize(raw)
        proc = uid.routing_process(DEV, "default", "bgp")
        ibgp = next(n for n in batch.nodes if n.uid == uid.bgp_session(proc, "10.0.0.2", "default"))
        ebgp = next(n for n in batch.nodes if n.uid == uid.bgp_session(proc, "192.0.2.1", "default"))
        assert ibgp.props["state"] == "shutdown"
        assert "state" not in ebgp.props

    def test_normalize_bgp_session_filtered_by_resolves_to_route_policy(self):
        batch = _collector().normalize(RAW)
        proc = uid.routing_process(DEV, "default", "bgp")
        ibgp = uid.bgp_session(proc, "10.0.0.2", "default")
        ebgp = uid.bgp_session(proc, "192.0.2.1", "default")
        rm_in = uid.route_policy(DEV, "route-map", "RM-IN")
        pl = uid.route_policy(DEV, "prefix-list", "PL-CUSTOMER-IN")
        filtered = [(r.start_uid, r.end_uid, r.key) for r in batch.rels if r.rel_type == "FILTERED_BY"]
        assert (ibgp, rm_in, {"direction": "in"}) in filtered
        assert (ebgp, pl, {"direction": "in"}) in filtered

    def test_normalize_redistribute_filtered_by_route_map(self):
        batch = _collector().normalize(RAW)
        proc = uid.routing_process(DEV, "default", "bgp")
        rm_static = uid.route_policy(DEV, "route-map", "RM-STATIC-TO-BGP")
        filtered = [(r.start_uid, r.end_uid, r.key) for r in batch.rels if r.rel_type == "FILTERED_BY"]
        assert (proc, rm_static, {"direction": "redistribute", "protocol": "static"}) in filtered

    def test_normalize_route_policy_entries_continue_and_set_clause(self):
        batch = _collector().normalize(RAW)
        rm_in = uid.route_policy(DEV, "route-map", "RM-IN")
        first = next(n for n in batch.nodes if n.uid == uid.route_policy_entry(rm_in, 10))
        second = next(n for n in batch.nodes if n.uid == uid.route_policy_entry(rm_in, 20))
        assert first.props["kind"] == "clause" and first.props["action"] == "permit"
        assert first.props["continues"] is True and first.props["continue_seq"] == 20
        assert first.props["set_local_pref"] == 150
        assert second.props["set_weight"] == 100
        assert second.props["set_communities"] == ["65001:100"]
        assert second.props["set_communities_additive"] is True
        has_rule = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "HAS_RULE"}
        assert (rm_in, first.uid) in has_rule and (rm_in, second.uid) in has_rule

    def test_normalize_route_policy_entry_references_resolves_prefix_list(self):
        batch = _collector().normalize(RAW)
        rm_in = uid.route_policy(DEV, "route-map", "RM-IN")
        entry = uid.route_policy_entry(rm_in, 10)
        pl = uid.route_policy(DEV, "prefix-list", "PL-CUSTOMER-IN")
        refs = [(r.start_uid, r.end_uid, r.key) for r in batch.rels if r.rel_type == "REFERENCES"]
        assert (entry, pl, {"kind": "prefix-list"}) in refs

    def test_normalize_prefix_list_entries_min_max_len(self):
        batch = _collector().normalize(RAW)
        pl = uid.route_policy(DEV, "prefix-list", "PL-CUSTOMER-IN")
        first = next(n for n in batch.nodes if n.uid == uid.prefix_list_entry(pl, 10))
        second = next(n for n in batch.nodes if n.uid == uid.prefix_list_entry(pl, 20))
        assert first.label == "PrefixListEntry"
        # le 24 alone on a /16 base: ge defaults to the base prefix's own length
        assert first.props["min_len"] == 16 and first.props["max_len"] == 24
        assert second.props["min_len"] == 25 and second.props["max_len"] == 32
        has_rule = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "HAS_RULE"}
        assert (pl, first.uid) in has_rule and (pl, second.uid) in has_rule

    def test_normalize_prefix_list_line_without_ge_le_eq_is_an_exact_match(self):
        """A line with no `ge`, `le` or `eq` matches its own prefix length only, so a
        default-only list permits 0.0.0.0/0 and nothing else."""
        raw = {
            **RAW,
            CMD_PREFIX_LIST: PREFIX_LIST_TEXT
            + "\nip prefix-list DEFAULT-ONLY seq 5 permit 0.0.0.0/0"
            + "\nip prefix-list DEFAULT-ONLY seq 10 permit 10.20.0.0/16\n",
        }
        batch = _collector().normalize(raw)
        pl = uid.route_policy(DEV, "prefix-list", "DEFAULT-ONLY")
        default = next(n for n in batch.nodes if n.uid == uid.prefix_list_entry(pl, 5))
        exact = next(n for n in batch.nodes if n.uid == uid.prefix_list_entry(pl, 10))
        assert (default.props["min_len"], default.props["max_len"]) == (0, 0)
        assert (exact.props["min_len"], exact.props["max_len"]) == (16, 16)
        entries = [default.props, exact.props]
        assert prefixlist.evaluate(entries, "0.0.0.0/0")
        assert prefixlist.evaluate(entries, "10.20.0.0/16")
        assert not prefixlist.evaluate(entries, "10.20.1.0/24")
        assert not prefixlist.evaluate(entries, "8.8.8.0/24")

    def test_normalize_dangling_prefix_list_reference_warns_and_has_no_references_edge(self, caplog):
        """No REFERENCES edge is written for a target absent from this batch."""
        with caplog.at_level("WARNING"):
            batch = _collector().normalize(RAW)
        rm_dangling = uid.route_policy(DEV, "route-map", "RM-DANGLING")
        entry = next(n for n in batch.nodes if n.uid == uid.route_policy_entry(rm_dangling, 10))
        assert entry.props["match_prefix_lists"] == ["PL-GHOST"]
        assert not [r for r in batch.rels if r.rel_type == "REFERENCES" and r.start_uid == entry.uid]
        assert "PL-GHOST" in caplog.text and "not captured" in caplog.text

    def test_normalize_no_bgp_config_yields_no_routing_nodes(self, monkeypatch):
        """A box with no BGP/prefix-list/route-map config captured (`routing` is
        None) yields no routing nodes."""
        raw = {k: v for k, v in RAW.items() if k not in (CMD_BGP, CMD_PREFIX_LIST, CMD_ROUTE_MAP)}
        inter = iosxe.parse(raw)
        assert inter["routing"] is None
        batch = _collector().normalize(raw)
        assert not [n for n in batch.nodes if n.label in ("RoutingProcess", "BgpSession", "RoutePolicy")]


# --- OSPF: parse/normalize/side_tables against the fixture texts ----------------------------


class TestOspf:
    def test_parse_process_router_id_and_two_areas(self):
        ospf = iosxe.parse(OSPF_RAW)["ospf"]
        proc = ospf["processes"][0]
        assert proc["process"] == "1"
        assert proc["router_id"] == "10.255.255.1"
        areas = {a["area_id"]: a["type"] for a in proc["areas"]}
        assert areas == {AREA_0: "normal", AREA_10: "stub"}

    def test_parse_redistribute_carries_route_map_from_the_config_extract(self):
        proc = iosxe.parse(OSPF_RAW)["ospf"]["processes"][0]
        assert proc["redistribute"] == [{"protocol": "static", "route_map": "RM-STATIC-TO-BGP"}]

    def test_parse_interfaces_carry_area_cost_network_type_and_passive(self):
        by_name = {i["name"]: i for i in iosxe.parse(OSPF_RAW)["ospf"]["interfaces"]}
        backbone = by_name["GigabitEthernet1/0/1"]
        assert (backbone["area"], backbone["cost"], backbone["network_type"], backbone["passive"]) == (
            AREA_0,
            1,
            "broadcast",
            False,
        )
        stub_if = by_name["GigabitEthernet1/0/3"]
        assert (stub_if["area"], stub_if["cost"], stub_if["passive"]) == (AREA_10, 10, True)

    def test_parse_adjacency_from_the_neighbor_template(self):
        adjacencies = iosxe.parse(OSPF_RAW)["ospf"]["adjacencies"]
        assert len(adjacencies) == 1
        adj = adjacencies[0]
        assert adj["local_interface"] == "GigabitEthernet1/0/1"
        assert adj["neighbor_router_id"] == "10.255.0.2"
        assert adj["neighbor_ip"] == "10.0.0.2"
        assert adj["state"] == "FULL/BDR"
        # the area comes from the interface table, not the neighbor table
        assert adj["area"] == AREA_0

    def test_parse_router_lsa_through_ntc_templates_carries_its_links(self):
        lsa = next(r for r in iosxe.parse(OSPF_RAW)["ospf"]["lsdb"] if r["lsa_type"] == "router")
        assert (lsa["area"], lsa["lsid"], lsa["adv_router"]) == (AREA_0, "10.255.255.1", "10.255.255.1")
        assert (lsa["age"], lsa["seq"]) == (120, 0x80000005)
        assert lsa["metric"] is None
        assert lsa["links"] == [
            {"link_type": "point-to-point", "link_id": "10.255.0.2", "link_data": "10.0.0.1", "metric": 40},
            {"link_type": "stub", "link_id": "10.0.0.0", "link_data": "255.255.255.0", "metric": 40},
        ]

    def test_parse_network_lsa_through_ntc_templates_carries_attached_routers(self):
        lsa = next(r for r in iosxe.parse(OSPF_RAW)["ospf"]["lsdb"] if r["lsa_type"] == "network")
        assert lsa["area"] == AREA_0
        assert lsa["attached_routers"] == ["10.255.255.1", "10.255.255.2"]
        assert lsa["mask"] == "255.255.255.0"

    def test_parse_summary_lsa_through_the_fixture_first_parser(self):
        lsa = next(r for r in iosxe.parse(OSPF_RAW)["ospf"]["lsdb"] if r["lsa_type"] == "summary")
        assert (lsa["area"], lsa["lsid"], lsa["mask"], lsa["metric"]) == (
            AREA_10,
            "10.10.10.0",
            "255.255.255.0",
            20,
        )

    def test_parse_asbr_summary_lsa_carries_the_asbr_router_id_as_its_lsid(self):
        lsa = next(r for r in iosxe.parse(OSPF_RAW)["ospf"]["lsdb"] if r["lsa_type"] == "asbr-summary")
        assert (lsa["area"], lsa["lsid"], lsa["metric"]) == (AREA_0, "10.255.255.3", 30)
        assert lsa["mask"] is None

    def test_parse_external_lsa_belongs_to_no_area(self):
        """A type-5 AS-external LSA is flooded domain-wide."""
        lsa = next(r for r in iosxe.parse(OSPF_RAW)["ospf"]["lsdb"] if r["lsa_type"] == "external")
        assert lsa["area"] is None
        assert lsa["forwarding_address"] == "10.0.0.2"
        assert lsa["metric_type"] == 2
        assert lsa["metric"] == 100

    def test_parse_nssa_external_lsa_belongs_to_its_own_area(self):
        """A type-7 NSSA-external floods only within its own (NSSA) area."""
        lsa = next(r for r in iosxe.parse(OSPF_RAW)["ospf"]["lsdb"] if r["lsa_type"] == "nssa-external")
        assert lsa["area"] == AREA_10
        assert lsa["forwarding_address"] == AREA_0
        assert lsa["metric_type"] == 2
        assert lsa["metric"] == 50

    def test_parse_absent_for_a_payload_that_predates_the_capture(self):
        """A raw file without the OSPF commands has no `ospf` key."""
        older = {k: v for k, v in RAW.items() if k not in OSPF_COMMANDS}
        assert iosxe.parse_ospf(older) is None
        assert "ospf" not in iosxe.parse(older)

    def test_normalize_ospf_process_is_a_routing_process_in_its_vrf(self):
        batch = _collector().normalize(OSPF_RAW)
        proc = uid.routing_process(DEV, "default", "ospf-1")
        node = next(n for n in batch.nodes if n.uid == proc)
        assert node.label == "RoutingProcess"
        assert node.props["proto"] == "ospf"
        assert node.props["process_id"] == "1"
        assert node.props["router_id"] == "10.255.255.1"
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
        gi1 = uid.interface(DEV, "GigabitEthernet1/0/1")
        gi3 = uid.interface(DEV, "GigabitEthernet1/0/3")
        assert (gi1, area0) in in_area and (gi3, area10) in in_area
        assert in_area[(gi1, area0)].props == {"cost": 1, "network_type": "broadcast", "passive": False}
        assert in_area[(gi3, area10)].props == {"cost": 10, "network_type": "broadcast", "passive": True}

    def test_normalize_adjacency_endpoints_its_local_interface(self):
        batch = _collector().normalize(OSPF_RAW)
        proc = uid.routing_process(DEV, "default", "ospf-1")
        iu = uid.interface(DEV, "GigabitEthernet1/0/1")
        adju = uid.ospf_adjacency(proc, iu, "10.255.0.2")
        adj = next(n for n in batch.nodes if n.uid == adju)
        assert adj.props["state"] == "FULL/BDR"
        assert adj.props["neighbor_ip"] == "10.0.0.2"
        assert any(r.rel_type == "ENDPOINT" and r.start_uid == adju and r.end_uid == iu for r in batch.rels)
        assert any(r.rel_type == "HAS" and r.start_uid == proc and r.end_uid == adju for r in batch.rels)

    def test_normalize_redistribute_resolves_to_the_shared_bgp_route_map(self):
        """Both redistributions resolve to the one RoutePolicy node the BGP capture defines."""
        batch = _collector().normalize(OSPF_RAW)
        proc = uid.routing_process(DEV, "default", "ospf-1")
        rm_static = uid.route_policy(DEV, "route-map", "RM-STATIC-TO-BGP")
        filtered = [(r.start_uid, r.end_uid, r.key) for r in batch.rels if r.rel_type == "FILTERED_BY"]
        assert (proc, rm_static, {"direction": "redistribute", "protocol": "static"}) in filtered

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
        assert {r["context_uid"] for r in rows} == {DEFAULT_VRF_UID}
        assert {r["process"] for r in rows} == {"1"}

    def test_the_lsdb_table_is_declared_so_a_run_accounts_for_it(self):
        assert "ospf_lsdb" in IosxeCollector.SIDE_TABLES

    def test_a_device_with_no_router_ospf_process_reports_the_lsdb_table_unsupported(self):
        """IOS-XE never refuses an OSPF command for lack of the feature."""
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
    return IosxeCollector(
        IosxeConfig(
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
    return uid.bgp_session(uid.routing_process(DEV, "default", "bgp"), peer_ip, "default")


# the ARP command of the one VRF the fixture's `show vrf` names
VRF_ARP = iosxe.CMD_ARP_VRF.format(vrf="mgmt")


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
        assert fake.commands[: len(iosxe.COMMANDS)] == list(iosxe.COMMANDS)
        # the ARP table of the one VRF comes first
        assert fake.commands[len(iosxe.COMMANDS)] == VRF_ARP
        derived = fake.commands[len(iosxe.COMMANDS) + 1 :]
        assert derived[0] == CMD_BGP_SESSIONS
        assert derived[1] == iosxe.CMD_BGP_NEIGHBORS
        assert derived[2:5] == [
            iosxe.bgp_route_command("10.0.0.2", d) for d in ("received", "accepted", "advertised")
        ]
        assert len(derived) == 2 + 3 * 2  # the session and neighbor tables, then two peers
        assert CMD_BGP_SESSIONS in raw

    def test_capture_none_asks_the_device_for_nothing_beyond_the_static_commands(self, monkeypatch):
        collector, raw, fake = _fetch(monkeypatch, capture="none")
        assert fake.commands == [*iosxe.COMMANDS, VRF_ARP]
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
        assert fake.commands == [*iosxe.COMMANDS, VRF_ARP, CMD_BGP_SESSIONS, iosxe.CMD_BGP_NEIGHBORS]
        outcomes = collector.table_outcomes(raw)
        # the session table was read, so this run states nothing about it and
        # the write's own outcome stands; only the path table was left out
        assert "bgp_sessions" not in outcomes
        assert outcomes["bgp_session_routes"].status == "not-captured"
        tables = collector.side_tables(raw)
        assert [r["peer_ip"] for r in tables["bgp_sessions"]] == ["10.0.0.2", "192.0.2.1"]
        assert tables["bgp_session_routes"] == []

    def test_parse_bgp_sessions_carries_the_device_word_for_each_state(self):
        sessions = iosxe.parse(RAW)["bgp_observed"]["sessions"]
        assert [(s["peer_ip"], s["state"], s["prefixes_received"]) for s in sessions] == [
            ("10.0.0.2", "Established", 1),
            ("192.0.2.1", "Idle", None),
        ]
        # this command reports no advertised count or capabilities
        assert all(
            s["established_since_ms"] is None
            and s["prefixes_advertised"] is None
            and s["capabilities"] is None
            for s in sessions
        )

    def test_parse_bgp_paths_carries_attributes_and_the_best_marking(self):
        routes = iosxe.parse(RAW)["bgp_observed"]["routes"]
        accepted = [r for r in routes if r["peer_ip"] == "10.0.0.2" and r["direction"] == "accepted"]
        assert len(accepted) == 1
        row = accepted[0]
        assert row["prefix"] == "10.20.0.0/24"
        assert row["next_hop"] == "10.0.0.2"
        assert (row["local_pref"], row["med"], row["origin"]) == (150, 0, "i")
        assert row["best"] is True
        assert row["path_id"] is None
        assert row["communities"] is None

    def test_a_received_direction_is_pre_decision_and_carries_no_best_marking(self):
        routes = iosxe.parse(RAW)["bgp_observed"]["routes"]
        received = [r for r in routes if r["peer_ip"] == "192.0.2.1" and r["direction"] == "received"]
        assert sorted(r["prefix"] for r in received) == ["10.20.0.0/24", "198.51.100.0/24"]
        assert all(r["best"] is None for r in received)

    def test_side_tables_join_observations_to_the_session_node_and_its_context(self):
        collector = _bgp_collector()
        tables = collector.side_tables(RAW)
        batch = collector.normalize(RAW)
        nodes = {n.uid for n in batch.nodes if n.label == "BgpSession"}
        for table in ("bgp_sessions", "bgp_session_routes"):
            assert tables[table]
            for row in tables[table]:
                assert row["device_uid"] == DEV
                assert row["context_uid"] == DEFAULT_VRF_UID
        # every observed session that is also configured joins a node of this run
        assert {r["session_uid"] for r in tables["bgp_sessions"]} <= nodes
        assert _session_uid("10.0.0.2") in nodes

    def test_observed_path_rows_carry_the_interval_columns_and_the_stage(self):
        rows = _bgp_collector().side_tables(RAW)["bgp_session_routes"]
        row = next(r for r in rows if r["direction"] == "advertised" and r["peer_ip"] == "10.0.0.2")
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
        outcome = directions[(_session_uid("10.0.0.2"), "received")]
        assert outcome.status == "not-captured"
        assert "soft-reconfiguration" in outcome.detail
        assert outcome.row_count is None
        # the same session's other two directions were captured
        assert directions[(_session_uid("10.0.0.2"), "accepted")].status == "complete"
        assert directions[(_session_uid("10.0.0.2"), "advertised")].status == "complete"

    def test_a_direction_the_box_answered_with_nothing_is_empty_not_uncaptured(self, monkeypatch):
        collector, raw, _fake = _fetch(monkeypatch)
        down = _directions(collector, raw)[(_session_uid("192.0.2.1"), "accepted")]
        assert (down.status, down.row_count) == ("complete-empty", 0)

    def test_a_box_without_bgp_reads_unsupported_not_failed(self, monkeypatch):
        """`classify_command_failure` reads the device's own rejection banner."""
        command = iosxe.bgp_route_command("10.0.0.2", "accepted")
        collector, raw, _fake = _fetch(
            monkeypatch, failures={command: f"{command!r} rejected by device: % Invalid input detected"}
        )
        outcome = _directions(collector, raw)[(_session_uid("10.0.0.2"), "accepted")]
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
        command = iosxe.bgp_route_command("10.0.0.2", "advertised")
        collector, raw, _fake = _fetch(
            monkeypatch, failures={command: f"{command!r} exited 1: Permission denied"}
        )
        assert _directions(collector, raw)[(_session_uid("10.0.0.2"), "advertised")].status == "failed"

    def test_the_session_table_is_volatile_so_its_timers_never_defeat_the_skip(self):
        assert CMD_BGP_SESSIONS in IosxeCollector.VOLATILE_RAW_KEYS

    def test_a_listen_range_neighbor_is_not_a_capture_target(self):
        """A `neighbor <prefix>` listen range names no single address to query."""
        bgp = {"neighbors": [{"peer_ip": "10.1.0.0/16"}, {"peer_ip": "10.1.1.2"}]}
        assert iosxe.bgp_capture_targets(bgp) == ["10.1.1.2"]

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


# --- first-hop redundancy (HSRP/VRRP) --------------------------------------------------
#
# `show standby brief` and `show vrrp brief` in the column form the ntc-templates
# `cisco_ios_show_standby_brief`/`cisco_ios_show_vrrp_brief` templates parse. The
# interface column is abbreviated the way the box prints it; the stage matches it
# to the full names `show interfaces` spells.

STANDBY_TEXT = """\
Interface   Grp  Pri P State   Active          Standby         Virtual IP
Vl10        10   110 P Active  local           10.10.10.2      10.10.10.254
Gi1/0/3     3    90    Standby 10.0.3.2        local           10.0.3.254
"""

VRRP_TEXT = """\
Interface          Grp Pri Time  Own Pre State   Master addr     Group addr
Gi1/0/9            9   100 3609       Y  Master  10.0.9.1        10.0.9.254
"""

FHRP_RAW = {**RAW, CMD_STANDBY: STANDBY_TEXT, CMD_VRRP: VRRP_TEXT}


def _fhrp_rels(batch, rel_type, start, end):
    return [r for r in batch.rels if r.rel_type == rel_type and r.start_uid == start and r.end_uid == end]


def test_fhrp_commands_are_optional_and_join_the_command_set():
    for cmd in (CMD_STANDBY, CMD_VRRP):
        assert cmd in iosxe.COMMANDS
        assert IosxeCollector.OPTIONAL_COMMANDS[cmd] == ""
    assert iosxe.SECTIONS["hsrp"].command == CMD_STANDBY
    assert iosxe.SECTIONS["vrrp"].command == CMD_VRRP


def test_parse_standby_and_vrrp_briefs_into_fhrp_rows_with_the_printed_interface_names():
    inter = iosxe.parse(FHRP_RAW)
    assert inter["fhrp"] == [
        {
            # as the brief prints it; the stage resolves it against the interface
            # table's `Vlan10` (`IfNameResolver`)
            "interface": "Vl10",
            "kind": "hsrp",
            "group": 10,
            "vip": "10.10.10.254",
            "priority": 110,
            "state": "Active",
            "virtual_mac": None,
        },
        {
            "interface": "Gi1/0/3",
            "kind": "hsrp",
            "group": 3,
            "vip": "10.0.3.254",
            "priority": 90,
            "state": "Standby",
            "virtual_mac": None,
        },
        {
            "interface": "Gi1/0/9",
            "kind": "vrrp",
            "group": 9,
            "vip": "10.0.9.254",
            "priority": 100,
            "state": "Master",
            "virtual_mac": None,
        },
    ]
    assert iosxe.parse(RAW)["fhrp"] == []
    old = {k: v for k, v in RAW.items() if k not in (CMD_STANDBY, CMD_VRRP)}
    assert iosxe.parse(old)["fhrp"] == []


def test_normalize_hsrp_virtual_address_joins_the_member_prefix_in_its_vrf():
    """Vlan10 sits in vrf mgmt with 10.10.10.1/24: the virtual address takes
    the same VRF and the same prefix length, so one Prefix serves both."""
    batch = _collector().normalize(FHRP_RAW)
    iu = uid.interface(DEV, "Vlan10")
    vru = uid.vrf(DEV, "mgmt")
    vip = uid.ip(vru, "10.10.10.254")
    (edge,) = _fhrp_rels(batch, "HAS_IP", iu, vip)
    assert edge.props == {"fhrp": "hsrp", "group": 10, "state": "active"}
    # one Prefix in the SVI's context serves both addresses
    prefixes = [
        n
        for n in batch.nodes
        if n.label == "Prefix" and n.props.get("cidr") == "10.10.10.0/24" and n.props.get("anchor") == vru
    ]
    assert [n.uid for n in prefixes] == [uid.prefix(vru, "10.10.10.0/24")]
    assert _fhrp_rels(batch, "IN", vip, prefixes[0].uid)
    assert _fhrp_rels(batch, "IN", uid.ip(vru, "10.10.10.1"), prefixes[0].uid)


def test_normalize_emits_one_fhrp_group_per_virtual_address_with_member_priority():
    batch = _collector().normalize(FHRP_RAW)
    groups = {n.props["vip"]: n for n in batch.nodes if n.label == "FhrpGroup"}
    assert set(groups) == {"10.10.10.254", "10.0.3.254", "10.0.9.254"}
    assert groups["10.10.10.254"].props["kind"] == "hsrp"
    assert groups["10.0.9.254"].props["kind"] == "vrrp"
    gi3 = uid.interface(DEV, "GigabitEthernet1/0/3")
    (standby,) = _fhrp_rels(batch, "MEMBER_OF", gi3, groups["10.0.3.254"].uid)
    assert standby.props == {"priority": 90, "state": "standby"}
    gi9 = uid.interface(DEV, "GigabitEthernet1/0/9")
    (master,) = _fhrp_rels(batch, "MEMBER_OF", gi9, groups["10.0.9.254"].uid)
    assert master.props == {"priority": 100, "state": "master"}
    for vip, group in groups.items():
        vru = uid.vrf(DEV, "mgmt" if vip.startswith("10.10.") else "default")
        assert _fhrp_rels(batch, "HAS_IP", group.uid, uid.ip(vru, vip))


def test_the_base_fixture_emits_no_fhrp_group():
    batch = _collector().normalize(RAW)
    assert not [n for n in batch.nodes if n.label == "FhrpGroup"]


def test_a_box_that_rejects_the_fhrp_commands_records_the_sections_unsupported(monkeypatch):
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd in (CMD_STANDBY, CMD_VRRP):
            raise ssh.CommandFailed(f"{cmd!r} exited 1: % Invalid input detected at '^' marker.")
        return FHRP_RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    batch = c.normalize(c.fetch())
    assert batch.sections["hsrp"].status == "unsupported"
    assert batch.sections["vrrp"].status == "unsupported"
    assert not [n for n in batch.nodes if n.label == "FhrpGroup"]
    assert batch.sections["interfaces"].status == "ok"


def test_fhrp_sections_read_empty_on_the_base_fixture_and_ok_with_groups(monkeypatch):
    base = _sections(monkeypatch, RAW)
    assert (base["hsrp"].status, base["vrrp"].status) == ("empty", "empty")
    full = _sections(monkeypatch, FHRP_RAW)
    assert (full["hsrp"].status, full["vrrp"].status) == ("ok", "ok")
    assert full["hsrp"].detail == ""


def test_normalize_aggregate_attribute_map_lands_on_the_edge_and_the_process():
    """An aggregate's `attribute-map` is recorded raw on its ORIGINATES edge
    and attached to the process as FILTERED_BY {redistribute, aggregate} when
    it resolves; an undefined one keeps the raw name and gets no edge."""
    raw = dict(
        RAW,
        **{
            CMD_BGP: BGP_TEXT.replace(
                "  redistribute static route-map RM-STATIC-TO-BGP",
                "  aggregate-address 10.0.0.0 255.0.0.0 summary-only attribute-map RM-STATIC-TO-BGP\n"
                "  aggregate-address 10.1.0.0 255.255.0.0 attribute-map RM-GHOST\n"
                "  redistribute static route-map RM-STATIC-TO-BGP",
            )
        },
    )
    batch = _collector().normalize(raw)
    proc = uid.routing_process(DEV, "default", "bgp")
    vru = uid.vrf(DEV, "default")
    originates = {r.end_uid: r.props for r in batch.rels if r.rel_type == "ORIGINATES" and r.start_uid == vru}
    assert originates[uid.prefix(vru, "10.0.0.0/8")] == {
        "proto": "aggregate",
        "summary_only": True,
        "as_set": False,
        "attribute_map": "RM-STATIC-TO-BGP",
        "unsupported_options": [],
    }
    assert originates[uid.prefix(vru, "10.1.0.0/16")]["attribute_map"] == "RM-GHOST"
    filtered = [(r.end_uid, r.key) for r in batch.rels if r.rel_type == "FILTERED_BY" and r.start_uid == proc]
    rm = uid.route_policy(DEV, "route-map", "RM-STATIC-TO-BGP")
    assert (rm, {"direction": "redistribute", "protocol": "aggregate"}) in filtered
    assert not [end for end, key in filtered if key.get("protocol") == "aggregate" and end != rm]


def test_no_ospf_database_command_carries_a_detail_keyword():
    """IOS-XE 17.12 answers `show ip ospf database router detail` with `Line has invalid
    autocommand`."""
    database = [command for command in OSPF_COMMANDS if command.startswith("show ip ospf database ")]
    assert len(database) == 6
    assert not [command for command in database if command.split()[-1] == "detail"]


def test_an_invalid_autocommand_line_is_a_rejected_command_that_reads_unsupported():
    """IOS-XE answers a command its parser does not accept on the exec channel
    with `Line has invalid autocommand "..."`, exit 0 and no `%`."""
    from hst.collectors import ssh
    from hst.collectors.cli_collector import classify_command_failure

    line = 'Line has invalid autocommand "show ip ospf database router detail"'
    assert ssh._cli_rejection("\n" + line + "\n") == line
    failure = ssh.CommandFailed(f"{iosxe.CMD_OSPF_DB_ROUTER!r} rejected by device: {line}")
    assert classify_command_failure(failure)[0] == "unsupported"


# What IOS/IOS-XE prints, exit 0 and no `%`, for a command TACACS+ command
# authorization denies the account.
AUTHZ_DENIED = "Command authorization failed.\n"


def test_a_command_authorization_refusal_is_a_rejected_command_that_reads_unauthorized():
    """IOS-XE's line, then the `%` forms IOS-XR and NX-OS print."""
    from hst.collectors import ssh
    from hst.collectors.cli_collector import classify_command_failure

    for line in (
        "Command authorization failed.",
        "% Authorization failed.",
        "% Permission denied for the role",
        "% This command is not authorized",
    ):
        assert ssh._cli_rejection(line + "\n") == line
        failure = ssh.CommandFailed(f"{CMD_INTERFACE_CONFIG!r} rejected by device: {line}")
        assert classify_command_failure(failure)[0] == "unauthorized"


def test_an_authorization_refusal_recorded_ok_reads_unauthorized_not_an_empty_config(monkeypatch):
    """A payload whose fetch recorded the refusal `ok` keeps the line as the answer."""
    from hst.core.model import section_verdict

    denied = (CMD_INTERFACE_CONFIG, CMD_NAT, CMD_BGP)
    sections = _sections(monkeypatch, {**RAW, **dict.fromkeys(denied, AUTHZ_DENIED)})
    for name in ("interface_config", "nat", "bgp"):
        assert sections[name].status == "unauthorized"
        assert "Command authorization failed." in sections[name].detail
    assert sections["interfaces"].status == "ok"
    assert section_verdict(sections, IosxeCollector.AUTHORITATIVE_SECTIONS) == "partial"


def test_an_authorization_refusal_of_show_interfaces_fails_the_device(monkeypatch):
    from hst.core.model import section_verdict

    sections = _sections(monkeypatch, {**RAW, CMD_INTERFACES: AUTHZ_DENIED})
    assert sections["interfaces"].status == "unauthorized"
    assert section_verdict(sections, IosxeCollector.AUTHORITATIVE_SECTIONS) == "failed"


# --- an optional command the template cannot read ---------------------------------------
#
# The device answered, so the fetch recorded `ok`, but the template sends the
# answer to its Error rule. That costs the command's own section, as a refused
# optional command does, and never the device.


def test_an_unreadable_optional_answer_is_a_malformed_section_and_the_device_loads(monkeypatch):
    """An answer no detector knows makes the OSPF database template raise."""
    outputs = {**RAW, CMD_OSPF_DB_ROUTER: "\nA device answer no detector knows\n"}
    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    batch = c.normalize(c.fetch())
    section = batch.sections["ospf_lsdb_router"]
    assert section.status == "malformed"
    assert "A device answer no detector knows" in section.detail
    assert CMD_OSPF_DB_ROUTER in section.detail
    assert batch.sections["interfaces"].status == "ok"
    assert batch.sections["rib"].status == "ok"
    assert any(n.label == "Device" for n in batch.nodes)


def test_an_unreadable_access_list_costs_the_acl_section_only(monkeypatch):
    outputs = {**RAW, CMD_ACL: "Extended IP access list EDGE-IN\n    10 deny icmp any any no-such-type\n"}
    sections = _sections(monkeypatch, outputs)
    assert sections["acl"].status == "malformed"
    assert "no-such-type" in sections["acl"].detail
    assert sections["nat"].status == "ok"
    assert sections["rib"].status == "ok"


def test_an_unreadable_required_answer_fails_the_device(monkeypatch):
    """`show vrf` is required: without it no interface has its VRF."""
    import pytest
    from textfsm import TextFSMError

    FakeSshSession({**RAW, CMD_VRF: "A device answer no detector knows\n"}).install(monkeypatch)
    c = _collector()
    with pytest.raises(TextFSMError, match="show vrf"):
        c.normalize(c.fetch())


def test_a_parse_failure_does_not_hide_a_refusal_already_recorded():
    """A refused command keeps its own status. `malformed` replaces only an
    `ok` the fetch recorded, or no record at all."""
    from hst.collectors.base import RAW_OUTCOMES_KEY
    from hst.collectors.cli_collector import PARSE_FAILURES_KEY, effective_outcomes

    recorded = {"a": {"status": "unsupported", "detail": "% Invalid input"}, "b": {"status": "ok"}}
    raw = {RAW_OUTCOMES_KEY: recorded}
    outcomes = effective_outcomes(raw, {PARSE_FAILURES_KEY: {"a": "err a", "b": "err b", "c": "err c"}})
    assert (outcomes["a"].status, outcomes["a"].detail) == ("unsupported", "% Invalid input")
    assert (outcomes["b"].status, outcomes["b"].detail) == ("malformed", "err b")
    assert (outcomes["c"].status, outcomes["c"].detail) == ("malformed", "err c")


# --- unread set lines, community lists and AS-path access lists ----------


def test_a_route_map_set_line_without_a_field_is_kept_on_the_entry():
    """A set line no set_* field reads lands in `set_unsupported`; `set as-path
    prepend last-as` is not read as AS numbers, `set community none` not as a
    community named `none`, and `set ip next-hop peer-address` not as an
    address."""
    text = (
        "route-map RM-SET permit 10\n"
        " set as-path prepend last-as 2\n"
        " set community none\n"
        " set ip next-hop peer-address\n"
        " set extcommunity rt 65000:1\n"
        " set local-preference 200\n"
    )
    clause = iosxe.parse_route_maps(text)["RM-SET"][0]
    assert clause["set_unsupported"] == [
        "set as-path prepend last-as 2",
        "set community none",
        "set ip next-hop peer-address",
        "set extcommunity rt 65000:1",
    ]
    assert clause["set_as_path_prepend"] == []
    assert clause["set_communities"] == []
    assert clause["set_next_hop"] is None
    assert clause["set_local_pref"] == 200


def test_match_community_exact_match_is_kept_unsupported():
    clause = iosxe.parse_route_maps("route-map RM permit 10\n match community CL1 exact-match\n")["RM"][0]
    assert clause["match_community_lists"] == ["CL1"]
    assert clause["match_unsupported"] == ["match community CL1 exact-match"]


def test_parse_community_and_as_path_lists():
    text = (
        "ip community-list standard CL-STD permit 65000:1 65000:2\n"
        "ip community-list standard CL-STD deny internet\n"
        "ip community-list 7 permit 4259840007\n"
        "ip community-list expanded CL-EXP permit ^65000:1[0-9]$\n"
        "ip community-list 150 deny _65001:.*_\n"
    )
    lists = {cl["name"]: cl for cl in iosxe.parse_community_lists(text)}
    assert lists["CL-STD"] == {
        "name": "CL-STD",
        "kind": "community-list",
        "entries": [
            {"seq": 1, "action": "permit", "match_type": "standard", "value": "65000:1 65000:2"},
            {"seq": 2, "action": "deny", "match_type": "standard", "value": "internet"},
        ],
    }
    assert lists["7"]["entries"] == [
        {"seq": 1, "action": "permit", "match_type": "standard", "value": "65000:7"}
    ]
    assert lists["CL-EXP"]["entries"][0]["match_type"] == "expanded"
    assert lists["150"]["entries"] == [
        {"seq": 1, "action": "deny", "match_type": "expanded", "value": "_65001:.*_"}
    ]
    (as_path,) = iosxe.parse_as_path_lists(
        "ip as-path access-list 5 permit _64512_\nip as-path access-list 5 deny .*\n"
    )
    assert as_path == {
        "name": "5",
        "kind": "as-path-list",
        "entries": [
            {"seq": 1, "action": "permit", "match_type": "expanded", "value": "_64512_"},
            {"seq": 2, "action": "deny", "match_type": "expanded", "value": ".*"},
        ],
    }


def test_the_lists_are_read_only_when_a_route_map_names_one(monkeypatch):
    text = ROUTE_MAP_TEXT + "route-map RM-CL permit 10\n match community CL-STD\n set local-preference 50\n"
    assert iosxe.match_list_commands(ROUTE_MAP_TEXT) == []
    assert iosxe.match_list_commands(text) == [iosxe.CMD_COMMUNITY_LIST, iosxe.CMD_AS_PATH_LIST]
    answers = {
        **RAW,
        CMD_ROUTE_MAP: text,
        iosxe.CMD_COMMUNITY_LIST: "ip community-list standard CL-STD permit 65000:1\n",
        iosxe.CMD_AS_PATH_LIST: "",
    }
    fake = FakeSshSession(lambda cmd: answers.get(cmd, "")).install(monkeypatch)
    collector = _bgp_collector("none")
    raw = collector.fetch()
    assert fake.commands[-2:] == [iosxe.CMD_COMMUNITY_LIST, iosxe.CMD_AS_PATH_LIST]
    batch = collector.normalize(raw)
    cl = uid.route_policy(DEV, "community-list", "CL-STD")
    line = next(n for n in batch.nodes if n.uid == uid.match_list_entry(cl, 1))
    assert line.label == "MatchListEntry"
    assert (line.props["match_type"], line.props["value"]) == ("standard", "65000:1")
    entry = uid.route_policy_entry(uid.route_policy(DEV, "route-map", "RM-CL"), 10)
    assert any(r.rel_type == "REFERENCES" and r.start_uid == entry and r.end_uid == cl for r in batch.rels)

    plain = FakeSshSession(lambda cmd: RAW.get(cmd, "")).install(monkeypatch)
    _bgp_collector("none").fetch()
    assert iosxe.CMD_COMMUNITY_LIST not in plain.commands


# --- a leaked route's next-hop VRF and the Null0 routes ---------------------------------

_LEAK_ROUTE_TEXT = """\
Routing Table: CUST
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP

Gateway of last resort is 10.0.0.1 to network 0.0.0.0

B*    0.0.0.0/0 [20/0] via 10.0.0.1 (default), 00:01:02
      10.0.0.0/8 is variably subnetted, 5 subnets, 4 masks
B        10.20.0.0/24 [200/0] via 192.0.2.1 (SHARED), 00:01:02
                      [200/0] via 192.0.2.2 (SHARED), 00:01:02
D        10.0.0.0/8 is a summary, 00:05:00, Null0
B        10.64.0.0/10 [200/0] via 0.0.0.0, 00:01:02, Null0
S        10.128.0.0/9 is directly connected, Null0
"""


def test_a_leaked_routes_next_hop_vrf_and_the_null0_routes_reach_the_side_rows():
    """`via 10.0.0.1 (default)` names the table the next hop resolves
    in, on the route line and on a further path. A summary, a BGP
    aggregate (`via 0.0.0.0, Null0`) and a blackhole static are discard
    routes with no next hop to forward to."""
    raw = dict(RAW, **{CMD_ROUTE: _LEAK_ROUTE_TEXT})
    rows = {(r["prefix"], r["next_hop"]): r for r in _collector().side_tables(raw)["rib"]}
    default, shared = uid.vrf(DEV, "default"), uid.vrf(DEV, "SHARED")
    assert rows[("0.0.0.0/0", "10.0.0.1")]["next_hop_context_uid"] == default
    assert rows[("10.20.0.0/24", "192.0.2.1")]["next_hop_context_uid"] == shared
    path = rows[("10.20.0.0/24", "192.0.2.2")]
    assert (path["next_hop_context_uid"], path["discard"]) == (shared, None)
    for prefix in ("10.0.0.0/8", "10.64.0.0/10", "10.128.0.0/9"):
        row = rows[(prefix, None)]
        assert (row["discard"], row["interface"], row["next_hop_context_uid"]) == ("blackhole", "Null0", None)
    assert len(rows) == 6


# --- route-reflector-client, filter-list, prefix-list beside a route-map --------------------

_SESSION_BGP_TEXT = """\
router bgp 65001
 bgp router-id 10.255.255.1
 neighbor RR-CLIENTS peer-group
 neighbor RR-CLIENTS remote-as 65001
 neighbor 10.0.0.2 remote-as 65001
 neighbor 10.0.0.3 peer-group RR-CLIENTS
 neighbor 10.0.0.4 remote-as 65001
 neighbor 10.0.0.4 peer-group GHOST
 neighbor 192.0.2.1 remote-as 65010
 !
 address-family ipv4
  neighbor RR-CLIENTS route-reflector-client
  neighbor 10.0.0.2 route-reflector-client
  neighbor 10.0.0.2 activate
  neighbor 10.0.0.3 activate
  neighbor 10.0.0.4 activate
  neighbor 192.0.2.1 activate
  neighbor 192.0.2.1 filter-list 10 in
  neighbor 192.0.2.1 prefix-list PL-CUSTOMER-IN out
  neighbor 192.0.2.1 route-map RM-IN out
 exit-address-family
!
"""


def _sessions(batch):
    return {n.props["peer_ip"]: n for n in batch.nodes if n.label == "BgpSession"}


def test_route_reflector_client_is_stated_on_every_session():
    """True from the neighbor or its peer-group, false when neither
    states it, absent when the peer-group is undefined and could have."""
    sessions = _sessions(_collector().normalize(dict(RAW, **{CMD_BGP: _SESSION_BGP_TEXT})))
    assert sessions["10.0.0.2"].props["route_reflector_client"] is True
    assert sessions["10.0.0.3"].props["route_reflector_client"] is True
    assert "route_reflector_client" not in sessions["10.0.0.4"].props
    assert sessions["192.0.2.1"].props["route_reflector_client"] is False


def test_a_filter_list_and_a_prefix_list_beside_a_route_map_are_recorded():
    """The AS-path filter-list is written for the engine to fail closed on."""
    batch = _collector().normalize(dict(RAW, **{CMD_BGP: _SESSION_BGP_TEXT}))
    session = _sessions(batch)["192.0.2.1"]
    assert session.props["import_filter_list_name"] == "10"
    assert (session.props["export_policy_name"], session.props["export_policy_kind"]) == (
        "RM-IN",
        "route-map",
    )
    assert session.props["export_prefix_list_name"] == "PL-CUSTOMER-IN"
    filters = {
        (r.key.get("direction"), r.end_uid)
        for r in batch.rels
        if r.rel_type == "FILTERED_BY" and r.start_uid == session.uid
    }
    assert filters == {
        ("out", uid.route_policy(DEV, "route-map", "RM-IN")),
        ("out-prefix-list", uid.route_policy(DEV, "prefix-list", "PL-CUSTOMER-IN")),
    }


# --- peer-session and peer-policy templates; the cluster id -----------------------------

_TEMPLATE_BGP_TEXT = """\
router bgp 65001
 template peer-session IBGP-BASE
  remote-as 65001
  description core
 exit-peer-session
 !
 template peer-session IBGP
  inherit peer-session IBGP-BASE
 exit-peer-session
 !
 template peer-policy RR-CLIENT
  route-reflector-client
  route-map RM-IN in
 exit-peer-policy
 !
 bgp router-id 10.255.255.1
 bgp cluster-id 167772161
 neighbor 10.0.0.2 inherit peer-session IBGP
 neighbor 10.0.0.3 inherit peer-session IBGP
 neighbor 10.0.0.3 cluster-id 10.9.9.9
 neighbor 10.0.0.4 inherit peer-session MISSING
 neighbor 192.0.2.1 remote-as 65010
 !
 address-family ipv4
  neighbor 10.0.0.2 activate
  neighbor 10.0.0.2 inherit peer-policy RR-CLIENT
  neighbor 10.0.0.3 activate
  neighbor 10.0.0.4 activate
  neighbor 192.0.2.1 activate
 exit-address-family
!
"""


def test_a_neighbor_takes_its_remote_as_and_policy_from_its_templates():
    """A neighbor whose remote-as comes from a peer-session template, through
    a second template it inherits, is a session."""
    batch = _collector().normalize(dict(RAW, **{CMD_BGP: _TEMPLATE_BGP_TEXT}))
    sessions = _sessions(batch)
    assert sessions["10.0.0.2"].props["peer_asn"] == 65001
    assert sessions["10.0.0.2"].props["route_reflector_client"] is True
    assert sessions["10.0.0.2"].props["import_policy_name"] == "RM-IN"
    assert sessions["10.0.0.3"].props["peer_asn"] == 65001
    assert sessions["10.0.0.3"].props["route_reflector_client"] is False
    assert "10.0.0.4" not in sessions


def test_a_neighbor_with_no_resolvable_remote_as_is_recorded_on_its_process():
    """The neighbor whose template is not in the capture writes no session;
    its process names it, so the simulation does not read it as absent."""
    batch = _collector().normalize(dict(RAW, **{CMD_BGP: _TEMPLATE_BGP_TEXT}))
    process = next(n for n in batch.nodes if n.uid == uid.routing_process(DEV, "default", "bgp"))
    assert process.props["session_gaps"] == [
        "neighbor 10.0.0.4 has no resolvable remote-as (unresolved template peer-session MISSING)"
    ]


def test_every_session_carries_the_cluster_id_and_a_neighbor_its_own():
    """`bgp cluster-id` in its 32-bit form is the dotted quad 10.0.0.1; a
    neighbor's own `cluster-id` takes its place on that session."""
    sessions = _sessions(_collector().normalize(dict(RAW, **{CMD_BGP: _TEMPLATE_BGP_TEXT})))
    assert sessions["10.0.0.2"].props["cluster_id"] == "10.0.0.1"
    assert sessions["10.0.0.3"].props["cluster_id"] == "10.9.9.9"
    assert sessions["192.0.2.1"].props["cluster_id"] == "10.0.0.1"
