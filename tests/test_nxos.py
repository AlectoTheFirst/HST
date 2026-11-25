"""NX-OS collector: probe/fetch over a monkeypatched transport, `_rows` unwrapping
(including the dict-vs-list `TABLE_x/ROW_x` collapse), `parse` against a
shape-faithful `| json` fixture, and the resulting normalize/side_tables output."""

import json

import pytest
from tests.conftest import FakeSshSession

from hst import reasoner
from hst.collectors import nxos
from hst.collectors.auth import SshPassword
from hst.collectors.cli_collector import classify_command_failure
from hst.collectors.nxos import (
    CMD_ACL,
    CMD_ARP,
    CMD_BGP,
    CMD_BGP_SESSIONS,
    CMD_HSRP,
    CMD_INTERFACE,
    CMD_INTERFACE_CONFIG,
    CMD_LLDP,
    CMD_MAC,
    CMD_NAT,
    CMD_OSPF,
    CMD_OSPF_CONFIG,
    CMD_OSPF_DB_ASBR_SUMMARY,
    CMD_OSPF_DB_EXTERNAL,
    CMD_OSPF_DB_NETWORK,
    CMD_OSPF_DB_NSSA,
    CMD_OSPF_DB_ROUTER,
    CMD_OSPF_DB_SUMMARY,
    CMD_OSPF_IF,
    CMD_OSPF_NBR,
    CMD_ROUTE,
    CMD_RPM,
    CMD_TRUNK,
    CMD_VERSION,
    CMD_VLAN,
    CMD_VPC,
    CMD_VRF,
    CMD_VRF_IF,
    CMD_VRRP,
    NxosCollector,
    NxosConfig,
)
from hst.core import manifest, uid

HOST, USER = "n9k1", "ro"
SERIAL = "FDO1234ABCD"
# minted by the in-memory registry from the host_name in RAW's show version
DEV = "dev:sw1"
# routed addressing (connected/NAT) anchors on the owning VrfInstance uid; the NAT
# rule fixture below carries no `vrf` clause, so it's the device's default table
DEFAULT_VRF_UID = uid.vrf(DEV, "default")

VERSION_PAYLOAD = {
    "sys_ver_str": "9.3(5)",
    "chassis_id": "Nexus9000 C93180YC-EX chassis",
    "proc_board_id": SERIAL,
    "host_name": "sw1",
}

# ROW_interface: a list of four rows exercising phys/lag/loopback/svi kinds
INTERFACE_PAYLOAD = {
    "TABLE_interface": {
        "ROW_interface": [
            {
                "interface": "Ethernet1/1",
                "state": "up",
                "admin_state": "up",
                "eth_hw_addr": "aabb.ccdd.ee01",
                "eth_ip_addr": "10.0.0.1",
                "eth_ip_mask": 24,
                # link speed: a known, fixed-rate operational value
                "eth_speed": "1000 Mb/s",
                "eth_duplex": "full",
                "eth_bw": 1000000,
            },
            {"interface": "port-channel1", "state": "up", "admin_state": "up"},
            {"interface": "loopback0", "state": "up", "admin_state": "up"},
            {
                "interface": "Vlan10",
                "svi_admin_state": "up",
                "svi_line_proto": "up",
                "svi_mac": "aabb.ccdd.ee10",
                "svi_ip_addr": "10.10.10.1",
                "svi_ip_mask": 24,
            },
            # auto-negotiated: neither field states a value, and eth_bw is absent too
            {
                "interface": "Ethernet1/2",
                "state": "up",
                "admin_state": "up",
                "eth_speed": "auto-speed",
                "eth_duplex": "auto",
            },
            # a Gb/s-denominated speed, exercising the unit conversion
            {
                "interface": "Ethernet1/3",
                "state": "up",
                "admin_state": "up",
                "eth_speed": "10 Gb/s",
                "eth_duplex": "full",
                "eth_bw": 10000000,
            },
        ],
    },
}

LLDP_PAYLOAD = {
    "TABLE_nbor_detail": {
        "ROW_nbor_detail": [
            {
                "l_port_id": "Ethernet1/1",
                "sys_name": "core1",
                "port_id": "Ethernet2/1",
                "chassis_id": "aabb.ccdd.ef01",
            },
        ],
    },
}

# ROW_vlanbrief collapses to a bare dict: exactly one VLAN row (the dict-not-list case)
VLAN_PAYLOAD = {
    "TABLE_vlanbrief": {
        "ROW_vlanbrief": {"vlanshowbr-vlanid": "10", "vlanshowbr-vlanname": "DATA"},
    },
}

VRF_PAYLOAD = {
    "TABLE_vrf": {
        "ROW_vrf": [{"vrf_name": "default"}, {"vrf_name": "mgmt"}],
    },
}

# nested TABLE_vrf/ROW_vrf -> TABLE_addrf/ROW_addrf -> TABLE_prefix/ROW_prefix ->
# TABLE_path/ROW_path; every inner level collapses to a dict (single row each)
ROUTE_PAYLOAD = {
    "TABLE_vrf": {
        "ROW_vrf": [
            {
                "vrf-name-out": "default",
                "TABLE_addrf": {
                    "ROW_addrf": {
                        "addrf": "ipv4",
                        "TABLE_prefix": {
                            "ROW_prefix": {
                                "ipprefix": "10.0.0.0/24",
                                "TABLE_path": {"ROW_path": {"clientname": "direct", "pref": 0, "metric": 0}},
                            }
                        },
                    }
                },
            },
            {
                "vrf-name-out": "mgmt",
                "TABLE_addrf": {
                    "ROW_addrf": {
                        "addrf": "ipv4",
                        "TABLE_prefix": {
                            "ROW_prefix": {
                                "ipprefix": "10.255.0.0/32",
                                "TABLE_path": {
                                    "ROW_path": {
                                        "ipnexthop": "10.255.0.2",
                                        "clientname": "static",
                                        "pref": 1,
                                        "metric": 1,
                                    }
                                },
                            }
                        },
                    }
                },
            },
        ],
    },
}

MAC_PAYLOAD = {
    "TABLE_mac_address": {
        "ROW_mac_address": [
            {"disp_vlan": "10", "disp_mac_addr": "aabb.ccdd.ef99", "disp_port": "Ethernet1/1"},
            # NX-OS emits "-" in the vlan field of router/static mac entries.
            {"disp_vlan": "-", "disp_mac_addr": "aabb.ccdd.efff", "disp_port": "sup-eth1"},
        ],
    },
}

# TABLE_vrf/ROW_vrf and the nested TABLE_adj/ROW_adj both collapse to dicts here
ARP_PAYLOAD = {
    "TABLE_vrf": {
        "ROW_vrf": {
            "vrf-name-out": "default",
            "TABLE_adj": {
                "ROW_adj": {"ip-addr-out": "10.0.0.5", "mac": "aabb.ccdd.efaa", "intf-out": "Ethernet1/1"}
            },
        },
    },
}

# ROW_if holds per-interface vrf membership, with the default vrf as "".
VRF_IF_PAYLOAD = {
    "TABLE_if": {
        "ROW_if": [
            {"if_name": "Vlan10", "vrf_name": "prod"},
            {"if_name": "Ethernet1/1", "vrf_name": "default"},
        ],
    },
}

# `show running-config nat` is plain text (no JSON rendering): interface
# sub-blocks carry the inside/outside roles, the flat lines the pools and
# rules; NX-OS spells the pool mask `prefix-length`
NAT_CONFIG_TEXT = """\
!Command: show running-config nat
!Running configuration last done at: Thu Jul 30 12:00:00 2026
feature nat

interface Ethernet1/1
  ip nat outside

interface Vlan10
  ip nat inside

ip nat pool POOL-A 192.0.2.0 192.0.2.255 prefix-length 24
ip nat inside source list ACL-NAT pool POOL-A overload
ip nat inside source static 10.10.10.5 192.0.2.5
"""

# EDGE-IN and MGMT-OUT are the two interface filters bound below.
ACL_PAYLOAD = {
    "TABLE_ip_ipv6_mac": {
        "ROW_ip_ipv6_mac": [
            {
                "op": "ip",
                "acl_name": "ACL-NAT",
                "TABLE_seqno": {
                    "ROW_seqno": [
                        {
                            "seqno": 10,
                            "permitdeny": "permit",
                            "proto": "ip",
                            "src_ip_prefix": "10.10.10.0/24",
                            "dest_any": "any",
                        },
                        {
                            "seqno": 20,
                            "permitdeny": "permit",
                            "proto": "ip",
                            "src_ip_prefix": "10.10.10.7/32",
                            "dest_any": "any",
                        },
                    ]
                },
            },
            {
                "op": "ip",
                "acl_name": "EDGE-IN",
                "TABLE_seqno": {
                    "ROW_seqno": [
                        {
                            "seqno": 10,
                            "permitdeny": "permit",
                            "proto": "tcp",
                            "src_ip_prefix": "10.0.0.0/24",
                            "dest_ip_prefix": "203.0.113.10/32",
                            "dest_port_op": "eq",
                            "dest_port1_num": 443,
                        },
                        {
                            "seqno": 20,
                            "permitdeny": "permit",
                            "proto": "tcp",
                            "src_any": "any",
                            "dest_ip_prefix": "203.0.113.10/32",
                            "established": True,
                        },
                        {
                            "seqno": 30,
                            "permitdeny": "permit",
                            "proto": "ip",
                            "src_addrgrp": "PARTNERS",
                            "dest_any": "any",
                        },
                        {
                            "seqno": 40,
                            "permitdeny": "deny",
                            "proto": "ip",
                            "src_any": "any",
                            "dest_any": "any",
                        },
                    ]
                },
            },
            {
                "op": "ip",
                "acl_name": "MGMT-OUT",
                "TABLE_seqno": {
                    "ROW_seqno": [
                        {
                            "seqno": 10,
                            "permitdeny": "permit",
                            "proto": "ip",
                            "src_ip_prefix": "10.10.10.0/24",
                            "dest_any": "any",
                        },
                    ]
                },
            },
        ]
    }
}

# `show running-config interface`. The base fixture binds no access group.
INTERFACE_CONFIG_TEXT = """\
interface Ethernet1/1
  no switchport
  ip address 10.0.0.1/24
interface port-channel1
  no switchport
interface loopback0
  ip address 10.255.0.1/32
interface Vlan10
  no shutdown
  ip address 10.10.10.1/24
"""

# port-channel1 binds a list that this capture's `show ip access-lists` never printed.
ACL_BINDING_INTERFACE_CONFIG_TEXT = """\
interface Ethernet1/1
  no switchport
  ip address 10.0.0.1/24
  ip access-group EDGE-IN in
interface port-channel1
  no switchport
  ip access-group UNCOLLECTED-ACL in
interface Vlan10
  no shutdown
  ip address 10.10.10.1/24
  ip access-group MGMT-OUT out
"""

# `show running-config bgp`. The inbound route-map RM-GHOST is defined nowhere.
BGP_CONFIG_TEXT = """\
!Command: show running-config bgp
!Running configuration last done at: Thu Jul 30 12:05:00 2026
feature bgp

router bgp 65001
  router-id 10.255.0.1
  vrf CUST-A
    router-id 10.255.1.1
    address-family ipv4 unicast
      redistribute direct route-map RM-CONN
    neighbor 10.1.1.2
      remote-as 65001
      address-family ipv4 unicast
        route-map RM-IN in
        route-map RM-OUT out
    neighbor 192.0.2.2
      remote-as 65099
      address-family ipv4 unicast
        route-map RM-OUT out
    neighbor 192.0.2.9
      remote-as 65098
      address-family ipv4 unicast
        route-map RM-GHOST in
"""

# `show running-config rpm` carries the prefix-lists and the route-maps in one output.
RPM_CONFIG_TEXT = """\
!Command: show running-config rpm
ip prefix-list PL-TEST seq 10 permit 10.0.0.0/8 le 24
ip prefix-list PL-TEST seq 20 permit 172.16.0.0/16 eq 24
route-map RM-IN permit 10
  match ip address prefix-list PL-TEST
  set local-preference 150
  continue 20
route-map RM-IN permit 20
  set community 65001:100 additive
route-map RM-OUT permit 10
  match ip address prefix-list PL-GHOST
  set metric 50
route-map RM-CONN permit 10
  match tag 100
  set origin incomplete
"""

AREA_0 = "0.0.0.0"  # noqa: S104 - an OSPF area id

# --- OSPF --------------------------------------------------------------------------------
# The field and wrapper names below come from the docs.
OSPF_PAYLOAD = {
    "TABLE_ctx": {
        "ROW_ctx": {
            "ptag": "1",
            "cname": "default",
            "rid": "10.255.0.1",
            "TABLE_area": {
                "ROW_area": [
                    {"aid": AREA_0, "bkbone_area": "true", "stub_area": "false"},
                    {"aid": "0.0.0.10", "nssa_area": "true"},
                    {"aid": "0.0.0.20"},
                ]
            },
        }
    }
}

OSPF_IF_PAYLOAD = {
    "TABLE_ctx": {
        "ROW_ctx": {
            "ptag": "1",
            "cname": "default",
            "TABLE_intf": {
                "ROW_intf": [
                    {
                        "ifname": "Ethernet1/1",
                        "area": AREA_0,
                        "cost": "40",
                        "if_type": "P2P",
                        "passive": "false",
                        "state": "P2P",
                    },
                    {
                        "ifname": "Vlan10",
                        "area": "0.0.0.10",
                        "cost": "10",
                        "if_type": "BCAST",
                        "passive": "true",
                        "state": "DR",
                    },
                    {"ifname": "loopback0", "area": AREA_0, "cost": "1", "if_type": "LOOPBACK"},
                    # a process interface the interface table never listed
                    {"ifname": "Ethernet1/48", "area": AREA_0, "cost": "4"},
                ]
            },
        }
    }
}

OSPF_NBR_PAYLOAD = {
    "TABLE_ctx": {
        "ROW_ctx": {
            "ptag": "1",
            "cname": "default",
            "TABLE_nbr": {
                "ROW_nbr": [
                    {"rid": "10.255.0.2", "addr": "10.0.0.2", "intf": "Ethernet1/1", "state": "FULL"},
                    {"rid": "10.255.0.3", "addr": "10.10.10.2", "intf": "Vlan10", "state": "2WAY"},
                ]
            },
        }
    }
}

# The router LSA arrives under the per-area nesting (`TABLE_area` holding
# `TABLE_lsdb`), with `ROW_lsdb` collapsed to a bare dict for the single LSA.
OSPF_DB_ROUTER_PAYLOAD = {
    "TABLE_ctx": {
        "ROW_ctx": {
            "ptag": "1",
            "cname": "default",
            "TABLE_area": {
                "ROW_area": {
                    "aid": AREA_0,
                    "TABLE_lsdb": {
                        "ROW_lsdb": {
                            "lsid": "10.255.0.1",
                            "advrouter": "10.255.0.1",
                            "age": "120",
                            "seqno": "0x80000005",
                            "TABLE_link": {
                                "ROW_link": [
                                    {
                                        "type": "P2P",
                                        "id": "10.255.0.2",
                                        "data": "10.0.0.1",
                                        "metric": "40",
                                    },
                                    {
                                        "type": "STUB",
                                        "id": "10.0.0.0",
                                        "data": "255.255.255.0",
                                        "metric": "40",
                                    },
                                ]
                            },
                        }
                    },
                }
            },
        }
    }
}

# The other three database commands arrive under the flat nesting: `TABLE_lsdb`
# directly under the context, with the area on the LSA row itself.
OSPF_DB_NETWORK_PAYLOAD = {
    "TABLE_ctx": {
        "ROW_ctx": {
            "ptag": "1",
            "cname": "default",
            "TABLE_lsdb": {
                "ROW_lsdb": {
                    "area": AREA_0,
                    "lsid": "10.0.0.1",
                    "advrouter": "10.255.0.1",
                    "age": "300",
                    "seqno": "0x80000002",
                    "netmask": "255.255.255.0",
                    "TABLE_rtr": {
                        "ROW_rtr": [{"rtr": "10.255.0.1"}, {"rtr": "10.255.0.2"}],
                    },
                }
            },
        }
    }
}

# The summary LSA states its mask as a prefix length, which the schema carries
# as a dotted quad whichever form the platform printed.
OSPF_DB_SUMMARY_PAYLOAD = {
    "TABLE_ctx": {
        "ROW_ctx": {
            "ptag": "1",
            "cname": "default",
            "TABLE_lsdb": {
                "ROW_lsdb": {
                    "area": "0.0.0.10",
                    "lsid": "10.10.10.0",
                    "advrouter": "10.255.0.1",
                    "age": "45",
                    "seqno": "0x80000003",
                    "netmask": "/24",
                    "metric": "20",
                }
            },
        }
    }
}

# An AS-external LSA belongs to no area.
OSPF_DB_EXTERNAL_PAYLOAD = {
    "TABLE_ctx": {
        "ROW_ctx": {
            "ptag": "1",
            "cname": "default",
            "TABLE_lsdb": {
                "ROW_lsdb": {
                    "lsid": "203.0.113.0",
                    "advrouter": "10.255.0.2",
                    "age": "900",
                    "seqno": "0x80000001",
                    "netmask": "255.255.255.0",
                    "metric": "100",
                    "metrictype": "E2",
                    "fwdaddr": "10.0.0.2",
                }
            },
        }
    }
}

# The NSSA external LSA (type 7) carries the area it was originated in.
OSPF_DB_NSSA_PAYLOAD = {
    "TABLE_ctx": {
        "ROW_ctx": {
            "ptag": "1",
            "cname": "default",
            "TABLE_lsdb": {
                "ROW_lsdb": {
                    "area": "0.0.0.10",
                    "lsid": "198.51.100.0",
                    "advrouter": "10.255.0.3",
                    "age": "600",
                    "seqno": "0x80000004",
                    "netmask": "255.255.255.128",
                    "metric": "50",
                    "metrictype": "E1",
                    "fwdaddr": "10.10.10.2",
                }
            },
        }
    }
}

# The ASBR summary LSA (type 4) carries no network mask (RFC 2328 A.4.4).
OSPF_DB_ASBR_SUMMARY_PAYLOAD = {
    "TABLE_ctx": {
        "ROW_ctx": {
            "ptag": "1",
            "cname": "default",
            "TABLE_lsdb": {
                "ROW_lsdb": {
                    "area": "0.0.0.10",
                    "lsid": "10.255.0.9",
                    "advrouter": "10.255.0.1",
                    "age": "75",
                    "seqno": "0x80000002",
                    "metric": "30",
                }
            },
        }
    }
}

# `show running-config ospf`. RM-GHOST is defined nowhere.
OSPF_CONFIG_TEXT = """\
!Command: show running-config ospf
feature ospf

router ospf 1
  router-id 10.255.0.1
  area 0.0.0.20 stub
  redistribute direct route-map RM-CONN
  redistribute bgp 65001 route-map RM-GHOST
"""

# --- the BGP observation capture ----------------------------------------------------------
# The field names below are what NX-OS documents for these commands.

# `show bgp sessions | json`. ROW_vrf is a bare dict.
BGP_SESSIONS_PAYLOAD = {
    "totalpeers": 3,
    "totalestablishedpeers": 2,
    "localas": 65001,
    "TABLE_vrf": {
        "ROW_vrf": {
            "vrf-name-out": "CUST-A",
            "local-as": 65001,
            "router-id": "10.255.1.1",
            "TABLE_neighbor": {
                "ROW_neighbor": [
                    {
                        "neighbor-id": "10.1.1.2",
                        "remoteas": 65001,
                        "connectionsdropped": 0,
                        "lastflap": "P1DT2H3M",
                        "lastread": "PT20S",
                        "lastwrite": "PT8S",
                        "state": "Established",
                        "localport": 179,
                        "remoteport": 55380,
                        "notificationssent": 0,
                        "notificationsreceived": 0,
                    },
                    {
                        "neighbor-id": "192.0.2.2",
                        "remoteas": 65099,
                        "connectionsdropped": 1,
                        "lastflap": "PT4H12M",
                        "state": "Established",
                        "localport": 179,
                        "remoteport": 40122,
                    },
                    {
                        "neighbor-id": "192.0.2.9",
                        "remoteas": 65098,
                        "connectionsdropped": 4,
                        "lastflap": "PT6M",
                        "state": "Idle",
                    },
                ]
            },
        }
    },
}


def _bgp_paths_payload(vrf, prefixes):
    """One `show bgp ... neighbors <peer> <direction> | json` payload.

    `prefixes` is a list of (prefix, [path row, ...]) pairs, wrapped in the
    vrf/afi/safi/rd/prefix/path nesting NX-OS uses for every BGP table.
    """
    return {
        "TABLE_vrf": {
            "ROW_vrf": {
                "vrf-name-out": vrf,
                "TABLE_afi": {
                    "ROW_afi": {
                        "afi": 1,
                        "TABLE_safi": {
                            "ROW_safi": {
                                "safi": 1,
                                "af-name": "IPv4 Unicast",
                                "TABLE_rd": {
                                    "ROW_rd": {
                                        "TABLE_prefix": {
                                            "ROW_prefix": [
                                                {"ipprefix": p, "TABLE_path": {"ROW_path": paths}}
                                                for p, paths in prefixes
                                            ]
                                        }
                                    }
                                },
                            }
                        },
                    }
                },
            }
        }
    }


# The line a box with no soft reconfiguration inbound answers with: a zero
# exit status and no rejection banner, so the fetch keeps it as output and the
# direction reads not-captured on the text alone.
BGP_NO_SOFT_RECONFIG = "% Inbound soft-reconfiguration is not configured for this neighbor\n"

# 10.1.1.2, the iBGP peer: one accepted path for 10.20.0.0/24 that the inbound
# route-map raised the local preference of and the device marked best, and one
# advertised prefix.
BGP_IBGP_ACCEPTED = _bgp_paths_payload(
    "CUST-A",
    [
        (
            "10.20.0.0/24",
            [
                {
                    "pathnr": 0,
                    "ipnexthop": "10.1.1.2",
                    "aspath": "",
                    "localpref": 150,
                    "metric": 0,
                    "origin": "i",
                    "community": "65001:100",
                    "best": "true",
                }
            ],
        )
    ],
)
BGP_IBGP_ADVERTISED = _bgp_paths_payload(
    "CUST-A",
    [
        (
            "10.0.0.0/24",
            [{"pathnr": 0, "ipnexthop": "10.1.1.1", "aspath": "", "localpref": 100, "origin": "i"}],
        )
    ],
)

# 192.0.2.2 is the eBGP peer with soft reconfiguration inbound.
BGP_EBGP_RECEIVED = _bgp_paths_payload(
    "CUST-A",
    [
        (
            "10.20.0.0/24",
            [
                {
                    "pathnr": 0,
                    "ipnexthop": "192.0.2.2",
                    "aspath": "65099",
                    "localpref": 100,
                    "metric": 50,
                    "origin": "i",
                }
            ],
        ),
        (
            "198.51.100.0/24",
            [{"pathnr": 0, "ipnexthop": "192.0.2.2", "aspath": "65099 64500", "origin": "e"}],
        ),
    ],
)
BGP_EBGP_ACCEPTED = _bgp_paths_payload(
    "CUST-A",
    [
        (
            "10.20.0.0/24",
            [
                {
                    "pathnr": 0,
                    "ipnexthop": "192.0.2.2",
                    "aspath": "65099",
                    "localpref": 100,
                    "metric": 50,
                    "origin": "i",
                    "best": "false",
                }
            ],
        )
    ],
)
BGP_EBGP_ADVERTISED = _bgp_paths_payload(
    "CUST-A",
    [
        (
            "10.0.0.0/24",
            [{"pathnr": 0, "ipnexthop": "192.0.2.1", "aspath": "65001", "origin": "i", "best": "true"}],
        )
    ],
)


def _bgp_capture_raw():
    """The observation commands that the base fixture's fetch issues, and their answers."""
    out = {CMD_BGP_SESSIONS: json.dumps(BGP_SESSIONS_PAYLOAD)}
    answers = {
        ("10.1.1.2", "received"): BGP_NO_SOFT_RECONFIG,
        ("10.1.1.2", "accepted"): json.dumps(BGP_IBGP_ACCEPTED),
        ("10.1.1.2", "advertised"): json.dumps(BGP_IBGP_ADVERTISED),
        ("192.0.2.2", "received"): json.dumps(BGP_EBGP_RECEIVED),
        ("192.0.2.2", "accepted"): json.dumps(BGP_EBGP_ACCEPTED),
        ("192.0.2.2", "advertised"): json.dumps(BGP_EBGP_ADVERTISED),
        ("192.0.2.9", "received"): BGP_NO_SOFT_RECONFIG,
        ("192.0.2.9", "accepted"): "{}",
        ("192.0.2.9", "advertised"): "{}",
    }
    for (peer_ip, direction), text in answers.items():
        out[nxos.bgp_route_command("CUST-A", peer_ip, direction)] = text
    return out


# `show interface trunk | json`. Ethernet1/3 allows VLAN 10 and a range with no VLANs.
TRUNK_PAYLOAD = {
    "TABLE_interface": {
        "ROW_interface": {
            "interface": "Ethernet1/3",
            "native": "1",
            "status": "trunking",
            "portchannel": "--",
        },
    },
    "TABLE_allowed_vlans": {
        "ROW_allowed_vlans": {"interface": "Ethernet1/3", "allowedvlans": "10,20-30"},
    },
}

_PAYLOADS = {
    CMD_VERSION: VERSION_PAYLOAD,
    CMD_INTERFACE: INTERFACE_PAYLOAD,
    CMD_LLDP: LLDP_PAYLOAD,
    CMD_VLAN: VLAN_PAYLOAD,
    CMD_VRF: VRF_PAYLOAD,
    CMD_ROUTE: ROUTE_PAYLOAD,
    CMD_MAC: MAC_PAYLOAD,
    CMD_ARP: ARP_PAYLOAD,
    CMD_VRF_IF: VRF_IF_PAYLOAD,
    CMD_ACL: ACL_PAYLOAD,
    CMD_OSPF: OSPF_PAYLOAD,
    CMD_OSPF_IF: OSPF_IF_PAYLOAD,
    CMD_OSPF_NBR: OSPF_NBR_PAYLOAD,
    CMD_OSPF_DB_ROUTER: OSPF_DB_ROUTER_PAYLOAD,
    CMD_OSPF_DB_NETWORK: OSPF_DB_NETWORK_PAYLOAD,
    CMD_OSPF_DB_SUMMARY: OSPF_DB_SUMMARY_PAYLOAD,
    CMD_OSPF_DB_EXTERNAL: OSPF_DB_EXTERNAL_PAYLOAD,
    CMD_OSPF_DB_NSSA: OSPF_DB_NSSA_PAYLOAD,
    CMD_OSPF_DB_ASBR_SUMMARY: OSPF_DB_ASBR_SUMMARY_PAYLOAD,
    CMD_TRUNK: TRUNK_PAYLOAD,
}
RAW = {cmd: json.dumps(payload) for cmd, payload in _PAYLOADS.items()}
RAW[CMD_NAT] = NAT_CONFIG_TEXT
RAW[CMD_BGP] = BGP_CONFIG_TEXT
RAW[CMD_RPM] = RPM_CONFIG_TEXT
RAW[CMD_INTERFACE_CONFIG] = INTERFACE_CONFIG_TEXT
# no VLAN access map in the base fixture
RAW[nxos.CMD_VLAN_FILTER] = ""
RAW[CMD_OSPF_CONFIG] = OSPF_CONFIG_TEXT
# HSRP, VRRP and vPC are empty in the base fixture.
RAW[CMD_HSRP] = "{}"
# CDP is empty in the base fixture.
RAW[nxos.CMD_CDP] = "{}"
RAW[CMD_VRRP] = "{}"
RAW[CMD_VPC] = "{}"
# The observation capture is per fetch.
RAW.update(_bgp_capture_raw())
# the neighbor detail answers without a router id; test_bgp_peer_router_id.py
# covers the answered case
RAW[nxos.CMD_BGP_NEIGHBORS] = ""

# the same box with the access-group lines the base fixture leaves out
ACL_RAW = {**RAW, CMD_INTERFACE_CONFIG: ACL_BINDING_INTERFACE_CONFIG_TEXT}

# A single-ACE list carrying a qualifier that is not `established`: a
# time-range. The flow tuple has no column for it at all, so it must land as
# service opacity, not as a definite state.
QUALIFIER_ACL_PAYLOAD = {
    "TABLE_ip_ipv6_mac": {
        "ROW_ip_ipv6_mac": [
            {
                "op": "ip",
                "acl_name": "TIME-IN",
                "TABLE_seqno": {
                    "ROW_seqno": [
                        {
                            "seqno": 10,
                            "permitdeny": "permit",
                            "proto": "tcp",
                            "src_any": "any",
                            "dest_ip_prefix": "203.0.113.10/32",
                            "dest_port_op": "eq",
                            "dest_port1_num": 22,
                            "timerange": "BUSINESS-HOURS",
                        },
                    ]
                },
            },
        ]
    }
}

QUALIFIER_INTERFACE_CONFIG_TEXT = """\
interface Ethernet1/1
  no switchport
  ip address 10.0.0.1/24
  ip access-group TIME-IN in
"""

QUALIFIER_RAW = {
    **RAW,
    CMD_ACL: json.dumps(QUALIFIER_ACL_PAYLOAD),
    CMD_INTERFACE_CONFIG: QUALIFIER_INTERFACE_CONFIG_TEXT,
}


def _collector():
    return NxosCollector(
        NxosConfig(host=HOST, auth=SshPassword(username=USER, password="pw"), site_code="hq", l3dom="corp"),
        None,
    )


# SSH transport plumbing (auth/pin forwarding, observed host keys, one-transport-per-fetch,
# probe) is shared by every CLI collector and is exercised once, parametrized over vendors,
# in test_ssh_transport_conformance.py.


# --- _rows: the dict-vs-list TABLE_x/ROW_x quirk ---------------------------------------


def test_rows_returns_list_untouched():
    payload = {"TABLE_x": {"ROW_x": [{"a": 1}, {"a": 2}]}}
    assert nxos._rows(payload, "x") == [{"a": 1}, {"a": 2}]


def test_rows_collapses_single_row_dict_to_a_list():
    payload = {"TABLE_x": {"ROW_x": {"a": 1}}}
    assert nxos._rows(payload, "x") == [{"a": 1}]


def test_rows_missing_table_or_row_is_empty():
    assert nxos._rows({}, "x") == []
    assert nxos._rows({"TABLE_x": {}}, "x") == []


def test_lldp_failure_degrades_to_empty_neighbors(monkeypatch, caplog):
    """A box with LLDP disabled refuses the command; that must cost the neighbor
    hints, not the whole inventory."""
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd == nxos.CMD_LLDP:
            raise ssh.CommandFailed("'show lldp neighbors detail | json' exited 1: LLDP is not enabled")
        return RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    inter = nxos.parse(raw)
    assert inter["neighbors"] == []
    assert inter["interfaces"] and inter["rib"]  # the rest of the fetch survived
    assert "show lldp neighbors detail" in caplog.text and "continuing without it" in caplog.text


def test_required_command_failure_aborts_the_fetch(monkeypatch):
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd == nxos.CMD_INTERFACE:
            raise ssh.CommandFailed("'show interface | json' exited 1")
        return RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    with pytest.raises(ssh.CommandFailed):
        _collector().fetch()


# --- section outcomes: what each command produced -----------------------------------------


def _sections(monkeypatch, outputs):
    """`Batch.sections` for one fetched payload."""
    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    return c.normalize(c.fetch()).sections


def test_a_failed_arp_read_reads_as_a_failed_section(monkeypatch):
    """The stand-in `{}` parses to no ARP rows."""
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd == CMD_ARP:
            raise ssh.CommandFailed(f"{CMD_ARP!r} exited 1")
        return RAW[cmd]

    sections = _sections(monkeypatch, outputs)
    assert sections["arp"].status == "failed"
    assert sections["interfaces"].status == "ok"


def test_a_table_the_switch_returned_with_no_rows_reads_empty(monkeypatch):
    sections = _sections(monkeypatch, {**RAW, CMD_ARP: json.dumps({"TABLE_vrf": {"ROW_vrf": []}})})
    assert sections["arp"].status == "empty"
    assert sections["arp"].row_count == 0


def test_an_empty_payload_reads_empty_not_malformed(monkeypatch):
    """`{}` is what a switch with an empty ARP or MAC table answers."""
    sections = _sections(monkeypatch, {**RAW, CMD_ARP: "{}"})
    assert sections["arp"].status == "empty" and sections["arp"].row_count == 0


def test_a_json_command_that_printed_nothing_reads_empty_and_does_not_fail_the_parse(monkeypatch):
    """NX-OS prints no output at all, not `{}`, for a `| json` command with no
    rows. A required table such as the MAC table answering that way must read
    `empty`, not take the whole device's normalize down with a JSON error."""
    raw = {**RAW, CMD_MAC: "", CMD_ACL: "   \n"}
    batch = _collector().normalize(raw)
    assert [n for n in batch.nodes if n.label == "Device"]
    sections = _sections(monkeypatch, raw)
    assert sections["mac_table"].status == "empty" and sections["mac_table"].row_count == 0
    assert sections["acl"].status == "empty"


def test_a_json_command_that_answered_text_names_itself_in_the_error():
    raw = {**RAW, CMD_MAC: "% Structured output unsupported\n"}
    with pytest.raises(ValueError, match=r"show mac address-table \| json.*Structured output unsupported"):
        nxos.parse(raw)


def test_a_non_empty_payload_carrying_no_table_reads_malformed(monkeypatch):
    """A payload with content in it but not the table the command promises is
    an answer in the wrong shape, which `_rows` answers [] to all the same."""
    sections = _sections(monkeypatch, {**RAW, CMD_ARP: json.dumps({"TABLE_other": {"ROW_other": []}})})
    assert sections["arp"].status == "malformed"


def test_a_collected_table_reads_ok_with_its_row_count(monkeypatch):
    sections = _sections(monkeypatch, RAW)
    assert sections["arp"].status == "ok" and sections["arp"].row_count == 1
    assert sections["rib"].status == "ok"


def test_a_payload_with_no_recorded_outcomes_reads_unknown():
    """Raw files with no recorded outcomes claim nothing."""
    c = _collector()
    assert {s.status for s in c.normalize(dict(RAW)).sections.values()} == {"unknown"}


# --- parse: pure, no transport involved --------------------------------------------------


def test_parse_device_is_serial_and_hostname():
    inter = nxos.parse(RAW)
    assert inter["device"] == {
        "hostname": "sw1",
        "serial": SERIAL,
        "platform": "nxos",
        "os_version": "9.3(5)",
    }


def test_parse_phys_interface_has_mac_and_ip():
    inter = nxos.parse(RAW)
    eth = next(i for i in inter["interfaces"] if i["name"] == "Ethernet1/1")
    assert eth["kind"] == "phys"
    assert eth["mac"] == "aabbccddee01"
    assert eth["admin_up"] is True
    assert eth["ips"] == [{"ip": "10.0.0.1", "prefixlen": 24, "vrf": ""}]
    assert eth["vlan"] is None


def test_parse_svi_has_vlan_and_ip():
    inter = nxos.parse(RAW)
    svi = next(i for i in inter["interfaces"] if i["name"] == "Vlan10")
    assert svi["kind"] == "svi"
    assert svi["mac"] == "aabbccddee10"
    assert svi["vlan"] == 10
    assert svi["ips"] == [{"ip": "10.10.10.1", "prefixlen": 24, "vrf": "prod"}]


def test_parse_stamps_ip_vrf_from_show_vrf_interface():
    inter = nxos.parse(RAW)
    by_name = {i["name"]: i for i in inter["interfaces"]}
    assert by_name["Vlan10"]["ips"][0]["vrf"] == "prod"
    # phys interface sits in the default vrf, stamped "" per convention
    assert by_name["Ethernet1/1"]["ips"][0]["vrf"] == ""


def test_parse_lag_and_loopback_have_no_mac_or_ip():
    inter = nxos.parse(RAW)
    by_name = {i["name"]: i for i in inter["interfaces"]}
    assert by_name["port-channel1"]["kind"] == "lag"
    assert by_name["port-channel1"]["mac"] is None
    assert by_name["port-channel1"]["ips"] == []
    assert by_name["loopback0"]["kind"] == "loopback"


def test_parse_lldp_neighbor():
    inter = nxos.parse(RAW)
    assert inter["neighbors"] == [
        {
            "local_port": "Ethernet1/1",
            "name": "core1",
            "mac": "aabbccddef01",
            "port": "Ethernet2/1",
            "proto": "lldp",
        },
    ]


def test_parse_unparseable_chassis_id_yields_none_mac():
    raw = dict(RAW)
    raw[CMD_LLDP] = json.dumps(
        {
            "TABLE_nbor_detail": {
                "ROW_nbor_detail": {
                    "l_port_id": "Ethernet1/1",
                    "sys_name": "core1",
                    "port_id": "Ethernet2/1",
                    "chassis_id": "core1.example.com",
                },
            },
        }
    )
    inter = nxos.parse(raw)
    assert inter["neighbors"][0]["mac"] is None


def test_parse_vlans_and_vrfs():
    inter = nxos.parse(RAW)
    assert inter["vlans"] == [{"vid": 10, "name": "DATA"}]
    # NX-OS RTs are not captured (see nxos.py).
    assert inter["vrfs"] == [
        {"name": "default", "rd": None, "rt_import": [], "rt_export": []},
        {"name": "mgmt", "rd": None, "rt_import": [], "rt_export": []},
    ]


def test_parse_vrf_dict_surfaces_rd_when_the_row_carries_one():
    """NX-OS RTs are not captured."""
    raw = dict(RAW)
    raw[CMD_VRF] = json.dumps({"TABLE_vrf": {"ROW_vrf": [{"vrf_name": "CUST", "rd": "65000:1"}]}})
    inter = nxos.parse(raw)
    assert inter["vrfs"] == [{"name": "CUST", "rd": "65000:1", "rt_import": [], "rt_export": []}]


def test_parse_rib_rows():
    inter = nxos.parse(RAW)
    assert inter["rib"] == [
        {
            "vrf": "default",
            "prefix": "10.0.0.0/24",
            "next_hop": None,
            "interface": None,
            "protocol": "direct",
            "metric": 0,
        },
        {
            "vrf": "mgmt",
            "prefix": "10.255.0.0/32",
            "next_hop": "10.255.0.2",
            "interface": None,
            "protocol": "static",
            "metric": 1,
        },
    ]


def test_parse_mac_and_arp_rows():
    inter = nxos.parse(RAW)
    # the "-" disp_vlan row (router/static entry) is skipped; the good row survives
    assert inter["mac_table"] == [{"vlan": 10, "mac": "aabbccddef99", "port_name": "Ethernet1/1"}]
    assert inter["arp"] == [
        {"vrf": "default", "ip": "10.0.0.5", "mac": "aabbccddefaa", "interface_name": "Ethernet1/1"}
    ]


# --- NAT: parse and normalize against the running-config/ACL fixtures --------------------


def test_parse_nat_if_roles_from_interface_sub_blocks():
    nat = nxos.parse(RAW)["nat"]
    assert nat["if_roles"] == {"Ethernet1/1": "outside", "Vlan10": "inside"}


def test_parse_nat_pool_prefix_length_spelling_reduces_to_cidr():
    pools = nxos.parse(RAW)["nat"]["pools"]
    assert pools["POOL-A"]["start"] == "192.0.2.0"
    assert pools["POOL-A"]["end"] == "192.0.2.255"
    assert pools["POOL-A"]["cidr"] == "192.0.2.0/24"


def test_parse_nat_rules_in_config_order():
    rules = nxos.parse(RAW)["nat"]["rules"]
    assert [r["direction"] for r in rules] == ["inside-source", "inside-source"]
    assert rules[0]["acl"] == "ACL-NAT" and rules[0]["pool"] == "POOL-A" and rules[0]["overload"]
    assert rules[1]["static"] and rules[1]["local"] == "10.10.10.5" and rules[1]["global"] == "192.0.2.5"


def test_parse_acls_host_prefix_lands_as_bare_ip():
    acls = nxos.parse(RAW)["nat"]["acls"]
    assert acls["ACL-NAT"] == [
        {"action": "permit", "src": "10.10.10.0/24", "dst": "any"},
        {"action": "permit", "src": "10.10.10.7", "dst": "any"},
    ]


def test_normalize_nat_rulebase_rules_and_edges():
    batch = _collector().normalize(RAW)
    rb = next(n for n in batch.nodes if n.label == "FwRulebase")
    assert rb.uid == "nxos:n9k1:nat:inside-source"
    assert rb.props["kind"] == "nat" and rb.props["vendor"] == "cisco"
    assert (DEV, rb.uid) in [(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENFORCES"]

    list_rule = next(n for n in batch.nodes if n.uid == "nxos:n9k1:nat:inside-source:1")
    assert list_rule.props["kind"] == "snat" and list_rule.props["overload"] is True
    assert list_rule.props["approximate"] is False and list_rule.props["src_any"] is False
    edges = {(r.rel_type, r.end_uid) for r in batch.rels if r.start_uid == list_rule.uid}
    assert ("ORIG_SRC", uid.prefix(DEFAULT_VRF_UID, "10.10.10.0/24")) in edges
    assert ("ORIG_SRC", uid.ip(DEFAULT_VRF_UID, "10.10.10.7")) in edges
    assert ("XLATE_SRC", uid.prefix(DEFAULT_VRF_UID, "192.0.2.0/24")) in edges
    pool = next(n for n in batch.nodes if n.uid == uid.prefix(DEFAULT_VRF_UID, "192.0.2.0/24"))
    assert pool.props["kind"] == "nat-pool"
    assert list_rule.props["translation"] == "192.0.2.0/24"

    static_rule = next(n for n in batch.nodes if n.uid == "nxos:n9k1:nat:inside-source:2")
    # configured after the list rule, evaluated before it
    assert static_rule.props["static"] is True and static_rule.props["position"] == 1
    assert list_rule.props["position"] == 2
    edges = {(r.rel_type, r.end_uid) for r in batch.rels if r.start_uid == static_rule.uid}
    assert ("ORIG_SRC", uid.ip(DEFAULT_VRF_UID, "10.10.10.5")) in edges
    assert ("XLATE_SRC", uid.ip(DEFAULT_VRF_UID, "192.0.2.5")) in edges


def test_normalize_nat_roles_prop_merge_onto_existing_interfaces():
    batch = _collector().normalize(RAW)
    eth = next(n for n in batch.nodes if n.uid == uid.interface(DEV, "Ethernet1/1"))
    svi = next(n for n in batch.nodes if n.uid == uid.interface(DEV, "Vlan10"))
    # prop-merged onto the node the interface loop already built, not a duplicate
    assert eth.props["nat_role"] == "outside" and eth.props["kind"] == "phys"
    assert svi.props["nat_role"] == "inside" and svi.props["kind"] == "svi"


# --- Interface ACLs: access-group bindings and the filter rulebase they mint ---------------


def test_base_fixture_binds_no_access_group_and_mints_no_acl_rulebase():
    assert nxos.parse(RAW)["acl"]["bindings"] == []
    batch = _collector().normalize(RAW)
    assert not [n for n in batch.nodes if n.props.get("match_context") == "interface-acl"]


def test_parse_access_group_bindings_in_config_order():
    assert nxos.parse(ACL_RAW)["acl"]["bindings"] == [
        {"interface": "Ethernet1/1", "direction": "in", "acl": "EDGE-IN"},
        {"interface": "port-channel1", "direction": "in", "acl": "UNCOLLECTED-ACL"},
        {"interface": "Vlan10", "direction": "out", "acl": "MGMT-OUT"},
    ]


def test_parse_extended_acl_carries_protocol_ports_and_opaque_reasons():
    aces = nxos.parse(ACL_RAW)["acl"]["lists"]["EDGE-IN"]
    assert [a["action"] for a in aces] == ["permit", "permit", "permit", "deny"]
    assert aces[0]["proto"] == "tcp" and aces[0]["ports"] == "443" and aces[0]["dst"] == "203.0.113.10"
    # `established` is Cisco's own connection-state keyword and carries a
    # definite answer, so it lands on `states` and `qualifier_reason` is None.
    assert aces[1]["states"] == ["established"]
    assert aces[1]["qualifier_reason"] is None
    assert aces[2]["src_opaque_reason"] == (
        "the ACE matches address-group 'PARTNERS', which is not collected"
    )
    assert aces[3]["src_any"] is True and aces[3]["dst_any"] is True


def test_parse_standard_acl_is_source_only_with_an_implicit_any_destination():
    aces = nxos.parse(ACL_RAW)["acl"]["lists"]["MGMT-OUT"]
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


def test_normalize_mints_one_rulebase_per_acl_name_enforced_by_the_device():
    batch = _collector().normalize(ACL_RAW)
    rbs = {
        n.uid: n
        for n in batch.nodes
        if n.label == "FwRulebase" and n.props.get("match_context") == "interface-acl"
    }
    assert set(rbs) == {
        "nxos:n9k1:acl:edge-in~f89b1a37",
        "nxos:n9k1:acl:uncollected-acl~6bc82fe0",
        "nxos:n9k1:acl:mgmt-out~bf66d13c",
    }
    for rb in rbs.values():
        assert rb.props["kind"] == "access" and rb.props["vendor"] == "cisco"
        assert rb.props["default_action"] == "deny" and rb.props["af"] == 4
    enforces = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENFORCES"}
    assert all((DEV, u) in enforces for u in rbs)
    # each binding is a PROTECTED_BY edge from the interface, in its direction
    assert {
        (r.start_uid, r.end_uid, r.props["direction"]) for r in batch.rels if r.rel_type == "PROTECTED_BY"
    } == {
        (uid.interface(DEV, "Ethernet1/1"), "nxos:n9k1:acl:edge-in~f89b1a37", "in"),
        (uid.interface(DEV, "port-channel1"), "nxos:n9k1:acl:uncollected-acl~6bc82fe0", "in"),
        (uid.interface(DEV, "Vlan10"), "nxos:n9k1:acl:mgmt-out~bf66d13c", "out"),
    }


def test_normalize_ace_position_action_and_no_interface_on_any_rule():
    batch = _collector().normalize(ACL_RAW)
    rb_uid = "nxos:n9k1:acl:edge-in~f89b1a37"
    rules = sorted(
        (n for n in batch.nodes if n.label == "FwRule" and n.uid.startswith(rb_uid + ":")),
        key=lambda n: n.props["position"],
    )
    assert [r.props["position"] for r in rules] == [1, 2, 3, 4]
    assert [r.props["action"] for r in rules] == ["permit", "permit", "permit", "deny"]
    for r in rules:
        assert "in_interface" not in r.props
        assert "out_interface" not in r.props


def test_normalize_established_ace_carries_a_definite_state_not_an_opaque_one():
    """`established` is Cisco's own connection-state scoping and the device's
    answer is definite: the gate skips a traced NEW flow past it with a
    leg note, not indeterminate, so the rule carries `states` and no
    `states_opaque` at all."""
    batch = _collector().normalize(ACL_RAW)
    rule = next(n for n in batch.nodes if n.uid == "nxos:n9k1:acl:edge-in~f89b1a37:2")
    assert rule.props["states"] == ["established"]
    assert not rule.props.get("states_opaque")


def test_normalize_time_range_ace_carries_an_opaque_service_not_a_definite_state():
    """A time-range is a match dimension that the flow tuple has no column for."""
    batch = _collector().normalize(QUALIFIER_RAW)
    rule_uid = "nxos:n9k1:acl:time-in~773e4637:1"
    rule = next(n for n in batch.nodes if n.uid == rule_uid)
    assert not rule.props.get("states")
    svc = next(n for n in batch.nodes if n.uid == f"{rule_uid}:svc")
    assert svc.props["opaque"] is True
    assert "BUSINESS-HOURS" in svc.props["opaque_reason"]


def test_normalize_address_group_ace_mints_an_opaque_net_object_not_a_silent_any():
    batch = _collector().normalize(ACL_RAW)
    rule_uid = "nxos:n9k1:acl:edge-in~f89b1a37:3"
    rule = next(n for n in batch.nodes if n.uid == rule_uid)
    assert rule.props["src_any"] is False
    src = next(n for n in batch.nodes if n.uid == f"{rule_uid}:src")
    assert src.props["opaque"] is True
    assert "PARTNERS" in src.props["opaque_reason"]
    assert any(r.rel_type == "SRC" and r.start_uid == rule_uid and r.end_uid == src.uid for r in batch.rels)


def test_normalize_outbound_binding_is_an_out_edge_not_a_rule_property():
    batch = _collector().normalize(ACL_RAW)
    rule = next(n for n in batch.nodes if n.uid == "nxos:n9k1:acl:mgmt-out~bf66d13c:1")
    assert "out_interface" not in rule.props
    assert "in_interface" not in rule.props
    assert {
        (r.start_uid, r.props["direction"])
        for r in batch.rels
        if r.rel_type == "PROTECTED_BY" and r.end_uid == "nxos:n9k1:acl:mgmt-out~bf66d13c"
    } == {(uid.interface(DEV, "Vlan10"), "out")}


def test_normalize_uncollected_acl_binding_is_fail_visible_not_silent():
    """UNCOLLECTED-ACL is bound and does not appear in `show ip access-lists`."""
    batch = _collector().normalize(ACL_RAW)
    rb_uid = "nxos:n9k1:acl:uncollected-acl~6bc82fe0"
    rb = next(n for n in batch.nodes if n.uid == rb_uid)
    assert rb.props["default_action"] == "deny"
    enforces = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENFORCES"}
    assert (DEV, rb_uid) in enforces
    src = next(n for n in batch.nodes if n.uid == f"{rb_uid}:1:src")
    assert src.props["opaque"] is True
    assert "UNCOLLECTED-ACL" in src.props["opaque_reason"]
    rule = next(n for n in batch.nodes if n.uid == f"{rb_uid}:1")
    assert "in_interface" not in rule.props
    assert any(
        r.rel_type == "PROTECTED_BY"
        and r.start_uid == uid.interface(DEV, "port-channel1")
        and r.end_uid == rb_uid
        for r in batch.rels
    )


def test_nat_failure_degrades_to_no_nat_nodes(monkeypatch):
    """A box without `feature nat` refuses the NAT running-config; the
    inventory must land with no NAT rulebase and nothing else missing."""
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd in (CMD_NAT, CMD_ACL):
            raise ssh.CommandFailed(f"{cmd!r} exited 1")
        return RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    inter = nxos.parse(raw)
    assert inter["nat"] == {"if_roles": {}, "pools": {}, "rules": [], "acls": {}}
    batch = c.normalize(raw)
    assert not [n for n in batch.nodes if n.label in ("FwRulebase", "NatRule")]
    assert inter["interfaces"] and inter["rib"]


# --- normalize: end-to-end spot checks ---------------------------------------------------


def test_normalize_serial_uid_and_vendor():
    batch = _collector().normalize(RAW)
    dev = next(n for n in batch.nodes if n.label == "Device")
    assert dev.uid == DEV
    assert dev.props["vendor"] == "cisco"
    assert dev.props["serial"] == SERIAL


def test_normalize_stamps_role_so_the_gateway_rule_can_see_the_box():
    """reasoner.py's gateway-from-router-interface rule keys on Device.role."""
    batch = _collector().normalize(RAW)
    dev = next(n for n in batch.nodes if n.label == "Device")
    assert dev.props["role"] in reasoner.GATEWAY_ROLES


def test_normalize_svi_shares_the_bridge_domain_uid():
    batch = _collector().normalize(RAW)
    vu = uid.vlan("nxos:n9k1", 10)
    seg = "bd:vlan:fab0:10"
    assert any(n.uid == vu and n.label == "VlanInstance" for n in batch.nodes)
    assert any(n.uid == seg and n.label == "BridgeDomain" for n in batch.nodes)


def test_normalize_svi_gets_in_vrf_toward_its_vrf_interface_vrf():
    batch = _collector().normalize(RAW)
    iu = uid.interface(DEV, "Vlan10")
    vru = uid.vrf(DEV, "prod")
    assert any(r.rel_type == "IN_VRF" and r.start_uid == iu and r.end_uid == vru for r in batch.rels)
    assert any(n.uid == vru and n.label == "VrfInstance" and n.props["name"] == "prod" for n in batch.nodes)


def test_normalize_lldp_hint_lands_on_the_port():
    batch = _collector().normalize(RAW)
    pu = uid.port(DEV, "Ethernet1/1")
    port = next(n for n in batch.nodes if n.uid == pu)
    assert port.props["lldp_neighbor_name"] == "core1"
    assert port.props["lldp_neighbor_mac"] == "aabbccddef01"
    assert port.props["lldp_neighbor_port"] == "Ethernet2/1"


# --- side_tables: rows carry the derived device_uid ---------------------------------------


def test_side_tables_rows_carry_device_uid():
    rows = _collector().side_tables(RAW)
    assert rows["rib"] and all(r["device_uid"] == DEV for r in rows["rib"])
    assert rows["mac"] and all(r["device_uid"] == DEV for r in rows["mac"])
    assert rows["arp"] and all(r["device_uid"] == DEV for r in rows["arp"])
    assert rows["rib"][0]["prefix"] == "10.0.0.0/24"


# --- fallback formula: side_tables' device_uid must match normalize()'s ---------------------


def test_side_tables_fallback_uid_matches_normalize_when_no_serial_or_hostname(monkeypatch):
    # side_tables() and cisco_common.normalize_cisco share `fallback_device_uid(inter, scope)`.
    bare_inter = {
        "device": {"hostname": None, "serial": None, "platform": "nxos", "os_version": "9.3(5)"},
        "interfaces": [],
        "neighbors": [],
        "vlans": [],
        "vrfs": [],
        "rib": [
            {"vrf": "default", "prefix": "10.0.0.0/24", "next_hop": None, "protocol": "direct", "metric": 0}
        ],
        "mac_table": [],
        "arp": [],
    }
    monkeypatch.setattr(nxos, "parse", lambda raw: bare_inter)
    c = _collector()
    batch = c.normalize(RAW)
    dev = next(n for n in batch.nodes if n.label == "Device")
    # the registry keys a box without serial and hostname by its scope
    assert c.scope == "nxos:n9k1"
    assert dev.uid == c.identity.resolve_device("ref", "nxos:n9k1:unknown", None)
    rows = c.side_tables(RAW)
    assert rows["rib"][0]["device_uid"] == dev.uid


@pytest.mark.parametrize("kind", ["phys", "lag", "loopback", "svi"])
def test_every_fixture_interface_kind_is_present(kind):
    inter = nxos.parse(RAW)
    assert any(i["kind"] == kind for i in inter["interfaces"])


def test_kind_subinterface_beats_lag_for_dotted_port_channel_name():
    assert nxos._kind("port-channel1.10") == "subif"
    assert nxos._kind("port-channel1") == "lag"


# --- Link speed: eth_speed/eth_duplex/eth_bw onto the Port ----------------------------------


def test_normalize_known_speed_and_duplex_land_on_the_port():
    batch = _collector().normalize(RAW)
    port = next(n for n in batch.nodes if n.uid == uid.port(DEV, "Ethernet1/1"))
    assert port.props["speed_mbps"] == 1000
    assert port.props["duplex"] == "full"
    assert port.props["speed_source"] == "nxos:eth_speed"
    assert port.props["bandwidth_kbit"] == 1000000


def test_normalize_auto_speed_and_duplex_give_nulls_and_no_source():
    batch = _collector().normalize(RAW)
    port = next(n for n in batch.nodes if n.uid == uid.port(DEV, "Ethernet1/2"))
    assert "speed_mbps" not in port.props
    assert "duplex" not in port.props
    assert "speed_source" not in port.props
    assert "bandwidth_kbit" not in port.props


def test_normalize_missing_speed_fields_give_nulls_and_no_source():
    """port-channel1's fixture row carries no eth_speed, eth_duplex or eth_bw."""
    batch = _collector().normalize(RAW)
    port = next(n for n in batch.nodes if n.uid == uid.port(DEV, "port-channel1"))
    assert "speed_mbps" not in port.props
    assert "duplex" not in port.props
    assert "speed_source" not in port.props


def test_normalize_gb_per_s_speed_converts_to_mbit():
    batch = _collector().normalize(RAW)
    port = next(n for n in batch.nodes if n.uid == uid.port(DEV, "Ethernet1/3"))
    assert port.props["speed_mbps"] == 10000
    assert port.props["duplex"] == "full"
    assert port.props["speed_source"] == "nxos:eth_speed"
    assert port.props["bandwidth_kbit"] == 10000000


# --- BGP/route-map/prefix-list: parse -----------------------------------------------------

CUST_A_RPU = uid.routing_process(DEV, "CUST-A", "bgp")
DEFAULT_RPU = uid.routing_process(DEV, "default", "bgp")
CUST_A_VRU = uid.vrf(DEV, "CUST-A")
RM_IN_UID = uid.route_policy(DEV, "route-map", "RM-IN")
RM_OUT_UID = uid.route_policy(DEV, "route-map", "RM-OUT")
RM_CONN_UID = uid.route_policy(DEV, "route-map", "RM-CONN")
PL_TEST_UID = uid.route_policy(DEV, "prefix-list", "PL-TEST")


def test_parse_bgp_default_and_per_vrf_processes():
    bgp = nxos.parse(RAW)["bgp"]
    procs = {p["vrf"]: p for p in bgp["processes"]}
    assert procs[None]["asn"] == 65001
    assert procs[None]["router_id"] == "10.255.0.1"
    assert procs[None]["neighbors"] == []
    assert procs["CUST-A"]["asn"] == 65001
    assert procs["CUST-A"]["router_id"] == "10.255.1.1"


def test_parse_bgp_neighbor_ebgp_and_ibgp():
    proc = next(p for p in nxos.parse(RAW)["bgp"]["processes"] if p["vrf"] == "CUST-A")
    by_peer = {n["peer_ip"]: n for n in proc["neighbors"]}
    # remote-as == the process's own asn means iBGP.
    assert by_peer["10.1.1.2"]["remote_as"] == 65001
    assert by_peer["10.1.1.2"]["route_map_in"] == "RM-IN"
    assert by_peer["10.1.1.2"]["route_map_out"] == "RM-OUT"
    assert by_peer["192.0.2.2"]["remote_as"] == 65099
    assert by_peer["192.0.2.2"]["route_map_out"] == "RM-OUT"
    assert by_peer["192.0.2.9"]["remote_as"] == 65098
    assert by_peer["192.0.2.9"]["route_map_in"] == "RM-GHOST"  # never defined


def test_parse_bgp_redistribution_route_map():
    proc = next(p for p in nxos.parse(RAW)["bgp"]["processes"] if p["vrf"] == "CUST-A")
    assert proc["redistribute"] == [{"protocol": "direct", "route_map": "RM-CONN"}]


def test_parse_prefix_list_eq_and_le():
    entries = nxos.parse(RAW)["bgp"]["prefix_lists"]["PL-TEST"]
    assert entries[0] == {
        "seq": 10,
        "action": "permit",
        "prefix": "10.0.0.0/8",
        "eq": None,
        "ge": None,
        "le": 24,
        "min_len": 8,
        "max_len": 24,
    }
    assert entries[1] == {
        "seq": 20,
        "action": "permit",
        "prefix": "172.16.0.0/16",
        "eq": 24,
        "ge": None,
        "le": None,
        "min_len": 24,
        "max_len": 24,
    }


def test_parse_route_map_continue_chain_and_set_clauses():
    clauses = nxos.parse(RAW)["bgp"]["route_maps"]["RM-IN"]
    assert [c["seq"] for c in clauses] == [10, 20]
    first, second = clauses
    assert first["action"] == "permit"
    assert first["match_prefix_lists"] == ["PL-TEST"]
    assert first["set_local_pref"] == 150
    assert first["continue_seq"] == 20
    assert second["set_communities"] == ["65001:100"]
    assert second["set_communities_additive"] is True
    assert second["continue_seq"] is None


def test_parse_route_map_keeps_a_match_line_it_cannot_read():
    """NX-OS applies `match ip address <acl>` to policy-based routing only."""
    clauses = nxos.parse_route_map_config(
        "route-map RM-ACL deny 10\n  match ip address ACL-10\n  match interface Ethernet1/1\n"
        "route-map RM-ACL permit 20\n"
    )["RM-ACL"]
    assert clauses[0]["match_unsupported"] == ["match interface Ethernet1/1"]
    assert clauses[0]["match_ignored"] == ["match ip address ACL-10"]
    assert "match_unsupported" not in clauses[1]


def test_parse_route_map_ghost_prefix_list_reference_is_recorded_raw():
    clause = nxos.parse(RAW)["bgp"]["route_maps"]["RM-OUT"][0]
    assert clause["match_prefix_lists"] == ["PL-GHOST"]
    assert clause["set_metric"] == 50


def test_bgp_failure_degrades_to_no_bgp_key(monkeypatch):
    """A box without `feature bgp` refuses the plain-text extracts."""
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd in (CMD_BGP, CMD_RPM):
            raise ssh.CommandFailed(f"{cmd!r} exited 1")
        return RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    inter = nxos.parse(raw)
    assert inter["bgp"] == {"processes": [], "route_maps": {}, "prefix_lists": {}}
    batch = c.normalize(raw)
    assert not [n for n in batch.nodes if n.label in ("BgpSession", "RoutePolicy")]
    # RoutingProcess by protocol, not by label: the same fixture's OSPF
    # capture succeeded, and its own process is not a BGP object.
    assert not [n for n in batch.nodes if n.label == "RoutingProcess" and n.props["proto"] == "bgp"]
    assert inter["interfaces"] and inter["rib"]


# --- BGP/route-map/prefix-list: normalize -------------------------------------------------


def test_normalize_routing_process_per_vrf():
    batch = _collector().normalize(RAW)
    proc = next(n for n in batch.nodes if n.uid == CUST_A_RPU)
    assert proc.label == "RoutingProcess"
    assert proc.props["proto"] == "bgp"
    assert proc.props["asn"] == 65001
    assert proc.props["router_id"] == "10.255.1.1"
    assert any(
        r.rel_type == "IN_VRF" and r.start_uid == CUST_A_RPU and r.end_uid == CUST_A_VRU for r in batch.rels
    )
    default_proc = next(n for n in batch.nodes if n.uid == DEFAULT_RPU)
    assert default_proc.props["router_id"] == "10.255.0.1"


def test_normalize_stub_vrf_instance_minted_for_a_vrf_bgp_only_knows_about():
    """CUST-A appears only under `router bgp ... vrf CUST-A`."""
    batch = _collector().normalize(RAW)
    vrf_node = next(n for n in batch.nodes if n.uid == CUST_A_VRU)
    assert vrf_node.label == "VrfInstance"
    assert vrf_node.props["name"] == "CUST-A"


def test_normalize_bgp_session_local_and_peer_asn_both_present():
    batch = _collector().normalize(RAW)
    ibgp = next(n for n in batch.nodes if n.uid == uid.bgp_session(CUST_A_RPU, "10.1.1.2", "CUST-A"))
    ebgp = next(n for n in batch.nodes if n.uid == uid.bgp_session(CUST_A_RPU, "192.0.2.2", "CUST-A"))
    assert ibgp.label == "BgpSession"
    assert ibgp.props["local_asn"] == 65001 and ibgp.props["peer_asn"] == 65001
    assert ebgp.props["local_asn"] == 65001 and ebgp.props["peer_asn"] == 65099
    assert any(
        r.rel_type == "HAS" and r.start_uid == CUST_A_RPU and r.end_uid == ibgp.uid for r in batch.rels
    )


def test_normalize_bgp_session_shutdown_neighbor_gets_state_shutdown(monkeypatch):
    """A `shutdown` line under a neighbor block must reach
    BgpSession.state so an administratively down peer is distinguishable from
    an up one; a neighbor with no `shutdown` line carries no state prop."""
    raw = dict(RAW)
    raw[CMD_BGP] = (
        "router bgp 65001\n"
        "  vrf CUST-A\n"
        "    neighbor 192.0.2.2\n"
        "      remote-as 65099\n"
        "      shutdown\n"
        "    neighbor 192.0.2.9\n"
        "      remote-as 65098\n"
    )
    raw[CMD_RPM] = RPM_CONFIG_TEXT
    c = _collector()
    batch = c.normalize(raw)
    shut = next(n for n in batch.nodes if n.uid == uid.bgp_session(CUST_A_RPU, "192.0.2.2", "CUST-A"))
    up = next(n for n in batch.nodes if n.uid == uid.bgp_session(CUST_A_RPU, "192.0.2.9", "CUST-A"))
    assert shut.props["state"] == "shutdown"
    assert "state" not in up.props


# --- BGP address families ------------------------------------------------------------------

AF_BGP_CONFIG = """\
router bgp 65001
  router-id 10.255.0.1
  address-family ipv4 unicast
    redistribute ospf 1 route-map RM-OSPF1
    redistribute ospf 2 route-map RM-OSPF2
  address-family ipv6 unicast
    redistribute static route-map RM-V6-STATIC
  neighbor 10.0.0.2
    remote-as 65001
    address-family l2vpn evpn
  neighbor 2001:db8::2
    remote-as 65002
    address-family ipv6 unicast
      route-map V6-IN in
  neighbor 10.0.0.3
    remote-as 65003
    address-family ipv4 unicast
    address-family ipv6 unicast
  neighbor 10.0.0.4
    remote-as 65004
"""
DEFAULT_BGP_RPU = uid.routing_process(DEV, "default", "bgp")


def _af_batch():
    raw = dict(RAW)
    raw[CMD_BGP] = AF_BGP_CONFIG
    return _collector().normalize(raw)


def _af_session(batch, peer):
    return next(n for n in batch.nodes if n.uid == uid.bgp_session(DEFAULT_BGP_RPU, peer, "default"))


def test_an_ipv6_redistribution_is_a_gap_and_not_an_ipv4_route_map():
    """An IPv6-only `redistribute static route-map X` filed on the process would
    redistribute every IPv4 static through X, and name `static` a protocol the
    process redistributes."""
    batch = _af_batch()
    process = next(n for n in batch.nodes if n.uid == DEFAULT_BGP_RPU)
    assert process.props["redistribute_protocols"] == ["ospf"]
    assert "redist_static_route_map" not in process.props
    assert any(
        "address-family ipv6 unicast redistribute static route-map RM-V6-STATIC" in g
        for g in process.props["origin_context_gaps"]
    )


def test_a_protocol_redistributed_through_two_route_maps_keeps_the_first_and_reports_the_second():
    batch = _af_batch()
    process = next(n for n in batch.nodes if n.uid == DEFAULT_BGP_RPU)
    assert process.props["redist_ospf_route_map"] == "RM-OSPF1"
    gaps = process.props["origin_context_gaps"]
    assert any("redistribute ospf 2 names route-map RM-OSPF2" in g and "RM-OSPF1" in g for g in gaps)


def test_the_same_route_map_for_two_instance_tags_is_not_a_gap():
    raw = dict(RAW)
    raw[CMD_BGP] = (
        "router bgp 65001\n"
        "  address-family ipv4 unicast\n"
        "    redistribute ospf 1 route-map RM\n"
        "    redistribute ospf 2 route-map RM\n"
    )
    process = next(n for n in _collector().normalize(raw).nodes if n.uid == DEFAULT_BGP_RPU)
    assert process.props["redist_ospf_route_map"] == "RM"
    assert not process.props["origin_context_gaps"]


def test_a_neighbor_states_the_address_families_it_activates():
    batch = _af_batch()
    assert _af_session(batch, "10.0.0.2").props["afi_safi"] == ["l2vpn-evpn"]
    assert _af_session(batch, "2001:db8::2").props["afi_safi"] == ["ipv6-unicast"]
    assert _af_session(batch, "10.0.0.3").props["afi_safi"] == ["ipv4-unicast", "ipv6-unicast"]
    # NX-OS exchanges nothing for a neighbor that activates no family
    assert _af_session(batch, "10.0.0.4").props.get("afi_safi") in ([], None)


def test_a_neighbor_with_an_unresolved_template_is_a_process_gap_and_no_session():
    raw = dict(RAW)
    raw[CMD_BGP] = "router bgp 65001\n  neighbor 10.0.0.9\n    remote-as 65009\n    inherit peer MISSING\n"
    batch = _collector().normalize(raw)
    process = next(n for n in batch.nodes if n.uid == DEFAULT_BGP_RPU)
    assert any(
        "neighbor 10.0.0.9 has unresolved template inheritance" in g for g in process.props["session_gaps"]
    )
    assert not [n for n in batch.nodes if n.label == "BgpSession" and n.props.get("peer_ip") == "10.0.0.9"]


def test_normalize_bgp_session_filtered_by_attached_route_maps():
    batch = _collector().normalize(RAW)
    su = uid.bgp_session(CUST_A_RPU, "10.1.1.2", "CUST-A")
    session = next(n for n in batch.nodes if n.uid == su)
    assert session.props["import_policy_name"] == "RM-IN"
    assert session.props["import_policy_kind"] == "route-map"
    assert session.props["export_policy_name"] == "RM-OUT"
    assert session.props["export_policy_kind"] == "route-map"
    edges = {(r.rel_type, r.end_uid, r.key.get("direction")) for r in batch.rels if r.start_uid == su}
    assert ("FILTERED_BY", RM_IN_UID, "in") in edges
    assert ("FILTERED_BY", RM_OUT_UID, "out") in edges


def test_normalize_prefix_list_policy_and_entries():
    batch = _collector().normalize(RAW)
    policy = next(n for n in batch.nodes if n.uid == PL_TEST_UID)
    assert policy.label == "RoutePolicy" and policy.props["kind"] == "prefix-list"
    e10 = uid.prefix_list_entry(PL_TEST_UID, 10)
    e20 = uid.prefix_list_entry(PL_TEST_UID, 20)
    n10 = next(n for n in batch.nodes if n.uid == e10)
    n20 = next(n for n in batch.nodes if n.uid == e20)
    assert n10.label == "PrefixListEntry"
    assert n10.props["min_len"] == 8 and n10.props["max_len"] == 24 and n10.props["le"] == 24
    assert n20.props["min_len"] == 24 and n20.props["max_len"] == 24 and n20.props["eq"] == 24
    assert any(
        r.rel_type == "HAS_RULE" and r.start_uid == PL_TEST_UID and r.end_uid == e10 for r in batch.rels
    )


def test_normalize_route_map_continue_chain_and_set_clauses():
    batch = _collector().normalize(RAW)
    e10 = uid.route_policy_entry(RM_IN_UID, 10)
    e20 = uid.route_policy_entry(RM_IN_UID, 20)
    n10 = next(n for n in batch.nodes if n.uid == e10)
    n20 = next(n for n in batch.nodes if n.uid == e20)
    assert n10.label == "RoutePolicyEntry" and n10.props["kind"] == "clause"
    assert n10.props["continues"] is True and n10.props["continue_seq"] == 20
    assert n10.props["set_local_pref"] == 150
    assert n20.props["set_communities"] == ["65001:100"]
    assert n20.props["set_communities_additive"] is True
    assert any(r.rel_type == "HAS_RULE" and r.start_uid == RM_IN_UID and r.end_uid == e10 for r in batch.rels)


def test_normalize_route_policy_entry_references_resolved_prefix_list():
    batch = _collector().normalize(RAW)
    e10 = uid.route_policy_entry(RM_IN_UID, 10)
    entry = next(n for n in batch.nodes if n.uid == e10)
    assert entry.props["match_prefix_lists"] == ["PL-TEST"]
    assert any(
        r.rel_type == "REFERENCES" and r.start_uid == e10 and r.end_uid == PL_TEST_UID for r in batch.rels
    )


def test_normalize_redistribution_filtered_by_resolved_route_map():
    batch = _collector().normalize(RAW)
    proc = next(n for n in batch.nodes if n.uid == CUST_A_RPU)
    assert proc.props["redist_direct_route_map"] == "RM-CONN"
    edge = next(
        r
        for r in batch.rels
        if r.rel_type == "FILTERED_BY" and r.start_uid == CUST_A_RPU and r.end_uid == RM_CONN_UID
    )
    assert edge.key == {"direction": "redistribute", "protocol": "direct"}


def test_normalize_dangling_neighbor_route_map_warns_no_edge_raw_name_kept(caplog):
    """The neighbor `route-map RM-GHOST in` names a route-map that is never defined."""
    c = _collector()
    su = uid.bgp_session(CUST_A_RPU, "192.0.2.9", "CUST-A")
    batch = c.normalize(RAW)
    session = next(n for n in batch.nodes if n.uid == su)
    assert session.props["import_policy_name"] == "RM-GHOST"
    assert session.props["import_policy_kind"] == "route-map"
    assert not any(r.rel_type == "FILTERED_BY" and r.start_uid == su for r in batch.rels)
    assert "RM-GHOST" in caplog.text
    assert "undefined" in caplog.text


def test_normalize_dangling_match_prefix_list_warns_no_references_edge(caplog):
    """RM-OUT's `match ip address prefix-list PL-GHOST` names an undefined prefix-list."""
    c = _collector()
    e10 = uid.route_policy_entry(RM_OUT_UID, 10)
    batch = c.normalize(RAW)
    entry = next(n for n in batch.nodes if n.uid == e10)
    assert entry.props["match_prefix_lists"] == ["PL-GHOST"]
    assert not any(r.rel_type == "REFERENCES" and r.start_uid == e10 for r in batch.rels)
    assert "PL-GHOST" in caplog.text
    assert "undefined" in caplog.text


def test_normalize_neighbor_with_no_remote_as_is_dropped(monkeypatch, caplog):
    """An absent `remote-as` makes the peer unusable."""
    raw = dict(RAW)
    raw[CMD_BGP] = (
        "router bgp 65001\n"
        "  vrf CUST-A\n"
        "    neighbor 192.0.2.50\n"
        "      address-family ipv4 unicast\n"
        "        route-map RM-OUT out\n"
    )
    raw[CMD_RPM] = RPM_CONFIG_TEXT
    c = _collector()
    batch = c.normalize(raw)
    assert not [n for n in batch.nodes if n.label == "BgpSession"]
    assert "192.0.2.50" in caplog.text
    assert "no remote-as" in caplog.text


def test_normalize_neighbor_with_a_listen_range_is_dropped_not_a_session(monkeypatch, caplog):
    """`neighbor 10.0.0.0/24` is a listen range."""
    raw = dict(RAW)
    raw[CMD_BGP] = "router bgp 65001\n  vrf CUST-A\n    neighbor 10.0.0.0/24\n      remote-as 65001\n"
    raw[CMD_RPM] = RPM_CONFIG_TEXT
    c = _collector()
    batch = c.normalize(raw)
    assert not [n for n in batch.nodes if n.label == "BgpSession"]
    assert "10.0.0.0/24" in caplog.text


def test_normalize_bgp_nodes_absent_when_bgp_key_missing_entirely(monkeypatch):
    inter = {
        "device": {"hostname": "sw2", "serial": "FDO9999ZZZZ", "platform": "nxos", "os_version": "9.3(5)"},
        "interfaces": [],
        "neighbors": [],
        "vlans": [],
        "vrfs": [],
        "rib": [],
        "mac_table": [],
        "arp": [],
    }
    monkeypatch.setattr(nxos, "parse", lambda raw: inter)
    batch = _collector().normalize(RAW)
    assert not [n for n in batch.nodes if n.label in ("RoutingProcess", "BgpSession", "RoutePolicy")]


# --- OSPF: parse --------------------------------------------------------------------------

OSPF_RPU = uid.routing_process(DEV, "default", "ospf-1")


def _ospf(raw=None):
    return nxos.parse(raw or RAW)["ospf"]


def test_parse_ospf_process_router_id_and_areas():
    procs = _ospf()["processes"]
    assert len(procs) == 1
    proc = procs[0]
    assert (proc["process"], proc["vrf"], proc["router_id"]) == ("1", "", "10.255.0.1")
    assert {a["area_id"]: a["type"] for a in proc["areas"]} == {
        AREA_0: "normal",
        "0.0.0.10": "nssa",
        # the operational table does not classify it; the running-config does
        "0.0.0.20": "stub",
    }


def test_parse_ospf_redistribution_route_maps():
    """Mirrors the BGP redistribution parse: one entry per protocol that names
    a route-map, in the config's own order."""
    assert _ospf()["processes"][0]["redistribute"] == [
        {"protocol": "direct", "route_map": "RM-CONN"},
        {"protocol": "bgp", "route_map": "RM-GHOST"},
    ]


def test_parse_ospf_interfaces_carry_cost_network_type_and_passive():
    by_name = {i["name"]: i for i in _ospf()["interfaces"]}
    assert by_name["Ethernet1/1"]["area"] == AREA_0
    assert by_name["Ethernet1/1"]["cost"] == 40
    # the platform's own word for the network type lands as the protocol's
    assert by_name["Ethernet1/1"]["network_type"] == "point-to-point"
    assert by_name["Ethernet1/1"]["passive"] is False
    assert by_name["Vlan10"]["network_type"] == "broadcast"
    assert by_name["Vlan10"]["passive"] is True
    assert by_name["loopback0"]["network_type"] == "loopback"


def test_parse_ospf_adjacencies_carry_state_and_the_area_of_their_interface():
    by_rid = {a["neighbor_router_id"]: a for a in _ospf()["adjacencies"]}
    assert by_rid["10.255.0.2"]["state"] == "FULL"
    assert by_rid["10.255.0.2"]["local_interface"] == "Ethernet1/1"
    assert by_rid["10.255.0.2"]["neighbor_ip"] == "10.0.0.2"
    # the neighbor table states no area; the interface the adjacency runs
    # over is where it comes from
    assert by_rid["10.255.0.2"]["area"] == AREA_0
    assert by_rid["10.255.0.3"]["state"] == "2WAY"
    assert by_rid["10.255.0.3"]["area"] == "0.0.0.10"


def test_parse_ospf_router_lsa_carries_its_links():
    """The per-area database nesting, and the body a router LSA needs: no
    LSA-level metric, one entry per link with its own."""
    lsa = next(r for r in _ospf()["lsdb"] if r["lsa_type"] == "router")
    assert (lsa["area"], lsa["lsid"], lsa["adv_router"]) == (AREA_0, "10.255.0.1", "10.255.0.1")
    assert (lsa["age"], lsa["seq"]) == (120, 0x80000005)
    assert lsa["metric"] is None
    assert lsa["links"] == [
        {"link_type": "point-to-point", "link_id": "10.255.0.2", "link_data": "10.0.0.1", "metric": 40},
        {"link_type": "stub", "link_id": "10.0.0.0", "link_data": "255.255.255.0", "metric": 40},
    ]


def test_parse_ospf_network_lsa_carries_its_attached_routers():
    """The flat database nesting, with the area on the LSA row itself."""
    lsa = next(r for r in _ospf()["lsdb"] if r["lsa_type"] == "network")
    assert lsa["area"] == AREA_0
    assert lsa["attached_routers"] == ["10.255.0.1", "10.255.0.2"]
    assert lsa["mask"] == "255.255.255.0"


def test_parse_ospf_summary_lsa_mask_normalizes_a_prefix_length():
    lsa = next(r for r in _ospf()["lsdb"] if r["lsa_type"] == "summary")
    assert (lsa["area"], lsa["lsid"], lsa["mask"], lsa["metric"]) == (
        "0.0.0.10",
        "10.10.10.0",
        "255.255.255.0",
        20,
    )


def test_parse_ospf_external_lsa_carries_forwarding_address_and_metric_type():
    """An AS-external LSA belongs to no area: it is flooded domain-wide."""
    lsa = next(r for r in _ospf()["lsdb"] if r["lsa_type"] == "external")
    assert lsa["area"] is None
    assert lsa["forwarding_address"] == "10.0.0.2"
    assert lsa["metric_type"] == 2
    assert lsa["metric"] == 100


def test_parse_ospf_nssa_external_lsa_belongs_to_its_nssa_and_carries_a_type_5_body():
    """A type 7 is originated inside one NSSA and stays there, so unlike a
    type 5 it carries an area. Its body is a type 5's."""
    lsa = next(r for r in _ospf()["lsdb"] if r["lsa_type"] == "nssa-external")
    assert lsa["area"] == "0.0.0.10"
    assert (lsa["lsid"], lsa["adv_router"]) == ("198.51.100.0", "10.255.0.3")
    assert lsa["mask"] == "255.255.255.128"
    assert lsa["metric"] == 50
    assert lsa["metric_type"] == 1
    assert lsa["forwarding_address"] == "10.10.10.2"


def test_parse_ospf_asbr_summary_lsa_names_the_asbr_and_the_metric_to_it():
    """The network-mask field is unused for a type 4 LSA (RFC 2328 A.4.4)."""
    lsa = next(r for r in _ospf()["lsdb"] if r["lsa_type"] == "asbr-summary")
    assert lsa["area"] == "0.0.0.10"
    assert (lsa["lsid"], lsa["adv_router"]) == ("10.255.0.9", "10.255.0.1")
    assert lsa["metric"] == 30
    assert lsa["mask"] is None
    assert lsa["links"] is None and lsa["attached_routers"] is None

    with_mask = nxos._ospf_lsas(
        {
            "TABLE_ctx": {
                "ROW_ctx": {
                    "ptag": "1",
                    "cname": "default",
                    "TABLE_lsdb": {
                        "ROW_lsdb": {
                            "area": "0.0.0.10",
                            "lsid": "10.255.0.9",
                            "netmask": "255.255.255.252",
                            "metric": "30",
                        }
                    },
                }
            }
        },
        "asbr-summary",
    )
    assert with_mask[0]["mask"] == "255.255.255.252"


def test_parse_ospf_config_reads_a_per_vrf_process():
    """`vrf <name>` under `router ospf` is its own process, the same way it is
    under `router bgp`."""
    parsed = nxos.parse_ospf_config(
        "router ospf 1\n"
        "  router-id 10.255.0.1\n"
        "  vrf CUST-A\n"
        "    router-id 10.255.1.1\n"
        "    redistribute static route-map RM-CONN\n"
    )
    assert parsed[("1", "")]["router_id"] == "10.255.0.1"
    assert parsed[("1", "CUST-A")]["router_id"] == "10.255.1.1"
    assert parsed[("1", "CUST-A")]["redistribute"] == [{"protocol": "static", "route_map": "RM-CONN"}]
    # the default-VRF block must not absorb the VRF block's own lines
    assert parsed[("1", "")]["redistribute"] == []


def test_parse_ospf_redistribute_without_a_route_map_attaches_no_policy():
    """`redistribute static` with no route-map is the absence of a filter, not
    an unnamed one, so it is not recorded as an attachment."""
    parsed = nxos.parse_ospf_config("router ospf 1\n  redistribute static\n")
    assert parsed[("1", "")]["redistribute"] == []


def test_parse_ospf_area_zero_is_the_same_area_written_either_way():
    parsed = nxos.parse_ospf_config("router ospf 1\n  area 0 nssa\n")
    assert parsed[("1", "")]["area_types"] == {AREA_0: "nssa"}


def test_ospf_failure_degrades_to_an_empty_ospf_shape(monkeypatch):
    """A box without `feature ospf` refuses every OSPF command."""
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd in nxos.OSPF_COMMANDS:
            raise ssh.CommandFailed(f"{cmd!r} exited 1: % Invalid command at '^' marker")
        return RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    inter = nxos.parse(raw)
    assert inter["ospf"] == {"processes": [], "interfaces": [], "adjacencies": [], "lsdb": []}
    assert inter["interfaces"] and inter["rib"]
    batch = c.normalize(raw)
    assert not [n for n in batch.nodes if n.label in ("OspfArea", "OspfAdjacency")]


def test_parse_ospf_absent_for_a_payload_that_predates_the_capture():
    """A raw file sealed before the OSPF commands existed carries none of them."""
    older = {k: v for k, v in RAW.items() if k not in nxos.OSPF_COMMANDS}
    assert nxos.parse_ospf(older) is None
    assert "ospf" not in nxos.parse(older)


def test_ospf_sections_report_what_each_command_produced(monkeypatch):
    sections = _sections(monkeypatch, RAW)
    assert sections["ospf"].status == "ok"
    assert sections["ospf_neighbors"].status == "ok"
    assert sections["ospf_config"].status == "ok"
    # one section per database command, the two later types included
    assert sections["ospf_lsdb_nssa_external"].status == "ok"
    assert sections["ospf_lsdb_asbr_summary"].status == "ok"


def test_a_box_without_the_ospf_feature_reads_unsupported_not_failed(monkeypatch):
    """NX-OS answers a command for a disabled feature with an invalid-command
    banner. That is a box without the feature, not a fault: the sections read
    `unsupported`, which does not degrade the device."""
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd in nxos.OSPF_COMMANDS:
            raise ssh.CommandFailed(f"{cmd!r} exited 1: % Invalid command at '^' marker")
        return RAW[cmd]

    sections = _sections(monkeypatch, outputs)
    assert sections["ospf"].status == "unsupported"
    assert sections["ospf_lsdb_router"].status == "unsupported"
    assert sections["interfaces"].status == "ok"


# --- OSPF: the side-store table and its outcome -------------------------------------------


def test_side_tables_carry_the_lsdb_rows_keyed_to_the_device_and_context():
    tables = _collector().side_tables(RAW)
    assert "ospf_lsdb" in tables
    assert {"rib", "mac", "arp"} <= set(tables)
    rows = tables["ospf_lsdb"]
    assert {r["lsa_type"] for r in rows} == {
        "router",
        "network",
        "summary",
        "external",
        "nssa-external",
        "asbr-summary",
    }
    assert {r["device_uid"] for r in rows} == {DEV}
    assert {r["context_uid"] for r in rows} == {DEFAULT_VRF_UID}
    assert {r["process"] for r in rows} == {"1"}


def test_the_lsdb_table_is_declared_so_a_run_accounts_for_it():
    assert "ospf_lsdb" in NxosCollector.SIDE_TABLES


def test_a_box_without_the_ospf_feature_reports_the_lsdb_table_unsupported(monkeypatch):
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd in nxos.OSPF_COMMANDS:
            raise ssh.CommandFailed(f"{cmd!r} exited 1: % Invalid command at '^' marker")
        return RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    outcome = nxos.ospf_table_outcomes(raw)["ospf_lsdb"]
    assert outcome.status == "unsupported"
    assert outcome.detail
    assert c.table_outcomes(raw)["ospf_lsdb"].status == "unsupported"
    assert c.side_tables(raw)["ospf_lsdb"] == []


def test_a_device_that_answered_the_ospf_commands_reports_no_unsupported_table(monkeypatch):
    """An enabled process with an empty database is a table that was read and
    came back empty, never an absent feature."""
    empty = {**RAW, **dict.fromkeys(nxos.OSPF_COMMANDS, "{}")}
    empty[CMD_OSPF_CONFIG] = ""
    FakeSshSession(empty).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    assert nxos.ospf_table_outcomes(raw) == {}
    assert "ospf_lsdb" not in c.table_outcomes(raw)
    assert c.side_tables(raw)["ospf_lsdb"] == []


def test_a_payload_with_no_recorded_outcomes_claims_nothing_about_the_feature():
    assert nxos.ospf_table_outcomes(dict(RAW)) == {}


# --- OSPF: every VRF -----------------------------------------------------------------------
# Without `vrf all` NX-OS answers the OSPF commands for the default VRF alone.

TENANT_LSA = {"lsid": "10.255.1.1", "advrouter": "10.255.1.1", "age": "5", "seqno": "0x80000001"}


def _tenant_ctx(**body):
    return {"ptag": "1", "cname": "TENANT", **body}


def _with_tenant(payload, row):
    ctx = payload["TABLE_ctx"]["ROW_ctx"]
    return {"TABLE_ctx": {"ROW_ctx": [*(ctx if isinstance(ctx, list) else [ctx]), row]}}


def _tenant_answers():
    """The answers of a box that runs OSPF in the default VRF and in TENANT."""
    answers = dict(RAW)
    answers[CMD_OSPF] = json.dumps(
        _with_tenant(
            OSPF_PAYLOAD,
            _tenant_ctx(rid="10.255.1.1", TABLE_area={"ROW_area": {"aid": "0.0.0.5"}}),
        )
    )
    answers[CMD_OSPF_IF] = json.dumps(
        _with_tenant(
            OSPF_IF_PAYLOAD,
            _tenant_ctx(TABLE_intf={"ROW_intf": {"ifname": "Ethernet1/9", "area": "0.0.0.5", "cost": "7"}}),
        )
    )
    answers[CMD_OSPF_DB_ROUTER] = json.dumps(
        _with_tenant(
            OSPF_DB_ROUTER_PAYLOAD,
            _tenant_ctx(TABLE_area={"ROW_area": {"aid": "0.0.0.5", "TABLE_lsdb": {"ROW_lsdb": TENANT_LSA}}}),
        )
    )
    answers[CMD_OSPF_CONFIG] = OSPF_CONFIG_TEXT + "  vrf TENANT\n    router-id 10.255.1.1\n"
    return answers


def _legacy(raw):
    """The payload under the `LEGACY_OSPF_COMMANDS` spellings, with each recorded
    outcome under the same spelling."""
    old = nxos.LEGACY_OSPF_COMMANDS
    out = {old.get(key, key): value for key, value in raw.items()}
    stored = raw.get(nxos.RAW_OUTCOMES_KEY)
    if isinstance(stored, dict):
        out[nxos.RAW_OUTCOMES_KEY] = {old.get(key, key): value for key, value in stored.items()}
    return out


def test_every_ospf_read_asks_for_every_vrf():
    asked = [cmd for cmd in nxos.OSPF_COMMANDS if cmd != CMD_OSPF_CONFIG]
    assert len(asked) == 9
    assert all(cmd.endswith(" vrf all | json") for cmd in asked)
    assert set(nxos.LEGACY_OSPF_COMMANDS) == set(asked)
    assert all(old == cmd.replace(" vrf all", "") for cmd, old in nxos.LEGACY_OSPF_COMMANDS.items())


def test_a_tenant_vrf_process_has_its_areas_interfaces_and_lsas():
    ospf = nxos.parse(_tenant_answers())["ospf"]
    tenant = next(p for p in ospf["processes"] if p["vrf"] == "TENANT")
    assert "observed" not in tenant
    assert tenant["router_id"] == "10.255.1.1"
    assert [a["area_id"] for a in tenant["areas"]] == ["0.0.0.5"]
    assert [i["name"] for i in ospf["interfaces"] if i["vrf"] == "TENANT"] == ["Ethernet1/9"]
    assert [r["lsid"] for r in ospf["lsdb"] if r["vrf"] == "TENANT"] == ["10.255.1.1"]


def test_each_context_states_whether_its_database_was_read(monkeypatch):
    """The table outcome states the device; each context states its own. The
    default VRF holds LSAs, TENANT holds one, and a VRF the running-config
    declares that the operational table does not list was not read."""
    answers = _tenant_answers()
    answers[CMD_OSPF_CONFIG] += "  vrf GHOST\n    router-id 10.255.2.1\n"
    FakeSshSession(answers).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    device = c._device_uid(c._inter(raw))

    outcomes = c.table_outcomes(raw)

    context = {
        vrf: outcomes.get(manifest.ospf_context_key(uid.vrf(device, vrf)))
        for vrf in ("default", "TENANT", "GHOST")
    }
    assert context["default"].status == "complete"
    assert context["TENANT"].status == "complete"
    assert context["TENANT"].row_count == 1
    assert context["GHOST"].status == "not-captured"
    assert "did not answer for this VRF" in context["GHOST"].detail
    assert "ospf_lsdb" not in outcomes


def test_a_process_with_no_lsas_in_its_vrf_is_complete_empty(monkeypatch):
    answers = _tenant_answers()
    answers[CMD_OSPF_DB_ROUTER] = RAW[CMD_OSPF_DB_ROUTER]
    FakeSshSession(answers).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    device = c._device_uid(c._inter(raw))

    outcome = c.table_outcomes(raw)[manifest.ospf_context_key(uid.vrf(device, "TENANT"))]

    assert (outcome.status, outcome.row_count) == ("complete-empty", 0)


def test_a_payload_sealed_with_the_legacy_ospf_commands_is_read_and_claims_the_default_vrf_alone(monkeypatch):
    """A process that only the running-config declares is not claimed as observed."""
    FakeSshSession(_tenant_answers()).install(monkeypatch)
    c = _collector()
    fetched = c.fetch()
    legacy = _legacy(
        {
            **fetched,
            CMD_OSPF: RAW[CMD_OSPF],
            CMD_OSPF_IF: RAW[CMD_OSPF_IF],
            CMD_OSPF_DB_ROUTER: RAW[CMD_OSPF_DB_ROUTER],
        }
    )
    assert CMD_OSPF not in legacy
    assert "show ip ospf | json" in legacy

    ospf = nxos.parse(legacy)["ospf"]
    by_vrf = {p["vrf"]: p for p in ospf["processes"]}
    assert "observed" not in by_vrf[""]
    assert by_vrf["TENANT"]["observed"] is False
    assert by_vrf["TENANT"]["areas"] == []
    assert {r["vrf"] for r in ospf["lsdb"]} == {""}

    device = c._device_uid(c._inter(legacy))
    outcomes = c.table_outcomes(legacy)
    tenant = outcomes[manifest.ospf_context_key(uid.vrf(device, "TENANT"))]
    assert tenant.status == "not-captured"
    assert "default VRF alone" in tenant.detail
    assert outcomes[manifest.ospf_context_key(uid.vrf(device, "default"))].status == "complete"
    assert c.sections(legacy)["ospf"].status == "ok"
    assert c.sections(legacy)["ospf_lsdb_router"].status == "ok"


def test_the_legacy_ospf_commands_beside_the_vrf_all_ones_do_not_make_a_payload_default_only():
    assert nxos.ospf_default_vrf_only(_legacy(RAW)) is True
    assert nxos.ospf_default_vrf_only(RAW) is False
    assert nxos.ospf_default_vrf_only({**RAW, **_legacy(RAW)}) is False


# --- OSPF: normalize ----------------------------------------------------------------------


def test_normalize_ospf_process_is_a_routing_process_in_its_vrf():
    batch = _collector().normalize(RAW)
    proc = next(n for n in batch.nodes if n.uid == OSPF_RPU)
    assert proc.label == "RoutingProcess"
    assert proc.props["proto"] == "ospf"
    assert proc.props["process_id"] == "1"
    assert proc.props["router_id"] == "10.255.0.1"
    assert any(
        r.rel_type == "IN_VRF" and r.start_uid == OSPF_RPU and r.end_uid == DEFAULT_VRF_UID
        for r in batch.rels
    )


def test_normalize_ospf_areas_carry_their_type():
    batch = _collector().normalize(RAW)
    areas = {n.props["area_id"]: n.props.get("type") for n in batch.nodes if n.label == "OspfArea"}
    assert areas == {AREA_0: "normal", "0.0.0.10": "nssa", "0.0.0.20": "stub"}
    for area_id in areas:
        au = uid.ospf_area(OSPF_RPU, area_id)
        assert any(r.rel_type == "HAS" and r.start_uid == OSPF_RPU and r.end_uid == au for r in batch.rels)


def test_normalize_interface_in_area_carries_cost_network_type_and_passive():
    batch = _collector().normalize(RAW)
    iu = uid.interface(DEV, "Ethernet1/1")
    edge = next(r for r in batch.rels if r.rel_type == "IN_AREA" and r.start_uid == iu)
    assert edge.end_uid == uid.ospf_area(OSPF_RPU, AREA_0)
    assert edge.props["cost"] == 40
    assert edge.props["network_type"] == "point-to-point"
    assert edge.props["passive"] is False
    svi = next(
        r for r in batch.rels if r.rel_type == "IN_AREA" and r.start_uid == uid.interface(DEV, "Vlan10")
    )
    assert svi.props["passive"] is True


def test_normalize_ospf_interface_with_no_interface_node_is_fail_visible(caplog):
    """The process reports Ethernet1/48, which the interface table never listed."""
    batch = _collector().normalize(RAW)
    missing = uid.interface(DEV, "Ethernet1/48")
    assert not [r for r in batch.rels if r.rel_type == "IN_AREA" and r.start_uid == missing]
    assert "Ethernet1/48" in caplog.text


def test_normalize_ospf_adjacency_endpoints_the_local_interface():
    batch = _collector().normalize(RAW)
    iu = uid.interface(DEV, "Ethernet1/1")
    adju = uid.ospf_adjacency(OSPF_RPU, iu, "10.255.0.2")
    adj = next(n for n in batch.nodes if n.uid == adju)
    assert adj.label == "OspfAdjacency"
    assert adj.props["state"] == "FULL"
    assert adj.props["area"] == AREA_0
    assert adj.props["neighbor_router_id"] == "10.255.0.2"
    assert adj.props["neighbor_ip"] == "10.0.0.2"
    assert any(r.rel_type == "ENDPOINT" and r.start_uid == adju and r.end_uid == iu for r in batch.rels)
    assert any(r.rel_type == "HAS" and r.start_uid == OSPF_RPU and r.end_uid == adju for r in batch.rels)


def test_normalize_ospf_redistribution_filtered_by_resolved_route_map():
    """RM-GHOST is defined nowhere."""
    batch = _collector().normalize(RAW)
    proc = next(n for n in batch.nodes if n.uid == OSPF_RPU)
    assert proc.props["redist_direct_route_map"] == "RM-CONN"
    assert proc.props["redist_bgp_route_map"] == "RM-GHOST"
    edges = [r for r in batch.rels if r.rel_type == "FILTERED_BY" and r.start_uid == OSPF_RPU]
    assert [(r.key["protocol"], r.end_uid) for r in edges] == [
        ("direct", uid.route_policy(DEV, "route-map", "RM-CONN"))
    ]
    assert all(r.key["direction"] == "redistribute" for r in edges)


def test_normalize_ospf_objects_absent_when_the_ospf_key_is_missing_entirely(monkeypatch):
    inter = dict(nxos.parse(RAW))
    del inter["ospf"]
    monkeypatch.setattr(nxos, "parse", lambda raw: inter)
    batch = _collector().normalize(RAW)
    assert not [n for n in batch.nodes if n.label in ("OspfArea", "OspfAdjacency")]
    assert not [n for n in batch.nodes if n.label == "RoutingProcess" and n.props["proto"] == "ospf"]


# --- BGP observations: the capture, the parse, and the outcomes it records -----------------


CUST_A_UID = uid.vrf(DEV, "CUST-A")


def _bgp_collector(capture="all"):
    return NxosCollector(
        NxosConfig(
            host=HOST,
            auth=SshPassword(username=USER, password="pw"),
            site_code="hq",
            l3dom="corp",
            capture_bgp=capture,
        ),
        None,
    )


def _session_uid(peer_ip, vrf="CUST-A"):
    """The BgpSession uid an observed row of this peer joins the graph through."""
    return uid.bgp_session(uid.routing_process(DEV, vrf, "bgp"), peer_ip, vrf)


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


def test_capture_all_reads_the_session_table_and_three_directions_per_peer(monkeypatch):
    """The per-neighbor commands are derived from the BGP running-config this
    same fetch read, so the command set is per fetch and not per class."""
    _c, raw, fake = _fetch(monkeypatch)
    assert fake.commands[: len(nxos.COMMANDS)] == list(nxos.COMMANDS)
    derived = fake.commands[len(nxos.COMMANDS) :]
    assert derived[0] == CMD_BGP_SESSIONS
    assert derived[1] == nxos.CMD_BGP_NEIGHBORS
    assert derived[2:5] == [
        nxos.bgp_route_command("CUST-A", "10.1.1.2", d) for d in ("received", "accepted", "advertised")
    ]
    assert len(derived) == 2 + 3 * 3  # the session and neighbor tables, then three peers
    assert CMD_BGP_SESSIONS in raw


def test_capture_none_asks_the_device_for_nothing_beyond_the_static_commands(monkeypatch):
    collector, raw, fake = _fetch(monkeypatch, capture="none")
    assert fake.commands == list(nxos.COMMANDS)
    assert CMD_BGP_SESSIONS not in raw
    outcomes = collector.table_outcomes(raw)
    assert outcomes["bgp_sessions"].status == "not-captured"
    assert outcomes["bgp_session_routes"].status == "not-captured"
    assert "capture_bgp setting is none" in outcomes["bgp_session_routes"].detail
    # every direction of every configured session is stated too
    directions = _directions(collector, raw)
    assert len(directions) == 9
    assert {o.status for o in directions.values()} == {"not-captured"}


def test_capture_sessions_reads_state_only_and_states_the_paths_not_captured(monkeypatch):
    collector, raw, fake = _fetch(monkeypatch, capture="sessions")
    assert fake.commands == [*nxos.COMMANDS, CMD_BGP_SESSIONS, nxos.CMD_BGP_NEIGHBORS]
    outcomes = collector.table_outcomes(raw)
    # the session table was read, so this run states nothing about it and the
    # write's own outcome stands; only the path table was left out
    assert "bgp_sessions" not in outcomes
    assert outcomes["bgp_session_routes"].status == "not-captured"
    tables = collector.side_tables(raw)
    assert [r["peer_ip"] for r in tables["bgp_sessions"]] == ["10.1.1.2", "192.0.2.2", "192.0.2.9"]
    assert tables["bgp_session_routes"] == []


def test_the_session_table_is_asked_for_every_vrf():
    """Without the `vrf all` clause NX-OS answers for the default VRF alone."""
    assert CMD_BGP_SESSIONS == "show bgp sessions vrf all | json"


def test_a_box_that_refuses_the_vrf_all_clause_is_asked_for_the_default_vrf(monkeypatch):
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd == CMD_BGP_SESSIONS:
            raise ssh.CommandFailed(f"{cmd!r} exited 16: Syntax error while parsing {cmd!r}")
        if cmd == nxos.CMD_BGP_SESSIONS_DEFAULT_VRF:
            return RAW[CMD_BGP_SESSIONS]
        return RAW[cmd]

    fake = FakeSshSession(outputs).install(monkeypatch)
    collector = _bgp_collector("sessions")
    raw = collector.fetch()
    assert fake.commands[len(nxos.COMMANDS) :] == [
        CMD_BGP_SESSIONS,
        nxos.CMD_BGP_NEIGHBORS,
        nxos.CMD_BGP_SESSIONS_DEFAULT_VRF,
    ]
    assert nxos.bgp_sessions_command(raw) == nxos.CMD_BGP_SESSIONS_DEFAULT_VRF
    assert "bgp_sessions" not in collector.table_outcomes(raw)
    assert [r["peer_ip"] for r in collector.side_tables(raw)["bgp_sessions"]] == [
        "10.1.1.2",
        "192.0.2.2",
        "192.0.2.9",
    ]


def test_a_payload_sealed_with_the_default_vrf_table_reads_and_hashes_like_the_vrf_all_one():
    """Both commands are declared volatile and observed."""
    from hst.collectors.base import obs_sha, raw_sha

    legacy = {nxos.CMD_BGP_SESSIONS_DEFAULT_VRF if k == CMD_BGP_SESSIONS else k: v for k, v in RAW.items()}
    assert nxos.bgp_sessions_command(legacy) == nxos.CMD_BGP_SESSIONS_DEFAULT_VRF
    assert nxos.parse(legacy)["bgp_observed"]["sessions"] == nxos.parse(RAW)["bgp_observed"]["sessions"]
    for keys in (NxosCollector.VOLATILE_RAW_KEYS, NxosCollector.OBSERVATION_RAW_KEYS):
        assert {CMD_BGP_SESSIONS, nxos.CMD_BGP_SESSIONS_DEFAULT_VRF} <= set(keys)
    collector = _bgp_collector()
    assert raw_sha(collector, legacy) == raw_sha(collector, RAW)
    moved = {**legacy, nxos.CMD_BGP_SESSIONS_DEFAULT_VRF: "{}"}
    assert raw_sha(collector, moved) == raw_sha(collector, legacy)
    assert obs_sha(collector, moved) != obs_sha(collector, legacy)


def test_parse_bgp_sessions_carries_the_device_word_for_each_state():
    sessions = nxos.parse(RAW)["bgp_observed"]["sessions"]
    assert [(s["vrf"], s["peer_ip"], s["state"]) for s in sessions] == [
        ("CUST-A", "10.1.1.2", "Established"),
        ("CUST-A", "192.0.2.2", "Established"),
        ("CUST-A", "192.0.2.9", "Idle"),
    ]
    # This command reports a relative last flap and no counters.
    assert all(
        s["established_since_ms"] is None
        and s["prefixes_received"] is None
        and s["prefixes_advertised"] is None
        and s["capabilities"] is None
        for s in sessions
    )


def test_parse_bgp_paths_carries_attributes_and_the_best_marking():
    routes = nxos.parse(RAW)["bgp_observed"]["routes"]
    accepted = [r for r in routes if r["peer_ip"] == "10.1.1.2" and r["direction"] == "accepted"]
    assert len(accepted) == 1
    row = accepted[0]
    assert row["prefix"] == "10.20.0.0/24"
    assert row["next_hop"] == "10.1.1.2"
    assert (row["local_pref"], row["med"], row["origin"]) == (150, 0, "i")
    assert row["communities"] == "65001:100"
    assert row["best"] is True
    assert row["path_id"] == "0"


def test_a_received_direction_is_pre_decision_and_carries_no_best_marking():
    routes = nxos.parse(RAW)["bgp_observed"]["routes"]
    received = [r for r in routes if r["peer_ip"] == "192.0.2.2" and r["direction"] == "received"]
    assert sorted(r["prefix"] for r in received) == ["10.20.0.0/24", "198.51.100.0/24"]
    assert all(r["best"] is None for r in received)


def test_two_peers_supplying_one_prefix_are_two_rows_and_best_marks_one():
    """The observation the `rib` table cannot make: which peer supplied which
    alternative, and which one the device chose."""
    routes = nxos.parse(RAW)["bgp_observed"]["routes"]
    accepted = [r for r in routes if r["direction"] == "accepted" and r["prefix"] == "10.20.0.0/24"]
    assert sorted(r["peer_ip"] for r in accepted) == ["10.1.1.2", "192.0.2.2"]
    assert [r["peer_ip"] for r in accepted if r["best"]] == ["10.1.1.2"]


def test_side_tables_join_observations_to_the_session_node_and_its_context():
    collector = _bgp_collector()
    tables = collector.side_tables(RAW)
    batch = collector.normalize(RAW)
    nodes = {n.uid for n in batch.nodes if n.label == "BgpSession"}
    for table in ("bgp_sessions", "bgp_session_routes"):
        assert tables[table]
        for row in tables[table]:
            assert row["device_uid"] == DEV
            assert row["context_uid"] == CUST_A_UID
    # every observed session that is also configured joins a node of this run
    assert {r["session_uid"] for r in tables["bgp_sessions"]} <= nodes
    assert _session_uid("10.1.1.2") in nodes


def test_observed_path_rows_carry_the_interval_columns_and_the_stage():
    rows = _bgp_collector().side_tables(RAW)["bgp_session_routes"]
    row = next(r for r in rows if r["direction"] == "advertised" and r["peer_ip"] == "10.1.1.2")
    assert (row["rib_type"], row["policy_stage"], row["safi"]) == ("adj-rib-out", "post-export", "unicast")
    assert (row["af"], row["prefixlen"]) == (4, 24)
    assert row["lo"] and row["hi"]
    assert row["next_hop_context_uid"] is None
    received = next(r for r in rows if r["direction"] == "received")
    assert (received["rib_type"], received["policy_stage"]) == ("adj-rib-in", "pre-import")
    accepted = next(r for r in rows if r["direction"] == "accepted")
    assert (accepted["rib_type"], accepted["policy_stage"]) == ("loc-rib", "post-import")


def test_a_received_direction_without_soft_reconfiguration_reports_not_captured(monkeypatch):
    """The box does not retain the pre-policy table and says so with a zero exit
    status. The direction is `not-captured`."""
    collector, raw, _fake = _fetch(monkeypatch)
    directions = _directions(collector, raw)
    outcome = directions[(_session_uid("10.1.1.2"), "received")]
    assert outcome.status == "not-captured"
    assert "soft-reconfiguration" in outcome.detail
    assert outcome.row_count is None
    # the same session's other two directions were captured
    assert directions[(_session_uid("10.1.1.2"), "accepted")].status == "complete"
    assert directions[(_session_uid("10.1.1.2"), "advertised")].status == "complete"


def test_a_direction_the_box_answered_with_nothing_is_empty_not_uncaptured(monkeypatch):
    collector, raw, _fake = _fetch(monkeypatch)
    down = _directions(collector, raw)[(_session_uid("192.0.2.9"), "accepted")]
    assert (down.status, down.row_count) == ("complete-empty", 0)


def test_a_box_without_feature_bgp_reads_unsupported_not_failed(monkeypatch):
    """`classify_command_failure` reads the device's own rejection banner: a
    box that lacks the feature is not a box someone has to fix."""
    command = nxos.bgp_route_command("CUST-A", "10.1.1.2", "accepted")
    collector, raw, _fake = _fetch(
        monkeypatch, failures={command: f"{command!r} rejected by device: % Invalid command"}
    )
    outcome = _directions(collector, raw)[(_session_uid("10.1.1.2"), "accepted")]
    assert outcome.status == "not-captured"
    assert "Invalid command" in outcome.detail


def test_a_box_without_feature_bgp_states_the_session_table_not_captured(monkeypatch):
    """A refused session command is stated for the table itself."""
    collector, raw, _fake = _fetch(
        monkeypatch,
        failures={
            command: f"{command!r} rejected by device: % Invalid command"
            for command in (CMD_BGP_SESSIONS, nxos.CMD_BGP_SESSIONS_DEFAULT_VRF)
        },
    )
    outcomes = collector.table_outcomes(raw)
    assert outcomes["bgp_sessions"].status == "not-captured"
    assert "Invalid command" in outcomes["bgp_sessions"].detail
    assert collector.side_tables(raw)["bgp_sessions"] == []


def test_a_session_table_the_box_answered_leaves_the_write_outcome_alone(monkeypatch):
    collector, raw, _fake = _fetch(monkeypatch)
    assert "bgp_sessions" not in collector.table_outcomes(raw)


def test_a_direction_refused_for_a_fixable_reason_reads_failed(monkeypatch):
    command = nxos.bgp_route_command("CUST-A", "10.1.1.2", "advertised")
    collector, raw, _fake = _fetch(
        monkeypatch, failures={command: f"{command!r} exited 1: Permission denied"}
    )
    assert _directions(collector, raw)[(_session_uid("10.1.1.2"), "advertised")].status == "failed"


def test_a_received_direction_refused_with_a_nonzero_exit_for_soft_reconfiguration_is_not_captured(
    monkeypatch,
):
    """The live NX-OS shape: `received-routes` for a neighbor without
    `soft-reconfiguration inbound` exits non-zero with the reason on stdout.
    That is the same permitted coverage gap as the zero-exit `%` answer, so
    the direction reads `not-captured` with the device's words, not `failed`."""
    command = nxos.bgp_route_command("CUST-A", "10.1.1.2", "advertised")
    words = "% Inbound soft reconfiguration not enabled on this neighbor"
    collector, raw, _fake = _fetch(monkeypatch, failures={command: f"{command!r} exited 244: {words}"})
    outcome = _directions(collector, raw)[(_session_uid("10.1.1.2"), "advertised")]
    assert outcome.status == "not-captured"
    assert "soft reconfiguration" in outcome.detail


def test_a_received_table_refused_with_only_cmd_exec_error_is_not_captured(monkeypatch):
    """The live NX-OS answer with `| json native` for a received table it does
    not keep: exit status 244 and only `Cmd exec error.`. A session that is
    shut down or not up gives it, and so does `soft-reconfiguration inbound`
    without `always` toward a peer that can refresh its routes."""
    command = nxos.bgp_route_command("CUST-A", "10.1.1.2", "received")
    collector, raw, _fake = _fetch(
        monkeypatch, failures={command: f"'{command} native' exited 244: Cmd exec error."}
    )
    outcome = _directions(collector, raw)[(_session_uid("10.1.1.2"), "received")]
    assert outcome.status == "not-captured"
    assert "Cmd exec error" in outcome.detail
    assert not [name for name, o in collector.table_outcomes(raw).items() if o.status == "failed"]


def test_cmd_exec_error_on_an_accepted_or_advertised_table_reads_failed(monkeypatch):
    """Only the received table has a known reason for the box not to hold it."""
    for direction in ("accepted", "advertised"):
        command = nxos.bgp_route_command("CUST-A", "10.1.1.2", direction)
        collector, raw, _fake = _fetch(
            monkeypatch, failures={command: f"'{command} native' exited 244: Cmd exec error."}
        )
        assert _directions(collector, raw)[(_session_uid("10.1.1.2"), direction)].status == "failed"


def test_a_feature_refusal_with_a_nonzero_exit_reads_unsupported_once_the_banner_is_carried():
    from hst.collectors import ssh

    failure = ssh.CommandFailed(f"{nxos.CMD_VPC!r} exited 16: % Invalid command at '^' marker.")
    assert classify_command_failure(failure)[0] == "unsupported"
    assert classify_command_failure(ssh.CommandFailed(f"{nxos.CMD_VPC!r} exited 16: "))[0] == "failed"


def test_the_exec_channel_answer_for_a_feature_the_box_does_not_run_reads_unsupported(monkeypatch):
    """The live NX-OS answer on an exec channel: exit status 16 and `Syntax
    error while parsing`, with no `%` banner. OSPF, vPC and LLDP off cost
    their sections, and no section degrades the device."""
    from hst.collectors import ssh

    refused = (*nxos.OSPF_COMMANDS, CMD_VPC, CMD_LLDP)

    def outputs(cmd):
        if cmd in refused:
            sent = f"{cmd} native" if cmd.endswith(" | json") else cmd
            raise ssh.CommandFailed(f"{sent!r} exited 16: Syntax error while parsing {sent!r}")
        return RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    sections = c.normalize(raw).sections
    for name in (*nxos.OSPF_SECTIONS, "vpc", "neighbors"):
        assert sections[name].status == "unsupported", name
    assert not [n for n, s in sections.items() if s.status in ("failed", "malformed", "unauthorized")]
    assert c.table_outcomes(raw)["ospf_lsdb"].status == "unsupported"


def test_the_session_table_is_volatile_so_its_timers_never_defeat_the_skip():
    assert CMD_BGP_SESSIONS in NxosCollector.VOLATILE_RAW_KEYS


def test_the_route_command_omits_the_vrf_clause_for_the_default_table():
    assert nxos.bgp_route_command("", "10.1.1.2", "received") == (
        "show bgp ipv4 unicast neighbors 10.1.1.2 received-routes | json"
    )
    assert nxos.bgp_route_command("default", "10.1.1.2", "accepted") == (
        "show bgp ipv4 unicast neighbors 10.1.1.2 routes | json"
    )
    assert nxos.bgp_route_command("CUST-A", "192.0.2.2", "advertised") == (
        "show bgp vrf CUST-A ipv4 unicast neighbors 192.0.2.2 advertised-routes | json"
    )


def test_a_listen_range_neighbor_is_not_a_capture_target():
    """A `neighbor <prefix>` range names no single address to query."""
    processes = [{"vrf": "CUST-A", "neighbors": [{"peer_ip": "10.1.0.0/16"}, {"peer_ip": "10.1.1.2"}]}]
    assert nxos.bgp_capture_targets(processes) == [("CUST-A", "10.1.1.2")]


def test_a_neighbor_with_no_remote_as_is_not_a_capture_target():
    """The box starts no session for a `neighbor <ip>` block with only `shutdown` under it."""
    processes = nxos.parse_bgp_config(
        "router bgp 65001\n"
        "  template peer PG\n"
        "    remote-as 65010\n"
        "  neighbor 10.0.0.1\n"
        "    shutdown\n"
        "  neighbor 10.0.0.2\n"
        "    inherit peer PG\n"
        "  neighbor 10.0.0.3\n"
        "    inherit peer PG_NOT_CAPTURED\n"
        "  neighbor 10.0.0.4\n"
        "    remote-as 65004\n"
    )
    assert nxos.bgp_capture_targets(processes) == [
        ("default", "10.0.0.2"),
        ("default", "10.0.0.3"),
        ("default", "10.0.0.4"),
    ]


def test_only_ipv4_unicast_neighbors_are_capture_targets():
    """Every path command asks for `ipv4 unicast`."""
    processes = nxos.parse_bgp_config(
        "router bgp 65001\n"
        "  neighbor 10.0.0.1\n"
        "    remote-as 65001\n"
        "    address-family l2vpn evpn\n"
        "      send-community extended\n"
        "  neighbor 2001:db8::2\n"
        "    remote-as 65002\n"
        "    address-family ipv6 unicast\n"
        "  neighbor 2001:db8::3\n"
        "    remote-as 65003\n"
        "  neighbor 2001:db8::4\n"
        "    remote-as 65004\n"
        "    address-family ipv4 unicast\n"
        "  neighbor 192.0.2.2\n"
        "    remote-as 65005\n"
        "  neighbor 192.0.2.3\n"
        "    remote-as 65006\n"
        "    address-family ipv6 unicast\n"
        "    address-family ipv4 unicast\n"
        "      route-map RM-IN in\n"
    )
    default = next(p for p in processes if p["vrf"] is None)
    by_ip = {n["peer_ip"]: n for n in default["neighbors"]}
    assert by_ip["10.0.0.1"]["address_families"] == ["l2vpn evpn"]
    assert by_ip["192.0.2.2"]["address_families"] == []
    assert by_ip["192.0.2.3"]["address_families"] == ["ipv6 unicast", "ipv4 unicast"]
    assert by_ip["192.0.2.3"]["route_map_in"] == "RM-IN"
    assert nxos.bgp_capture_targets(processes) == [
        ("default", "2001:db8::4"),
        ("default", "192.0.2.2"),
        ("default", "192.0.2.3"),
    ]


# --- `json_native`: the `| json native` pipe on NX-OS 9.3 and later ------------------------


def _native_collector():
    return NxosCollector(
        NxosConfig(
            host=HOST,
            auth=SshPassword(username=USER, password="pw"),
            site_code="hq",
            l3dom="corp",
            json_native=True,
        ),
        None,
    )


def test_json_native_rewrites_every_json_command_and_keys_the_payload_by_the_plain_one(monkeypatch):
    """With `json_native` set, every `| json` command goes out as `| json
    native`, including the per-neighbor BGP tables derived during the fetch;
    the plain-text running-config extracts are untouched. The payload stays
    keyed by the plain command, so parsers and sections read it unchanged."""
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd.endswith(" | json"):
            raise ssh.CommandFailed(f"{cmd!r} was sent without native")
        plain = cmd[: -len(" native")] if cmd.endswith(" | json native") else cmd
        return RAW[plain]

    fake = FakeSshSession(outputs).install(monkeypatch)
    collector = _native_collector()
    raw = collector.fetch()
    sent = fake.commands
    assert sent[0] == "show version | json native"
    assert nxos.CMD_BGP in sent and nxos.CMD_RPM in sent
    assert all(not c.endswith(" | json") for c in sent)
    assert any(c.startswith("show bgp ") and c.endswith("| json native") for c in sent)
    assert set(nxos.COMMANDS) <= set(raw)
    assert collector.normalize(raw).nodes


def test_json_native_is_off_by_default_and_the_plain_pipe_is_sent():
    assert NxosConfig(host=HOST, auth=SshPassword(username=USER, password="pw")).json_native is False
    assert nxos._NativeJsonSession.rewrite("show vrf | json") == "show vrf | json native"
    assert nxos._NativeJsonSession.rewrite("show running-config bgp") == "show running-config bgp"


def test_the_json_size_limit_line_is_a_refused_command_that_names_itself():
    """`JSONScripterror: xml output is large for processing` arrives with exit 0 and no `%`."""
    from hst.collectors import ssh

    line = "JSONScripterror: xml output is large for processing"
    assert ssh._cli_rejection(line + "\n") == line
    failure = ssh.CommandFailed(f"{nxos.CMD_ROUTE!r} rejected by device: {line}")
    assert classify_command_failure(failure)[0] == "failed"


def test_a_default_route_prefix_list_entry_passes_registry_validation():
    """`ip prefix-list X seq 5 permit 0.0.0.0/0` has `min_len` and `max_len` of 0."""
    raw = {
        **RAW,
        CMD_RPM: RPM_CONFIG_TEXT
        + "ip prefix-list PXL_DEFAULT_ROUTE seq 5 permit 0.0.0.0/0\n"
        + "ip prefix-list PXL_ANY seq 5 permit 0.0.0.0/0 le 32\n",
    }
    batch = _collector().normalize(raw)
    batch.validate_registry()
    entries = {n.uid: n.props for n in batch.nodes if n.label == "PrefixListEntry"}
    exact = entries[uid.prefix_list_entry(uid.route_policy(DEV, "prefix-list", "PXL_DEFAULT_ROUTE"), 5)]
    assert (exact["min_len"], exact["max_len"]) == (0, 0)
    ranged = entries[uid.prefix_list_entry(uid.route_policy(DEV, "prefix-list", "PXL_ANY"), 5)]
    assert (ranged["min_len"], ranged["max_len"]) == (0, 32)


def test_the_release_is_read_from_nxos_ver_str_when_sys_ver_str_is_absent():
    """Nexus 9000 states `nxos_ver_str`; `sys_ver_str` is the older key."""
    version = dict(json.loads(RAW[CMD_VERSION]))
    version.pop("sys_ver_str", None)
    version["nxos_ver_str"] = "10.5(4)"
    inter = nxos.parse({**RAW, CMD_VERSION: json.dumps(version)})
    assert inter["device"]["os_version"] == "10.5(4)"


# --- trunk membership: `show vlan` member lists and `show interface trunk` (schema v0.7.0) --


def test_expand_port_list_handles_a_range_and_single_ports():
    assert nxos.expand_port_list("Ethernet1/1,Ethernet1/3-4,port-channel10") == [
        "Ethernet1/1",
        "Ethernet1/3",
        "Ethernet1/4",
        "port-channel10",
    ]
    assert nxos.expand_port_list("Eth1/1/3-5") == ["Eth1/1/3", "Eth1/1/4", "Eth1/1/5"]
    assert nxos.expand_port_list("") == [] and nxos.expand_port_list(None) == []
    # a reversed range and a non-string entry are dropped, never raised
    assert nxos.expand_port_list("Ethernet1/5-3") == []


def test_expand_vlan_list_intersects_with_the_vlans_that_exist():
    existing = {10, 20, 25}
    assert nxos.expand_vlan_list("10,20-30", existing) == [10, 20, 25]
    assert nxos.expand_vlan_list("1-4094", existing) == [10, 20, 25]
    assert nxos.expand_vlan_list("all", existing) == [10, 20, 25]
    assert nxos.expand_vlan_list("none", existing) == []
    assert nxos.expand_vlan_list("30-40", existing) == []


VLAN_PLIST_PAYLOAD = {
    "TABLE_vlanbrief": {
        "ROW_vlanbrief": [
            # a single port and a range on one VLAN
            {
                "vlanshowbr-vlanid": "10",
                "vlanshowbr-vlanname": "DATA",
                "vlanshowplist-ifidx": "Ethernet1/1,Ethernet1/2-3",
            },
            # an SVI-only VLAN: no member port
            {"vlanshowbr-vlanid": "20", "vlanshowbr-vlanname": "SVI-ONLY"},
            # a member port the interface table does not list
            {
                "vlanshowbr-vlanid": "30",
                "vlanshowbr-vlanname": "GHOST",
                "vlanshowplist-ifidx": "Ethernet1/48",
            },
        ],
    },
}


def test_parse_vlan_ports_reads_the_member_list_and_the_trunk_table():
    """The two sources merge: the trunk allows 10 and 20-30 on Ethernet1/3, so
    VLANs 20 and 30 gain that port beside what the member lists state."""
    ports = nxos.parse_vlan_ports(VLAN_PLIST_PAYLOAD, TRUNK_PAYLOAD)
    assert ports == {
        10: ["Ethernet1/1", "Ethernet1/2", "Ethernet1/3"],
        20: ["Ethernet1/3"],
        30: ["Ethernet1/3", "Ethernet1/48"],
    }
    assert nxos.parse_vlan_ports(VLAN_PLIST_PAYLOAD, {}) == {
        10: ["Ethernet1/1", "Ethernet1/2", "Ethernet1/3"],
        30: ["Ethernet1/48"],
    }


def test_parse_vlan_ports_falls_back_to_the_bare_plist_spelling():
    payload = {
        "TABLE_vlanbrief": {"ROW_vlanbrief": {"vlanshowbr-vlanid": "10", "vlanshowplist": "Ethernet1/9"}}
    }
    assert nxos.parse_vlan_ports(payload, {}) == {10: ["Ethernet1/9"]}


def test_parse_vlan_ports_takes_the_allowed_list_only_for_vlans_the_box_has():
    trunk = {
        "TABLE_allowed_vlans": {"ROW_allowed_vlans": {"interface": "Ethernet1/2", "allowedvlans": "1-4094"}}
    }
    assert nxos.parse_vlan_ports(VLAN_PLIST_PAYLOAD, trunk) == {
        10: ["Ethernet1/1", "Ethernet1/2", "Ethernet1/3"],
        20: ["Ethernet1/2"],
        30: ["Ethernet1/2", "Ethernet1/48"],
    }


def test_parse_puts_the_membership_map_beside_the_vlan_list():
    inter = nxos.parse({**RAW, CMD_VLAN: json.dumps(VLAN_PLIST_PAYLOAD), CMD_TRUNK: "{}"})
    assert inter["vlans"] == [
        {"vid": 10, "name": "DATA"},
        {"vid": 20, "name": "SVI-ONLY"},
        {"vid": 30, "name": "GHOST"},
    ]
    assert inter["vlan_ports"] == {10: ["Ethernet1/1", "Ethernet1/2", "Ethernet1/3"], 30: ["Ethernet1/48"]}


def test_parse_without_the_trunk_command_reads_the_member_lists():
    raw = {k: v for k, v in RAW.items() if k != CMD_TRUNK}
    raw[CMD_VLAN] = json.dumps(VLAN_PLIST_PAYLOAD)
    assert nxos.parse(raw)["vlan_ports"][10] == ["Ethernet1/1", "Ethernet1/2", "Ethernet1/3"]


def _carries(batch) -> set[tuple[str, str]]:
    return {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "CARRIES"}


def test_normalize_emits_carries_for_a_range_and_a_single_port_and_none_for_an_svi_only_vlan():
    batch = _collector().normalize({**RAW, CMD_VLAN: json.dumps(VLAN_PLIST_PAYLOAD), CMD_TRUNK: "{}"})
    vlan10 = uid.vlan("nxos:n9k1", 10)
    assert _carries(batch) == {
        (uid.port(DEV, "Ethernet1/1"), vlan10),
        (uid.port(DEV, "Ethernet1/2"), vlan10),
        (uid.port(DEV, "Ethernet1/3"), vlan10),
    }
    # the SVI-only VLAN has its node (the name database) and no carriage
    assert any(n.uid == uid.vlan("nxos:n9k1", 20) and n.label == "VlanInstance" for n in batch.nodes)
    # a member port the interface table never listed is dropped, not dangled
    assert not [n for n in batch.nodes if n.uid == uid.port(DEV, "Ethernet1/48")]
    assert not [r for r in batch.rels if r.end_uid == uid.vlan("nxos:n9k1", 30)]


def test_normalize_emits_carries_from_the_trunk_table_alone():
    batch = _collector().normalize(RAW)
    assert _carries(batch) == {(uid.port(DEV, "Ethernet1/3"), uid.vlan("nxos:n9k1", 10))}


def test_the_trunk_command_is_optional_and_its_section_reads_unsupported_when_refused(monkeypatch):
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd == CMD_TRUNK:
            raise ssh.CommandFailed("'show interface trunk | json' exited 1: % Invalid command")
        return RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    assert raw[CMD_TRUNK] == "{}"
    assert c.sections(raw)["trunks"].status == "unsupported"
    assert _carries(c.normalize(raw)) == set()


# --- first-hop redundancy (HSRP/VRRP) and vPC ------------------------------------------
# Every field name in the payloads below is a first-contact guess (see nxos.py).

HSRP_PAYLOAD = {
    "TABLE_grp_detail": {
        "ROW_grp_detail": [
            {
                "sh_if_index": "Vlan10",
                "sh_group_num": 10,
                "sh_group_type": "v4",
                "sh_group_version": "v2",
                "sh_group_state": "Active",
                "sh_prio": 110,
                "sh_cfg_prio": 110,
                "sh_preempt": "enabled",
                "sh_vip": "10.10.10.254",
                "sh_active_router_addr": "local",
                "sh_standby_router_addr": "10.10.10.2",
                "sh_vmac": "0000.0c9f.f00a",
            },
            {
                "sh_if_index": "loopback0",
                "sh_group_num": 99,
                "sh_group_type": "v4",
                "sh_group_state": "Active",
                "sh_prio": 100,
                "sh_vip": "10.99.99.1",
            },
        ]
    }
}

# one group: ROW_vrrp_group collapses to a bare dict
VRRP_PAYLOAD = {
    "TABLE_vrrp_group": {
        "ROW_vrrp_group": {
            "sh_if_name": "Ethernet1/1",
            "sh_group_id": "1",
            "sh_group_type": "ipv4",
            "sh_group_state": "Master",
            "sh_prio": "100",
            "sh_vip_addr": "10.0.0.254",
            "sh_preempt": "enabled",
        }
    }
}

VPC_PAYLOAD = {
    "vpc-domain-id": "10",
    "vpc-peer-status": "peer-ok",
    "vpc-peer-status-reason": "SUCCESS",
    "vpc-peer-keepalive-status": "peer-alive",
    "vpc-role": "primary",
    "num-of-vpcs": "1",
    "TABLE_peerlink": {
        "ROW_peerlink": {
            "peer-link-id": "1",
            "peerlink-ifindex": "Po1",
            "peer-link-port-state": "1",
            "peer-up-vlan-bitset": "1,10",
        }
    },
    "TABLE_vpc": {"ROW_vpc": [{"vpc-id": "11", "vpc-ifindex": "Po11", "vpc-port-state": "1"}]},
}

FHRP_RAW = {
    **RAW,
    CMD_HSRP: json.dumps(HSRP_PAYLOAD),
    CMD_VRRP: json.dumps(VRRP_PAYLOAD),
    CMD_VPC: json.dumps(VPC_PAYLOAD),
}

# the other member of the pair: another chassis, the standby of group 10 and the
# secondary of vPC domain 10
PEER_SERIAL = "FDO5678EFGH"
# minted by the in-memory registry from the peer's host_name
PEER_DEV = "dev:sw2"
PEER_HSRP_PAYLOAD = {
    "TABLE_grp_detail": {
        "ROW_grp_detail": {
            **HSRP_PAYLOAD["TABLE_grp_detail"]["ROW_grp_detail"][0],
            "sh_group_state": "Standby",
            "sh_prio": 90,
            "sh_cfg_prio": 90,
            "sh_active_router_addr": "10.10.10.1",
            "sh_standby_router_addr": "local",
        }
    }
}
FHRP_PEER_RAW = {
    **FHRP_RAW,
    CMD_VERSION: json.dumps({**VERSION_PAYLOAD, "proc_board_id": PEER_SERIAL, "host_name": "sw2"}),
    CMD_HSRP: json.dumps(PEER_HSRP_PAYLOAD),
    CMD_VPC: json.dumps({**VPC_PAYLOAD, "vpc-role": "secondary"}),
}


def _member_collector(host, source_name="nxos-hq"):
    return NxosCollector(
        NxosConfig(
            host=host,
            auth=SshPassword(username=USER, password="pw"),
            site_code="hq",
            l3dom="corp",
            source_name=source_name,
        ),
        None,
    )


def _rels(batch, rel_type, start=None, end=None):
    return [
        r
        for r in batch.rels
        if r.rel_type == rel_type
        and (start is None or r.start_uid == start)
        and (end is None or r.end_uid == end)
    ]


def _domain_of_ip(batch, ip_uid):
    """The routing domain name the stage resolved for an address: the `l3dom`
    `connected_address` stamps, which is also what `uid.fhrp` embeds."""
    (node,) = [n for n in batch.nodes if n.label == "IpAddress" and n.uid == ip_uid]
    return node.props["l3dom"]


def test_fhrp_commands_are_optional_and_join_the_command_set():
    for cmd in (CMD_HSRP, CMD_VRRP, CMD_VPC):
        assert cmd in nxos.COMMANDS
        assert NxosCollector.OPTIONAL_COMMANDS[cmd] == "{}"
    assert nxos.SECTIONS["hsrp"].command == CMD_HSRP
    assert nxos.SECTIONS["vrrp"].command == CMD_VRRP
    assert nxos.SECTIONS["vpc"].command == CMD_VPC


def test_fhrp_sections_join_the_read_recipes():
    from hst.collectors.recipes import section_recipe

    for section, cmd in (("hsrp", CMD_HSRP), ("vrrp", CMD_VRRP), ("vpc", CMD_VPC)):
        recipe = section_recipe("nxos", section)
        assert recipe is not None and recipe.commands == (cmd,)


def test_parse_hsrp_and_vrrp_rows_land_in_one_fhrp_list():
    inter = nxos.parse(FHRP_RAW)
    assert inter["fhrp"] == [
        {
            "interface": "Vlan10",
            "kind": "hsrp",
            "group": 10,
            "vip": "10.10.10.254",
            "priority": 110,
            "state": "Active",
            "virtual_mac": "0000.0c9f.f00a",
        },
        {
            "interface": "loopback0",
            "kind": "hsrp",
            "group": 99,
            "vip": "10.99.99.1",
            "priority": 100,
            "state": "Active",
            "virtual_mac": None,
        },
        {
            "interface": "Ethernet1/1",
            "kind": "vrrp",
            "group": 1,
            "vip": "10.0.0.254",
            "priority": 100,
            "state": "Master",
            "virtual_mac": None,
        },
    ]
    assert inter["vpc"] == {"domain": 10, "role": "primary", "peer_link": "Po1", "peer_status": "peer-ok"}


def test_parse_without_the_feature_or_without_the_commands_yields_no_groups():
    """The base fixture's `{}` stand-ins and a payload without the
    commands read the same way: no groups, no domain."""
    assert nxos.parse(RAW)["fhrp"] == []
    assert "vpc" not in nxos.parse(RAW)
    old = {k: v for k, v in RAW.items() if k not in (CMD_HSRP, CMD_VRRP, CMD_VPC)}
    assert nxos.parse(old)["fhrp"] == []
    assert "vpc" not in nxos.parse(old)


def test_normalize_hsrp_virtual_address_joins_the_member_svi_prefix():
    """The virtual address is a HAS_IP on the member SVI, marked with the
    protocol, the group and the member's state, and it sits in the SVI's own
    connected Prefix: the prefix length is copied from the SVI's address."""
    batch = _collector().normalize(FHRP_RAW)
    iu = uid.interface(DEV, "Vlan10")
    vru = uid.vrf(DEV, "prod")
    vip = uid.ip(vru, "10.10.10.254")
    (edge,) = _rels(batch, "HAS_IP", start=iu, end=vip)
    assert edge.props == {"fhrp": "hsrp", "group": 10, "state": "active"}
    # the SVI's own address keeps a bare edge
    (own,) = _rels(batch, "HAS_IP", start=iu, end=uid.ip(vru, "10.10.10.1"))
    assert own.props == {}
    # one Prefix in the SVI's context serves both addresses: no second one was minted
    prefixes = [
        n
        for n in batch.nodes
        if n.label == "Prefix" and n.props.get("cidr") == "10.10.10.0/24" and n.props.get("anchor") == vru
    ]
    assert [n.uid for n in prefixes] == [uid.prefix(vru, "10.10.10.0/24")]
    assert _rels(batch, "IN", start=vip, end=prefixes[0].uid)
    assert _rels(batch, "IN", start=uid.ip(vru, "10.10.10.1"), end=prefixes[0].uid)


def test_normalize_emits_one_fhrp_group_with_member_priority_and_state():
    batch = _collector().normalize(FHRP_RAW)
    vru = uid.vrf(DEV, "prod")
    dom = _domain_of_ip(batch, uid.ip(vru, "10.10.10.254"))
    gu = uid.fhrp("hsrp", dom, "10.10.10.254")
    (group,) = [n for n in batch.nodes if n.label == "FhrpGroup" and n.props["kind"] == "hsrp"]
    assert group.uid == gu
    assert group.props == {
        "kind": "hsrp",
        "group_id": 10,
        "vip": "10.10.10.254",
        "af": 4,
        "virtual_mac": "00000c9ff00a",
    }
    (member,) = _rels(batch, "MEMBER_OF", start=uid.interface(DEV, "Vlan10"), end=gu)
    assert member.props == {"priority": 110, "state": "active"}
    assert _rels(batch, "HAS_IP", start=gu, end=uid.ip(vru, "10.10.10.254"))


def test_normalize_vrrp_group_is_marked_vrrp_with_the_master_state():
    batch = _collector().normalize(FHRP_RAW)
    iu = uid.interface(DEV, "Ethernet1/1")
    vru = uid.vrf(DEV, "default")
    (edge,) = _rels(batch, "HAS_IP", start=iu, end=uid.ip(vru, "10.0.0.254"))
    assert edge.props == {"fhrp": "vrrp", "group": 1, "state": "master"}
    (group,) = [n for n in batch.nodes if n.label == "FhrpGroup" and n.props["kind"] == "vrrp"]
    assert group.uid == uid.fhrp("vrrp", _domain_of_ip(batch, uid.ip(vru, "10.0.0.254")), "10.0.0.254")
    (member,) = _rels(batch, "MEMBER_OF", start=iu, end=group.uid)
    assert member.props == {"priority": 100, "state": "master"}


def test_both_members_of_a_pair_merge_on_one_fhrp_group_node():
    """Two chassis, two batches, one group: the uid is derived from the routing
    domain and the virtual address, which both members share."""
    first = _member_collector("n9k1").normalize(FHRP_RAW)
    second = _member_collector("n9k2").normalize(FHRP_PEER_RAW)
    (g1,) = [n for n in first.nodes if n.label == "FhrpGroup" and n.props["kind"] == "hsrp"]
    (g2,) = [n for n in second.nodes if n.label == "FhrpGroup" and n.props["kind"] == "hsrp"]
    assert g1.uid == g2.uid
    (m1,) = _rels(first, "MEMBER_OF", start=uid.interface(DEV, "Vlan10"), end=g1.uid)
    (m2,) = _rels(second, "MEMBER_OF", start=uid.interface(PEER_DEV, "Vlan10"), end=g2.uid)
    assert (m1.props["priority"], m1.props["state"]) == (110, "active")
    assert (m2.props["priority"], m2.props["state"]) == (90, "standby")
    # each member holds the address in its own context, marked with its own state
    peer_vip = uid.ip(uid.vrf(PEER_DEV, "prod"), "10.10.10.254")
    (h2,) = _rels(second, "HAS_IP", start=uid.interface(PEER_DEV, "Vlan10"), end=peer_vip)
    assert h2.props == {"fhrp": "hsrp", "group": 10, "state": "standby"}


def test_a_group_on_an_interface_with_no_own_address_is_skipped_and_named(monkeypatch):
    """loopback0 carries no IPv4 address."""
    batch = _collector().normalize(FHRP_RAW)
    assert not [n for n in batch.nodes if n.label == "IpAddress" and n.props["ip"] == "10.99.99.1"]
    assert not [n for n in batch.nodes if n.label == "FhrpGroup" and n.props["group_id"] == 99]
    sections = _sections(monkeypatch, FHRP_RAW)
    assert sections["hsrp"].status == "ok" and sections["hsrp"].row_count == 2
    assert "hsrp group 99 on loopback0" in sections["hsrp"].detail
    assert "no IPv4 address of its own" in sections["hsrp"].detail
    assert sections["vrrp"].status == "ok" and sections["vrrp"].detail == ""


def test_normalize_vpc_domain_is_a_redundancy_group_both_peers_share():
    first = _member_collector("n9k1").normalize(FHRP_RAW)
    second = _member_collector("n9k2").normalize(FHRP_PEER_RAW)
    gu = uid.rgrp("vpc", "nxos-hq", "10")
    for batch in (first, second):
        (group,) = [n for n in batch.nodes if n.label == "RedundancyGroup"]
        assert group.uid == gu
        assert group.props == {"kind": "vpc", "name": "vpc-domain-10", "domain_id": "10"}
    (m1,) = _rels(first, "MEMBER_OF", start=DEV, end=gu)
    (m2,) = _rels(second, "MEMBER_OF", start=PEER_DEV, end=gu)
    assert m1.props == {"role": "primary", "peer_link": "Po1", "peer_status": "peer-ok"}
    assert m2.props == {"role": "secondary", "peer_link": "Po1", "peer_status": "peer-ok"}


def test_a_collector_without_a_source_row_scopes_the_vpc_group_by_its_own_scope():
    batch = _collector().normalize(FHRP_RAW)
    (group,) = [n for n in batch.nodes if n.label == "RedundancyGroup"]
    assert group.uid == uid.rgrp("vpc", "nxos:n9k1", "10")


def test_the_base_fixture_emits_no_fhrp_group_and_no_vpc_group():
    batch = _collector().normalize(RAW)
    assert not [n for n in batch.nodes if n.label in ("FhrpGroup", "RedundancyGroup")]
    assert not [r for r in batch.rels if r.rel_type == "HAS_IP" and r.props.get("fhrp")]


def test_a_box_without_the_feature_records_the_sections_unsupported_and_emits_nothing(monkeypatch):
    """`feature hsrp`/`feature vrrp`/`feature vpc` absent: the box rejects the
    command line. The fetch survives, the sections read unsupported, and the
    twin carries no group."""
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd in (CMD_HSRP, CMD_VRRP, CMD_VPC):
            raise ssh.CommandFailed(f"{cmd!r} exited 1: % Invalid command at '^' marker.")
        return FHRP_RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    batch = c.normalize(raw)
    for name in ("hsrp", "vrrp", "vpc"):
        assert batch.sections[name].status == "unsupported", name
    assert not [n for n in batch.nodes if n.label in ("FhrpGroup", "RedundancyGroup")]
    assert batch.sections["interfaces"].status == "ok"


def test_the_trunk_section_reads_ok_with_the_interface_wrapper(monkeypatch):
    FakeSshSession(RAW).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    assert c.sections(raw)["trunks"].status == "ok"


def test_fhrp_and_vpc_sections_read_empty_on_the_base_fixture_and_ok_with_groups(monkeypatch):
    base = _sections(monkeypatch, RAW)
    assert {base[n].status for n in ("hsrp", "vrrp", "vpc")} == {"empty"}
    full = _sections(monkeypatch, FHRP_RAW)
    assert (full["hsrp"].status, full["hsrp"].row_count) == ("ok", 2)
    assert (full["vrrp"].status, full["vrrp"].row_count) == ("ok", 1)
    assert (full["vpc"].status, full["vpc"].row_count) == ("ok", 1)


# --- CDP: the brief table beside the LLDP detail table ------------------------------------
#
# Structure from a first-contact capture: `TABLE_cdp_neighbor_brief_info`/
# `ROW_cdp_neighbor_brief_info` with `device_id`, `intf_id`, `port_id`,
# `platform_id` and a `capability` list. A Nexus far end spells `device_id`
# as `<host>.<domain>(<serial>)`; a Catalyst far end sends the bare name.

CDP_PAYLOAD = {
    "TABLE_cdp_neighbor_brief_info": {
        "ROW_cdp_neighbor_brief_info": [
            {
                "ifindex": 436222976,
                "device_id": "core2.example.com(ABC1234XYZ)",
                "intf_id": "Ethernet1/2",
                "ttl": "158",
                "capability": ["router", "switch", "IGMP_cnd_filtering", "Supports-STP-Dispute"],
                "platform_id": "N9K-C93180YC-FX3",
                "port_id": "Ethernet1/30",
            },
            {
                "ifindex": 436234240,
                "device_id": "access1.mgmt.example.com",
                "intf_id": "Ethernet1/3",
                "ttl": "162",
                "capability": ["router", "switch", "IGMP_cnd_filtering"],
                "platform_id": "cisco C9407R",
                "port_id": "TenGigabitEthernet3/0/6",
            },
        ]
    },
    "neigh_count": 2,
}

CDP_RAW = {**RAW, nxos.CMD_CDP: json.dumps(CDP_PAYLOAD)}


def test_cdp_is_an_optional_command_with_its_own_section():
    assert nxos.CMD_CDP in nxos.COMMANDS
    assert NxosCollector.OPTIONAL_COMMANDS[nxos.CMD_CDP] == "{}"
    assert nxos.SECTIONS["cdp"].command == nxos.CMD_CDP
    assert nxos.SECTIONS["cdp"].table == "cdp_neighbor_brief_info"
    # the two tables share one `neighbors` list, so neither counts it as its own
    assert nxos.SECTIONS["neighbors"].rows_key is None
    assert nxos.SECTIONS["cdp"].rows_key is None


def test_parse_cdp_neighbors_join_the_lldp_rows():
    inter = nxos.parse(CDP_RAW)
    cdp = [n for n in inter["neighbors"] if n["proto"] == "cdp"]
    assert [n["proto"] for n in inter["neighbors"]] == ["lldp", "cdp", "cdp"]
    assert cdp[0] == {
        "local_port": "Ethernet1/2",
        "name": "core2.example.com",
        "serial": "ABC1234XYZ",
        "mac": None,
        "port": "Ethernet1/30",
        "proto": "cdp",
    }
    # a far end that sends no serial keeps its name and states no serial
    assert cdp[1]["name"] == "access1.mgmt.example.com"
    assert cdp[1]["serial"] is None
    assert cdp[1]["local_port"] == "Ethernet1/3"
    assert cdp[1]["port"] == "TenGigabitEthernet3/0/6"


@pytest.mark.parametrize(
    "value, expected",
    [
        ("core2.example.com(ABC1234XYZ)", ("core2.example.com", "ABC1234XYZ")),
        ("core2(ABC1234XYZ)", ("core2", "ABC1234XYZ")),
        ("access1.mgmt.example.com", ("access1.mgmt.example.com", None)),
        ("  edge1  ", ("edge1", None)),
        ("", (None, None)),
        (None, (None, None)),
    ],
)
def test_cdp_device_id_splits_name_and_serial(value, expected):
    assert nxos._cdp_device_id(value) == expected


def test_lldp_null_text_is_absent_not_a_name():
    """NX-OS prints the string `null` for a TLV the neighbor did not send: a
    host that advertises only a chassis MAC reads `sys_name: "null"`. That
    string must not become the neighbor's name."""
    raw = dict(RAW)
    raw[CMD_LLDP] = json.dumps(
        {
            "TABLE_nbor_detail": {
                "ROW_nbor_detail": {
                    "chassis_type": "Mac Address",
                    "chassis_id": "6805.ca9f.512c",
                    "port_type": "Mac Address",
                    "port_id": "6805.ca9f.512c",
                    "l_port_id": "Eth1/11",
                    "port_desc": "null",
                    "sys_name": "null",
                    "sys_desc": "null",
                },
            },
        }
    )
    inter = nxos.parse(raw)
    assert inter["neighbors"] == [
        {
            "local_port": "Eth1/11",
            "name": None,
            "mac": "6805ca9f512c",
            "port": "6805.ca9f.512c",
            "proto": "lldp",
        }
    ]


def test_normalize_cdp_hint_lands_on_the_port_with_its_serial():
    batch = _collector().normalize(CDP_RAW)
    by_uid = {n.uid: n for n in batch.nodes}
    port = by_uid[uid.port(DEV, "Ethernet1/2")]
    assert port.props["cdp_neighbor_name"] == "core2.example.com"
    assert port.props["cdp_neighbor_port"] == "Ethernet1/30"
    assert port.props["cdp_neighbor_serial"] == "ABC1234XYZ"
    assert "cdp_neighbor_mac" not in port.props
    # the LLDP hint on Ethernet1/1 is untouched by the CDP rows
    assert by_uid[uid.port(DEV, "Ethernet1/1")].props["lldp_neighbor_name"] == "core1"


def test_cdp_failure_degrades_to_the_lldp_rows_alone(monkeypatch, caplog):
    from hst.collectors import ssh

    def outputs(cmd):
        if cmd == nxos.CMD_CDP:
            raise ssh.CommandFailed("'show cdp neighbors | json' exited 1: CDP is not enabled")
        return RAW[cmd]

    FakeSshSession(outputs).install(monkeypatch)
    inter = nxos.parse(_collector().fetch())
    assert [n["proto"] for n in inter["neighbors"]] == ["lldp"]
    assert "show cdp neighbors" in caplog.text and "continuing without it" in caplog.text


def test_a_box_with_cdp_off_reads_unsupported_and_loads(monkeypatch):
    """The live answer of a box with CDP off: exit status 0 and one note in
    place of the table. The device loads, the CDP section reads unsupported
    with the box's words, and the LLDP rows stand."""
    FakeSshSession({**RAW, nxos.CMD_CDP: "Note: CDP not enabled\n"}).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    batch = c.normalize(raw)
    assert (batch.sections["cdp"].status, batch.sections["cdp"].detail) == (
        "unsupported",
        "Note: CDP not enabled",
    )
    assert batch.sections["interfaces"].status == "ok"
    assert [n["proto"] for n in nxos.parse(raw)["neighbors"]] == ["lldp"]


def test_an_optional_answer_that_is_not_json_costs_its_section_not_the_device(monkeypatch):
    """Text from a required command fails the device."""
    FakeSshSession({**RAW, CMD_VPC: "Note: an answer this parser does not know\n"}).install(monkeypatch)
    c = _collector()
    raw = c.fetch()
    batch = c.normalize(raw)
    assert batch.sections["vpc"].status == "malformed"
    assert "not JSON" in batch.sections["vpc"].detail
    assert batch.sections["interfaces"].status == "ok"
    with pytest.raises(ValueError, match="not JSON"):
        _collector().normalize({**raw, CMD_VLAN: "Note: an answer this parser does not know\n"})


# --- policy-based-routing matches, unread set lines, community and AS-path lists ----------


def test_parse_route_map_keeps_pbr_only_matches_apart_from_unread_ones():
    """`match ip address <acl>`, `match ipv6 address <acl>`, `match vlan` and
    `match as-number` are ignored by route filtering (`match_ignored`);
    `match route-type` is not read (`match_unsupported`); `match source-protocol`
    is read."""
    (clause,) = nxos.parse_route_map_config(
        "route-map RM permit 10\n"
        "  match ip address ACL-10\n"
        "  match ipv6 address ACL6\n"
        "  match vlan 10\n"
        "  match as-number 65000\n"
        "  match route-type external\n"
        "  match source-protocol ospf\n"
    )["RM"]
    assert clause["match_ignored"] == [
        "match ip address ACL-10",
        "match ipv6 address ACL6",
        "match vlan 10",
        "match as-number 65000",
    ]
    assert clause["match_unsupported"] == ["match route-type external"]
    assert clause["match_protocols"] == ["ospf"]


def test_parse_route_map_keeps_the_set_lines_it_cannot_read():
    (clause,) = nxos.parse_route_map_config(
        "route-map RM permit 10\n"
        "  set as-path prepend last-as 2\n"
        "  set ip next-hop unchanged\n"
        "  set community none\n"
        "  set metric-type type-1\n"
        "  set as-path prepend 65000 65000\n"
    )["RM"]
    assert clause["set_unsupported"] == [
        "set as-path prepend last-as 2",
        "set ip next-hop unchanged",
        "set community none",
        "set metric-type type-1",
    ]
    assert clause["set_as_path_prepend"] == ["65000", "65000"]
    assert clause["set_next_hop"] is None
    assert clause["set_communities"] == []


def test_parse_match_lists_from_the_rpm_extract():
    text = (
        "ip community-list standard CL1 seq 10 permit 65000:1 65000:2\n"
        "ip community-list standard CL1 seq 20 deny internet\n"
        'ip community-list expanded CL2 seq 5 permit "^65001:.*"\n'
        'ip as-path access-list AP1 seq 10 permit "_64512$"\n'
    )
    lists = {(ml["kind"], ml["name"]): ml["entries"] for ml in nxos.parse_match_lists(text)}
    assert lists[("community-list", "CL1")] == [
        {"seq": 10, "action": "permit", "match_type": "standard", "value": "65000:1 65000:2"},
        {"seq": 20, "action": "deny", "match_type": "standard", "value": "internet"},
    ]
    assert lists[("community-list", "CL2")] == [
        {"seq": 5, "action": "permit", "match_type": "expanded", "value": "^65001:.*"}
    ]
    assert lists[("as-path-list", "AP1")] == [
        {"seq": 10, "action": "permit", "match_type": "expanded", "value": "_64512$"}
    ]


def test_normalize_links_a_route_map_to_the_community_list_it_names():
    rpm = (
        RPM_CONFIG_TEXT
        + "ip community-list standard CL1 seq 10 permit 65000:1\n"
        + "route-map RM-CL permit 10\n  match community CL1\n  set comm-list CL1 delete\n"
    )
    batch = _collector().normalize({**RAW, CMD_RPM: rpm})
    cl = uid.route_policy(DEV, "community-list", "CL1")
    line = next(n for n in batch.nodes if n.uid == uid.match_list_entry(cl, 10))
    assert line.label == "MatchListEntry"
    entry = uid.route_policy_entry(uid.route_policy(DEV, "route-map", "RM-CL"), 10)
    refs = [r for r in batch.rels if r.rel_type == "REFERENCES" and r.start_uid == entry and r.end_uid == cl]
    assert len(refs) == 1


# --- a Null0 route is a discard route ----------------------------------------------------


def test_a_null0_route_reaches_the_side_rows_as_a_discard_route():
    """A static to Null0 and a BGP aggregate's `0.0.0.0` via Null0 drop what
    they match: discard, with no next hop to forward to."""
    paths = [
        ("10.128.0.0/9", {"ifname": "Null0", "clientname": "static", "pref": 1, "metric": 0}),
        ("10.64.0.0/10", {"ipnexthop": "0.0.0.0", "ifname": "Null0", "clientname": "bgp-65001", "metric": 0}),  # noqa: S104 - a next hop
        ("10.30.0.0/24", {"ipnexthop": "10.0.0.2", "ifname": "Eth1/1", "clientname": "static", "metric": 0}),
    ]
    payload = {
        "TABLE_vrf": {
            "ROW_vrf": [
                {
                    "vrf-name-out": "default",
                    "TABLE_addrf": {
                        "ROW_addrf": {
                            "addrf": "ipv4",
                            "TABLE_prefix": {
                                "ROW_prefix": [
                                    {"ipprefix": prefix, "TABLE_path": {"ROW_path": path}}
                                    for prefix, path in paths
                                ]
                            },
                        }
                    },
                }
            ]
        }
    }
    rows = {r["prefix"]: r for r in _collector().side_tables({**RAW, CMD_ROUTE: json.dumps(payload)})["rib"]}
    for prefix in ("10.128.0.0/9", "10.64.0.0/10"):
        assert (rows[prefix]["discard"], rows[prefix]["next_hop"]) == ("blackhole", None), prefix
    assert (rows["10.30.0.0/24"]["discard"], rows["10.30.0.0/24"]["next_hop"]) == (None, "10.0.0.2")


# --- a leaked route's next hop resolves in the VRF NX-OS names ---------------------------


def test_a_leaked_next_hop_resolves_in_the_vrf_after_the_percent_sign():
    """`*via 10.0.0.1%default` in VRF CUST: the next hop is the address, and the
    row resolves it in the default table, not in CUST."""
    paths = [
        ("0.0.0.0/0", {"ipnexthop": "10.0.0.1%default", "clientname": "bgp-65001", "metric": 0}),
        ("10.20.0.0/24", {"ipnexthop": "192.0.2.1%SHARED", "clientname": "bgp-65001", "metric": 0}),
        ("10.30.0.0/24", {"ipnexthop": "10.0.0.2", "ifname": "Eth1/1", "clientname": "static", "metric": 0}),
    ]
    payload = {
        "TABLE_vrf": {
            "ROW_vrf": [
                {
                    "vrf-name-out": "CUST",
                    "TABLE_addrf": {
                        "ROW_addrf": {
                            "addrf": "ipv4",
                            "TABLE_prefix": {
                                "ROW_prefix": [
                                    {"ipprefix": prefix, "TABLE_path": {"ROW_path": path}}
                                    for prefix, path in paths
                                ]
                            },
                        }
                    },
                }
            ]
        }
    }
    rows = {r["prefix"]: r for r in _collector().side_tables({**RAW, CMD_ROUTE: json.dumps(payload)})["rib"]}
    dev = rows["0.0.0.0/0"]["device_uid"]
    assert (rows["0.0.0.0/0"]["next_hop"], rows["0.0.0.0/0"]["next_hop_context_uid"]) == (
        "10.0.0.1",
        uid.vrf(dev, "default"),
    )
    assert (rows["10.20.0.0/24"]["next_hop"], rows["10.20.0.0/24"]["next_hop_context_uid"]) == (
        "192.0.2.1",
        uid.vrf(dev, "SHARED"),
    )
    assert rows["10.30.0.0/24"]["next_hop_context_uid"] is None


# --- route-reflector-client, filter-list, prefix-list beside a route-map --------------------

_SESSION_BGP_TEXT = """\
router bgp 65001
  router-id 10.255.0.1
  template peer-policy RR-POLICY
    route-reflector-client
    filter-list AS-OUT out
  neighbor 10.1.1.2
    remote-as 65001
    address-family ipv4 unicast
      route-reflector-client
  neighbor 10.1.1.3
    remote-as 65001
    address-family ipv4 unicast
      inherit peer-policy RR-POLICY 10
  neighbor 10.1.1.4
    remote-as 65001
    address-family ipv4 unicast
  neighbor 192.0.2.2
    remote-as 65099
    address-family ipv4 unicast
      filter-list AS-IN in
      prefix-list PL-TEST in
      route-map RM-IN in
"""


def _session_batch():
    return _collector().normalize({**RAW, CMD_BGP: _SESSION_BGP_TEXT})


def test_route_reflector_client_is_stated_on_every_session():
    """True from the neighbor's address family or an inherited
    peer-policy template, false when neither states it."""
    sessions = {n.props["peer_ip"]: n.props for n in _session_batch().nodes if n.label == "BgpSession"}
    assert sessions["10.1.1.2"]["route_reflector_client"] is True
    assert sessions["10.1.1.3"]["route_reflector_client"] is True
    assert sessions["10.1.1.4"]["route_reflector_client"] is False
    assert sessions["192.0.2.2"]["route_reflector_client"] is False


def test_a_filter_list_and_a_prefix_list_beside_a_route_map_are_recorded():
    """A filter-list on the neighbor or from a peer-policy template is written."""
    batch = _session_batch()
    sessions = {n.props["peer_ip"]: n for n in batch.nodes if n.label == "BgpSession"}
    templated = sessions["10.1.1.3"].props
    assert templated["export_filter_list_name"] == "AS-OUT"
    assert "export_policy_name" not in templated
    edge = sessions["192.0.2.2"]
    assert edge.props["import_filter_list_name"] == "AS-IN"
    assert (edge.props["import_policy_name"], edge.props["import_policy_kind"]) == ("RM-IN", "route-map")
    assert edge.props["import_prefix_list_name"] == "PL-TEST"
    filters = {
        (r.key.get("direction"), r.end_uid)
        for r in batch.rels
        if r.rel_type == "FILTERED_BY" and r.start_uid == edge.uid
    }
    assert filters == {
        ("in", uid.route_policy(DEV, "route-map", "RM-IN")),
        ("in-prefix-list", uid.route_policy(DEV, "prefix-list", "PL-TEST")),
    }


# --- the cluster id; a neighbor written as no session ------------------------------------

_CLUSTER_BGP_TEXT = """\
router bgp 65001
  router-id 10.255.0.1
  cluster-id 10.255.255.255
  neighbor 10.1.1.2
    remote-as 65001
    address-family ipv4 unicast
      route-reflector-client
  neighbor 10.1.1.3
    inherit peer IBGP-MISSING
  neighbor 10.1.1.4
  vrf CUST
    cluster-id 4294967295
    neighbor 192.0.2.2
      remote-as 65099
"""


def test_every_session_carries_its_process_cluster_id():
    """`cluster-id` under `router bgp` and under a VRF, the 32-bit form read
    as the dotted quad."""
    batch = _collector().normalize({**RAW, CMD_BGP: _CLUSTER_BGP_TEXT})
    sessions = {n.props["peer_ip"]: n.props for n in batch.nodes if n.label == "BgpSession"}
    assert sessions["10.1.1.2"]["cluster_id"] == "10.255.255.255"
    assert sessions["192.0.2.2"]["cluster_id"] == "255.255.255.255"


def test_a_neighbor_written_as_no_session_is_recorded_on_its_process():
    """A neighbor whose template is not in the capture and one with no
    remote-as write no session; the process names both, so the simulation
    does not read them as absent."""
    batch = _collector().normalize({**RAW, CMD_BGP: _CLUSTER_BGP_TEXT})
    process = next(n for n in batch.nodes if n.uid == uid.routing_process(DEV, "default", "bgp"))
    assert process.props["session_gaps"] == [
        "neighbor 10.1.1.3 has unresolved template inheritance (unresolved template peer IBGP-MISSING)",
        "neighbor 10.1.1.4 has no remote-as",
    ]
    cust = next(n for n in batch.nodes if n.uid == uid.routing_process(DEV, "CUST", "bgp"))
    assert "session_gaps" not in cust.props
