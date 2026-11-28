"""IOS-XE collector. It sends the 28 show commands of `COMMANDS` and parses
them offline, through ntc-templates where a template exists and through text
parsers otherwise.

`show vrf` lists the member interfaces of each non-default VRF.
`cisco_common.if_vrf_map` maps each interface name to its VRF from it. An
interface in no VRF list is in the default VRF. Its interface addresses get
the VRF `""`, and its ARP rows get `"default"`.

`show vrf detail` gives the RD and the import and export route targets.
`cisco_common.vrf_rt_fields` merges them onto the `show vrf` rows by VRF name.

TextFSM output details:

  - `show lldp neighbors detail` reads interface names in short form from the
    `Local Intf: Gi1/0/1` line. The LLDP names are canonicalized through
    netutils, with the table that `core/normalize.py` uses, to the full names
    that the other commands print. CDP output prints full names.
  - `show ip route vrf *` records hold a one-letter protocol code (`C`, `S`,
    ...). `cisco_common.expand_protocol` expands the codes that the legend
    defines. The template captures the `Routing Table: <vrf>` header for each
    record. The repository's copy of the template (`templates/`) records each
    line that no rule reads and each further path line after it. The `rib`
    section then reads `partial` with the count (`RIB_UNREAD_KEY`). An answer
    of which no line could be read fails the device
    (`cli_parse.parse_with_unread`).
  - The interfaces template captures the primary `Internet address` only. A
    secondary address is dropped.

FIRST CONTACT, one capture per command:

    ssh <user>@<host> 'show version' \
      > data/raw/iosxe/first-contact/show-version.txt
    # one file per entry in COMMANDS:
    #   show-interfaces.txt, show-lldp-neighbors-detail.txt, show-vrf.txt,
    #   show-vrf-detail.txt, show-ip-route-vrf-star.txt, show-ip-arp.txt,
    #   show-cdp-neighbors-detail.txt, show-run-include-ip-nat.txt,
    #   show-ip-nat-statistics.txt, show-ip-access-lists.txt,
    #   show-run-section-router-bgp.txt, show-run-include-ip-prefix-list.txt,
    #   show-run-section-route-map.txt, show-run-section-interface.txt,
    #   show-run-include-vlan-filter.txt,
    #   show-ip-ospf.txt, show-ip-ospf-interface.txt, show-ip-ospf-neighbor.txt,
    #   show-ip-ospf-database-router-detail.txt, show-ip-ospf-database-network-detail.txt,
    #   show-ip-ospf-database-summary-detail.txt, show-ip-ospf-database-asbr-summary-detail.txt,
    #   show-ip-ospf-database-external-detail.txt, show-ip-ospf-database-nssa-external-detail.txt,
    #   show-run-section-router-ospf.txt, show-standby-brief.txt, show-vrrp-brief.txt
    #
    # The HSRP and VRRP summaries go through ntc-templates' own
    # `cisco_ios_show_standby_brief` and `cisco_ios_show_vrrp_brief` templates
    # (CMD_STANDBY/CMD_VRRP).
"""

from __future__ import annotations

import functools
import ipaddress
import logging
import re
from collections.abc import Iterator, Sequence
from typing import Any, ClassVar

from textfsm import TextFSMError

from hst.core import debug_capture, uid
from hst.core.identity import chassis_serial
from hst.core.l3domain import DEFAULT_VRF
from hst.core.manifest import BGP_ROUTES_TABLE, BGP_SESSIONS_TABLE, OSPF_LSDB_TABLE, bgp_direction_key
from hst.core.model import Batch, SectionOutcome, TableOutcome
from hst.core.mtu import MTU_NORMALIZATION_VERSION
from hst.core.normalize import IfNameResolver

from . import cisco_bgp_table, cli_parse, ssh, streams
from .base import RAW_OUTCOMES_KEY, register
from .cisco_bgp import (
    expand_dynamic_neighbors,
    inherit_peer_templates,
    nest_router_ids,
    parse_neighbor_router_ids,
    peer_network,
    stamp_dynamic_observations,
    stamp_peer_router_ids,
)
from .cisco_common import (
    MTU_ALWAYS_PRESENT,
    MTU_COMMANDS,
    RIB_EMPTY_ANSWER,
    ace_port_clause,
    ace_qualifiers,
    annotate_fhrp_sections,
    arp_row,
    capture_match_lists,
    capture_mtu,
    cdp_neighbor_rows,
    device_uid,
    fhrp_rows,
    if_vrf_map,
    interface_kind,
    lldp_neighbor_rows,
    mtu_interface_fields,
    mtu_sections,
    ospf_adjacency_rows_from_neighbor_records,
    ospf_area_id,
    ospf_lsa_detail_rows,
    ospf_text_link_type,
    parse_access_groups,
    parse_mtu,
    parse_nat_config,
    parse_ospf_interface_text,
    parse_ospf_process_text,
    parse_ospf_redistribute_config,
    parse_vlan_filters,
    rib_row,
    stamp_ospf_vrfs,
    unmodeled_ace_fields,
    vrf_of,
    vrf_rt_fields,
    wildcard_cidr,
)
from .cli_collector import (
    PATH_TIMEOUT_LIMIT,
    CiscoCliCollector,
    Section,
    SshSourceConfig,
    classify_command_failure,
    effective_outcomes,
    failed_feature_outcome,
    not_sent_after_timeouts,
)
from .util import (
    canonical_mac,
    lpm_columns,
    parse_aggregate_options,
    parse_asn,
    parse_cluster_id,
    parse_maximum_paths,
)

logger = logging.getLogger(__name__)

CMD_VERSION = "show version"
CMD_INTERFACES = "show interfaces"
CMD_LLDP = "show lldp neighbors detail"
CMD_VRF = "show vrf"
CMD_VRF_DETAIL = "show vrf detail"
CMD_ROUTE = "show ip route vrf *"
CMD_ARP = "show ip arp"
# `show ip arp` prints the global table only. The fetch derives one command
# per VRF from the `show vrf` answer (`arp_vrf_commands`). These commands are
# optional. A refusal loses the entries of that VRF, and the `arp` section
# reads partial.
CMD_ARP_VRF = "show ip arp vrf {vrf}"
ARP_VRF_KEY_RE = re.compile(r"show ip arp vrf (\S+)")
CMD_CDP = "show cdp neighbors detail"
CMD_NAT = "show running-config | include ^ip nat"
CMD_NAT_STATS = "show ip nat statistics"
CMD_ACL = "show ip access-lists"
# `| section` keeps the indented match, set and neighbor sub-lines that an
# anchored `^` include drops.
# `ip prefix-list` lines are never indented. `| include` reads them all.
CMD_BGP = "show running-config | section ^router bgp"
CMD_PREFIX_LIST = "show running-config | include ^ip prefix-list"
CMD_ROUTE_MAP = "show running-config | section ^route-map"
# The community lists and AS-path access lists that the `match community`,
# `match as-path` and `set comm-list delete` lines of a route-map name. Their
# lines are never indented. `| include` reads them all. The fetch sends both
# commands only when the route-map text names a list (`match_list_commands`).
# Both commands are optional, and a refusal loses the lists only.
CMD_COMMUNITY_LIST = "show running-config | include ^ip community-list"
CMD_AS_PATH_LIST = "show running-config | include ^ip as-path access-list"
# `ip access-group <acl> in|out` is an indented interface sub-line and needs a
# `| section` capture. `show interfaces` holds no access-group bindings.
CMD_INTERFACE_CONFIG = "show running-config | section ^interface"
# `vlan filter <map> vlan-list <ids>` is a global config line. The VLAN access
# map filters every packet of the listed VLANs.
CMD_VLAN_FILTER = "show running-config | include ^vlan filter"
# First-hop redundancy. Both commands are optional. A box with no group
# answers with an empty table. A refused command loses the groups only.
#
# FIRST CONTACT: no live IOS-XE capture has checked these commands. The
# ntc-templates index maps them to
# `cisco_ios_show_standby_brief` (INTERFACE, GROUP, PRIORITY, PREEMPT, STATE,
# ACTIVE, STANDBY, VIRTUAL_IP_ADDRESS) and `cisco_ios_show_vrrp_brief`
# (INTERFACE, GROUP, PRIORITY, STATE, MASTER_IP_ADDRESS, VIRTUAL_IP_ADDRESS).
CMD_STANDBY = "show standby brief"
CMD_VRRP = "show vrrp brief"
# OSPF. The 10 OSPF commands are optional.
CMD_OSPF = "show ip ospf"
CMD_OSPF_IF = "show ip ospf interface"
CMD_OSPF_NBR = "show ip ospf neighbor"
# Each type keyword alone prints the whole LSA with the bodies that SPF needs.
# IOS-XE has no `detail` keyword after it. IOS-XE 17.12 answers
# `show ip ospf database router detail` with `Line has invalid autocommand`.
# The ntc-templates `cisco_ios_show_ip_ospf_database_router` and `_network`
# templates parse the router and network commands. They are the only 2 OSPF
# database templates of the installed package for `cisco_ios`.
# `ospf_lsa_detail_rows` (`cisco_common.py`) parses the other 4 commands.
CMD_OSPF_DB_ROUTER = "show ip ospf database router"
CMD_OSPF_DB_NETWORK = "show ip ospf database network"
CMD_OSPF_DB_SUMMARY = "show ip ospf database summary"
CMD_OSPF_DB_ASBR_SUMMARY = "show ip ospf database asbr-summary"
CMD_OSPF_DB_EXTERNAL = "show ip ospf database external"
CMD_OSPF_DB_NSSA_EXTERNAL = "show ip ospf database nssa-external"
# The same `| section` capture as `CMD_BGP`. It holds `router-id` and
# `redistribute ... route-map <name>` (`cisco_common.parse_ospf_redistribute_config`).
# The operational commands print neither.
CMD_OSPF_CONFIG = "show running-config | section ^router ospf"

# The optional running-config extracts, which every IOS-XE release has. The
# device refuses them to a privilege-1 account with the words of a missing
# feature. Their refusal reads `unauthorized`
# (`cli_collector.classify_command_failure`).
ALWAYS_PRESENT_COMMANDS: frozenset[str] = frozenset(
    {
        CMD_NAT,
        CMD_BGP,
        CMD_PREFIX_LIST,
        CMD_ROUTE_MAP,
        CMD_INTERFACE_CONFIG,
        CMD_OSPF_CONFIG,
        *MTU_ALWAYS_PRESENT["iosxe"],
    }
)

OSPF_COMMANDS: tuple[str, ...] = (
    CMD_OSPF,
    CMD_OSPF_IF,
    CMD_OSPF_NBR,
    CMD_OSPF_DB_ROUTER,
    CMD_OSPF_DB_NETWORK,
    CMD_OSPF_DB_SUMMARY,
    CMD_OSPF_DB_ASBR_SUMMARY,
    CMD_OSPF_DB_EXTERNAL,
    CMD_OSPF_DB_NSSA_EXTERNAL,
    CMD_OSPF_CONFIG,
)
# The OSPF commands that must read `ok` before an empty parse reads as no OSPF process.
OSPF_FEATURE_COMMANDS: tuple[str, ...] = (
    CMD_OSPF,
    CMD_OSPF_DB_ROUTER,
    CMD_OSPF_DB_NETWORK,
    CMD_OSPF_DB_SUMMARY,
    CMD_OSPF_DB_ASBR_SUMMARY,
    CMD_OSPF_DB_EXTERNAL,
    CMD_OSPF_DB_NSSA_EXTERNAL,
)

COMMANDS: tuple[str, ...] = (
    CMD_VERSION,
    CMD_INTERFACES,
    CMD_LLDP,
    CMD_VRF,
    CMD_VRF_DETAIL,
    CMD_ROUTE,
    CMD_ARP,
    CMD_CDP,
    CMD_NAT,
    CMD_NAT_STATS,
    CMD_ACL,
    CMD_BGP,
    CMD_PREFIX_LIST,
    CMD_ROUTE_MAP,
    CMD_INTERFACE_CONFIG,
    CMD_VLAN_FILTER,
    *OSPF_COMMANDS,
    CMD_STANDBY,
    CMD_VRRP,
)

# The OSPF lists are nested under the `ospf` key. No OSPF section declares a `rows_key`.
OSPF_SECTIONS: dict[str, Section] = {
    "ospf": Section(CMD_OSPF),
    "ospf_interfaces": Section(CMD_OSPF_IF),
    "ospf_neighbors": Section(CMD_OSPF_NBR),
    "ospf_lsdb_router": Section(CMD_OSPF_DB_ROUTER),
    "ospf_lsdb_network": Section(CMD_OSPF_DB_NETWORK),
    "ospf_lsdb_summary": Section(CMD_OSPF_DB_SUMMARY),
    "ospf_lsdb_asbr_summary": Section(CMD_OSPF_DB_ASBR_SUMMARY),
    "ospf_lsdb_external": Section(CMD_OSPF_DB_EXTERNAL),
    "ospf_lsdb_nssa_external": Section(CMD_OSPF_DB_NSSA_EXTERNAL),
    "ospf_config": Section(CMD_OSPF_CONFIG),
}

# Maps each section name to its command and to the intermediate-shape list of
# its rows. A section with no rows is judged on whether its command returned
# any output. LLDP and CDP feed one merged `neighbors` list and declare no rows
# key. Each is judged on its own output.
SECTIONS: dict[str, Section] = {
    "device": Section(CMD_VERSION),
    # An answer with no interfaces is not an empty table.
    "interfaces": Section(CMD_INTERFACES, "interfaces", empty_answer=()),
    "vrfs": Section(CMD_VRF, "vrfs"),
    "vrf_detail": Section(CMD_VRF_DETAIL),
    "rib": Section(CMD_ROUTE, "rib", empty_answer=RIB_EMPTY_ANSWER),
    "arp": Section(CMD_ARP, "arp"),
    "lldp": Section(CMD_LLDP),
    "cdp": Section(CMD_CDP),
    "nat": Section(CMD_NAT),
    "nat_stats": Section(CMD_NAT_STATS),
    "acl": Section(CMD_ACL),
    "bgp": Section(CMD_BGP),
    "prefix_lists": Section(CMD_PREFIX_LIST),
    "route_maps": Section(CMD_ROUTE_MAP),
    "interface_config": Section(CMD_INTERFACE_CONFIG),
    "vlan_filter": Section(CMD_VLAN_FILTER),
    **OSPF_SECTIONS,
    # HSRP and VRRP rows share the one `fhrp` list of the intermediate shape
    # and declare no `rows_key`. Each is judged on its own output.
    "hsrp": Section(CMD_STANDBY),
    "vrrp": Section(CMD_VRRP),
}

_VLAN_RE = re.compile(r"\d+")
_NAT_IF_ROLE_RE = re.compile(r"^(Inside|Outside) interfaces:\s*(.*)$")


@debug_capture.traced
def _nat_if_roles(stats_text: str) -> dict[str, str]:
    """The NAT role of each interface from the `Inside interfaces:` and
    `Outside interfaces:` lines of `show ip nat statistics`. The names
    continue on indented lines, separated by commas."""
    roles: dict[str, str] = {}
    side: str | None = None
    for line in stats_text.splitlines():
        m = _NAT_IF_ROLE_RE.match(line.strip())
        if m:
            side = m.group(1).lower()
            names = m.group(2)
        elif side and line[:1].isspace():
            names = line.strip()
        else:
            side = None
            continue
        for name in re.split(r"[,\s]+", names):
            if name:
                roles[name] = side
    return roles


def _acl_side(row: dict[str, Any], p: str) -> str | None:
    if row.get(f"{p}_any"):
        return "any"
    if row.get(f"{p}_host"):
        return row[f"{p}_host"]
    if row.get(f"{p}_network"):
        return wildcard_cidr(row[f"{p}_network"], row.get(f"{p}_wildcard"))
    return None


@debug_capture.traced
def _acl_records(records: list[dict[str, Any]]) -> dict[str, list[dict]]:
    """Convert TextFSM `show ip access-lists` records to the ACE shape that
    `resolve_acl_sources` reads. The header line gives a record with an empty
    action, which registers the ACL with no ACE."""
    out: dict[str, list[dict]] = {}
    for r in records:
        name = r.get("acl_name")
        if not name:
            continue
        aces = out.setdefault(name, [])
        if not r.get("action"):
            continue
        aces.append({"action": r["action"], "src": _acl_side(r, "src"), "dst": _acl_side(r, "dst")})
    return out


# Protocol keywords that match every protocol.
_ANY_PROTOCOLS = {"ip", "ipv4"}


def _acl_filter_side(row: dict[str, Any], p: str, *, implicit_any: bool = False) -> dict[str, Any]:
    """One side of an IOS-XE ACE row for the interface-ACL rulebase.

    Returns the `<side>_any` / `<side>` / `<side>_opaque_reason` fields of the
    shared ACE shape that `cisco_common.acl_stage` reads. A side that the
    template read as an object-group, or as a network whose wildcard is not a
    contiguous prefix, holds a reason in place of an address.
    """
    if row.get(f"{p}_any"):
        return {f"{p}_any": True, p: None, f"{p}_opaque_reason": None}
    if row.get(f"{p}_host"):
        return {f"{p}_any": False, p: row[f"{p}_host"], f"{p}_opaque_reason": None}
    if row.get(f"{p}_network"):
        cidr = wildcard_cidr(row[f"{p}_network"], row.get(f"{p}_wildcard"))
        if cidr:
            return {f"{p}_any": False, p: cidr, f"{p}_opaque_reason": None}
        network, wildcard = row[f"{p}_network"], row.get(f"{p}_wildcard")
        return {
            f"{p}_any": False,
            p: None,
            f"{p}_opaque_reason": f"the wildcard {wildcard} on {network} is not a contiguous prefix",
            f"{p}_opaque_note": f"wildcard {network} {wildcard} not a prefix",
        }
    group = row.get(f"{p}_network_object_group_name")
    if group:
        return {
            f"{p}_any": False,
            p: None,
            f"{p}_opaque_reason": f"the ACE matches object-group {group!r}, which is not collected",
            f"{p}_opaque_note": f"object-group {group} not collected",
        }
    if implicit_any:
        return {f"{p}_any": True, p: None, f"{p}_opaque_reason": None}
    return {f"{p}_any": False, p: None, f"{p}_opaque_reason": None}


def _acl_filter_service(row: dict[str, Any]) -> dict[str, Any]:
    """The service fields of an IOS-XE ACE row. They hold the protocol, the
    ports and the reason for a service that neither expresses. IOS-XE prints a
    well-known port by its keyword (`eq bgp`, `eq domain`). The keyword table
    of the row's protocol resolves it."""
    proto = (row.get("protocol") or "").lower() or None
    if proto in _ANY_PROTOCOLS:
        proto = None
    ports, why, note = ace_port_clause(
        row.get("dst_port_match"),
        row.get("dst_port") or row.get("dst_port_range_start"),
        row.get("dst_port_range_end"),
        proto=proto,
    )
    src_port, src_why, src_note = ace_port_clause(
        row.get("src_port_match"),
        row.get("src_port") or row.get("src_port_range_start"),
        row.get("src_port_range_end"),
        proto=proto,
    )
    group = row.get("service_object_group_name")
    if group:
        why = f"the ACE matches service object-group {group!r}, which is not collected"
        note = f"service object-group {group} not collected"
    out: dict[str, Any] = {
        "proto": proto,
        "ports": ports,
        "src_port": src_port,
        "svc_opaque_reason": why or src_why,
    }
    if why or src_why:
        out["svc_opaque_note"] = note if why else f"src {src_note}"
    return out


# The values of the `show ip access-lists` template (templates/
# cisco_ios_show_ip_access-lists.textfsm) that the ACE conversion accounts
# for. The set holds the values it reads, the counters and logging values it
# drops (LINE_NUM, LOG, LOG_TAG, MATCHES), and 2 values that only qualify a
# value read as undecided (FLAGS_MATCH beside TCP_FLAG, STATE beside TIME).
# Any other value makes the ACE undecided (`unmodeled_ace_fields`).
_ACE_RECORD_FIELDS = frozenset(
    {
        "acl_type",
        "acl_name",
        "line_num",
        "action",
        "protocol",
        "service_object_group_name",
        "flags_match",
        "tcp_flag",
        "log",
        "log_tag",
        "icmp_type",
        "time",
        "state",
        "matches",
    }
    | {
        f"{side}_{column}"
        for side in ("src", "dst")
        for column in (
            "host",
            "any",
            "network",
            "wildcard",
            "network_object_group_name",
            "port_match",
            "port",
            "port_range_start",
            "port_range_end",
        )
    }
)


@debug_capture.traced
def _acl_filter_records(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Convert TextFSM `show ip access-lists` records to the interface-ACL ACE shape.

    `_acl_records` builds the address-only shape that NAT match-list
    resolution reads. The interface-ACL shape also holds the protocol, the
    ports and the reasons a rule cannot be decided. A name that appears with
    only its header line maps to an empty ACE list. `acl_stage` reads it as an
    access list with only its implicit deny.

    `log` is dropped with no marker.
    """
    out: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        name = r.get("acl_name")
        if not name:
            continue
        aces = out.setdefault(name, [])
        if not r.get("action"):
            continue
        standard = (r.get("acl_type") or "").lower() == "standard"
        # TCP_FLAG is one field for the whole flag list ("established", "ack
        # established", ...). `established` is the Cisco connection-state
        # keyword and has a definite answer. It goes to `states` and stays out
        # of the other flags in `qualifier_reason`.
        flags = [f.lstrip("+-") for f in (r.get("tcp_flag") or "").split()]
        established = "established" in flags
        other_flags = [f for f in flags if f != "established"]
        ace = {
            "action": r["action"],
            **_acl_filter_side(r, "src"),
            **_acl_filter_side(r, "dst", implicit_any=standard),
            **_acl_filter_service(r),
            **ace_qualifiers(
                tcp_flags=other_flags,
                icmp_type=r.get("icmp_type"),
                time_range=r.get("time"),
                unmodeled=unmodeled_ace_fields(r, _ACE_RECORD_FIELDS),
            ),
        }
        if established:
            ace["states"] = ["established"]
        aces.append(ace)
    return out


# --- BGP / route-policy config: router bgp, ip prefix-list, route-map -----------------
#
# These parsers convert raw config text to the vendor-neutral intermediate
# shape that `cisco_common.routing_stage` reads. They read the BGP process of
# the default VRF and one `BgpProcess` per VRF from each
# `address-family ipv4|ipv6 [unicast] [vrf <name>]` block. They read the
# neighbors, with an administrative `neighbor <ip> shutdown` line,
# `peer-group` membership and the fields a neighbor inherits from its group.
# They also read `bgp listen range` peer ranges, `network` and
# `aggregate-address` origins, redistribution lines, `ip prefix-list`, and the
# match and set clauses of `route-map` that BGP route filtering reads.
# `template peer-session` and `template peer-policy` blocks are read and
# inherited like NX-OS templates (`cisco_bgp.inherit_peer_templates`).
# Confederation is not read.

_ROUTER_BGP_RE = re.compile(r"^router bgp (\d+(?:\.\d+)?)\s*$")
_BGP_ROUTER_ID_RE = re.compile(r"^bgp router-id (\S+)\s*$")
_NEIGHBOR_RE = re.compile(r"^neighbor (\S+) (\S+)(?:\s+(.*))?$")
_BGP_AF_RE = re.compile(r"^address-family (ipv4|ipv6)(?:\s+unicast)?(?:\s+vrf\s+(\S+))?$")
_BGP_NETWORK_RE = re.compile(r"^network (\S+)(?:\s+mask\s+(\S+))?(?:\s+route-map\s+(\S+))?$")
_BGP_AGGREGATE_RE = re.compile(r"^aggregate-address (\S+)(?:\s+(.*))?$")
_BGP_CLUSTER_ID_RE = re.compile(r"^bgp cluster-id (\S+)\s*$")
_BGP_TEMPLATE_RE = re.compile(r"^template (peer-session|peer-policy) (\S+)\s*$")


def _parse_redistribute(stripped: str) -> dict[str, Any] | None:
    """Tokenize a `redistribute <protocol> [... route-map <name> ...]` line. Only the
    protocol and an optional `route-map` name are captured."""
    tokens = stripped.split()
    if len(tokens) < 2 or tokens[0] != "redistribute":
        return None
    route_map = None
    if "route-map" in tokens:
        idx = tokens.index("route-map")
        if idx + 1 < len(tokens):
            route_map = tokens[idx + 1]
    return {"protocol": tokens[1], "route_map": route_map}


def _apply_neighbor_keyword(nb: dict[str, Any], keyword: str, rest: str) -> None:
    """Record one `neighbor <ip> <keyword> <rest>` setting on `nb`. The same
    line inside a `template peer-session|peer-policy` block is recorded the
    same way. `inherit peer-session <name>` and `inherit peer-policy <name>
    [<seq>]` add `peer_templates` references. They are resolved after the
    stanza is read."""
    if keyword == "remote-as" and rest:
        nb["remote_as"] = parse_asn(rest.split()[0])
    elif keyword == "description":
        nb["description"] = rest or None
    elif keyword == "shutdown":
        nb["shutdown"] = True
    elif keyword == "next-hop-self":
        # `all` also rewrites routes reflected from an iBGP peer
        nb["next_hop_self"] = "all" if rest.split()[:1] == ["all"] else "ebgp"
    elif keyword in ("route-map", "prefix-list", "filter-list") and rest:
        tokens = rest.split()
        if len(tokens) >= 2 and tokens[1] in ("in", "out"):
            nb[f"{keyword.replace('-', '_')}_{tokens[1]}"] = tokens[0]
    elif keyword == "route-reflector-client":
        nb["route_reflector_client"] = True
    elif keyword == "cluster-id" and rest:
        nb["cluster_id"] = parse_cluster_id(rest.split()[0])
    elif keyword == "inherit" and rest:
        tokens = rest.split()
        if len(tokens) >= 2 and tokens[0] in ("peer-session", "peer-policy"):
            seq = int(tokens[2]) if len(tokens) > 2 and tokens[2].isdigit() else 0
            nb.setdefault("peer_templates", []).append((tokens[0], tokens[1], seq))


@debug_capture.traced
def parse_bgp_config(text: str) -> dict[str, Any] | None:
    """Parse `router bgp <asn>` config text to {"asn", "router_id", "neighbors": [...],
    "redistribute": [...], "processes": [...]}, or None when the capture holds no
    BGP process.

    `processes` holds one entry per VRF and address family, the default VRF's
    first: its `vrf`, `af`, neighbors, redistribution, `network` and
    `aggregate-address` origins. The top-level `neighbors` and `redistribute` are
    the default VRF's. The indentation depth matters only inside a `template`
    block. An `address-family ... [vrf <name>]` line opens the process of the
    lines after it, up to `exit-address-family` or `exit`. A neighbor
    configured outside every address-family block belongs to the default VRF's
    process when the capture has no address-family block. Otherwise its fields
    are merged into the same neighbor inside a block.
    """
    asn: int | None = None
    router_id: str | None = None
    process_data: dict[str, dict[str, Any]] = {
        DEFAULT_VRF: {
            "neighbors": {},
            "redistribute": [],
            "networks": [],
            "aggregates": [],
            "origin_context_gaps": [],
            "af": 4,
        }
    }
    global_neighbors: dict[str, dict[str, Any]] = {}
    # Maps (kind, name) to the fields of the template, parsed like a neighbor's fields.
    templates: dict[tuple[str, str], dict[str, Any]] = {}
    template: dict[str, Any] | None = None
    template_indent = 0
    cluster_id: str | None = None
    current_vrf = DEFAULT_VRF
    in_address_family = False
    saw_address_family = False
    always_compare_med = False
    multipath_relax = False
    current_af = 4

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped == "!":
            continue
        if m := _ROUTER_BGP_RE.match(stripped):
            asn = parse_asn(m.group(1))
            continue
        if asn is None:
            continue
        indent = len(raw_line) - len(raw_line.lstrip())
        if template is not None:
            # a template's body is indented under its header and closed by
            # `exit-peer-session` or `exit-peer-policy`
            if stripped in {"exit-peer-session", "exit-peer-policy"}:
                template = None
                continue
            if indent > template_indent:
                keyword, _, rest = stripped.partition(" ")
                _apply_neighbor_keyword(template, keyword, rest.strip())
                continue
            template = None
        if m := _BGP_TEMPLATE_RE.match(stripped):
            template = templates.setdefault((m[1], m[2]), {"peer_ip": m[2]})
            template_indent = indent
            continue
        if m := _BGP_ROUTER_ID_RE.match(stripped):
            router_id = m.group(1)
            continue
        if m := _BGP_CLUSTER_ID_RE.match(stripped):
            cluster_id = parse_cluster_id(m.group(1))
            continue
        if stripped == "bgp always-compare-med":
            always_compare_med = True
            continue
        if stripped == "bgp bestpath as-path multipath-relax":
            multipath_relax = True
            continue
        if parsed_paths := parse_maximum_paths(stripped):
            # The paths count for the current address family, or for the IPv4
            # unicast family of the default VRF outside every address family.
            paths = process_data[current_vrf].setdefault("maximum_paths", {})
            for kind, count in parsed_paths:
                paths[f"{kind}_v{current_af if in_address_family else 4}"] = count
            continue
        if m := _BGP_AF_RE.match(stripped):
            saw_address_family = True
            in_address_family = True
            current_vrf = m.group(2) or DEFAULT_VRF
            current_af = 4 if m.group(1) == "ipv4" else 6
            process_data.setdefault(
                current_vrf,
                {
                    "neighbors": {},
                    "redistribute": [],
                    "networks": [],
                    "aggregates": [],
                    "origin_context_gaps": [],
                    "af": 4 if m.group(1) == "ipv4" else 6,
                },
            )
            continue
        if stripped in {"exit-address-family", "exit"}:
            current_vrf = DEFAULT_VRF
            in_address_family = False
            current_af = 4
            continue
        if stripped == "default-information originate":
            # Under `router bgp`, `default-information originate` takes no
            # other keyword. With it, a default route is redistributed into BGP.
            afs = process_data[current_vrf].setdefault("default_information_originate_afs", [])
            if current_af not in afs:
                afs.append(current_af)
            continue
        if m := re.match(r"^bgp listen range (\S+) peer-group (\S+)$", stripped):
            neighbors = process_data[current_vrf]["neighbors"] if in_address_family else global_neighbors
            neighbors[m[1]] = {"peer_ip": m[1], "peer_group": m[2]}
            continue
        if m := _NEIGHBOR_RE.match(stripped):
            peer_ip, keyword, rest = m.group(1), m.group(2), (m.group(3) or "")
            neighbors = process_data[current_vrf]["neighbors"] if in_address_family else global_neighbors
            nb = neighbors.setdefault(peer_ip, {"peer_ip": peer_ip})
            if keyword == "peer-group":
                if rest:
                    nb["peer_group"] = rest.split()[0]
                else:
                    nb["is_peer_group"] = True
            else:
                _apply_neighbor_keyword(nb, keyword, rest)
            continue
        if stripped.startswith("redistribute "):
            r = _parse_redistribute(stripped)
            if r:
                process_data[current_vrf]["redistribute"].append(r)
            continue
        if match := _BGP_NETWORK_RE.match(stripped):
            prefix = match[1]
            if match[2]:
                prefix = str(ipaddress.ip_network(f"{prefix}/{match[2]}", strict=False))
            process_data[current_vrf]["networks"].append(
                {"prefix": prefix if "/" in prefix else None, "raw": match[1], "route_map": match[3]}
            )
            continue
        if match := _BGP_AGGREGATE_RE.match(stripped):
            prefix = match[1]
            options = (match[2] or "").split()
            if options and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", options[0]):
                prefix = str(ipaddress.ip_network(f"{prefix}/{options.pop(0)}", strict=False))
            recorded, gap = parse_aggregate_options(prefix if "/" in prefix else None, options)
            recorded["raw"] = match[1]
            if gap:
                process_data[current_vrf]["origin_context_gaps"].append(gap)
            process_data[current_vrf]["aggregates"].append(recorded)

    if asn is None:
        return None
    processes = []
    for vrf_name, data in process_data.items():
        merged = []
        scoped_neighbors = dict(data["neighbors"])
        if vrf_name == DEFAULT_VRF and not saw_address_family:
            scoped_neighbors = global_neighbors
        else:
            for peer, neighbor in global_neighbors.items():
                if peer_network(peer) is not None and neighbor.get("peer_group") in scoped_neighbors:
                    scoped_neighbors.setdefault(peer, neighbor)
        for peer_ip, scoped in scoped_neighbors.items():
            unscoped = global_neighbors.get(peer_ip, {})
            nb = {**unscoped, **scoped}
            # A peer-session template is inherited outside the address family
            # and a peer-policy template inside it. Both apply.
            references = [*(unscoped.get("peer_templates") or []), *(scoped.get("peer_templates") or [])]
            if references:
                nb = inherit_peer_templates({**nb, "peer_templates": references}, templates)
                nb.pop("peer_templates", None)
            group = nb.get("peer_group")
            if group:
                inherited = {**global_neighbors.get(group, {}), **scoped_neighbors.get(group, {})}
                nb = {**inherited, **nb}
                nb.pop("is_peer_group", None)
                if not inherited.get("is_peer_group"):
                    nb["inheritance_gaps"] = [f"undefined peer-group {group}"]
            try:
                ipaddress.ip_network(peer_ip, strict=False)
            except ValueError:
                continue  # a named peer group is an inheritance source only
            merged.append(nb)
        processes.append(
            {
                "vrf": vrf_name,
                "af": data["af"],
                "asn": asn,
                "router_id": router_id,
                **({"cluster_id": cluster_id} if cluster_id else {}),
                **({"always_compare_med": True} if always_compare_med else {}),
                **({"maximum_paths": data["maximum_paths"]} if data.get("maximum_paths") else {}),
                **({"multipath_relax": True} if multipath_relax else {}),
                **(
                    {"default_information_originate_afs": sorted(data["default_information_originate_afs"])}
                    if data.get("default_information_originate_afs")
                    else {}
                ),
                "neighbors": merged,
                "redistribute": data["redistribute"],
                "networks": data["networks"],
                "aggregates": data["aggregates"],
                "origin_context_gaps": data["origin_context_gaps"],
            }
        )
    default = processes[0]
    return {
        "asn": asn,
        "router_id": router_id,
        "neighbors": default["neighbors"],
        "redistribute": default["redistribute"],
        "processes": processes,
    }


# `seq <n>` is absent from the running-config when the box is configured with
# `no ip prefix-list sequence-number`. IOS then numbers the entries 5, 10, 15 in
# the order of the lines.
_PL_HEADER_RE = re.compile(r"^ip prefix-list (\S+) (?:seq (\d+) )?(permit|deny) (\S+)(.*)$")
_PL_DESCRIPTION_RE = re.compile(r"^ip prefix-list \S+ description\b")


@debug_capture.traced
def parse_prefix_lists(text: str) -> dict[str, list[dict[str, Any]]]:
    """Parse `ip prefix-list <name> seq <n> permit|deny <prefix> [ge <n>] [le <n>] [eq <n>]`
    lines to {name: [{"seq", "action", "prefix", "ge", "le", "eq"}, ...]}.
    `ge`, `le` and `eq` keep their configured value, or None when absent. The
    graph stage of `cisco_common` computes the `min_len`/`max_len` range.
    """
    out: dict[str, list[dict[str, Any]]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        m = _PL_HEADER_RE.match(line)
        if not m:
            if line.startswith("ip prefix-list ") and not _PL_DESCRIPTION_RE.match(line):
                logger.warning("iosxe: prefix-list line not read, entry left out: %r", line)
            continue
        name, seq_text, action, prefix, rest = m.groups()
        previous = out.get(name)
        seq = int(seq_text) if seq_text else (previous[-1]["seq"] + 5 if previous else 5)
        ge = le = eq = None
        tokens = rest.split()
        for i in range(0, len(tokens) - 1, 2):
            if tokens[i] == "ge":
                ge = int(tokens[i + 1])
            elif tokens[i] == "le":
                le = int(tokens[i + 1])
            elif tokens[i] == "eq":
                eq = int(tokens[i + 1])
        out.setdefault(name, []).append(
            {"seq": seq, "action": action, "prefix": prefix, "ge": ge, "le": le, "eq": eq}
        )
    return out


_RM_HEADER_RE = re.compile(r"^route-map (\S+) (permit|deny) (\d+)\s*$")
# `match ip address prefix-list <name>...` is the IOS-XE grammar for a prefix-list
# match. A bare ACL name in the same command (`match ip address <acl>`) has no schema
# property. It goes verbatim to `match_unsupported` with every other match line that
# no pattern here reads.
_MATCH_PL_RE = re.compile(r"^match ip address prefix-list (.+)$")
_MATCH_AS_PATH_RE = re.compile(r"^match as-path (.+)$")
_MATCH_COMMUNITY_RE = re.compile(r"^match community (.+)$")
_MATCH_TAG_RE = re.compile(r"^match tag (.+)$")
_MATCH_METRIC_RE = re.compile(r"^match metric (\d+)\s*$")
_MATCH_SOURCE_PROTO_RE = re.compile(r"^match source-protocol (.+)$")
_SET_LOCAL_PREF_RE = re.compile(r"^set local-preference (\d+)\s*$")
_SET_METRIC_RE = re.compile(r"^set metric (\d+)\s*$")
_SET_ORIGIN_RE = re.compile(r"^set origin (\S+)\s*$")
_SET_TAG_RE = re.compile(r"^set tag (\d+)\s*$")
_SET_WEIGHT_RE = re.compile(r"^set weight (\d+)\s*$")
_SET_NEXT_HOP_RE = re.compile(r"^set ip next-hop (\d+\.\d+\.\d+\.\d+)\s*$")
_SET_AS_PATH_PREPEND_RE = re.compile(r"^set as-path prepend (\d+(?:\s+\d+)*)\s*$")
_SET_COMMUNITY_RE = re.compile(r"^set community (.+)$")
_SET_COMM_LIST_DEL_RE = re.compile(r"^set comm-list (\S+) delete\s*$")
_CONTINUE_RE = re.compile(r"^continue(?:\s+(\d+))?\s*$")


def _new_clause(action: str, seq: int) -> dict[str, Any]:
    return {
        "seq": seq,
        "action": action,
        "continues": False,
        "continue_seq": None,
        "match_prefix_lists": [],
        "match_as_path_lists": [],
        "match_community_lists": [],
        "match_tags": [],
        "match_metric": None,
        "match_protocols": [],
        "set_local_pref": None,
        "set_metric": None,
        "set_origin": None,
        "set_tag": None,
        "set_weight": None,
        "set_next_hop": None,
        "set_as_path_prepend": [],
        "set_communities": [],
        "set_communities_additive": None,
        "set_comm_list_delete": None,
    }


@debug_capture.traced
def parse_route_maps(text: str) -> dict[str, list[dict[str, Any]]]:
    """Parse `route-map <name> permit|deny <seq>` clauses and their `match`, `set`
    and `continue` sub-lines to {name: [clause, ...]} in config order.

    Each match and set field stored here has a `RoutePolicyEntry` property. A
    `match` line that no field reads is kept verbatim in `match_unsupported`,
    and the clause does not read as one with no match. A `set` line that no
    field reads (`set community none`, `set as-path prepend last-as`,
    `set ip next-hop peer-address`, `set extcommunity`, ...) is kept in
    `set_unsupported`, and the clause does not read as one that sets nothing
    more. `match community ... exact-match` also goes to `match_unsupported`.
    The engine has no exact-set comparison.

    `set community ... additive` is recorded as the configured keyword.
    `set_communities_additive` is True or False and is set only when a
    `set community` line is present.
    """
    out: dict[str, list[dict[str, Any]]] = {}
    current: dict[str, Any] | None = None
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped == "!":
            continue
        if m := _RM_HEADER_RE.match(stripped):
            current = _new_clause(m.group(2), int(m.group(3)))
            out.setdefault(m.group(1), []).append(current)
            continue
        if current is None:
            continue
        if m := _MATCH_PL_RE.match(stripped):
            current["match_prefix_lists"].extend(m.group(1).split())
        elif m := _MATCH_AS_PATH_RE.match(stripped):
            current["match_as_path_lists"].extend(m.group(1).split())
        elif m := _MATCH_COMMUNITY_RE.match(stripped):
            current["match_community_lists"].extend(t for t in m.group(1).split() if t != "exact-match")
            if "exact-match" in m.group(1).split():
                current.setdefault("match_unsupported", []).append(stripped)
        elif m := _MATCH_TAG_RE.match(stripped):
            current["match_tags"].extend(int(t) for t in m.group(1).split())
        elif m := _MATCH_METRIC_RE.match(stripped):
            current["match_metric"] = int(m.group(1))
        elif m := _MATCH_SOURCE_PROTO_RE.match(stripped):
            current["match_protocols"].extend(m.group(1).split())
        elif m := _SET_LOCAL_PREF_RE.match(stripped):
            current["set_local_pref"] = int(m.group(1))
        elif m := _SET_METRIC_RE.match(stripped):
            current["set_metric"] = int(m.group(1))
        elif m := _SET_ORIGIN_RE.match(stripped):
            current["set_origin"] = m.group(1)
        elif m := _SET_TAG_RE.match(stripped):
            current["set_tag"] = int(m.group(1))
        elif m := _SET_WEIGHT_RE.match(stripped):
            current["set_weight"] = int(m.group(1))
        elif m := _SET_NEXT_HOP_RE.match(stripped):
            current["set_next_hop"] = m.group(1)
        elif m := _SET_AS_PATH_PREPEND_RE.match(stripped):
            current["set_as_path_prepend"].extend(m.group(1).split())
        elif (m := _SET_COMMUNITY_RE.match(stripped)) and m.group(1).split() != ["none"]:
            tokens = m.group(1).split()
            current["set_communities_additive"] = "additive" in tokens
            current["set_communities"].extend(community_token(t) for t in tokens if t != "additive")
        elif m := _SET_COMM_LIST_DEL_RE.match(stripped):
            current["set_comm_list_delete"] = m.group(1)
        elif m := _CONTINUE_RE.match(stripped):
            current["continues"] = True
            current["continue_seq"] = int(m.group(1)) if m.group(1) else None
        elif stripped.startswith("match "):
            current.setdefault("match_unsupported", []).append(stripped)
        elif stripped.startswith("set "):
            current.setdefault("set_unsupported", []).append(stripped)
    return out


_NAMES_A_LIST_RE = re.compile(r"(?:\A|\n)[^\S\n]*(?:match community|match as-path|set comm-list)\s")


def match_list_commands(route_map_text: str) -> list[str]:
    """Return both list commands when a route-map clause names a community
    list or an AS-path list (`match community`, `match as-path`,
    `set comm-list ... delete`). Return no command otherwise."""
    return [CMD_COMMUNITY_LIST, CMD_AS_PATH_LIST] if _NAMES_A_LIST_RE.search(route_map_text) else []


def community_token(token: str) -> str:
    """Convert a community as IOS prints it to `ASN:NN`. Without
    `ip bgp-community new-format` the running-config shows a community as one
    32-bit number. The engine and the RIB use the `ASN:NN` form."""
    if token.isdigit():
        value = int(token)
        return f"{value >> 16}:{value & 0xFFFF}"
    return token


_CL_STANDARD_RE = re.compile(
    r"^ip community-list (?:standard (\S+)|(\d+))(?: seq (\d+))? (permit|deny)(?: (.+))?$"
)
_CL_EXPANDED_RE = re.compile(
    r"^ip community-list (?:expanded (\S+)|(\d+))(?: seq (\d+))? (permit|deny) (.+)$"
)
_AS_PATH_ACL_RE = re.compile(r"^ip as-path access-list (\S+)(?: seq (\d+))? (permit|deny) (.+)$")


def _list_entries(
    out: dict[str, list[dict[str, Any]]], name: str, seq: str | None, entry: dict[str, Any]
) -> None:
    lines = out.setdefault(name, [])
    entry["seq"] = int(seq) if seq else (lines[-1]["seq"] + 1 if lines else 1)
    lines.append(entry)


def parse_community_lists(text: str) -> list[dict[str, Any]]:
    """Parse `ip community-list` lines to `[{"name", "kind": "community-list",
    "entries"}]` in config order. A named `standard` list or a number from 1
    to 99 holds communities that a route must all carry (`standard`). A named
    `expanded` list or a number from 100 to 500 holds a regular expression
    (`expanded`). A line with no explicit `seq` takes the next number after
    the line before it."""
    out: dict[str, list[dict[str, Any]]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("ip community-list "):
            continue
        number = None
        m = _CL_STANDARD_RE.match(line)
        if m and m.group(2):
            number = int(m.group(2))
        if m and (m.group(1) or (number is not None and number < 100)):
            values = [community_token(t) for t in (m.group(5) or "").split()]
            entry = {"action": m.group(4), "match_type": "standard", "value": " ".join(values)}
            _list_entries(out, m.group(1) or m.group(2), m.group(3), entry)
            continue
        m = _CL_EXPANDED_RE.match(line)
        if m:
            entry = {"action": m.group(4), "match_type": "expanded", "value": m.group(5).strip()}
            _list_entries(out, m.group(1) or m.group(2), m.group(3), entry)
            continue
        logger.warning("iosxe: community-list line not read, entry left out: %r", line)
    return [{"name": name, "kind": "community-list", "entries": entries} for name, entries in out.items()]


def parse_as_path_lists(text: str) -> list[dict[str, Any]]:
    """Parse `ip as-path access-list <name> permit|deny <regex>` lines to
    `[{"name", "kind": "as-path-list", "entries"}]` in config order."""
    out: dict[str, list[dict[str, Any]]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("ip as-path access-list "):
            continue
        m = _AS_PATH_ACL_RE.match(line)
        if not m:
            logger.warning("iosxe: as-path access-list line not read, entry left out: %r", line)
            continue
        entry = {"action": m.group(3), "match_type": "expanded", "value": m.group(4).strip()}
        _list_entries(out, m.group(1), m.group(2), entry)
    return [{"name": name, "kind": "as-path-list", "entries": entries} for name, entries in out.items()]


# --- OSPF: operational commands and the config extract --------------------------------


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _hex_int_or_none(value: Any) -> int | None:
    try:
        return int(value, 16)
    except (TypeError, ValueError):
        return None


def _group_router_lsa_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group `cisco_ios_show_ip_ospf_database_router` records, one per link,
    into one row per LSA with a `links` list. `ospf_side_rows` reads this shape."""
    order: list[tuple[Any, ...]] = []
    by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
    for r in records:
        key = (r["process_id"], r["area"], r["lsa_id"], r["lsa_adv_router"], r["lsa_seq_number"])
        lsa = by_key.get(key)
        if lsa is None:
            lsa = {
                "process": r["process_id"],
                "area": ospf_area_id(r["area"]),
                "lsa_type": "router",
                "lsid": r["lsa_id"],
                "adv_router": r["lsa_adv_router"],
                "seq": _hex_int_or_none(r["lsa_seq_number"]),
                "age": _int_or_none(r["lsa_age"]),
                "metric": None,
                "links": [],
                "attached_routers": None,
                "mask": None,
                "forwarding_address": None,
                "metric_type": None,
            }
            by_key[key] = lsa
            order.append(key)
        lsa["links"].append(
            {
                "link_type": ospf_text_link_type(r["ls_link_type"]),
                "link_id": r.get("ls_link_id") or None,
                "link_data": r.get("ls_link_data") or None,
                "metric": _int_or_none(r.get("ls_tos_0_metrics")),
            }
        )
    return [by_key[k] for k in order]


def _group_network_lsa_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group `cisco_ios_show_ip_ospf_database_network` records, one per
    attached router, into one row per LSA with an `attached_routers` list."""
    order: list[tuple[Any, ...]] = []
    by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
    for r in records:
        key = (r["process_id"], r["area"], r["lsa_id"], r["lsa_adv_router"], r["lsa_seq_number"])
        lsa = by_key.get(key)
        if lsa is None:
            lsa = {
                "process": r["process_id"],
                "area": ospf_area_id(r["area"]),
                "lsa_type": "network",
                "lsid": r["lsa_id"],
                "adv_router": r["lsa_adv_router"],
                "seq": _hex_int_or_none(r["lsa_seq_number"]),
                "age": _int_or_none(r["lsa_age"]),
                "metric": None,
                "links": None,
                "attached_routers": [],
                "mask": r.get("lsa_network_mask") or None,
                "forwarding_address": None,
                "metric_type": None,
            }
            by_key[key] = lsa
            order.append(key)
        if r.get("ls_att_router"):
            lsa["attached_routers"].append(r["ls_att_router"])
    return [by_key[k] for k in order]


@debug_capture.traced
def parse_ospf(raw: dict[str, str]) -> dict[str, Any] | None:
    """Parse the OSPF captures to the intermediate `ospf` shape, described in
    the docstring of `cisco_common.normalize_cisco`. Return `None` when the
    payload holds none of the 10 OSPF commands."""
    if not any(cmd in raw for cmd in OSPF_COMMANDS):
        return None

    processes = parse_ospf_process_text(raw.get(CMD_OSPF) or "")
    by_process = {p["process"]: p for p in processes}

    config = parse_ospf_redistribute_config(raw.get(CMD_OSPF_CONFIG) or "")
    for process, entry in config.items():
        proc = by_process.setdefault(
            process,
            # A process the config declares that the operational command did
            # not answer for is kept, with its redistribution.
            {"process": process, "router_id": None, "areas": [], "redistribute": []},
        )
        proc["router_id"] = proc["router_id"] or entry["router_id"]
        proc["redistribute"] = entry["redistribute"]
        proc.update({k: v for k, v in entry.items() if k.startswith("default_information_originate")})

    interfaces = parse_ospf_interface_text(raw.get(CMD_OSPF_IF) or "")
    area_by_if = {i["name"]: i["area"] for i in interfaces if i.get("area") is not None}

    # `show ip ospf neighbor` prints every neighbor across every process in one table
    # with no per-row process column. Every adjacency gets the first process of this
    # capture, and `stamp_ospf_vrfs` then gives it the process of its local interface.
    nbr_records = cli_parse.parse("iosxe", CMD_OSPF_NBR, raw.get(CMD_OSPF_NBR) or "")
    process_id = next(iter(by_process), None)
    adjacencies = ospf_adjacency_rows_from_neighbor_records(
        nbr_records, process=process_id, area_by_if=area_by_if
    )

    router_records = cli_parse.parse("iosxe", CMD_OSPF_DB_ROUTER, raw.get(CMD_OSPF_DB_ROUTER) or "")
    network_records = cli_parse.parse("iosxe", CMD_OSPF_DB_NETWORK, raw.get(CMD_OSPF_DB_NETWORK) or "")
    lsdb: list[dict[str, Any]] = [
        *_group_router_lsa_records(router_records),
        *_group_network_lsa_records(network_records),
        *ospf_lsa_detail_rows(raw.get(CMD_OSPF_DB_SUMMARY) or "", default_type="summary"),
        *ospf_lsa_detail_rows(raw.get(CMD_OSPF_DB_ASBR_SUMMARY) or "", default_type="asbr-summary"),
        *ospf_lsa_detail_rows(raw.get(CMD_OSPF_DB_EXTERNAL) or "", default_type="external"),
        *ospf_lsa_detail_rows(raw.get(CMD_OSPF_DB_NSSA_EXTERNAL) or "", default_type="nssa-external"),
    ]

    return {
        "processes": list(by_process.values()),
        "interfaces": interfaces,
        "adjacencies": adjacencies,
        "lsdb": lsdb,
    }


# --- BGP session and path observations: the per-neighbor capture -----------
#
# The graph holds which process peers with which and which policy filters each
# direction (`parse_bgp_config`, `routing_stage`). It does not hold what crossed
# a session. The `rib` table holds the RIB next hop and no peer. These parsers
# read the observed sessions and paths from the commands of this platform.
# `bgp_side_rows` maps them onto the side-store tables `bgp_sessions` and
# `bgp_session_routes` (`core/sidestore.py`), like the observation capture of
# `nxos.py`. The capture covers the IPv4 processes that `parse_bgp_config`
# reads. These are the process of the default VRF and the process of each
# `address-family ipv4 vrf <name>` block. The summary and path commands of a
# VRF hold `vpnv4 vrf <name>` (`bgp_summary_command`, `bgp_route_command`).
#
# `cisco_bgp_table.path_rows` takes the column positions from the header line and
# reads rows that sit up to 2 columns right of them.

CMD_BGP_SESSIONS = "show ip bgp summary"


# Every neighbor of every address family and VRF. Each block holds its VRF in
# its header and the router ID of the peer on a `remote router ID` line
# (`cisco_bgp.parse_neighbor_router_ids`). No other command here prints the
# router ID of the peer. The counters change on every fetch, and the command is
# volatile. `stamp_peer_router_ids` keeps the router IDs in the change hash.
CMD_BGP_NEIGHBORS = "show bgp all neighbors"


def bgp_summary_command(vrf: str = DEFAULT_VRF) -> str:
    return CMD_BGP_SESSIONS if not vrf or vrf == DEFAULT_VRF else f"show ip bgp vpnv4 vrf {vrf} summary"


# The 3 directions of a session and the per-neighbor command keyword of each.
# `received` needs soft reconfiguration inbound on the neighbor. Without it,
# IOS-XE keeps no pre-policy table and answers with a message. The direction is
# then recorded as `not-captured`.
BGP_DIRECTION_KEYWORDS: dict[str, str] = {
    "received": "received-routes",
    "accepted": "routes",
    "advertised": "advertised-routes",
}
BGP_RIB_TYPES: dict[str, str] = {
    "received": "adj-rib-in",
    "accepted": "loc-rib",
    "advertised": "adj-rib-out",
}
BGP_POLICY_STAGES: dict[str, str] = {
    "received": "pre-import",
    "accepted": "post-import",
    "advertised": "post-export",
}
# Each command of the BGP observation capture reads the IPv4 unicast paths of
# one VRF. A command for a VRF other than the default holds `vpnv4 vrf <name>`.
# The sub-family of each observed row comes from the command and is not parsed
# from the output.
BGP_SAFI = "unicast"


def bgp_route_command(peer_ip: str, direction: str, vrf: str = DEFAULT_VRF) -> str:
    """Return the per-neighbor path command for one direction, `show ip bgp
    [vpnv4 vrf <vrf>] neighbors <peer> received-routes|routes|advertised-routes`.
    The VRF clause is present for every VRF except the default."""
    scope = "" if not vrf or vrf == DEFAULT_VRF else f"vpnv4 vrf {vrf} "
    return f"show ip bgp {scope}neighbors {peer_ip} {BGP_DIRECTION_KEYWORDS[direction]}"


# Matches every raw key that the BGP observation capture derives per fetch.
# These are the session summary of each VRF (`bgp_summary_command`) and the
# path command of each peer and direction (`bgp_route_command`). No other
# command of this collector matches the pattern.
BGP_OBSERVATION_KEY_RE = re.compile(
    r"show ip bgp (?:vpnv4 vrf \S+ )?(?:summary|neighbors \S+ (?:"
    + "|".join(map(re.escape, BGP_DIRECTION_KEYWORDS.values()))
    + r"))"
)


# Matches the derived observation commands, which are the BGP summaries, the
# BGP path tables and the per-VRF ARP tables.
OBSERVATION_KEY_RE = re.compile(f"{BGP_OBSERVATION_KEY_RE.pattern}|{ARP_VRF_KEY_RE.pattern}")


# the header line of the `show vrf` table
_VRF_TABLE_HEADER_RE = re.compile(r"^[ \t]*Name\s+Default RD\s+Protocols\s+Interfaces", re.M)


def arp_vrf_commands(vrf_text: str) -> list[str]:
    """Return the ARP command of each VRF that the `show vrf` answer lists.

    The answer is read from the table header on. During the fetch, the answer
    of an exec channel still holds the login banner. The fetch removes the
    banner after its last command (`_strip_exec_banner`). An answer that the
    template cannot read gives no command. The parse of the payload reports
    that failure."""
    m = _VRF_TABLE_HEADER_RE.search(vrf_text or "")
    if m is None:
        return []
    try:
        rows = cli_parse.parse("iosxe", CMD_VRF, vrf_text[m.start() :])
    except TextFSMError:
        return []
    return list(dict.fromkeys(CMD_ARP_VRF.format(vrf=r["name"]) for r in rows if r.get("name")))


def _arp_vrf_rows(
    raw: dict[str, Any], vrf_by_if: dict[str, str], resolve: IfNameResolver
) -> list[dict[str, Any]]:
    """The rows of the per-VRF ARP tables. Each row holds the VRF of its
    command."""
    rows: list[dict[str, Any]] = []
    for key, text in raw.items():
        m = ARP_VRF_KEY_RE.fullmatch(key) if isinstance(key, str) else None
        if m and isinstance(text, str) and text:
            rows += cli_parse.parse(
                "iosxe", key, text, row=lambda r, vrf=m[1]: {**arp_row(r, vrf_by_if, resolve), "vrf": vrf}
            )
    return rows


def _bgp_scopes(bgp: dict[str, Any] | None) -> list[tuple[str, int]]:
    """Return the (VRF, 4) scope of each IPv4 process, or the default VRF when
    there is no IPv4 process. A VRF with only listen ranges gets a scope too."""
    return list(
        dict.fromkeys(
            (p.get("vrf") or DEFAULT_VRF, 4)
            for p in (bgp or {}).get("processes") or ([bgp] if bgp else [])
            if int(p.get("af") or 4) == 4
        )
    ) or [(DEFAULT_VRF, 4)]


def _bgp_scoped_targets(
    bgp: dict[str, Any] | None, observed: list[dict[str, Any]] | None = None
) -> list[tuple[str, int, str]]:
    """Return (VRF, address family, peer) for each peer of each configured
    process, with the dynamic peers that `observed` matches to a listen range.
    The list is in configuration order and has no duplicates.

    The address family is the family of the process. `parse_bgp_config` keys
    processes by VRF and does not record which address-family block activates
    a neighbor. The neighbors of the `address-family ipv6` block of the default
    VRF therefore join its IPv4 process. It is not known here whether such a
    neighbor also has IPv4 unicast. Each such peer gets the IPv4 path commands,
    and the answer of the device shows whether it has IPv4 unicast
    (`_command_outcome`)."""
    out: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int, str]] = set()
    for process in (bgp or {}).get("processes") or ([bgp] if bgp else []):
        vrf, af = process.get("vrf") or DEFAULT_VRF, int(process.get("af") or 4)
        expanded = expand_dynamic_neighbors(process.get("neighbors") or [], observed or [], vrf)
        for peer_ip in bgp_capture_targets({**process, "neighbors": expanded}):
            target = (vrf, af, peer_ip)
            if target not in seen:
                seen.add(target)
                out.append(target)
    return out


def bgp_capture_targets(bgp: dict[str, Any] | None) -> list[str]:
    """Return the neighbor addresses of one process in configuration order and
    without duplicates. The input is the `parse_bgp_config` result from which
    `routing_stage` builds the BgpSession nodes of the graph. A
    `neighbor <prefix>` listen range has no single address to query and is
    skipped. A fetch asks for the path tables of the peers of the IPv4
    processes (`_bgp_scoped_targets`)."""
    out: list[str] = []
    seen: set[str] = set()
    for n in (bgp or {}).get("neighbors") or []:
        peer_ip = n.get("peer_ip") or ""
        try:
            ipaddress.ip_address(peer_ip)
        except ValueError:
            continue
        if peer_ip not in seen:
            seen.add(peer_ip)
            out.append(peer_ip)
    return out


def _bgp_session_state(value: str) -> tuple[str, int | None]:
    """Read the state column of the IOS-XE summary table. The column holds the
    count of received prefixes once a session is Established, and the
    connection state word otherwise (`Idle`, `Active`, `Connect`, ...). A digit
    string means Established. Any other value is returned unmapped as the
    state word of the device."""
    if value.isdigit():
        return "Established", int(value)
    return value, None


def parse_bgp_sessions(text: str) -> list[dict[str, Any]]:
    """Parse a session summary (`bgp_summary_command`) to one observed-session
    record per IPv4 unicast neighbor. `parse_bgp_observations` adds the VRF of
    the command to each record.
    `established_since_ms`, `prefixes_advertised` and `capabilities` stay
    null. The command reports a relative up/down duration and no advertised
    count or capabilities. An absolute time needs the fetch clock, and the row
    writer does not hold it."""
    out: list[dict[str, Any]] = []
    # Dynamic peers have a '*' prefix. The installed TextFSM template accepts
    # only a bare address at the start of the row. The match starts at the
    # first line start in the whitespace before the '*'.
    text = re.sub(r"(\A|(?<=\S)[^\S\n]*\n)\s*\*(?=\d+\.)", r"\1", text)
    for row in cli_parse.parse("iosxe", CMD_BGP_SESSIONS, text):
        peer_ip = row.get("bgp_neighbor")
        if not peer_ip:
            continue
        # A row with an address family other than IPv4 unicast is skipped.
        # `show ip bgp summary` prints no "For address family:" header.
        af = row.get("address_family") or ""
        if af and "ipv4" not in af.lower():
            continue
        state, prefixes_received = _bgp_session_state(row.get("state_or_prefixes_received") or "")
        out.append(
            {
                "peer_ip": peer_ip,
                "state": state,
                **(
                    {"peer_asn": int(row["neighbor_as"])} if str(row.get("neighbor_as", "")).isdigit() else {}
                ),
                "established_since_ms": None,
                "prefixes_received": prefixes_received,
                "prefixes_advertised": None,
                "capabilities": None,
            }
        )
    return out


def _count_bgp_paths(text: str) -> int:
    """Count the path rows that `iter_bgp_paths` yields for this payload
    without building them."""
    return sum(1 for _ in cisco_bgp_table.path_rows(text))


def iter_bgp_paths(text: str, *, peer_ip: str, direction: str) -> Iterator[dict[str, Any]]:
    """Parse one `bgp_route_command` payload to one record per path of each
    prefix. Each record is built when its line is read
    (`cisco_bgp_table.path_rows`). `_direction_rows` adds the VRF.

    The command output has no per-path identifier and no community list.
    `path_id` and `communities` stay None. A metric or local preference that
    the table leaves blank is None.
    """
    received = direction == "received"
    rows = cisco_bgp_table.path_rows(text)
    for status, prefix, next_hop, metric, local_pref, _weight, as_path, origin in rows:
        yield {
            "peer_ip": peer_ip,
            "direction": direction,
            "prefix": prefix,
            "path_id": None,
            "next_hop": next_hop,
            "as_path": as_path,
            "local_pref": int(local_pref) if local_pref else None,
            "med": int(metric) if metric else None,
            "origin": origin,
            "communities": None,
            # None for the received direction, which is read before the
            # decision process runs and has no marking (nxos.py `_bgp_best`).
            # None for a table that prints no status column (`status` None).
            "best": None if received or status is None else ">" in status,
        }


def parse_bgp_paths(text: str, *, peer_ip: str, direction: str) -> list[dict[str, Any]]:
    """`iter_bgp_paths` as a list."""
    return list(iter_bgp_paths(text, peer_ip=peer_ip, direction=direction))


def _direction_rows(text: str, peer_ip: str, direction: str, vrf: str, af: int) -> Iterator[dict[str, Any]]:
    """The observed paths of one session direction with its VRF and address
    family. The rows form one part of the `routes` of `parse_bgp_observations`."""
    for row in iter_bgp_paths(text, peer_ip=peer_ip, direction=direction):
        row.update(vrf=vrf, af=af)
        yield row


@debug_capture.traced
def parse_bgp_observations(raw: dict[str, str], bgp: dict[str, Any] | None) -> dict[str, Any]:
    """The observed half of the BGP capture, for the payload's own commands.

    `sessions` is the observed session state, `routes` every observed path,
    and `directions` one entry per session and direction the fetch asked
    for, with the row count of that direction. A direction whose command is
    absent from the payload has no row count.

    `routes` is a `streams.ChainRows` view with one part per direction that
    the payload answered. A part reads the command text in the payload and
    builds each path when it is read. A pass over the view yields the paths
    of every direction in order. Its length and the row count of each
    direction come from a counting pass that builds no rows. A fetch calls
    this function before any path command is in the payload, and the counting
    pass then counts nothing.
    """
    sessions: list[dict[str, Any]] = []
    scopes = _bgp_scopes(bgp)
    for vrf, af in scopes:
        command = bgp_summary_command(vrf)
        for session in parse_bgp_sessions(raw.get(command) or ""):
            sessions.append({**session, "vrf": vrf, "af": af})
    parts: list[tuple[int, functools.partial[Iterator[dict[str, Any]]]]] = []
    directions: list[dict[str, Any]] = []
    for vrf, af, peer_ip in _bgp_scoped_targets(bgp, sessions):
        for direction in BGP_DIRECTION_KEYWORDS:
            command = bgp_route_command(peer_ip, direction, vrf)
            entry: dict[str, Any] = {
                "vrf": vrf,
                "af": af,
                "peer_ip": peer_ip,
                "direction": direction,
                "command": command,
                "row_count": None,
            }
            if command in raw:
                text = raw[command]
                count = _count_bgp_paths(text)
                parts.append((count, functools.partial(_direction_rows, text, peer_ip, direction, vrf, af)))
                entry["row_count"] = count
            directions.append(entry)
    observed: dict[str, Any] = {
        "sessions": sessions,
        "routes": streams.ChainRows(parts),
        "directions": directions,
    }
    if ids := parse_neighbor_router_ids(raw.get(CMD_BGP_NEIGHBORS)):
        observed["peer_router_ids"] = nest_router_ids(ids)
    return observed


def _bgp_session_uid(device_uid: str, peer_ip: str, vrf: str = DEFAULT_VRF) -> str:
    """The BgpSession uid that joins an observed row to the graph. It uses the
    formula of `cisco_common.routing_stage` (`uid.bgp_session(uid.
    routing_process(dev, vrf, "bgp"), peer_ip, vrf)`,
    `cisco_bgp.emit_bgp_peer`)."""
    return uid.bgp_session(uid.routing_process(device_uid, vrf, "bgp"), peer_ip, vrf)


@debug_capture.traced
def bgp_side_rows(inter: dict[str, Any], device_uid: str) -> dict[str, Sequence[dict[str, Any]]]:
    """Map the observed BGP records onto the two side-store tables with the
    device, context and session uids. `context_uid` is
    `uid.vrf(device_uid, <the session's VRF>)`, the formula that
    `cisco_common.side_rows` uses for `rib` and `arp`.

    `bgp_session_routes` is a `streams.MappedRows` view over the observed
    paths. Each row is built when it is read."""
    observed = inter.get("bgp_observed") or {}
    if not observed.get("sessions") and not observed.get("routes"):
        return {}
    sessions = [
        {
            "device_uid": device_uid,
            "context_uid": uid.vrf(device_uid, s.get("vrf") or DEFAULT_VRF),
            "session_uid": _bgp_session_uid(device_uid, s["peer_ip"], s.get("vrf") or DEFAULT_VRF),
            "peer_ip": s["peer_ip"],
            # This collector captures the IPv4 unicast family only.
            "af": s.get("af", 4),
            "safi": BGP_SAFI,
            "state": s.get("state"),
            "established_since_ms": s.get("established_since_ms"),
            "prefixes_received": s.get("prefixes_received"),
            "prefixes_advertised": s.get("prefixes_advertised"),
            "capabilities": s.get("capabilities"),
        }
        for s in observed.get("sessions") or []
    ]
    contexts: dict[str, str] = {}
    session_uids: dict[tuple[str, str], str] = {}

    def route(r: dict[str, Any]) -> dict[str, Any]:
        direction = r["direction"]
        vrf = r.get("vrf") or DEFAULT_VRF
        context_uid = contexts.get(vrf)
        if context_uid is None:
            context_uid = contexts[vrf] = uid.vrf(device_uid, vrf)
        peer_ip = r["peer_ip"]
        session_uid = session_uids.get((peer_ip, vrf))
        if session_uid is None:
            session_uid = session_uids[peer_ip, vrf] = _bgp_session_uid(device_uid, peer_ip, vrf)
        return {
            "device_uid": device_uid,
            "context_uid": context_uid,
            "session_uid": session_uid,
            "peer_ip": peer_ip,
            "safi": BGP_SAFI,
            "direction": direction,
            "rib_type": BGP_RIB_TYPES[direction],
            "policy_stage": BGP_POLICY_STAGES[direction],
            "path_id": r.get("path_id"),
            "prefix": r["prefix"],
            "next_hop": r.get("next_hop"),
            # This platform's commands never resolve a BGP next hop
            # outside the session's own context.
            "next_hop_context_uid": None,
            "as_path": r.get("as_path"),
            "local_pref": r.get("local_pref"),
            "med": r.get("med"),
            "origin": r.get("origin"),
            "communities": r.get("communities"),
            "best": r.get("best"),
            **lpm_columns(r["prefix"]),
        }

    return {
        "bgp_sessions": sessions,
        "bgp_session_routes": streams.MappedRows(observed.get("routes") or [], route),
    }


# The detail of a BGP table or direction that a run did not read, per capture
# setting.
_CAPTURE_REASONS: dict[str, str] = {
    "none": "the source's capture_bgp setting is none",
    "sessions": "the source's capture_bgp setting is sessions, which reads session state only",
}

# `_command_outcome` reads an answer in place without a stripped copy.
# `\S` matches each character that `str.isspace` rejects and `str.strip` keeps.
# The class of `_LINE_BREAK_RE` holds every line boundary that `str.splitlines`
# splits on.
_NON_SPACE_RE = re.compile(r"\S")
_LINE_BREAK_RE = re.compile(r"[\n\r\x0b\x0c\x1c-\x1e\x85\u2028\u2029]")


def _arp_vrf_outcome(arp: SectionOutcome, outcomes: dict[str, SectionOutcome]) -> SectionOutcome:
    """The `arp` section, partial when the table of a VRF was not read."""
    missed = sorted(
        m[1]
        for command, out in outcomes.items()
        if (m := ARP_VRF_KEY_RE.fullmatch(command)) and out.status != "ok"
    )
    if not missed or arp.status not in ("ok", "empty"):
        return arp
    detail = f"the ARP table of VRF {', '.join(missed)} was not read"
    return SectionOutcome(status="partial", detail=detail, row_count=arp.row_count or 0)


def _command_outcome(text: Any, recorded: SectionOutcome | None, row_count: int | None) -> TableOutcome:
    """The outcome of one observation command, from its recorded outcome and
    its answer.

    A command that the platform refused as unknown is `not-captured`. The box
    does not have the feature or does not keep the table. A command refused
    for another reason, such as a credential without the privilege or a
    failed command, is `failed`. A command that answered with a `%` line in
    place of a table is `not-captured` too, with the words of the device as
    detail. IOS-XE answers this way for a received table when no soft
    reconfiguration inbound is configured, with a zero exit status and no
    rejection banner.

    The answer can be a full path table and is read in place. The first
    non-blank character decides the outcome. The detail is the stripped first
    non-blank line, found without copying the rest.
    """
    if recorded is None:
        return TableOutcome(status="not-captured")
    if recorded.status == "unsupported":
        return TableOutcome(status="not-captured", detail=recorded.detail)
    if recorded.status != "ok":
        return TableOutcome(status="failed", detail=recorded.detail)
    body = text if isinstance(text, str) else str(text or "")
    first = _NON_SPACE_RE.search(body)
    if first is None:
        return TableOutcome(status="complete-empty", row_count=0)
    start = first.start()
    if body[start] == "%":
        end = _LINE_BREAK_RE.search(body, start)
        return TableOutcome(
            status="not-captured", detail=body[start : end.start() if end else len(body)].strip()
        )
    count = row_count or 0
    if not count:
        return TableOutcome(status="complete-empty", row_count=0)
    return TableOutcome(status="complete", row_count=count)


# The detail for a path answer that holds lines shaped like path rows of which
# the reader read none. `cisco_bgp_table` does not know the layout of the answer.
_UNREAD_PATHS = "the answer holds path rows, and none of them could be read"

# The detail for a session of an address family other than IPv4 unicast. Such
# a session has no observed paths, and the session table leaves it out.
_IPV4_UNICAST_ONLY = "IOS-XE BGP session observation captures IPv4 unicast only"


def bgp_table_outcomes(
    raw: dict[str, Any], inter: dict[str, Any], device_uid: str, *, capture: str
) -> dict[str, TableOutcome]:
    """The outcomes of the BGP tables and of the 3 directions of each session,
    like `bgp_table_outcomes` in nxos.py.

    The configured processes are the ones that `parse` read into
    `inter["routing"]`. The BGP configuration is parsed once per payload."""
    outcomes: dict[str, TableOutcome] = {}
    recorded = effective_outcomes(raw, inter, ALWAYS_PRESENT_COMMANDS)
    observed = inter.get("bgp_observed") or {}
    if capture in _CAPTURE_REASONS:
        detail = _CAPTURE_REASONS[capture]
        outcomes[BGP_ROUTES_TABLE] = TableOutcome(status="not-captured", detail=detail)
        if capture == "none":
            outcomes[BGP_SESSIONS_TABLE] = TableOutcome(status="not-captured", detail=detail)
    if capture != "none":
        # The commands are in the order the fetch sends them. The first
        # failure reported is the same on every run.
        bgp = (inter.get("routing") or {}).get("bgp")
        summary_commands = dict.fromkeys(
            [CMD_BGP_SESSIONS, *(bgp_summary_command(vrf) for vrf, _ in _bgp_scopes(bgp))]
        )
        states = [_command_outcome(raw.get(cmd), recorded.get(cmd), None) for cmd in summary_commands]
        bad = next((state for state in states if state.status == "failed"), None) or next(
            (state for state in states if state.status == "not-captured"), None
        )
        if bad is not None:
            outcomes[BGP_SESSIONS_TABLE] = bad
        elif any(entry.get("af", 4) != 4 for entry in observed.get("directions") or []):
            outcomes[BGP_SESSIONS_TABLE] = TableOutcome(status="not-captured", detail=_IPV4_UNICAST_ONLY)
    for entry in observed.get("directions") or []:
        session_uid = _bgp_session_uid(device_uid, entry["peer_ip"], entry.get("vrf") or DEFAULT_VRF)
        text = raw.get(entry["command"])
        outcome = _command_outcome(text, recorded.get(entry["command"]), entry["row_count"])
        if (
            outcome.status == "complete-empty"
            and entry["row_count"] == 0
            and isinstance(text, str)
            and cisco_bgp_table.holds_path_rows(text)
        ):
            outcome = TableOutcome(status="failed", detail=_UNREAD_PATHS)
        if outcome.status == "not-captured" and not outcome.detail:
            # A session of an IPv6 process is sent no path command
            # (`_bgp_scoped_targets`), whatever the capture setting.
            if entry.get("af", 4) != 4:
                outcome = outcome.model_copy(update={"detail": _IPV4_UNICAST_ONLY})
            elif capture in _CAPTURE_REASONS:
                outcome = outcome.model_copy(update={"detail": _CAPTURE_REASONS[capture]})
        outcomes[bgp_direction_key(session_uid, entry["direction"])] = outcome
    return outcomes


# The `cisco_ios_show_interfaces` ntc-template splits the duplex and speed line
# ("  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX") and the MTU and
# BW line ("  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,") into the
# `duplex`, `speed` and `bandwidth` fields. DUPLEX holds the `-duplex` suffix
# ("Full-duplex", "Auto-duplex"), and the BANDWIDTH value is "1000000 Kbit".
# On an `Auto-duplex, Auto-speed` line, DUPLEX matches "Auto-duplex", which
# reads as unknown like an absent line. SPEED does not match "Auto-speed",
# which has no `b/s` suffix, and the field is empty.
_IOSXE_SPEED_RE = re.compile(r"^(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>Mb/s|Gb/s)$", re.IGNORECASE)
_IOSXE_BANDWIDTH_RE = re.compile(r"^(?P<value>\d+)\s*Kbit(?:/sec)?$", re.IGNORECASE)


def _iosxe_speed_mbps(speed: Any) -> int | None:
    if not isinstance(speed, str) or not speed:
        return None
    m = _IOSXE_SPEED_RE.match(speed.strip())
    if not m:
        return None
    mbps = float(m["value"]) * (1000 if m["unit"].lower() == "gb/s" else 1)
    rounded = round(mbps)
    return rounded if abs(mbps - rounded) < 1e-6 else None


def _iosxe_duplex(duplex: Any) -> str | None:
    if not isinstance(duplex, str):
        return None
    value = duplex.strip().lower().removesuffix("-duplex")
    return value if value in ("full", "half") else None


def _iosxe_bandwidth_kbit(bandwidth: Any) -> int | None:
    """The `BW` value of the MTU line that `mtu_interface_fields` also reads.
    The value is the routing-metric bandwidth in Kbit/s."""
    if not isinstance(bandwidth, str) or not bandwidth:
        return None
    m = _IOSXE_BANDWIDTH_RE.match(bandwidth.strip())
    return int(m["value"]) if m else None


def _parse_interface(row: dict[str, Any]) -> dict:
    name = row["interface"]
    kind = interface_kind(name, lag_prefix="port-channel", svi=True)
    vlan = None
    if kind == "svi":
        m = _VLAN_RE.search(name)
        vlan = int(m.group()) if m else None
    ips = []
    if row.get("ip_address") and row.get("prefix_length"):
        ips.append({"ip": row["ip_address"], "prefixlen": int(row["prefix_length"]), "vrf": ""})
    speed_mbps = _iosxe_speed_mbps(row.get("speed"))
    duplex = _iosxe_duplex(row.get("duplex"))
    parsed = {
        **mtu_interface_fields(row),
        "name": name,
        "kind": kind,
        "mac": canonical_mac(row.get("mac_address")),
        # `link_status` starts with "administratively" when the port is shut
        # down by config. "down" alone is the operational state.
        "admin_up": not (row.get("link_status") or "").startswith("administratively"),
        "ips": ips,
        "vlan": vlan,
        "speed_mbps": speed_mbps,
        "duplex": duplex,
        "speed_source": "iosxe:show interfaces" if (speed_mbps is not None or duplex is not None) else None,
        "bandwidth_kbit": _iosxe_bandwidth_kbit(row.get("bandwidth")),
    }
    description = (row.get("description") or "").strip()
    if description:
        parsed["description"] = description
    return parsed


def stack_serials(raw: dict[str, str]) -> list[str]:
    """Every chassis serial that `show version` lists, one per member of a
    stack. The first one is the Device's `serial` (`parse`). A placeholder
    names no chassis and is left out (`chassis_serial`)."""
    rows = cli_parse.parse("iosxe", CMD_VERSION, raw[CMD_VERSION])
    return [s for s in (rows[0] if rows else {}).get("serial") or [] if chassis_serial(s)]


# The key of the intermediate shape that holds the count of route-table lines
# that the template could not read (`cli_parse.parse_with_unread`). `sections`
# reports the count on the `rib` section. The key is absent when every line was
# read.
RIB_UNREAD_KEY = "rib_unread_lines"


@debug_capture.traced
def parse(raw: dict[str, str]) -> dict[str, Any]:
    """Turn the `{command: raw_cli_text}` outputs into the intermediate shape of
    all Cisco families that `cisco_common.normalize_cisco` reads. The function
    has no side effects."""
    version_rows = cli_parse.parse("iosxe", CMD_VERSION, raw[CMD_VERSION])
    v = version_rows[0] if version_rows else {}
    serials = stack_serials(raw)
    device = {
        "hostname": v.get("hostname") or "unknown",
        "serial": serials[0] if serials else None,
        "platform": "iosxe",
        "os_version": v.get("version") or None,
    }

    vrf_rows = cli_parse.parse("iosxe", CMD_VRF, raw[CMD_VRF])

    # `show vrf detail` holds the RD and the route targets. They are merged
    # onto the `show vrf` rows by name below.
    detail_text = raw.get(CMD_VRF_DETAIL)
    detail_rows = cli_parse.parse("iosxe", CMD_VRF_DETAIL, detail_text) if detail_text else []
    detail_by_name = {r["vrf"]: r for r in detail_rows}

    interfaces = [
        _parse_interface(row) for row in cli_parse.parse("iosxe", CMD_INTERFACES, raw[CMD_INTERFACES])
    ]
    # `show vrf` abbreviates the member names. They are matched to the names of the
    # interface table.
    names = [ifc["name"] for ifc in interfaces]
    resolve = IfNameResolver(names)
    vrf_by_if = if_vrf_map(vrf_rows, vrf_key="name", device_ifnames=names)
    for ifc in interfaces:
        vname = vrf_of(vrf_by_if, resolve, ifc["name"], "")
        for ip in ifc["ips"]:
            ip["vrf"] = vname

    lldp_rows = cli_parse.parse("iosxe", CMD_LLDP, raw[CMD_LLDP])
    cdp_rows = cli_parse.parse("iosxe", CMD_CDP, raw[CMD_CDP])
    neighbors = lldp_neighbor_rows(lldp_rows, name_key="neighbor_name") + cdp_neighbor_rows(cdp_rows)

    # Each record becomes its row when it is parsed (`cli_parse.parse(row=)`).
    # The TextFSM records of a full table are never all held at once. A table
    # line that the template cannot read loses that line only (`RIB_UNREAD_KEY`).
    rib, rib_unread = cli_parse.parse_with_unread(
        "iosxe",
        CMD_ROUTE,
        raw[CMD_ROUTE],
        row=functools.partial(
            rib_row, next_hop_key="nexthop_ip", interface_key="nexthop_if", next_hop_vrf_key="nexthop_vrf"
        ),
    )
    rib = [row for row in rib if row is not None]
    arp = cli_parse.parse(
        "iosxe", CMD_ARP, raw[CMD_ARP], row=functools.partial(arp_row, vrf_by_if=vrf_by_if, resolve=resolve)
    ) + _arp_vrf_rows(raw, vrf_by_if, resolve)

    nat = parse_nat_config(raw[CMD_NAT].splitlines())
    nat["if_roles"].update(_nat_if_roles(raw[CMD_NAT_STATS]))
    acl_rows = cli_parse.parse("iosxe", CMD_ACL, raw[CMD_ACL])
    nat["acls"] = _acl_records(acl_rows)

    # The access-list capture is read a second time. NAT resolves match lists
    # from the address-only shape above. The interface-ACL rulebases need the
    # protocol, the ports and the reasons a rule cannot be decided.
    acl = {
        "lists": _acl_filter_records(acl_rows),
        "bindings": parse_access_groups((raw.get(CMD_INTERFACE_CONFIG) or "").splitlines())
        + parse_vlan_filters((raw.get(CMD_VLAN_FILTER) or "").splitlines()),
    }

    bgp = parse_bgp_config(raw.get(CMD_BGP) or "")
    prefix_lists = parse_prefix_lists(raw.get(CMD_PREFIX_LIST) or "")
    route_maps = parse_route_maps(raw.get(CMD_ROUTE_MAP) or "")
    community_lists = parse_community_lists(raw.get(CMD_COMMUNITY_LIST) or "")
    as_path_lists = parse_as_path_lists(raw.get(CMD_AS_PATH_LIST) or "")
    routing = (
        {"bgp": bgp, "prefix_lists": prefix_lists, "route_maps": route_maps}
        if any((bgp, prefix_lists, route_maps, community_lists, as_path_lists))
        else None
    )
    if routing is not None and community_lists:
        routing["community_lists"] = community_lists
    if routing is not None and as_path_lists:
        routing["as_path_lists"] = as_path_lists
    bgp_observed = parse_bgp_observations(raw, bgp)

    # A missing command and the "" stand-in both parse to no groups.
    standby_text = raw.get(CMD_STANDBY)
    vrrp_text = raw.get(CMD_VRRP)
    fhrp = fhrp_rows(
        cli_parse.parse("iosxe", CMD_STANDBY, standby_text) if standby_text else [],
        kind="hsrp",
        priority_key="priority",
        vip_key="virtual_ip_address",
    ) + fhrp_rows(
        cli_parse.parse("iosxe", CMD_VRRP, vrrp_text) if vrrp_text else [],
        kind="vrrp",
        priority_key="priority",
        vip_key="virtual_ip_address",
    )

    inter: dict[str, Any] = {
        "device": device,
        "interfaces": interfaces,
        "neighbors": neighbors,
        "vlans": [],
        "vrfs": [{"name": r["name"], **vrf_rt_fields(detail_by_name.get(r["name"]))} for r in vrf_rows],
        "nat": nat,
        "acl": acl,
        "routing": routing,
        "rib": rib,
        "mac_table": [],
        "arp": arp,
        "bgp_observed": bgp_observed,
        "fhrp": fhrp,
    }
    # None for a payload without the OSPF capture (`table_outcomes`).
    ospf = parse_ospf(raw)
    if ospf is not None:
        stamp_ospf_vrfs(ospf, vrf_by_if, resolve)
        inter["ospf"] = ospf
    if rib_unread:
        inter[RIB_UNREAD_KEY] = rib_unread
    inter["mtu_model"] = (v.get("hardware") or [None])[0]
    parse_mtu(raw, inter, family="iosxe", config_command=CMD_INTERFACE_CONFIG)
    return inter


class IosxeConfig(SshSourceConfig):
    # The MTU capture is optional. A stored capture always replays.
    capture_mtu: bool = False


@register
class IosxeCollector(CiscoCliCollector):
    NORMALIZATION_VERSIONS: ClassVar[dict[str, str]] = {
        # the '.' of a subinterface name stays in the Interface and Port uid
        "iface_uid": uid.IFACE_UID_VERSION,
        "mtu": MTU_NORMALIZATION_VERSION,
        "bgp_dynamic_peers": "1",
        # an OSPF process is keyed by its id and holds its VRF
        "ospf_process": "1",
        # the ARP table of each VRF
        "arp_vrf": "1",
        # a static translation to an interface address keeps its rule
        "nat_static_interface": "1",
        # the interface description on Interface and Port
        "port_description": "1",
        # an `ip prefix-list` line with no ge, le or eq is an exact match
        "prefix_list_exact": "1",
        # A refused always-present command reads unauthorized. A refusal
        # recorded `ok` reads as the refusal. The side tables are judged by
        # the sections that feed them.
        "read-failures": "1",
        # interface access lists hold their installation evidence
        "acl_installation": "1",
        # a NAT rule's position is its evaluation order, statics first
        "nat_position": "1",
        # BgpSession holds route-reflector-client, a filter-list and a
        # prefix-list beside a route-map
        "bgp_session_filters": "1",
        # A placeholder serial identifies no chassis. A serial that 2 devices
        # report in one run keys the later device by its ref.
        "serial": "1",
        # Neighbors inherit peer-session and peer-policy templates. BgpSession
        # holds the cluster id. RoutingProcess holds the neighbors that get no
        # session.
        "bgp_cluster_id": "1",
        # RoutingProcess records maximum-paths and multipath-relax
        "bgp_multipath": "1",
        # BgpSession holds the peer's router id from the neighbor output
        "bgp_peer_router_id": "1",
        # a zone-member interface binds an opaque zone-based firewall rulebase
        "zbfw_gap": "1",
    }
    # Version 2 reads path rows by column position (`cisco_bgp_table`).
    PARSER_VERSION: ClassVar[str] = "2"
    NORMALIZATION_OUTCOME_KEYS = (*COMMANDS, *MTU_COMMANDS["iosxe"].values())

    def sections(self, raw):
        inter = self._inter(raw)
        sections = {**super().sections(raw), **mtu_sections(raw, inter, family=self.name)}
        sections["rib"] = cli_parse.unread_outcome(sections["rib"], inter.get(RIB_UNREAD_KEY, 0))
        sections["arp"] = _arp_vrf_outcome(sections["arp"], effective_outcomes(raw, inter))
        # The collector does not read a zone-based firewall. With zones
        # configured, the `interface_config` section is partial, and the
        # coverage check of the tracer reads a leg across this router as
        # undecided.
        zones = sorted(
            {b["acl"] for b in (inter.get("acl") or {}).get("bindings") or [] if b.get("family") == "zone"}
        )
        current = sections.get("interface_config")
        if zones and current is not None and current.status in ("ok", "empty"):
            sections["interface_config"] = SectionOutcome(
                status="partial",
                row_count=current.row_count or 0,
                detail="zone-based firewall configured (zones "
                + ", ".join(zones)
                + "); zone-pair inspect policies are not modeled",
            )
        return annotate_fhrp_sections(sections, inter, {"hsrp": "hsrp", "vrrp": "vrrp"})

    name = "iosxe"
    ConfigModel = IosxeConfig
    KIND = "group"
    COMMANDS = COMMANDS
    # The ages of the ARP table and the route table and the up/down column of
    # the BGP session summaries change on every fetch. The BGP path tables
    # change with every route that the peers send. No graph object is built
    # from the ARP, route and path texts. They feed only the `arp`, `rib` and
    # `bgp_session_routes` side tables. The summaries feed the graph only
    # through the dynamic peers they list. `stamp_dynamic_observations` keeps
    # these peers in the change hash as `_strata_dynamic_bgp`. Each key is also
    # an observation key, and its side-store rows follow `obs_sha`. The
    # recorded outcome of the route command stays in the change hash through
    # NORMALIZATION_OUTCOME_KEYS. The uptime in `show version` and the hit
    # counters in `show ip nat statistics` also change on every fetch and are
    # not declared. The Device node and the NAT roles of the interfaces are
    # built from those texts and stay in the change hash. The batch digest
    # (`graph_sha`) spares an unchanged device its graph write.
    VOLATILE_RAW_KEYS = (CMD_ARP, CMD_ROUTE, CMD_BGP_SESSIONS, CMD_BGP_NEIGHBORS)
    VOLATILE_RAW_KEY_PATTERN = OBSERVATION_KEY_RE
    # The ARP table, the RIB, the BGP session summaries, the BGP neighbor
    # detail and the BGP path tables. OBSERVATION_KEY_RE matches the per-VRF
    # summaries, the path commands and the per-VRF ARP tables, which each
    # fetch derives. The BGP neighbor detail is volatile, and the change hash
    # holds only its router ids (`stamp_peer_router_ids`).
    OBSERVATION_RAW_KEYS = (CMD_ARP, CMD_ROUTE, CMD_BGP_SESSIONS, CMD_BGP_NEIGHBORS)
    OBSERVATION_RAW_KEY_PATTERN = OBSERVATION_KEY_RE
    OPTIONAL_COMMANDS: ClassVar[dict[str, str]] = {
        CMD_LLDP: "",
        CMD_CDP: "",
        CMD_ARP: "",
        CMD_VRF_DETAIL: "",
        CMD_NAT: "",
        CMD_NAT_STATS: "",
        CMD_ACL: "",
        CMD_BGP: "",
        CMD_PREFIX_LIST: "",
        CMD_ROUTE_MAP: "",
        CMD_INTERFACE_CONFIG: "",
        CMD_VLAN_FILTER: "",
        # OSPF: the stand-ins parse to no processes, no adjacencies and no LSAs.
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
        # HSRP and VRRP. A box with no group answers with an empty table. The
        # stand-in covers a refused command.
        CMD_STANDBY: "",
        CMD_VRRP: "",
    }
    ALWAYS_PRESENT_COMMANDS: ClassVar[frozenset[str]] = ALWAYS_PRESENT_COMMANDS
    SECTIONS = SECTIONS
    # The sections of the required commands.
    AUTHORITATIVE_SECTIONS = ("device", "interfaces", "vrfs", "rib")
    # The 3 tables of every Cisco family, the link-state database and the 2
    # BGP observation tables.
    SIDE_TABLES: ClassVar[tuple[str, ...]] = (
        *CiscoCliCollector.SIDE_TABLES,
        "ospf_lsdb",
        BGP_ROUTES_TABLE,
        BGP_SESSIONS_TABLE,
    )
    # The labels that each optional section owns alone, for the section-level
    # carry (`Collector.SECTION_LABELS`). `arp`, `lldp`, `cdp` and `nat_stats`
    # own no label. `arp` writes side-store rows and no graph object. The
    # neighbor reads only merge properties onto the Ports that the `interfaces`
    # section wrote. NAT statistics only add interface roles. `vrf_detail` is
    # the only producer of `RouteTarget` on this family. The 10 OSPF sections
    # are absent.
    SECTION_LABELS: ClassVar[dict[str, tuple[str, ...]]] = {
        "arp": (),
        "lldp": (),
        "cdp": (),
        "nat_stats": (),
        "vrf_detail": ("RouteTarget",),
        "nat": ("NatRule",),
        "acl": ("FwRule", "NetObject", "SvcObject"),
        "interface_config": ("FwRule", "NetObject", "SvcObject"),
        "vlan_filter": ("FwRule", "NetObject", "SvcObject"),
        "bgp": ("RoutingProcess", "BgpSession", "BgpPeerRange"),
        "route_maps": ("RoutePolicyEntry",),
        "prefix_lists": ("PrefixListEntry",),
        # Both `hsrp` and `vrrp` write `FhrpGroup`, and neither owns it.
        "hsrp": (),
        "vrrp": (),
    }

    @staticmethod
    def _parse(raw: dict[str, str]) -> dict[str, Any]:
        return parse(raw)

    def _ospf_table_outcomes(self, raw: dict[str, str]) -> dict[str, TableOutcome]:
        """Return `{ospf_lsdb: unsupported}` when the device runs no OSPF
        process. Return a failed outcome when an OSPF feature command did not
        answer, and an empty dict otherwise.

        IOS-XE prints nothing for `show ip ospf` and its siblings when no
        `router ospf` process is configured.
        """
        recorded = effective_outcomes(raw, self._inter(raw), ALWAYS_PRESENT_COMMANDS)
        statuses = [recorded[cmd].status for cmd in OSPF_FEATURE_COMMANDS if cmd in recorded]
        if any(status != "ok" for status in statuses):
            # A command that did not answer leaves its part of the database
            # empty. That empty table is not the answer of the device.
            failed = failed_feature_outcome(recorded, OSPF_FEATURE_COMMANDS, "OSPF")
            return {OSPF_LSDB_TABLE: failed} if failed is not None else {}
        inter = self._inter(raw)
        ospf = inter.get("ospf")
        if ospf is not None and not ospf.get("processes"):
            return {
                OSPF_LSDB_TABLE: TableOutcome(
                    status="unsupported", detail="the device does not have the feature this table reads"
                )
            }
        return {}

    def normalize(self, raw: dict[str, str]) -> Batch:
        """The shared Cisco normalization, with every serial of a stack bound to
        the one Device uid. The first serial resolves the uid, and the registry
        binds the other serials to it. The uid stays when a member leaves the
        stack or another member becomes the first one."""
        batch = super().normalize(raw)
        serials = stack_serials(raw)
        if len(serials) > 1:
            dev = self._device_uid(self._inter(raw))
            for serial in serials[1:]:
                self.identity.bind_device(dev, "serial", serial)
        return batch

    def _device_uid(self, inter: dict[str, Any]) -> str:
        """The Device node uid of this payload, with the formula of `CiscoCliCollector.side_tables`."""
        return device_uid(inter, self.scope, self.identity, self.config.host)

    def side_tables(self, raw: dict[str, str]) -> dict[str, Sequence[dict[str, Any]]]:
        """The 3 base Cisco tables and the 2 BGP observation tables."""
        inter = self._inter(raw)
        return {**super().side_tables(raw), **bgp_side_rows(inter, self._device_uid(inter))}

    def table_outcomes(self, raw: dict[str, Any]) -> dict[str, TableOutcome]:
        """The outcomes of the MAC table, the OSPF link-state database
        (`_ospf_table_outcomes`), the BGP tables and the 3 directions of each
        session (`bgp_table_outcomes`)."""
        inter = self._inter(raw)
        return {
            "mac": TableOutcome(status="not-captured", detail="the IOS-XE collector reads no MAC table"),
            **self._ospf_table_outcomes(raw),
            **bgp_table_outcomes(raw, inter, self._device_uid(inter), capture=self.config.capture_bgp),
        }

    async def _afetch_over(self, s) -> dict[str, Any]:
        """Run the static command loop (`SshCliCollector._afetch_over`), the
        per-VRF ARP reads, the BGP observation capture, the optional MTU capture
        and the match-list reads."""
        raw = await super()._afetch_over(s)
        await self._afetch_arp_vrfs(s, raw)
        await self._afetch_bgp_observations(s, raw)
        if self.config.capture_mtu:
            await capture_mtu(s, raw, family=self.name, check=self.check_stop)
        commands = match_list_commands(raw.get(CMD_ROUTE_MAP) or "")
        await capture_match_lists(s, raw, commands, check=self.check_stop)
        return raw

    async def _afetch_arp_vrfs(self, s, raw: dict[str, Any]) -> None:
        """Read the ARP table of each VRF that `show vrf` lists. A refusal is
        recorded under `RAW_OUTCOMES_KEY` and leaves an empty answer. A timeout
        ends the fetch."""
        outcomes = raw.get(RAW_OUTCOMES_KEY)
        if not isinstance(outcomes, dict):
            outcomes = {}
            raw[RAW_OUTCOMES_KEY] = outcomes
        for cmd in arp_vrf_commands(raw.get(CMD_VRF) or ""):
            self.check_stop()
            try:
                raw[cmd] = await s.run(cmd)
                outcomes[cmd] = {"status": "ok"}
            except ssh.CommandFailed as exc:
                logger.warning("%s: %r failed (%s); continuing without it", self.name, cmd, exc)
                raw[cmd] = ""
                status, detail = classify_command_failure(exc)
                outcomes[cmd] = {"status": status, "detail": detail}

    async def _afetch_bgp_observations(self, s, raw: dict[str, Any]) -> None:
        """Read the observed session state and, for `capture_bgp` of `all`,
        the three path tables of every configured neighbor.

        Every command is optional like the `OPTIONAL_COMMANDS`. A refusal is
        logged, recorded under `RAW_OUTCOMES_KEY` with the words of the device,
        and left as an empty stand-in payload.

        A path command that times out is recorded the same way when each
        command has its own session, on an exec channel or with a fresh
        connection per command. The direction then reads `failed`. On one
        shell session the timeout ends the fetch (`ssh.ShellSession.run`).

        After `PATH_TIMEOUT_LIMIT` timeouts in a row the fetch sends no more
        path commands. Each command not sent reads `failed` with that reason
        (`not_sent_after_timeouts`).
        """
        capture = self.config.capture_bgp
        if capture == "none":
            return
        bgp = parse_bgp_config(raw.get(CMD_BGP) or "")
        commands = list(dict.fromkeys(bgp_summary_command(vrf) for vrf, _ in _bgp_scopes(bgp)))
        if CMD_BGP_SESSIONS not in commands:
            commands.insert(0, CMD_BGP_SESSIONS)
        commands.append(CMD_BGP_NEIGHBORS)
        outcomes = raw.get(RAW_OUTCOMES_KEY)
        if not isinstance(outcomes, dict):
            outcomes = {}
            raw[RAW_OUTCOMES_KEY] = outcomes
        session_per_command = (
            getattr(self.config, "channel", "exec") == "exec" or self.config.fresh_connection_per_command
        )

        async def read_commands(commands, *, timeout_costs_command=False):
            timeouts = 0
            for cmd in commands:
                if timeouts >= PATH_TIMEOUT_LIMIT:
                    raw[cmd] = ""
                    outcomes[cmd] = not_sent_after_timeouts(timeouts)
                    continue
                self.check_stop()
                try:
                    raw[cmd] = await s.run(cmd)
                    outcomes[cmd] = {"status": "ok"}
                    timeouts = 0
                except (ssh.CommandFailed, ssh.SshTimeout) as exc:
                    if isinstance(exc, ssh.SshTimeout) and not timeout_costs_command:
                        raise
                    timeouts = timeouts + 1 if isinstance(exc, ssh.SshTimeout) else 0
                    if timeouts == PATH_TIMEOUT_LIMIT:
                        logger.warning(
                            "%s: %d path commands in a row timed out; the rest are not sent",
                            self.name,
                            timeouts,
                        )
                    logger.warning("%s: %r failed (%s); continuing without it", self.name, cmd, exc)
                    raw[cmd] = ""
                    status, detail = classify_command_failure(exc)
                    outcomes[cmd] = {"status": status, "detail": detail}

        await read_commands(commands)
        sessions = parse_bgp_observations(raw, bgp)["sessions"]
        processes = (bgp or {}).get("processes") or ([bgp] if bgp else [])
        stamp_dynamic_observations(raw, processes, sessions)
        stamp_peer_router_ids(raw, parse_neighbor_router_ids(raw.get(CMD_BGP_NEIGHBORS)))
        if capture == "all":
            await read_commands(
                [
                    bgp_route_command(peer, direction, vrf)
                    for vrf, af, peer in _bgp_scoped_targets(bgp, sessions)
                    if af == 4
                    for direction in BGP_DIRECTION_KEYWORDS
                ],
                timeout_costs_command=session_per_command,
            )

    def probe(self) -> str:
        out = self._run(CMD_VERSION)
        for line in out.splitlines():
            if line.strip():
                return line.strip()
        return "connected (empty version output)"
