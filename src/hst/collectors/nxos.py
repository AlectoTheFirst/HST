"""The NX-OS collector runs the show commands in `COMMANDS` and the per-neighbor
BGP observation capture. Every command is `| json` except the running-config
extracts.

The VRF membership of an interface comes from `show vrf interface` (`if_name`
and `vrf_name` of `TABLE_if/ROW_if`). The "default" VRF is stored as `""`. The
`next_hop` of a RIB or ARP row is `None` for a connected or direct route.

At first contact, capture the payloads and rerun `parse()` on them:

    ssh <user>@<host> 'show version | json' \
      > data/raw/nxos/first-contact/show-version.json
    # repeat once per entry in COMMANDS, one file per command:
    #   show-interface.json, show-lldp-neighbors-detail.json,
    #   show-cdp-neighbors.json, show-vlan.json,
    #   show-vrf.json, show-ip-route-vrf-all.json, show-mac-address-table.json,
    #   show-ip-arp-vrf-all.json, show-vrf-interface.json,
    #   show-running-config-nat.txt, show-ip-access-lists.json,
    #   show-running-config-bgp.txt, show-running-config-rpm.txt,
    #   show-running-config-interface.txt,
    #   show-ip-ospf.json, show-ip-ospf-interface.json,
    #   show-ip-ospf-neighbors.json, show-ip-ospf-database-router.json,
    #   show-ip-ospf-database-network.json,
    #   show-ip-ospf-database-summary.json,
    #   show-ip-ospf-database-external.json,
    #   show-ip-ospf-database-nssa-external.json,
    #   show-ip-ospf-database-asbr-summary.json, show-running-config-ospf.txt,
    #   show-interface-trunk.json
    #   show-hsrp-all.json, show-vrrp-detail.json, show-vpc.json
    # plus the BGP observation capture, per fetch
    # (see CMD_BGP_SESSIONS): show-bgp-sessions-vrf-all.json, and per neighbor
    #   show-bgp-neighbors-<peer>-received-routes.json, -routes.json,
    #   -advertised-routes.json
"""

from __future__ import annotations

import contextlib
import functools
import ipaddress
import json
import logging
import re
from collections.abc import Callable, Iterable, Iterator, Sequence
from typing import Any, ClassVar

from hst.core import uid
from hst.core.l3domain import DEFAULT_VRF
from hst.core.manifest import (
    BGP_ROUTES_TABLE,
    BGP_SESSIONS_TABLE,
    OSPF_LSDB_TABLE,
    bgp_direction_key,
    ospf_context_key,
)
from hst.core.model import Batch, SectionOutcome, TableOutcome
from hst.core.mtu import MTU_NORMALIZATION_VERSION
from hst.core.normalize import IfNameResolver

from . import cli_parse, ssh, streams
from .base import RAW_OUTCOMES_KEY, register
from .cisco_bgp import (
    emit_bgp_peer,
    expand_dynamic_neighbors,
    inherit_peer_templates,
    neighbor_key,
    nest_router_ids,
    observed_peer_router_id,
    peer_network,
    reflector_client,
    router_id_or_none,
    stamp_dynamic_observations,
    stamp_peer_router_ids,
)
from .cisco_common import (
    MTU_ALWAYS_PRESENT,
    MTU_COMMANDS,
    OSPF_LSA_TYPES,
    OSPF_REDIST_PROTOCOLS,
    ace_port_clause,
    ace_qualifiers,
    annotate_fhrp_sections,
    capture_mtu,
    cdp_device_id,
    device_uid,
    list_references,
    match_list_stage,
    mtu_sections,
    ospf_default_originate,
    parse_access_groups,
    parse_mtu,
    parse_nat_config,
    parse_vlan_filters,
    unmodeled_ace_fields,
)
from .cli_collector import (
    PATH_TIMEOUT_LIMIT,
    CiscoCliCollector,
    Section,
    SshSourceConfig,
    build_sections,
    classify_command_failure,
    effective_outcomes,
    failed_feature_outcome,
    not_sent_after_timeouts,
)
from .util import (
    GraphBuilder,
    as_int,
    bgp_multipath_props,
    canonical_mac,
    lpm_columns,
    parse_aggregate_options,
    parse_asn,
    parse_cluster_id,
    parse_maximum_paths,
)

logger = logging.getLogger(__name__)

CMD_VERSION = "show version | json"
CMD_INTERFACE = "show interface | json"
CMD_LLDP = "show lldp neighbors detail | json"
# The brief CDP table. `device_id` is `<hostname>[.<domain>](<serial>)` on a
# Nexus far end and a bare hostname on the rest (`cisco_common.cdp_device_id`).
CMD_CDP = "show cdp neighbors | json"
# A device with CDP off answers the CDP command with this one line in place of
# the table, with exit status 0. The answer gives no neighbors and an
# `unsupported` section (`cdp_off_note`).
_CDP_OFF_RE = re.compile(r"\s*(Note: CDP not enabled\.?)\s*")
CMD_VLAN = "show vlan | json"
CMD_VRF = "show vrf | json"
CMD_ROUTE = "show ip route vrf all | json"
CMD_MAC = "show mac address-table | json"
CMD_ARP = "show ip arp vrf all | json"
CMD_VRF_IF = "show vrf interface | json"
CMD_TRUNK = "show interface trunk | json"
# The NAT config and the interface NAT roles have no JSON rendering.
CMD_NAT = "show running-config nat"
CMD_ACL = "show ip access-lists | json"
# The BGP process and neighbor config, the route-maps and the prefix-lists
# have no `| json` rendering. `show running-config` on NX-OS has no `route-map`
# or `ip prefix-list` keyword. The Route Policy Manager extract `rpm` holds
# both, with the community lists and the as-path lists. `CMD_RPM` feeds both
# parsers. Each parser skips the lines of the other.
CMD_BGP = "show running-config bgp"
CMD_RPM = "show running-config rpm"
# The OSPF commands.
#
# No OSPF command is in `VOLATILE_RAW_KEYS`. The change hash covers every one
# of them. The process, interface and neighbor reads build graph objects
# (`RoutingProcess`, `OspfArea`, `OspfAdjacency` and the `IN_AREA` edges). LSA
# age and neighbor uptime change between fetches. The change hash of a device
# that runs OSPF differs on every fetch. LSA age and neighbor uptime are not
# graph properties, and the batch digest (`graph_sha`) excludes them.
#
# Without the `vrf all` clause NX-OS answers for the default VRF alone.
CMD_OSPF = "show ip ospf vrf all | json"
CMD_OSPF_IF = "show ip ospf interface vrf all | json"
CMD_OSPF_NBR = "show ip ospf neighbors vrf all | json"
# The link-state database has one command per LSA type. `detail` returns the
# bodies that SPF needs (the links of a router LSA, the attached routers of a
# network LSA, the mask of a summary LSA, the forwarding address and the
# metric type of an external LSA). The form without `detail` returns a header
# list.
CMD_OSPF_DB_ROUTER = "show ip ospf database router detail vrf all | json"
CMD_OSPF_DB_NETWORK = "show ip ospf database network detail vrf all | json"
CMD_OSPF_DB_SUMMARY = "show ip ospf database summary detail vrf all | json"
CMD_OSPF_DB_EXTERNAL = "show ip ospf database external detail vrf all | json"
# The NSSA external LSA (type 7) and the ASBR summary LSA (type 4).
CMD_OSPF_DB_NSSA = "show ip ospf database nssa-external detail vrf all | json"
CMD_OSPF_DB_ASBR_SUMMARY = "show ip ospf database asbr-summary detail vrf all | json"
CMD_OSPF_CONFIG = "show running-config ospf"
# Each OSPF command's spelling without the `vrf all` clause.
LEGACY_OSPF_COMMANDS: dict[str, str] = {
    CMD_OSPF: "show ip ospf | json",
    CMD_OSPF_IF: "show ip ospf interface | json",
    CMD_OSPF_NBR: "show ip ospf neighbors | json",
    CMD_OSPF_DB_ROUTER: "show ip ospf database router detail | json",
    CMD_OSPF_DB_NETWORK: "show ip ospf database network detail | json",
    CMD_OSPF_DB_SUMMARY: "show ip ospf database summary detail | json",
    CMD_OSPF_DB_EXTERNAL: "show ip ospf database external detail | json",
    CMD_OSPF_DB_NSSA: "show ip ospf database nssa-external detail | json",
    CMD_OSPF_DB_ASBR_SUMMARY: "show ip ospf database asbr-summary detail | json",
}


def _ospf_command(raw: dict[str, Any], command: str) -> str:
    """The key of `raw` that holds the answer of `command`. The key is the
    command, or its `LEGACY_OSPF_COMMANDS` spelling when the payload holds
    that spelling alone."""
    legacy = LEGACY_OSPF_COMMANDS.get(command)
    return legacy if command not in raw and legacy in raw else command


def ospf_default_vrf_only(raw: dict[str, Any]) -> bool:
    """True when the process table of this payload covers the default VRF
    alone. Such a payload holds the `LEGACY_OSPF_COMMANDS` spelling of CMD_OSPF
    without CMD_OSPF."""
    return CMD_OSPF not in raw and LEGACY_OSPF_COMMANDS[CMD_OSPF] in raw


def _ospf_aliased(raw: dict[str, Any]) -> dict[str, Any]:
    """Returns `raw` with each OSPF answer and recorded outcome copied from its
    `LEGACY_OSPF_COMMANDS` spelling to the command, when the command is absent."""
    aliases = {c: old for c, old in LEGACY_OSPF_COMMANDS.items() if c not in raw and old in raw}
    if not aliases:
        return raw
    out = dict(raw)
    stored = raw.get(RAW_OUTCOMES_KEY)
    outcomes = dict(stored) if isinstance(stored, dict) else None
    for command, old in aliases.items():
        out[command] = raw[old]
        if outcomes is not None and old in outcomes and command not in outcomes:
            outcomes[command] = outcomes[old]
    if outcomes is not None:
        out[RAW_OUTCOMES_KEY] = outcomes
    return out


# `ip access-group <acl> in|out` is in the interface stanzas of the running-config.
CMD_INTERFACE_CONFIG = "show running-config interface"
# `vlan filter <map> vlan-list <ids>` is global config. A VLAN access map filters
# every packet of the VLANs in its list. `show running-config interface` does not
# show it.
CMD_VLAN_FILTER = 'show running-config | include "^vlan filter"'
# First-hop redundancy and vPC. All 3 commands are optional. A device without
# `feature hsrp`, `feature vrrp` or `feature vpc` refuses the command. The
# refusal is classified as `unsupported`
# (cli_collector.classify_command_failure). It degrades the section of that
# command alone.
CMD_HSRP = "show hsrp all | json"
CMD_VRRP = "show vrrp detail | json"
CMD_VPC = "show vpc | json"

OSPF_COMMANDS: tuple[str, ...] = (
    CMD_OSPF,
    CMD_OSPF_IF,
    CMD_OSPF_NBR,
    CMD_OSPF_DB_ROUTER,
    CMD_OSPF_DB_NETWORK,
    CMD_OSPF_DB_SUMMARY,
    CMD_OSPF_DB_EXTERNAL,
    CMD_OSPF_DB_NSSA,
    CMD_OSPF_DB_ASBR_SUMMARY,
    CMD_OSPF_CONFIG,
)
# The subset whose refusal proves the device has no OSPF process.
OSPF_FEATURE_COMMANDS: tuple[str, ...] = (
    CMD_OSPF,
    CMD_OSPF_DB_ROUTER,
    CMD_OSPF_DB_NETWORK,
    CMD_OSPF_DB_SUMMARY,
    CMD_OSPF_DB_EXTERNAL,
    CMD_OSPF_DB_NSSA,
    CMD_OSPF_DB_ASBR_SUMMARY,
)

# The commands of the BGP observation capture are not in `COMMANDS`. The set
# is decided per fetch. `capture_bgp` on the source selects the session state,
# the per-neighbor path tables, or neither. The per-neighbor commands contain
# peers that the same fetch first reads from `show running-config bgp`. Every
# command of the capture is optional.
#
# The session table of every VRF. Without the `vrf all` clause the command
# answers for the default VRF alone. A session in any other VRF then has no
# observed state, and a dynamic range in such a VRF has no observed peer.
CMD_BGP_SESSIONS = "show bgp sessions vrf all | json"
# The table of the default VRF alone. A fetch runs this command when the
# device refuses the `vrf all` clause (`bgp_sessions_command`).
CMD_BGP_SESSIONS_DEFAULT_VRF = "show bgp sessions | json"
# The neighbor detail of every VRF. It is the only command that returns the
# router identifier of the peer (`parse_bgp_neighbor_router_ids`). Its counters
# change on every fetch, and the command is volatile. `stamp_peer_router_ids`
# keeps the router identifiers in the change hash.
CMD_BGP_NEIGHBORS = "show bgp vrf all neighbors | json"


def bgp_sessions_command(raw: dict[str, Any]) -> str:
    """The session-table command that this payload is read from. It is
    CMD_BGP_SESSIONS_DEFAULT_VRF when the payload holds that command and holds
    no CMD_BGP_SESSIONS or a CMD_BGP_SESSIONS whose recorded outcome is not
    `ok`. Otherwise it is CMD_BGP_SESSIONS."""
    if CMD_BGP_SESSIONS_DEFAULT_VRF not in raw:
        return CMD_BGP_SESSIONS
    if CMD_BGP_SESSIONS not in raw:
        return CMD_BGP_SESSIONS_DEFAULT_VRF
    outcome = effective_outcomes(raw, {}).get(CMD_BGP_SESSIONS)
    return CMD_BGP_SESSIONS if outcome is None or outcome.status == "ok" else CMD_BGP_SESSIONS_DEFAULT_VRF


# The 3 directions of a session, with the per-neighbor command keyword, the
# RIB type and the policy stage of each. `received` needs
# `soft-reconfiguration inbound` on the neighbor. Without it NX-OS does not
# retain the pre-policy table and refuses the command. The refusal is recorded
# as a `not-captured` direction.
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

# Every command of this collector asks for `ipv4 unicast`.
BGP_SAFI = "unicast"
# The address family of the per-neighbor path commands, in the spelling of the
# running-config under a neighbor block.
IPV4_UNICAST = "ipv4 unicast"


# NX-OS refuses `received-routes` for a neighbor without `soft-reconfiguration
# inbound`, with a non-zero exit and this phrase on standard output.
_SOFT_RECONFIG_RE = re.compile(r"soft[- ]reconfiguration", re.IGNORECASE)
# On an exec channel with `| json native`, NX-OS refuses `received-routes` with
# exit status 244 and this line alone when it keeps no pre-policy table for the
# neighbor. This happens when the session is shut down or not up, or when
# `soft-reconfiguration inbound` is set without `always` and the peer can
# refresh its routes.
_CMD_EXEC_ERROR_RE = re.compile(r"\bCmd exec error\b")


def _received_not_retained(command: str, detail: str) -> bool:
    """True when a failed command is a `received-routes` table that the device
    refused with `_CMD_EXEC_ERROR_RE`. The device does not retain such a table.
    The refusal is a limit of its configuration."""
    received = command.endswith(f" {BGP_DIRECTION_KEYWORDS['received']} | json")
    return received and _CMD_EXEC_ERROR_RE.search(detail) is not None


def bgp_route_command(vrf: str, peer_ip: str, direction: str) -> str:
    """The per-neighbor path command for one direction, in the form
    `show bgp [vrf <vrf>] ipv4 unicast neighbors <peer> received-routes|routes|
    advertised-routes | json`. The VRF clause is omitted for the default table."""
    scope = "" if not vrf or vrf == DEFAULT_VRF else f"vrf {vrf} "
    return f"show bgp {scope}ipv4 unicast neighbors {peer_ip} {BGP_DIRECTION_KEYWORDS[direction]} | json"


# The pattern matches every raw key that the BGP path capture derives per
# fetch. Each key is the path command of one peer and one direction
# (`bgp_route_command`). No other command of this collector matches the
# pattern.
BGP_OBSERVATION_KEY_RE = re.compile(
    r"show bgp (?:vrf \S+ )?ipv4 unicast neighbors \S+ (?:"
    + "|".join(map(re.escape, BGP_DIRECTION_KEYWORDS.values()))
    + r") \| json"
)


COMMANDS: tuple[str, ...] = (
    CMD_VERSION,
    CMD_INTERFACE,
    CMD_LLDP,
    CMD_CDP,
    CMD_VLAN,
    CMD_VRF,
    CMD_ROUTE,
    CMD_MAC,
    CMD_ARP,
    CMD_VRF_IF,
    CMD_NAT,
    CMD_ACL,
    CMD_BGP,
    CMD_RPM,
    CMD_INTERFACE_CONFIG,
    CMD_VLAN_FILTER,
    *OSPF_COMMANDS,
    CMD_TRUNK,
    CMD_HSRP,
    CMD_VRRP,
    CMD_VPC,
)

# The trunk membership section holds the VLAN ids of each port. Its rows go to
# the `vlan_ports` map of the intermediate shape, and the section declares no
# `rows_key`.
TRUNK_SECTIONS: dict[str, Section] = {
    "trunks": Section(CMD_TRUNK, None, "interface"),
}

# Every OSPF `| json` section is under `TABLE_ctx`/`ROW_ctx` with one context
# per process and VRF pair. It declares no `rows_key`.
OSPF_SECTIONS: dict[str, Section] = {
    "ospf": Section(CMD_OSPF, None, "ctx"),
    "ospf_interfaces": Section(CMD_OSPF_IF, None, "ctx"),
    "ospf_neighbors": Section(CMD_OSPF_NBR, None, "ctx"),
    "ospf_lsdb_router": Section(CMD_OSPF_DB_ROUTER, None, "ctx"),
    "ospf_lsdb_network": Section(CMD_OSPF_DB_NETWORK, None, "ctx"),
    "ospf_lsdb_summary": Section(CMD_OSPF_DB_SUMMARY, None, "ctx"),
    "ospf_lsdb_external": Section(CMD_OSPF_DB_EXTERNAL, None, "ctx"),
    "ospf_lsdb_nssa_external": Section(CMD_OSPF_DB_NSSA, None, "ctx"),
    "ospf_lsdb_asbr_summary": Section(CMD_OSPF_DB_ASBR_SUMMARY, None, "ctx"),
    "ospf_config": Section(CMD_OSPF_CONFIG),
}

# Each section name maps to its command, the list of the intermediate shape
# for its rows, and the `TABLE_<table>` wrapper of those rows. A payload with
# the wrapper and no rows is an empty table. A payload without the wrapper is
# a malformed answer. `_rows` returns [] for both. A section whose command has
# no JSON rendering declares no table. Such a section is judged by whether the
# extract has any text.
SECTIONS: dict[str, Section] = {
    "device": Section(CMD_VERSION),
    "interfaces": Section(CMD_INTERFACE, "interfaces", "interface"),
    "vrf_interfaces": Section(CMD_VRF_IF, None, "if"),
    # These sections declare no `rows_key`. The LLDP and CDP rows share the
    # `neighbors` list of the intermediate shape. Each section counts the rows
    # of its own `TABLE_` wrapper.
    "neighbors": Section(CMD_LLDP, None, "nbor_detail"),
    "cdp": Section(CMD_CDP, None, "cdp_neighbor_brief_info"),
    "vlans": Section(CMD_VLAN, "vlans", "vlanbrief"),
    "vrfs": Section(CMD_VRF, "vrfs", "vrf"),
    "rib": Section(CMD_ROUTE, "rib", "vrf"),
    "mac_table": Section(CMD_MAC, "mac_table", "mac_address"),
    "arp": Section(CMD_ARP, "arp", "vrf"),
    "nat": Section(CMD_NAT),
    "acl": Section(CMD_ACL, None, "ip_ipv6_mac"),
    "bgp": Section(CMD_BGP),
    "route_maps": Section(CMD_RPM),
    "prefix_lists": Section(CMD_RPM),
    "interface_config": Section(CMD_INTERFACE_CONFIG),
    "vlan_filter": Section(CMD_VLAN_FILTER),
    **OSPF_SECTIONS,
    **TRUNK_SECTIONS,
    # These sections declare no `rows_key`. The HSRP and VRRP rows share the
    # `fhrp` list of the intermediate shape. Each section counts the rows of
    # its own `TABLE_` wrapper. A configured vPC domain always has a
    # `TABLE_peerlink` wrapper.
    "hsrp": Section(CMD_HSRP, None, "grp_detail"),
    "vrrp": Section(CMD_VRRP, None, "vrrp_group"),
    "vpc": Section(CMD_VPC, None, "peerlink"),
}

_VLAN_RE = re.compile(r"\d+")
# A port list entry that ends in a numeric range. `Ethernet1/3-4` expands to
# Ethernet1/3 and Ethernet1/4. The stem holds every character before the low
# number of the range. `Eth1/1/3-4` expands on its last element alone.
_PORT_RANGE_RE = re.compile(r"^(?P<stem>.*?)(?P<lo>\d+)-(?P<hi>\d+)$")
_VLAN_RANGE_RE = re.compile(r"^(?P<lo>\d+)(?:-(?P<hi>\d+))?$")
# Trunk allowed-list spellings that mean every VLAN.
_ALL_VLANS = {"all", "1-4094", "1-4093"}
# The highest VLAN id of an expanded range. An allowed list of `1-4094` covers
# every VLAN and is intersected with the existing VLANs.
_MAX_VID = 4094


def expand_port_list(text: Any) -> list[str]:
    """Expands `Ethernet1/1,Ethernet1/3-4,port-channel10` to one name per port.

    FIRST CONTACT: `show vlan | json` has the member port list of each VLAN
    in `vlanshowplist-ifidx`. The list is a comma-separated string with dash
    ranges on the last number. A range whose low end exceeds its high end is
    dropped. A value that is not a string gives an empty list.
    """
    if not isinstance(text, str):
        return []
    out: list[str] = []
    for item in (part.strip() for part in text.split(",")):
        if not item:
            continue
        m = _PORT_RANGE_RE.match(item)
        if m is None:
            out.append(item)
            continue
        lo, hi = int(m["lo"]), int(m["hi"])
        if lo > hi:
            continue
        out.extend(f"{m['stem']}{n}" for n in range(lo, hi + 1))
    return out


def expand_vlan_list(text: Any, existing: set[int]) -> list[int]:
    """Expands `10,20,30-40` to the listed VLAN ids that exist on the device."""
    if not isinstance(text, str):
        return []
    lowered = text.strip().lower()
    if lowered in _ALL_VLANS:
        return sorted(existing)
    if lowered in {"none", ""}:
        return []
    vids: set[int] = set()
    for item in (part.strip() for part in text.split(",")):
        m = _VLAN_RANGE_RE.match(item)
        if m is None:
            continue
        lo = int(m["lo"])
        hi = int(m["hi"]) if m["hi"] else lo
        if lo > hi or hi > _MAX_VID:
            continue
        vids.update(v for v in range(lo, hi + 1) if v in existing)
    return sorted(vids)


def parse_vlan_ports(vlan_payload: dict[str, Any], trunk_payload: dict[str, Any]) -> dict[int, list[str]]:
    """The trunk membership map `{vid: [port names]}` from 2 sources. The
    first source is the member port list of each VLAN row in
    `show vlan | json`. The second source is the allowed list of each trunk in
    `show interface trunk | json`, when the device answered it. A port in
    either source carries the VLAN.

    FIRST CONTACT: the `ROW_vlanbrief` rows have `vlanshowplist-ifidx`, with
    `vlanshowplist` as the fallback spelling. The trunk table has the
    `TABLE_allowed_vlans`/`ROW_allowed_vlans` wrapper with `interface` and
    `allowedvlans`.
    """
    members: dict[int, set[str]] = {}
    existing: set[int] = set()
    for row in _rows(vlan_payload, "vlanbrief"):
        try:
            vid = int(row["vlanshowbr-vlanid"])
        except (KeyError, TypeError, ValueError):
            continue
        existing.add(vid)
        plist = row.get("vlanshowplist-ifidx")
        if plist is None:
            plist = row.get("vlanshowplist")
        for port in expand_port_list(plist):
            members.setdefault(vid, set()).add(port)
    for row in _rows(trunk_payload, "allowed_vlans"):
        port = row.get("interface")
        if not isinstance(port, str) or not port:
            continue
        for vid in expand_vlan_list(row.get("allowedvlans"), existing):
            members.setdefault(vid, set()).add(port)
    return {vid: sorted(ports) for vid, ports in sorted(members.items()) if ports}


# The helpers below decode the text between the bounds of `text.strip()` without a copy.
#
# `\s` in a str pattern and `str.strip` use the same definition of whitespace
# (`str.isspace`). The stripped text starts at the first `\S`.
_NON_SPACE = re.compile(r"\S")
# Every character `str.splitlines` ends a line at ("\r\n" ends at its "\r").
_LINE_BREAK = re.compile("[\n\r\x0b\x0c\x1c-\x1e\x85\u2028\u2029]")
# The whitespace that JSON allows around a value. `json.loads` skips exactly
# this set. The pattern equals `json.decoder.WHITESPACE`.
_JSON_WHITESPACE = re.compile(r"[ \t\n\r]*")
_DECODER = json.JSONDecoder()
# The string reader of the decoder. `JSONDecoder` reads every key with it.
_scanstring = json.decoder.scanstring


def _content_span(text: str) -> tuple[int, int] | None:
    """`(start, end)` with `text[start:end] == text.strip()`, or None when the
    stripped text is empty. The function makes no copy of the text."""
    match = _NON_SPACE.search(text)
    if match is None:
        return None
    end = len(text)
    # The loop stops at `match.start()` at the latest. That character is not whitespace.
    while text[end - 1].isspace():
        end -= 1
    return match.start(), end


def _first_line(text: str, start: int, end: int) -> str:
    """`text[start:end].splitlines()[0]` for a non-empty span, without
    splitting the span."""
    match = _LINE_BREAK.search(text, start, end)
    return text[start : match.start() if match else end]


def _decode_span(text: str, start: int, end: int) -> Any:
    """`json.loads(text[start:end])` for a span that `_content_span` returned,
    without the slice. The function raises ValueError in the same cases as
    `json.loads`. The positions in the error count from the start of `text`.

    The value ends at or before `end`. It ends on a character that is not
    whitespace, and every character from `end` on is whitespace. The text
    between the value and `end` must be JSON whitespace. Any other text there
    is the extra data that `json.loads` rejects."""
    value, stop = _DECODER.raw_decode(text, start)
    if _JSON_WHITESPACE.match(text, stop, end).end() != end:
        raise json.JSONDecodeError("Extra data", text, stop)
    return value


def _json_payload(text: Any, command: str) -> dict[str, Any]:
    """The object that a `| json` command answered with, or `{}` for no answer.

    NX-OS prints no text when a `| json` command has no rows. Text that is not
    JSON raises for a required command. For an optional command within
    `cli_parse.tolerating`, the error is recorded and the answer reads as no
    rows. This degrades the section of that command alone
    (`cli_collector.effective_outcomes`).

    The answer is read in place with the result of
    `json.loads(text.strip())` (`_content_span`, `_decode_span`). A full-table
    answer is not copied.
    """
    if not isinstance(text, str):
        text = str(text or "")
    span = _content_span(text)
    if span is None:
        return {}
    start, end = span
    try:
        payload = _decode_span(text, start, end)
    except ValueError as exc:
        error = _not_json(command, text, start, end)
        if cli_parse.tolerated(command, str(error)):
            logger.warning("nxos: %s; continuing without its rows", error)
            return {}
        raise error from exc
    return payload if isinstance(payload, dict) else {}


def _not_json(command: str, text: str, start: int, end: int) -> ValueError:
    """The error for an answer that is not JSON. The message holds the command
    and the first line of the stripped answer `text[start:end]`."""
    head = _first_line(text, start, min(end, start + 120))
    return ValueError(f"{command!r} answered with text that is not JSON: {head!r}")


def cdp_off_note(text: Any) -> str | None:
    """The note the CDP command answered with on a box that runs no CDP, or
    None for any other answer (`_CDP_OFF_RE`)."""
    m = _CDP_OFF_RE.fullmatch(text) if isinstance(text, str) else None
    return m.group(1) if m else None


def _rows(payload: dict[str, Any], table: str) -> list[dict]:
    """Unwraps the NX-OS `TABLE_<table>`/`ROW_<table>` nesting.

    `ROW_<table>` is a dict when the table has one row.
    """
    rows = (payload.get(f"TABLE_{table}") or {}).get(f"ROW_{table}")
    if rows is None:
        return []
    if isinstance(rows, dict):
        return [rows]
    return rows


# The code below reads a `| json` answer in pieces. `_Scan` walks the route
# table and the path tables of a full-table peer in place. The walk reads the
# `TABLE_`/`ROW_` wrappers above the prefix rows one key at a time. It decodes
# each prefix row alone, builds its records and drops the row before the next
# row. The walk decodes and drops every value that it does not descend into.
# Between values it reads the grammar and the whitespace of JSON. It raises
# ValueError on exactly the text that `json.loads` rejects.
#
# The walk yields the records of `_rows` over the decoded tree, in the same
# order, when each followed wrapper occurs once in its object and every
# wrapper and row on the path is an object. Every other shape raises
# `_Irregular`. These shapes are a repeated wrapper (the tree keeps the last
# one), a row that is not an object, a prefix row that the record code fails
# on, and prefixes of a sub-family row before the route-distinguisher rows
# that replace them. The caller then decodes that answer whole and reads its
# rows from the tree (`_rows`). No known NX-OS release prints any of these
# shapes.


class _Irregular(Exception):
    """The answer has a shape for which the piecewise walk and the decoded
    tree give different rows."""


class _Scan:
    """A position in the text of one answer. It moves forward one JSON value
    at a time."""

    __slots__ = ("pos", "text")

    def __init__(self, text: str, pos: int) -> None:
        self.text = text
        self.pos = pos

    def at(self, prefix: str) -> bool:
        """Whether the text at the position starts with `prefix`."""
        return self.text.startswith(prefix, self.pos)

    def value(self) -> Any:
        """The decoded value at the position. The position moves past the value."""
        value, self.pos = _DECODER.raw_decode(self.text, self.pos)
        return value

    def members(self) -> Iterator[str]:
        """The keys of the object at the position, in order.

        At each key the position is at the value of the key. The caller reads
        the value (with `value` or with its own walk) before it asks for the
        next key. After the last key the position is past the object."""
        text = self.text
        space = _JSON_WHITESPACE.match
        pos = space(text, self.pos + 1).end()
        if text.startswith("}", pos):
            self.pos = pos + 1
            return
        while True:
            if not text.startswith('"', pos):
                raise json.JSONDecodeError("Expecting property name enclosed in double quotes", text, pos)
            key, pos = _scanstring(text, pos + 1, True)
            pos = space(text, pos).end()
            if not text.startswith(":", pos):
                raise json.JSONDecodeError("Expecting ':' delimiter", text, pos)
            self.pos = space(text, pos + 1).end()
            yield key
            pos = space(text, self.pos).end()
            if text.startswith("}", pos):
                self.pos = pos + 1
                return
            if not text.startswith(",", pos):
                raise json.JSONDecodeError("Expecting ',' delimiter", text, pos)
            pos = space(text, pos + 1).end()

    def elements(self) -> Iterator[None]:
        """Yields once at each element of the array at the position, with the
        position at the element."""
        text = self.text
        space = _JSON_WHITESPACE.match
        pos = space(text, self.pos + 1).end()
        if text.startswith("]", pos):
            self.pos = pos + 1
            return
        while True:
            self.pos = pos
            yield
            pos = space(text, self.pos).end()
            if text.startswith("]", pos):
                self.pos = pos + 1
                return
            if not text.startswith(",", pos):
                raise json.JSONDecodeError("Expecting ',' delimiter", text, pos)
            pos = space(text, pos + 1).end()


def _member(scan: _Scan, name: str) -> Iterator[None]:
    """Yields once at the value of the key `name` of the object at the scan,
    when the object has that key. Every other value is decoded and dropped. A
    second key `name` raises `_Irregular`."""
    found = False
    for key in scan.members():
        if key != name:
            scan.value()
        elif found:
            raise _Irregular
        else:
            found = True
            yield


def _table_rows(scan: _Scan, table: str) -> Iterator[None]:
    """Yields once at each row that `_rows` reads from the `TABLE_<table>`
    value at the scan. The rows are a single row object or each object of a
    row array. A null `ROW_<table>` and a table without `ROW_<table>` yield no
    row. Any other shape raises `_Irregular`."""
    if not scan.at("{"):
        raise _Irregular
    for _ in _member(scan, f"ROW_{table}"):
        if scan.at("{"):
            yield
        elif scan.at("["):
            for _ in scan.elements():
                if not scan.at("{"):
                    raise _Irregular
                yield
        elif scan.at("null"):
            scan.value()
        else:
            raise _Irregular


def _piece(records: Iterator[dict[str, Any]]) -> list[dict[str, Any]]:
    """The records of one decoded prefix row. A row that the record code fails
    on raises `_Irregular`. The tree reader fails on such a row after it has
    decoded the whole answer as JSON."""
    try:
        return list(records)
    except (AttributeError, TypeError) as exc:
        raise _Irregular from exc


def _value_end(scan: _Scan, end: int) -> None:
    """Raises the extra-data error of `json.loads` when the text between the
    value that the scan read and `end` is not JSON whitespace, like
    `_decode_span`."""
    if _JSON_WHITESPACE.match(scan.text, scan.pos, end).end() != end:
        raise json.JSONDecodeError("Extra data", scan.text, scan.pos)


def _kind(name: str) -> str:
    # a dotted name is a subinterface of any parent kind
    if "." in name:
        return "subif"
    n = name.lower()
    if n.startswith("vlan"):
        return "svi"
    if n.startswith("loopback"):
        return "loopback"
    if n.startswith("port-channel"):
        return "lag"
    if n.startswith("mgmt"):
        return "mgmt"
    return "phys"


def _admin_up(row: dict) -> bool:
    # The field name depends on the interface type (physical or SVI). The first field with
    # a value is used.
    for key in ("admin_state", "svi_admin_state", "state", "svi_line_proto"):
        val = row.get(key)
        if val is not None:
            return val == "up"
    return False


def _interface_ips(row: dict) -> list[dict]:
    if row.get("eth_ip_addr") and row.get("eth_ip_mask") is not None:
        return [{"ip": row["eth_ip_addr"], "prefixlen": int(row["eth_ip_mask"]), "vrf": ""}]
    if row.get("svi_ip_addr") and row.get("svi_ip_mask") is not None:
        return [{"ip": row["svi_ip_addr"], "prefixlen": int(row["svi_ip_mask"]), "vrf": ""}]
    return []


def _if_vrf_map(payload: dict[str, Any], resolve: IfNameResolver) -> dict[str, str]:
    """Maps each interface slug to its VRF name from `TABLE_if/ROW_if` of
    `show vrf interface`. The "default" VRF is stored as `""`, as in
    `cisco_common.normalize_cisco`. `resolve` resolves each name against the
    interface table before the slug is built. A caller looks up an interface
    by `resolve.slug`."""
    out: dict[str, str] = {}
    for row in _rows(payload, "if"):
        name = row.get("if_name")
        if not name:
            continue
        vrf = row.get("vrf_name") or ""
        out[resolve.slug(name)] = "" if vrf == "default" else vrf
    return out


def _ace_side(row: dict, p: str) -> str | None:
    """One side of an NX-OS ACE row. The result is `any`, a host (from a /32
    prefix) or a cidr. The result is None when the row has no address for the
    side (object-groups, addrgroups)."""
    if row.get(f"{p}_any"):
        return "any"
    val = row.get(f"{p}_ip_prefix")
    if not val:
        return None
    return val.removesuffix("/32")


def _acl_records(payload: dict[str, Any]) -> dict[str, list[dict]]:
    """Converts `show ip access-lists | json` to the shared ACE shape that
    `resolve_acl_sources` reads. An ACL with no parseable ACE maps to an empty
    list."""
    out: dict[str, list[dict]] = {}
    for row in _rows(payload, "ip_ipv6_mac"):
        name = row.get("acl_name")
        if not name:
            continue
        aces = out.setdefault(name, [])
        for seq in _rows(row, "seqno"):
            action = seq.get("permitdeny")
            if not action:
                continue
            aces.append({"action": action, "src": _ace_side(seq, "src"), "dst": _ace_side(seq, "dest")})
    return out


# Protocol keywords that name every protocol.
_ANY_PROTOCOLS = {"ip", "ipv4", "0"}

# The `op` column of a `show ip access-lists | json` row holds the table of
# the access list. The IPv4 table alone is modeled. The interface-ACL
# rulebases have af=4. A row with no `op` is read as the IPv4 table.
_IPV4_ACL_OPS = {"ip", "ipv4", ""}

# The NX-OS ACE columns beyond the address pair.
_NXOS_SIDE_GROUP_KEY = "addrgrp"

# The columns of a `seqno` row that the ACE conversion handles. They are the
# columns that it reads, `ip` (the any-protocol keyword that a row can have in
# place of `proto`), and the columns that it drops (`seqno`, `remark`, `log`,
# `match_count`). The dropped columns do not narrow a match. A row with any
# other column (`dscp`, `precedence`, `fragments`, a packet length, a TTL)
# makes the ACE undecided (`unmodeled_ace_fields`).
_ACE_ROW_FIELDS = frozenset(
    {"seqno", "permitdeny", "proto", "proto_str", "ip", "remark", "established", "log", "timerange"}
    | {"icmp_type", "icmp_str", "port_grp", "match_count"}
    | {
        f"{side}_{column}"
        for side in ("src", "dest")
        for column in (
            "any",
            "ip_prefix",
            "addrgrp",
            "port_op",
            "port1_num",
            "port1_str",
            "port2_num",
            "port2_str",
        )
    }
)


def _ace_filter_side(row: dict, p: str) -> dict[str, Any]:
    """One side of an NX-OS ACE row for the interface-ACL rulebase.

    Returns the `<side>_any`, `<side>` and `<side>_opaque_reason` fields of the
    shared ACE shape that `cisco_common.acl_stage` reads. The fields use the
    `src` and `dst` names of that shape (NX-OS spells the destination `dest`).
    An address group gives a reason in place of an address.
    """
    name = "src" if p == "src" else "dst"
    if row.get(f"{p}_any"):
        return {f"{name}_any": True, name: None, f"{name}_opaque_reason": None}
    val = row.get(f"{p}_ip_prefix")
    if val:
        host = val.removesuffix("/32")
        return {f"{name}_any": False, name: host, f"{name}_opaque_reason": None}
    group = row.get(f"{p}_{_NXOS_SIDE_GROUP_KEY}")
    if group:
        return {
            f"{name}_any": False,
            name: None,
            f"{name}_opaque_reason": f"the ACE matches address-group {group!r}, which is not collected",
            f"{name}_opaque_note": f"address-group {group} not collected",
        }
    return {f"{name}_any": False, name: None, f"{name}_opaque_reason": None}


def _ace_filter_service(row: dict) -> dict[str, Any]:
    """The service fields of an NX-OS ACE row. They are the protocol, the ports
    and the opaque reason for a clause outside both. NX-OS prints the number of
    a port keyword beside the keyword (`dest_port1_num` 179 beside
    `dest_port1_str` bgp). A keyword with no number is resolved through the
    keyword table of the protocol of the row."""
    proto = str(row.get("proto_str") or row.get("proto") or "").lower() or None
    if proto in _ANY_PROTOCOLS:
        proto = None
    ports, why, note = ace_port_clause(
        row.get("dest_port_op"),
        row.get("dest_port1_num") or row.get("dest_port1_str"),
        row.get("dest_port2_num") or row.get("dest_port2_str"),
        proto=proto,
    )
    src_port, src_why, src_note = ace_port_clause(
        row.get("src_port_op"),
        row.get("src_port1_num") or row.get("src_port1_str"),
        row.get("src_port2_num") or row.get("src_port2_str"),
        proto=proto,
    )
    group = row.get("port_grp")
    if group:
        why = f"the ACE matches port-group {group!r}, which is not collected"
        note = f"port-group {group} not collected"
    out: dict[str, Any] = {
        "proto": proto,
        "ports": ports,
        "src_port": src_port,
        "svc_opaque_reason": why or src_why,
    }
    if why or src_why:
        out["svc_opaque_note"] = note if why else f"src {src_note}"
    return out


def _acl_filter_records(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Converts `show ip access-lists | json` to the interface-ACL ACE shape.

    An access list with no parseable ACE maps to an empty list.

    `log` is dropped with no marker.
    """
    out: dict[str, list[dict[str, Any]]] = {}
    for row in _rows(payload, "ip_ipv6_mac"):
        name = row.get("acl_name")
        if not name or str(row.get("op") or "").lower() not in _IPV4_ACL_OPS:
            continue
        aces = out.setdefault(name, [])
        for seq in _rows(row, "seqno"):
            action = seq.get("permitdeny")
            if not action:
                continue
            # The ICMP type is `icmp_str` (`echo`, `echo-reply`) or `icmp_type`.
            ace = {
                "action": action,
                **_ace_filter_side(seq, "src"),
                **_ace_filter_side(seq, "dest"),
                **_ace_filter_service(seq),
                **ace_qualifiers(
                    icmp_type=seq.get("icmp_str") or seq.get("icmp_type"),
                    time_range=seq.get("timerange"),
                    unmodeled=unmodeled_ace_fields(seq, _ACE_ROW_FIELDS),
                ),
            }
            if seq.get("established"):
                ace["states"] = ["established"]
            aces.append(ace)
    return out


# --- BGP / route-map / prefix-list: plain-text config parse -----------------------------
#
# `show running-config bgp` and `show running-config rpm` return indented
# Cisco-style config text. The parse covers the BGP process (global and per
# VRF), the neighbor policy attachments of ipv4 unicast, `ip prefix-list`,
# `route-map` (match, set, continue) and 5 redistribution protocols (rip,
# static, direct, ospf, eigrp).

# A node is (line_text, children). `children` is a list of nodes.
ConfigNode = tuple[str, list]


def _config_tree(lines: list[str]) -> list[ConfigNode]:
    """Converts indented config text to a tree of (line, children) pairs with
    one level per indent step. Blank lines and `!` comment lines are dropped."""
    root: list[ConfigNode] = []
    stack: list[tuple[int, list]] = [(-1, root)]
    for raw in lines:
        if not raw.strip() or raw.strip().startswith("!"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        text = raw.strip()
        while indent <= stack[-1][0]:
            stack.pop()
        node: ConfigNode = (text, [])
        stack[-1][1].append(node)
        stack.append((indent, node[1]))
    return root


_AGGREGATE_RE = re.compile(r"^aggregate-address\s+(?P<prefix>\S+)(?:\s+(?P<options>.*))?$")
_ROUTE_MAP_DIR_RE = re.compile(r"^(route-map|prefix-list|filter-list)\s+(\S+)\s+(in|out)$")
# The neighbor dict key of each attachment kind. The full key is `<key>_<direction>`.
_ATTACHMENT_KEYS = {"route-map": "route_map", "prefix-list": "prefix_list", "filter-list": "filter_list"}

REDIST_PROTOCOLS: tuple[str, ...] = ("rip", "static", "direct", "ospf", "eigrp")


def _new_bgp_process(asn: int, vrf: str | None) -> dict[str, Any]:
    return {
        "asn": asn,
        "vrf": vrf,
        "router_id": None,
        "neighbors": [],
        "redistribute": [],
        "networks": [],
        "aggregates": [],
        "origin_context_gaps": [],
    }


def _parse_af_process(children: list[ConfigNode], proc: dict[str, Any], af: int = 4) -> None:
    """Parses an `address-family ipv4 unicast` or `address-family ipv6 unicast`
    block directly under `router bgp` or `vrf`. It reads the configured
    networks, aggregates, redistributions and `maximum-paths`, and whether
    `default-information originate` is set."""
    for line, _sub in children:
        if line == "default-information originate":
            afs = proc.setdefault("default_information_originate_afs", [])
            if af not in afs:
                afs.append(af)
        elif parsed_paths := parse_maximum_paths(line):
            # The `maximum-paths` of the family is keyed by `<type>_v<family>`.
            for kind, count in parsed_paths:
                proc.setdefault("maximum_paths", {})[f"{kind}_v{af}"] = count
        elif line.startswith("network "):
            tokens = line.split()
            prefix = tokens[1]
            if len(tokens) >= 4 and tokens[2] == "mask":
                prefix = str(ipaddress.ip_network(f"{prefix}/{tokens[3]}", strict=False))
            route_map = tokens[tokens.index("route-map") + 1] if "route-map" in tokens else None
            proc["networks"].append({"prefix": prefix, "route_map": route_map})
        elif m := _AGGREGATE_RE.match(line):
            options = (m["options"] or "").split()
            prefix = m["prefix"]
            if options and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", options[0]):
                prefix = str(ipaddress.ip_network(f"{prefix}/{options.pop(0)}", strict=False))
            recorded, gap = parse_aggregate_options(prefix, options)
            if gap:
                proc["origin_context_gaps"].append(gap)
            proc["aggregates"].append(recorded)
        elif line.startswith("redistribute "):
            tokens = line.split()
            protocol = tokens[1]
            route_map = tokens[tokens.index("route-map") + 1] if "route-map" in tokens else None
            entry: dict[str, Any] = {"protocol": protocol, "route_map": route_map}
            # The entry has the instance tag (`redistribute ospf 2 route-map B`)
            # when the line has one. The entry has the address family when it
            # is not IPv4.
            if len(tokens) > 2 and tokens[2] != "route-map":
                entry["tag"] = tokens[2]
            if af != 4:
                entry["af"] = af
            proc["redistribute"].append(entry)


def _parse_neighbor(line: str, children: list[ConfigNode]) -> dict[str, Any]:
    """Parses a neighbor block. The neighbor is a configured address or a
    passive range. Observations expand a range into peers."""
    peer_ip = line.split()[1]
    n: dict[str, Any] = {
        "peer_ip": peer_ip,
        "remote_as": None,
        "shutdown": False,
        # Every `address-family <afi> <safi>` that the neighbor block activates,
        # in configuration order. The list is empty for a block that activates
        # none.
        "address_families": [],
        "route_map_in": None,
        "route_map_out": None,
        "prefix_list_in": None,
        "prefix_list_out": None,
        # `filter_list_in`, `filter_list_out` (an AS-path filter-list) and
        # `route_reflector_client` are set when the block has them.
    }
    for cline, csub in children:
        if cline.startswith(("inherit peer ", "inherit peer-session ", "inherit peer-policy ")):
            tokens = cline.split()
            n.setdefault("peer_templates", []).append(
                (tokens[1], tokens[2], int(tokens[3]) if len(tokens) > 3 else 0)
            )
        elif cline.startswith("remote-as "):
            if cline.startswith("remote-as route-map "):
                n["remote_as_route_map"] = cline.split()[2]
            else:
                n["remote_as"] = parse_asn(cline.split()[1])
                if n["remote_as"] is None:
                    n["remote_as_unread"] = cline.split()[1]
        elif cline == "shutdown":
            n["shutdown"] = True
        elif cline.startswith("address-family "):
            family = " ".join(cline.split()[1:3])
            if family not in n["address_families"]:
                n["address_families"].append(family)
            if family != IPV4_UNICAST:
                continue
            for aline, _asub in csub:
                if aline == "next-hop-self" or aline.startswith("next-hop-self "):
                    n["next_hop_self"] = "all" if aline.split()[1:2] == ["all"] else "ebgp"
                    continue
                if aline.startswith("inherit peer-policy "):
                    tokens = aline.split()
                    n.setdefault("peer_templates", []).append(
                        ("peer-policy", tokens[2], int(tokens[3]) if len(tokens) > 3 else 0)
                    )
                    continue
                if aline == "route-reflector-client":
                    n["route_reflector_client"] = True
                    continue
                m = _ROUTE_MAP_DIR_RE.match(aline)
                if not m:
                    continue
                kind, name, direction = m.group(1), m.group(2), m.group(3)
                n[f"{_ATTACHMENT_KEYS[kind]}_{direction}"] = name
        # A peer-policy template is already an address-family body.
        elif cline == "route-reflector-client":
            n["route_reflector_client"] = True
        elif cline == "next-hop-self" or cline.startswith("next-hop-self "):
            n["next_hop_self"] = "all" if cline.split()[1:2] == ["all"] else "ebgp"
        elif m := _ROUTE_MAP_DIR_RE.match(cline):
            kind, name, direction = m.groups()
            n[f"{_ATTACHMENT_KEYS[kind]}_{direction}"] = name
    return n


def parse_bgp_config(text: str) -> list[dict[str, Any]]:
    """Parses `show running-config bgp` to one dict per BGP process. The
    default VRF has one dict (`vrf: None`, from the config directly under
    `router bgp`). Each `vrf <name>` sub-block has one dict. A device with no
    `router bgp` stanza gives an empty list. This covers a device without BGP
    config and a device with `feature bgp` disabled."""
    processes: list[dict[str, Any]] = []
    for line, children in _config_tree(text.splitlines()):
        m = re.match(r"^router bgp (\S+)$", line)
        asn = parse_asn(m.group(1)) if m else None
        if asn is None:
            continue
        templates = {
            tuple(cline.split()[1:3]): _parse_neighbor("neighbor template", csub)
            for cline, csub in children
            if cline.startswith(("template peer ", "template peer-session ", "template peer-policy "))
        }
        default_proc = _new_bgp_process(asn, None)
        for cline, csub in children:
            if cline.startswith("router-id "):
                default_proc["router_id"] = cline.split()[1]
            elif cline.startswith("cluster-id "):
                default_proc["cluster_id"] = parse_cluster_id(cline.split()[1])
            elif cline == "bestpath always-compare-med":
                default_proc["always_compare_med"] = True
            elif cline == "bestpath as-path multipath-relax":
                default_proc["multipath_relax"] = True
            elif cline.startswith(("address-family ipv4 unicast", "address-family ipv6 unicast")):
                _parse_af_process(csub, default_proc, 4 if cline.startswith("address-family ipv4") else 6)
            elif cline.startswith("neighbor "):
                default_proc["neighbors"].append(
                    inherit_peer_templates(_parse_neighbor(cline, csub), templates)
                )
            elif (vm := re.match(r"^vrf (\S+)$", cline)) is not None:
                vrf_proc = _new_bgp_process(asn, vm.group(1))
                for vline, vsub in csub:
                    if vline.startswith("router-id "):
                        vrf_proc["router_id"] = vline.split()[1]
                    elif vline.startswith("cluster-id "):
                        vrf_proc["cluster_id"] = parse_cluster_id(vline.split()[1])
                    elif vline == "bestpath always-compare-med":
                        vrf_proc["always_compare_med"] = True
                    elif vline == "bestpath as-path multipath-relax":
                        vrf_proc["multipath_relax"] = True
                    elif vline.startswith(("address-family ipv4 unicast", "address-family ipv6 unicast")):
                        _parse_af_process(vsub, vrf_proc, 4 if vline.startswith("address-family ipv4") else 6)
                    elif vline.startswith("neighbor "):
                        vrf_proc["neighbors"].append(
                            inherit_peer_templates(_parse_neighbor(vline, vsub), templates)
                        )
                processes.append(vrf_proc)
        processes.append(default_proc)
    return processes


def _new_route_map_clause(action: str, seq: int) -> dict[str, Any]:
    return {
        "seq": seq,
        "action": action,
        "continue_seq": None,
        "match_prefix_lists": [],
        "match_as_path_lists": [],
        "match_community_lists": [],
        "match_tags": [],
        "match_metric": None,
        "set_local_pref": None,
        "set_metric": None,
        "set_origin": None,
        "set_tag": None,
        "set_weight": None,
        "set_next_hop": None,
        "set_as_path_prepend": [],
        "set_communities": [],
        "set_communities_additive": False,
        "set_comm_list_delete": None,
        "calls_policy": None,
    }


# Match lines NX-OS applies to policy-based routing only.
# Route filtering and redistribution ignore them (`BooleanExprs.TRUE`).
_PBR_ONLY_MATCH = re.compile(r"^match (?:as-number\b|vlan\b|ip(?:v6)? address (?!prefix-list\b))")


def _apply_route_map_line(clause: dict[str, Any], line: str) -> None:
    """Applies one indented line under a `route-map NAME {permit|deny} SEQ`
    clause. A match line that the platform documents for policy-based routing
    alone (`match ip address <acl>`, `match ipv6 address <acl>`, `match vlan`,
    `match as-number`) is kept in `match_ignored`. Route filtering ignores
    such a line, and it adds no condition. Any other unrecognized `match` line
    is kept verbatim in `match_unsupported`. An unrecognized `set` line (`set
    as-path prepend last-as`, `set ip next-hop unchanged`, `set community
    none`, `set metric-type`) is kept in `set_unsupported`. Any other
    unrecognized line is ignored."""
    if m := re.match(r"^continue (\d+)$", line):
        clause["continue_seq"] = int(m.group(1))
    elif m := re.match(r"^match ip address prefix-list (.+)$", line):
        clause["match_prefix_lists"].extend(m.group(1).split())
    elif m := re.match(r"^match as-path (.+)$", line):
        clause["match_as_path_lists"].extend(m.group(1).split())
    elif m := re.match(r"^match community (.+)$", line):
        clause["match_community_lists"].extend(m.group(1).split())
    elif m := re.match(r"^match tag (.+)$", line):
        clause["match_tags"].extend(int(t) for t in m.group(1).split())
    elif m := re.match(r"^match metric (\d+)$", line):
        clause["match_metric"] = int(m.group(1))
    elif m := re.match(r"^match source-protocol (\S+)$", line):
        clause.setdefault("match_protocols", []).append(m.group(1))
    elif _PBR_ONLY_MATCH.match(line):
        clause.setdefault("match_ignored", []).append(line)
    elif m := re.match(r"^set local-preference (\d+)$", line):
        clause["set_local_pref"] = int(m.group(1))
    elif m := re.match(r"^set metric (\d+)$", line):
        clause["set_metric"] = int(m.group(1))
    elif m := re.match(r"^set origin (igp|egp|incomplete)$", line):
        clause["set_origin"] = m.group(1)
    elif m := re.match(r"^set tag (\d+)$", line):
        clause["set_tag"] = int(m.group(1))
    elif m := re.match(r"^set weight (\d+)$", line):
        clause["set_weight"] = int(m.group(1))
    elif m := re.match(r"^set ip next-hop (\d+\.\d+\.\d+\.\d+)$", line):
        clause["set_next_hop"] = m.group(1)
    elif m := re.match(r"^set as-path prepend (\d+(?: \d+)*)$", line):
        clause["set_as_path_prepend"].extend(m.group(1).split())
    elif line.startswith("set community ") and line.split()[2:] != ["none"]:
        parts = line.split()[2:]
        clause["set_communities"].extend(p for p in parts if p != "additive")
        if "additive" in parts:
            clause["set_communities_additive"] = True
    elif m := re.match(r"^set comm-list (\S+) delete$", line):
        clause["set_comm_list_delete"] = m.group(1)
    elif m := re.match(r"^call (\S+)$", line):
        clause["calls_policy"] = m.group(1)
    elif line.startswith("match "):
        clause.setdefault("match_unsupported", []).append(line)
    elif line.startswith("set "):
        clause.setdefault("set_unsupported", []).append(line)


_COMMUNITY_LIST_RE = re.compile(
    r"^ip community-list (standard|expanded) (\S+)(?: seq (\d+))? (permit|deny) ?(.*)$"
)
_AS_PATH_LIST_RE = re.compile(r"^ip as-path access-list (\S+)(?: seq (\d+))? (permit|deny) (.+)$")


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return text[1:-1]
    return text


def parse_match_lists(text: str) -> list[dict[str, Any]]:
    """Parses the `ip community-list` and `ip as-path access-list` lines of
    `show running-config rpm` to `[{"name", "kind", "entries"}]`. `kind` is
    `community-list` or `as-path-list`. The entries of each list are sorted by
    `seq`. A `standard` community-list line holds communities, and a route must
    have all of them. An `expanded` community-list line and every AS-path line
    hold a regular expression that NX-OS prints in double quotes."""
    lists: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if m := _COMMUNITY_LIST_RE.match(line):
            kind, name = "community-list", m.group(2)
            value = " ".join(m.group(5).split()) if m.group(1) == "standard" else _unquote(m.group(5))
            entry = {"action": m.group(4), "match_type": m.group(1), "value": value, "seq": m.group(3)}
        elif m := _AS_PATH_LIST_RE.match(line):
            kind, name = "as-path-list", m.group(1)
            entry = {
                "action": m.group(3),
                "match_type": "expanded",
                "value": _unquote(m.group(4)),
                "seq": m.group(2),
            }
        else:
            if line.startswith(("ip community-list ", "ip as-path access-list ")):
                logger.warning("nxos: community or as-path list line not read, entry left out: %r", line)
            continue
        entries = lists.setdefault((kind, name), [])
        entry["seq"] = int(entry["seq"]) if entry["seq"] else (entries[-1]["seq"] + 1 if entries else 1)
        entries.append(entry)
    return [
        {"name": name, "kind": kind, "entries": sorted(entries, key=lambda e: e["seq"])}
        for (kind, name), entries in lists.items()
    ]


def parse_route_map_config(text: str) -> dict[str, list[dict[str, Any]]]:
    """Parses the `route-map` stanzas of `show running-config rpm` to
    {name: [clause, ...]}, sorted by `seq`."""
    maps: dict[str, list[dict[str, Any]]] = {}
    for line, children in _config_tree(text.splitlines()):
        m = re.match(r"^route-map (\S+) (permit|deny) (\d+)$", line)
        if not m:
            continue
        clause = _new_route_map_clause(m.group(2), int(m.group(3)))
        for cline, _csub in children:
            _apply_route_map_line(clause, cline)
        maps.setdefault(m.group(1), []).append(clause)
    for entries in maps.values():
        entries.sort(key=lambda e: e["seq"])
    return maps


_PREFIX_LIST_RE = re.compile(
    r"^ip prefix-list (?P<name>\S+) seq (?P<seq>\d+) (?P<action>permit|deny) (?P<prefix>\S+)"
    r"(?: eq (?P<eq>\d+))?(?: ge (?P<ge>\d+))?(?: le (?P<le>\d+))?$"
)


def parse_prefix_list_config(text: str) -> dict[str, list[dict[str, Any]]]:
    """Parses the `ip prefix-list` lines of `show running-config rpm` to
    {name: [entry, ...]}, sorted by `seq`. `min_len` and `max_len` resolve the
    combination of `eq`, `ge` and `le`. Without all 3 the range is the prefix
    length alone. `eq` gives (len, len). `ge` alone gives (low, 32). `le` alone
    gives (prefixlen, high). `ge` with `le` gives (low, high). Every entry has
    the `seq` of the NX-OS running-config."""
    lists: dict[str, list[dict[str, Any]]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        m = _PREFIX_LIST_RE.match(line)
        if not m:
            description = re.match(r"^ip prefix-list \S+ description\b", line)
            if line.startswith("ip prefix-list ") and not description:
                logger.warning("nxos: prefix-list line not read, entry left out: %r", line)
            continue
        prefix = m["prefix"]
        plen = int(prefix.split("/")[1])
        eq = int(m["eq"]) if m["eq"] else None
        ge = int(m["ge"]) if m["ge"] else None
        le = int(m["le"]) if m["le"] else None
        if eq is not None:
            min_len = max_len = eq
        elif ge is not None and le is not None:
            min_len, max_len = ge, le
        elif ge is not None:
            min_len, max_len = ge, 32
        elif le is not None:
            min_len, max_len = plen, le
        else:
            min_len = max_len = plen
        lists.setdefault(m["name"], []).append(
            {
                "seq": int(m["seq"]),
                "action": m["action"],
                "prefix": prefix,
                "eq": eq,
                "ge": ge,
                "le": le,
                "min_len": min_len,
                "max_len": max_len,
            }
        )
    for entries in lists.values():
        entries.sort(key=lambda e: e["seq"])
    return lists


# --- OSPF: the `| json` operational tables and the running-config extract ---------------

# Maps the `if_type` and network-type words of NX-OS to the names of the
# protocol. The schema holds the names of the protocol. An unmapped value is
# kept in lower case.
_OSPF_NETWORK_TYPES: dict[str, str] = {
    "p2p": "point-to-point",
    "point-to-point": "point-to-point",
    "point_to_point": "point-to-point",
    "bcast": "broadcast",
    "broadcast": "broadcast",
    "nbma": "nbma",
    "p2mp": "point-to-multipoint",
    "point-to-multipoint": "point-to-multipoint",
    "loopback": "loopback",
    "virtual": "virtual",
}

# The router-LSA link types, keyed by the numbers of the protocol (RFC 2328
# A.4.2) and by the words that a platform prints for them.
_OSPF_LINK_TYPES: dict[str, str] = {
    "1": "point-to-point",
    "2": "transit",
    "3": "stub",
    "4": "virtual",
    "p2p": "point-to-point",
    "point-to-point": "point-to-point",
    "transit": "transit",
    "stub": "stub",
    "virtual": "virtual",
}

# The LSA type of the rows of each database command. `_lsa_type` prefers a
# type in the row.
_OSPF_DB_COMMANDS: tuple[tuple[str, str], ...] = (
    (CMD_OSPF_DB_ROUTER, "router"),
    (CMD_OSPF_DB_NETWORK, "network"),
    (CMD_OSPF_DB_SUMMARY, "summary"),
    (CMD_OSPF_DB_EXTERNAL, "external"),
    (CMD_OSPF_DB_NSSA, "nssa-external"),
    (CMD_OSPF_DB_ASBR_SUMMARY, "asbr-summary"),
)

# `redistribute <proto> [<tag>] route-map <name>`, over `cisco_common.OSPF_REDIST_PROTOCOLS`.
_OSPF_REDIST_RE = re.compile(
    r"^redistribute\s+(?P<proto>" + "|".join(OSPF_REDIST_PROTOCOLS) + r")(?:\s+\S+)?"
    r"\s+route-map\s+(?P<rm>\S+)$"
)
_OSPF_AREA_TYPE_RE = re.compile(r"^area\s+(?P<aid>\S+)\s+(?P<type>stub|nssa)\b")


def _first(row: dict, *keys: str) -> Any:
    """The value of the first key in `keys` that has a value."""
    for key in keys:
        val = row.get(key)
        if val is not None and val != "":
            return val
    return None


def _int(value: Any) -> int | None:
    """An integer column from an int, a decimal string or a hexadecimal string.
    Every platform prints an LSA sequence number in hexadecimal
    ("0x80000005"). Returns None for a value that is not a number, such as "-"."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    with contextlib.suppress(ValueError):
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    return None


def _bool(value: Any) -> bool | None:
    """A boolean column. NX-OS renders a boolean as the string "true" or "false"."""
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in ("true", "yes", "enabled", "1"):
        return True
    if text in ("false", "no", "disabled", "0"):
        return False
    return None


def _ospf_vrf(name: Any) -> str:
    """The VRF of an OSPF context. The default VRF is `""`, as in the rest of
    this collector."""
    text = str(name or "").strip()
    return "" if text in ("", "default") else text


def _area_id(value: Any) -> str | None:
    """An area id in dotted form. Area 0 and area 0.0.0.0 give the same id."""
    if value is None or value == "":
        return None
    text = str(value).strip()
    if text.isdigit():
        with contextlib.suppress(ValueError):
            return str(ipaddress.IPv4Address(int(text)))
    return text


def _ospf_mask(value: Any) -> str | None:
    """A network mask as a dotted quad. Accepts the dotted form, a bare
    prefix length and a "/24" prefix length."""
    if value is None or value == "":
        return None
    text = str(value).strip().lstrip("/")
    if text.isdigit():
        length = int(text)
        if 0 <= length <= 32:
            return str(ipaddress.IPv4Network(f"0.0.0.0/{length}").netmask)
        return None
    with contextlib.suppress(ValueError):
        return str(ipaddress.IPv4Address(text))
    return None


def _metric_type(value: Any) -> int | None:
    """The external metric type, 1 or 2 (the LSA's E bit). Platforms print it
    as a bare number, as "E2", or as "type-2"."""
    if value is None:
        return None
    digits = re.search(r"[12]", str(value))
    return int(digits.group()) if digits else None


def _ospf_contexts(payload: dict[str, Any]) -> list[tuple[str, str, dict]]:
    """(process, vrf, row) for every `TABLE_ctx`/`ROW_ctx` entry. NX-OS keys
    every OSPF table by context, with one context per process and VRF pair."""
    out = []
    for row in _rows(payload, "ctx"):
        process = str(_first(row, "ptag", "process_tag", "instance") or "")
        out.append((process, _ospf_vrf(_first(row, "cname", "vrf_name_out", "vrf")), row))
    return out


def _ospf_areas(ctx: dict) -> list[dict[str, Any]]:
    """The areas of one process with the type of the schema (`normal`, `stub`
    or `nssa`). The backbone and every other area that is neither stub nor
    NSSA is `normal`."""
    areas = []
    for row in _rows(ctx, "area"):
        aid = _area_id(_first(row, "aid", "area", "area_id"))
        if aid is None:
            continue
        if _bool(_first(row, "nssa_area", "nssa")):
            kind = "nssa"
        elif _bool(_first(row, "stub_area", "stub")):
            kind = "stub"
        else:
            kind = "normal"
        areas.append({"area_id": aid, "type": kind})
    return areas


def _ospf_links(lsa: dict) -> list[dict[str, Any]]:
    """The links of a router LSA. Each link has its type, the link id and the
    link data that the protocol defines for the type, and its metric."""
    links = []
    for row in _rows(lsa, "link"):
        raw_type = str(_first(row, "type", "link_type", "lnk_type") or "").strip().lower()
        links.append(
            {
                "link_type": _OSPF_LINK_TYPES.get(raw_type, raw_type or None),
                "link_id": _first(row, "id", "link_id", "lnk_id"),
                "link_data": _first(row, "data", "link_data", "lnk_data"),
                "metric": _int(_first(row, "metric", "cost", "tos0_metric")),
            }
        )
    return links


def _ospf_attached_routers(lsa: dict) -> list[str]:
    """The attached routers of a network LSA. Each row holds one router id. A
    plain list of router ids is read too."""
    flat = lsa.get("attached_rtr")
    if isinstance(flat, list) and all(not isinstance(v, dict) for v in flat):
        return [str(v) for v in flat if v]
    routers = []
    for row in _rows(lsa, "rtr"):
        rid = _first(row, "rtr", "rtrid", "attached_rtr", "id")
        if rid:
            routers.append(str(rid))
    return routers


def _lsa_type(lsa: dict, default: str) -> str:
    """The type in the LSA row when it is in `OSPF_LSA_TYPES`, else the type
    of the command of the row."""
    stated = str(_first(lsa, "lsa_type", "type") or "").strip().lower()
    return stated if stated in OSPF_LSA_TYPES else default


def _ospf_lsas(payload: dict[str, Any], default_type: str) -> list[dict[str, Any]]:
    """Converts the payload of one database command to LSA rows with the
    columns of `ospf_lsdb`. The function reads both nestings of NX-OS. The
    first has an area level under the context (`TABLE_area`, with the area id
    on the area row). The second has a flat `TABLE_lsdb` under the context
    (with the area id on the LSA row)."""
    out: list[dict[str, Any]] = []
    for process, vrf, ctx in _ospf_contexts(payload):
        scoped: list[tuple[str | None, dict]] = []
        for area_row in _rows(ctx, "area"):
            aid = _area_id(_first(area_row, "aid", "area", "area_id"))
            scoped.extend((aid, lsa) for lsa in _rows(area_row, "lsdb"))
        scoped.extend((_area_id(_first(lsa, "area", "aid", "area_id")), lsa) for lsa in _rows(ctx, "lsdb"))
        for area, lsa in scoped:
            lsa_type = _lsa_type(lsa, default_type)
            out.append(
                {
                    "process": process,
                    "vrf": vrf,
                    "area": area,
                    "lsa_type": lsa_type,
                    "lsid": _first(lsa, "lsid", "id", "link_id"),
                    "adv_router": _first(lsa, "advrouter", "adv_router", "adv_rtr", "advrtr"),
                    "seq": _int(_first(lsa, "seqno", "seq", "seq_no", "seqnum")),
                    "age": _int(_first(lsa, "age", "lsa_age")),
                    # Router LSAs and network LSAs have no LSA-level metric.
                    # The costs of a router LSA are per link. A network LSA
                    # has no cost.
                    "metric": (
                        None
                        if lsa_type in ("router", "network")
                        else _int(_first(lsa, "metric", "cost", "tos0_metric"))
                    ),
                    "links": _ospf_links(lsa) if lsa_type == "router" else None,
                    "attached_routers": (_ospf_attached_routers(lsa) if lsa_type == "network" else None),
                    "mask": _ospf_mask(_first(lsa, "netmask", "mask", "prefixlen", "masklen")),
                    "forwarding_address": _first(lsa, "fwdaddr", "fwd_addr", "forwarding_address"),
                    "metric_type": _metric_type(_first(lsa, "metrictype", "metric_type", "ext_type")),
                }
            )
    return out


# --- BGP session and path observations: the per-neighbor `| json` capture ---------------
#
# These parsers read the paths of each session, the peer of each path and the
# best path. `bgp_side_rows` maps them to the 2 side-store tables
# `bgp_sessions` and `bgp_session_routes` (`core/sidestore.py`).


def _bgp_communities(value: Any) -> str | None:
    """The community list as one string. NX-OS renders it as a space-separated
    string or as a list. Both give the string of the `communities` column of
    the schema."""
    if isinstance(value, list):
        joined = " ".join(str(v) for v in value if v not in (None, ""))
        return joined or None
    text = str(value).strip() if value not in (None, "") else ""
    return text or None


def _bgp_best(row: dict, direction: str) -> bool | None:
    """True when the device marked this path as best.

    Returns None for the received direction. Received paths are read before
    the decision process and have no best mark.
    """
    if direction == "received":
        return None
    for key in ("best", "bestpath"):
        value = row.get(key)
        if value is None:
            continue
        return str(value).strip().lower() in ("true", "yes", "1")
    return None


def _states_no_remote_as(neighbor: dict[str, Any]) -> bool:
    """True when a neighbor record shows that the block has no remote AS. The
    block has no `remote-as` in any spelling, in the block or in a template,
    and no unresolved template. A record without the `remote_as` field gives
    no information about the remote AS."""
    return (
        "remote_as" in neighbor
        and neighbor["remote_as"] is None
        and not neighbor.get("remote_as_unread")
        and not neighbor.get("remote_as_route_map")
        and not neighbor.get("inheritance_gaps")
    )


def bgp_capture_targets(
    processes: list[dict[str, Any]], observed: list[dict[str, Any]] | None = None
) -> list[tuple[str, str]]:
    """The (vrf, peer address) pairs whose path tables a fetch asks for, in
    configuration order and without duplicates.

    The pairs come from `show running-config bgp`. A `neighbor <prefix>`
    passive range is skipped.

    Every path command asks for `ipv4 unicast` (`bgp_route_command`). A
    neighbor is a target when it has that family. A neighbor block that
    activates other families without `ipv4 unicast` is skipped. A block that
    activates no family is kept when its address is IPv4. An IPv6 address
    without an `ipv4 unicast` block is skipped.

    A neighbor with no remote AS is skipped (`_states_no_remote_as`). The
    device starts no session for it and refuses all 3 path commands, and
    `bgp_stage` drops the peer.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for proc in processes:
        vrf = proc.get("vrf") or DEFAULT_VRF
        for neighbor in expand_dynamic_neighbors(proc.get("neighbors") or [], observed or [], vrf):
            peer_ip = neighbor.get("peer_ip") or ""
            try:
                address = ipaddress.ip_address(peer_ip)
            except ValueError:
                continue
            if _states_no_remote_as(neighbor):
                continue
            families = neighbor.get("address_families") or []
            if IPV4_UNICAST not in families and (families or address.version != 4):
                continue
            key = (vrf, peer_ip)
            if key not in seen:
                seen.add(key)
                out.append(key)
    return out


def parse_bgp_sessions(text: str) -> list[dict[str, Any]]:
    """Parses `show bgp sessions | json` to one observed-session record per
    neighbor.

    `state` is the session state in the wording of the device.
    `established_since_ms`, `prefixes_received`, `prefixes_advertised` and
    `capabilities` stay null.
    """
    if not str(text or "").strip():
        return []
    try:
        payload = json.loads(text)
    except ValueError:
        return []
    if not isinstance(payload, dict):
        return []
    out: list[dict[str, Any]] = []
    for vrf_row in _rows(payload, "vrf"):
        vrf_name = vrf_row.get("vrf-name-out") or DEFAULT_VRF
        for neighbor in _rows(vrf_row, "neighbor"):
            peer_ip = neighbor.get("neighbor-id")
            if not peer_ip:
                continue
            out.append(
                {
                    "vrf": vrf_name,
                    "peer_ip": peer_ip,
                    "state": neighbor.get("state"),
                    **({"peer_asn": as_int(neighbor["remoteas"])} if neighbor.get("remoteas") else {}),
                    "established_since_ms": None,
                    "prefixes_received": None,
                    "prefixes_advertised": None,
                    "capabilities": None,
                }
            )
    return out


# The spellings of the remote router identifier key in a neighbor row of NX-OS.
_NEIGHBOR_ROUTER_ID_KEYS = ("rtrid", "remote-router-id", "remoterouterid", "remote_router_id")


def parse_bgp_neighbor_router_ids(text: str) -> dict[tuple[str, str], str]:
    """Parses `show bgp vrf all neighbors | json` to
    {(vrf, peer ip): remote router id}.

    A neighbor row with no identifier or with 0.0.0.0 (a session that did not
    open) adds no entry. A blank or unreadable answer gives an empty dict."""
    if not str(text or "").strip():
        return {}
    try:
        payload = json.loads(text)
    except ValueError:
        return {}
    if not isinstance(payload, dict):
        return {}
    out: dict[tuple[str, str], str] = {}
    for vrf_row in _rows(payload, "vrf"):
        vrf_name = vrf_row.get("vrf-name-out") or DEFAULT_VRF
        for neighbor in _rows(vrf_row, "neighbor"):
            peer_ip = neighbor.get("neighbor") or neighbor.get("neighbor-id")
            if not peer_ip:
                continue
            rid = next(
                (r for key in _NEIGHBOR_ROUTER_ID_KEYS if (r := router_id_or_none(neighbor.get(key)))), None
            )
            if rid:
                out.setdefault(neighbor_key(vrf_name, str(peer_ip)), rid)
    return out


def parse_ospf_config(text: str) -> dict[tuple[str, str], dict[str, Any]]:
    """Parses `show running-config ospf` to {(process, vrf): {router_id,
    area_types, redistribute}}.

    A `redistribute <proto> [<tag>] route-map <name>` line gives one entry.

    A `vrf <name>` sub-block is a separate process. The process of the default
    VRF has the empty VRF name.
    """
    out: dict[tuple[str, str], dict[str, Any]] = {}

    def _block(process: str, vrf: str, children: list[ConfigNode]) -> dict[str, Any]:
        entry = out.setdefault((process, vrf), {"router_id": None, "area_types": {}, "redistribute": []})
        for line, _sub in children:
            if line.startswith("router-id "):
                entry["router_id"] = line.split()[1]
            elif m := _OSPF_REDIST_RE.match(line):
                entry["redistribute"].append({"protocol": m["proto"], "route_map": m["rm"]})
            elif line == "default-information originate" or line.startswith("default-information originate "):
                entry.update(ospf_default_originate(line.removeprefix("default-information originate")))
            elif m := _OSPF_AREA_TYPE_RE.match(line):
                aid = _area_id(m["aid"])
                if aid is not None:
                    entry["area_types"][aid] = m["type"]
        return entry

    for line, children in _config_tree(text.splitlines()):
        m = re.match(r"^router ospf (\S+)$", line)
        if not m:
            continue
        process = m.group(1)
        _block(process, "", [(cl, cs) for cl, cs in children if not cl.startswith("vrf ")])
        for cline, csub in children:
            if vm := re.match(r"^vrf (\S+)$", cline):
                _block(process, _ospf_vrf(vm.group(1)), csub)
    return out


def parse_ospf(raw: dict[str, str]) -> dict[str, Any] | None:
    """Converts the OSPF captures to the intermediate `ospf` shape (see the
    docstring of `cisco_common.normalize_cisco`).

    Returns None when the payload has no OSPF command.
    """
    if not any(_ospf_command(raw, cmd) in raw for cmd in OSPF_COMMANDS):
        return None

    def _payload(cmd: str) -> dict[str, Any]:
        try:
            loaded = json.loads(raw.get(_ospf_command(raw, cmd)) or "{}")
        except ValueError:
            logger.warning("nxos: %r did not answer JSON; OSPF table skipped", cmd)
            return {}
        return loaded if isinstance(loaded, dict) else {}

    config = parse_ospf_config(raw.get(CMD_OSPF_CONFIG) or "")

    processes: dict[tuple[str, str], dict[str, Any]] = {}
    for process, vrf, ctx in _ospf_contexts(_payload(CMD_OSPF)):
        processes[(process, vrf)] = {
            "process": process,
            "vrf": vrf,
            "router_id": _first(ctx, "rid", "router_id", "routerid"),
            "areas": _ospf_areas(ctx),
            "redistribute": [],
        }
    for (process, vrf), entry in config.items():
        proc = processes.setdefault(
            (process, vrf),
            # A process of the config alone keeps its redistribution.
            {
                "process": process,
                "vrf": vrf,
                "router_id": None,
                "areas": [],
                "redistribute": [],
                # `observed` is False for a process of the config alone. Its
                # areas, interfaces, adjacencies and LSAs were not read
                # (`ospf_context_outcomes`).
                "observed": False,
            },
        )
        proc["router_id"] = proc["router_id"] or entry["router_id"]
        proc["redistribute"] = entry["redistribute"]
        proc.update({k: v for k, v in entry.items() if k.startswith("default_information_originate")})
        # The area types of the operational table come first. The stub or nssa
        # type of the config replaces a `normal` area and adds an area that the
        # table did not list.
        types = entry["area_types"]
        known = {a["area_id"] for a in proc["areas"]}
        for area in proc["areas"]:
            if area["type"] == "normal" and area["area_id"] in types:
                area["type"] = types[area["area_id"]]
        proc["areas"].extend(
            {"area_id": aid, "type": kind} for aid, kind in types.items() if aid not in known
        )

    interfaces = []
    area_by_if: dict[str, str] = {}
    for process, vrf, ctx in _ospf_contexts(_payload(CMD_OSPF_IF)):
        for row in _rows(ctx, "intf"):
            name = _first(row, "ifname", "if_name", "intf_name")
            area = _area_id(_first(row, "area", "aid", "area_id"))
            if not name or area is None:
                continue
            raw_type = str(_first(row, "if_type", "type", "network_type") or "").strip().lower()
            area_by_if[str(name)] = area
            interfaces.append(
                {
                    "process": process,
                    "vrf": vrf,
                    "name": str(name),
                    "area": area,
                    "cost": _int(_first(row, "cost", "if_cost")),
                    "network_type": _OSPF_NETWORK_TYPES.get(raw_type, raw_type or None),
                    "passive": _bool(_first(row, "passive", "if_passive", "passive_iface")),
                }
            )

    adjacencies = []
    for process, vrf, ctx in _ospf_contexts(_payload(CMD_OSPF_NBR)):
        for row in _rows(ctx, "nbr"):
            name = _first(row, "intf", "ifname", "if_name")
            rid = _first(row, "rid", "nbr_rid", "router_id")
            if not name or not rid:
                continue
            adjacencies.append(
                {
                    "process": process,
                    "vrf": vrf,
                    # A neighbor row without an area takes the area of its
                    # local interface.
                    "area": _area_id(_first(row, "area", "aid")) or area_by_if.get(str(name)),
                    "local_interface": str(name),
                    "neighbor_router_id": str(rid),
                    "neighbor_ip": _first(row, "addr", "ipaddr", "nbr_addr"),
                    "state": _first(row, "state", "nbrstate", "nbr_state"),
                }
            )

    lsdb: list[dict[str, Any]] = []
    for cmd, lsa_type in _OSPF_DB_COMMANDS:
        lsdb.extend(_ospf_lsas(_payload(cmd), lsa_type))

    return {
        "processes": list(processes.values()),
        "interfaces": interfaces,
        "adjacencies": adjacencies,
        "lsdb": lsdb,
    }


def ospf_context_outcomes(
    raw: dict[str, Any], inter: dict[str, Any], device_uid: str
) -> dict[str, TableOutcome]:
    """The link-state database outcome of each forwarding context that holds
    an OSPF process, keyed by `manifest.ospf_context_key`.

    The table outcome covers the device as a whole. A context whose process
    the operational table answered for is `complete` with its LSAs, or
    `complete-empty` without LSAs. A context with a process of the
    running-config alone is `not-captured`. The areas, interfaces, adjacencies
    and LSAs of such a process were not read. For a payload with the
    `LEGACY_OSPF_COMMANDS` spellings alone, the detail of such a context
    states that the commands answer for the default VRF alone."""
    ospf = inter.get("ospf") or {}
    rows: dict[str, int] = {}
    for lsa in ospf.get("lsdb") or ():
        vrf = lsa.get("vrf") or DEFAULT_VRF
        rows[vrf] = rows.get(vrf, 0) + 1
    unread: dict[str, list[str]] = {}
    seen: list[str] = []
    for proc in ospf.get("processes") or ():
        vrf = proc.get("vrf") or DEFAULT_VRF
        if vrf not in seen:
            seen.append(vrf)
        if proc.get("observed") is False:
            unread.setdefault(vrf, []).append(str(proc.get("process") or ""))
    default_only = ospf_default_vrf_only(raw)
    out: dict[str, TableOutcome] = {}
    for vrf in seen:
        key = ospf_context_key(uid.vrf(device_uid, vrf))
        if vrf in unread:
            why = (
                "this payload's OSPF commands answer for the default VRF alone"
                if default_only
                else "the OSPF process table did not answer for this VRF"
            )
            out[key] = TableOutcome(
                status="not-captured", detail=f"{why}: process {', '.join(unread[vrf])} in VRF {vrf}"
            )
        elif rows.get(vrf):
            out[key] = TableOutcome(status="complete", row_count=rows[vrf])
        else:
            out[key] = TableOutcome(status="complete-empty", row_count=0)
    return out


def ospf_table_outcomes(
    raw: dict[str, Any], inter: dict[str, Any] | None = None, device_uid: str | None = None
) -> dict[str, TableOutcome]:
    """`{ospf_lsdb: unsupported}` when the device has no OSPF feature. With
    the parse and the device uid, each forwarding context gets its own outcome
    (`ospf_context_outcomes`).

    The table is `unsupported` when every recorded outcome of
    `OSPF_FEATURE_COMMANDS` is `unsupported`. NX-OS answers a command for a
    feature that is not enabled with an invalid-command banner. The fetch
    records that answer as `unsupported`
    (`cli_collector.classify_command_failure`). A payload with no recorded
    outcome for these commands does not give `unsupported`. A refusal that is
    recorded `ok` with its banner as the answer reads as the refusal
    (`cli_collector.effective_outcomes`). A failed command of
    `OSPF_FEATURE_COMMANDS` gives the table outcome of
    `failed_feature_outcome`.
    """
    recorded = effective_outcomes(_ospf_aliased(raw), {})
    statuses = [recorded[cmd].status for cmd in OSPF_FEATURE_COMMANDS if cmd in recorded]
    if statuses and all(status == "unsupported" for status in statuses):
        return {
            OSPF_LSDB_TABLE: TableOutcome(
                status="unsupported", detail="the device does not have the feature this table reads"
            )
        }
    out: dict[str, TableOutcome] = {}
    if inter is not None and device_uid is not None:
        out.update(ospf_context_outcomes(raw, inter, device_uid))
    # A command that failed, was refused or did not parse leaves its part of
    # the database empty. Such an empty table is not the answer of the device.
    failed = failed_feature_outcome(recorded, OSPF_FEATURE_COMMANDS, "OSPF")
    if failed is not None:
        out[OSPF_LSDB_TABLE] = failed
    return out


def parse_bgp_paths(text: str, *, vrf: str, peer_ip: str, direction: str) -> list[dict[str, Any]]:
    """Parses one `show bgp ... neighbors <peer> <direction> | json` payload
    to one record per path of each prefix.

    NX-OS nests every BGP table as vrf, address family, sub-family, route
    distinguisher (for a VPN table), prefix and path. A payload whose
    sub-family holds the prefixes without a route-distinguisher level is read
    too.

    The address family comes from the prefix.
    """
    return list(_bgp_path_rows(text, vrf=vrf, peer_ip=peer_ip, direction=direction))


def _bgp_path_rows(
    text: Any, *, vrf: str, peer_ip: str, direction: str, whole: bool | None = None
) -> Iterator[dict[str, Any]]:
    """Yields the records of `parse_bgp_paths` one at a time. A blank answer
    and an answer that is not a JSON object yield no record.

    The answer is read in pieces (`_path_pieces`). An answer with a shape that
    raises `_Irregular` is decoded whole (`_iter_bgp_paths`), and the tree
    lives as long as the iteration. `whole` holds that result when an earlier
    read of the same answer found it (`_read_direction`). When `whole` is
    None, the records are collected before the first one is yielded. The walk
    can raise `_Irregular` after it has read some records.
    """
    where = {"vrf": vrf, "peer_ip": peer_ip, "direction": direction}
    if isinstance(text, str):
        span = _content_span(text)
        if span is None:
            return
        start = span[0]
        # `json.loads(text)` skips JSON whitespace alone. A JSON object is the
        # only value with records.
        if text[start] != "{" or _JSON_WHITESPACE.match(text, 0, start).end() != start:
            return
        if whole is None:
            try:
                rows = list(_path_pieces(text, start, len(text), **where))
            except ValueError:
                return
            except _Irregular:
                whole = True
            else:
                yield from rows
                return
        if not whole:
            yield from _path_pieces(text, start, len(text), **where)
            return
    elif not str(text or "").strip():
        return
    try:
        payload = json.loads(text)
    except ValueError:
        return
    if not isinstance(payload, dict):
        return
    yield from _iter_bgp_paths(payload, **where)


def _iter_bgp_paths(
    payload: dict[str, Any], *, vrf: str, peer_ip: str, direction: str
) -> Iterator[dict[str, Any]]:
    """The path records of one decoded path table (`parse_bgp_paths`)."""
    for vrf_row in _rows(payload, "vrf"):
        for afi_row in _rows(vrf_row, "afi"):
            for safi_row in _rows(afi_row, "safi"):
                for holder in _rows(safi_row, "rd") or [safi_row]:
                    for prefix_row in _rows(holder, "prefix"):
                        yield from _path_records(prefix_row, vrf=vrf, peer_ip=peer_ip, direction=direction)


def _path_records(
    prefix_row: dict[str, Any], *, vrf: str, peer_ip: str, direction: str
) -> Iterator[dict[str, Any]]:
    """The path records of one prefix row, one per path. A row without a
    prefix gives no record."""
    prefix = prefix_row.get("ipprefix")
    if not prefix:
        return
    for path_row in _rows(prefix_row, "path"):
        path_id = path_row.get("pathnr")
        yield {
            "vrf": vrf,
            "peer_ip": peer_ip,
            "direction": direction,
            "prefix": prefix,
            "path_id": None if path_id is None else str(path_id),
            "next_hop": path_row.get("ipnexthop"),
            "as_path": path_row.get("aspath") or None,
            "local_pref": as_int(path_row.get("localpref")),
            "med": as_int(path_row.get("metric")),
            "origin": path_row.get("origin"),
            "communities": _bgp_communities(path_row.get("community")),
            "best": _bgp_best(path_row, direction),
        }


def _path_pieces(text: str, start: int, end: int, **where: str) -> Iterator[dict[str, Any]]:
    """`_iter_bgp_paths` of the path table that opens at `text[start]` and
    ends before `end`, read in pieces."""
    scan = _Scan(text, start)
    for _ in _member(scan, "TABLE_vrf"):
        for _ in _table_rows(scan, "vrf"):
            for _ in _member(scan, "TABLE_afi"):
                for _ in _table_rows(scan, "afi"):
                    for _ in _member(scan, "TABLE_safi"):
                        for _ in _table_rows(scan, "safi"):
                            yield from _safi_pieces(scan, **where)
    _value_end(scan, end)


def _safi_pieces(scan: _Scan, **where: str) -> Iterator[dict[str, Any]]:
    """The records of the sub-family row at the scan. They come from its
    route-distinguisher rows when it has any, else from its own prefixes. The
    choice is the same as in `_iter_bgp_paths`."""
    rd_rows = 0
    rd_seen = own_seen = False
    for key in scan.members():
        if key == "TABLE_rd" and not rd_seen:
            rd_seen = True
            for _ in _table_rows(scan, "rd"):
                if own_seen:
                    # The walk has read the own prefixes of the row. The tree
                    # reads the route-distinguisher rows in their place.
                    raise _Irregular
                rd_rows += 1
                for _ in _member(scan, "TABLE_prefix"):
                    yield from _prefix_pieces(scan, **where)
        elif key == "TABLE_prefix" and not own_seen:
            own_seen = True
            if rd_rows:
                scan.value()
            else:
                yield from _prefix_pieces(scan, **where)
        elif key in ("TABLE_rd", "TABLE_prefix"):
            raise _Irregular
        else:
            scan.value()


def _prefix_pieces(scan: _Scan, **where: str) -> Iterator[dict[str, Any]]:
    """The records of the `TABLE_prefix` value at the scan, one decoded
    prefix row at a time."""
    for _ in _table_rows(scan, "prefix"):
        yield from _piece(_path_records(scan.value(), **where))


# The kind and the detail of the stripped answer of an observation command,
# for `_command_outcome`. The kinds are `empty`, `percent` (a `%` line),
# `not-json`, `not-object` (JSON that is not an object) and `object`. The
# detail is the first line of the device for `percent` and "" for every other
# kind.
CommandFacts = tuple[str, str]


def _outcome_facts(text: Any) -> CommandFacts:
    """The `CommandFacts` of `str(text or "").strip()`, without the copy of the
    text."""
    if not isinstance(text, str):
        text = str(text or "")
    span = _content_span(text)
    if span is None:
        return "empty", ""
    return _span_facts(text, *span)


def _span_facts(text: str, start: int, end: int) -> CommandFacts:
    """The `CommandFacts` of the stripped answer `text[start:end]`."""
    if text[start] == "%":
        return "percent", _first_line(text, start, end).strip()
    try:
        payload = _decode_span(text, start, end)
    except ValueError:
        return "not-json", ""
    return ("object" if isinstance(payload, dict) else "not-object"), ""


def _direction_facts(text: Any, *, vrf: str, peer_ip: str, direction: str) -> tuple[CommandFacts, int]:
    """`_outcome_facts(text)` and the count of records that `parse_bgp_paths`
    reads from the same answer, from one read of the answer
    (`_read_direction`)."""
    facts, count, _whole = _read_direction(text, vrf=vrf, peer_ip=peer_ip, direction=direction)
    return facts, count


def _read_direction(text: Any, *, vrf: str, peer_ip: str, direction: str) -> tuple[CommandFacts, int, bool]:
    """`_direction_facts` of one path answer, and True when its records are
    read from its decoded tree (the `whole` of `_bgp_path_rows`).

    The walk over the answer in pieces (`_path_pieces`) counts the records and
    drops each one. The answer is decoded whole only when the walk raises
    `_Irregular`.

    `_command_outcome` reads the stripped answer. `parse_bgp_paths` reads the
    answer as it is. Both give the same result when the whitespace around the
    value is JSON whitespace, which `json.loads` skips. One read of the
    stripped answer then serves both. `json.loads` rejects any other
    whitespace at an edge (a no-break space, U+2028) and a leading `%`.
    `parse_bgp_paths` reads no records from such an answer, and the count is
    0.

    The decoder raises RecursionError for an answer that is nested deeper
    than the interpreter allows. The error propagates from the parse, and the
    load of the device fails with it.
    """
    where = {"vrf": vrf, "peer_ip": peer_ip, "direction": direction}
    if not isinstance(text, str):
        rows = _bgp_path_rows(text, **where)
        return _outcome_facts(text), sum(1 for _ in rows), True
    span = _content_span(text)
    if span is None:
        return ("empty", ""), 0, False
    start, end = span
    json_before = _JSON_WHITESPACE.match(text, 0, start).end() == start
    json_after = _JSON_WHITESPACE.match(text, end).end() == len(text)
    json_edges = json_before and json_after
    if text[start] == "{":
        try:
            count = sum(1 for _ in _path_pieces(text, start, end, **where))
        except ValueError:
            return ("not-json", ""), 0, False
        except _Irregular:
            pass
        else:
            return ("object", ""), count if json_edges else 0, False
    if text[start] != "{" or not json_edges:
        return _span_facts(text, start, end), 0, False
    try:
        payload = json.loads(text)
    except ValueError:
        return ("not-json", ""), 0, True
    return ("object", ""), sum(1 for _ in _iter_bgp_paths(payload, **where)), True


def parse_bgp_observations(raw: dict[str, str], processes: list[dict[str, Any]]) -> dict[str, Any]:
    """The observed part of the BGP capture, from the commands of the payload.

    `sessions` is the observed session state and `routes` holds every observed
    path. `directions` has one entry per session and direction that the fetch
    asked for, with the row count of that direction. A direction whose
    command is absent from the payload has a `row_count` of None.
    `command_facts` holds the `CommandFacts` of every path command of the
    payload, for `bgp_table_outcomes`.

    The function reads each path table once, in pieces, to count its records
    and to get its facts (`_read_direction`). `routes` is a
    `streams.ChainRows` that holds no record. Each read of `routes` reads
    each table again from the text of the payload, in pieces. The decoded
    table of a full-table peer and its full list of paths never exist in
    memory. An answer that raises `_Irregular` is the exception. Such an
    answer is decoded whole here and again on each read of `routes`, one
    table at a time.
    """
    sessions = parse_bgp_sessions(raw.get(bgp_sessions_command(raw)) or "")
    parts: list[tuple[int, Callable[[], Iterable[dict[str, Any]]]]] = []
    directions: list[dict[str, Any]] = []
    command_facts: dict[str, CommandFacts] = {}
    for vrf, peer_ip in bgp_capture_targets(processes, sessions):
        for direction in BGP_DIRECTION_KEYWORDS:
            command = bgp_route_command(vrf, peer_ip, direction)
            entry: dict[str, Any] = {
                "vrf": vrf,
                "peer_ip": peer_ip,
                "direction": direction,
                "command": command,
                "row_count": None,
            }
            if command in raw:
                text = raw[command]
                facts, count, whole = _read_direction(text, vrf=vrf, peer_ip=peer_ip, direction=direction)
                command_facts[command] = facts
                entry["row_count"] = count
                if count:
                    rows = functools.partial(
                        _bgp_path_rows, text, vrf=vrf, peer_ip=peer_ip, direction=direction, whole=whole
                    )
                    parts.append((count, rows))
            directions.append(entry)
    observed: dict[str, Any] = {
        "sessions": sessions,
        "routes": streams.ChainRows(parts),
        "directions": directions,
        "command_facts": command_facts,
    }
    if ids := parse_bgp_neighbor_router_ids(raw.get(CMD_BGP_NEIGHBORS) or ""):
        observed["peer_router_ids"] = nest_router_ids(ids)
    return observed


def _bgp_session_uid(device_uid: str, vrf_name: str, peer_ip: str) -> str:
    """The BgpSession uid that joins an observed row to the graph.

    The formula is the one of `bgp_stage`, `uid.bgp_session(uid.routing_process(dev, vname,
    "bgp"), peer_ip, vname)`.
    """
    return uid.bgp_session(uid.routing_process(device_uid, vrf_name, "bgp"), peer_ip, vrf_name)


def bgp_side_rows(inter: dict[str, Any], device_uid: str) -> dict[str, Sequence[dict[str, Any]]]:
    """Maps the observed BGP records to the 2 side-store tables, with the
    device, context and session uids.

    `context_uid` is `uid.vrf(device_uid, name)`. `cisco_common.side_rows`
    uses the same formula for `rib` and `arp`. The context of an observed
    path matches the VrfInstance node of the same run.

    `bgp_session_routes` is a `streams.MappedRows` over the observed paths.
    Each row is built when it is read. The 2 uids of a row depend on its VRF
    and its peer alone and are derived once per session.
    """
    observed = inter.get("bgp_observed") or {}
    sessions = []
    for s in observed.get("sessions") or []:
        vrf_name = s["vrf"] or DEFAULT_VRF
        sessions.append(
            {
                "device_uid": device_uid,
                "context_uid": uid.vrf(device_uid, vrf_name),
                "session_uid": _bgp_session_uid(device_uid, vrf_name, s["peer_ip"]),
                "peer_ip": s["peer_ip"],
                # The path commands of this collector ask for IPv4 unicast alone.
                "af": 4,
                "safi": BGP_SAFI,
                "state": s.get("state"),
                "established_since_ms": s.get("established_since_ms"),
                "prefixes_received": s.get("prefixes_received"),
                "prefixes_advertised": s.get("prefixes_advertised"),
                "capabilities": s.get("capabilities"),
            }
        )
    # Maps (vrf, peer) to (context_uid, session_uid).
    session_uids: dict[tuple[str, str], tuple[str, str]] = {}

    def route_row(r: dict[str, Any]) -> dict[str, Any]:
        key = (r["vrf"], r["peer_ip"])
        uids = session_uids.get(key)
        if uids is None:
            vrf_name = r["vrf"] or DEFAULT_VRF
            uids = (uid.vrf(device_uid, vrf_name), _bgp_session_uid(device_uid, vrf_name, r["peer_ip"]))
            session_uids[key] = uids
        context_uid, session_uid = uids
        direction = r["direction"]
        return {
            "device_uid": device_uid,
            "context_uid": context_uid,
            "session_uid": session_uid,
            "peer_ip": r["peer_ip"],
            "safi": BGP_SAFI,
            "direction": direction,
            "rib_type": BGP_RIB_TYPES[direction],
            "policy_stage": BGP_POLICY_STAGES[direction],
            "path_id": r.get("path_id"),
            "prefix": r["prefix"],
            "next_hop": r.get("next_hop"),
            # A BGP next hop of this capture resolves in the context of its
            # session. No NX-OS command of the capture returns another context.
            "next_hop_context_uid": None,
            "as_path": r.get("as_path"),
            "local_pref": r.get("local_pref"),
            "med": r.get("med"),
            "origin": r.get("origin"),
            "communities": r.get("communities"),
            "best": r.get("best"),
            **lpm_columns(r["prefix"]),
        }

    routes = streams.MappedRows(observed.get("routes") or [], route_row)
    return {"bgp_sessions": sessions, "bgp_session_routes": routes}


# The outcome detail of a BGP table or direction that the run did not read,
# per capture setting.
_CAPTURE_REASONS: dict[str, str] = {
    "none": "the source's capture_bgp setting is none",
    "sessions": "the source's capture_bgp setting is sessions, which reads session state only",
}


def _command_outcome(
    text: Any, recorded: SectionOutcome | None, row_count: int | None, *, facts: CommandFacts | None = None
) -> TableOutcome:
    """The outcome of one observation command, from its recorded outcome and
    its answer.

    A command that the platform refused as unknown is `not-captured`. The
    device does not have the feature or does not retain the table. A command
    refused for another reason (a credential without the privilege, a command
    that failed) is `failed`. A command that answered with a `%` line is
    `not-captured`.

    `facts` holds the `CommandFacts` of the answer from the parse
    (`parse_bgp_observations`). When `facts` is None, the function reads the
    answer.
    """
    if recorded is None:
        return TableOutcome(status="not-captured")
    if recorded.status == "unsupported":
        return TableOutcome(status="not-captured", detail=recorded.detail)
    if recorded.status != "ok":
        return TableOutcome(status="failed", detail=recorded.detail)
    kind, detail = _outcome_facts(text) if facts is None else facts
    if kind == "empty":
        return TableOutcome(status="complete-empty", row_count=0)
    if kind == "percent":
        return TableOutcome(status="not-captured", detail=detail)
    if kind == "not-json":
        return TableOutcome(status="failed", detail="the command answered with text that is not JSON")
    if kind == "not-object":
        return TableOutcome(status="failed", detail="the command answered with JSON that is not an object")
    count = row_count or 0
    if not count:
        return TableOutcome(status="complete-empty", row_count=0)
    return TableOutcome(status="complete", row_count=count)


def bgp_table_outcomes(
    raw: dict[str, Any], inter: dict[str, Any], device_uid: str, *, capture: str
) -> dict[str, TableOutcome]:
    """The outcomes of the BGP observation tables and of each session
    direction.

    A table that the capture setting excludes is `not-captured`. A table whose
    command the device refused as unknown is `not-captured`. Each session
    direction gets its own outcome, keyed by `manifest.bgp_direction_key`.
    """
    outcomes: dict[str, TableOutcome] = {}
    recorded = effective_outcomes(raw, inter)
    observed = inter.get("bgp_observed") or {}
    if capture in _CAPTURE_REASONS:
        detail = _CAPTURE_REASONS[capture]
        outcomes[BGP_ROUTES_TABLE] = TableOutcome(status="not-captured", detail=detail)
        if capture == "none":
            outcomes[BGP_SESSIONS_TABLE] = TableOutcome(status="not-captured", detail=detail)
    if capture != "none":
        sessions_command = bgp_sessions_command(raw)
        state = _command_outcome(
            raw.get(sessions_command),
            recorded.get(sessions_command),
            len(observed.get("sessions") or []),
        )
        if state.status in ("not-captured", "failed"):
            outcomes[BGP_SESSIONS_TABLE] = state
    facts = observed.get("command_facts") or {}
    for entry in observed.get("directions") or []:
        vrf_name = entry["vrf"] or DEFAULT_VRF
        session_uid = _bgp_session_uid(device_uid, vrf_name, entry["peer_ip"])
        outcome = _command_outcome(
            raw.get(entry["command"]),
            recorded.get(entry["command"]),
            entry["row_count"],
            facts=facts.get(entry["command"]),
        )
        if outcome.status == "not-captured" and not outcome.detail and capture in _CAPTURE_REASONS:
            outcome = outcome.model_copy(update={"detail": _CAPTURE_REASONS[capture]})
        outcomes[bgp_direction_key(session_uid, entry["direction"])] = outcome
    return outcomes


# `eth_speed` is "1000 Mb/s", "10 Gb/s", or "auto-speed" for a negotiated port.
# Any other value parses to None.
_ETH_SPEED_RE = re.compile(r"^(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>Mb/s|Gb/s)$", re.IGNORECASE)


def _nxos_speed_mbps(eth_speed: Any) -> int | None:
    if not isinstance(eth_speed, str):
        return None
    m = _ETH_SPEED_RE.match(eth_speed.strip())
    if not m:
        return None
    mbps = float(m["value"]) * (1000 if m["unit"].lower() == "gb/s" else 1)
    rounded = round(mbps)
    return rounded if abs(mbps - rounded) < 1e-6 else None


def _nxos_duplex(eth_duplex: Any) -> str | None:
    """The duplex from `eth_duplex`. `full` and `half` are kept. `auto` (a
    negotiated port that does not report the result), an absent value and any
    other value give None."""
    if isinstance(eth_duplex, str) and eth_duplex.strip().lower() in ("full", "half"):
        return eth_duplex.strip().lower()
    return None


def _nxos_bandwidth_kbit(eth_bw: Any) -> int | None:
    """The routing-metric bandwidth of the Port in Kbit/s, from `eth_bw`."""
    if isinstance(eth_bw, bool):
        return None
    if isinstance(eth_bw, int):
        return eth_bw
    if isinstance(eth_bw, str) and eth_bw.strip().isascii() and eth_bw.strip().isdigit():
        return int(eth_bw.strip())
    return None


def _lldp_text(value: Any) -> str | None:
    """A text field of the LLDP detail table, or None when the neighbor did not
    send it. NX-OS prints the string `null` for a TLV that the neighbor did not
    send. For a host that advertises a chassis MAC alone, `sys_name`,
    `port_desc` and `sys_desc` are all `"null"`."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text == "null":
        return None
    return text


def _parse_interface(row: dict) -> dict:
    name = row["interface"]
    kind = _kind(name)
    vlan = None
    if kind == "svi":
        m = _VLAN_RE.search(name)
        vlan = int(m.group()) if m else None
    speed_mbps = _nxos_speed_mbps(row.get("eth_speed"))
    parsed = {
        "name": name,
        "kind": kind,
        # Every MTU-named field of the row is kept as stated.
        "mtu_raw_fields": {
            key: value
            for key, value in row.items()
            if "mtu" in key.lower() and isinstance(value, (str, int, float, bool))
        },
        "mac": canonical_mac(row.get("eth_hw_addr") or row.get("svi_mac")),
        "admin_up": _admin_up(row),
        "ips": _interface_ips(row),
        "vlan": vlan,
        "speed_mbps": speed_mbps,
        "duplex": _nxos_duplex(row.get("eth_duplex")),
        "speed_source": "nxos:eth_speed" if speed_mbps is not None else None,
        "bandwidth_kbit": _nxos_bandwidth_kbit(row.get("eth_bw")),
    }
    # `desc` on a physical or port-channel row, `svi_desc` on a VLAN interface.
    description = str(row.get("svi_desc" if kind == "svi" else "desc") or "").strip()
    if description:
        parsed["description"] = description
    return parsed


# --- first-hop redundancy and vPC ------------------------------------------------------


def _hsrp_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Converts `show hsrp all | json` to the `fhrp` rows of the intermediate shape."""
    rows = []
    for row in _rows(payload, "grp_detail"):
        vip = row.get("sh_vip") or row.get("sh_vip_v6")
        if not row.get("sh_if_index") or not vip:
            continue
        rows.append(
            {
                "interface": row["sh_if_index"],
                "kind": "hsrp",
                "group": as_int(row.get("sh_group_num")),
                "vip": str(vip),
                "priority": as_int(row.get("sh_prio")),
                "state": row.get("sh_group_state"),
                "virtual_mac": row.get("sh_vmac"),
            }
        )
    return rows


def _vrrp_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Converts `show vrrp detail | json` to the `fhrp` rows of the intermediate shape."""
    rows = []
    for row in _rows(payload, "vrrp_group"):
        vip = row.get("sh_vip_addr") or row.get("sh_vip")
        if not row.get("sh_if_name") or not vip:
            continue
        rows.append(
            {
                "interface": row["sh_if_name"],
                "kind": "vrrp",
                "group": as_int(row.get("sh_group_id")),
                "vip": str(vip),
                "priority": as_int(row.get("sh_prio")),
                "state": row.get("sh_group_state"),
                "virtual_mac": row.get("sh_vmac"),
            }
        )
    return rows


def _vpc(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Converts `show vpc | json` to the `vpc` entry of the intermediate shape.
    Returns None for a device that reports no domain. The peer-link row is the
    first `ROW_peerlink`. Its `peerlink-ifindex` is the port-channel name."""
    domain = payload.get("vpc-domain-id")
    if domain in (None, "", "not configured"):
        return None
    peerlink = _rows(payload, "peerlink")
    domain_id = as_int(domain)
    role = str(payload.get("vpc-role") or "").strip().lower()
    return {
        "domain": domain_id if domain_id is not None else str(domain),
        "role": role or None,
        "peer_link": peerlink[0].get("peerlink-ifindex") if peerlink else None,
        "peer_status": payload.get("vpc-peer-status"),
    }


def _rib_rows(text: Any) -> list[dict[str, Any]]:
    """Parses `show ip route vrf all | json` to one record per path of each
    prefix.

    The answer is read in pieces (`_rib_pieces`). An answer that raises
    `_Irregular` is decoded whole by `_json_payload` (`_rib_records`). Both
    reads give the same records and raise the same errors.
    """
    if not isinstance(text, str):
        text = str(text or "")
    span = _content_span(text)
    if span is not None and text[span[0]] == "{":
        start, end = span
        try:
            return _rib_pieces(text, start, end)
        except ValueError as exc:
            raise _not_json(CMD_ROUTE, text, start, end) from exc
        except _Irregular:
            pass
    return _rib_records(_json_payload(text, CMD_ROUTE))


def _rib_records(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """The RIB records of a decoded route tree (`_rib_rows`)."""
    rib: list[dict[str, Any]] = []
    for vrf_row in _rows(payload, "vrf"):
        vrf_name = vrf_row.get("vrf-name-out", "")
        for addrf_row in _rows(vrf_row, "addrf"):
            for prefix_row in _rows(addrf_row, "prefix"):
                rib.extend(_rib_path_records(vrf_name, prefix_row))
    return rib


def _rib_path_records(vrf_name: Any, prefix_row: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """The RIB records of one prefix row, one per path.

    The next hop of a leaked route resolves in another VRF. NX-OS prints that
    VRF after the address as `<address>%<vrf>` (`*via 10.0.0.1%default`). The
    address goes to `next_hop` of the record and the VRF to `next_hop_vrf`.
    `cisco_common.side_rows` writes `next_hop_vrf` as the
    `next_hop_context_uid` of the row. A record whose next hop has no VRF has
    no `next_hop_vrf` key.

    A path whose `ubest` is false is not a unicast best path. It is the route
    of another client that lost on preference, or a multicast-only path. It
    does not forward unicast traffic and has no record. A path without the
    `ubest` field keeps its record."""
    prefix = prefix_row.get("ipprefix")
    for path_row in _rows(prefix_row, "path"):
        ubest = path_row.get("ubest")
        if ubest is not None and str(ubest).lower() not in ("true", "1"):
            continue
        next_hop = path_row.get("ipnexthop")
        next_hop_vrf = None
        if isinstance(next_hop, str) and "%" in next_hop:
            next_hop, _, next_hop_vrf = next_hop.partition("%")
        yield {
            "vrf": vrf_name,
            "prefix": prefix,
            "next_hop": next_hop,
            **({"next_hop_vrf": next_hop_vrf} if next_hop_vrf else {}),
            "interface": path_row.get("ifname"),
            "protocol": path_row.get("clientname"),
            "metric": path_row.get("metric"),
        }


def _rib_pieces(text: str, start: int, end: int) -> list[dict[str, Any]]:
    """`_rib_records` of the route table that opens at `text[start]` and ends
    before `end`, read in pieces.

    The name of a VRF row is the last `vrf-name-out` of the row, as in the
    tree, at any position in the row. A name after the routes of the row is
    set on their records after the row has been read."""
    scan = _Scan(text, start)
    rib: list[dict[str, Any]] = []
    for _ in _member(scan, "TABLE_vrf"):
        for _ in _table_rows(scan, "vrf"):
            first = len(rib)
            vrf_name: Any = ""
            routes_read = renamed = False
            for key in scan.members():
                if key == "vrf-name-out":
                    vrf_name = scan.value()
                    renamed = routes_read
                elif key == "TABLE_addrf" and not routes_read:
                    routes_read = True
                    for _ in _table_rows(scan, "addrf"):
                        for _ in _member(scan, "TABLE_prefix"):
                            for _ in _table_rows(scan, "prefix"):
                                rib.extend(_piece(_rib_path_records(vrf_name, scan.value())))
                elif key == "TABLE_addrf":
                    raise _Irregular
                else:
                    scan.value()
            if renamed:
                for index in range(first, len(rib)):
                    rib[index]["vrf"] = vrf_name
    _value_end(scan, end)
    return rib


def parse(raw: dict[str, str]) -> dict[str, Any]:
    """Converts the `{command: raw_text}` outputs to the cross-family
    intermediate shape that `cisco_common.normalize_cisco` reads. The function
    has no side effects."""
    version = _json_payload(raw.get(CMD_VERSION), CMD_VERSION)
    device = {
        "hostname": version.get("host_name") or "unknown",
        "serial": version.get("proc_board_id"),
        "platform": "nxos",
        # Nexus 9000 reports the running release in `nxos_ver_str`. Nexus 5000
        # and 7000 report it in `sys_ver_str`.
        "os_version": version.get("nxos_ver_str") or version.get("sys_ver_str"),
    }

    interfaces = [
        _parse_interface(row)
        for row in _rows(_json_payload(raw.get(CMD_INTERFACE), CMD_INTERFACE), "interface")
    ]
    resolve = IfNameResolver(ifc["name"] for ifc in interfaces)
    vrf_by_if = _if_vrf_map(_json_payload(raw.get(CMD_VRF_IF), CMD_VRF_IF), resolve)
    for ifc in interfaces:
        vrf = vrf_by_if.get(resolve.slug(ifc["name"]), "")
        for ip in ifc["ips"]:
            ip["vrf"] = vrf

    neighbors: list[dict[str, Any]] = [
        {
            "local_port": row.get("l_port_id"),
            "name": _lldp_text(row.get("sys_name")),
            "mac": canonical_mac(row.get("chassis_id")),
            "port": _lldp_text(row.get("port_id")),
            "proto": "lldp",
        }
        for row in _rows(_json_payload(raw.get(CMD_LLDP), CMD_LLDP), "nbor_detail")
    ]
    cdp_text = raw.get(CMD_CDP)
    cdp_payload = {} if cdp_off_note(cdp_text) else _json_payload(cdp_text, CMD_CDP)
    for row in _rows(cdp_payload, "cdp_neighbor_brief_info"):
        name, serial = cdp_device_id(row.get("device_id"))
        neighbors.append(
            {
                "local_port": row.get("intf_id"),
                "name": name,
                "serial": serial,
                "mac": None,
                "port": row.get("port_id"),
                "proto": "cdp",
            }
        )

    vlan_payload = _json_payload(raw.get(CMD_VLAN), CMD_VLAN)
    vlans = [
        {"vid": int(row["vlanshowbr-vlanid"]), "name": row.get("vlanshowbr-vlanname")}
        for row in _rows(vlan_payload, "vlanbrief")
    ]
    # The trunk membership comes from the port list of each VLAN in `show vlan`
    # and from the trunk table when the payload has it.
    vlan_ports = parse_vlan_ports(vlan_payload, _json_payload(raw.get(CMD_TRUNK), CMD_TRUNK))

    # `show vrf | json` and `show vrf detail | json` have no route-target
    # columns.
    vrfs = [
        {"name": row["vrf_name"], "rd": row.get("rd") or None, "rt_import": [], "rt_export": []}
        for row in _rows(_json_payload(raw.get(CMD_VRF), CMD_VRF), "vrf")
    ]

    nat = parse_nat_config(raw[CMD_NAT].splitlines())
    acl_payload = _json_payload(raw.get(CMD_ACL), CMD_ACL)
    nat["acls"] = _acl_records(acl_payload)

    # The interface-ACL rulebases read the same access-list capture in a second
    # shape. NAT resolves match lists from the address-only shape above. The
    # rulebases need the protocol, the ports and the reasons that a rule cannot
    # be decided.
    acl = {
        "lists": _acl_filter_records(acl_payload),
        "bindings": parse_access_groups((raw.get(CMD_INTERFACE_CONFIG) or "").splitlines())
        + parse_vlan_filters((raw.get(CMD_VLAN_FILTER) or "").splitlines()),
    }

    rib = _rib_rows(raw.get(CMD_ROUTE))

    mac_table = []
    for row in _rows(_json_payload(raw.get(CMD_MAC), CMD_MAC), "mac_address"):
        try:
            vlan = int(row["disp_vlan"])
        except (KeyError, TypeError, ValueError):
            # A router or static entry has disp_vlan="-" and is skipped.
            continue
        mac_table.append(
            {"vlan": vlan, "mac": canonical_mac(row.get("disp_mac_addr")), "port_name": row.get("disp_port")}
        )

    arp = []
    for vrf_row in _rows(_json_payload(raw.get(CMD_ARP), CMD_ARP), "vrf"):
        vrf_name = vrf_row.get("vrf-name-out", "")
        for adj_row in _rows(vrf_row, "adj"):
            arp.append(
                {
                    "vrf": vrf_name,
                    "ip": adj_row.get("ip-addr-out"),
                    "mac": canonical_mac(adj_row.get("mac")),
                    "interface_name": adj_row.get("intf-out"),
                }
            )

    bgp = {
        "processes": parse_bgp_config(raw[CMD_BGP]),
        "route_maps": parse_route_map_config(raw[CMD_RPM]),
        "prefix_lists": parse_prefix_list_config(raw[CMD_RPM]),
    }
    if match_lists := parse_match_lists(raw[CMD_RPM]):
        bgp["match_lists"] = match_lists
    bgp_observed = parse_bgp_observations(raw, bgp["processes"])

    ospf = parse_ospf(raw)

    # A missing key and the `{}` stand-in parse to no groups and no domain.
    fhrp = _hsrp_rows(_json_payload(raw.get(CMD_HSRP), CMD_HSRP))
    fhrp += _vrrp_rows(_json_payload(raw.get(CMD_VRRP), CMD_VRRP))
    vpc = _vpc(_json_payload(raw.get(CMD_VPC), CMD_VPC))

    inter: dict[str, Any] = {
        "device": device,
        "interfaces": interfaces,
        "neighbors": neighbors,
        "vlans": vlans,
        "vlan_ports": vlan_ports,
        "vrfs": vrfs,
        "nat": nat,
        "acl": acl,
        "rib": rib,
        "mac_table": mac_table,
        "arp": arp,
        "bgp": bgp,
        "bgp_observed": bgp_observed,
        "fhrp": fhrp,
    }
    if vpc is not None:
        inter["vpc"] = vpc
    # A payload without the OSPF capture has no `ospf` key.
    if ospf is not None:
        inter["ospf"] = ospf
    inter["mtu_model"] = version.get("chassis_id")
    parse_mtu(raw, inter, family="nxos", config_command=CMD_INTERFACE_CONFIG)
    return inter


# --- BGP graph stage: the intermediate `bgp` shape to nodes and edges ---------------


def _ensure_vrf(b: GraphBuilder, dev: str, name: str, existing_vrf_uids: set[str]) -> str:
    """The VrfInstance uid `uid.vrf(dev, name)` of a BGP process or session.
    Writes a VrfInstance node without properties for a VRF that the base
    batch did not see."""
    vru = uid.vrf(dev, name)
    if vru not in existing_vrf_uids:
        b.node("VrfInstance", vru, name=name)
        b.rel("OWNED_BY", "VrfInstance", vru, "Device", dev)
    return vru


def _bgp_route_policy_nodes(b: GraphBuilder, bgp: dict[str, Any], *, dev: str) -> dict[tuple[str, str], str]:
    """Writes the RoutePolicy and PrefixListEntry nodes (kind=prefix-list), the
    RoutePolicy and RoutePolicyEntry nodes (kind=route-map) and the `HAS_RULE`
    edges. Then writes the REFERENCES edges of `match_prefix_lists`,
    `calls_policy` and the match lists of every entry. The REFERENCES pass
    runs after every policy name of the config is known. A route-map that
    calls a route-map defined later in the same config resolves. Returns
    {(kind, name): policy_uid} for the FILTERED_BY pass of the redistributions
    and the neighbors."""
    policy_uids: dict[tuple[str, str], str] = match_list_stage(b, bgp.get("match_lists") or [], dev=dev)
    refs: list[tuple[str, str, str]] = []

    for name, entries in (bgp.get("prefix_lists") or {}).items():
        pu = b.node("RoutePolicy", uid.route_policy(dev, "prefix-list", name), name=name, kind="prefix-list")
        policy_uids[("prefix-list", name)] = pu
        for e in entries:
            eu = uid.prefix_list_entry(pu, e["seq"])
            b.node(
                "PrefixListEntry",
                eu,
                seq=e["seq"],
                action=e["action"],
                prefix=e["prefix"],
                eq=e["eq"],
                ge=e["ge"],
                le=e["le"],
                min_len=e["min_len"],
                max_len=e["max_len"],
            )
            b.rel("HAS_RULE", "RoutePolicy", pu, "PrefixListEntry", eu)

    for name, clauses in (bgp.get("route_maps") or {}).items():
        pu = b.node("RoutePolicy", uid.route_policy(dev, "route-map", name), name=name, kind="route-map")
        policy_uids[("route-map", name)] = pu
        for c in clauses:
            eu = uid.route_policy_entry(pu, c["seq"])
            b.node(
                "RoutePolicyEntry",
                eu,
                seq=c["seq"],
                kind="clause",
                action=c["action"],
                continues=c["continue_seq"] is not None,
                continue_seq=c["continue_seq"],
                match_prefix_lists=c["match_prefix_lists"] or None,
                match_as_path_lists=c["match_as_path_lists"] or None,
                match_community_lists=c["match_community_lists"] or None,
                match_tags=c["match_tags"] or None,
                match_metric=c["match_metric"],
                match_protocols=c.get("match_protocols") or None,
                match_unsupported=c.get("match_unsupported"),
                match_ignored=c.get("match_ignored"),
                set_unsupported=c.get("set_unsupported"),
                set_local_pref=c["set_local_pref"],
                set_metric=c["set_metric"],
                set_origin=c["set_origin"],
                set_tag=c["set_tag"],
                set_weight=c["set_weight"],
                set_next_hop=c["set_next_hop"],
                set_as_path_prepend=c["set_as_path_prepend"] or None,
                set_communities=c["set_communities"] or None,
                set_communities_additive=c["set_communities_additive"] or None,
                set_comm_list_delete=c["set_comm_list_delete"],
                calls_policy=c["calls_policy"],
            )
            b.rel("HAS_RULE", "RoutePolicy", pu, "RoutePolicyEntry", eu)
            for pl_name in c["match_prefix_lists"]:
                refs.append((eu, "prefix-list", pl_name))
            if c["calls_policy"]:
                refs.append((eu, "call", c["calls_policy"]))
            for list_kind, list_name in list_references(c):
                refs.append((eu, list_kind, list_name))

    for eu, ref_kind, ref_name in refs:
        target_kind = "route-map" if ref_kind == "call" else ref_kind
        target = policy_uids.get((target_kind, ref_name))
        if target:
            b.rel("REFERENCES", "RoutePolicyEntry", eu, "RoutePolicy", target, kind=ref_kind)
        else:
            logger.warning(
                "nxos: route-map entry %s references undefined %s %r; raw name kept, no REFERENCES edge",
                eu,
                target_kind,
                ref_name,
            )

    return policy_uids


def _bgp_filter(
    b: GraphBuilder,
    *,
    start_label: str,
    start_uid: str,
    policy_uids: dict[tuple[str, str], str],
    name: str | None,
    kind: str,
    key: dict[str, Any],
) -> None:
    """Writes one `FILTERED_BY` edge (session import or export, or process
    redistribution) when `name` resolves to a RoutePolicy in this batch."""
    if not name:
        return
    target = policy_uids.get((kind, name))
    if target:
        b.rel("FILTERED_BY", start_label, start_uid, "RoutePolicy", target, key=key)
    else:
        logger.warning(
            "nxos: %s %s references undefined %s %r; raw name kept, no FILTERED_BY edge",
            start_uid,
            key,
            kind,
            name,
        )


def _redistribution_scope(proc: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """The `redistribute` statements that the IPv4 simulation applies, and a
    context gap for each other statement.

    A statement under `address-family ipv6 unicast` is a gap. A protocol with
    more than one instance tag and different route-maps (`redistribute ospf 1
    route-map A`, `redistribute ospf 2 route-map B`) keeps the first
    route-map in the model. Each later statement with another route-map is a
    gap."""
    kept: list[dict[str, Any]] = []
    gaps: list[str] = []
    seen: dict[str, dict[str, Any]] = {}
    for entry in proc["redistribute"]:
        protocol, route_map = entry["protocol"], entry.get("route_map")
        if entry.get("af", 4) != 4:
            gaps.append(
                f"address-family ipv6 unicast redistribute {protocol}"
                + (f" route-map {route_map}" if route_map else "")
                + " is not modelled"
            )
            continue
        first = seen.setdefault(protocol, entry)
        if first is not entry and first.get("route_map") != route_map:
            tag = entry.get("tag")
            gaps.append(
                f"redistribute {protocol}{f' {tag}' if tag else ''} names route-map {route_map or 'none'}, "
                f"but {protocol} already redistributes through route-map {first.get('route_map') or 'none'}; "
                "the model holds one route-map per protocol"
            )
            continue
        kept.append(entry)
    return kept, gaps


def bgp_stage(
    inter: dict[str, Any],
    *,
    dev: str,
    existing_vrf_uids: set[str],
    source: str,
    scope: str,
    existing_prefix_uids: frozenset[str] | set[str] = frozenset(),
) -> Batch:
    """Converts the intermediate `bgp` shape (`parse_bgp_config`,
    `parse_route_map_config`, `parse_prefix_list_config`) to a separate Batch
    of nodes and edges. `NxosCollector.normalize()` merges it into the base
    twin. An empty or absent `bgp` gives an empty Batch. This covers a device
    without a `router bgp` stanza, without BGP config or with `feature bgp`
    disabled. `existing_prefix_uids` holds the Prefix uids of the base twin.
    A network or aggregate statement for one of them sets no `kind`, and the
    merge keeps the connected kind."""
    bgp = inter.get("bgp") or {}
    b = GraphBuilder()
    policy_uids = _bgp_route_policy_nodes(b, bgp, dev=dev)

    for proc in bgp.get("processes") or []:
        vname = proc["vrf"] or DEFAULT_VRF
        vru = _ensure_vrf(b, dev, vname, existing_vrf_uids)
        rpu = uid.routing_process(dev, vname, "bgp")
        redistribute, redistribute_gaps = _redistribution_scope(proc)
        b.node(
            "RoutingProcess",
            rpu,
            proto="bgp",
            asn=proc["asn"],
            router_id=proc.get("router_id"),
            # Set when configured. An absent value is the default (gated MED).
            always_compare_med=True if proc.get("always_compare_med") else None,
            **bgp_multipath_props(proc.get("maximum_paths") or {}, bool(proc.get("multipath_relax"))),
            default_information_originate_afs=sorted(proc.get("default_information_originate_afs") or ())
            or None,
            redistribute_protocols=sorted({r["protocol"] for r in redistribute}),
            origin_config_recorded=True,
            origin_afs=[4, 6],
            origin_context_gaps=[*proc["origin_context_gaps"], *redistribute_gaps],
        )
        b.rel("IN_VRF", "RoutingProcess", rpu, "VrfInstance", vru)

        for network in proc["networks"]:
            net = ipaddress.ip_network(network["prefix"], strict=False)
            # A connected subnet keeps its connected kind. The ORIGINATES edge
            # holds the origination, keyed by proto.
            pu = uid.prefix(vru, str(net))
            declared = pu in existing_prefix_uids or b.props("Prefix", pu)
            b.node(
                "Prefix",
                pu,
                cidr=str(net),
                af=net.version,
                kind=None if declared else "bgp-network",
                anchor=vru,
            )
            b.rel(
                "ORIGINATES",
                "VrfInstance",
                vru,
                "Prefix",
                pu,
                key={"proto": "network"},
                proto="network",
                route_map=network.get("route_map"),
            )
            if network.get("route_map"):
                _bgp_filter(
                    b,
                    start_label="RoutingProcess",
                    start_uid=rpu,
                    policy_uids=policy_uids,
                    name=network["route_map"],
                    kind="route-map",
                    key={"direction": "redistribute", "protocol": "network"},
                )
        for aggregate in proc["aggregates"]:
            net = ipaddress.ip_network(aggregate["prefix"], strict=False)
            # A connected subnet keeps its connected kind. The ORIGINATES edge
            # holds the origination, keyed by proto.
            pu = uid.prefix(vru, str(net))
            declared = pu in existing_prefix_uids or b.props("Prefix", pu)
            b.node(
                "Prefix",
                pu,
                cidr=str(net),
                af=net.version,
                kind=None if declared else "aggregate",
                anchor=vru,
            )
            b.rel(
                "ORIGINATES",
                "VrfInstance",
                vru,
                "Prefix",
                pu,
                key={"proto": "aggregate"},
                proto="aggregate",
                summary_only=aggregate["summary_only"],
                as_set=aggregate["as_set"],
                attribute_map=aggregate.get("attribute_map"),
                unsupported_options=aggregate.get("unsupported_options", []),
            )
            _bgp_filter(
                b,
                start_label="RoutingProcess",
                start_uid=rpu,
                policy_uids=policy_uids,
                name=aggregate.get("attribute_map"),
                kind="route-map",
                key={"direction": "redistribute", "protocol": "aggregate"},
            )

        for protocol in sorted({r["protocol"] for r in redistribute}):
            rm = next((r["route_map"] for r in redistribute if r["protocol"] == protocol), None)
            if not rm:
                continue
            b.node("RoutingProcess", rpu, **{f"redist_{protocol}_route_map": rm})
            _bgp_filter(
                b,
                start_label="RoutingProcess",
                start_uid=rpu,
                policy_uids=policy_uids,
                name=rm,
                kind="route-map",
                key={"direction": "redistribute", "protocol": protocol},
            )

        # `session_gaps` holds each configured neighbor without a BgpSession.
        # The RoutingProcess records them for the simulation.
        session_gaps: list[str] = []
        for n in expand_dynamic_neighbors(
            proc["neighbors"],
            (inter.get("bgp_observed") or {}).get("sessions") or [],
            vname,
            report_missing=True,
        ):
            network = peer_network(n["peer_ip"])
            if n.get("inheritance_gaps") and network is None:
                logger.warning("nxos: neighbor %s has unresolved template inheritance; skipped", n["peer_ip"])
                session_gaps.append(
                    f"neighbor {n['peer_ip']} has unresolved template inheritance "
                    f"({'; '.join(n['inheritance_gaps'])})"
                )
                continue
            if n["remote_as"] is None and network is None:
                # Batfish's conversion emits no VI peer for a neighbor with no
                # remote AS (uid.py bgp_session's docstring).
                if n.get("remote_as_unread"):
                    reason = f"remote-as {n['remote_as_unread']!r} is not an AS number"
                elif n.get("remote_as_route_map"):
                    reason = f"remote-as route-map {n['remote_as_route_map']} applies to a prefix peer only"
                else:
                    reason = "has no remote-as"
                logger.warning(
                    "nxos: %s neighbor %s %s; peer dropped, no BgpSession node",
                    rpu,
                    n["peer_ip"],
                    reason,
                )
                session_gaps.append(f"neighbor {n['peer_ip']} {reason}")
                continue
            try:
                if network is None:
                    ipaddress.ip_address(n["peer_ip"])
            except ValueError:
                logger.warning(
                    "nxos: %s neighbor %s is not a single address; peer dropped, no BgpSession node",
                    rpu,
                    n["peer_ip"],
                )
                session_gaps.append(f"neighbor {n['peer_ip']} is not a single address")
                continue
            # A route-map is the session policy of its direction and a lone
            # prefix-list is the policy when there is no route-map. Batfish
            # honors only the route-map when both are attached.
            # The engine applies the prefix-list first.
            in_name = n["route_map_in"] or n["prefix_list_in"]
            in_kind = "route-map" if n["route_map_in"] else "prefix-list" if n["prefix_list_in"] else None
            out_name = n["route_map_out"] or n["prefix_list_out"]
            out_kind = "route-map" if n["route_map_out"] else "prefix-list" if n["prefix_list_out"] else None
            in_beside = n["prefix_list_in"] if n["route_map_in"] else None
            out_beside = n["prefix_list_out"] if n["route_map_out"] else None
            # The families that the neighbor activates in its block or through
            # a template. NX-OS exchanges no route for a family that the
            # neighbor does not activate. A neighbor without a family gets an
            # empty list. A neighbor whose template is not in the capture is
            # recorded in `session_gaps` above and skipped.
            afi_safi = sorted(f.replace(" ", "-") for f in n.get("address_families") or ())
            peer_label, su = emit_bgp_peer(
                b,
                rpu,
                vname,
                peer_ip=n["peer_ip"],
                local_asn=proc["asn"],
                peer_asn=n["remote_as"],
                afi_safi=afi_safi,
                state="shutdown" if n.get("shutdown") else None,
                **{
                    k: n[k]
                    for k in (
                        "dynamic_range",
                        "observed_state",
                        "remote_as_route_map",
                        "inheritance_gaps",
                        "next_hop_self",
                    )
                    if k in n
                },
                import_policy_name=in_name,
                import_policy_kind=in_kind,
                export_policy_name=out_name,
                export_policy_kind=out_kind,
                import_prefix_list_name=in_beside,
                export_prefix_list_name=out_beside,
                import_filter_list_name=n.get("filter_list_in"),
                export_filter_list_name=n.get("filter_list_out"),
                route_reflector_client=reflector_client(n),
                cluster_id=proc.get("cluster_id"),
                peer_router_id=observed_peer_router_id(inter.get("bgp_observed"), vname, n["peer_ip"]),
            )
            for direction, beside in (("in", in_beside), ("out", out_beside)):
                # The prefix-list edge has its own key. The `direction: 'in'` edge
                # stays the session policy.
                _bgp_filter(
                    b,
                    start_label=peer_label,
                    start_uid=su,
                    policy_uids=policy_uids,
                    name=beside,
                    kind="prefix-list",
                    key={"direction": f"{direction}-prefix-list"},
                )
            if in_name:
                _bgp_filter(
                    b,
                    start_label=peer_label,
                    start_uid=su,
                    policy_uids=policy_uids,
                    name=in_name,
                    kind=in_kind,
                    key={"direction": "in"},
                )
            if out_name:
                _bgp_filter(
                    b,
                    start_label=peer_label,
                    start_uid=su,
                    policy_uids=policy_uids,
                    name=out_name,
                    kind=out_kind,
                    key={"direction": "out"},
                )
        if session_gaps:
            b.node("RoutingProcess", rpu, session_gaps=session_gaps)

    return b.batch(source, scope)


class NxosConfig(SshSourceConfig):
    # The MTU, protocol and policy reads are optional. The parse reads them from a
    # stored capture in every case.
    capture_mtu: bool = False
    # NX-OS 9.3 and later support `| json native`.
    json_native: bool = False


class _NativeJsonSession:
    """The session of `_afetch_over` when `json_native` is set. Its async `run`
    rewrites every `| json` command to `| json native` before it sends the
    command. The caller keys its payload by the original command."""

    def __init__(self, session: Any) -> None:
        self._session = session
        self.host_key = getattr(session, "host_key", "")
        self.jump_host_key = getattr(session, "jump_host_key", "")

    @staticmethod
    def rewrite(command: str) -> str:
        return f"{command} native" if command.endswith(" | json") else command

    async def run(self, command: str) -> str:
        return await self._session.run(self.rewrite(command))


@register
class NxosCollector(CiscoCliCollector):
    # Every `| json` answer starts with the same `{` line. The banner strip
    # would remove that line as a banner. See `SshCliCollector.STRIP_EXEC_BANNER`.
    STRIP_EXEC_BANNER: ClassVar[bool] = False
    # Version 3 re-normalizes stored captures with the per-port payload MTU
    # profile and the scoped reading of the system-jumbo and network-QoS
    # parameters.
    PARSER_VERSION = "3"
    NORMALIZATION_VERSIONS: ClassVar[dict[str, str]] = {
        # The '.' of a subinterface name stays in the Interface and Port uid.
        "iface_uid": uid.IFACE_UID_VERSION,
        "mtu": MTU_NORMALIZATION_VERSION,
        "bgp_dynamic_peers": "1",
        # An OSPF process is keyed by its id.
        "ospf_process": "1",
        # A path that is not the unicast best path has no RIB row.
        "rib_best": "1",
        # Interface and Port have the interface description.
        "port_description": "1",
        # A refused always-present command reads unauthorized. A refusal that
        # is recorded `ok` reads as the refusal. The side tables are judged by
        # the sections that feed them. In version 2 a refused access list read
        # or VLAN filter read reads unauthorized.
        "read-failures": "2",
        # Interface access lists have their installation evidence.
        "acl_installation": "1",
        # The position of a NAT rule is its evaluation order, with static rules first.
        "nat_position": "1",
        # BgpSession has route-reflector-client, a filter-list and a prefix-list
        # beside a route-map.
        "bgp_session_filters": "1",
        # A placeholder serial identifies no chassis. When 2 devices report the
        # same serial in one run, the later device is keyed by its ref.
        "serial": "1",
        # The `<address>%<vrf>` next hop of a leaked route is split.
        "rib_next_hop_vrf": "1",
        # BgpSession has the cluster id. RoutingProcess has the neighbors
        # without a session.
        "bgp_cluster_id": "1",
        # A redistribution keeps its address family and instance tag. A
        # neighbor has the address families that it activates.
        "bgp_address_family": "1",
        # The OSPF commands ask for every VRF. The process of a tenant VRF has
        # its areas, interfaces, adjacencies and LSAs.
        "ospf_vrf_scope": "1",
        # RoutingProcess records maximum-paths and multipath-relax.
        "bgp_multipath": "1",
        # BgpSession has the router id of the peer from the neighbor output.
        "bgp_peer_router_id": "1",
    }
    NORMALIZATION_OUTCOME_KEYS = (*COMMANDS, *MTU_COMMANDS["nxos"].values())

    def sections(self, raw):
        inter = self._inter(raw)
        sections = {
            # The answers of a payload with the `LEGACY_OSPF_COMMANDS`
            # spellings are read as the answers of the current commands.
            **build_sections(_ospf_aliased(raw), inter, self.SECTIONS, self.ALWAYS_PRESENT_COMMANDS),
            **mtu_sections(raw, inter, family=self.name),
        }
        # The recorded outcome of the CDP command is `ok`. The note in place of
        # the table shows that the device does not run CDP.
        note = cdp_off_note(raw.get(CMD_CDP))
        if note is not None:
            sections["cdp"] = SectionOutcome(status="unsupported", detail=note)
        return annotate_fhrp_sections(sections, inter, {"hsrp": "hsrp", "vrrp": "vrrp"})

    name = "nxos"
    ConfigModel = NxosConfig
    KIND = "group"
    COMMANDS = COMMANDS
    # The age columns of the MAC and ARP tables, the last-read, last-write and
    # last-flap columns of the BGP session table and the ages of the route
    # table change on every fetch. The BGP path tables change with every route
    # that the peers send. No graph object is built from these answers. The
    # MAC, ARP, route and path texts feed the `mac`, `arp`, `rib` and
    # `bgp_session_routes` side tables alone. The session table feeds the
    # graph through its dynamic peers alone. `stamp_dynamic_observations`
    # keeps those peers in the change hash as `_strata_dynamic_bgp`. Each of
    # these keys is an observation key as well. Its side-store rows are
    # covered by `obs_sha`. The recorded outcome of the route command stays
    # in the change hash through NORMALIZATION_OUTCOME_KEYS. The uptime in
    # `show version` changes on every fetch and is not declared. The Device
    # node is built from that answer, and the answer stays in the change
    # hash. The batch digest (`graph_sha`) skips the graph write of an
    # unchanged device. Both session-table commands are declared. A key that
    # a payload does not hold changes neither hash.
    VOLATILE_RAW_KEYS = (
        CMD_MAC,
        CMD_ARP,
        CMD_ROUTE,
        CMD_BGP_SESSIONS,
        CMD_BGP_SESSIONS_DEFAULT_VRF,
        CMD_BGP_NEIGHBORS,
    )
    VOLATILE_RAW_KEY_PATTERN = BGP_OBSERVATION_KEY_RE
    # The observations of the switch are the ARP table, the MAC table, the
    # RIB, the BGP session state and the BGP path tables. The change hash
    # excludes all of them. A session that flapped, an endpoint that moved or
    # a route that changed reaches the side store through this hash. The path
    # commands contain peers that the same fetch discovers.
    # BGP_OBSERVATION_KEY_RE matches them.
    #
    # The OSPF link-state reads are observations and are not declared. They
    # are not volatile, and a change in them takes the full path. The BGP
    # neighbor detail is declared. It is volatile, and the change hash covers
    # the router ids of its answer alone (`stamp_peer_router_ids`).
    OBSERVATION_RAW_KEYS = (
        CMD_ARP,
        CMD_MAC,
        CMD_ROUTE,
        CMD_BGP_SESSIONS,
        CMD_BGP_SESSIONS_DEFAULT_VRF,
        CMD_BGP_NEIGHBORS,
    )
    OBSERVATION_RAW_KEY_PATTERN = BGP_OBSERVATION_KEY_RE
    # A device with LLDP or CDP disabled, or a credential without ARP
    # privilege, still gives its interfaces, VRFs and routes. The stand-ins
    # parse to empty tables. `_rows` returns [] for `{}`. The "" of a
    # plain-text extract splits to no lines and builds an empty `_config_tree`.
    OPTIONAL_COMMANDS: ClassVar[dict[str, str]] = {
        CMD_LLDP: "{}",
        CMD_CDP: "{}",
        CMD_ARP: "{}",
        CMD_NAT: "",
        CMD_ACL: "{}",
        CMD_BGP: "",
        CMD_RPM: "",
        CMD_INTERFACE_CONFIG: "",
        CMD_VLAN_FILTER: "",
        # A device without `feature ospf` refuses every OSPF command. The
        # stand-ins parse to no processes, no adjacencies and no LSAs.
        CMD_OSPF: "{}",
        CMD_OSPF_IF: "{}",
        CMD_OSPF_NBR: "{}",
        CMD_OSPF_DB_ROUTER: "{}",
        CMD_OSPF_DB_NETWORK: "{}",
        CMD_OSPF_DB_SUMMARY: "{}",
        CMD_OSPF_DB_EXTERNAL: "{}",
        CMD_OSPF_DB_NSSA: "{}",
        CMD_OSPF_DB_ASBR_SUMMARY: "{}",
        CMD_OSPF_CONFIG: "",
        # A device without trunk ports can give no answer to the trunk command.
        # The port list of each VLAN in `show vlan` holds the membership.
        CMD_TRUNK: "{}",
        # A device without HSRP, VRRP or vPC refuses the command of the
        # feature. The stand-ins parse to no groups and no domain. The recorded
        # outcome is `unsupported`.
        CMD_HSRP: "{}",
        CMD_VRRP: "{}",
        CMD_VPC: "{}",
    }
    # The reads that NX-OS answers on every release with any feature set. They
    # are the interface stanzas, the Route Policy Manager, the access lists and
    # the VLAN filters. The gates are built from them. The feature-scoped
    # extracts (`nat`, `bgp`, `ospf`) are excluded. A device without the
    # feature refuses them, and the refusal is `unsupported`.
    ALWAYS_PRESENT_COMMANDS: ClassVar[frozenset[str]] = frozenset(
        {CMD_INTERFACE_CONFIG, CMD_RPM, CMD_ACL, CMD_VLAN_FILTER, *MTU_ALWAYS_PRESENT["nxos"]}
    )
    # NX-OS reads the MAC table. The `mac` table is judged by its section.
    TABLE_SECTIONS: ClassVar[dict[str, tuple[str, ...]]] = {
        **CiscoCliCollector.TABLE_SECTIONS,
        "mac": ("mac_table",),
    }
    SECTIONS = SECTIONS
    # The structural sections of the payload are the interfaces, their VRF
    # membership, the VRFs, the VLANs, the RIB and the MAC table. Each one
    # comes from a required command. Neighbors, ARP, NAT, ACLs and the BGP
    # extracts are optional. The loss of an optional section degrades the
    # device.
    AUTHORITATIVE_SECTIONS = (
        "device",
        "interfaces",
        "vrf_interfaces",
        "vlans",
        "vrfs",
        "rib",
        "mac_table",
    )
    # The OSPF link-state database and the 2 BGP observation tables are added
    # to the 3 tables of every Cisco family.
    SIDE_TABLES = (
        *CiscoCliCollector.SIDE_TABLES,
        OSPF_LSDB_TABLE,
        BGP_ROUTES_TABLE,
        BGP_SESSIONS_TABLE,
    )
    # The labels that each optional section owns alone, for the section-level
    # carry (`Collector.SECTION_LABELS`). `neighbors` and `arp` own no label. A
    # neighbor merges LLDP properties onto a Port of the `interfaces` section
    # (cisco_common `_neighbor_stage` drops a neighbor whose port it cannot
    # match). ARP writes side-store rows and no graph objects. Each other
    # entry is the node set that is lost when its section does not answer.
    #
    # `acl` and `interface_config` share a set. They build one stage together
    # (cisco_common `acl_stage`). The ACL bodies come from `acl` and the
    # interface bindings from `interface_config`. The loss of either one loses
    # the same objects. `FwRulebase`, `RoutePolicy`, `Prefix`, `IpAddress`,
    # `VrfInstance` and `RoutingDomain` are absent. More than one section
    # writes each of them. A carry of such a label would restore the objects
    # of a section that answered.
    #
    # The OSPF sections are absent.
    SECTION_LABELS: ClassVar[dict[str, tuple[str, ...]]] = {
        "neighbors": (),
        "cdp": (),
        "arp": (),
        "nat": ("NatRule",),
        "acl": ("FwRule", "NetObject", "SvcObject"),
        "interface_config": ("FwRule", "NetObject", "SvcObject"),
        "vlan_filter": ("FwRule", "NetObject", "SvcObject"),
        "bgp": ("RoutingProcess", "BgpSession", "BgpPeerRange"),
        "route_maps": ("RoutePolicyEntry",),
        "prefix_lists": ("PrefixListEntry",),
        # `trunks` owns no label. It adds CARRIES edges to the Ports and
        # VlanInstances of the required sections.
        "trunks": (),
        # Both `hsrp` and `vrrp` write `FhrpGroup`, and neither section owns
        # it. The `vpc` section alone writes the vPC domain.
        "hsrp": (),
        "vrrp": (),
        "vpc": ("RedundancyGroup",),
    }

    @staticmethod
    def _parse(raw: dict[str, str]) -> dict[str, Any]:
        return parse(raw)

    def _device_uid(self, inter: dict[str, Any]) -> str:
        """The Device node uid of the rows of this payload. The formula is the
        one of `CiscoCliCollector.side_tables` for the 3 base tables. A BGP
        observation row and a RIB row of one fetch have the same device uid."""
        return device_uid(inter, self.scope, self.identity, self.config.host)

    def side_tables(self, raw: dict[str, str]) -> dict[str, Sequence[dict[str, Any]]]:
        """The 3 Cisco tables (`CiscoCliCollector.side_tables`) and the 2 BGP
        observation tables of this collector."""
        inter = self._inter(raw)
        return {**super().side_tables(raw), **bgp_side_rows(inter, self._device_uid(inter))}

    def table_outcomes(self, raw: dict[str, Any]) -> dict[str, TableOutcome]:
        """The outcomes of the OSPF link-state database (`ospf_table_outcomes`),
        the BGP tables and the 3 directions of each session
        (`bgp_table_outcomes`)."""
        inter = self._inter(raw)
        return {
            **ospf_table_outcomes(raw, inter, self._device_uid(inter)),
            **bgp_table_outcomes(raw, inter, self._device_uid(inter), capture=self.config.capture_bgp),
        }

    async def _afetch_over(self, s) -> dict[str, Any]:
        """Runs the static command loop (`SshCliCollector._afetch_over`), then
        the BGP observation capture with commands from the BGP running-config,
        then the MTU capture when `capture_mtu` is set."""
        if self.config.json_native:
            s = _NativeJsonSession(s)
        raw = await super()._afetch_over(s)
        await self._afetch_bgp_observations(s, raw)
        if self.config.capture_mtu:
            await capture_mtu(s, raw, family=self.name, check=self.check_stop)
        return raw

    async def _afetch_bgp_observations(self, s, raw: dict[str, Any]) -> None:
        """Reads the observed session state. For `capture_bgp` of `all`, also
        reads the 3 path tables of every configured neighbor.

        Every command here is optional in the sense of `OPTIONAL_COMMANDS`. A
        refusal is logged and recorded under `RAW_OUTCOMES_KEY` with the words
        of the device. The payload of the command is an empty stand-in.

        A path command that times out is recorded the same way when every
        command has its own session (an exec channel, or a new connection per
        command). The direction then reads `failed`. On one shell session the
        timeout ends the fetch. The session sends nothing after a timeout
        (`ssh.ShellSession.run`).

        After `PATH_TIMEOUT_LIMIT` timeouts in a row the fetch sends no more
        path commands. Each command that is not sent reads `failed` with the
        reason of `not_sent_after_timeouts`.
        """
        capture = self.config.capture_bgp
        if capture == "none":
            return
        processes = parse_bgp_config(raw.get(CMD_BGP) or "")
        commands = [CMD_BGP_SESSIONS, CMD_BGP_NEIGHBORS]
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
                    raw[cmd] = "{}"
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
                    raw[cmd] = "{}"
                    status, detail = classify_command_failure(exc)
                    if status == "failed" and (
                        _SOFT_RECONFIG_RE.search(detail) or _received_not_retained(cmd, detail)
                    ):
                        # The device does not retain the received table. This is a
                        # limit of the configuration. `_command_outcome` reads
                        # `unsupported` as `not-captured` with the words of the device.
                        status = "unsupported"
                    outcomes[cmd] = {"status": status, "detail": detail}

        await read_commands(commands)
        if (
            outcomes[CMD_BGP_SESSIONS]["status"] == "unsupported"
            and (outcomes.get(CMD_BGP) or {}).get("status") == "ok"
        ):
            # The device runs BGP and refused the `vrf all` clause. One command
            # reads the table of the default VRF.
            await read_commands([CMD_BGP_SESSIONS_DEFAULT_VRF])
        sessions = parse_bgp_sessions(raw.get(bgp_sessions_command(raw)) or "")
        stamp_dynamic_observations(raw, processes, sessions)
        stamp_peer_router_ids(raw, parse_bgp_neighbor_router_ids(raw.get(CMD_BGP_NEIGHBORS) or ""))
        if capture == "all":
            await read_commands(
                [
                    bgp_route_command(vrf, peer, direction)
                    for vrf, peer in bgp_capture_targets(processes, sessions)
                    for direction in BGP_DIRECTION_KEYWORDS
                ],
                timeout_costs_command=session_per_command,
            )

    def normalize(self, raw: dict[str, str]) -> Batch:
        """The base Cisco twin (`CiscoCliCollector.normalize`) merged with the
        batch of the BGP processes, route-maps and prefix-lists (`bgp_stage`)."""
        batch = super().normalize(raw)
        inter = self._inter(raw)
        if not inter.get("bgp"):
            return batch
        dev = next((n.uid for n in batch.nodes if n.label == "Device"), None)
        if dev is None:  # pragma: no cover - normalize_cisco always emits one Device node
            return batch
        existing_vrf_uids = {n.uid for n in batch.nodes if n.label == "VrfInstance"}
        extra = bgp_stage(
            inter,
            dev=dev,
            existing_vrf_uids=existing_vrf_uids,
            source=self.name,
            scope=self.scope,
            existing_prefix_uids={n.uid for n in batch.nodes if n.label == "Prefix"},
        )
        if not extra.nodes and not extra.rels:
            return batch
        merged = batch.model_copy(
            update={"nodes": [*batch.nodes, *extra.nodes], "rels": [*batch.rels, *extra.rels]}
        )
        merged.validate_registry()
        return merged

    def probe(self) -> str:
        version = _json_payload(self._run(CMD_VERSION), CMD_VERSION)
        return version.get("nxos_ver_str") or version.get("sys_ver_str") or "connected (empty version output)"
