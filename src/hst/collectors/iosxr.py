"""The IOS-XR collector parses the answers of its show commands offline. It
uses ntc-templates where a template exists and text parsing for the other
commands.

`show vrf all detail` also gives the VRF of each interface (`iosxe.py`).

Command forms of IOS-XR:

  - `show vrf all detail` and `show route vrf all ipv4` have the `all`
    keyword. IOS-XE has no `all` keyword. The route command of XR needs the
    address family.
  - The ntc-templates `show arp` template reads `show arp vrf all`.

The serial comes from `show inventory`, which has one record per FRU
(`name`/`descr`/`pid`/`vid`/`sn`). `_chassis_serial()` returns the `sn` of the
entry with the name `"Rack 0"`, the chassis name on physical and virtual XR
platforms. The hostname comes from `show running-config hostname`, an optional
command. A device whose answer has no hostname gets the host that the
collector reached as its name (`cisco_common.mint_name`).

When `show inventory` has no `"Rack 0"` entry or the entry has no `sn`,
`inter["device"]["serial"]` is `None`. The registry keys the device by the ref
of `cisco_common.fallback_device_uid()`, which holds the scope
(`iosxr:<host>`).

FIRST CONTACT: one capture per command.

    ssh <user>@<host> 'show version' \
      > data/raw/iosxr/first-contact/show-version.txt
    # repeat once per entry in COMMANDS, one file per command:
    #   show-interfaces.txt, show-lldp-neighbors-detail.txt,
    #   show-vrf-all-detail.txt, show-route-vrf-all-ipv4.txt,
    #   show-arp.txt, show-cdp-neighbors-detail.txt, show-inventory.txt,
    #   show-ospf.txt, show-ospf-interface.txt, show-ospf-neighbor.txt,
    #   show-ospf-database-router-detail.txt, show-ospf-database-network-detail.txt,
    #   show-ospf-database-summary-detail.txt, show-ospf-database-asbr-summary-detail.txt,
    #   show-ospf-database-external-detail.txt, show-ospf-database-nssa-external-detail.txt,
    #   show-run-router-ospf.txt, show-hsrp.txt
    #
    # The HSRP summary goes through the ntc-templates `cisco_xr_show_hsrp`
    # template (CMD_HSRP).

The mapping handles these TextFSM differences. The XR CDP template stores the
`Device ID` in `chassis_id`, and `neighbor_name` is a separate capture. The
neighbor name is read from either value. The interfaces template captures
`ip_address` as one `addr/plen` string. The IOS-XE template splits the 2
parts. Route records have one-letter protocol codes, which
`cisco_common.expand_protocol` expands. The repository copy of the route
template (`templates/`) records each line that no rule reads, and each further
path line after it. The `rib` section is then `partial` with the count
(`RIB_UNREAD_KEY`). An answer with no readable line fails the device
(`cli_parse.parse_with_unread`).
"""

from __future__ import annotations

import functools
import ipaddress
import logging
import re
from collections.abc import Iterator, Sequence
from typing import Any, ClassVar

from hst.core import uid
from hst.core.l3domain import DEFAULT_VRF
from hst.core.manifest import BGP_ROUTES_TABLE, BGP_SESSIONS_TABLE, OSPF_LSDB_TABLE, bgp_direction_key
from hst.core.model import SectionOutcome, TableOutcome
from hst.core.mtu import MTU_NORMALIZATION_VERSION
from hst.core.normalize import IfNameResolver

from . import cisco_bgp_table, cli_parse, iosxr_bgp, ssh, streams
from .base import RAW_OUTCOMES_KEY, register
from .cisco_bgp import (
    expand_dynamic_neighbors,
    nest_router_ids,
    parse_neighbor_router_ids,
    stamp_dynamic_observations,
    stamp_peer_router_ids,
)
from .cisco_common import (
    MTU_ALWAYS_PRESENT,
    MTU_COMMANDS,
    RIB_EMPTY_ANSWER,
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
    ospf_lsa_detail_rows,
    parse_access_groups,
    parse_mtu,
    parse_ospf_interface_text,
    parse_ospf_process_text,
    parse_ospf_redistribute_config,
    rib_row,
    stamp_ospf_vrfs,
    vrf_of,
    vrf_rt_fields,
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
from .util import canonical_mac, lpm_columns

logger = logging.getLogger(__name__)

CMD_VERSION = "show version"
CMD_INTERFACES = "show interfaces"
CMD_LLDP = "show lldp neighbors detail"
CMD_VRF = "show vrf all detail"
CMD_ROUTE = "show route vrf all ipv4"
# `show arp` prints only the table of the default VRF. `vrf all` adds the
# table of every VRF. The VRF of a row is read from its interface (`arp_row`).
#
# The `show arp` template reads the per-node headers of `vrf all`.
CMD_ARP = "show arp vrf all"
# The ARP key of a payload with only the default VRF. It is read when CMD_ARP is absent.
_CMD_ARP_DEFAULT_VRF = "show arp"
CMD_CDP = "show cdp neighbors detail"
CMD_INVENTORY = "show inventory"
# No other command of this collector gives the hostname. The command is
# optional. When the credential cannot read the running-config, the device gets
# the host that the collector reached as its name.
CMD_HOSTNAME = "show running-config hostname"
# Filtered running-config extracts. Each one is plain text for one stanza, and
# iosxr_bgp.py parses it offline.
CMD_BGP = "show running-config router bgp"
CMD_PREFIX_SET = "show running-config prefix-set"
CMD_ROUTE_POLICY = "show running-config route-policy"
# The community sets and the AS-path sets that `community matches-any NAME` and
# `as-path in NAME` of a route-policy reference. A fetch sends both commands
# only when the route-policy text references a set (`iosxr_bgp.names_a_set`).
# Both commands are optional.
CMD_COMMUNITY_SET = "show running-config community-set"
CMD_AS_PATH_SET = "show running-config as-path-set"

# The interface filter bindings (`ipv4|ipv6 access-group <name> ingress|egress`),
# each with its `interface` stanza line, for `cisco_common.parse_access_groups`.
# The access list bodies are not collected, and a bound list is judged by the
# opaque placeholder rule. The `include` filter makes this command differ from
# the unfiltered `show running-config interface` of the opt-in MTU capture
# (MTU_COMMANDS). The unfiltered command in the payload marks MTU as captured.
#
# IOS-XR documents the quoted alternation as the regex form of `include`.
CMD_INTERFACE_CONFIG = 'show running-config interface | include "^interface |access-group"'
# First-hop redundancy. The command is optional. A device with no group answers
# with an empty table. ntc-templates has no VRRP summary template for XR, and
# VRRP is not captured.
#
# The ntc-templates index maps the command to `cisco_xr_show_hsrp`
# (INTERFACE, GROUP, PRIO, PREEMPT, STATE, ACTIVE_ADDR, STANDBY_ADDR,
# GROUP_ADDR).
CMD_HSRP = "show hsrp"
# The 10 OSPF commands are optional.
CMD_OSPF = "show ospf"
CMD_OSPF_IF = "show ospf interface"
CMD_OSPF_NBR = "show ospf neighbor"
# `detail` prints the LSA bodies that SPF needs. `ospf_lsa_detail_rows`
# (`cisco_common.py`) parses each of the 6 commands.
CMD_OSPF_DB_ROUTER = "show ospf database router detail"
CMD_OSPF_DB_NETWORK = "show ospf database network detail"
CMD_OSPF_DB_SUMMARY = "show ospf database summary detail"
CMD_OSPF_DB_ASBR_SUMMARY = "show ospf database asbr-summary detail"
CMD_OSPF_DB_EXTERNAL = "show ospf database external detail"
CMD_OSPF_DB_NSSA_EXTERNAL = "show ospf database nssa-external detail"
# The answer holds `router-id` and `redistribute ... route-policy <name>`
# (`cisco_common.parse_ospf_redistribute_config`).
CMD_OSPF_CONFIG = "show running-config router ospf"

# The optional commands that every IOS-XR release has. They are the
# running-config extracts, including the interface bindings. An extract answers
# empty for a stanza that is not configured. The refusal of one of these
# commands is `unauthorized` (`cli_collector.classify_command_failure`).
ALWAYS_PRESENT_COMMANDS: frozenset[str] = frozenset(
    {
        CMD_BGP,
        CMD_PREFIX_SET,
        CMD_ROUTE_POLICY,
        CMD_OSPF_CONFIG,
        CMD_INTERFACE_CONFIG,
        *MTU_ALWAYS_PRESENT["iosxr"],
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
    CMD_ROUTE,
    CMD_ARP,
    CMD_CDP,
    CMD_INVENTORY,
    CMD_HOSTNAME,
    CMD_BGP,
    CMD_PREFIX_SET,
    CMD_ROUTE_POLICY,
    *OSPF_COMMANDS,
    CMD_HSRP,
    CMD_INTERFACE_CONFIG,
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

# Maps a section name to its command and to the intermediate-shape list of its
# rows. A section without a rows list is `empty` when the command returned no
# output. The LLDP rows and the CDP rows go into one merged `neighbors` list,
# and neither section has a rows list.
SECTIONS: dict[str, Section] = {
    "device": Section(CMD_VERSION),
    "inventory": Section(CMD_INVENTORY),
    "hostname": Section(CMD_HOSTNAME),
    # A device always has interfaces. An answer without interfaces is `malformed`.
    "interfaces": Section(CMD_INTERFACES, "interfaces", empty_answer=()),
    "vrfs": Section(CMD_VRF, "vrfs"),
    "rib": Section(CMD_ROUTE, "rib", empty_answer=RIB_EMPTY_ANSWER),
    "arp": Section(CMD_ARP, "arp"),
    "lldp": Section(CMD_LLDP),
    "cdp": Section(CMD_CDP),
    "bgp": Section(CMD_BGP),
    "prefix_sets": Section(CMD_PREFIX_SET),
    "route_policies": Section(CMD_ROUTE_POLICY),
    **OSPF_SECTIONS,
    "hsrp": Section(CMD_HSRP),
    "interface_config": Section(CMD_INTERFACE_CONFIG),
}

# The `name` of the chassis record in the `show inventory` output.
_CHASSIS_ENTRY = "Rack 0"


def _chassis_serial(inventory_rows: list[dict[str, Any]]) -> str | None:
    entry = next((r for r in inventory_rows if r.get("name") == _CHASSIS_ENTRY), {})
    return entry.get("sn") or None


# --- BGP session and path observations: the per-neighbor capture -----------
#
# These parsers read the session state and the paths. `bgp_side_rows` maps them
# onto the side-store tables `bgp_sessions` and `bgp_session_routes`. The
# summary command and the path commands of a VRF have the clause
# `vrf <name> ipv4 unicast` (`bgp_summary_command`, `bgp_route_command`).
#
# `cisco_bgp_table.path_rows` takes the column positions from the header line and
# reads rows up to 2 columns right of it.

CMD_BGP_SESSIONS = "show bgp summary"


# The neighbor detail of the default VRF and of every other VRF. Each block has
# its VRF in its header and the router ID of the peer on a `Remote router ID`
# line (`cisco_bgp.parse_neighbor_router_ids`). No other command of this
# collector gives the router ID of the peer. The counters of both answers
# change on every fetch, and both keys are volatile. `stamp_peer_router_ids`
# keeps the router IDs in the change hash.
CMD_BGP_NEIGHBORS = "show bgp neighbors"
CMD_BGP_VRF_NEIGHBORS = "show bgp vrf all neighbors"


def bgp_summary_command(vrf: str = DEFAULT_VRF) -> str:
    return CMD_BGP_SESSIONS if not vrf or vrf == DEFAULT_VRF else f"show bgp vrf {vrf} ipv4 unicast summary"


# Maps each of the 3 directions of a session to its per-neighbor command
# keyword. IOS-XR writes the received direction as 2 words, "received routes".
# `received` needs soft reconfiguration inbound on the neighbor. Without it,
# IOS-XR does not keep the pre-policy table and answers with a `%` line. The
# direction is then `not-captured`.
BGP_DIRECTION_KEYWORDS: dict[str, str] = {
    "received": "received routes",
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
# Every command of the BGP observation capture reads the IPv4 unicast paths of
# one VRF. The command has `vrf <name> ipv4 unicast` for a VRF other than the
# default. The sub-family of every observed row is this constant. It is not
# parsed from the output.
BGP_SAFI = "unicast"


def bgp_route_command(peer_ip: str, direction: str, vrf: str = DEFAULT_VRF) -> str:
    """Return the per-neighbor path command for one direction, `show bgp
    [vrf <vrf> ipv4 unicast] neighbors <peer>
    received routes|routes|advertised-routes`. The command has the VRF clause
    for every VRF except the default."""
    scope = "" if not vrf or vrf == DEFAULT_VRF else f"vrf {vrf} ipv4 unicast "
    return f"show bgp {scope}neighbors {peer_ip} {BGP_DIRECTION_KEYWORDS[direction]}"


# Matches every raw key that the BGP observation capture derives per fetch.
# The keys are the session summary of each VRF (`bgp_summary_command`) and the
# path command of each peer and direction (`bgp_route_command`). No other
# command of this collector matches.
BGP_OBSERVATION_KEY_RE = re.compile(
    r"show bgp (?:vrf \S+ ipv4 unicast )?(?:summary|neighbors \S+ (?:"
    + "|".join(map(re.escape, BGP_DIRECTION_KEYWORDS.values()))
    + r"))"
)


def _bgp_scopes(bgp: dict[str, Any] | None) -> list[tuple[str, int]]:
    """Return (VRF, 4) for each IPv4 process, including a VRF with only
    passive ranges. Without a process, return the default VRF."""
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
    """Return (VRF, address family, peer) for every peer of every configured
    process, in configuration order and without duplicates. The result
    includes the dynamic peers of `observed` that match a listen range.

    `iosxr_bgp.parse_bgp` reads the block of an IPv6 neighbor into the same
    process as the IPv4 neighbors. A neighbor has IPv4 unicast when it has
    `address-family ipv4 unicast`, on the neighbor or through its groups.
    `iosxr_bgp.resolve_bgp_sessions` resolves this into the `afi_safi` of the
    session. An IPv6 neighbor without IPv4 unicast is an IPv6 session with
    address family 6 and gets no IPv4 path command. An IPv6 neighbor with IPv4
    unicast is read as an IPv4 neighbor."""
    out: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int, str]] = set()
    for process in (bgp or {}).get("processes") or ([bgp] if bgp else []):
        vrf, af = process.get("vrf") or DEFAULT_VRF, int(process.get("af") or 4)
        expanded = expand_dynamic_neighbors(
            process.get("neighbors") or [], observed or [], vrf, peer_key="addr"
        )
        ipv4_unicast = {
            session["peer_ip"]
            for session in iosxr_bgp.resolve_bgp_sessions({**process, "neighbors": expanded})
            if "ipv4-unicast" in session["afi_safi"]
        }
        for peer_ip in bgp_capture_targets({**process, "neighbors": expanded}):
            ipv6_only = ipaddress.ip_address(peer_ip).version == 6 and peer_ip not in ipv4_unicast
            target = (vrf, 6 if ipv6_only else af, peer_ip)
            if target not in seen:
                seen.add(target)
                out.append(target)
    return out


def bgp_capture_targets(bgp: dict[str, Any] | None) -> list[str]:
    """Return the neighbor addresses of one process, in configuration order
    and without duplicates. The addresses come from the raw neighbor list of
    `iosxr_bgp.parse_bgp`, before `resolve_bgp_sessions` applies the
    inheritance chain of neighbor-group, af-group and session-group.
    `cisco_common.bgp_stage` builds the BgpSession nodes of the graph from the
    same shape. A neighbor address that is not a single address is skipped. A
    fetch requests the path tables of the neighbors with IPv4 unicast
    (`_bgp_scoped_targets`)."""
    out: list[str] = []
    seen: set[str] = set()
    for n in (bgp or {}).get("neighbors") or []:
        peer_ip = n.get("addr") or ""
        try:
            ipaddress.ip_address(peer_ip)
        except ValueError:
            continue
        if peer_ip not in seen:
            seen.add(peer_ip)
            out.append(peer_ip)
    return out


_BGP_SESSION_ROW_RE = re.compile(
    r"^\*?(?P<peer>\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+(?P<asn>\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(?P<state>\S+)\s*$"
)


def _bgp_session_state(value: str) -> tuple[str, int | None]:
    """One column of the IOS-XR summary table holds the number of prefixes
    received for an Established session and the connection state word
    (`Idle`, `Active`, `Connect`) otherwise."""
    if value.isdigit():
        return "Established", int(value)
    return value, None


def parse_bgp_sessions(text: str) -> list[dict[str, Any]]:
    """Return one observed-session record per neighbor of an IPv4 unicast
    session summary (`bgp_summary_command`). `_BGP_SESSION_ROW_RE` reads each
    neighbor row (`Neighbor Spk AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down St/PfxRcd`).

    `established_since_ms`, `prefixes_advertised` and `capabilities` are None.
    The command reports a relative up/down duration and no advertised count or
    capabilities.
    """
    out: list[dict[str, Any]] = []
    for raw_line in text.splitlines():
        m = _BGP_SESSION_ROW_RE.match(raw_line.strip())
        if not m:
            continue
        state, prefixes_received = _bgp_session_state(m["state"])
        out.append(
            {
                "peer_ip": m["peer"],
                "state": state,
                "peer_asn": int(m["asn"]),
                "established_since_ms": None,
                "prefixes_received": prefixes_received,
                "prefixes_advertised": None,
                "capabilities": None,
            }
        )
    return out


def _count_bgp_paths(text: str) -> int:
    """Return the count of the path rows that `iter_bgp_paths` yields for this
    payload. The count builds no row dict."""
    return sum(1 for _ in cisco_bgp_table.path_rows(text))


def iter_bgp_paths(text: str, *, peer_ip: str, direction: str) -> Iterator[dict[str, Any]]:
    """Yield one record per path of each prefix of a `bgp_route_command`
    payload. Each record is built when its line is read
    (`cisco_bgp_table.path_rows`). `_direction_rows` adds the VRF.

    The table has no per-path identifier and no community list. `path_id` and
    `communities` are None. A blank metric or local preference is None.
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
            # `best` is None for the received direction and for a table without
            # a status column (nxos.py `_bgp_best`).
            "best": None if received or status is None else ">" in status,
        }


def parse_bgp_paths(text: str, *, peer_ip: str, direction: str) -> list[dict[str, Any]]:
    """`iter_bgp_paths` as a list."""
    return list(iter_bgp_paths(text, peer_ip=peer_ip, direction=direction))


def _direction_rows(text: str, peer_ip: str, direction: str, vrf: str, af: int) -> Iterator[dict[str, Any]]:
    """Yield the observed paths of one session direction with its VRF and
    address family. The result is one part of `routes` in
    `parse_bgp_observations`."""
    for row in iter_bgp_paths(text, peer_ip=peer_ip, direction=direction):
        row.update(vrf=vrf, af=af)
        yield row


def parse_bgp_observations(raw: dict[str, str], bgp: dict[str, Any] | None) -> dict[str, Any]:
    """Return the observed half of the BGP capture for the commands of the
    payload.

    `sessions` is the observed session state and `routes` holds every
    observed path. `directions` has one entry per session and direction that
    the fetch requests, with the row count of that direction. A direction
    whose command is absent from the payload has no row count.

    `routes` is a `streams.ChainRows` view with one part per direction that
    the payload answered. A part reads the text of its command from the
    payload and builds each path when it is read. A pass over `routes` yields
    the paths of every direction in order. The length of `routes` and the row
    count of each direction come from a counting pass that builds no rows. A
    fetch calls this function before a path command is in the payload, and
    nothing is counted then.
    """
    sessions: list[dict[str, Any]] = []
    scopes = _bgp_scopes(bgp)
    for vrf, af in scopes:
        for session in parse_bgp_sessions(raw.get(bgp_summary_command(vrf)) or ""):
            sessions.append({**session, "vrf": vrf, "af": af})
    parts: list[tuple[int, functools.partial[Iterator[dict[str, Any]]]]] = []
    directions: list[dict[str, Any]] = []
    for vrf, af, peer_ip in _bgp_scoped_targets(bgp, sessions):
        for direction in BGP_DIRECTION_KEYWORDS:
            command = bgp_route_command(peer_ip, direction, vrf)
            entry: dict[str, Any] = {
                "peer_ip": peer_ip,
                "vrf": vrf,
                "af": af,
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
    if ids := parse_neighbor_router_ids(raw.get(CMD_BGP_NEIGHBORS), raw.get(CMD_BGP_VRF_NEIGHBORS)):
        observed["peer_router_ids"] = nest_router_ids(ids)
    return observed


def _bgp_session_uid(device_uid: str, peer_ip: str, vrf: str = DEFAULT_VRF) -> str:
    """Return the BgpSession uid that joins an observed row to the graph.
    `cisco_common.bgp_stage` uses the same formula (`uid.bgp_session(uid.
    routing_process(dev, vrf, "bgp"), peer_ip, vrf)`, `cisco_bgp.emit_bgp_peer`)."""
    return uid.bgp_session(uid.routing_process(device_uid, vrf, "bgp"), peer_ip, vrf)


def bgp_side_rows(inter: dict[str, Any], device_uid: str) -> dict[str, Sequence[dict[str, Any]]]:
    """Map the observed BGP records onto the 2 side-store tables, with the
    device, context and session uids. `context_uid` is
    `uid.vrf(device_uid, <the VRF of the session>)`, the formula that
    `cisco_common.side_rows` uses for `rib` and `arp`.

    `bgp_session_routes` is a `streams.MappedRows` view over the observed
    paths. Each row is built when it is read. The context uid is built once
    per VRF, and the session uid once per (peer, VRF)."""
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


# The detail text for a BGP table or direction that a run did not read, by
# capture setting.
_CAPTURE_REASONS: dict[str, str] = {
    "none": "the source's capture_bgp setting is none",
    "sessions": "the source's capture_bgp setting is sessions, which reads session state only",
}

# `_command_outcome` reads an answer without a stripped copy. `\S` matches a
# character for which `str.isspace` is False. `str.strip` removes every other
# character. `_LINE_BREAK_RE` holds every line boundary of `str.splitlines`.
_NON_SPACE_RE = re.compile(r"\S")
_LINE_BREAK_RE = re.compile(r"[\n\r\x0b\x0c\x1c-\x1e\x85\u2028\u2029]")


def _command_outcome(text: Any, recorded: SectionOutcome | None, row_count: int | None) -> TableOutcome:
    """Return the outcome of one observation command from its recorded outcome
    and its answer.

    A command that the platform refused as unknown is `not-captured`. The
    device does not have the feature or does not keep the table. A command
    refused for another reason (a credential without the privilege, a command
    that failed) is `failed`. A command that ran and answered with a `%` line
    and no table is `not-captured`, with the line of the device as detail.
    IOS-XR answers in this way for a received table without soft
    reconfiguration inbound, with a zero exit status and no rejection banner.

    The answer can be a full path table and is not copied. The first non-blank
    character decides the outcome. The detail is the stripped first line of
    the stripped answer.
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


# The detail of a path answer that holds lines shaped like path rows when the
# reader read none of them. `cisco_bgp_table` does not know the layout.
_UNREAD_PATHS = "the answer holds path rows, and none of them could be read"

# The detail for a session of an address family other than IPv4 unicast. The
# session has no observed paths, and the session table leaves it out.
_IPV4_UNICAST_ONLY = "IOS-XR BGP session observation captures IPv4 unicast only"


def bgp_table_outcomes(
    raw: dict[str, Any], inter: dict[str, Any], device_uid: str, *, capture: str
) -> dict[str, TableOutcome]:
    """Return the outcomes of the BGP tables and of the 3 directions of each
    session, as nxos.py does.

    The configured processes are the processes that `parse` read into
    `inter["xr_bgp_processes"]` with the VRF and the address family of
    `iosxr_bgp.parse_bgp`. The BGP configuration is not parsed again."""
    outcomes: dict[str, TableOutcome] = {}
    recorded = effective_outcomes(raw, inter, ALWAYS_PRESENT_COMMANDS)
    observed = inter.get("bgp_observed") or {}
    if capture in _CAPTURE_REASONS:
        detail = _CAPTURE_REASONS[capture]
        outcomes[BGP_ROUTES_TABLE] = TableOutcome(status="not-captured", detail=detail)
        if capture == "none":
            outcomes[BGP_SESSIONS_TABLE] = TableOutcome(status="not-captured", detail=detail)
    if capture != "none":
        # The commands are in fetch order.
        processes = inter.get("xr_bgp_processes")
        scopes = _bgp_scopes({"processes": processes} if processes else None)
        summary_commands = dict.fromkeys([CMD_BGP_SESSIONS, *(bgp_summary_command(vrf) for vrf, _ in scopes)])
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
            # A session of another address family is sent no path command
            # (`_bgp_scoped_targets`), whatever the capture setting.
            if entry.get("af", 4) != 4:
                outcome = outcome.model_copy(update={"detail": _IPV4_UNICAST_ONLY})
            elif capture in _CAPTURE_REASONS:
                outcome = outcome.model_copy(update={"detail": _CAPTURE_REASONS[capture]})
        outcomes[bgp_direction_key(session_uid, entry["direction"])] = outcome
    return outcomes


# The `cisco_xr_show_interfaces` ntc-template splits the duplex/speed line
# ("  Full-duplex, 1000Mb/s, link type is force-up") and the MTU/BW line
# ("  MTU 1514 bytes, BW 1000000 Kbit") into the fields `duplex`, `speed` and
# `bandwidth`. An `Auto-duplex, Auto-speed` line leaves both fields empty.
_IOSXR_SPEED_RE = re.compile(r"^(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>Mb/s|Gb/s)$", re.IGNORECASE)
_IOSXR_BANDWIDTH_RE = re.compile(r"^(?P<value>\d+)\s*Kbit$", re.IGNORECASE)


def _iosxr_speed_mbps(speed: Any) -> int | None:
    if not isinstance(speed, str) or not speed:
        return None
    m = _IOSXR_SPEED_RE.match(speed.strip())
    if not m:
        return None
    mbps = float(m["value"]) * (1000 if m["unit"].lower() == "gb/s" else 1)
    rounded = round(mbps)
    return rounded if abs(mbps - rounded) < 1e-6 else None


def _iosxr_duplex(duplex: Any) -> str | None:
    if isinstance(duplex, str) and duplex.strip().lower() in ("full", "half"):
        return duplex.strip().lower()
    return None


def _iosxr_bandwidth_kbit(bandwidth: Any) -> int | None:
    """Return the `BW` value of the MTU line in Kbit/s, or None. The value is
    the routing-metric bandwidth. The Port keeps it for reference."""
    if not isinstance(bandwidth, str) or not bandwidth:
        return None
    m = _IOSXR_BANDWIDTH_RE.match(bandwidth.strip())
    return int(m["value"]) if m else None


def _parse_interface(row: dict[str, Any]) -> dict:
    ips = []
    addr = row.get("ip_address") or ""
    if "/" in addr:
        ip, plen = addr.split("/", 1)
        ips.append({"ip": ip, "prefixlen": int(plen), "vrf": ""})
    speed_mbps = _iosxr_speed_mbps(row.get("speed"))
    duplex = _iosxr_duplex(row.get("duplex"))
    parsed = {
        **mtu_interface_fields(row),
        "name": row["interface"],
        # IOS-XR has no SVI. The LAG prefix is Bundle-Ether.
        "kind": interface_kind(row["interface"], lag_prefix="bundle-ether"),
        "mac": canonical_mac(row.get("mac_address")),
        "admin_up": not (row.get("admin_state") or "").startswith("admin"),
        "ips": ips,
        "vlan": None,
        "speed_mbps": speed_mbps,
        "duplex": duplex,
        "speed_source": "iosxr:show interfaces" if (speed_mbps is not None or duplex is not None) else None,
        "bandwidth_kbit": _iosxr_bandwidth_kbit(row.get("bandwidth")),
    }
    description = (row.get("description") or "").strip()
    if description:
        parsed["description"] = description
    return parsed


# --- OSPF operational commands and config extract ----------------------------------------


def parse_ospf(raw: dict[str, str]) -> dict[str, Any] | None:
    """Return the intermediate `ospf` shape of the OSPF captures (the docstring
    of `cisco_common.normalize_cisco`). Return None when the payload holds
    none of the 10 OSPF commands."""
    if not any(cmd in raw for cmd in OSPF_COMMANDS):
        return None

    processes = parse_ospf_process_text(raw.get(CMD_OSPF) or "")
    by_process = {p["process"]: p for p in processes}

    config = parse_ospf_redistribute_config(raw.get(CMD_OSPF_CONFIG) or "")
    for process, entry in config.items():
        proc = by_process.setdefault(
            process,
            # A process of the config alone keeps its redistribution.
            {"process": process, "router_id": None, "areas": [], "redistribute": []},
        )
        proc["router_id"] = proc["router_id"] or entry["router_id"]
        proc["redistribute"] = entry["redistribute"]
        proc.update({k: v for k, v in entry.items() if k.startswith("default_information_originate")})

    interfaces = parse_ospf_interface_text(raw.get(CMD_OSPF_IF) or "")
    area_by_if = {i["name"]: i["area"] for i in interfaces if i.get("area") is not None}

    # `show ospf neighbor` has no process column. Each adjacency gets the first process
    # of this capture, and `stamp_ospf_vrfs` gives it the process of its local interface.
    nbr_records = cli_parse.parse("iosxr", CMD_OSPF_NBR, raw.get(CMD_OSPF_NBR) or "")
    process_id = next(iter(by_process), None)
    adjacencies = ospf_adjacency_rows_from_neighbor_records(
        nbr_records, process=process_id, area_by_if=area_by_if
    )

    lsdb: list[dict[str, Any]] = [
        *ospf_lsa_detail_rows(raw.get(CMD_OSPF_DB_ROUTER) or "", default_type="router"),
        *ospf_lsa_detail_rows(raw.get(CMD_OSPF_DB_NETWORK) or "", default_type="network"),
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


# The key of the intermediate shape that holds the count of the route table lines
# that the template could not read (`cli_parse.parse_with_unread`). `sections`
# states the count on the `rib` section. The key is absent when the template
# read every line.
RIB_UNREAD_KEY = "rib_unread_lines"


_HOSTNAME_RE = re.compile(r"^hostname\s+(\S+)", re.M)


def _hostname(text: str | None) -> str | None:
    """Return the name of the `hostname <name>` line of `show running-config hostname`, or None."""
    m = _HOSTNAME_RE.search(text or "")
    return m[1] if m else None


def parse(raw: dict[str, str]) -> dict[str, Any]:
    """Return the cross-family intermediate shape of the `{command: raw_cli_text}`
    outputs for `cisco_common.normalize_cisco`. The parse is pure.

    `device.hostname` is the name of `show running-config hostname`, or None
    when the answer is absent or holds no name. `device.serial` is the `sn` of
    the `"Rack 0"` entry of `show inventory`, or None when that entry or its
    `sn` is absent."""
    version_rows = cli_parse.parse("iosxr", CMD_VERSION, raw[CMD_VERSION])
    v = version_rows[0] if version_rows else {}
    inventory_rows = cli_parse.parse("iosxr", CMD_INVENTORY, raw[CMD_INVENTORY])
    device = {
        "hostname": _hostname(raw.get(CMD_HOSTNAME)),
        "serial": _chassis_serial(inventory_rows),
        "platform": "iosxr",
        "os_version": v.get("version") or None,
    }

    vrf_rows = cli_parse.parse("iosxr", CMD_VRF, raw[CMD_VRF])

    interfaces = [
        _parse_interface(row) for row in cli_parse.parse("iosxr", CMD_INTERFACES, raw[CMD_INTERFACES])
    ]
    # `show vrf` abbreviates its members. They are matched to the names of the interface table.
    names = [ifc["name"] for ifc in interfaces]
    resolve = IfNameResolver(names)
    vrf_by_if = if_vrf_map(vrf_rows, vrf_key="vrf", device_ifnames=names)
    for ifc in interfaces:
        vname = vrf_of(vrf_by_if, resolve, ifc["name"], "")
        for ip in ifc["ips"]:
            ip["vrf"] = vname

    lldp_rows = cli_parse.parse("iosxr", CMD_LLDP, raw[CMD_LLDP])
    cdp_rows = cli_parse.parse("iosxr", CMD_CDP, raw[CMD_CDP])
    # The XR CDP template stores `Device ID` in `chassis_id` (module docstring).
    neighbors = lldp_neighbor_rows(lldp_rows, name_key="neighbor") + cdp_neighbor_rows(
        cdp_rows, name_keys=("neighbor_name", "chassis_id")
    )

    # Each record is turned into its row when it is parsed (`cli_parse.parse(row=)`).
    # The TextFSM records of a full table are not held at once. A line that the
    # template cannot read is counted under `RIB_UNREAD_KEY`, and the other
    # lines are read.
    rib, rib_unread = cli_parse.parse_with_unread(
        "iosxr",
        CMD_ROUTE,
        raw[CMD_ROUTE],
        row=functools.partial(rib_row, next_hop_key="next_hop", interface_key="interface"),
    )
    # `rib_row` returns None for a backup path (`(!)`).
    rib = [row for row in rib if row is not None]
    arp = cli_parse.parse(
        "iosxr",
        CMD_ARP,
        raw.get(CMD_ARP, raw.get(_CMD_ARP_DEFAULT_VRF, "")),
        row=functools.partial(arp_row, vrf_by_if=vrf_by_if, resolve=resolve),
    )
    # A missing command and the "" stand-in both parse to no groups.
    hsrp_text = raw.get(CMD_HSRP)
    fhrp = fhrp_rows(
        cli_parse.parse("iosxr", CMD_HSRP, hsrp_text) if hsrp_text else [],
        kind="hsrp",
        priority_key="prio",
        vip_key="group_addr",
    )

    inter: dict[str, Any] = {
        "device": device,
        "interfaces": interfaces,
        "neighbors": neighbors,
        "vlans": [],
        "vrfs": [{"name": r["vrf"], **vrf_rt_fields(r)} for r in vrf_rows],
        "rib": rib,
        "mac_table": [],
        "arp": arp,
        "fhrp": fhrp,
    }
    # The `router bgp` extract is parsed once for the configuration and for the
    # observations.
    bgp = iosxr_bgp.parse_bgp(raw[CMD_BGP])
    inter.update(
        iosxr_bgp.parse(
            bgp,
            raw[CMD_PREFIX_SET],
            raw[CMD_ROUTE_POLICY],
            raw.get(CMD_COMMUNITY_SET) or "",
            raw.get(CMD_AS_PATH_SET) or "",
        )
    )
    # None for a payload without the OSPF capture (`table_outcomes`).
    ospf = parse_ospf(raw)
    if ospf is not None:
        stamp_ospf_vrfs(ospf, vrf_by_if, resolve)
        inter["ospf"] = ospf
    # The observed session state and paths of the observation commands in the
    # payload. The result is empty when the payload holds no observation command.
    # `bgp_capture_targets` reads the raw neighbor list of `iosxr_bgp.parse_bgp`
    # before `resolve_bgp_sessions` applies the inheritance chain.
    inter["bgp_observed"] = parse_bgp_observations(raw, bgp)
    if rib_unread:
        inter[RIB_UNREAD_KEY] = rib_unread
    inter["mtu_model"] = next((r.get("pid") for r in inventory_rows if r.get("name") == "Rack 0"), None)
    parse_mtu(raw, inter, family="iosxr", config_command=MTU_COMMANDS["iosxr"]["config"])
    # The interface filter bindings. This family collects no list body. `lists`
    # is empty, and every bound list is read as not collected.
    bindings = parse_access_groups((raw.get(CMD_INTERFACE_CONFIG) or "").splitlines())
    if bindings:
        inter["acl"] = {"lists": {}, "bindings": bindings}
    return inter


class IosxrConfig(SshSourceConfig):
    capture_mtu: bool = False


@register
class IosxrCollector(CiscoCliCollector):
    NORMALIZATION_VERSIONS: ClassVar[dict[str, str]] = {
        # The '.' of a subinterface name stays in the Interface and Port uid.
        "iface_uid": uid.IFACE_UID_VERSION,
        "mtu": MTU_NORMALIZATION_VERSION,
        "bgp_dynamic_peers": "1",
        # An OSPF process is keyed by its id and holds its VRF.
        "ospf_process": "1",
        # The ARP table of every VRF.
        "arp_vrf": "1",
        # A backup path marked `(!)` has no RIB row.
        "rib_best": "1",
        # The interface description is on Interface and Port.
        "port_description": "1",
        # A refused always-present command is unauthorized. A refusal recorded
        # `ok` is a refusal. The side tables are judged by their sections.
        # In version 2, a refused interface binding extract is unauthorized.
        "read-failures": "2",
        # Interface access lists hold their installation evidence.
        "acl_installation": "1",
        # The origins are under the process address family.
        "bgp_af_origins": "1",
        # BgpSession states route-reflector-client.
        "bgp_session_filters": "1",
        # A placeholder serial identifies no chassis. When 2 devices report one
        # serial in one run, the later device is keyed by its ref.
        "serial": "1",
        # BgpSession holds the cluster id. RoutingProcess holds the neighbors
        # that get no session.
        "bgp_cluster_id": "1",
        # RoutingProcess holds maximum-paths and multipath-relax.
        "bgp_multipath": "1",
        # BgpSession holds the router id of the peer from the neighbor output.
        "bgp_peer_router_id": "1",
    }
    # Version 2 reads the path rows by column position (`cisco_bgp_table`).
    PARSER_VERSION: ClassVar[str] = "2"
    NORMALIZATION_OUTCOME_KEYS = (*COMMANDS, *MTU_COMMANDS["iosxr"].values())

    def sections(self, raw):
        inter = self._inter(raw)
        sections = {**super().sections(raw), **mtu_sections(raw, inter, family=self.name)}
        sections["rib"] = cli_parse.unread_outcome(sections["rib"], inter.get(RIB_UNREAD_KEY, 0))
        if CMD_ARP not in raw and _CMD_ARP_DEFAULT_VRF in raw:
            # A payload without CMD_ARP is judged on the ARP command that it sent.
            old = {"arp": Section(_CMD_ARP_DEFAULT_VRF, "arp")}
            sections["arp"] = build_sections(raw, inter, old, self.ALWAYS_PRESENT_COMMANDS)["arp"]
        return annotate_fhrp_sections(sections, inter, {"hsrp": "hsrp"})

    name = "iosxr"
    ConfigModel = IosxrConfig
    KIND = "group"
    COMMANDS = COMMANDS
    # The ages of the ARP and route tables and the up/down column of the BGP
    # session summaries change on every fetch. The BGP path tables change with
    # every route of the peers. The ARP, route and path texts feed only the
    # side tables `arp`, `rib` and `bgp_session_routes`. The summaries feed the
    # graph only through the dynamic peers that they list.
    # `stamp_dynamic_observations` keeps these peers in the change hash as
    # `_strata_dynamic_bgp`. Each key is an observation key as well, and its
    # rows reach the side store through `obs_sha`. The recorded outcome of the
    # route command stays in the change hash through NORMALIZATION_OUTCOME_KEYS.
    # The uptime in `show version` changes on every fetch and is not declared.
    # The Device node is built from that text, and the text stays in the change
    # hash. The batch digest (`graph_sha`) skips the graph write of an unchanged
    # device.
    VOLATILE_RAW_KEYS = (
        CMD_ARP,
        _CMD_ARP_DEFAULT_VRF,
        CMD_ROUTE,
        CMD_BGP_SESSIONS,
        CMD_BGP_NEIGHBORS,
        CMD_BGP_VRF_NEIGHBORS,
    )
    VOLATILE_RAW_KEY_PATTERN = BGP_OBSERVATION_KEY_RE
    # The ARP table, the RIB, the BGP session summaries and the BGP path tables.
    # The per-VRF summaries and the path commands are derived per fetch and
    # are matched by BGP_OBSERVATION_KEY_RE.
    # The BGP neighbor detail is declared as well. It is volatile, and the change
    # hash holds only its router ids (`stamp_peer_router_ids`).
    OBSERVATION_RAW_KEYS = (
        CMD_ARP,
        _CMD_ARP_DEFAULT_VRF,
        CMD_ROUTE,
        CMD_BGP_SESSIONS,
        CMD_BGP_NEIGHBORS,
        CMD_BGP_VRF_NEIGHBORS,
    )
    OBSERVATION_RAW_KEY_PATTERN = BGP_OBSERVATION_KEY_RE
    # A device with LLDP/CDP disabled, or a credential without the ARP privilege,
    # still gives its interfaces, VRFs and routes.
    OPTIONAL_COMMANDS: ClassVar[dict[str, str]] = {
        CMD_LLDP: "",
        CMD_CDP: "",
        CMD_ARP: "",
        # A credential denied the running-config loses only the hostname.
        CMD_HOSTNAME: "",
        CMD_BGP: "",
        CMD_PREFIX_SET: "",
        CMD_ROUTE_POLICY: "",
        # A credential denied the running-config loses only the filter bindings.
        CMD_INTERFACE_CONFIG: "",
        # The OSPF stand-ins parse to no process, no adjacency and no LSA.
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
        # A device with no HSRP group answers with an empty table. The stand-in
        # is used when the credential is denied the command.
        CMD_HSRP: "",
    }
    ALWAYS_PRESENT_COMMANDS: ClassVar[frozenset[str]] = ALWAYS_PRESENT_COMMANDS
    SECTIONS = SECTIONS
    # The sections of the required commands. On XR, `inventory` holds the chassis serial.
    AUTHORITATIVE_SECTIONS = ("device", "inventory", "interfaces", "vrfs", "rib")
    SIDE_TABLES: ClassVar[tuple[str, ...]] = (
        *CiscoCliCollector.SIDE_TABLES,
        "ospf_lsdb",
        BGP_ROUTES_TABLE,
        BGP_SESSIONS_TABLE,
    )
    # The labels that only one optional section writes (`Collector.SECTION_LABELS`).
    # `arp`, `lldp` and `cdp` own no label. On XR, `RouteTarget` comes from the
    # authoritative `vrfs` section. No OSPF section is the only owner of a label.
    SECTION_LABELS: ClassVar[dict[str, tuple[str, ...]]] = {
        "arp": (),
        "lldp": (),
        "cdp": (),
        "bgp": ("RoutingProcess", "BgpSession", "BgpPeerRange"),
        "prefix_sets": ("PrefixListEntry",),
        "route_policies": ("RoutePolicyEntry",),
        # `hsrp` is the only FHRP section on XR and the only writer of `FhrpGroup`.
        "hsrp": ("FhrpGroup",),
        "interface_config": ("FwRule", "NetObject", "SvcObject"),
    }

    @staticmethod
    def _parse(raw: dict[str, str]) -> dict[str, Any]:
        return parse(raw)

    def _ospf_table_outcomes(self, raw: dict[str, str]) -> dict[str, TableOutcome]:
        """Return `{ospf_lsdb: unsupported}` when the device runs no OSPF process,
        a `failed` outcome when an OSPF command did not answer, and `{}` otherwise.

        IOS-XR prints nothing for `show ospf` and the other OSPF commands when no
        `router ospf` process is configured.
        """
        recorded = effective_outcomes(raw, self._inter(raw), ALWAYS_PRESENT_COMMANDS)
        statuses = [recorded[cmd].status for cmd in OSPF_FEATURE_COMMANDS if cmd in recorded]
        if any(status != "ok" for status in statuses):
            # A command that did not answer leaves its database empty. The empty
            # table is not the answer of the device.
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

    def _device_uid(self, inter: dict[str, Any]) -> str:
        """Return the Device node uid of the rows of this payload.
        `CiscoCliCollector.side_tables` uses the same formula for the base
        tables. A BGP observation row and a RIB row of one fetch have one device."""
        return device_uid(inter, self.scope, self.identity, self.config.host)

    def side_tables(self, raw: dict[str, str]) -> dict[str, Sequence[dict[str, Any]]]:
        """Return the 3 base Cisco tables and the 2 BGP observation tables."""
        inter = self._inter(raw)
        return {**super().side_tables(raw), **bgp_side_rows(inter, self._device_uid(inter))}

    def table_outcomes(self, raw: dict[str, Any]) -> dict[str, TableOutcome]:
        """Return the outcomes of the MAC table, the OSPF link-state database
        (`_ospf_table_outcomes`), the BGP tables and the 3 directions of each
        session (`bgp_table_outcomes`)."""
        inter = self._inter(raw)
        return {
            # No command of this family reads a MAC table. `side_rows` leaves the
            # table empty.
            "mac": TableOutcome(status="not-captured", detail="the IOS-XR collector reads no MAC table"),
            **self._ospf_table_outcomes(raw),
            **bgp_table_outcomes(raw, inter, self._device_uid(inter), capture=self.config.capture_bgp),
        }

    async def _afetch_over(self, s) -> dict[str, Any]:
        """Run the static command loop (`SshCliCollector._afetch_over`) and then
        the BGP observation capture with commands from the BGP running-config."""
        raw = await super()._afetch_over(s)
        await self._afetch_bgp_observations(s, raw)
        if self.config.capture_mtu:
            await capture_mtu(s, raw, family=self.name, check=self.check_stop)
        if iosxr_bgp.names_a_set(raw.get(CMD_ROUTE_POLICY) or ""):
            await capture_match_lists(s, raw, (CMD_COMMUNITY_SET, CMD_AS_PATH_SET), check=self.check_stop)
        return raw

    async def _afetch_bgp_observations(self, s, raw: dict[str, Any]) -> None:
        """Read the observed session state and, for `capture_bgp` of `all`,
        the three path tables of every configured neighbor.

        Every command is optional as in `OPTIONAL_COMMANDS`. A refusal is
        logged and recorded under `RAW_OUTCOMES_KEY` with the words of the
        device, and the payload gets an empty stand-in. A device without BGP or
        without soft reconfiguration inbound loses the observation and keeps
        the fetch.

        A path command that times out is recorded in the same way when every
        command has its own session, on an exec channel or on a new connection
        per command. The direction is then `failed`. On one shell session the
        timeout ends the fetch. The session sends nothing after a timeout
        (`ssh.ShellSession.run`).

        After `PATH_TIMEOUT_LIMIT` timeouts in a row, the fetch sends no more
        path commands. Each command that is not sent is `failed` with the
        detail of `not_sent_after_timeouts`.
        """
        capture = self.config.capture_bgp
        if capture == "none":
            return
        bgp = iosxr_bgp.parse_bgp(raw.get(CMD_BGP) or "")
        commands = list(dict.fromkeys(bgp_summary_command(vrf) for vrf, _ in _bgp_scopes(bgp)))
        if CMD_BGP_SESSIONS not in commands:
            commands.insert(0, CMD_BGP_SESSIONS)
        commands += [CMD_BGP_NEIGHBORS, CMD_BGP_VRF_NEIGHBORS]
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
        stamp_dynamic_observations(raw, processes, sessions, peer_key="addr")
        stamp_peer_router_ids(
            raw, parse_neighbor_router_ids(raw.get(CMD_BGP_NEIGHBORS), raw.get(CMD_BGP_VRF_NEIGHBORS))
        )
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
