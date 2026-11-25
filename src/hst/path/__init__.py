"""Path evaluation.

Cypher fetches candidates. This package applies longest-prefix match and
first-match rule semantics to them.

`trace(session, src_ip, dst_ip)` returns a dict. Its `hops` list is ordered.
A hop has the keys `uid`, `kind`, `label` and `note`, among others. The hops
cover the endpoint, the switch port, the L2 fabric (uplink ports and switches
between the client and the router), the router port, the router interface,
the PBR policy (winning rule), the routing table, the route, the egress
interface and the tunnel or WAN link.

This file re-exports the names with callers outside the package.

Tests monkeypatch `_read` and `_read_one` on this package. Every database
read inside the package resolves them through `hst.path` at call time.
"""

from __future__ import annotations

from .addrsets import _intersect, _intervals, _subtract, _to_cidrs
from .gates import _Trail
from .gates.aci import aci_contract_verdict
from .gates.firewall import _device_rulebase_verdict, _zone_pair_verdict
from .gates.nat import _NAT_RULES_QUERY, _nat_match_set, _translate_set
from .gates.pbr import _pbr_partition
from .gates.routing import _NEXT_HOP_DEVICE_QUERY, _NEXT_HOP_DOMAIN_QUERY, _next_hop_device
from .session import LIVE_SNAP, CycleSession, NoRun, _read, _read_one, load_gateways, pinned
from .trace import (
    _DST_INSTANCES_QUERY,
    _IFACE_SEGMENT_QUERY,
    MAX_INTERPRETATIONS,
    start_tables,
    start_vrfs,
    trace,
    trace_from_identity,
    trace_from_vrf,
)
from .verdict import DENY, INDETERMINATE, PERMIT, classify_action

# The names with callers outside this package, in src/ or tests/. Internal
# helpers stay in their home modules and are imported from there.
__all__ = [
    "DENY",
    "INDETERMINATE",
    "LIVE_SNAP",
    "MAX_INTERPRETATIONS",
    "PERMIT",
    "_DST_INSTANCES_QUERY",
    "_IFACE_SEGMENT_QUERY",
    "_NAT_RULES_QUERY",
    "_NEXT_HOP_DEVICE_QUERY",
    "_NEXT_HOP_DOMAIN_QUERY",
    "CycleSession",
    "NoRun",
    "_Trail",
    "_device_rulebase_verdict",
    "_intersect",
    "_intervals",
    "_nat_match_set",
    "_next_hop_device",
    "_pbr_partition",
    "_read",
    "_read_one",
    "_subtract",
    "_to_cidrs",
    "_translate_set",
    "_zone_pair_verdict",
    "aci_contract_verdict",
    "classify_action",
    "load_gateways",
    "pinned",
    "start_tables",
    "start_vrfs",
    "trace",
    "trace_from_identity",
    "trace_from_vrf",
]
