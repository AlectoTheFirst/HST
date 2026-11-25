"""Pinned pyarrow schemas of the HST tables."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pyarrow as pa

GRAPH_DELTA = pa.schema(
    [
        pa.field("snapshot_ts", pa.int64()),
        pa.field("parent_ts", pa.int64()),
        pa.field("kind", pa.string()),
        pa.field("change", pa.string()),
        pa.field("uid", pa.string()),
        pa.field("label", pa.string()),
        pa.field("start_uid", pa.string()),
        pa.field("end_uid", pa.string()),
        pa.field("device_uid", pa.string()),
        pa.field("props_before", pa.string()),
        pa.field("props_after", pa.string()),
        pa.field("run_id", pa.string()),
    ]
)

LAYOUT = pa.schema(
    [
        pa.field("uid", pa.string()),
        pa.field("kind", pa.string()),
        pa.field("parent_uid", pa.string()),
        pa.field("u", pa.int32()),
        pa.field("v", pa.int32()),
        pa.field("w", pa.int32()),
        pa.field("h", pa.int32()),
        pa.field("side", pa.string()),
        pa.field("slot", pa.int32()),
        pa.field("points", pa.string()),
        pa.field("valid_from_ts", pa.int64()),
        pa.field("reason", pa.string()),
        pa.field("layout_version", pa.int32()),
        pa.field("run_id", pa.string()),
        pa.field("snapshot_ts", pa.int64()),
    ]
)


def _fields(*spec: tuple[str, pa.DataType]) -> pa.Schema:
    return pa.schema([pa.field(name, kind) for name, kind in spec])


STR, INT, BOOL = pa.string(), pa.int64(), pa.bool_()

# The count columns of Tier 1, in table order.
COUNTS = (
    "n_ports",
    "n_ports_connected",
    "n_ports_up",
    "n_interfaces",
    "n_vrfs",
    "n_vlans",
    "n_prefixes",
    "n_rulebases",
    "n_rules",
    "n_nat_rules",
    "n_pbr",
    "n_sessions",
    "n_tunnels",
    "n_endpoints",
    "n_unbound",
    "n_contexts",
    "n_ports_with_context",
    "n_ports_with_port_edge",
)

RENDER_T0 = _fields(
    ("uid", STR),
    ("kind", STR),
    ("parent_uid", STR),
    ("label", STR),
    ("code", STR),
    ("block_kind", STR),
    ("device_count", INT),
    ("observed_count", INT),
    ("carried_count", INT),
    ("failed_count", INT),
    ("added_count", INT),
    ("removed_count", INT),
    ("changed_count", INT),
    ("snapshot_ts", INT),
)

RENDER_T1 = _fields(
    ("uid", STR),
    ("site_uid", STR),
    ("block_uid", STR),
    ("group_uid", STR),
    ("label", STR),
    ("role", STR),
    ("tier", STR),
    ("vendor", STR),
    ("model", STR),
    ("os_version", STR),
    ("mgmt_ip", STR),
    ("status", STR),
    ("carried_reason", STR),
    ("last_seen_ts", INT),
    ("change", STR),
    *((name, INT) for name in COUNTS),
    ("snapshot_ts", INT),
)

RENDER_T1_EDGES = _fields(
    ("pair_id", STR),
    ("a_uid", STR),
    ("b_uid", STR),
    ("cable_count", INT),
    ("lag_count", INT),
    ("tunnel_count", INT),
    ("change", STR),
    ("snapshot_ts", INT),
)

RENDER_T1_CONTEXTS = _fields(
    ("device_uid", STR),
    ("context_uid", STR),
    ("identity_uid", STR),
    ("kind", STR),
    ("name", STR),
    ("rd", STR),
)

CONTEXT_IDENTITY = _fields(
    ("identity_uid", STR),
    ("basis", STR),
    ("rd", STR),
    ("name", STR),
    ("routing_domain_uid", STR),
    ("member_count", INT),
)

RENDER_T2_PORTS = _fields(
    ("uid", STR),
    ("device_uid", STR),
    ("tile", STR),
    ("name", STR),
    ("name_short", STR),
    ("admin_status", STR),
    ("oper_status", STR),
    ("speed_mbps", INT),
    ("lag_uid", STR),
    ("connected", BOOL),
    ("interface_uid", STR),
    ("context_uid", STR),
    ("change", STR),
)

RENDER_T2_SEGMENTS = _fields(
    ("uid", STR),
    ("device_uid", STR),
    ("tile", STR),
    ("bridge_domain_uid", STR),
    ("vid", INT),
    ("name", STR),
    ("prefix", STR),
    ("client_count", INT),
    ("change", STR),
)

RENDER_T2_CABLES = _fields(
    ("cable_id", STR),
    ("tile_a", STR),
    ("tile_b", STR),
    ("a_port", STR),
    ("b_port", STR),
    ("a_dev", STR),
    ("b_dev", STR),
    ("source", STR),
    ("speed_mbps", INT),
    ("speed_agreement", BOOL),
    ("carried", BOOL),
    ("change", STR),
)

RENDER_T2_CONTEXTS = _fields(
    ("uid", STR),
    ("device_uid", STR),
    ("tile", STR),
    ("kind", STR),
    ("name", STR),
    ("is_default", BOOL),
    ("order", INT),
    ("change", STR),
)

RENDER_T1_CIRCUITS = _fields(
    ("uid", STR),
    ("name", STR),
    ("type", STR),
    ("state", STR),
    ("bandwidth_mbps", INT),
    ("provider", STR),
    ("family", STR),
    ("a_device", STR),
    ("a_port", STR),
    ("a_vlan", STR),
    ("z_device", STR),
    ("z_port", STR),
    ("z_vlan", STR),
    ("cable_id", STR),
    ("change", STR),
)

RENDER_T1_FABRIC_PORTS = _fields(
    ("uid", STR),
    ("device_uid", STR),
    ("name", STR),
    ("ibx", STR),
    ("metro", STR),
    ("state", STR),
    ("speed_mbps", INT),
    ("redundancy", STR),
    ("lag_name", STR),
    ("cable_ids", STR),
    ("bound_by", STR),
    ("port_uid", STR),
    ("port_device", STR),
    ("binding_issue", STR),
    ("binding_ports", STR),
    ("change", STR),
)

RENDER_BINDINGS = _fields(("object_uid", STR), ("device_uid", STR), ("label", STR))

# Each changed element has one delta row. The column `table` holds the name of the tier table of the row.
TIER_DELTA = _fields(
    ("snapshot_ts", INT),
    ("parent_ts", INT),
    ("table", STR),
    ("tile", STR),
    ("uid", STR),
    ("op", STR),
    ("before", STR),
    ("after", STR),
)

SCHEMAS: dict[str, pa.Schema] = {
    "graph_delta": GRAPH_DELTA,
    "layout": LAYOUT,
    "render_t0": RENDER_T0,
    "render_t1": RENDER_T1,
    "render_t1_edges": RENDER_T1_EDGES,
    "render_t1_contexts": RENDER_T1_CONTEXTS,
    "render_t1_circuits": RENDER_T1_CIRCUITS,
    "render_t1_fabric_ports": RENDER_T1_FABRIC_PORTS,
    "context_identity": CONTEXT_IDENTITY,
    "render_t2_ports": RENDER_T2_PORTS,
    "render_t2_cables": RENDER_T2_CABLES,
    "render_t2_contexts": RENDER_T2_CONTEXTS,
    "render_t2_segments": RENDER_T2_SEGMENTS,
    "render_bindings": RENDER_BINDINGS,
    "render_t0_delta": TIER_DELTA,
    "render_t1_delta": TIER_DELTA,
    "render_t2_delta": TIER_DELTA,
}

SCHEMA_VERSIONS: dict[str, int] = {**dict.fromkeys(SCHEMAS, 1), "render_t1": 2}

# The key columns of each tier table, and the delta table its changes go to.
KEYS: dict[str, tuple[str, ...]] = {
    "render_t0": ("uid",),
    "render_t1": ("uid",),
    "render_t1_edges": ("pair_id",),
    "render_t1_contexts": ("device_uid", "context_uid"),
    "render_t1_circuits": ("uid",),
    "render_t1_fabric_ports": ("uid",),
    "context_identity": ("identity_uid",),
    "render_t2_ports": ("uid",),
    "render_t2_cables": ("cable_id",),
    "render_t2_contexts": ("device_uid", "uid"),
    "render_t2_segments": ("uid",),
}


def key_of(name: str, row: Mapping[str, Any]) -> str:
    return "|".join(str(row[k]) for k in KEYS[name])


DELTA_OF: dict[str, str] = {
    "render_t0": "render_t0_delta",
    "render_t1": "render_t1_delta",
    "render_t1_edges": "render_t1_delta",
    "render_t1_contexts": "render_t1_delta",
    "render_t1_circuits": "render_t1_delta",
    "render_t1_fabric_ports": "render_t1_delta",
    "context_identity": "render_t1_delta",
    "render_t2_ports": "render_t2_delta",
    "render_t2_cables": "render_t2_delta",
    "render_t2_contexts": "render_t2_delta",
    "render_t2_segments": "render_t2_delta",
}
# Tier 2 tables are tiled by block uid. The other tables are read whole.
TILED = frozenset({"render_t2_ports", "render_t2_cables", "render_t2_contexts", "render_t2_segments"})
