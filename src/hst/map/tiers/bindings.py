"""Attribution of graph objects to devices.

An object belongs to a device by its uid when the uid embeds the device uid,
and otherwise by the table `render_bindings`. The table holds one row for each
object that a Tier 1 count column counts and whose uid does not embed its device uid.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

from .. import store
from .bootstrap import CATEGORY_LABEL
from .schemas import RENDER_BINDINGS

TABLE = "render_bindings"

# The uid prefixes whose next segment is a device uid (core/uid.py), longest first.
_SCOPED = (
    "ospfarea:rproc:",
    "ospfadj:rproc:",
    "bgp:rproc:",
    "bgprange:",
    "rproc:",
    "rtpol:",
    "vlan:",
    "vrf:",
    "bgp:",
    "fc:",
)
_ENDS = frozenset(":~/")


def device_of(uid: str, devices: Collection[str]) -> str | None:
    """The device a uid embeds, when that device is in `devices`."""
    if uid in devices:
        return uid
    head = uid.split("/", 1)[0]
    if head != uid and head in devices:
        return head
    for prefix in _SCOPED:
        if uid.startswith(prefix):
            rest = uid[len(prefix) :]
            for i, ch in enumerate(rest):
                if ch in _ENDS and rest[:i] in devices:
                    return rest[:i]
            return None
    return None


def rows(
    members: Mapping[str, Mapping[str, Iterable[str]]], devices: Collection[str]
) -> list[dict[str, Any]]:
    """The binding rows of the counted objects whose uid does not embed their device uid."""
    out = []
    for device, by_column in members.items():
        for column, label in CATEGORY_LABEL.items():
            for uid in sorted(by_column.get(column, ())):
                if device_of(uid, devices) != device:
                    out.append({"object_uid": uid, "device_uid": device, "label": label})
    return out


def read(sidestore_dir: Path, run_key: int | None) -> pa.Table:
    path = None if run_key is None else store.table_path(sidestore_dir, TABLE, run_key)
    if path is None or not path.exists():
        return RENDER_BINDINGS.empty_table()
    return pq.read_table(path, schema=RENDER_BINDINGS)


def lookup(table: pa.Table, uids: Collection[str]) -> dict[str, set[str]]:
    """The devices bound to each of `uids`."""
    if not uids or table.num_rows == 0:
        return {}
    hit = table.filter(pc.is_in(table["object_uid"], value_set=pa.array(sorted(uids), pa.string())))
    out: dict[str, set[str]] = {}
    for uid, device in zip(hit["object_uid"].to_pylist(), hit["device_uid"].to_pylist(), strict=True):
        out.setdefault(uid, set()).add(device)
    return out


def without(table: pa.Table, devices: Collection[str]) -> pa.Table:
    """The rows bound to devices outside `devices`."""
    if not devices or table.num_rows == 0:
        return table
    keep = pc.invert(pc.is_in(table["device_uid"], value_set=pa.array(sorted(devices), pa.string())))
    return table.filter(keep)
