"""The port groups, one row per device and module or name range, derived on
read."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

NAME = "render_t2_port_groups"
SCHEMA_VERSION = 1
COLUMNS = (
    "device_uid",
    "tile",
    "group_key",
    "first_name",
    "last_name",
    "port_count",
    "up",
    "down",
    "admin_down",
    "connected",
)

_TRAILING_NUMBER = re.compile(r"\d+$")
_DIGITS = re.compile(r"(\d+)")


def group_key(name: str) -> str:
    return _TRAILING_NUMBER.sub("", name)


def natural(name: str) -> tuple[tuple[str | int, ...], str]:
    """A sort key that orders the numbers inside a name by value."""
    parts = _DIGITS.split(name)
    return tuple(int(p) if i % 2 else p for i, p in enumerate(parts)), name


def _state(port: Mapping[str, Any]) -> str | None:
    admin = str(port.get("admin_status") or "").lower()
    oper = str(port.get("oper_status") or "").lower()
    if admin == "down" or oper.startswith("admin"):
        return "admin_down"
    if oper == "up":
        return "up"
    if oper and oper != "unknown":
        return "down"
    return None


def groups(ports: Iterable[Mapping[str, Any]], cables: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The groups of `ports`, ordered by device uid and group key in natural order.

    A port is connected when it is an end of one of `cables`. A port counts in
    at most one of `up`, `down` and `admin_down`. Admin down takes precedence
    over the operational state. A port without a known state counts in none.
    """
    ends = {c[k] for c in cables for k in ("a_port", "b_port") if c.get(k) is not None}
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for port in ports:
        name = port.get("name") or ""
        key = (port["device_uid"], group_key(name))
        row = found.get(key)
        if row is None:
            row = found[key] = {
                "device_uid": key[0],
                "tile": port.get("tile"),
                "group_key": key[1],
                "first_name": name,
                "last_name": name,
                "port_count": 0,
                "up": 0,
                "down": 0,
                "admin_down": 0,
                "connected": 0,
            }
        row["port_count"] += 1
        if natural(name) < natural(row["first_name"]):
            row["first_name"] = name
        if natural(name) > natural(row["last_name"]):
            row["last_name"] = name
        state = _state(port)
        if state is not None:
            row[state] += 1
        if port.get("uid") in ends:
            row["connected"] += 1
    return [found[k] for k in sorted(found, key=lambda k: (k[0], natural(k[1])))]
