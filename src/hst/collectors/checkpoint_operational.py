"""Read-only VSX operational evidence, kept separate from management policy."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any

VS_KINDS = {"S": "virtual-system", "B": "bridge", "R": "virtual-router", "W": "virtual-switch"}
_DEVICE = re.compile(r"^\s*(\d+)\s*\|\s*([SBRW])\s+([^|]+)\|")


def virtual_devices(text: str) -> dict[int, dict[str, str]]:
    devices = {}
    for line in text.splitlines():
        match = _DEVICE.match(line)
        if match:
            devices[int(match[1])] = {"kind": VS_KINDS[match[2]], "name": match[3].strip()}
    return devices


def cluster_state(text: str) -> str:
    """Only the member marked `(local)` sets this observation's role."""
    states = []
    for line in text.splitlines():
        match = re.match(r"^\s*\d+\s+\(local\)\s+\S+\s+\d+%\s+(.+?)\s*$", line)
        if not match:
            continue
        value = match[1].upper()
        # ACTIVE(!) and ACTIVE ATTENTION are degraded states.
        if re.match(r"ACTIVE(?:\s+\S+)?$", value) and not value.startswith("ACTIVE ATTENTION"):
            states.append("active")
        elif value.split()[0] in {"STANDBY", "BACKUP", "DOWN", "READY", "INIT"}:
            states.append(value.split()[0].lower())
        else:
            states.append("unknown")
    return states[0] if len(states) == 1 else "unknown"


def installed_policy(text: str) -> list[dict[str, str]]:
    """The HOST IF POLICY DATE rows of `fw stat -s`."""
    rows = []
    for line in text.splitlines():
        match = re.match(
            r"^\s*\S+\s+([<>])(\S+)\s+(\S+)\s+(\d{1,2}[A-Za-z]{3}\d{4}\s+\d\d:\d\d:\d\d)\s*:",
            line,
        )
        if match:
            rows.append(
                {
                    "direction": "in" if match[1] == "<" else "out",
                    "interface": match[2],
                    "policy_name": match[3],
                    "installed_at_raw": match[4],
                }
            )
    return rows


def context_kind(raw: Mapping[str, Any], vsid: int, context: Mapping[str, Any]) -> str:
    if vsid == 0:
        return "management"
    return str(
        context.get("kind")
        or virtual_devices(str(raw.get("vsx stat -v", ""))).get(vsid, {}).get("kind", "virtual-system")
    )


def bgp_peers(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        try:
            peer = ipaddress.ip_address(fields[0])
            peer_as = int(fields[1])
        except ValueError:
            continue
        if not 0 < peer_as <= 4294967295:
            continue
        state = next(
            (
                s.lower()
                for s in fields[2:]
                if s.lower() in {"idle", "connect", "active", "opensent", "openconfirm", "established"}
            ),
            None,
        )
        if state:
            rows.append({"peer_ip": str(peer), "peer_asn": peer_as, "state": state, "af": peer.version})
    return rows


def local_as(text: str) -> int | None:
    match = re.search(
        r"(?:^|\n)\s*(?:AS|Autonomous System(?: Number)?)\s*[:=]?\s*(\d+)\s*(?:\n|$)", text, re.I
    )
    if not match and text.strip().isdigit():
        value = int(text.strip())
    elif match:
        value = int(match[1])
    else:
        return None
    return value if 0 < value <= 4294967295 else None
