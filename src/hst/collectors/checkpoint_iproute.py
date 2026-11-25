"""Strict iproute2 text fallback for Gaia builds without JSON support."""

from __future__ import annotations

import ipaddress
import re

COMMANDS = {
    "interfaces": "ip -o address show",
    "links": "ip -d -o link show",
    "routes4": "ip -o -4 route show table all",
    "routes6": "ip -o -6 route show table all",
    "neighbors4": "ip -o -4 neigh show",
    "neighbors6": "ip -o -6 neigh show",
}


def parse(key: str, text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        words = line.replace("\\", " ").split()

        def after(token, default=None, words=words):
            return (
                words[words.index(token) + 1]
                if token in words and words.index(token) + 1 < len(words)
                else default
            )

        if key == "interfaces":
            match = re.match(r"^(\d+):\s+(\S+)\s+(inet6?)\s+(\S+)", line)
            if not match:
                raise ValueError("unrecognized ip address row")
            address = ipaddress.ip_interface(match[4])
            name = match[2].split("@")[0]
            row = next((r for r in rows if r["ifname"] == name), None)
            if row is None:
                row = {"ifindex": int(match[1]), "ifname": name, "addr_info": []}
                rows.append(row)
            row["addr_info"].append({"local": str(address.ip), "prefixlen": address.network.prefixlen})
        elif key == "links":
            match = re.match(r"^(\d+):\s+(\S+):\s+<([^>]*)>", line)
            if not match:
                raise ValueError("unrecognized ip link row")
            name, _, parent = match[2].partition("@")
            row = {
                "ifindex": int(match[1]),
                "ifname": name,
                "flags": match[3].split(","),
                "operstate": after("state", "UNKNOWN"),
                "mtu": int(after("mtu", "0")),
            }
            if parent:
                row["link"] = parent
            if after("master"):
                row["master"] = after("master")
            for kind in ("ether", "loopback"):
                if after("link/" + kind):
                    row.update(link_type=kind, address=after("link/" + kind))
            if "vlan" in words and after("id"):
                row["linkinfo"] = {"info_kind": "vlan", "info_data": {"id": int(after("id"))}}
            elif "bridge" in words or "bond" in words:
                row["linkinfo"] = {"info_kind": "bridge" if "bridge" in words else "bond"}
            rows.append(row)
        elif key.startswith("neighbors"):
            address = ipaddress.ip_address(words[0])
            if not after("dev"):
                raise ValueError("neighbor lacks interface")
            rows.append(
                {
                    "dst": str(address),
                    "dev": after("dev"),
                    "lladdr": after("lladdr"),
                    "state": [
                        w
                        for w in words
                        if w
                        in {
                            "REACHABLE",
                            "STALE",
                            "PERMANENT",
                            "DELAY",
                            "PROBE",
                            "FAILED",
                            "INCOMPLETE",
                            "NOARP",
                        }
                    ],
                }
            )
        else:
            kind = (
                words[0]
                if words[0]
                in {"local", "broadcast", "unreachable", "blackhole", "prohibit", "throw", "unicast"}
                else "unicast"
            )
            prefix = words[1] if words[0] == kind else words[0]
            if prefix != "default":
                prefix = str(ipaddress.ip_network(prefix, strict=False))
            row = {
                "dst": prefix,
                "type": kind,
                "protocol": after("proto"),
                "table": after("table", "main"),
                "metric": int(after("metric", "0")),
            }
            if "nexthop" in words:
                row["nexthops"] = []
                for part in line.split("nexthop")[1:]:
                    fields = part.split()
                    hop = {}
                    for token, target in (("via", "gateway"), ("dev", "dev"), ("weight", "weight")):
                        if token in fields:
                            hop[target] = fields[fields.index(token) + 1]
                    row["nexthops"].append(hop)
            else:
                row.update(gateway=after("via"), dev=after("dev"))
            if any(token in words for token in ("encap", "nhid", "linkdown")):
                raise ValueError("route has unsupported forwarding attributes")
            rows.append(row)
    return rows
