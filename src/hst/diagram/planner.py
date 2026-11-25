"""The diagram planner builds a nested view model of the devices and cables of
one snapshot. The unified map lays out the model.

The planner sets direction, blocks, groups and LAGs. The browser sets the
coordinates.

- The drawing reads from the outside in. The outer devices have a WAN link or
  an edge tier (`OUTER_TIERS`). Every other device gets its hop count from
  them, and each cable points from its outer end to its inner end. A cable
  between 2 devices at one depth is `lateral`, such as a peer-link, an ISL or
  a cluster sync link. ELK layers the drawing from these directions.
- Each site holds function blocks (Internet edge, WAN edge, campus, DC). A
  device goes in the block of its tier (`BLOCK_OF_TIER`). A device with no
  tier takes the block that most of its cabled neighbors are in, marked
  `inferred`. A firewall goes in a firewall block, keyed by the blocks that
  its cables face.
- A `RedundancyGroup` (vPC domain, firewall cluster) whose members share one
  block is a box inside that block.
- A `Lag` is an overlay on its member cables, and every cable is drawn. A LAG
  whose member cables reach 2 or more devices of one redundancy group is
  multi-chassis, marked `inferred`.

The output is deterministic. The same rows in any order give the same model.
The planner reads no database, and `app/routes/topology.py` reads the rows.
"""

from __future__ import annotations

import re
from collections import Counter, deque
from collections.abc import Iterable, Mapping
from typing import Any

from hst.core.identity import short_name

# The tiers that face the outside of a site (core/device_roles.py TIER_ROLES).
OUTER_TIERS = frozenset({"internet-edge", "wan-edge", "sdwan-hub", "sdwan-edge"})

# The function block of each design tier. `firewall` has no entry. A firewall
# goes in a firewall block keyed by the blocks that it faces.
BLOCK_OF_TIER: dict[str, str] = {
    "internet-edge": "internet-edge",
    "wan-edge": "wan-edge",
    "sdwan-hub": "wan-edge",
    "sdwan-edge": "wan-edge",
    "core": "campus",
    "distribution": "campus",
    "access": "campus",
    "wireless": "campus",
    "access-point": "campus",
    "spine": "dc",
    "leaf": "dc",
}

# The order of the tiers inside one block, top first.
TIER_PARTITION: dict[str, int] = {
    "internet-edge": 0,
    "sdwan-hub": 0,
    "wan-edge": 0,
    "sdwan-edge": 1,
    "firewall": 0,
    "core": 0,
    "spine": 0,
    "distribution": 1,
    "leaf": 1,
    "wireless": 1,
    "access": 2,
    "access-point": 3,
}

BLOCK_LABELS: dict[str, str] = {
    "internet-edge": "Internet edge",
    "wan-edge": "WAN edge",
    "campus": "Campus",
    "dc": "Data center",
    "firewall": "Firewall",
    "other": "Other",
}

# The site of a device that no site claims.
NO_SITE = "-"


def _cable_id(a: tuple[str, str], b: tuple[str, str]) -> str:
    x, y = (a, b) if a <= b else (b, a)
    return f"{x[0]}|{x[1]}~{y[0]}|{y[1]}"


def _block_id(site: str, key: str) -> str:
    return f"block:{site}:{key}"


def plan(
    devices: Iterable[Mapping[str, Any]],
    cables: Iterable[Mapping[str, Any]],
    lags: Iterable[Mapping[str, Any]] = (),
    groups: Iterable[Mapping[str, Any]] = (),
    wan_devices: Iterable[str] = (),
) -> dict[str, Any]:
    """The view model of the drawn devices.

    `devices` rows hold uid, name, role, tier, role_basis, site, vendor and
    model, and optionally mgmt_ip. `cables` rows hold a_dev, a_port, b_dev,
    b_port and source, and optionally a_name, b_name and speed_mbps. A cable
    with one end outside `devices` is an exit of the drawing. `lags` rows hold
    uid, dev, name and the member port names, and optionally the `neighbors`
    that the member ports report (port, name, far_port, proto). A member port
    without a cable whose neighbor is known is an exit to that neighbor. No
    collector collected that neighbor, and `far_dev` is empty. `groups` rows
    hold uid, kind, name and the member device uids. `wan_devices` are the
    devices that hold a WAN link.
    """
    devs = {d["uid"]: dict(d) for d in devices}
    order = sorted(devs, key=lambda u: (devs[u].get("name") or u, u))

    # One line per cable. A cable with its far end outside the drawing is an exit.
    lines: dict[str, dict[str, Any]] = {}
    exits: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for c in cables:
        a = (c["a_dev"], c.get("a_port") or "")
        b = (c["b_dev"], c.get("b_port") or "")
        a_in, b_in = a[0] in devs, b[0] in devs
        if a_in and b_in:
            line = {"a": a, "b": b, "source": c.get("source"), "speed_mbps": c.get("speed_mbps")}
            lines.setdefault(_cable_id(a, b), line)
        elif a_in or b_in:
            near, far = (a, b) if a_in else (b, a)
            far_name = c.get("b_name") if a_in else c.get("a_name")
            exits.setdefault(
                (near[0], near[1], far[0], far[1]),
                {
                    "dev": near[0],
                    "port": near[1] or None,
                    "far_dev": far[0],
                    "far_port": far[1] or None,
                    "far_name": far_name or far[0],
                    "source": c.get("source"),
                },
            )

    adjacency: dict[str, set[str]] = {u: set() for u in devs}
    for line in lines.values():
        x, y = line["a"][0], line["b"][0]
        if x != y:
            adjacency[x].add(y)
            adjacency[y].add(x)

    depth, anchor_basis = _depths(
        devs, order, adjacency, set(wan_devices), {e["dev"] for e in exits.values()}
    )
    # The neighbor exits are added after `_depths`, which takes the exit devices
    # as anchors. A neighbor that no collector reached makes no anchor.
    lags = list(lags)
    _neighbor_exits(lags, devs, lines, exits)

    blocks, block_basis = _blocks(devs, order, adjacency)

    # A redundancy group is a box when its members share one block.
    group_of: dict[str, str] = {}
    group_nodes: list[dict[str, Any]] = []
    split_groups: list[dict[str, Any]] = []
    for g in sorted(groups, key=lambda g: g["uid"]):
        members = sorted({m for m in g.get("members") or [] if m in devs and m not in group_of})
        if len(members) < 2:
            continue
        homes = {(devs[m].get("site") or NO_SITE, blocks[m]) for m in members}
        if len(homes) == 1:
            [(site, key)] = homes
            group_nodes.append(
                {
                    "id": g["uid"],
                    "kind": "group",
                    "parent": _block_id(site, key),
                    "label": g.get("name") or g["uid"],
                    "group_kind": g.get("kind"),
                }
            )
            for m in members:
                group_of[m] = g["uid"]
        else:
            split_groups.append(
                {"uid": g["uid"], "kind": g.get("kind"), "name": g.get("name"), "members": members}
            )

    # The hierarchy is site, block, group, device.
    site_nodes: dict[str, dict[str, Any]] = {}
    block_nodes: dict[str, dict[str, Any]] = {}
    device_nodes: list[dict[str, Any]] = []
    for u in order:
        d = devs[u]
        site = d.get("site") or NO_SITE
        key = blocks[u]
        kind = key.split(":", 1)[0]
        site_nodes.setdefault(site, {"id": f"site:{site}", "kind": "site", "parent": None, "label": site})
        bid = _block_id(site, key)
        if bid not in block_nodes:
            faces = key.split(":", 1)[1].split("+") if ":" in key else []
            label = BLOCK_LABELS[kind] + (f" ({', '.join(BLOCK_LABELS[f] for f in faces)})" if faces else "")
            block_nodes[bid] = {
                "id": bid,
                "kind": "block",
                "parent": f"site:{site}",
                "label": label,
                "block_kind": kind,
                "faces": faces,
            }
        tier = d.get("tier")
        device_nodes.append(
            {
                "id": u,
                "kind": "device",
                "parent": group_of.get(u, bid),
                "label": d.get("name") or u,
                "role": d.get("role"),
                "tier": tier,
                "role_basis": d.get("role_basis"),
                "block_basis": block_basis[u],
                "vendor": d.get("vendor"),
                "model": d.get("model"),
                "mgmt_ip": d.get("mgmt_ip"),
                "depth": depth.get(u),
                "anchor": anchor_basis.get(u),
                "partition": TIER_PARTITION.get(tier) if tier else None,
            }
        )

    # The outer end of a cable is its `from` end. A cable with one depth on
    # both ends is lateral.
    unreached = float("inf")
    out_cables = []
    for cid in sorted(lines):
        line = lines[cid]
        a, b = line["a"], line["b"]
        da, db = depth.get(a[0], unreached), depth.get(b[0], unreached)
        if db < da:
            a, b = b, a
        out_cables.append(
            {
                "id": cid,
                "from": {"dev": a[0], "port": a[1] or None},
                "to": {"dev": b[0], "port": b[1] or None},
                "source": line["source"],
                "speed_mbps": line["speed_mbps"],
                "lateral": da == db,
            }
        )

    return {
        "nodes": [
            *sorted(site_nodes.values(), key=lambda n: n["id"]),
            *sorted(block_nodes.values(), key=lambda n: n["id"]),
            *group_nodes,
            *device_nodes,
        ],
        "cables": out_cables,
        "exits": sorted(
            exits.values(), key=lambda e: (e["dev"], e["port"] or "", e["far_dev"], e["far_port"] or "")
        ),
        "lags": _lags(lags, devs, lines, groups, exits.values()),
        "split_groups": split_groups,
    }


def _depths(
    devs: Mapping[str, Mapping[str, Any]],
    order: list[str],
    adjacency: Mapping[str, set[str]],
    wan_devices: set[str],
    exit_devices: set[str],
) -> tuple[dict[str, int], dict[str, str]]:
    """The hop count of each device from the anchors, and the basis of each anchor.

    The anchors are the first of these sets that is not empty:
    1. the devices with a WAN link or an outer tier
    2. the devices with a cable that leaves the drawing
    3. the devices of the topmost tier
    4. the device with the most cables

    A device that no cable path from an anchor reaches has no depth."""
    anchors = {
        u: "wan-link" if u in wan_devices else "tier"
        for u in order
        if u in wan_devices or devs[u].get("tier") in OUTER_TIERS
    }
    if not anchors:
        anchors = {u: "exit" for u in order if u in exit_devices}
    if not anchors:
        ranked = [
            u for u in order if devs[u].get("tier") in TIER_PARTITION and devs[u].get("tier") != "firewall"
        ]
        if ranked:
            top = min(TIER_PARTITION[devs[u]["tier"]] for u in ranked)
            anchors = {u: "tier" for u in ranked if TIER_PARTITION[devs[u]["tier"]] == top}
    if not anchors and order:
        # `order` is by name. The first of the best-connected devices wins a tie.
        best = min(order, key=lambda u: -len(adjacency[u]))
        anchors = {best: "connected"}
    depth = dict.fromkeys(anchors, 0)
    queue = deque(u for u in order if u in anchors)
    while queue:
        u = queue.popleft()
        for v in sorted(adjacency[u]):
            if v not in depth:
                depth[v] = depth[u] + 1
                queue.append(v)
    return depth, anchors


def _blocks(
    devs: Mapping[str, Mapping[str, Any]], order: list[str], adjacency: Mapping[str, set[str]]
) -> tuple[dict[str, str], dict[str, str]]:
    """The block key of each device, and its basis (`tier`, `inferred` from the
    cabled neighbors, or `none`).

    The key is the block kind, and for a firewall block also the blocks it
    faces, e.g. `firewall:campus+wan-edge`. Neighbors count only within one
    site."""
    block: dict[str, str] = {}
    basis: dict[str, str] = {}
    firewalls = []
    for u in order:
        tier = devs[u].get("tier")
        if tier == "firewall" or (tier is None and devs[u].get("role") == "firewall"):
            firewalls.append(u)
        elif tier in BLOCK_OF_TIER:
            block[u], basis[u] = BLOCK_OF_TIER[tier], "tier"

    def site(u: str) -> str:
        return devs[u].get("site") or NO_SITE

    for u in order:
        if u in block or u in firewalls:
            continue
        votes = Counter(
            block[v] for v in adjacency[u] if v in block and basis[v] == "tier" and site(v) == site(u)
        )
        if votes:
            top = max(votes.values())
            block[u], basis[u] = min(k for k, n in votes.items() if n == top), "inferred"
        else:
            block[u], basis[u] = "other", "none"

    for u in firewalls:
        faces = sorted(
            {block[v] for v in adjacency[u] if v in block and v not in firewalls and site(v) == site(u)}
        )
        block[u] = "firewall" + (f":{'+'.join(faces)}" if faces else "")
        basis[u] = "tier"
    return block, basis


def _neighbor_name(name: str) -> str:
    """A CDP device id without the serial that NX-OS appends, as in `ACC-SW-04(FDO12345678)`."""
    return re.sub(r"\([^()]*\)$", "", name).strip() or name


def _neighbor_exits(
    lags: Iterable[Mapping[str, Any]],
    devs: Mapping[str, Mapping[str, Any]],
    lines: Mapping[str, Mapping[str, Any]],
    exits: dict[tuple[str, str, str, str], dict[str, Any]],
) -> None:
    """Add an exit for each LAG member port without a cable whose CDP or LLDP
    neighbor is known and is not a device of this drawing."""
    ends = {end for line in lines.values() for end in (line["a"], line["b"])}
    ends |= {(e["dev"], e["port"] or "") for e in exits.values()}
    drawn = {short_name(str(d.get("name") or "")) for d in devs.values()} - {""}
    for lag in lags:
        dev = lag["dev"]
        if dev not in devs:
            continue
        for n in lag.get("neighbors") or []:
            port = n.get("port") or ""
            if not port or not n.get("name") or (dev, port) in ends:
                continue
            if short_name(_neighbor_name(str(n["name"]))) in drawn:
                continue
            exits.setdefault(
                (dev, port, "", n.get("far_port") or ""),
                {
                    "dev": dev,
                    "port": port,
                    "far_dev": "",
                    "far_port": n.get("far_port") or None,
                    "far_name": _neighbor_name(str(n["name"])),
                    "source": f"{n.get('proto') or 'cdp'}, no cable",
                },
            )


def _lags(
    lags: Iterable[Mapping[str, Any]],
    devs: Mapping[str, Mapping[str, Any]],
    lines: Mapping[str, Mapping[str, Any]],
    groups: Iterable[Mapping[str, Any]],
    exits: Iterable[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    """Each drawn LAG as an overlay on its member cables. A member port with
    no cable is listed as a stub."""
    by_end: dict[tuple[str, str], tuple[str, tuple[str, str]]] = {}
    for cid, line in lines.items():
        by_end[line["a"]] = (cid, line["b"])
        by_end[line["b"]] = (cid, line["a"])
    exit_ends = {(e["dev"], e["port"] or "") for e in exits}
    member_sets = [set(g.get("members") or []) for g in groups]
    out = []
    for lag in sorted(lags, key=lambda r: r["uid"]):
        dev = lag["dev"]
        if dev not in devs:
            continue
        cable_ids, far_devs, loose = [], set(), []
        for port in sorted(set(lag.get("ports") or [])):
            hit = by_end.get((dev, port))
            if hit is None:
                if (dev, port) not in exit_ends:
                    loose.append(port)
            else:
                cable_ids.append(hit[0])
                far_devs.add(hit[1][0])
        multi = len(far_devs) >= 2 and any(far_devs <= members for members in member_sets)
        out.append(
            {
                "id": lag["uid"],
                "dev": dev,
                "name": lag.get("name"),
                "cables": sorted(cable_ids),
                "far": sorted(far_devs),
                "ports_without_cable": loose,
                "multi_chassis": multi,
                "basis": "inferred" if multi else "collector",
            }
        )
    return out
