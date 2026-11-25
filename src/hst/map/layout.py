"""Grid placement of the map elements.

`place` keeps every row in force and places only the elements that have no
row. A new device takes a spare slot in the rows of its partition. A device of
a partition with no spare slot goes to the annex rows below the rows of its
plate. A plate grows over its blocks and a site over its plate. A site, plate
or block with no element in the run leaves the layout with a `removed` row.
`replan` places everything again under the next `layout_version`. Every device
box is `DEVICE_W` by `DEVICE_H` for any port count.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from hst.diagram import planner

from . import store
from .tiers.schemas import LAYOUT

TABLE = "layout"
KINDS = ("region", "site", "plate", "block", "group", "device", "port", "cable", "segment")
FIRST_SEEN = "first-seen"
RELATION_RESOLVED = "relation-resolved"
ANNEX = "annex"
REPLAN = "replan"
# The reason of the row of a site, plate or block with no element in the run. The element leaves the
# layout at that run.
REMOVED = "removed"

UNASSIGNED_SITE = "site:unassigned"
UNASSIGNED_PLATE = "plate:unassigned"

# The layers of a site, top first. A layer is a row when it holds
# a device.
LAYERS = (
    "edge",
    "sdwan-edge",
    "external",
    "firewall",
    "upstream",
    "core",
    "distribution",
    "access",
    "access-point",
    "other",
    "segment",
)
TIER_LAYER = {
    "internet-edge": "edge",
    "wan-edge": "edge",
    "sdwan-hub": "edge",
    "sdwan-edge": "sdwan-edge",
    "firewall": "firewall",
    "core": "core",
    "spine": "distribution",
    "distribution": "distribution",
    "wireless": "distribution",
    "leaf": "access",
    "access": "access",
    "access-point": "access-point",
}
# The layer of a device without a tier, by role.
ROLE_LAYER = {
    "router": "upstream",
    "gateway": "upstream",
    "firewall": "firewall",
    "sdwan-hub": "edge",
    "sdwan-edge": "sdwan-edge",
}
# The layers above the closets. Their rows sit centred over the whole plate.
TRUNK = frozenset(LAYERS[: LAYERS.index("core") + 1])

ALGORITHM_VERSION = 11
# A site that holds a device of this role is a hub and sits at the centre of its country block.
HUB_ROLE = "sdwan-hub"
# The block of the sites whose location, code and hostnames name no country.
OTHER_REGION = "region:other"
# The block of the cloud sites (Equinix Fabric and the cloud providers), next to the core block.
CLOUD_REGION = "region:cloud"
# The block of the CNC sites at the estate's centre.
CORE_REGION = "region:core"
# A site that holds a device of this platform is a virtual CNC.
NETWORK_EDGE = "network-edge"
# The platform of the Equinix device of a site and IBX, which holds the Fabric ports there.
FABRIC_PLATFORM = "equinix-fabric"
# The `Site.kind` of a colocation site.
COLO = "colo"
# A site group is a box of the estate. A group of CNC sites has the core prefix.
GROUP_REGION = "region:group"
GROUP_SEP = " / "
# The padding inside a site group box, for the names of the boxes inside it.
GROUP_PAD = 6
# The site of the Fabric spine of a metro, between the sites of the metro in their site group.
SPINE_PREFIX = "EQUINIX-FABRIC-"
# The uid infix of a named block of a site and the prefix of its kind, `named:<zone>:<name>`.
NAMED_KIND = "named"
NAMED_INFIX = ":named:"
EXTERNAL = "external"
# The zones of a named block placed in the layer `external`. An internet edge is placed as an
# external device.
EXTERNAL_ZONES = frozenset({EXTERNAL, "internet"})
# The naming standard of a site code and a hostname, with the country token and then the city token.
_PLACE = re.compile(r"^([A-Za-z]{2})-([A-Za-z0-9]+)(?:-|$)")
# The country token of the naming standard for an ISO 3166 code that differs from it. ISO writes the
# United Kingdom as GB, and site codes and hostnames write UK. One country is one block.
_NAMING_TOKEN = {"GB": "UK"}
# An Equinix IBX code: the metro code and a number.
_IBX = re.compile(r"^[A-Za-z]{2}[0-9]{1,2}$")
DEVICE_W = 4
DEVICE_H = 3
# Room between two devices for the cable lanes and the port and link labels.
GAP = 4
PITCH_W = DEVICE_W + GAP
PITCH_H = DEVICE_H + GAP
# A slot is half a pitch. A parent centres over 2 children on the grid.
HALF = PITCH_W // 2
BLOCK_MARGIN = 1
PLATE_PAD = 2
CHANNEL = 2
SITE_GAP = 8
REGION_GAP = 3 * SITE_GAP
SITE_GROWTH = 0.25
# The share of the sites of a country block that the spiral cell holds. A larger site joins the
# centre group.
CELL_SHARE = 0.75
# The slot of an element outside the grid of its parent (an annexed device or block, the Unassigned site).
NO_SLOT = -1


@dataclass(frozen=True)
class Placement:
    uid: str
    kind: str
    parent_uid: str | None
    u: int
    v: int
    w: int
    h: int
    side: str | None = None
    slot: int | None = None
    points: str | None = None
    valid_from_ts: int = 0
    reason: str = FIRST_SEEN
    layout_version: int = 1

    def row(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "kind": self.kind,
            "parent_uid": self.parent_uid,
            "u": self.u,
            "v": self.v,
            "w": self.w,
            "h": self.h,
            "side": self.side,
            "slot": self.slot,
            "points": self.points,
            "valid_from_ts": self.valid_from_ts,
            "reason": self.reason,
            "layout_version": self.layout_version,
            "run_id": str(self.valid_from_ts),
            "snapshot_ts": self.valid_from_ts,
        }

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> Placement:
        return cls(
            uid=row["uid"],
            kind=row["kind"],
            parent_uid=row["parent_uid"],
            u=row["u"],
            v=row["v"],
            w=row["w"],
            h=row["h"],
            side=row["side"],
            slot=row["slot"],
            points=row["points"],
            valid_from_ts=row["valid_from_ts"],
            reason=row["reason"],
            layout_version=row["layout_version"],
        )

    def same_place(self, other: Placement) -> bool:
        return (self.parent_uid, self.u, self.v, self.w, self.h, self.side, self.slot, self.points) == (
            other.parent_uid,
            other.u,
            other.v,
            other.w,
            other.h,
            other.side,
            other.slot,
            other.points,
        )


@dataclass(frozen=True)
class Estate:
    """The map elements of one run.

    `devices` rows hold uid, name, role, tier, site (the site code or None) and
    optionally platform and site_kind (the `Site.kind` of the site). `ports`
    rows hold uid, device_uid and name. `cables` rows hold a_port and b_port
    (port uids). `groups` rows hold uid and members. `sites` lists site codes
    that hold no device.
    """

    devices: Sequence[Mapping[str, Any]]
    ports: Sequence[Mapping[str, Any]] = ()
    cables: Sequence[Mapping[str, Any]] = ()
    groups: Sequence[Mapping[str, Any]] = ()
    wan_devices: Sequence[str] = ()
    sites: Sequence[str] = ()
    # The devices with a segment of clients. Each takes a segment bar in the segment row.
    segment_devices: Sequence[str] = ()
    # The site code pairs joined by a tunnel or a cable. They give the order of the country blocks.
    site_links: Sequence[tuple[str, str]] = ()
    # The cloud sites, code to name. They sit in `CLOUD_REGION`.
    cloud_sites: Mapping[str, str] = field(default_factory=dict)
    # The site group path of a site code, from the top.
    site_groups: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    # The ISO 3166 alpha-2 code of the country the Postgres location of a site code names.
    site_countries: Mapping[str, str] = field(default_factory=dict)
    # The name and the zone of the named block of a device uid.
    named_blocks: Mapping[str, tuple[str, str | None]] = field(default_factory=dict)
    # The spine site of a metro and the codes of the sites of the metro beside it.
    spines: Mapping[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class Result:
    rows: list[Placement]
    replan_recommended: bool
    layout_version: int


def segment_uid(device: str, bridge_domain: str | None) -> str:
    return f"{device}/segment/{bridge_domain or 'none'}"


def segments_uid(device: str) -> str:
    """The layout element of the segment bar of `device`."""
    return f"{device}/segments"


def cable_id(a_port: str, b_port: str) -> str:
    return "~".join(sorted((a_port, b_port)))


def site_uid(code: str) -> str:
    return f"site:{code}"


def plate_uid(site: str) -> str:
    return UNASSIGNED_PLATE if site == UNASSIGNED_SITE else "plate:" + site.removeprefix("site:")


def region_uid(country: str) -> str:
    return f"region:{country}"


def group_uid(path: Sequence[str], core: bool) -> str:
    return f"{CORE_REGION if core else GROUP_REGION}:{GROUP_SEP.join(path)}"


def is_group(region: str) -> bool:
    return region.startswith((f"{GROUP_REGION}:", f"{CORE_REGION}:"))


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-").lower() or "block"


def site_country(code: str, hostnames: Iterable[str], located: str | None = None) -> str | None:
    """The country of the site's location, `located`, else the country token of the site code, else the most
    common one of the hostnames of its devices."""
    if located:
        country = located.upper()
        return _NAMING_TOKEN.get(country, country)
    own = _PLACE.match(code)
    if own:
        return own[1].upper()
    votes = Counter(m[1].upper() for m in map(_PLACE.match, hostnames) if m)
    return min(votes, key=lambda c: (-votes[c], c)) if votes else None


def is_cnc_code(code: str) -> bool:
    """Whether the site code, or the last token of it, is an Equinix IBX code."""
    return bool(_IBX.match(code) or _IBX.match(code.rsplit("-", 1)[-1]))


def _city(code: str) -> str:
    own = _PLACE.match(code)
    return own[2].upper() if own else ""


def _natural(name: str) -> tuple[Any, ...]:
    return tuple(int(t) if t.isdigit() else t for t in re.split(r"(\d+)", name.lower()))


def _ring(i: int) -> int:
    """The ring of cell `i` of the centred spiral. Ring k holds the cells (2k - 1)^2 to (2k + 1)^2 - 1."""
    return (math.isqrt(i) + 1) // 2


def _spiral(i: int) -> tuple[int, int]:
    """Cell `i` of a square spiral around the centre. Cell 0 is at the centre. Ring k is the 8k cells
    around ring k - 1, clockwise from the east side."""
    if i == 0:
        return (0, 0)
    k = _ring(i)
    j = i - (2 * k - 1) ** 2
    side = 2 * k
    if j < side:
        return (k, -k + 1 + j)
    j -= side
    if j < side:
        return (k - 1 - j, k)
    j -= side
    if j < side:
        return (-k, k - 1 - j)
    j -= side
    return (-k + 1 + j, -k)


@dataclass
class Hierarchy:
    sites: list[str]
    blocks: dict[str, tuple[str, str]]
    block_devices: dict[str, list[str]]
    device_block: dict[str, str]
    device_group: dict[str, str]
    group_block: dict[str, str]
    device_site: dict[str, str]
    layer: dict[str, int]
    parent: dict[str, str | None]
    children: dict[str, list[str]]
    names: dict[str, str]
    ports: dict[str, list[str]]
    port_device: dict[str, str]
    cables: dict[str, tuple[str, str]]
    segment_devices: set[str] = field(default_factory=set)
    # The sites that hold a device of `HUB_ROLE`.
    hub_sites: set[str] = field(default_factory=set)
    # The CNC sites. They sit in `CORE_REGION`.
    cnc_sites: set[str] = field(default_factory=set)
    site_region: dict[str, str] = field(default_factory=dict)
    # The sites of each block. The core block is in country and code order. A country block has the
    # hubs first in code order, then the other sites in city and code order.
    regions: dict[str, list[str]] = field(default_factory=dict)
    # The blocks from the estate's centre outwards: `CORE_REGION`, `CLOUD_REGION`, then the country blocks.
    region_order: list[str] = field(default_factory=list)
    # The site group a site group sits in, and the site groups in a site group.
    region_parent: dict[str, str | None] = field(default_factory=dict)
    region_children: dict[str, list[str]] = field(default_factory=dict)
    # The spine site of a metro and the sites of the metro beside it, in code order.
    spines: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def site_of_block(self, block: str) -> str:
        return self.blocks[block][0]

    def site_devices(self, site: str) -> list[str]:
        return sorted((d for d, s in self.device_site.items() if s == site), key=lambda d: (self.names[d], d))


def layer_of(device: Mapping[str, Any]) -> int:
    tier = device.get("tier")
    name = TIER_LAYER.get(str(tier)) if tier else ROLE_LAYER.get(str(device.get("role")), "other")
    return LAYERS.index(name or "other")


def hierarchy(estate: Estate) -> Hierarchy:
    """Sites, blocks, groups, devices, ports and cables of `estate`, with the
    planner's blocks and tier order."""
    devs = {d["uid"]: d for d in estate.devices}
    port_device = {p["uid"]: p["device_uid"] for p in estate.ports if p["device_uid"] in devs}
    port_name = {p["uid"]: p.get("name") or p["uid"] for p in estate.ports}
    cables: dict[str, tuple[str, str]] = {}
    for c in estate.cables:
        a, b = c["a_port"], c["b_port"]
        if a in port_device and b in port_device and a != b:
            cables.setdefault(cable_id(a, b), (a, b))
    model = planner.plan(
        [
            {
                "uid": uid,
                "name": d.get("name") or uid,
                "role": d.get("role"),
                "tier": d.get("tier"),
                "site": d.get("site"),
            }
            for uid, d in devs.items()
        ],
        [
            {"a_dev": port_device[a], "a_port": a, "b_dev": port_device[b], "b_port": b}
            for a, b in cables.values()
        ],
        (),
        (),
        [u for u in estate.wan_devices if u in devs],
    )
    nodes = {n["id"]: n for n in model["nodes"]}
    blocks: dict[str, tuple[str, str]] = {}
    device_block: dict[str, str] = {}
    device_site: dict[str, str] = {}
    layer: dict[str, int] = {}
    for node in model["nodes"]:
        if node["kind"] != "device":
            continue
        uid = node["id"]
        site = devs[uid].get("site")
        if site:
            block = node["parent"]
            blocks[block] = (site_uid(site), nodes[block]["block_kind"])
            device_site[uid] = site_uid(site)
        else:
            role = devs[uid].get("role") or "unknown"
            block = f"block:unassigned:{role}"
            blocks[block] = (UNASSIGNED_SITE, "role")
            device_site[uid] = UNASSIGNED_SITE
        device_block[uid] = block
        layer[uid] = layer_of(devs[uid])
    # A device of a named block leaves the block of its tier. A device of zone external or internet is
    # placed in the layer `external`, above the firewall.
    for uid, (name, zone) in sorted(estate.named_blocks.items()):
        site = device_site.get(uid)
        if site is None or site == UNASSIGNED_SITE:
            continue
        block = f"block:{site.removeprefix('site:')}{NAMED_INFIX}{_slug(name)}"
        blocks[block] = (site, f"{NAMED_KIND}:{zone or 'none'}:{name}")
        device_block[uid] = block
        if zone in EXTERNAL_ZONES:
            layer[uid] = min(layer[uid], LAYERS.index(EXTERNAL))
    held = set(device_block.values())
    blocks = {b: v for b, v in blocks.items() if b in held}

    names = {uid: str(d.get("name") or uid) for uid, d in devs.items()}
    device_group: dict[str, str] = {}
    group_block: dict[str, str] = {}
    for g in sorted(estate.groups, key=lambda g: g["uid"]):
        members = sorted({m for m in g.get("members") or [] if m in devs and m not in device_group})
        homes = {device_block[m] for m in members}
        if len(members) >= 2 and len(homes) == 1:
            group_block[g["uid"]] = homes.pop()
            for m in members:
                device_group[m] = g["uid"]

    # The uplink tree. The parent of a device is the cabled neighbour of the nearest higher layer in
    # the same site. The neighbour with the most cables is preferred, then the lowest name.
    links: dict[str, dict[str, int]] = {uid: {} for uid in devs}
    for a, b in cables.values():
        da, db = port_device[a], port_device[b]
        if da != db and device_site[da] == device_site[db]:
            links[da][db] = links[da].get(db, 0) + 1
            links[db][da] = links[db].get(da, 0) + 1
    parent: dict[str, str | None] = {}
    for uid in devs:
        above = [n for n in links[uid] if layer[n] < layer[uid]]
        parent[uid] = min(above, key=lambda n: (-layer[n], -links[uid][n], names[n], n)) if above else None
    children: dict[str, list[str]] = {uid: [] for uid in devs}
    for uid, p in parent.items():
        if p is not None:
            children[p].append(uid)
    for kids in children.values():
        kids.sort(key=lambda d: (names[d], d))

    block_devices: dict[str, list[str]] = {b: [] for b in blocks}
    for uid in sorted(device_block, key=lambda d: (names[d], d)):
        block_devices[device_block[uid]].append(uid)

    ports: dict[str, list[str]] = {uid: [] for uid in devs}
    for p in sorted(port_device, key=lambda p: (_natural(port_name[p]), p)):
        ports[port_device[p]].append(p)

    known = {s for s, _kind in blocks.values() if s != UNASSIGNED_SITE} | {site_uid(c) for c in estate.sites}
    far: dict[str, set[str]] = {}
    for a, b in estate.site_links:
        sa, sb = site_uid(a), site_uid(b)
        if sa != sb and sa in known and sb in known:
            far.setdefault(sa, set()).add(sb)
            far.setdefault(sb, set()).add(sa)
    sites = sorted(known, key=lambda s: s.removeprefix("site:"))
    hub_sites = {device_site[u] for u, d in devs.items() if d.get("role") == HUB_ROLE} & known
    hostnames: dict[str, list[str]] = {}
    for uid, s in device_site.items():
        hostnames.setdefault(s, []).append(names[uid])
    # A colocation site, a site with Fabric ports, or a virtual CNC.
    colo_sites = {
        device_site[u]
        for u, d in devs.items()
        if d.get("site_kind") == COLO or d.get("platform") in (NETWORK_EDGE, FABRIC_PLATFORM)
    }
    cnc_sites: set[str] = set()
    country_of: dict[str, str | None] = {}
    site_region: dict[str, str] = {}
    for s in sites:
        code = s.removeprefix("site:")
        country = country_of[s] = site_country(code, hostnames.get(s, ()), estate.site_countries.get(code))
        if is_cnc_code(code) or s in colo_sites:
            cnc_sites.add(s)
        if code in estate.cloud_sites:
            site_region[s] = CLOUD_REGION
        elif s in cnc_sites:
            site_region[s] = CORE_REGION
        else:
            site_region[s] = region_uid(country) if country else OTHER_REGION
    spines = {
        site_uid(c): tuple(site_uid(x) for x in xs if site_uid(x) in known)
        for c, xs in estate.spines.items()
        if site_uid(c) in known
    }
    # A site of a site group sits in the box of its group.
    paths = {site_uid(c): tuple(p) for c, p in estate.site_groups.items() if p and site_uid(c) in known}
    under: dict[tuple[str, ...], set[str]] = {}
    for s, path in paths.items():
        for n in range(1, len(path) + 1):
            under.setdefault(path[:n], set()).add(s)
    core_paths = {p for p, members in under.items() if all(m in cnc_sites or m in spines for m in members)}

    def group(path: tuple[str, ...]) -> str:
        return group_uid(path, path in core_paths)

    region_parent: dict[str, str | None] = {}
    region_children: dict[str, list[str]] = {}
    for path in sorted(under):
        uid = group(path)
        region_parent[uid] = group(path[:-1]) if len(path) > 1 else None
        region_children.setdefault(uid, [])
        if len(path) > 1:
            region_children.setdefault(group(path[:-1]), []).append(uid)
    for s, path in paths.items():
        site_region[s] = group(path)

    def member_order(s: str) -> tuple[Any, ...]:
        if s in cnc_sites:
            return (False, country_of[s] or "", s)
        return (s not in hub_sites, _city(s.removeprefix("site:")) if s not in hub_sites else "", s)

    regions: dict[str, list[str]] = {uid: [] for uid in region_parent}
    for s in sorted(sites, key=member_order):
        regions.setdefault(site_region[s], []).append(s)
    # The blocks whose sites join the most sites outside them sit nearest the centre.
    reach = {
        r: {f for s in members for f in far.get(s, ()) if site_region[f] != r}
        for r, members in regions.items()
    }
    tops = [r for r in regions if region_parent.get(r) is None]
    first = [r for r in (CORE_REGION, CLOUD_REGION) if regions.get(r)]
    first += sorted(r for r in tops if r.startswith(f"{CORE_REGION}:"))
    region_order = first + sorted(
        (r for r in tops if r not in first and r not in (CORE_REGION, CLOUD_REGION)),
        key=lambda r: (is_group(r), -len(reach[r]), -len(regions[r]), r),
    )
    return Hierarchy(
        sites=sites,
        blocks=blocks,
        block_devices=block_devices,
        device_block=device_block,
        device_group=device_group,
        group_block=group_block,
        device_site=device_site,
        layer=layer,
        parent=parent,
        children=children,
        names=names,
        ports=ports,
        port_device=port_device,
        cables=cables,
        segment_devices={d for d in estate.segment_devices if d in devs},
        hub_sites=hub_sites,
        cnc_sites=cnc_sites,
        site_region=site_region,
        regions=regions,
        region_order=region_order,
        region_parent=region_parent,
        region_children=region_children,
        spines=spines,
    )


@dataclass(frozen=True)
class _SitePlan:
    """The rows of a plate, top first. Each row has its layer and its devices with their half-slot
    column."""

    width: int
    rows: list[tuple[int, list[tuple[str, int]]]]

    @property
    def size(self) -> tuple[int, int]:
        return self.width * PITCH_W + 2 * PLATE_PAD, max(1, len(self.rows)) * PITCH_H + 2 * PLATE_PAD


# A box on the grid as (u, v, w, h).
Box = tuple[int, int, int, int]
# Boxes from the top-left corner of their block, each as (u, v, w, h, slot).
_Cells = dict[str, tuple[int, int, int, int, int]]


@dataclass(frozen=True)
class _RegionPlan:
    """The size of a block and the cell of each of its sites from its top-left corner, as
    (u, v, w, h, slot)."""

    w: int
    h: int
    cells: dict[str, tuple[int, int, int, int, int]]
    # The boxes of the site groups inside a site group, from its top-left corner, as (u, v, w, h, slot).
    regions: dict[str, tuple[int, int, int, int, int]] = field(default_factory=dict)


def _clash(a: tuple[int, int, int, int], b: tuple[int, int, int, int], gap: int) -> bool:
    """Whether the boxes `a` and `b`, each (u, v, w, h), come closer than `gap`."""
    return (
        a[0] < b[0] + b[2] + gap
        and b[0] < a[0] + a[2] + gap
        and a[1] < b[1] + b[3] + gap
        and b[1] < a[1] + a[3] + gap
    )


def _reach(spot: tuple[int, int], w: int, h: int) -> tuple[int, int, int, int]:
    """The sort key of a box at `spot`. The key is the Chebyshev distance of its centre from the
    origin, then the Manhattan distance, then the spot."""
    du, dv = abs(2 * spot[0] + w), abs(2 * spot[1] + h)
    return max(du, dv), du + dv, spot[1], spot[0]


# The most boxes `_pack` places one against another.
PACK_NEAREST_MAX = 64


def _shelves(sizes: Sequence[tuple[int, int]], gap: int) -> list[tuple[int, int]]:
    """The top-left corners of boxes of `sizes`, in order, in rows `gap` apart that are about as wide as
    the whole is tall, a row as high as its highest box."""
    area = sum((w + gap) * (h + gap) for w, h in sizes)
    width = max(math.isqrt(area), max((w for w, _h in sizes), default=0))
    corners: list[tuple[int, int]] = []
    x = y = row = 0
    for w, h in sizes:
        if x and x + w > width:
            x, y, row = 0, y + row + gap, 0
        corners.append((x, y))
        x, row = x + w + gap, max(row, h)
    return corners


def _pack(sizes: Sequence[tuple[int, int]], gap: int) -> list[tuple[int, int]]:
    """The top-left corners of boxes of `sizes`, in order. The first box is centred on the origin.
    Each next box is placed against a side of a box placed before it, `gap` apart, at the free spot
    whose centre is nearest the origin. More than `PACK_NEAREST_MAX` boxes are laid in rows from the
    origin."""
    if len(sizes) > PACK_NEAREST_MAX:
        return _shelves(sizes, gap)
    placed: list[tuple[int, int, int, int]] = []
    for w, h in sizes:
        spots = {(-(w // 2), -(h // 2))} if not placed else set()
        for pu, pv, pw, ph in placed:
            for u in (pu, pu + pw - w, pu + (pw - w) // 2):
                spots |= {(u, pv - gap - h), (u, pv + ph + gap)}
            for v in (pv, pv + ph - h, pv + (ph - h) // 2):
                spots |= {(pu - gap - w, v), (pu + pw + gap, v)}
        for _key, (u, v) in sorted((_reach(s, w, h), s) for s in spots):
            if not any(_clash((u, v, w, h), p, gap) for p in placed):
                placed.append((u, v, w, h))
                break
    return [(u, v) for u, v, _w, _h in placed]


def _cover(sizes: Sequence[tuple[int, int]]) -> tuple[int, int]:
    """The width and the height that `CELL_SHARE` of `sizes` fit in, each by its nearest rank."""
    if not sizes:
        return DEVICE_W, DEVICE_H
    rank = max(0, math.ceil(CELL_SHARE * len(sizes)) - 1)
    return sorted(w for w, _h in sizes)[rank], sorted(h for _w, h in sizes)[rank]


def _trunk_halves(h: Hierarchy, trunk: Mapping[int, list[str]]) -> tuple[int, dict[str, int]]:
    """The width in slots of the trunk rows and the half slot of each trunk device from their left edge.

    Each block takes one column range in every trunk row it has devices in. 2 blocks whose rows overlap
    take ranges side by side, and the area of a block holds only its own devices. A block that overlaps
    no other block sits centred.
    """
    line = {layer: i for i, layer in enumerate(sorted(trunk))}
    members: dict[str, dict[int, list[str]]] = {}
    for layer, devs in trunk.items():
        for d in devs:
            members.setdefault(h.device_block[d], {}).setdefault(line[layer], []).append(d)
    order = sorted(members, key=lambda b: (min(members[b]), b))
    span = {b: (min(members[b]), max(members[b])) for b in order}
    width = {b: max(len(ds) for ds in members[b].values()) for b in order}

    def overlap(a: str, b: str) -> bool:
        return a != b and span[a][0] <= span[b][1] and span[b][0] <= span[a][1]

    start: dict[str, int] = {}
    for b in order:
        x = 0
        for lo, hi in sorted((start[o], start[o] + width[o]) for o in start if overlap(o, b)):
            if x + width[b] <= lo:
                break
            x = max(x, hi)
        start[b] = x
    total = max((start[b] + width[b] for b in order), default=0)
    halves: dict[str, int] = {}
    for b in order:
        base = 2 * start[b] if any(overlap(o, b) for o in order) else total - width[b]
        for ds in members[b].values():
            for i, d in enumerate(ds):
                halves[d] = base + width[b] - len(ds) + 2 * i
    return total, halves


def _cell(plate: Placement, line: int, half: int) -> tuple[int, int]:
    return plate.u + PLATE_PAD + GAP // 2 + half * HALF, plate.v + PLATE_PAD + line * PITCH_H


def _plan_site(h: Hierarchy, site: str) -> _SitePlan:
    """The layered drawing of `site`. The trunk layers are centred on top. The closets are side by
    side below as tidy trees, wrapped at the width bound."""
    devices = h.site_devices(site)
    if site == UNASSIGNED_SITE:
        roles: list[tuple[int, list[tuple[str, int]]]] = []
        for block in sorted(b for b, (s, _kind) in h.blocks.items() if s == site):
            roles.append((LAYERS.index("other"), [(d, 2 * i) for i, d in enumerate(h.block_devices[block])]))
        return _SitePlan(max((len(r[1]) for r in roles), default=1), roles)

    def inside(d: str) -> bool:
        return h.device_site.get(d) == site and LAYERS[h.layer[d]] not in TRUNK

    def kids(d: str) -> list[str]:
        return [c for c in h.children[d] if inside(c)]

    widths: dict[str, int] = {}

    def width(d: str) -> int:
        if d not in widths:
            widths[d] = max(1, sum(width(c) for c in kids(d)))
        return widths[d]

    def place(d: str, x: int, out: dict[str, int]) -> int:
        xs = []
        for c in kids(d):
            xs.append(place(c, x, out))
            x += 2 * widths[c]
        out[d] = (xs[0] + xs[-1]) // 2 if xs else x
        return out[d]

    trunk: dict[int, list[str]] = {}
    owners: list[str] = []
    for d in devices:
        if LAYERS[h.layer[d]] in TRUNK:
            trunk.setdefault(h.layer[d], []).append(d)
        elif (p := h.parent[d]) is None or not inside(p):
            owners.append(d)
    owners.sort(key=lambda d: (h.layer[d], h.names[d], d))
    # The width bound counts device slots. The spare column between closets is added to it.
    bound = max(math.ceil(math.sqrt(3 * len(devices))), *(width(o) for o in owners), 1)
    closet_rows: list[dict[str, int]] = []
    current: dict[str, int] = {}
    x = used = 0
    for owner in owners:
        if current and used + width(owner) > bound:
            closet_rows.append(current)
            current, x, used = {}, 0, 0
        place(owner, 2 * x, current)
        # A closet with children keeps a spare column for growth. A lone device sits next to its neighbour.
        x += width(owner) + (1 if kids(owner) else 0)
        used += width(owner)
    if current:
        closet_rows.append(current)
    trunk_w, trunk_at = _trunk_halves(h, trunk)
    total = max([1, trunk_w, *((max(xs.values()) // 2 + 1) for xs in closet_rows)])
    # The segment bars of the trunk devices join the segment row of the first closet row group.
    trunk_halves = {d: total - trunk_w + half for d, half in trunk_at.items()}
    pending = {d: half for d, half in trunk_halves.items() if d in h.segment_devices}
    if not closet_rows and pending:
        closet_rows.append({})
    segment_rows: list[list[tuple[str, int]]] = []
    for i, xs in enumerate(closet_rows):
        bars = {d: half for d, half in xs.items() if d in h.segment_devices}
        if i == 0:
            bars.update(pending)
        segment_rows.append(_segment_row(bars))
    # A segment row with more bars than columns widens the plate.
    total = max([total, *(x // 2 + 1 for row in segment_rows for _uid, x in row)])
    rows: list[tuple[int, list[tuple[str, int]]]] = []
    for layer in sorted(trunk):
        line = [(d, total - trunk_w + trunk_at[d]) for d in trunk[layer]]
        rows.append((layer, sorted(line, key=lambda e: (e[1], e[0]))))
    for xs, bar_row in zip(closet_rows, segment_rows, strict=True):
        by_layer: dict[int, list[tuple[str, int]]] = {}
        for d, half in xs.items():
            by_layer.setdefault(h.layer[d], []).append((d, half))
        for layer in sorted(by_layer):
            rows.append((layer, sorted(by_layer[layer], key=lambda e: (e[1], e[0]))))
        if bar_row:
            rows.append((LAYERS.index("segment"), bar_row))
    return _SitePlan(total, rows)


def _segment_row(bars: Mapping[str, int]) -> list[tuple[str, int]]:
    """The segment bars under the column of their device. A bar whose column is taken goes to the
    next free slot."""
    taken: set[int] = set()
    out: list[tuple[str, int]] = []
    for device, half in sorted(bars.items(), key=lambda e: (e[1], e[0])):
        x = half
        while any(abs(x - t) < 2 for t in taken):
            x += 2
        taken.add(x)
        out.append((segments_uid(device), x))
    return sorted(out, key=lambda e: (e[1], e[0]))


@dataclass
class _Builder:
    h: Hierarchy
    rows: dict[str, Placement]
    run_key: int
    version: int
    reason: str
    written: dict[str, Placement] = field(default_factory=dict)
    replan_recommended: bool = False
    _plans: dict[str, _SitePlan] = field(default_factory=dict)
    _site_uids: dict[str, set[str]] | None = None
    _annex_uids: dict[str, set[str]] | None = None
    _far: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for a, b in self.h.cables.values():
            self._far.setdefault(a, self.h.port_device[b])
            self._far.setdefault(b, self.h.port_device[a])

    def plan(self, site: str) -> _SitePlan:
        if site not in self._plans:
            self._plans[site] = _plan_site(self.h, site)
        return self._plans[site]

    def row_site(self, p: Placement) -> str | None:
        """The site that holds the row of a device or a segment bar. It is the site of its block, else the
        site of its device in the run. A device that changes site keeps the row of its old site until it
        is placed again."""
        device = p.uid if p.kind == "device" else p.parent_uid or ""
        return self.site_of_row(p) or self.h.device_site.get(device)

    def _index(self, p: Placement) -> None:
        if p.kind not in ("device", "segment"):
            return
        site = self.row_site(p) or ""
        if p.kind == "device" and self._site_uids is not None:
            self._site_uids.setdefault(site, set()).add(p.uid)
        if p.slot == NO_SLOT and self._annex_uids is not None:
            self._annex_uids.setdefault(site, set()).add(p.uid)

    def site_rows(self, site: str) -> list[Placement]:
        """The device rows in force in the grid of the plate of `site`."""
        if self._site_uids is None:
            self._site_uids = {}
            for row in self.rows.values():
                self._index(row)
        rows = (self.rows[u] for u in self._site_uids.get(site, ()))
        return [r for r in rows if (r.slot or 0) >= 0 and self.row_site(r) == site]

    def annex_rows(self, site: str) -> list[Placement]:
        """The device and segment rows in force in the annex rows of `site`."""
        if self._annex_uids is None:
            self._annex_uids = {}
            for row in self.rows.values():
                self._index(row)
        rows = (self.rows[u] for u in self._annex_uids.get(site, ()))
        return [r for r in rows if r.slot == NO_SLOT and self.row_site(r) == site]

    def put(self, p: Placement) -> Placement:
        p = Placement(**{**p.__dict__, "valid_from_ts": self.run_key, "layout_version": self.version})
        old = self.rows.get(p.uid)
        if old is not None and old.layout_version == self.version and old.same_place(p):
            return old
        if p.reason == ANNEX:
            self.replan_recommended = True
        self.rows[p.uid] = p
        self.written[p.uid] = p
        self._index(p)
        return p

    def plate_size(self, site: str) -> tuple[int, int]:
        return self.plan(site).size

    def annex_height(self, site: str) -> int:
        return 2 * PITCH_H + CHANNEL

    def cell_size(self, site: str) -> tuple[int, int]:
        w, h = self.plate_size(site)
        return w, h + self.annex_height(site)

    # --- sites and plates ---------------------------------------------------------------

    def unassigned(self) -> bool:
        """Whether a device of the run has no site."""
        return UNASSIGNED_SITE in self.h.device_site.values()

    def place_sites(self) -> None:
        if not any(r.kind in ("region", "site") for r in self.rows.values()):
            self.plan_sites()
            return
        if CLOUD_REGION in self.h.regions and CLOUD_REGION not in self.rows:
            right = max(r.u + r.w for r in self.rows.values() if r.kind in ("region", "site"))
            slot = max((r.slot or 0) for r in self.rows.values() if r.kind == "region") + 1
            self.put_region(CLOUD_REGION, right + REGION_GAP, 0, slot, FIRST_SEEN)
        overflow_u = 0
        overflow_v = max(r.v + r.h for r in self.rows.values() if r.kind in ("region", "site")) + REGION_GAP
        for site in self.h.sites:
            if site in self.rows:
                continue
            region = self.h.site_region[site]
            cell = self.free_site_cell(site, region)
            if cell is not None:
                u, v, w, h, slot = cell
                self.put_site(site, u, v, w, h, slot, FIRST_SEEN, region)
                continue
            w, h = self.cell_size(site)
            if region not in self.rows:
                self.put(
                    Placement(
                        region, "region", None, overflow_u, overflow_v, w, h, slot=NO_SLOT, reason=ANNEX
                    )
                )
            self.put_site(site, overflow_u, overflow_v, w, h, NO_SLOT, ANNEX, region)
            overflow_u += w + SITE_GAP
        if self.unassigned() and UNASSIGNED_SITE not in self.rows:
            right = max(r.u + r.w for r in self.rows.values() if r.kind in ("region", "site"))
            w, h = self.cell_size(UNASSIGNED_SITE)
            self.put_site(UNASSIGNED_SITE, right + REGION_GAP, 0, w, h, NO_SLOT, FIRST_SEEN, None)

    def free_site_cell(self, site: str, region: str) -> tuple[int, int, int, int, int] | None:
        """The free spot for `site` inside its country block nearest the centre of the block, as
        (u, v, w, h, slot).

        A spot sits against a site of the block, `SITE_GAP` apart, and keeps that gap to every other site.
        """
        block = self.rows.get(region)
        if block is None or block.slot == NO_SLOT:
            return None
        members = [r for r in self.rows.values() if r.kind == "site" and r.parent_uid == region]
        w, h = self.cell_size(site)
        spots = [(block.u, block.v)]
        for r in members:
            spots += [(r.u + r.w + SITE_GAP, r.v), (r.u, r.v + r.h + SITE_GAP)]
            spots += [(r.u - SITE_GAP - w, r.v), (r.u, r.v - SITE_GAP - h)]
        cu, cv = 2 * block.u + block.w, 2 * block.v + block.h
        for u, v in sorted(
            set(spots), key=lambda s: (abs(2 * s[0] + w - cu) + abs(2 * s[1] + h - cv), s[1], s[0])
        ):
            inside = (
                block.u <= u and u + w <= block.u + block.w and block.v <= v and v + h <= block.v + block.h
            )
            if inside and not any(_clash((u, v, w, h), (r.u, r.v, r.w, r.h), SITE_GAP) for r in members):
                return u, v, w, h, max((r.slot or 0) for r in members) + 1 if members else 0
        return None

    def plan_sites(self) -> None:
        """The blocks packed around the estate's centre in their order."""
        plans = [(region, self.plan_region(region)) for region in self.h.region_order]
        corners = _pack([(p.w, p.h) for _r, p in plans], REGION_GAP)
        u0 = -min((u for u, _v in corners), default=0)
        v0 = -min((v for _u, v in corners), default=0)
        right = -REGION_GAP
        for i, ((region, plan), (u, v)) in enumerate(zip(plans, corners, strict=True)):
            self.put_region(region, u + u0, v + v0, i, self.reason, plan)
            right = max(right, u + u0 + plan.w)
        if self.unassigned():
            w, h = self.cell_size(UNASSIGNED_SITE)
            self.put_site(UNASSIGNED_SITE, right + REGION_GAP, 0, w, h, NO_SLOT, self.reason, None)

    def put_region(
        self, region: str, u: int, v: int, slot: int, reason: str, plan: _RegionPlan | None = None
    ) -> None:
        plan = plan or self.plan_region(region)
        parent = self.h.region_parent.get(region)
        self.put(Placement(region, "region", parent, u, v, plan.w, plan.h, slot=slot, reason=reason))
        for child, (cu, cv, cw, ch, k) in plan.regions.items():
            parent = self.h.region_parent.get(child)
            self.put(Placement(child, "region", parent, u + cu, v + cv, cw, ch, slot=k, reason=reason))
        for site, (su, sv, sw, sh, cell) in plan.cells.items():
            self.put_site(site, u + su, v + sv, sw, sh, cell, reason, self.h.site_region.get(site, region))

    def plan_group(self, region: str) -> _RegionPlan:
        """The plan of a site group. Each Fabric spine sits between the sites of its metro. These units,
        the other sites and the site groups inside the group are packed around its centre, with a padding."""
        members = self.h.regions.get(region, [])
        units: list[tuple[int, int, _Cells, _Cells]] = []
        done: set[str] = set()
        for spine in sorted(s for s in members if s in self.h.spines):
            beside = [s for s in self.h.spines[spine] if s in members]
            cells: _Cells = {}
            x = height = 0
            for site in [*beside[:1], spine, *beside[1:]]:
                w, h = self.cell_size(site)
                cells[site] = (x, 0, w, h, 0)
                x, height = x + w + SITE_GAP, max(height, h)
                done.add(site)
            # The spine runs the height of the sites beside it.
            su, sv, sw, _sh, _slot = cells[spine]
            cells[spine] = (su, sv, sw, height, 0)
            units.append((x - SITE_GAP, height, cells, {}))
        for site in members:
            if site not in done:
                w, h = self.cell_size(site)
                units.append((w, h, {site: (0, 0, w, h, 0)}, {}))
        for k, child in enumerate(self.h.region_children.get(region, [])):
            plan = self.plan_region(child)
            units.append((plan.w, plan.h, plan.cells, {child: (0, 0, plan.w, plan.h, k), **plan.regions}))
        if not units:
            return _RegionPlan(2 * GROUP_PAD, 2 * GROUP_PAD, {})
        corners = _pack([(w, h) for w, h, _c, _r in units], SITE_GAP)
        u0 = GROUP_PAD - min(u for u, _v in corners)
        v0 = GROUP_PAD - min(v for _u, v in corners)
        out_cells: _Cells = {}
        out_regions: _Cells = {}
        for (cu, cv), (_w, _h, cells, regions) in zip(corners, units, strict=True):
            for site, (su, sv, sw, sh, _slot) in cells.items():
                out_cells[site] = (cu + u0 + su, cv + v0 + sv, sw, sh, len(out_cells))
            for child, (ru, rv, rw, rh, k) in regions.items():
                out_regions[child] = (cu + u0 + ru, cv + v0 + rv, rw, rh, k)
        w = max(cu + u0 + uw for (cu, _cv), (uw, _uh, _c, _r) in zip(corners, units, strict=True)) + GROUP_PAD
        h = max(cv + v0 + uh for (_cu, cv), (_uw, uh, _c, _r) in zip(corners, units, strict=True)) + GROUP_PAD
        return _RegionPlan(w, h, out_cells, out_regions)

    def plan_region(self, region: str) -> _RegionPlan:
        """The plan of `region`. The hubs and the sites larger than the spiral cell form a near-square
        group at its centre. The other sites lie on a square spiral around the group, with 25 percent
        spare cells. The spiral cell holds `CELL_SHARE` of the other sites. The core block is one group
        of all its sites."""
        if is_group(region):
            return self.plan_group(region)
        members = self.h.regions[region]
        if region == CORE_REGION:
            group = set(members)
        else:
            others = {s: self.cell_size(s) for s in members if s not in self.h.hub_sites}
            cover_w, cover_h = _cover(list(others.values()))
            group = self.h.hub_sites | {s for s, (w, h) in others.items() if w > cover_w or h > cover_h}
        hubs = [s for s in members if s in group]
        spokes = [s for s in members if s not in group]
        sizes = [self.cell_size(s) for s in spokes] or [(DEVICE_W, DEVICE_H)]
        cell_w, cell_h = max(w for w, _h in sizes), max(h for _w, h in sizes)
        pitch_w, pitch_h = cell_w + SITE_GAP, cell_h + SITE_GAP
        hub_w = max((self.cell_size(s)[0] for s in hubs), default=0)
        hub_h = max((self.cell_size(s)[1] for s in hubs), default=0)
        cols = math.ceil(math.sqrt(len(hubs)))
        lines = math.ceil(len(hubs) / cols) if hubs else 0
        group_w = cols * hub_w + SITE_GAP * max(0, cols - 1)
        group_h = lines * hub_h + SITE_GAP * max(0, lines - 1)
        span = max(math.ceil((group_w + SITE_GAP) / pitch_w), math.ceil((group_h + SITE_GAP) / pitch_h))
        inner_rings = math.ceil((span - 1) / 2) if hubs else 0
        inner_cells = (2 * inner_rings + 1) ** 2 if hubs else 0
        inner_w = (2 * inner_rings + 1) * pitch_w - SITE_GAP
        inner_h = (2 * inner_rings + 1) * pitch_h - SITE_GAP
        # The cells are relative to the centre cell of the spiral. The return value has the top-left
        # corner of the block at 0, 0.
        cells: dict[str, tuple[int, int, int, int, int]] = {}
        gu = -inner_rings * pitch_w + (inner_w - group_w) // 2
        gv = -inner_rings * pitch_h + (inner_h - group_h) // 2
        for k, hub in enumerate(hubs):
            w, h = self.cell_size(hub)
            cells[hub] = (
                gu + (k % cols) * (hub_w + SITE_GAP),
                gv + (k // cols) * (hub_h + SITE_GAP),
                w,
                h,
                k,
            )
        for j, site in enumerate(spokes):
            x, y = _spiral(inner_cells + j)
            cells[site] = (x * pitch_w, y * pitch_h, cell_w, cell_h, inner_cells + j)
        boxes = [(gu, gv, group_w, group_h)] if hubs else []
        for j in range(len(spokes) + math.ceil(len(spokes) * SITE_GROWTH)):
            x, y = _spiral(inner_cells + j)
            boxes.append((x * pitch_w, y * pitch_h, cell_w, cell_h))
        u0, v0 = min(b[0] for b in boxes), min(b[1] for b in boxes)
        w = max(b[0] + b[2] for b in boxes) - u0
        h = max(b[1] + b[3] for b in boxes) - v0
        return _RegionPlan(
            w, h, {s: (u - u0, v - v0, cw, ch, slot) for s, (u, v, cw, ch, slot) in cells.items()}
        )

    def put_site(
        self, site: str, u: int, v: int, w: int, h: int, slot: int, reason: str, region: str | None
    ) -> None:
        self.put(Placement(site, "site", region, u, v, w, h, slot=slot, reason=reason))
        plan = self.plan(site)
        plate_w, plate_h = plan.size
        if site in self.h.spines:
            plate_h = max(plate_h, h - self.annex_height(site))
        plate = self.put(Placement(plate_uid(site), "plate", site, u, v, plate_w, plate_h, reason=reason))
        for line, (layer, devices) in enumerate(plan.rows):
            for uid, half in devices:
                if LAYERS[layer] == "segment":
                    self.put_segment(uid, plate, line, half, reason)
                else:
                    self.put_device(uid, plate, line, half, reason)

    def put_device(self, device: str, plate: Placement, line: int, half: int, reason: str) -> None:
        u, v = _cell(plate, line, half)
        parent = self.h.device_group.get(device, self.h.device_block[device])
        self.put(Placement(device, "device", parent, u, v, DEVICE_W, DEVICE_H, slot=half, reason=reason))

    def put_segment(self, uid: str, plate: Placement, line: int, half: int, reason: str) -> None:
        u, v = _cell(plate, line, half)
        device = uid.removesuffix("/segments")
        self.put(Placement(uid, "segment", device, u, v, DEVICE_W, DEVICE_H, slot=half, reason=reason))

    def site_of_row(self, row: Placement) -> str | None:
        seen = 0
        while row.kind not in ("site",) and row.parent_uid is not None and seen < 8:
            parent = self.rows.get(row.parent_uid)
            if parent is None:
                return None
            row, seen = parent, seen + 1
        return row.uid if row.kind == "site" else None

    def annex_cell(self, site: str, w: int, h: int, skip: str | None = None) -> tuple[int, int]:
        """The next cell of the annex rows below the rows of the plate of `site`, on the columns of the plate,
        within the planned width of the site. The row of `skip`, the element being placed again, takes no
        cell."""
        plate = self.rows[plate_uid(site)]
        cell_u, _v, cell_w, _h = self.planned_site(site)
        left, top = cell_u + PLATE_PAD + GAP // 2, plate.v + plate.h + GAP
        annexed = [r for r in self.annex_rows(site) if r.uid != skip]
        if not annexed:
            return left, top
        line_v = max(r.v for r in annexed)
        u = max(r.u + r.w for r in annexed if r.v == line_v) + GAP
        if u + w > cell_u + cell_w - PLATE_PAD:
            return left, max(r.v + r.h for r in annexed) + GAP
        return u, line_v

    # --- devices ------------------------------------------------------------------------

    def device_block_of(self, row: Placement) -> str | None:
        parent = row.parent_uid
        if parent is not None and parent in self.h.group_block:
            return self.h.group_block[parent]
        prow = self.rows.get(parent or "")
        if prow is not None and prow.kind == "group":
            return prow.parent_uid
        return parent

    def place_devices(self) -> None:
        for site in [*self.h.sites, UNASSIGNED_SITE]:
            for device in self.h.site_devices(site):
                row = self.rows.get(device)
                parent = self.h.device_group.get(device, self.h.device_block[device])
                if row is not None and self.holds(row, site):
                    if row.parent_uid != parent:
                        moved = {**row.__dict__, "parent_uid": parent, "reason": RELATION_RESOLVED}
                        self.put(Placement(**moved))
                    continue
                reason = FIRST_SEEN if row is None else RELATION_RESOLVED
                self.place_new_device(device, site, parent, reason)

    def holds(self, row: Placement, site: str) -> bool:
        """Whether the row in force of a device stays in `site`. The row sits in a block of `site`, or,
        when its block has no row, its cell lies inside the site cell. A device keeps its cell while its
        site stays the same, also in the annex rows."""
        home = self.site_of_row(row)
        return home == site if home is not None else self.in_site(row, site)

    def in_site(self, row: Placement, site: str) -> bool:
        """Whether the cell of `row` lies inside the site cell of `site`, plate or annex."""
        cell = self.rows.get(site)
        return cell is not None and cell.u <= row.u < cell.u + cell.w and cell.v <= row.v < cell.v + cell.h

    def free_cell(self, device: str, site: str) -> tuple[int, int, int] | None:
        """The free cell in the layer row of `device` nearest to the column of its parent, as (u, v, half)."""
        plate = self.rows[plate_uid(site)]
        rows = self.site_rows(site)
        same = [r for r in rows if r.uid != device and self.h.layer.get(r.uid) == self.h.layer[device]]
        if not same:
            return None
        v = min(r.v for r in same)
        line = [r for r in rows if r.v == v and r.uid != device]
        up = self.h.parent.get(device)
        parent_row = self.rows.get(up) if up is not None else None
        if parent_row is not None and self.in_site(parent_row, site):
            target = parent_row.u
        else:
            target = plate.u + plate.w // 2 - DEVICE_W // 2
        last_half = (plate.w - 2 * PLATE_PAD - GAP // 2 - DEVICE_W) // HALF
        for half in sorted(range(last_half + 1), key=lambda x: (abs(_cell(plate, 0, x)[0] - target), x)):
            u = _cell(plate, 0, half)[0]
            if all(abs(r.u - u) >= PITCH_W for r in line):
                return u, v, half
        return None

    def place_new_device(self, device: str, site: str, parent: str, reason: str) -> None:
        cell = self.free_cell(device, site)
        if cell is not None:
            u, v, half = cell
            self.put(Placement(device, "device", parent, u, v, DEVICE_W, DEVICE_H, slot=half, reason=reason))
            return
        u, v = self.annex_cell(site, DEVICE_W, DEVICE_H)
        self.put(Placement(device, "device", parent, u, v, DEVICE_W, DEVICE_H, slot=NO_SLOT, reason=ANNEX))

    def place_segments(self) -> None:
        """A new segment bar takes the free cell in the planned segment row below its device nearest its
        column, else a cell of the annex rows. A bar left away from its device is placed again that way."""
        for device in sorted(self.h.segment_devices):
            uid = segments_uid(device)
            dev = self.rows.get(device)
            if dev is None:
                continue
            site = self.h.device_site[device]
            bar = self.rows.get(uid)
            if bar is not None and not self.bar_left(bar, dev, site):
                continue
            plate = self.rows.get(plate_uid(site))
            bars = [
                r
                for r in self.rows.values()
                if r.kind == "segment" and r.uid != uid and r.slot is not None and r.slot >= 0
                if self.in_site(r, site) and r.v > dev.v
            ]
            reason = FIRST_SEEN if bar is None else RELATION_RESOLVED
            if plate is None or not bars:
                u, v = self.annex_cell(site, DEVICE_W, DEVICE_H, uid)
                self.put(
                    Placement(uid, "segment", device, u, v, DEVICE_W, DEVICE_H, slot=NO_SLOT, reason=ANNEX)
                )
                continue
            v = min(r.v for r in bars)
            line = [r for r in bars if r.v == v]
            last_half = (plate.w - 2 * PLATE_PAD - GAP // 2 - DEVICE_W) // HALF
            for half in sorted(range(last_half + 1), key=lambda x: (abs(_cell(plate, 0, x)[0] - dev.u), x)):
                u = _cell(plate, 0, half)[0]
                if all(abs(r.u - u) >= PITCH_W for r in line):
                    self.put(
                        Placement(uid, "segment", device, u, v, DEVICE_W, DEVICE_H, slot=half, reason=reason)
                    )
                    break
            else:
                u, v = self.annex_cell(site, DEVICE_W, DEVICE_H, uid)
                self.put(
                    Placement(uid, "segment", device, u, v, DEVICE_W, DEVICE_H, slot=NO_SLOT, reason=ANNEX)
                )

    def bar_left(self, bar: Placement, dev: Placement, site: str) -> bool:
        """Whether the segment bar `bar` may lie away from its device `dev` of `site`. True when the bar
        lies outside the site cell, or when it was placed before the row of its device. A device placed
        again in a new cell gets a new row. A bar placed again on its own cell writes no row."""
        return not self.in_site(bar, site) or bar.valid_from_ts < dev.valid_from_ts

    def place_blocks(self) -> None:
        """A block is the bounding box of the device rows in force in it and of their segment bars, plus
        a margin. The rows include a device that the run does not hold."""
        held: dict[str, list[Placement]] = {}
        for row in self.rows.values():
            block = self.device_block_of(row) if row.kind == "device" else None
            if block is not None:
                held.setdefault(block, []).append(row)
        for block, (site, _kind) in sorted(self.h.blocks.items()):
            devices = held.get(block, [])
            members = devices + [
                self.rows[segments_uid(r.uid)] for r in devices if segments_uid(r.uid) in self.rows
            ]
            if not members:
                continue
            u, v = min(r.u for r in members) - BLOCK_MARGIN, min(r.v for r in members) - BLOCK_MARGIN
            w = max(r.u + r.w for r in members) + BLOCK_MARGIN - u
            h = max(r.v + r.h for r in members) + BLOCK_MARGIN - v
            annexed = all(r.slot == NO_SLOT for r in members)
            reason = self.reason if block not in self.rows or self.reason == REPLAN else RELATION_RESOLVED
            slot = NO_SLOT if annexed else 0
            self.put(Placement(block, "block", plate_uid(site), u, v, w, h, slot=slot, reason=reason))

    def fit_sites(self) -> None:
        """A plate covers the blocks of its site, with the plate padding around them. A site covers its
        plate, with the name channel below it. No child exceeds its parent. Neither is smaller than its
        planned box. Only an annex grows a plate. The grown rows take `reason = relation-resolved`, as a
        grown block does, and keep their planned box in `points`."""
        blocks: dict[str, list[Placement]] = {}
        for block, (site, _kind) in sorted(self.h.blocks.items()):
            if block in self.rows:
                blocks.setdefault(site, []).append(self.rows[block])
        pad = PLATE_PAD - BLOCK_MARGIN
        for site, rows in sorted(blocks.items()):
            plate, cell = self.rows.get(plate_uid(site)), self.rows.get(site)
            if plate is None or cell is None:
                continue
            boxes = [(b.u - pad, b.v - pad, b.w + 2 * pad, b.h + 2 * pad) for b in rows]
            plate = self.fit(plate, self.planned_box(plate, partial(self.recovered_plate, site)), boxes)
            self.fit(cell, self.planned_site(site), [(plate.u, plate.v, plate.w, plate.h + CHANNEL)])

    def planned_box(self, row: Placement, recover: Callable[[], Box]) -> Box:
        """The planned box of a site or plate row. It is the box in its `points` when a fit grew it, and
        its own box when it did not grow. For a grown row without a box in `points`, it is the box that
        `recover` gives."""
        if row.points:
            (u, v), (right, bottom) = json.loads(row.points)
            return u, v, right - u, bottom - v
        if row.reason == RELATION_RESOLVED:
            return recover()
        return row.u, row.v, row.w, row.h

    def planned_site(self, site: str) -> Box:
        """The planned box of the cell of `site`. For a grown cell without a box in `points`, it is the
        recovered plate with the annex strip below it."""

        def recover() -> Box:
            u, v, w, h = self.planned_box(self.rows[plate_uid(site)], lambda: self.recovered_plate(site))
            return u, v, w, h + self.annex_height(site)

        return self.planned_box(self.rows[site], recover)

    def recovered_plate(self, site: str) -> Box:
        """The plan box of the plate of `site` from the device and segment rows in its grid. It spans the
        columns up to the last slot and the rows down to the last line. A bar left away from its device is
        not counted."""
        plate = self.rows[plate_uid(site)]

        def planned(r: Placement) -> bool:
            if r.kind not in ("device", "segment") or r.slot is None or r.slot < 0 or r.v < plate.v:
                return False
            if r.kind == "segment":
                dev = self.rows.get(r.parent_uid or "")
                if dev is None or self.bar_left(r, dev, site):
                    return False
            return self.row_site(r) == site

        grid = [r for r in self.rows.values() if planned(r)]
        if not grid:
            return plate.u, plate.v, PITCH_W + 2 * PLATE_PAD, PITCH_H + 2 * PLATE_PAD
        u = min(r.u - PLATE_PAD - GAP // 2 - (r.slot or 0) * HALF for r in grid)
        width = max((r.slot or 0) // 2 for r in grid) + 1
        lines = max((r.v - plate.v - PLATE_PAD) // PITCH_H for r in grid) + 1
        return u, plate.v, width * PITCH_W + 2 * PLATE_PAD, lines * PITCH_H + 2 * PLATE_PAD

    def fit(self, row: Placement, planned: Box, boxes: Sequence[Box]) -> Placement:
        """`row` as the bounding box of its planned box and each of `boxes`. The row grows over the boxes
        and shrinks back to its planned box when they shrink. A row that `fit` writes keeps its planned
        box in `points`. The row in force is returned when it fits. A grown row without a box in `points`
        is written once with the box."""
        u = min([planned[0], *(b[0] for b in boxes)])
        v = min([planned[1], *(b[1] for b in boxes)])
        right = max([planned[0] + planned[2], *(b[0] + b[2] for b in boxes)])
        bottom = max([planned[1] + planned[3], *(b[1] + b[3] for b in boxes)])
        box = (u, v, right - u, bottom - v)
        if box == (row.u, row.v, row.w, row.h) and (row.points or row.reason != RELATION_RESOLVED):
            return row
        corners = [[planned[0], planned[1]], [planned[0] + planned[2], planned[1] + planned[3]]]
        points = json.dumps(corners, separators=(",", ":"))
        fitted = {**row.__dict__, "u": u, "v": v, "w": box[2], "h": box[3], "points": points}
        return self.put(Placement(**{**fitted, "reason": RELATION_RESOLVED}))

    def retire(self) -> None:
        """A site, plate or block with no element in the run leaves the layout. Its last row is written
        again with `reason = removed`, and the placement at the run has no row for it."""
        sites = {*self.h.sites, *([UNASSIGNED_SITE] if self.unassigned() else [])}
        live = sites | {plate_uid(s) for s in sites} | set(self.h.blocks)
        for uid, row in sorted(self.rows.items()):
            if row.kind in ("site", "plate", "block") and uid not in live:
                gone = {**row.__dict__, "valid_from_ts": self.run_key, "layout_version": self.version}
                self.written[uid] = Placement(**{**gone, "reason": REMOVED})
                del self.rows[uid]

    def place_groups(self) -> None:
        for group, block in sorted(self.h.group_block.items()):
            members = [self.rows[d] for d, g in self.h.device_group.items() if g == group]
            u, v = min(r.u for r in members), min(r.v for r in members)
            w = max(r.u + r.w for r in members) - u
            h = max(r.v + r.h for r in members) - v
            reason = self.reason if group not in self.rows else RELATION_RESOLVED
            if self.reason == REPLAN:
                reason = REPLAN
            self.put(Placement(group, "group", block, u - 1, v - 1, w + 2, h + 2, reason=reason))

    # --- ports and cables ---------------------------------------------------------------

    def facing(self, device: str, other: str) -> str:
        a = self.rows[self.h.device_site[device]]
        b = self.rows[self.h.device_site[other]]
        dx = (b.u + b.w / 2) - (a.u + a.w / 2)
        dy = (b.v + b.h / 2) - (a.v + a.h / 2)
        if abs(dx) >= abs(dy):
            return "e" if dx > 0 else "w"
        return "s" if dy > 0 else "n"

    def far_device(self, port: str) -> str | None:
        return self._far.get(port)

    def side_for(self, port: str, device: str, counts: dict[str, int]) -> str:
        """The wall of a port by the rank of its far device."""
        far = self.far_device(port)
        if far is None:
            return "e" if counts["e"] <= counts["w"] else "w"
        here, there = self.h.device_site[device], self.h.device_site[far]
        if here != there:
            if here == self.spine_pair(here, there):
                # A spine port faces the site of its far device.
                return "e" if self.rows[far].u > self.rows[device].u else "w"
            return "n"
        if self.h.layer[far] < self.h.layer[device]:
            return "n"
        if self.h.layer[far] > self.h.layer[device]:
            return "s"
        return "e" if self.rows[far].u > self.rows[device].u else "w"

    def far_column(self, port: str) -> tuple[int, int, str]:
        """The sort key of the ports of a wall, with cabled ports first, by the far column, then by name."""
        far = self.far_device(port)
        if far is None or far not in self.rows:
            return (1, 0, port)
        return (0, self.rows[far].u, port)

    def place_ports(self) -> None:
        for device, ports in self.h.ports.items():
            dev = self.rows[device]
            moved = device in self.written
            counts = {"n": 0, "s": 0, "e": 0, "w": 0}
            used: dict[str, set[int]] = {s: set() for s in counts}
            for port in ports:
                row = self.rows.get(port)
                if row is not None and row.parent_uid == device and row.side in counts:
                    counts[row.side] += 1
                    used[row.side].add(row.slot or 0)
            for port in sorted(ports, key=self.far_column):
                row = self.rows.get(port)
                kept = row is not None and row.parent_uid == device and row.side in counts
                if row is not None and kept and row.slot is not None and row.side is not None:
                    if moved:
                        reason = REPLAN if self.reason == REPLAN else RELATION_RESOLVED
                        self.put_port(port, dev, row.side, row.slot, reason)
                    continue
                side = self.side_for(port, device, counts)
                slot = 0
                while slot in used[side]:
                    slot += 1
                used[side].add(slot)
                counts[side] += 1
                self.put_port(port, dev, side, slot, self.reason)

    def put_port(self, port: str, dev: Placement, side: str, slot: int, reason: str) -> None:
        # The ports past the capacity of a side share its cells.
        cell = slot % (dev.w if side in ("n", "s") else max(1, dev.h - 2))
        if side == "n":
            u, v = dev.u + cell, dev.v
        elif side == "s":
            u, v = dev.u + cell, dev.v + dev.h - 1
        elif side == "e":
            u, v = dev.u + dev.w - 1, dev.v + 1 + cell
        else:
            u, v = dev.u, dev.v + 1 + cell
        self.put(Placement(port, "port", dev.uid, u, v, 1, 1, side=side, slot=slot, reason=reason))

    def spine_pair(self, a: str, b: str) -> str | None:
        """The spine of sites `a` and `b` when one of them is the spine of the metro of the other."""
        if b in self.h.spines.get(a, ()):
            return a
        if a in self.h.spines.get(b, ()):
            return b
        return None

    def spine_route(self, q: Placement, r: Placement, site: str, lane: int) -> list[tuple[int, int]]:
        """The route of a cross-connect from port `q` of `site` to port `r` of its spine. It runs up into
        the channel above the row of its device, along the channel out of the plate, and across the gap
        to the spine port."""
        device = self.rows[q.parent_uid or ""]
        plate = self.rows[plate_uid(site)]
        step = lane % (GAP - 1)
        y = device.v - 1 - step
        if r.u > plate.u:
            x = plate.u + plate.w + SITE_GAP // 2 + step - 1
        else:
            x = plate.u - SITE_GAP // 2 - step + 1
        return _simplify([(q.u, q.v), (q.u, y), (x, y), (x, r.v), (r.u, r.v)])

    def place_cables(self) -> None:
        lanes: dict[str, int] = {}
        for cid, (a, b) in sorted(self.h.cables.items()):
            if cid in self.rows and a not in self.written and b not in self.written:
                continue
            pa_, pb = self.rows[a], self.rows[b]
            a_dev, b_dev = self.h.port_device[a], self.h.port_device[b]
            site_a, site_b = self.h.device_site[a_dev], self.h.device_site[b_dev]
            spine = self.spine_pair(site_a, site_b) if site_a != site_b else None
            if spine is not None:
                q, r = (pb, pa_) if site_a == spine else (pa_, pb)
                site = site_b if site_a == spine else site_a
                lanes[site] = lanes.get(site, -1) + 1
                points = self.spine_route(q, r, site, lanes[site])
                # The route of a cross-connect to a spine belongs to the site group of the spine.
                parent = self.h.site_region[spine]
            elif site_a != site_b:
                points = [(pa_.u, pa_.v), (pb.u, pb.v)]
                parent = None
            else:
                points = _route(pa_, pb)
                parent = plate_uid(site_a)
            us, vs = [p[0] for p in points], [p[1] for p in points]
            u, v = min(us), min(vs)
            reason = self.reason if cid not in self.rows or self.reason == REPLAN else RELATION_RESOLVED
            self.put(
                Placement(
                    cid,
                    "cable",
                    parent,
                    u,
                    v,
                    max(us) - u + 1,
                    max(vs) - v + 1,
                    points=json.dumps([list(p) for p in points], separators=(",", ":")),
                    reason=reason,
                )
            )

    def build(self) -> None:
        self.place_sites()
        self.place_devices()
        self.place_segments()
        self.place_blocks()
        self.fit_sites()
        self.place_groups()
        self.place_ports()
        self.place_cables()
        self.retire()


def _step(port: Placement) -> tuple[int, int]:
    du, dv = {"n": (0, -1), "s": (0, 1), "e": (1, 0), "w": (-1, 0)}.get(port.side or "e", (1, 0))
    return port.u + du, port.v + dv


def _route(a: Placement, b: Placement) -> list[tuple[int, int]]:
    """The orthogonal route from port `a` to port `b` with at most two bends.

    Two ports on north or south edges join by a Z through the middle row between them, two on east or
    west edges by a Z through the middle column, and one of each by an L. Two ports of one device on
    the same edge join by a loop one cell outside it.
    """
    start, end = (a.u, a.v), (b.u, b.v)
    if a.parent_uid == b.parent_uid and a.side == b.side:
        return _simplify([start, _step(a), _step(b), end])
    vertical_a, vertical_b = a.side in ("n", "s"), b.side in ("n", "s")
    if vertical_a and vertical_b:
        mid = (a.v + b.v) // 2
        return _simplify([start, (a.u, mid), (b.u, mid), end])
    if not vertical_a and not vertical_b:
        mid = (a.u + b.u) // 2
        return _simplify([start, (mid, a.v), (mid, b.v), end])
    corner = (a.u, b.v) if vertical_a else (b.u, a.v)
    return _simplify([start, corner, end])


def _simplify(points: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """`points` without repeats and without the middle point of three on one line."""
    out: list[tuple[int, int]] = []
    for p in points:
        if out and out[-1] == p:
            continue
        if len(out) >= 2 and (out[-2][0] == out[-1][0] == p[0] or out[-2][1] == out[-1][1] == p[1]):
            out[-1] = p
            continue
        out.append(p)
    return out if len(out) > 1 else out * 2


def current_version(rows: Mapping[str, Placement]) -> int:
    return max((r.layout_version for r in rows.values()), default=0)


def place(estate: Estate, current: Mapping[str, Placement], run_key: int) -> Result:
    """The rows `run_key` adds to the layout in force at its parent, `current`.

    A layout with a version below `ALGORITHM_VERSION` is placed again in full.
    """
    version = current_version(current)
    if version == 0:
        return replan(estate, current, run_key, reason=FIRST_SEEN)
    if version < ALGORITHM_VERSION:
        return replan(estate, current, run_key)
    builder = _Builder(hierarchy(estate), dict(current), run_key, version, FIRST_SEEN)
    builder.build()
    return Result(sorted(builder.written.values(), key=_row_order), builder.replan_recommended, version)


def replan(estate: Estate, current: Mapping[str, Placement], run_key: int, *, reason: str = REPLAN) -> Result:
    """Every element of `estate` placed again under the next layout version, at least `ALGORITHM_VERSION`."""
    version = max(current_version(current) + 1, ALGORITHM_VERSION)
    builder = _Builder(hierarchy(estate), {}, run_key, version, reason)
    builder.build()
    return Result(sorted(builder.written.values(), key=_row_order), builder.replan_recommended, version)


def _row_order(p: Placement) -> tuple[int, str]:
    return KINDS.index(p.kind), p.uid


def write(path: Path, rows: Sequence[Placement]) -> None:
    store.private_file(path)
    pq.write_table(pa.Table.from_pylist([r.row() for r in rows], schema=LAYOUT), path)
