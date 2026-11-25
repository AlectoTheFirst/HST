"""The tier fold.

`Attribution` takes every diff record and keeps the devices it touches. `fold`
reads those devices again at the run with the bootstrap queries, keeps the
parent's rows of every other device, and emits the delta tables as the
difference between the parent's tiers and the new ones. With no parent, or
with `affected=None`, it reads every device. That read is the bootstrap.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pyarrow as pa

from hst.core import uid as uidmod
from hst.diagram import planner

from .. import layout
from ..site_config import SiteConfig
from . import bindings, bootstrap, fabric
from . import delta as deltamod
from .read import read_table
from .schemas import COUNTS, DELTA_OF, RENDER_BINDINGS, TILED, key_of

OBSERVED, CARRIED, FAILED = "observed", "carried", "failed"
NONE, ADDED, REMOVED, CHANGED, NOT_OBSERVED = "none", "added", "removed", "changed", "not-observed"
DEFAULT_CONTEXTS = frozenset({"default", "global", "main", "root", "vrf-default", "default-vrf"})
TIER_TABLES = (
    "render_t0",
    "render_t1",
    "render_t1_edges",
    "render_t1_contexts",
    "render_t1_circuits",
    "render_t1_fabric_ports",
    "context_identity",
    "render_t2_ports",
    "render_t2_cables",
    "render_t2_contexts",
    "render_t2_segments",
)
# Columns a row's own change marker leaves out of the comparison that sets it.
_MARKER = frozenset({"change", "snapshot_ts"})


class Attribution:
    """The devices a run's diff records touch."""

    def __init__(self, devices: Iterable[str], groups: Mapping[str, set[str]]) -> None:
        self.devices = set(devices)
        self.groups = groups
        self.affected: set[str] = set()
        self.pending: set[str] = set()
        self.records = 0

    def observe(self, record: Mapping[str, Any]) -> str | None:
        """Record the devices of `record` and return the first of them that is known."""
        self.records += 1
        if record["kind"] == "node":
            uids = [record["uid"]]
            if record["label"] == "Device":
                self.devices.add(record["uid"])
        else:
            uids = [record["start"], record["end"]]
        found: set[str] = set()
        for uid in uids:
            if uid is None:
                continue
            device = bindings.device_of(uid, self.devices)
            if device is not None:
                found.add(device)
            elif uid in self.groups:
                found |= self.groups[uid]
            else:
                self.pending.add(uid)
        self.affected |= found
        return min(found) if found else None

    def resolve(self, devices_at_t: Iterable[str], parent_bindings: pa.Table) -> dict[str, str]:
        """Attribute the pending uids by the devices of the run and the parent's bindings.

        Returns one device per uid that resolved. The other uids count on the Unassigned plate.
        """
        self.devices |= set(devices_at_t)
        resolved: dict[str, str] = {}
        rest = set()
        for uid in self.pending:
            device = bindings.device_of(uid, self.devices)
            if device is None:
                rest.add(uid)
            else:
                resolved[uid] = device
                self.affected.add(device)
        for uid, devices in bindings.lookup(parent_bindings, rest).items():
            self.affected |= devices
            resolved[uid] = min(devices)
        return resolved


@dataclass
class Parent:
    """One run's tiers, keyed by `key_of`."""

    key: int | None
    tables: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    bindings: pa.Table = field(default_factory=RENDER_BINDINGS.empty_table)

    @classmethod
    def load(cls, sidestore_dir: Path, key: int | None) -> Parent:
        parent = cls(key)
        for name in TIER_TABLES:
            table = None if key is None else read_table(sidestore_dir, name, key)
            parent.tables[name] = {} if table is None else {key_of(name, r): r for r in table.to_pylist()}
        parent.bindings = bindings.read(sidestore_dir, key)
        return parent

    @property
    def ready(self) -> bool:
        return self.key is not None and bool(self.tables.get("render_t1"))

    def groups(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for row in self.tables.get("render_t1", {}).values():
            if row.get("group_uid"):
                out.setdefault(row["group_uid"], set()).add(row["uid"])
        return out


@dataclass
class Folded:
    tables: dict[str, list[dict[str, Any]]]
    deltas: dict[str, list[dict[str, Any]]]
    bindings: pa.Table
    estate: layout.Estate
    hierarchy: layout.Hierarchy
    read_devices: int
    counts: dict[str, int]


def _status(row: Mapping[str, Any]) -> str:
    if not row.get("carried"):
        return OBSERVED
    return FAILED if "fail" in str(row.get("carried_reason") or "").lower() else CARRIED


def _marked(
    row: dict[str, Any], before: Mapping[str, Any] | None, *, not_observed: bool = False
) -> dict[str, Any]:
    if before is None:
        row["change"] = ADDED
    elif not_observed:
        row["change"] = NOT_OBSERVED
    else:
        same = all(row.get(k) == before.get(k) for k in row if k not in _MARKER)
        row["change"] = NONE if same else CHANGED
    return row


def _port_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "uid": row["uid"],
        "device_uid": row["device"],
        "name": row.get("name"),
        "name_short": bootstrap.name_short(row.get("name")),
        "admin_status": bootstrap.admin_status(row),
        "oper_status": bootstrap.oper_status(row),
        "speed_mbps": bootstrap.speed_mbps(row.get("speed_mbps")) or bootstrap.speed_mbps(row.get("speed")),
        "lag_uid": row.get("lag_uid"),
        "connected": bool(row.get("connected")),
        "interface_uid": row.get("interface_uid"),
        "context_uid": row.get("context_uid"),
    }


def _cable_row(row: Mapping[str, Any]) -> dict[str, Any]:
    a = (row["a_port"], row["a_dev"], bootstrap.speed_mbps(row.get("a_speed")))
    b = (row["b_port"], row["b_dev"], bootstrap.speed_mbps(row.get("b_speed")))
    a, b = sorted((a, b))
    speeds = [s for s in (a[2], b[2]) if s is not None]
    return {
        "cable_id": layout.cable_id(a[0], b[0]),
        "a_port": a[0],
        "b_port": b[0],
        "a_dev": a[1],
        "b_dev": b[1],
        "source": row.get("source"),
        "speed_mbps": min(speeds) if speeds else None,
        "speed_agreement": (a[2] == b[2]) if len(speeds) == 2 else None,
        "carried": bool(row.get("carried")),
    }


def _site_links(
    rows_t: Mapping[str, Mapping[str, Any]], facts: bootstrap.DeviceFacts, cables: Iterable[Mapping[str, Any]]
) -> list[tuple[str, str]]:
    """The site code pairs joined by a tunnel or a cable between their devices."""
    out: set[tuple[str, str]] = set()

    def join(a: str, b: str) -> None:
        sa, sb = rows_t.get(a, {}).get("site"), rows_t.get(b, {}).get("site")
        if sa and sb and sa != sb:
            out.add((min(sa, sb), max(sa, sb)))

    for t in facts.tunnels:
        join(t["device"], t["other"])
    for c in cables:
        join(c["a_dev"], c["b_dev"])
    return sorted(out)


def _segment_row(row: Mapping[str, Any]) -> dict[str, Any]:
    bd = row.get("bridge_domain_uid")
    return {
        "uid": layout.segment_uid(row["device"], bd),
        "device_uid": row["device"],
        "tile": None,
        "bridge_domain_uid": bd,
        "vid": row.get("vid"),
        "name": row.get("name"),
        "prefix": row.get("prefix"),
        "client_count": int(row.get("client_count") or 0),
    }


def _context_kind(row: Mapping[str, Any]) -> str:
    labels = set(row.get("labels") or ())
    if "FirewallInstance" in labels:
        return "cp-vs"
    if "Zone" in labels:
        return "zone"
    return "vdom" if row.get("kind") == "vdom" else "vrf"


def _identity_uid(rd: str | None, name: str | None) -> str:
    return f"ctx:rd:{rd}" if rd else f"ctx:name:{name or ''}"


def _block_label(block: str, kind: str) -> str:
    if kind == "role":
        return block.removeprefix("block:unassigned:")
    if kind.startswith(f"{layout.NAMED_KIND}:"):
        return kind.split(":", 2)[2]
    base = kind.split(":", 1)[0]
    return planner.BLOCK_LABELS.get(base, base)


def drawn(rows: Mapping[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """The device rows the map draws. A bound Network Edge device draws as the device it is bound to."""
    return {
        u: r
        for u, r in rows.items()
        if not (r.get("platform") == layout.NETWORK_EDGE and r.get("bound_device_uid"))
    }


def stored_sites(rows: dict[str, dict[str, Any]], config: SiteConfig) -> dict[str, dict[str, Any]]:
    """`rows` with each device's site named by the code the config holds for its Site uid. A graph Site
    keeps the code of whoever made it (a collector's `FR5` for the stored `fr5`), and the config's groups,
    blocks and countries are keyed by the stored code."""
    stored = config.stored_codes()
    if not stored:
        return rows
    return {
        u: {**r, "site": stored.get(uidmod.site(r["site"]), r["site"])} if r.get("site") else r
        for u, r in rows.items()
    }


def on_map(cable: Mapping[str, Any]) -> bool:
    """Whether a cable draws on the map. The link the reasoner derives from a Fabric circuit does not."""
    return cable.get("source") != fabric.CIRCUIT_CABLE


def aliases(rows: Mapping[str, Mapping[str, Any]]) -> dict[str, str]:
    """The unbound Network Edge devices that draw as the one device of another source with their hostname.

    The reasoner's `edge-devices` check proposes the same binding.
    """
    others: dict[str, list[str]] = {}
    for u, r in rows.items():
        if r.get("platform") != layout.NETWORK_EDGE:
            others.setdefault(str(r.get("label") or "").casefold(), []).append(u)
    out: dict[str, str] = {}
    for u, r in rows.items():
        if r.get("platform") == layout.NETWORK_EDGE and not r.get("bound_device_uid"):
            hits = others.get(str(r.get("label") or "").casefold(), [])
            if len(hits) == 1:
                out[u] = hits[0]
    return out


def _merge(facts: bootstrap.DeviceFacts, fab: fabric.FabricMap, alias: Mapping[str, str]) -> None:
    """The facts of each device in `alias` moved to the device it draws as."""

    def to(uid: Any) -> Any:
        return alias.get(uid, uid)

    for row in [*facts.ports, *facts.contexts, *facts.segments]:
        row["device"] = to(row["device"])
    for row in facts.tunnels:
        row["device"], row["other"] = to(row["device"]), to(row["other"])
    for row in [*facts.cables, *fab.cables]:
        row["a_dev"], row["b_dev"] = to(row["a_dev"]), to(row["b_dev"])
    for row in fab.circuits:
        row["a_device"], row["z_device"] = to(row["a_device"]), to(row["z_device"])
    for row in fab.fabric_ports:
        row["port_device"] = to(row["port_device"])
    for source, target in alias.items():
        for name, uids in facts.members.pop(source, {}).items():
            facts.members.setdefault(target, {}).setdefault(name, set()).update(uids)


def fold(
    session: bootstrap.Session,
    cts: int,
    parent: Parent,
    affected: set[str] | None,
    device_rows: Mapping[str, dict[str, Any]] | None = None,
    config: SiteConfig | None = None,
) -> Folded:
    """The tiers at `cts`, as the parent's rows with the rows of `affected` read again.

    `affected=None`, or a parent with no tiers, reads every device. `device_rows` is
    `bootstrap.device_rows` at `cts` when the caller has read it already. `config` holds the
    site groups and named blocks of the run.
    """
    config = config or SiteConfig()
    rows_t = drawn(device_rows if device_rows is not None else bootstrap.device_rows(session, cts))
    rows_t = stored_sites(rows_t, config)
    # The Fabric devices are read again at every run, with their ports, cross-connects and circuits.
    codes = {r["site"] for r in rows_t.values() if r.get("site")}
    fab = fabric.build(*bootstrap.fabric(session, cts), codes, config.groups)
    rows_t.update(fab.devices)
    alias = aliases(rows_t)
    old_t1: Mapping[str, Mapping[str, Any]] = parent.tables.get("render_t1", {})
    if affected is None or not parent.ready:
        targets = set(rows_t)
    else:
        targets = (affected | (set(rows_t) - set(old_t1)) | set(fab.devices)) & set(rows_t)
        # A device and the Network Edge device that draws as it are read together.
        targets |= {u for pair in alias.items() if targets & set(pair) for u in pair}
    facts = bootstrap.read(session, cts, targets - set(fab.devices))
    _merge(facts, fab, alias)
    for source in alias:
        del rows_t[source]
    targets -= set(alias)
    alive = set(rows_t)
    removed = set(old_t1) - alive
    kept = alive - targets

    def keep(name: str, *columns: str) -> list[dict[str, Any]]:
        return [dict(r) for r in parent.tables.get(name, {}).values() if all(r[c] in kept for c in columns)]

    ports = {r["uid"]: r for r in keep("render_t2_ports", "device_uid")}
    for row in [*facts.ports, *fab.ports]:
        ports[row["uid"]] = _port_row(row)
    cables = {r["cable_id"]: r for r in keep("render_t2_cables", "a_dev", "b_dev") if on_map(r)}
    for row in [*facts.cables, *fab.cables]:
        if row["a_dev"] in alive and row["b_dev"] in alive and on_map(row):
            cable = _cable_row(row)
            cables[cable["cable_id"]] = cable
    segments = {r["uid"]: r for r in keep("render_t2_segments", "device_uid")}
    for row in facts.segments:
        segment = _segment_row(row)
        segments[segment["uid"]] = segment

    groups: dict[str, list[str]] = {}
    for uid, row in rows_t.items():
        if row.get("group_uid"):
            groups.setdefault(row["group_uid"], []).append(uid)
    estate = layout.Estate(
        devices=[
            {
                "uid": u,
                "name": r["label"],
                "role": r.get("role"),
                "tier": r.get("tier"),
                "site": r.get("site"),
                "platform": r.get("platform"),
                "site_kind": r.get("site_kind"),
            }
            for u, r in sorted(rows_t.items())
        ],
        ports=[
            {"uid": p["uid"], "device_uid": p["device_uid"], "name": p.get("name")} for p in ports.values()
        ],
        cables=[{"a_port": c["a_port"], "b_port": c["b_port"]} for c in cables.values()],
        groups=[{"uid": g, "members": m} for g, m in sorted(groups.items())],
        wan_devices=sorted(u for u, r in rows_t.items() if r.get("wan")),
        site_links=_site_links(rows_t, facts, cables.values()),
        segment_devices=sorted({s["device_uid"] for s in segments.values() if s["client_count"] > 0}),
        cloud_sites=fab.sites,
        site_groups={**config.groups, **{spine: path for spine, (path, _sites) in fab.spines.items()}},
        named_blocks={uid: (b.name, b.zone) for uid, b in config.blocks.items() if uid in rows_t},
        site_countries=config.countries,
        spines={spine: sites for spine, (_path, sites) in fab.spines.items()},
    )
    h = layout.hierarchy(estate)
    tile = h.device_block

    new: dict[str, dict[str, dict[str, Any]]] = {name: {} for name in TIER_TABLES}
    old = {name: parent.tables.get(name, {}) for name in TIER_TABLES}

    for uid, port in ports.items():
        port["tile"] = tile.get(port["device_uid"])
        new["render_t2_ports"][uid] = _marked(port, old["render_t2_ports"].get(uid))
    for cid, cable in cables.items():
        cable["tile_a"], cable["tile_b"] = tile.get(cable["a_dev"]), tile.get(cable["b_dev"])
        new["render_t2_cables"][cid] = _marked(cable, old["render_t2_cables"].get(cid))
    for uid, segment in segments.items():
        segment["tile"] = tile.get(segment["device_uid"])
        new["render_t2_segments"][uid] = _marked(segment, old["render_t2_segments"].get(uid))

    contexts = [dict(r) for r in keep("render_t2_contexts", "device_uid")]
    t1_contexts = {key_of("render_t1_contexts", r): dict(r) for r in keep("render_t1_contexts", "device_uid")}
    fresh: dict[str, list[dict[str, Any]]] = {}
    for row in facts.contexts:
        fresh.setdefault(row["device"], []).append(row)
    for device, found in fresh.items():
        unique = {r["uid"]: r for r in found}.values()
        ordered = sorted(
            unique,
            key=lambda r: (
                not (r.get("is_default") or (r.get("name") or "").lower() in DEFAULT_CONTEXTS),
                str(r.get("name")),
            ),
        )
        for i, r in enumerate(ordered):
            name = r.get("name") or r["uid"]
            is_default = bool(r.get("is_default") or name.lower() in DEFAULT_CONTEXTS)
            contexts.append(
                {
                    "uid": r["uid"],
                    "device_uid": device,
                    "kind": _context_kind(r),
                    "name": name,
                    "is_default": is_default,
                    "order": i,
                }
            )
            row = {
                "device_uid": device,
                "context_uid": r["uid"],
                "identity_uid": _identity_uid(r.get("rd"), name),
                "kind": _context_kind(r),
                "name": name,
                "rd": r.get("rd"),
            }
            t1_contexts[key_of("render_t1_contexts", row)] = row
    for row in contexts:
        row["tile"] = tile.get(row["device_uid"])
        k = key_of("render_t2_contexts", row)
        new["render_t2_contexts"][k] = _marked(row, old["render_t2_contexts"].get(k))
    new["render_t1_contexts"] = t1_contexts
    identity: dict[str, dict[str, Any]] = {}
    for row in t1_contexts.values():
        ident = identity.setdefault(
            row["identity_uid"],
            {
                "identity_uid": row["identity_uid"],
                "basis": "rd" if row.get("rd") else "name",
                "rd": row.get("rd"),
                "name": row.get("name"),
                "routing_domain_uid": None,
                "member_count": 0,
            },
        )
        ident["member_count"] += 1
    new["context_identity"] = identity

    for uid, base in rows_t.items():
        status = _status(base)
        known = old_t1.get(uid, {})
        counts = facts.counts(uid) if uid in targets else {c: known.get(c) or 0 for c in COUNTS}
        site = base.get("site")
        row = {
            "uid": uid,
            "site_uid": layout.site_uid(site) if site else None,
            "block_uid": tile.get(uid),
            "group_uid": h.device_group.get(uid),
            "label": base["label"],
            "role": base.get("role"),
            "tier": base.get("tier"),
            "vendor": base.get("vendor"),
            "model": base.get("model"),
            "os_version": base.get("os_version"),
            "mgmt_ip": base.get("mgmt_ip"),
            "status": status,
            "carried_reason": base.get("carried_reason"),
            "last_seen_ts": base.get("last_seen_ts"),
            **counts,
            "snapshot_ts": cts,
        }
        new["render_t1"][uid] = _marked(row, old_t1.get(uid), not_observed=status != OBSERVED)

    new["render_t1_edges"] = _edges(new, old["render_t1_edges"], facts.tunnels, targets, cts)
    new["render_t0"] = _tier0(new["render_t1"], old_t1, removed, h, cts, fab.sites)
    for row in fab.circuits:
        circuit = {**row, "snapshot_ts": cts}
        new["render_t1_circuits"][row["uid"]] = _marked(circuit, old["render_t1_circuits"].get(row["uid"]))
    for row in fab.fabric_ports:
        new["render_t1_fabric_ports"][row["uid"]] = _marked(
            {**row, "snapshot_ts": cts}, old["render_t1_fabric_ports"].get(row["uid"])
        )

    bound = pa.concat_tables(
        [
            bindings.without(parent.bindings, targets | removed),
            pa.Table.from_pylist(bindings.rows(facts.members, alive), schema=RENDER_BINDINGS),
        ]
    )

    deltas: dict[str, list[dict[str, Any]]] = {d: [] for d in set(DELTA_OF.values())}
    for name in TIER_TABLES:
        tile_of = _tile_of(name) if name in TILED else (lambda _row: None)
        deltas[DELTA_OF[name]].extend(deltamod.changes(name, old.get(name, {}), new[name], tile_of))

    tables = {name: _ordered(name, rows) for name, rows in new.items()}
    t1 = new["render_t1"]
    return Folded(
        tables=tables,
        deltas=deltas,
        bindings=bound,
        estate=estate,
        hierarchy=h,
        read_devices=len(targets),
        counts={
            "added": sum(1 for r in t1.values() if r["change"] == ADDED),
            "removed": len(removed),
            "changed": sum(1 for r in t1.values() if r["change"] == CHANGED),
        },
    )


def _tile_of(name: str) -> Any:
    if name == "render_t2_cables":
        return lambda row: row.get("tile_a")
    return lambda row: row.get("tile")


def _ordered(name: str, rows: Mapping[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if name in TILED:
        first = "tile_a" if name == "render_t2_cables" else "tile"
        return [rows[k] for k in sorted(rows, key=lambda k: (rows[k].get(first) or "", k))]
    return [rows[k] for k in sorted(rows)]


def _edges(
    new: Mapping[str, Mapping[str, dict[str, Any]]],
    old: Mapping[str, Mapping[str, Any]],
    tunnels: Iterable[Mapping[str, Any]],
    targets: set[str],
    cts: int,
) -> dict[str, dict[str, Any]]:
    lag = {uid: p.get("lag_uid") for uid, p in new["render_t2_ports"].items()}
    pairs: dict[tuple[str, str], dict[str, Any]] = {}

    def pair(a: str, b: str) -> dict[str, Any]:
        x, y = sorted((a, b))
        return pairs.setdefault((x, y), {"cables": set(), "lags": set(), "tunnels": set()})

    for cable in new["render_t2_cables"].values():
        if cable["a_dev"] == cable["b_dev"]:
            continue
        entry = pair(cable["a_dev"], cable["b_dev"])
        entry["cables"].add(cable["cable_id"])
        entry["lags"] |= {lag.get(cable["a_port"]), lag.get(cable["b_port"])} - {None}
    for t in tunnels:
        if t["device"] != t["other"]:
            pair(t["device"], t["other"])["tunnels"].add(t["tunnel"])
    alive = new["render_t1"]
    for row in old.values():
        a, b = row["a_uid"], row["b_uid"]
        if a in alive and b in alive and not ({a, b} & targets) and row.get("tunnel_count"):
            pair(a, b)["tunnels"] |= {f"kept:{i}" for i in range(row["tunnel_count"])}
    out: dict[str, dict[str, Any]] = {}
    for (a, b), entry in pairs.items():
        pair_id = f"{a}|{b}"
        row = {
            "pair_id": pair_id,
            "a_uid": a,
            "b_uid": b,
            "cable_count": len(entry["cables"]),
            "lag_count": len(entry["lags"]),
            "tunnel_count": len(entry["tunnels"]),
            "snapshot_ts": cts,
        }
        out[pair_id] = _marked(row, old.get(pair_id))
    return out


def _tier0(
    t1: Mapping[str, Mapping[str, Any]],
    old_t1: Mapping[str, Mapping[str, Any]],
    removed: set[str],
    h: layout.Hierarchy,
    cts: int,
    cloud: Mapping[str, str] | None = None,
) -> dict[str, dict[str, Any]]:
    """The site, plate and block rows with their counts. `cloud` maps the code of a cloud site to its name."""
    names = cloud or {}
    rows: dict[str, dict[str, Any]] = {}

    def put(
        uid: str, kind: str, parent: str | None, label: str, code: str | None, block_kind: str | None
    ) -> None:
        rows[uid] = {
            "uid": uid,
            "kind": kind,
            "parent_uid": parent,
            "label": label,
            "code": code,
            "block_kind": block_kind,
            "device_count": 0,
            "observed_count": 0,
            "carried_count": 0,
            "failed_count": 0,
            "added_count": 0,
            "removed_count": 0,
            "changed_count": 0,
            "snapshot_ts": cts,
        }

    for site in [*h.sites, layout.UNASSIGNED_SITE]:
        code = None if site == layout.UNASSIGNED_SITE else site.removeprefix("site:")
        label = names.get(code or "") or code or "Unassigned"
        put(site, "site", None, label, code, None)
        put(layout.plate_uid(site), "plate", site, label, code, None)
    for block, (site, kind) in h.blocks.items():
        code = site.removeprefix("site:")
        fabric_site = code == fabric.FABRIC_SITE or code.startswith(layout.SPINE_PREFIX)
        cloud_label = "Fabric" if fabric_site else "Cloud"
        label = cloud_label if code in names else _block_label(block, kind)
        put(block, "block", layout.plate_uid(site), label, None, kind)

    def chain(block: str | None) -> list[str]:
        if block is None or block not in rows:
            return []
        plate = rows[block]["parent_uid"]
        return [block, plate, rows[plate]["parent_uid"]]

    for row in t1.values():
        for uid in chain(row.get("block_uid")):
            target = rows[uid]
            target["device_count"] += 1
            target[f"{row['status']}_count"] += 1
            if row["change"] in (ADDED, CHANGED):
                target[f"{row['change']}_count"] += 1
    for uid in removed:
        for ancestor in chain(old_t1[uid].get("block_uid")):
            rows[ancestor]["removed_count"] += 1
    return rows


def differences(folded: Folded, full: Folded) -> list[str]:
    """The rows where the folded tiers differ from the full read, for the consistency log."""
    out = []
    for name in ("render_t1", "render_t2_ports", "render_t2_cables", "render_t1_edges"):
        a = {key_of(name, r): r for r in folded.tables[name]}
        b = {key_of(name, r): r for r in full.tables[name]}
        for key in sorted(set(a) | set(b)):
            left, right = a.get(key), b.get(key)
            if left is None or right is None:
                out.append(f"{name} {key}: {'missing' if left is None else 'extra'} in the fold")
                continue
            cols = [c for c in right if c not in _MARKER and left.get(c) != right.get(c)]
            if cols:
                out.append(f"{name} {key}: {', '.join(cols)}")
    return out
