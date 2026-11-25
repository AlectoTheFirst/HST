"""A later lane that enters a device the same way takes over the recorded walk."""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from hst.core.config import Settings

from .gates import _Trail
from .mtu_topology import capturing

Walk = Callable[[], tuple[list[dict[str, Any]], int]]

# A walk sets these flags of the trail and does not clear them. A replay sets
# the flags that the recorded walk set.
_RAISED = ("dst_found", "dst_translated", "l2_boundary", "l2_mismatch")


@dataclass(frozen=True)
class _Record:
    """What one device walk drew and left on the trail."""

    # the visits the walk tested against its visited set, and those it found
    probes: frozenset[str]
    hits: frozenset[str]
    # the walk's first lane, the next free lane after it, and the lane it ended on
    lane: int
    lane_end: int
    lane_after: int
    depth_after: int
    # `_Trail.lane_state` of the first lane when the walk started
    held: tuple[Any, ...]
    # The hops in order, each with its lane offset from the first lane. None
    # stands for a copy of the hops that the first lane held before the walk.
    entries: tuple[tuple[int, dict[str, Any] | None], ...]
    legs: list[dict[str, Any]]
    notes: tuple[str, ...]
    warnings: tuple[str, ...]
    device_sequence: tuple[str, ...]
    dst_seen: tuple[Any, ...]
    lanes: int
    regions: int
    raised: tuple[str, ...]
    # the last destination instance that the walk pinned (`pin_dst`), if it pinned one
    dst_uid: tuple[str | None, ...]


def walk(
    trail: _Trail,
    gw: dict[str, Any],
    flow: tuple[Any, ...],
    depth: int,
    conn_state: str,
    visited: frozenset[str],
    lane: int,
    run: Walk,
) -> tuple[list[dict[str, Any]], int]:
    """Returns the legs and the next free lane of the walk of the device that
    `gw` enters. A record of the same walk is replayed if one applies.
    Otherwise `run` walks the device and the walk is recorded.

    `flow` is the flow the device is walked with (sources, destinations,
    service) and `visited` the visited set `run` walks it under."""
    if (
        trail.shared
        or trail.carrier_stack
        or trail.transport
        or capturing()
        or gw.get("firewall_instance_uid")
    ):
        return run()
    key = (
        _frozen(gw),
        _frozen(flow),
        depth,
        conn_state,
        trail.max_hops,
        trail.dst_translated,
        _frozen(trail.device_gate_state),
        _frozen(trail.reply_nat_chain),
    )
    held = trail.lane_state(lane, depth)
    for rec in trail.walk_memo.get(key, ()):
        if rec.held == held and frozenset(rec.probes & visited) == rec.hits and _fits(trail, rec):
            return _replay(trail, rec, lane)
    return _record(trail, key, visited, lane, held, run)


def _frozen(value: Any) -> Any:
    """`value` as a hashable key part, equal for equal values."""
    if isinstance(value, dict):
        return ("dict", tuple(sorted(((str(k), _frozen(v)) for k, v in value.items()), key=lambda kv: kv[0])))
    if isinstance(value, set | frozenset):
        return ("set", tuple(sorted((_frozen(v) for v in value), key=repr)))
    if isinstance(value, list | tuple):
        return ("seq", tuple(_frozen(v) for v in value))
    try:
        hash(value)
    except TypeError:
        return ("repr", repr(value))
    return value


def _fits(trail: _Trail, rec: _Record) -> bool:
    """Whether the lane budget and the region budget have room for the lanes
    and the regions that the recorded walk spent. A walk that spent lanes
    needs 1 lane more than it spent."""
    settings = Settings()
    lanes_fit = rec.lanes == 0 or trail.lanes_spent + rec.lanes + 1 <= settings.path_lane_cap
    regions_fit = rec.regions == 0 or trail.regions_spent + rec.regions <= settings.path_region_cap
    return lanes_fit and regions_fit


def _record(
    trail: _Trail,
    key: tuple[Any, ...],
    visited: frozenset[str],
    lane: int,
    held: tuple[Any, ...],
    run: Walk,
) -> tuple[list[dict[str, Any]], int]:
    """Walk the device by `run`, and keep the walk when a copy can repeat it."""
    start = len(trail.hops)
    upstream = [(h["uid"], h.get("_pos")) for h in trail.hops if h["lane"] == lane and not h["shared"]]
    counts = (len(trail.notes), len(trail.warnings), len(trail.device_sequence), len(trail.dst_seen))
    spent = (trail.lanes_spent, trail.regions_spent)
    raised = {name: getattr(trail, name) for name in _RAISED}
    dst_writes = trail.dst_writes
    trail.visit_probes.append(set())
    try:
        legs, lane_end = run()
    finally:
        probes = frozenset(trail.visit_probes.pop())
    lanes, regions = trail.lanes_spent - spent[0], trail.regions_spent - spent[1]
    settings = Settings()
    if (lanes and spent[0] + lanes + 1 > settings.path_lane_cap) or (
        regions and spent[1] + regions > settings.path_region_cap
    ):
        return legs, lane_end
    entries = _entries(trail.hops[start:], upstream, lane, lane_end)
    if (
        entries is None
        or not lane <= trail.lane < max(lane_end, lane + 1)
        or not all(isinstance(ll.get("lane"), int) and lane <= ll["lane"] < lane_end for ll in legs)
        or any("carrier" in ll or ll.get("decapsulated") for ll in legs)
    ):
        return legs, lane_end
    trail.walk_memo.setdefault(key, []).append(
        _Record(
            probes=probes,
            hits=frozenset(probes & visited),
            lane=lane,
            lane_end=lane_end,
            lane_after=trail.lane,
            depth_after=trail.depth,
            held=held,
            entries=entries,
            legs=copy.deepcopy(legs),
            notes=tuple(trail.notes[counts[0] :]),
            warnings=tuple(trail.warnings[counts[1] :]),
            device_sequence=tuple(trail.device_sequence[counts[2] :]),
            dst_seen=tuple(trail.dst_seen[counts[3] :]),
            lanes=lanes,
            regions=regions,
            raised=tuple(name for name in _RAISED if getattr(trail, name) and not raised[name]),
            dst_uid=(trail.dst_uid,) if trail.dst_writes != dst_writes else (),
        )
    )
    return legs, lane_end


def _entries(
    hops: list[dict[str, Any]], upstream: list[tuple[str, Any]], lane: int, lane_end: int
) -> tuple[tuple[int, dict[str, Any] | None], ...] | None:
    """The hops of the walk in the form that a replay places, or None if a
    replay cannot place them.

    A lane that the walk opens starts with a copy of the hops that the first
    lane held before the walk (`_replay_upstream`). An entry with None marks
    each such run of hops. A replay fills it from the hops of the lane that it
    enters. Every other hop belongs to the walk and is copied as drawn. A
    replay cannot place a hop that is shared, a hop outside the lanes of the
    walk, or a hop that the entry of a virtual system marked. The entry of a
    virtual system also rewrites hops that were drawn before the walk."""
    if not upstream:
        return None
    known = set(upstream)
    out: list[tuple[int, dict[str, Any] | None]] = []
    i = 0
    while i < len(hops):
        h = hops[i]
        if (
            h["shared"]
            or h.get("_pos") is None
            or not lane <= h["lane"] < lane_end
            or "virtual_context" in h
            or "forwarding_visit" in h
        ):
            return None
        if (h["uid"], h["_pos"]) in known:
            block = hops[i : i + len(upstream)]
            if (
                h["lane"] == lane
                or [(x["uid"], x.get("_pos")) for x in block] != upstream
                or any(x["lane"] != h["lane"] for x in block)
            ):
                return None
            out.append((h["lane"] - lane, None))
            i += len(upstream)
            continue
        out.append((h["lane"] - lane, copy.deepcopy(h)))
        i += 1
    return tuple(out)


def _replay(trail: _Trail, rec: _Record, lane: int) -> tuple[list[dict[str, Any]], int]:
    """Draw a recorded walk onto the lanes from `lane` on, and return its legs."""
    shift = lane - rec.lane
    upstream = [h for h in trail.hops if h["lane"] == lane and not h["shared"]]
    for offset, hop in rec.entries:
        if hop is None:
            for h in upstream:
                trail.append_hop({**h, "lane": lane + offset, "shared": False})
        else:
            trail.append_drawn({**copy.deepcopy(hop), "lane": lane + offset})
    for text in rec.notes:
        # A note of `once_notes` that the trail already holds is not added again.
        if not (text in trail.once_notes and text in trail.notes):
            trail.notes.append(text)
    trail.warnings.extend(rec.warnings)
    trail.device_sequence.extend(rec.device_sequence)
    trail.dst_seen.extend(rec.dst_seen)
    trail.lanes_spent += rec.lanes
    trail.regions_spent += rec.regions
    for name in rec.raised:
        setattr(trail, name, True)
    for uid in rec.dst_uid:
        if uid is not None:
            trail.pin_dst(uid)
    for probes in trail.visit_probes:
        probes |= rec.probes
    trail.depth = rec.depth_after
    trail.lane, trail.shared = rec.lane_after + shift, False
    legs = copy.deepcopy(rec.legs)
    for ll in legs:
        ll["lane"] += shift
    return legs, rec.lane_end + shift
