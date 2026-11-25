import itertools
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from tests.hst.estates import fixture_estate, synthetic_estate
from tests.support.cputime import cpu_time

from hst.map import layout, layout_read, store
from hst.map.layout import Estate, Placement
from hst.map.project import Projection


def _expected_uids(estate: Estate) -> set[str]:
    h = layout.hierarchy(estate)
    # The Unassigned site holds the devices without a site; with none it has no row.
    sites = {
        *h.sites,
        *([layout.UNASSIGNED_SITE] if layout.UNASSIGNED_SITE in h.device_site.values() else []),
    }
    return (
        set(h.regions)
        | sites
        | {layout.plate_uid(s) for s in sites}
        | set(h.blocks)
        | set(h.group_block)
        | set(h.device_block)
        | set(h.port_device)
        | set(h.cables)
        | {layout.segments_uid(d) for d in h.segment_devices}
    )


def _by_uid(rows: list[Placement]) -> dict[str, Placement]:
    return {r.uid: r for r in rows}


def _overlap(a: Placement, b: Placement) -> bool:
    return a.u < b.u + b.w and b.u < a.u + a.w and a.v < b.v + b.h and b.v < a.v + a.h


@pytest.mark.parametrize(
    "estate", [fixture_estate(), synthetic_estate(1, 400)], ids=["fixtures", "synthetic"]
)
def test_every_map_element_has_a_row(estate: Estate) -> None:
    result = layout.place(estate, {}, 100)
    rows = _by_uid(result.rows)
    assert set(rows) == _expected_uids(estate)
    assert {r.kind for r in result.rows} <= set(layout.KINDS)
    assert {r.reason for r in result.rows} == {layout.FIRST_SEEN}
    assert {r.layout_version for r in result.rows} == {layout.ALGORITHM_VERSION}
    assert not result.replan_recommended


def test_the_plan_is_independent_of_the_row_order() -> None:
    estate = synthetic_estate(2, 150)
    shuffled = Estate(
        devices=list(reversed(estate.devices)),
        ports=list(reversed(estate.ports)),
        cables=list(reversed(estate.cables)),
        groups=list(reversed(estate.groups)),
    )
    assert layout.place(estate, {}, 1).rows == layout.place(shuffled, {}, 1).rows


def test_no_two_device_boxes_overlap_and_ports_sit_on_their_box() -> None:
    rows = _by_uid(layout.place(synthetic_estate(3, 300), {}, 1).rows)
    devices = [r for r in rows.values() if r.kind == "device"]
    for i, a in enumerate(devices):
        assert not any(_overlap(a, b) for b in devices[i + 1 :]), a.uid
    for port in (r for r in rows.values() if r.kind == "port"):
        dev = rows[port.parent_uid]
        assert dev.u <= port.u < dev.u + dev.w and dev.v <= port.v < dev.v + dev.h
        on_edge = {
            "n": port.v == dev.v,
            "s": port.v == dev.v + dev.h - 1,
            "e": port.u == dev.u + dev.w - 1,
            "w": port.u == dev.u,
        }
        assert on_edge[port.side], port.uid


def test_no_two_sites_overlap_and_unassigned_is_east_of_the_spiral() -> None:
    rows = _by_uid(layout.place(synthetic_estate(4, 300, sites=9), {}, 1).rows)
    sites = [r for r in rows.values() if r.kind == "site"]
    for i, a in enumerate(sites):
        assert not any(_overlap(a, b) for b in sites[i + 1 :])
    unassigned = rows[layout.UNASSIGNED_SITE]
    assert unassigned.v == 0
    assert unassigned.u >= max(s.u + s.w for s in sites if s.uid != layout.UNASSIGNED_SITE)


def test_an_orphan_device_goes_to_a_role_band_of_the_unassigned_plate_in_name_order() -> None:
    estate = Estate(
        devices=[
            {"uid": "dev:b", "name": "b", "role": "router", "tier": None, "site": None},
            {"uid": "dev:a", "name": "a", "role": "router", "tier": None, "site": None},
            {"uid": "dev:c", "name": "c", "role": "firewall", "tier": None, "site": None},
            {"uid": "dev:x", "name": "x", "role": "router", "tier": "core", "site": "fra"},
        ]
    )
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    assert rows["dev:a"].parent_uid == rows["dev:b"].parent_uid == "block:unassigned:router"
    assert rows["dev:c"].parent_uid == "block:unassigned:firewall"
    assert rows["block:unassigned:router"].parent_uid == layout.UNASSIGNED_PLATE
    assert rows[layout.UNASSIGNED_PLATE].parent_uid == layout.UNASSIGNED_SITE
    assert rows["dev:a"].slot < rows["dev:b"].slot
    assert rows["dev:x"].parent_uid.startswith("block:fra:")


def test_a_port_without_a_cable_keeps_a_slot_on_the_east_or_west_edge() -> None:
    estate = Estate(
        devices=[
            {"uid": "dev:a", "name": "a", "role": "router", "tier": "core", "site": "fra"},
            {"uid": "dev:b", "name": "b", "role": "router", "tier": "core", "site": "fra"},
        ],
        ports=[
            *({"uid": f"dev:a/p{i}", "device_uid": "dev:a", "name": f"eth{i}"} for i in range(5)),
            {"uid": "dev:b/p0", "device_uid": "dev:b", "name": "eth0"},
        ],
        cables=[{"a_port": "dev:a/p0", "b_port": "dev:b/p0"}],
    )
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    assert rows["dev:a/p0"].side == "e"
    assert rows["dev:b/p0"].side == "w"
    loose = [rows[f"dev:a/p{i}"] for i in range(1, 5)]
    assert [p.side for p in loose] == ["w", "e", "w", "e"]
    assert [p.slot for p in loose] == [0, 1, 1, 2]
    cable = rows[layout.cable_id("dev:a/p0", "dev:b/p0")]
    points = json.loads(cable.points)
    assert points[0] == [rows["dev:a/p0"].u, rows["dev:a/p0"].v]
    assert points[-1] == [rows["dev:b/p0"].u, rows["dev:b/p0"].v]
    assert all(p[0] == q[0] or p[1] == q[1] for p, q in itertools.pairwise(points))


def test_a_cable_between_sites_is_one_straight_line_between_ports_facing_each_other() -> None:
    estate = Estate(
        devices=[
            {"uid": "dev:a", "name": "a", "role": "router", "tier": "wan-edge", "site": "s1"},
            {"uid": "dev:b", "name": "b", "role": "router", "tier": "wan-edge", "site": "s2"},
        ],
        ports=[
            {"uid": "dev:a/p", "device_uid": "dev:a", "name": "eth0"},
            {"uid": "dev:b/p", "device_uid": "dev:b", "name": "eth0"},
        ],
        cables=[{"a_port": "dev:a/p", "b_port": "dev:b/p"}],
    )
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    cable = rows[layout.cable_id("dev:a/p", "dev:b/p")]
    assert cable.parent_uid is None
    assert len(json.loads(cable.points)) == 2
    assert {rows["dev:a/p"].side, rows["dev:b/p"].side} == {"n"}


def test_a_second_run_of_the_same_estate_places_nothing() -> None:
    estate = synthetic_estate(5, 200)
    first = _by_uid(layout.place(estate, {}, 1).rows)
    assert layout.place(estate, first, 2).rows == []


def test_a_new_device_takes_a_spare_slot_and_moves_nothing() -> None:
    estate = synthetic_estate(6, 200)
    first = _by_uid(layout.place(estate, {}, 1).rows)
    h0 = layout.hierarchy(estate)

    def spare(uid: str) -> bool:
        """Whether the layer row of `uid` has a free cell in its plate."""
        plate = first[layout.plate_uid(h0.device_site[uid])]
        line = [first[d] for d in h0.site_devices(h0.device_site[uid]) if first[d].v == first[uid].v]
        first_u = plate.u + layout.PLATE_PAD + layout.GAP // 2
        last_u = plate.u + plate.w - layout.PLATE_PAD - layout.DEVICE_W
        return any(
            all(abs(r.u - u) >= layout.PITCH_W for r in line) for u in range(first_u, last_u + 1, layout.HALF)
        )

    peer = next(d for d in estate.devices if d["site"] and d["tier"] and spare(d["uid"]))
    new = {**peer, "uid": "dev:new", "name": "zzz-new"}
    grown = Estate(
        devices=[*estate.devices, new],
        ports=[*estate.ports, {"uid": "dev:new/p0", "device_uid": "dev:new", "name": "eth0"}],
        cables=estate.cables,
        groups=estate.groups,
    )
    result = layout.place(grown, first, 2)
    written = _by_uid(result.rows)
    # The block of the new device grows around it; no other row changes.
    assert {u for u, r in written.items() if r.kind != "block"} == {"dev:new", "dev:new/p0"}
    assert all(r.kind != "device" or u == "dev:new" for u, r in written.items())
    device = written["dev:new"]
    assert device.reason == layout.FIRST_SEEN
    h = layout.hierarchy(grown)
    kin = [
        first[d]
        for d in h.site_devices(h.device_site["dev:new"])
        if d != "dev:new" and h.layer[d] == h.layer["dev:new"]
    ]
    assert device.v in {r.v for r in kin}
    assert device.valid_from_ts == 2
    others = [r for r in first.values() if r.kind == "device"]
    assert not any(_overlap(device, r) for r in others)
    assert not result.replan_recommended


def test_a_full_row_sends_the_new_device_to_the_annex_below_its_plate() -> None:
    base = [
        {"uid": f"dev:d{i}", "name": f"d{i}", "role": "switch", "tier": "access", "site": "fra"}
        for i in range(3)
    ]
    rows = _by_uid(layout.place(Estate(devices=base), {}, 1).rows)
    plate = rows["plate:fra"]
    capacity = (plate.w - 2 * layout.PLATE_PAD) // layout.PITCH_W
    extra = [
        {"uid": f"dev:e{i}", "name": f"e{i}", "role": "switch", "tier": "access", "site": "fra"}
        for i in range(capacity - len(base) + 1)
    ]
    result = layout.place(Estate(devices=base + extra), rows, 2)
    written = _by_uid(result.rows)
    annexed = [r for r in written.values() if r.reason == layout.ANNEX]
    assert annexed
    plate = rows["plate:fra"]
    for row in annexed:
        assert row.slot == layout.NO_SLOT
        assert row.v >= plate.v + plate.h
    devices = [r for r in {**rows, **written}.values() if r.kind == "device"]
    for i, a in enumerate(devices):
        assert not any(_overlap(a, b) for b in devices[i + 1 :]), a.uid
    assert result.replan_recommended


def test_replan_writes_every_element_under_the_next_version(tmp_path: Path) -> None:
    sidestore = tmp_path / "sidestore"
    estate = synthetic_estate(7, 120)
    first = layout.place(estate, {}, 1)
    layout.write(store.table_path(sidestore, layout.TABLE, 1), first.rows)
    gone = estate.devices[0]["uid"]
    smaller = Estate(
        devices=estate.devices[1:],
        ports=[p for p in estate.ports if p["device_uid"] != gone],
        cables=estate.cables,
        groups=[g for g in estate.groups if gone not in g["members"]],
    )
    current = {u: Placement.from_row(r) for u, r in layout_read.rows_at(sidestore, 1).items()}
    again = layout.replan(smaller, current, 2)
    assert again.layout_version == layout.ALGORITHM_VERSION + 1
    assert {r.reason for r in again.rows} == {layout.REPLAN}
    assert {r.uid for r in again.rows} == _expected_uids(smaller)
    layout.write(store.table_path(sidestore, layout.TABLE, 2), again.rows)
    at_2 = layout_read.rows_at(sidestore, 2)
    assert {r["layout_version"] for r in at_2.values()} == {again.layout_version}
    assert gone not in at_2
    assert gone in layout_read.rows_at(sidestore, 1)


def test_the_placement_at_t_is_the_newest_row_at_or_below_t(tmp_path: Path) -> None:
    sidestore = tmp_path / "sidestore"
    estate = synthetic_estate(8, 80)
    first = layout.place(estate, {}, 10)
    layout.write(store.table_path(sidestore, layout.TABLE, 10), first.rows)
    moved = next(d for d in estate.devices if d["site"] is None)
    grown = Estate(
        devices=[{**d, "site": "s000"} if d is moved else d for d in estate.devices],
        ports=estate.ports,
        cables=estate.cables,
        groups=estate.groups,
    )
    second = layout.place(grown, _by_uid(first.rows), 20)
    layout.write(store.table_path(sidestore, layout.TABLE, 20), second.rows)
    assert layout_read.keys(sidestore) == [10, 20]
    assert layout_read.rows_at(sidestore, 15)[moved["uid"]]["valid_from_ts"] == 10
    at_20 = layout_read.rows_at(sidestore, 20)[moved["uid"]]
    assert at_20["valid_from_ts"] == 20
    assert at_20["reason"] in (layout.RELATION_RESOLVED, layout.ANNEX)
    assert {r["uid"] for r in layout_read.delta_at(sidestore, 20)} == {r.uid for r in second.rows}
    assert layout_read.delta_at(sidestore, 15) == []
    ports = [p["uid"] for p in estate.ports if p["device_uid"] == moved["uid"]]
    assert all(_by_uid(second.rows)[p].reason == layout.RELATION_RESOLVED for p in ports)


def test_a_new_site_takes_the_next_spiral_cell_without_moving_the_others() -> None:
    estate = synthetic_estate(9, 100, sites=3)
    first = _by_uid(layout.place(estate, {}, 1).rows)
    new = {"uid": "dev:far", "name": "far", "role": "router", "tier": "core", "site": "zzz"}
    result = layout.place(replace(estate, devices=[*estate.devices, new]), first, 2)
    written = _by_uid(result.rows)
    assert {"site:zzz", "plate:zzz", "dev:far"} <= set(written)
    assert not ({r.uid for r in first.values() if r.kind == "site"} & set(written))
    site = written["site:zzz"]
    assert site.slot == 3
    others = [r for r in first.values() if r.kind == "site"]
    assert not any(_overlap(site, r) for r in others)


def test_the_tiles_split_the_ports_and_cables_by_block_and_cover_every_one() -> None:
    est = synthetic_estate(9, 300)
    at = {p.uid: p.row() for p in layout.place(est, {}, 100).rows}
    base = layout_read.select(at, at.values(), None)
    assert {r["kind"] for r in base} >= {"site", "plate", "block", "device"}
    assert {r["kind"] for r in base} <= layout_read.BASE_KINDS
    blocks = [uid for uid, r in at.items() if r["kind"] == "block"]
    tiled = {b: {r["uid"] for r in layout_read.select(at, at.values(), b)} for b in blocks}
    ports = {uid for uid, r in at.items() if r["kind"] == "port"}
    cables = {uid for uid, r in at.items() if r["kind"] == "cable"}
    assert set().union(*tiled.values()) == ports | cables
    assert sum(len(t & ports) for t in tiled.values()) == len(ports)
    crossing = [c for c in cables if sum(c in t for t in tiled.values()) == 2]
    assert crossing, "the estate has cables between blocks"


AREA_PER_DEVICE = 250


def test_a_device_box_has_the_same_size_for_1_and_2000_ports() -> None:
    estate = Estate(
        devices=[
            {"uid": "dev:a", "name": "a", "role": "switch", "tier": "access", "site": "fra"},
            {"uid": "dev:b", "name": "b", "role": "router", "tier": "core", "site": "fra"},
        ],
        ports=[
            {"uid": "dev:a/p0", "device_uid": "dev:a", "name": "eth0"},
            *({"uid": f"dev:b/p{i}", "device_uid": "dev:b", "name": f"eth{i}"} for i in range(2000)),
        ],
        cables=[{"a_port": "dev:a/p0", "b_port": "dev:b/p0"}],
    )
    result = layout.place(estate, {}, 1)
    rows = _by_uid(result.rows)
    assert (rows["dev:a"].w, rows["dev:a"].h) == (rows["dev:b"].w, rows["dev:b"].h)
    assert (rows["dev:b"].w, rows["dev:b"].h) == (layout.DEVICE_W, layout.DEVICE_H)
    ports = [r for r in rows.values() if r.kind == "port"]
    assert len(ports) == 2001
    assert {p.reason for p in ports} == {layout.FIRST_SEEN}
    for port in ports:
        dev = rows[port.parent_uid]
        assert dev.u <= port.u < dev.u + dev.w and dev.v <= port.v < dev.v + dev.h
    assert not result.replan_recommended


@pytest.mark.parametrize(
    "estate",
    [
        fixture_estate(),
        synthetic_estate(1, 400),
        synthetic_estate(3, 300, sites=9),
        synthetic_estate(4, 20, sites=1),
    ],
    ids=["fixtures", "synthetic", "nine-sites", "one-site"],
)
def test_the_plate_area_per_device_stays_within_the_bound(estate: Estate) -> None:
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    per_site: dict[str, int] = {}
    for site in layout.hierarchy(estate).device_site.values():
        per_site[site] = per_site.get(site, 0) + 1
    for site, count in per_site.items():
        plate = rows[layout.plate_uid(site)]
        assert plate.w * plate.h <= AREA_PER_DEVICE * count, site


@pytest.mark.parametrize(
    "estate", [fixture_estate(), synthetic_estate(3, 300)], ids=["fixtures", "synthetic"]
)
def test_a_cable_inside_a_site_is_orthogonal_with_at_most_two_bends(estate: Estate) -> None:
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    cables = [r for r in rows.values() if r.kind == "cable" and r.parent_uid is not None]
    assert cables
    for cable in cables:
        points = json.loads(cable.points)
        assert len(points) <= 4, cable.uid
        assert all(p[0] == q[0] or p[1] == q[1] for p, q in itertools.pairwise(points)), cable.uid


@pytest.mark.parametrize(
    "estate", [fixture_estate(), synthetic_estate(3, 300)], ids=["fixtures", "synthetic"]
)
def test_a_cable_inside_one_block_stays_inside_its_band(estate: Estate) -> None:
    h = layout.hierarchy(estate)
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    inside = 0
    for cid, (a, b) in h.cables.items():
        block = h.device_block[h.port_device[a]]
        if h.device_block[h.port_device[b]] != block:
            continue
        band = rows[block]
        inside += 1
        for u, v in json.loads(rows[cid].points):
            assert band.u <= u < band.u + band.w and band.v <= v < band.v + band.h, cid
    assert inside


def test_place_replans_a_layout_of_an_older_algorithm_version() -> None:
    estate = synthetic_estate(10, 120)
    old = {r.uid: replace(r, layout_version=1) for r in layout.place(estate, {}, 1).rows}
    result = layout.place(estate, old, 2)
    assert result.layout_version == layout.ALGORITHM_VERSION == 11
    assert {r.uid for r in result.rows} == _expected_uids(estate)
    assert {r.reason for r in result.rows} == {layout.REPLAN}
    assert {r.layout_version for r in result.rows} == {11}
    assert {r.valid_from_ts for r in result.rows} == {2}


def test_place_replans_a_version_10_layout_to_version_11() -> None:
    estate = _campus(access=2, aps=3)
    old = {r.uid: replace(r, layout_version=10) for r in layout.place(estate, {}, 1).rows}
    result = layout.place(estate, old, 2)
    assert result.layout_version == 11
    assert {r.uid for r in result.rows} == _expected_uids(estate)
    assert {r.reason for r in result.rows} == {layout.REPLAN}
    assert {r.layout_version for r in result.rows} == {11}


def _edge(site: str, name: str, role: str = "sdwan-edge") -> dict[str, Any]:
    return {"uid": f"dev:{name}", "name": name, "role": role, "tier": role, "site": site}


def _apart(a: Placement, b: Placement, gap: int) -> bool:
    return (
        a.u + a.w + gap <= b.u or b.u + b.w + gap <= a.u or a.v + a.h + gap <= b.v or b.v + b.h + gap <= a.v
    )


def test_a_hub_is_a_site_with_a_hub_device_at_the_centre_of_its_country_block() -> None:
    fr = [f"FR-C{i:03d}-AA" for i in range(8)]
    de = [f"DE-C{i:03d}-BB" for i in range(3)]
    devices = [
        _edge("SFA", "FR-SITE-SFA-RTH-03", "sdwan-hub"),
        _edge("SDB", "DE-SITE-SDB-RTH-03", "sdwan-hub"),
        _edge("ES-SITE-TA", "ES-SITE-TA-RTS-01", "sdwan-hub"),
        _edge("ES-SITE-PS", "ES-SITE-PS-RTS-01"),
        _edge("lab", "lab-rts-01"),
        *(_edge(c, f"{c}-RTS-01") for c in fr + de),
    ]
    links = [(hub, c) for hub in ("SFA", "SDB", "ES-SITE-TA") for c in ("ES-SITE-PS", *fr, *de)]
    # A site joined to many sites holds no hub device, so it stays a spoke.
    links += [("DE-C000-BB", c) for c in fr[:5]]
    estate = Estate(devices=devices, site_links=links)
    assert layout.hierarchy(estate).hub_sites == {"site:SFA", "site:SDB", "site:ES-SITE-TA"}
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    sites = {r.uid: r for r in rows.values() if r.kind == "site" and r.uid != layout.UNASSIGNED_SITE}
    # The country comes from the site code, else from the hostnames of the site's devices.
    assert sites["site:SFA"].parent_uid == "region:FR"
    assert sites["site:SDB"].parent_uid == "region:DE"
    assert sites["site:ES-SITE-PS"].parent_uid == "region:ES"
    assert sites["site:lab"].parent_uid == layout.OTHER_REGION
    par, ring = sites["site:SFA"], [sites[f"site:{c}"] for c in fr]
    centre_u = (min(r.u for r in ring) + max(r.u + r.w for r in ring)) / 2
    centre_v = (min(r.v for r in ring) + max(r.v + r.h for r in ring)) / 2
    assert par.u <= centre_u <= par.u + par.w and par.v <= centre_v <= par.v + par.h
    assert par.slot == 0 and sites["site:SDB"].slot == 0
    assert sites["site:DE-C000-BB"].slot > 0
    # The blocks whose sites join the most sites outside them come first.
    regions = sorted((r for r in rows.values() if r.kind == "region"), key=lambda r: r.slot or 0)
    assert [r.uid for r in regions] == ["region:ES", "region:DE", "region:FR", layout.OTHER_REGION]
    for i, a in enumerate(regions):
        assert all(_apart(a, b, layout.REGION_GAP) for b in regions[i + 1 :])
    for s in sites.values():
        b = rows[s.parent_uid]
        assert b.u <= s.u and s.u + s.w <= b.u + b.w and b.v <= s.v and s.v + s.h <= b.v + b.h, s.uid
    listed = list(sites.values())
    for i, a in enumerate(listed):
        assert not any(_overlap(a, b) for b in listed[i + 1 :])
    # Every device has a site, so the estate has no Unassigned site.
    assert layout.UNASSIGNED_SITE not in rows and layout.UNASSIGNED_PLATE not in rows


def test_the_country_of_a_site_comes_from_its_location_then_its_code_then_its_hostnames() -> None:
    devices = [
        _edge("SFA", "DE-SITE-SFA-RTH-03"),
        _edge("FR-C001-AA", "FR-C001-AA-RTS-01"),
        _edge("SDB", "DE-SITE-SDB-RTH-03"),
        _edge("lab", "lab-rts-01"),
        _edge("XB3", "FR-SITE-XB3-RTH-03"),
        _edge("CLOUD-AWS", "aws", "router"),
    ]
    # The location names a country for SFA, FR-C001-AA, lab and the CNC and cloud sites, none for SDB.
    located = {"SFA": "AT", "FR-C001-AA": "CZ", "lab": "AT", "XB3": "PL", "CLOUD-AWS": "US"}
    estate = Estate(devices=devices, site_countries=located, cloud_sites={"CLOUD-AWS": "AWS"})
    h = layout.hierarchy(estate)
    assert h.site_region["site:SFA"] == "region:AT"
    assert h.site_region["site:FR-C001-AA"] == "region:CZ"
    assert h.site_region["site:lab"] == "region:AT"
    assert h.site_region["site:SDB"] == "region:DE"
    # The core block and the cloud block keep their rules.
    assert h.site_region["site:XB3"] == layout.CORE_REGION
    assert h.site_region["site:CLOUD-AWS"] == layout.CLOUD_REGION
    unlocated = layout.hierarchy(Estate(devices=devices, cloud_sites={"CLOUD-AWS": "AWS"}))
    assert unlocated.site_region["site:SFA"] == "region:DE"
    assert unlocated.site_region["site:FR-C001-AA"] == "region:FR"
    assert unlocated.site_region["site:lab"] == layout.OTHER_REGION
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    assert rows["site:SFA"].parent_uid == rows["site:lab"].parent_uid == "region:AT"


def test_a_located_united_kingdom_site_joins_the_uk_block_of_its_coded_neighbours() -> None:
    # ISO 3166 writes GB; the naming standard of site codes and hostnames writes UK
    devices = [_edge("UK-LON-01", "UK-LON-01-RTS-01"), _edge("MAN", "UK-MAN-MAN-RTS-01")]
    estate = Estate(devices=devices, site_countries={"MAN": "GB"})
    h = layout.hierarchy(estate)
    assert h.site_region["site:UK-LON-01"] == h.site_region["site:MAN"] == "region:UK"


def test_the_hubs_of_one_block_form_a_near_square_group() -> None:
    hubs = [f"TR-C{i:03d}-AA" for i in range(5)]
    rows = _by_uid(
        layout.place(Estate(devices=[_edge(c, f"{c}-RTS-01", "sdwan-hub") for c in hubs]), {}, 1).rows
    )
    cells = [rows[f"site:{c}"] for c in hubs]
    assert len({r.u for r in cells}) == 3
    assert len({r.v for r in cells}) == 2


def test_a_new_site_takes_a_free_cell_of_its_block_and_a_new_country_goes_to_the_overflow_row() -> None:
    base = [_edge(c, f"{c}-RTS-01") for c in (f"FR-C{i:03d}-AA" for i in range(4))]
    first = _by_uid(layout.place(Estate(devices=base), {}, 1).rows)
    grown = [
        *base,
        _edge("FR-ZZZZ-AA", "FR-ZZZZ-AA-RTS-01"),
        _edge("IT-SITE-TA", "IT-SITE-TA-RTH-01", "sdwan-hub"),
    ]
    result = layout.place(Estate(devices=grown), first, 2)
    written = _by_uid(result.rows)
    placed = [r for r in first.values() if r.kind in ("region", "site")]
    assert not ({r.uid for r in placed} & set(written))
    site, block = written["site:FR-ZZZZ-AA"], first["region:FR"]
    assert site.parent_uid == "region:FR" and site.reason == layout.FIRST_SEEN and site.slot == 4
    assert block.u <= site.u and site.u + site.w <= block.u + block.w
    assert block.v <= site.v and site.v + site.h <= block.v + block.h
    assert not any(_overlap(site, r) for r in placed if r.kind == "site")
    italy = written["site:IT-SITE-TA"]
    assert italy.reason == layout.ANNEX and italy.slot == layout.NO_SLOT
    assert written["region:IT"].reason == layout.ANNEX
    assert italy.v > max(r.v + r.h for r in placed)
    assert result.replan_recommended


def test_a_cnc_is_a_site_with_an_ibx_code_or_a_network_edge_device() -> None:
    for code in ("XB3", "XA6", "XC5", "XJ10", "eqx-xa2", "BR-SITE-XF4", "IT-SITE-XG2"):
        assert layout.is_cnc_code(code), code
    for code in ("ES-SITE-TA", "DE-SITE-SDA-POC", "FR-C001-AA", "s000", "AB123", "lab"):
        assert not layout.is_cnc_code(code), code
    devices = [
        _edge("XB3", "FR-SITE-XB3-RTH-03", "sdwan-hub"),
        {**_edge("VNE-SITE", "GB-SITE-XE1-NE-01", "router"), "platform": layout.NETWORK_EDGE},
        _edge("ES-SITE-TA", "ES-SITE-TA-RTS-01", "sdwan-hub"),
        _edge("FR-C001-AA", "FR-C001-AA-RTS-01"),
    ]
    h = layout.hierarchy(Estate(devices=devices))
    assert h.cnc_sites == {"site:XB3", "site:VNE-SITE"}
    assert h.regions[layout.CORE_REGION] == ["site:XB3", "site:VNE-SITE"]
    assert h.site_region["site:ES-SITE-TA"] == "region:ES"
    assert h.site_region["site:FR-C001-AA"] == "region:FR"


def test_a_colo_site_and_a_site_with_fabric_ports_are_cnc_sites() -> None:
    devices = [
        {**_edge("DE-SITE-HALL", "DE-SITE-HALL-SWC-01", "switch"), "site_kind": layout.COLO},
        {
            "uid": "eqx:ibx:ES-SITE-EQX:XH2",
            "name": "Equinix XH2",
            "role": "cloud",
            "tier": "wan-edge",
            "site": "ES-SITE-EQX",
            "platform": layout.FABRIC_PLATFORM,
        },
        _edge("ES-SITE-PS", "ES-SITE-PS-RTS-01"),
    ]
    h = layout.hierarchy(Estate(devices=devices))
    assert h.cnc_sites == {"site:DE-SITE-HALL", "site:ES-SITE-EQX"}
    assert h.site_region["site:ES-SITE-PS"] == "region:ES"


def test_a_trunk_block_takes_one_column_range_so_its_area_covers_no_other_block() -> None:
    devices = [
        _edge("XD1", "GB-SITE-XD1-RTH-01", "sdwan-hub"),
        _edge("XD1", "GB-SITE-XD1-RTH-02", "sdwan-edge"),
        {
            "uid": "dev:rti",
            "name": "UK-SITE-XD1-RTI-01",
            "role": "router",
            "tier": "internet-edge",
            "site": "XD1",
        },
    ]
    estate = Estate(devices=devices)
    h = layout.hierarchy(estate)
    hub, edge = "dev:GB-SITE-XD1-RTH-01", "dev:GB-SITE-XD1-RTH-02"
    assert h.device_block[hub] == h.device_block[edge] != h.device_block["dev:rti"]
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    # The hub and the edge sit in different trunk rows of one block, in one column.
    assert rows[hub].v != rows[edge].v and rows[hub].u == rows[edge].u
    assert not _overlap(rows[h.device_block[hub]], rows[h.device_block["dev:rti"]])
    assert rows[hub].u - rows["dev:rti"].u >= layout.PITCH_W


def test_a_site_larger_than_the_spiral_cell_joins_the_group_at_the_centre() -> None:
    small = [f"FR-C{i:03d}-AA" for i in range(8)]
    devices = [_edge(c, f"{c}-RTS-01") for c in small]
    devices += [
        {
            "uid": f"dev:hq{i}",
            "name": f"FR-SITE-HQ-SWA-{i:02d}",
            "role": "switch",
            "tier": "access",
            "site": "FR-SITE-HQ",
        }
        for i in range(6)
    ]
    rows = _by_uid(layout.place(Estate(devices=devices), {}, 1).rows)
    big = rows["site:FR-SITE-HQ"]
    cells = [rows[f"site:{c}"] for c in small]
    assert big.parent_uid == "region:FR" and big.slot == 0
    assert all(c.slot > 0 for c in cells)
    # The spiral cell is sized for the small sites, not for the large one.
    assert {(c.w, c.h) for c in cells} == {(cells[0].w, cells[0].h)} and cells[0].w < big.w
    listed = [big, *cells]
    for i, a in enumerate(listed):
        assert not any(_overlap(a, b) for b in listed[i + 1 :])


def _inside(a: Placement, b: Placement) -> bool:
    return b.u <= a.u and a.u + a.w <= b.u + b.w and b.v <= a.v and a.v + a.h <= b.v + b.h


def test_a_site_group_path_nests_boxes_and_its_sites_leave_their_blocks() -> None:
    devices = [
        _edge("XA2", "DE-SITE-XA2-RTH-01", "sdwan-hub"),
        _edge("XA6", "DE-SITE-XA6-RTH-01", "sdwan-hub"),
        _edge("XB3", "FR-SITE-XB3-RTH-01", "sdwan-hub"),
        _edge("FR-C000-AA", "FR-C000-AA-RTS-01"),
        _edge("FR-C001-AA", "FR-C001-AA-RTS-01"),
    ]
    groups = {
        "XA2": ("Area A", "Area A1"),
        "XA6": ("Area A", "Area A1"),
        "XB3": ("Area A", "Area A2"),
        "FR-C000-AA": ("Campus A",),
    }
    rows = _by_uid(layout.place(Estate(devices=devices, site_groups=groups), {}, 1).rows)
    emea = "region:core:Area A"
    fra, par = f"{emea} / Area A1", f"{emea} / Area A2"
    campus = "region:group:Campus A"
    assert rows[emea].parent_uid is None
    assert rows[fra].parent_uid == rows[par].parent_uid == emea
    assert rows["site:XA2"].parent_uid == rows["site:XA6"].parent_uid == fra
    assert rows["site:XB3"].parent_uid == par
    assert rows["site:FR-C000-AA"].parent_uid == campus
    assert rows["site:FR-C001-AA"].parent_uid == "region:FR"
    nested = [(fra, emea), (par, emea), ("site:XA2", fra), ("site:XB3", par), ("site:FR-C000-AA", campus)]
    for child, box in nested:
        assert _inside(rows[child], rows[box]), child
    assert not _overlap(rows[fra], rows[par])
    # A group of CNC sites packs first, at the centre.
    tops = sorted(
        (r for r in rows.values() if r.kind == "region" and r.parent_uid is None), key=lambda r: r.slot or 0
    )
    assert tops[0].uid == emea


def test_a_named_block_holds_its_devices_and_its_external_zone_rows_above_the_firewall() -> None:
    devices = [
        {"uid": "dev:swc1", "name": "DE-SITE-XA2-SWC-01", "role": "router", "tier": "core", "site": "XA2"},
        {"uid": "dev:swc2", "name": "DE-SITE-XA2-SWC-02", "role": "router", "tier": "core", "site": "XA2"},
        {"uid": "dev:vsx", "name": "XA2-VSX", "role": "firewall", "tier": "firewall", "site": "XA2"},
    ]
    estate = Estate(devices=devices, named_blocks={"dev:swc2": ("External", "external")})
    h = layout.hierarchy(estate)
    block = h.device_block["dev:swc2"]
    assert block == "block:XA2:named:external"
    assert h.blocks[block] == ("site:XA2", "named:external:External")
    assert h.device_block["dev:swc1"] != block
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    assert rows["dev:swc2"].v < rows["dev:vsx"].v < rows["dev:swc1"].v
    assert rows[block].kind == "block"


def test_a_device_of_zone_internet_is_placed_exactly_as_one_of_zone_external() -> None:
    devices = [
        {"uid": "dev:swc1", "name": "DE-SITE-XA2-SWC-01", "role": "router", "tier": "core", "site": "XA2"},
        {"uid": "dev:swc2", "name": "DE-SITE-XA2-SWC-02", "role": "router", "tier": "core", "site": "XA2"},
        {"uid": "dev:vsx", "name": "XA2-VSX", "role": "firewall", "tier": "firewall", "site": "XA2"},
    ]
    placed = {}
    for zone in ("external", "internet"):
        estate = Estate(devices=devices, named_blocks={"dev:swc2": ("Uplink", zone)})
        h = layout.hierarchy(estate)
        assert h.blocks["block:XA2:named:uplink"] == ("site:XA2", f"named:{zone}:Uplink")
        rows = _by_uid(layout.place(estate, {}, 1).rows)
        assert rows["dev:swc2"].v < rows["dev:vsx"].v < rows["dev:swc1"].v
        placed[zone] = {uid: (r.kind, r.parent_uid, r.u, r.v, r.w, r.h) for uid, r in rows.items()}
    assert placed["internet"] == placed["external"]


def test_the_fabric_spine_sits_between_the_sites_of_its_metro_with_its_ports_facing_them() -> None:
    spine_code = "EQUINIX-FABRIC-XA"
    devices = [
        {"uid": "dev:sw2", "name": "DE-SITE-XA2-SWC-01", "role": "router", "tier": "core", "site": "XA2"},
        {"uid": "dev:sw6", "name": "DE-SITE-XA6-SWC-01", "role": "router", "tier": "core", "site": "XA6"},
        {"uid": "eqx:fabric:XA", "name": "Fabric XA", "role": "cloud", "tier": None, "site": spine_code},
    ]
    ports = [
        {"uid": "dev:sw2/p1", "device_uid": "dev:sw2", "name": "eth1/1"},
        {"uid": "dev:sw6/p1", "device_uid": "dev:sw6", "name": "eth1/1"},
        {"uid": "eqx:port:xa2", "device_uid": "eqx:fabric:XA", "name": "XA2-1"},
        {"uid": "eqx:port:xa6", "device_uid": "eqx:fabric:XA", "name": "XA6-1"},
    ]
    pairs = [("dev:sw2/p1", "eqx:port:xa2"), ("dev:sw6/p1", "eqx:port:xa6")]
    group = ("Area A1",)
    estate = Estate(
        devices=devices,
        ports=ports,
        cables=[{"a_port": a, "b_port": b} for a, b in pairs],
        site_groups={"XA2": group, "XA6": group, "EQUINIX-FABRIC-XA": group},
        cloud_sites={"EQUINIX-FABRIC-XA": "Fabric XA"},
        spines={"EQUINIX-FABRIC-XA": ("XA2", "XA6")},
    )
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    box = "region:core:Area A1"
    west, spine, east = rows["site:XA2"], rows["site:EQUINIX-FABRIC-XA"], rows["site:XA6"]
    assert west.parent_uid == spine.parent_uid == east.parent_uid == box
    assert west.u + west.w < spine.u and spine.u + spine.w < east.u
    assert west.v == spine.v == east.v
    assert (rows["eqx:port:xa2"].side, rows["eqx:port:xa6"].side) == ("w", "e")
    for a, b in pairs:
        cable = rows[layout.cable_id(a, b)]
        assert cable.parent_uid == box
        points = [tuple(p) for p in json.loads(cable.points or "[]")]
        assert all(p[0] == q[0] or p[1] == q[1] for p, q in itertools.pairwise(points))
        assert {points[0], points[-1]} == {(rows[a].u, rows[a].v), (rows[b].u, rows[b].v)}


def test_a_spine_plate_runs_the_height_of_the_sites_beside_it() -> None:
    group, spine = ("Area A1",), "EQUINIX-FABRIC-XA"
    devices = [
        {"uid": f"dev:sw{i}", "name": f"XA2-SWA-{i:02d}", "role": "switch", "tier": "access", "site": "XA2"}
        for i in range(6)
    ]
    devices += [
        {"uid": "dev:sw6", "name": "DE-SITE-XA6-SWC-01", "role": "router", "tier": "core", "site": "XA6"},
        {"uid": "eqx:fabric:XA", "name": "Fabric XA", "role": "cloud", "tier": "wan-edge", "site": spine},
    ]
    estate = Estate(
        devices=devices,
        site_groups={"XA2": group, "XA6": group, spine: group},
        spines={spine: ("XA2", "XA6")},
    )
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    assert rows[f"plate:{spine}"].h == rows["plate:XA2"].h > rows["plate:XA6"].h


def test_the_core_block_sits_at_the_centre_with_the_cloud_block_against_it() -> None:
    cnc = {
        "XC4": "CH-SITE-XC4-RTH-01",
        "XB4": "FR-SITE-XB4-RTH-01",
        "XB3": "FR-SITE-XB3-RTH-01",
        "BR-SITE-XF4": "BR-SITE-XF4-RTH-01",
    }
    fr = [f"FR-C{i:03d}-AA" for i in range(6)]
    de = [f"DE-C{i:03d}-BB" for i in range(3)]
    devices = [_edge(c, n, "sdwan-hub") for c, n in cnc.items()]
    devices += [_edge(c, f"{c}-RTS-01") for c in fr + de]
    devices.append(
        {"uid": "eqx:fabric:XA", "name": "Fabric XA", "role": "cloud", "tier": None, "site": "EQUINIX-FABRIC"}
    )
    links = [(hub, c) for hub in cnc for c in fr + de]
    estate = Estate(devices=devices, site_links=links, cloud_sites={"EQUINIX-FABRIC": "Equinix Fabric"})
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    regions = sorted((r for r in rows.values() if r.kind == "region"), key=lambda r: r.slot or 0)
    assert [r.uid for r in regions[:2]] == [layout.CORE_REGION, layout.CLOUD_REGION]
    core, cloud = regions[0], regions[1]
    assert _apart(core, cloud, layout.REGION_GAP) and not _apart(core, cloud, layout.REGION_GAP + 1)
    # The CNC sites leave their country blocks for one near-square group in country and code order.
    members = sorted(
        (r for r in rows.values() if r.kind == "site" and r.parent_uid == layout.CORE_REGION),
        key=lambda r: r.slot or 0,
    )
    assert [r.uid for r in members] == ["site:BR-SITE-XF4", "site:XC4", "site:XB3", "site:XB4"]
    assert len({r.u for r in members}) == len({r.v for r in members}) == 2
    assert (core.u, core.v) == (min(r.u for r in members), min(r.v for r in members))
    assert (core.u + core.w, core.v + core.h) == (
        max(r.u + r.w for r in members),
        max(r.v + r.h for r in members),
    )
    assert {rows[f"site:{c}"].parent_uid for c in fr} == {"region:FR"}
    assert layout.UNASSIGNED_SITE not in rows


def _campus(*, access: int, aps: int) -> Estate:
    devices = [{"uid": "dev:core", "name": "lower-swc-01", "role": "switch", "tier": "core", "site": "fra"}]
    devices += [
        {"uid": f"dev:sw{i}", "name": f"upper-swa-{i:02d}", "role": "switch", "tier": "access", "site": "fra"}
        for i in range(access)
    ]
    devices += [
        {"uid": f"dev:ap{i}", "name": f"ap-{i:02d}", "role": "ap", "tier": "access-point", "site": "fra"}
        for i in range(aps)
    ]
    return Estate(devices=devices)


def _centre(r: Placement) -> float:
    return r.u + r.w / 2


def test_each_partition_of_a_block_takes_rows_of_its_own_core_first() -> None:
    estate = _campus(access=7, aps=20)
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    tiers = {"core": ["dev:core"], "access": [f"dev:sw{i}" for i in range(7)]}
    tiers["access-point"] = [f"dev:ap{i}" for i in range(20)]
    lines = {t: {rows[d].v for d in uids} for t, uids in tiers.items()}
    assert max(lines["core"]) < min(lines["access"])
    assert max(lines["access"]) < min(lines["access-point"])
    assert len(lines["access-point"]) > 1
    assert {rows[d].parent_uid for uids in tiers.values() for d in uids} == {"block:fra:campus"}


def test_a_single_core_device_is_centred_above_the_access_row() -> None:
    rows = _by_uid(layout.place(_campus(access=2, aps=0), {}, 1).rows)
    access = [rows[f"dev:sw{i}"] for i in range(2)]
    assert len({r.v for r in access}) == 1
    assert _centre(rows["dev:core"]) == sum(_centre(r) for r in access) / len(access)
    block = rows["block:fra:campus"]
    assert _centre(rows["dev:core"]) - block.u == block.u + block.w - _centre(rows["dev:core"])


def test_a_new_access_device_takes_a_spare_slot_in_the_access_rows() -> None:
    estate = _campus(access=2, aps=4)
    first = _by_uid(layout.place(estate, {}, 1).rows)
    new = {"uid": "dev:sw9", "name": "oben-swa-09", "role": "switch", "tier": "access", "site": "fra"}
    result = layout.place(replace(estate, devices=[*estate.devices, new]), first, 2)
    written = _by_uid(result.rows)
    assert set(written) == {"dev:sw9"}
    device = written["dev:sw9"]
    assert device.reason == layout.FIRST_SEEN
    assert device.v in {first[f"dev:sw{i}"].v for i in range(2)}
    others = [r for r in first.values() if r.kind == "device"]
    assert not any(_overlap(device, r) for r in others)
    block = first["block:fra:campus"]
    assert block.u <= device.u and device.u + device.w <= block.u + block.w
    assert not result.replan_recommended


def test_lone_devices_sit_side_by_side_and_a_closet_with_children_keeps_a_spare_column() -> None:
    campus = _campus(access=2, aps=3)
    ports = [{"uid": f"{d['uid']}/p", "device_uid": d["uid"]} for d in campus.devices]
    ports.append({"uid": "dev:sw0/p1", "device_uid": "dev:sw0"})
    cables = [{"a_port": "dev:sw0/p1", "b_port": "dev:ap0/p"}]
    estate = Estate(devices=campus.devices, ports=ports, cables=cables)
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    assert rows["dev:ap0"].v > rows["dev:sw0"].v and rows["dev:ap0"].u == rows["dev:sw0"].u
    assert rows["dev:sw1"].u - rows["dev:sw0"].u == 2 * layout.PITCH_W
    assert rows["dev:ap2"].u - rows["dev:ap1"].u == layout.PITCH_W
    assert rows["dev:ap1"].u - rows["dev:sw1"].u == layout.PITCH_W
    assert {rows["dev:ap1"].v, rows["dev:ap2"].v} == {rows["dev:ap0"].v}


def test_a_segment_bar_sits_in_the_segment_row_under_its_device_and_a_taken_column_moves_it_on() -> None:
    campus = _campus(access=2, aps=1)
    ports = [{"uid": f"{d['uid']}/p", "device_uid": d["uid"]} for d in campus.devices]
    ports.append({"uid": "dev:sw0/p1", "device_uid": "dev:sw0"})
    cables = [{"a_port": "dev:sw0/p1", "b_port": "dev:ap0/p"}]
    estate = Estate(
        devices=campus.devices, ports=ports, cables=cables, segment_devices=["dev:sw0", "dev:ap0"]
    )
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    bar_sw, bar_ap = rows[layout.segments_uid("dev:sw0")], rows[layout.segments_uid("dev:ap0")]
    assert bar_sw.kind == bar_ap.kind == "segment"
    assert bar_sw.parent_uid == "dev:sw0" and bar_ap.parent_uid == "dev:ap0"
    assert bar_sw.v == bar_ap.v > rows["dev:ap0"].v > rows["dev:sw0"].v
    assert {bar_sw.u, bar_ap.u} >= {rows["dev:ap0"].u}
    assert abs(bar_sw.u - bar_ap.u) >= layout.PITCH_W
    assert layout.segments_uid("dev:core") not in rows
    block = rows["block:fra:campus"]
    assert block.v + block.h >= bar_sw.v + bar_sw.h
    grown = replace(estate, segment_devices=["dev:sw0", "dev:ap0", "dev:core"])
    written = _by_uid(layout.place(grown, rows, 2).rows)
    bar_core = written[layout.segments_uid("dev:core")]
    assert bar_core.v == bar_sw.v and bar_core.reason == layout.FIRST_SEEN
    assert all(abs(bar_core.u - b.u) >= layout.PITCH_W for b in (bar_sw, bar_ap))


def test_a_router_without_a_tier_takes_the_row_above_the_core() -> None:
    campus = _campus(access=2, aps=2)
    router = {"uid": "dev:rt", "name": "core1", "role": "router", "tier": None, "site": "fra"}
    ports = [
        {"uid": "dev:rt/port/eth0", "device_uid": "dev:rt"},
        {"uid": "dev:core/port/1", "device_uid": "dev:core"},
    ]
    cables = [{"a_port": "dev:rt/port/eth0", "b_port": "dev:core/port/1"}]
    estate = Estate(devices=[*campus.devices, router], ports=ports, cables=cables)
    rows = _by_uid(layout.place(estate, {}, 1).rows)
    assert rows["dev:rt"].parent_uid == rows["dev:core"].parent_uid
    assert rows["dev:rt"].v < rows["dev:core"].v < rows["dev:sw0"].v


def test_the_cloud_sites_sit_in_one_block_against_the_core_block() -> None:
    devices = [_edge(c, f"{c}-RTS-01") for c in (f"FR-C{i:03d}-AA" for i in range(3))]
    devices.append(_edge("XB3", "FR-SITE-XB3-RTH-03", "sdwan-hub"))
    devices.append({"uid": "dev:orphan", "name": "orphan", "role": "router", "tier": None, "site": None})
    cloud = [
        {
            "uid": "eqx:fabric:XA",
            "name": "Fabric XA",
            "role": "cloud",
            "tier": None,
            "site": "EQUINIX-FABRIC",
        },
        {
            "uid": "eqx:cloud-azure",
            "name": "Microsoft Azure",
            "role": "cloud",
            "tier": None,
            "site": "CLOUD-AZURE",
        },
    ]
    names = {"EQUINIX-FABRIC": "Equinix Fabric", "CLOUD-AZURE": "Microsoft Azure"}
    rows = _by_uid(layout.place(Estate(devices=[*devices, *cloud], cloud_sites=names), {}, 1).rows)
    block, core = rows[layout.CLOUD_REGION], rows[layout.CORE_REGION]
    unassigned = rows[layout.UNASSIGNED_SITE]
    assert (core.slot, block.slot) == (0, 1)
    assert _apart(core, block, layout.REGION_GAP) and not _apart(core, block, layout.REGION_GAP + 1)
    assert (
        rows["site:EQUINIX-FABRIC"].parent_uid == rows["site:CLOUD-AZURE"].parent_uid == layout.CLOUD_REGION
    )
    for region in (block, core, rows["region:FR"]):
        assert region.u + region.w <= unassigned.u, region.uid
    # A layout without the cloud block gets it east of everything at the next placement.
    first = _by_uid(layout.place(Estate(devices=devices), {}, 1).rows)
    grown = layout.place(Estate(devices=[*devices, *cloud], cloud_sites=names), first, 2)
    written = _by_uid(grown.rows)
    placed = [r for r in first.values() if r.kind in ("region", "site")]
    assert written[layout.CLOUD_REGION].u >= max(r.u + r.w for r in placed)
    assert written["site:CLOUD-AZURE"].reason == layout.FIRST_SEEN
    assert not grown.replan_recommended


def _assert_nested(rows: dict[str, Any], site: str) -> None:
    """Every block of `site` lies inside its plate, the plate inside the site, a device inside its block."""
    plate = rows[layout.plate_uid(site)]
    assert _inside(plate, rows[site]), (plate, rows[site])
    blocks = [r for r in rows.values() if r.kind == "block" and r.parent_uid == plate.uid]
    assert blocks
    for block in blocks:
        assert _inside(block, plate), (block, plate)
    for device in (
        r for r in rows.values() if r.kind == "device" and r.parent_uid in {b.uid for b in blocks}
    ):
        assert _inside(device, rows[device.parent_uid]), device


def _store_run(sidestore: Path, estate: Estate, key: int) -> tuple[layout.Result, dict[str, Placement]]:
    """Place `estate` on the layout in force at the last run, write the rows and read the layout at `key`."""
    keys = layout_read.keys(sidestore)
    current = (
        {u: Placement.from_row(r) for u, r in layout_read.rows_at(sidestore, keys[-1]).items()}
        if keys
        else {}
    )
    result = layout.place(estate, current, key)
    if result.rows:
        layout.write(store.table_path(sidestore, layout.TABLE, key), result.rows)
    return result, {u: Placement.from_row(r) for u, r in layout_read.rows_at(sidestore, key).items()}


def _unifi(site: str | None) -> list[dict[str, Any]]:
    out = []
    for i in range(3):
        out.append(
            {"uid": f"dev:ap{i}", "name": f"ap-{i}", "role": "ap", "tier": "access-point", "site": site}
        )
        out.append(
            {"uid": f"dev:usw{i}", "name": f"usw-{i}", "role": "switch", "tier": "access", "site": site}
        )
    return out


def _unifi_estate(site: str | None, *, unifi: bool = True) -> Estate:
    """A core switch in site hq, cabled to three access points and three access switches in `site`."""
    core = {"uid": "dev:core1", "name": "core1", "role": "switch", "tier": "core", "site": "hq"}
    devices = [core, *(_unifi(site) if unifi else [])]
    ports = [{"uid": f"{d['uid']}/p0", "device_uid": d["uid"], "name": "eth0"} for d in devices]
    ports += [
        {"uid": f"dev:core1/p{i + 1}", "device_uid": "dev:core1", "name": f"eth{i + 1}"} for i in range(6)
    ]
    cables = [
        {"a_port": f"dev:core1/p{i + 1}", "b_port": f"{d['uid']}/p0"} for i, d in enumerate(devices[1:])
    ]
    return Estate(devices=devices, ports=ports, cables=cables)


def test_devices_that_get_a_site_are_placed_once_and_unchanged_runs_keep_every_cell(tmp_path: Path) -> None:
    sidestore = tmp_path / "sidestore"
    # Run A: one device in its site. Run B: six devices without a site. Run C: the six get the site.
    a, at_a = _store_run(sidestore, _unifi_estate(None, unifi=False), 1)
    assert layout.UNASSIGNED_SITE not in at_a
    b, at_b = _store_run(sidestore, _unifi_estate(None), 2)
    assert {"block:unassigned:ap", "block:unassigned:switch", layout.UNASSIGNED_PLATE} <= set(at_b)
    c, at_c = _store_run(sidestore, _unifi_estate("hq"), 3)
    assert c.replan_recommended
    moved = [d["uid"] for d in _unifi("hq")]
    assert {at_c[d].parent_uid for d in moved} == {"block:hq:campus"}
    assert all(at_c[d].valid_from_ts == 3 for d in moved)
    for d in moved:
        port = at_c[f"{d}/p0"]
        assert _inside(port, at_c[d]) and port.valid_from_ts == 3
    _assert_nested(at_c, "site:hq")
    devices = [r for r in at_c.values() if r.kind == "device"]
    for i, x in enumerate(devices):
        assert not any(_overlap(x, y) for y in devices[i + 1 :]), x.uid
    # The Unassigned site, its plate and its blocks hold nothing at run C, so they leave the layout.
    unassigned = {
        layout.UNASSIGNED_SITE,
        layout.UNASSIGNED_PLATE,
        "block:unassigned:ap",
        "block:unassigned:switch",
    }
    assert not unassigned & set(at_c)
    delta = {r["uid"]: r for r in layout_read.delta_at(sidestore, 3)}
    assert {delta[u]["reason"] for u in unassigned} == {layout.REMOVED}
    assert unassigned <= set(layout_read.rows_at(sidestore, 2))
    assert unassigned <= set(layout_read.rows_at(sidestore, 3, removed=True))
    # Runs D and E change nothing: no row is written, every position holds, and no re-plan is recommended.
    d, at_d = _store_run(sidestore, _unifi_estate("hq"), 4)
    e, at_e = _store_run(sidestore, _unifi_estate("hq"), 5)
    assert d.rows == [] and e.rows == []
    assert not d.replan_recommended and not e.replan_recommended
    assert at_d == at_c and at_e == at_c
    assert layout_read.delta_at(sidestore, 4) == [] and layout_read.delta_at(sidestore, 5) == []
    assert not a.replan_recommended and not b.replan_recommended


def test_an_annex_past_the_strip_of_its_site_grows_the_plate_and_the_site_and_holds_on_the_next_run() -> None:
    first = _by_uid(layout.place(_unifi_estate(None, unifi=False), {}, 1).rows)
    site = first["site:hq"]
    result = layout.place(_unifi_estate("hq"), first, 2)
    written = _by_uid(result.rows)
    annexed = [written[d["uid"]] for d in _unifi("hq")]
    assert {r.reason for r in annexed} == {layout.ANNEX} and {r.slot for r in annexed} == {layout.NO_SLOT}
    assert result.replan_recommended
    rows = {**first, **written}
    # Six annex rows need more than the strip below the plate: the plate and the site grow down over them.
    assert max(r.v + r.h for r in annexed) > site.v + site.h
    assert written["plate:hq"].h > first["plate:hq"].h and written["site:hq"].h > site.h
    assert (written["site:hq"].u, written["site:hq"].v, written["site:hq"].w) == (site.u, site.v, site.w)
    _assert_nested(rows, "site:hq")
    again = layout.place(_unifi_estate("hq"), rows, 3)
    assert again.rows == [] and not again.replan_recommended


def test_the_unassigned_site_returns_east_of_the_estate_when_a_device_loses_its_site() -> None:
    first = _by_uid(layout.place(_unifi_estate(None, unifi=False), {}, 1).rows)
    result = layout.place(_unifi_estate(None), first, 2)
    written = _by_uid(result.rows)
    unassigned = written[layout.UNASSIGNED_SITE]
    assert unassigned.reason == layout.FIRST_SEEN and unassigned.slot == layout.NO_SLOT
    assert unassigned.u >= max(r.u + r.w for r in first.values() if r.kind in ("region", "site"))
    # The placed sites and regions stay where they are.
    assert not {u for u, r in first.items() if r.kind in ("region", "site", "plate")} & set(written)
    # The six devices take the rows of the new plate, not an annex.
    assert {written[d["uid"]].reason for d in _unifi(None)} == {layout.FIRST_SEEN}
    assert not result.replan_recommended
    _assert_nested({**first, **written}, layout.UNASSIGNED_SITE)


def _segmented(site: str | None, *, unifi: bool = True, drop: str | None = None) -> Estate:
    """`_unifi_estate` with a segment bar on each of the six devices and a device in another site, without
    the device `drop`."""
    base = _unifi_estate(site, unifi=unifi)
    lab = {"uid": "dev:lab1", "name": "lab1", "role": "switch", "tier": "core", "site": "lab"}
    devices = [d for d in [*base.devices, lab] if d["uid"] != drop]
    held = {d["uid"] for d in devices}
    return Estate(
        devices=devices,
        ports=[p for p in base.ports if p["device_uid"] in held],
        cables=base.cables,
        segment_devices=[d["uid"] for d in _unifi(site)] if unifi else [],
    )


def _assert_block_fits_its_children(rows: dict[str, Placement], block_uid: str) -> None:
    """The block is the bounding box of every device row in it and of their segment bars, plus its margin."""
    devices = [r for r in rows.values() if r.kind == "device" and r.parent_uid == block_uid]
    children = devices + [
        rows[layout.segments_uid(d.uid)] for d in devices if layout.segments_uid(d.uid) in rows
    ]
    m = layout.BLOCK_MARGIN
    u, v = min(r.u for r in children) - m, min(r.v for r in children) - m
    w = max(r.u + r.w for r in children) + m - u
    h = max(r.v + r.h for r in children) + m - v
    block = rows[block_uid]
    assert (block.u, block.v, block.w, block.h) == (u, v, w, h)


@pytest.mark.parametrize("removed", ["dev:lab1", "dev:core1"], ids=["unrelated", "planned-device"])
def test_a_run_that_removes_a_device_keeps_the_block_over_all_its_devices_and_no_wider(
    tmp_path: Path, removed: str
) -> None:
    sidestore = tmp_path / "sidestore"
    _store_run(sidestore, _segmented(None, unifi=False), 1)
    _store_run(sidestore, _segmented(None), 2)
    # The six devices get their site: they and their segment bars go to the annex rows below core1.
    _c, at_c = _store_run(sidestore, _segmented("hq"), 3)
    moved = [d["uid"] for d in _unifi("hq")]
    assert {at_c[layout.segments_uid(d)].valid_from_ts for d in moved} == {3}
    _assert_block_fits_its_children(at_c, "block:hq:campus")
    _assert_nested(at_c, "site:hq")
    _d, at_d = _store_run(sidestore, _segmented("hq", drop=removed), 4)
    assert at_d["dev:core1"].parent_uid == "block:hq:campus"
    _assert_block_fits_its_children(at_d, "block:hq:campus")
    _assert_nested(at_d, "site:hq")
    assert at_d["plate:hq"].w == at_d["site:hq"].w == at_c["plate:hq"].w
    e, at_e = _store_run(sidestore, _segmented("hq", drop=removed), 5)
    assert e.rows == [] and not e.replan_recommended and at_e == at_d


def test_a_box_grown_over_bars_left_at_their_old_site_shrinks_back_to_its_devices(tmp_path: Path) -> None:
    sidestore = tmp_path / "sidestore"
    _a, at_a = _store_run(sidestore, _segmented(None, unifi=False), 1)
    _store_run(sidestore, _segmented(None), 2)
    _c, at_c = _store_run(sidestore, _segmented("hq"), 3)
    # The rows of an older planner: the segment bars stayed in the Unassigned plate, and the block, the plate
    # and the site grew over them, with no planned box kept.
    old = dict(at_c)
    for i, d in enumerate(_unifi("hq")):
        bar = old[layout.segments_uid(d["uid"])]
        old[bar.uid] = replace(bar, u=60 + 8 * i, v=15, slot=2 * i, valid_from_ts=2, reason=layout.FIRST_SEEN)
    for uid in ("block:hq:campus", "plate:hq", "site:hq"):
        old[uid] = replace(old[uid], w=106, reason=layout.RELATION_RESOLVED, points=None)
    result = layout.place(_segmented("hq"), old, 4)
    rows = {**old, **_by_uid(result.rows)}
    for d in _unifi("hq"):
        bar = rows[layout.segments_uid(d["uid"])]
        assert bar.valid_from_ts == 4 and _inside(bar, rows["site:hq"]), bar
    _assert_block_fits_its_children(rows, "block:hq:campus")
    _assert_nested(rows, "site:hq")
    # The plate and the site shrink back to the planned width, and keep their planned box.
    assert rows["plate:hq"].w == rows["site:hq"].w == at_a["plate:hq"].w
    assert json.loads(rows["plate:hq"].points)[0] == [at_a["plate:hq"].u, at_a["plate:hq"].v]
    again = layout.place(_segmented("hq"), rows, 5)
    assert again.rows == [] and not again.replan_recommended


def test_a_grown_plate_shrinks_back_to_its_planned_box_when_its_annex_leaves(tmp_path: Path) -> None:
    sidestore = tmp_path / "sidestore"
    _a, at_a = _store_run(sidestore, _segmented(None, unifi=False), 1)
    _store_run(sidestore, _segmented("hq"), 2)
    _c, at_c = _store_run(sidestore, _segmented("lab"), 3)
    for uid in ("plate:hq", "site:hq"):
        before, after = at_a[uid], at_c[uid]
        assert (after.u, after.v, after.w, after.h) == (before.u, before.v, before.w, before.h), uid
    d, at_d = _store_run(sidestore, _segmented("lab"), 4)
    assert d.rows == [] and at_d == at_c


def test_pack_places_a_thousand_boxes_without_overlap_in_bounded_time() -> None:
    sizes = [(40 + (i * 7) % 25, 30 + (i * 11) % 20) for i in range(1000)]
    with cpu_time() as spent:
        corners = layout._pack(sizes, layout.SITE_GAP)
    assert spent.seconds < 1.0
    assert len(corners) == len(sizes)
    boxes = [(u, v, w, h) for (u, v), (w, h) in zip(corners, sizes, strict=True)]
    # no two boxes closer than the gap, tested on a coarse bucket grid
    cell = 200
    buckets: dict[tuple[int, int], list[int]] = {}
    for i, (u, v, w, h) in enumerate(boxes):
        for bu in range((u - layout.SITE_GAP) // cell, (u + w + layout.SITE_GAP) // cell + 1):
            for bv in range((v - layout.SITE_GAP) // cell, (v + h + layout.SITE_GAP) // cell + 1):
                buckets.setdefault((bu, bv), []).append(i)
    for members in buckets.values():
        for a, b in itertools.combinations(members, 2):
            assert not layout._clash(boxes[a], boxes[b], layout.SITE_GAP), (a, b)
    assert corners == layout._pack(sizes, layout.SITE_GAP)


def test_pack_keeps_the_nearest_spot_placement_up_to_the_limit() -> None:
    sizes = [(40, 30)] * layout.PACK_NEAREST_MAX
    corners = layout._pack(sizes, layout.SITE_GAP)
    assert corners[0] == (-20, -15)
    assert corners != layout._shelves(sizes, layout.SITE_GAP)


def _site_rows(
    sidestore: Path, key: int, names: list[str], *, table: str = layout.TABLE, **fields: Any
) -> None:
    rows = [
        Placement(f"site:{n}", "site", None, i, 0, 1, 1, valid_from_ts=key, **fields)
        for i, n in enumerate(names)
    ]
    layout.write(store.table_path(sidestore, table, key), rows)


def _count_reads(monkeypatch: Any) -> list[str]:
    reads: list[str] = []
    real = layout_read.pq.read_table

    def counting(path: Any, *args: Any, **kwargs: Any) -> Any:
        reads.append(Path(path).parent.name + "/" + Path(path).name)
        return real(path, *args, **kwargs)

    monkeypatch.setattr(layout_read.pq, "read_table", counting)
    return reads


def test_the_placement_at_t_starts_from_the_newest_checkpoint_and_reads_no_older_file(
    tmp_path: Path, monkeypatch: Any
) -> None:
    sidestore = tmp_path / "sidestore"
    for key in range(1, 41):
        _site_rows(sidestore, key, [f"k{key}"])
    full = {f"site:k{k}" for k in range(1, 41)}
    walked = layout_read.rows_at(sidestore, 40)
    assert set(walked) == full
    # a checkpoint at 30: every row in force at 30, rewritten with its own run
    _site_rows(sidestore, 30, [f"k{k}" for k in range(1, 31)], table=layout_read.FULL_TABLE)
    reads = _count_reads(monkeypatch)
    at_40 = layout_read.rows_at(sidestore, 40)
    assert set(at_40) == full
    assert len(reads) == 11 and reads[-1] == "layout_full/30.parquet"
    assert not any(read in reads for read in ("layout/29.parquet", "layout/30.parquet"))
    assert layout_read.chain_length(sidestore, 40) == 10
    # at a run before the checkpoint, it is not used
    assert set(layout_read.rows_at(sidestore, 20)) == {f"site:k{k}" for k in range(1, 21)}


def test_a_checkpoint_does_not_bring_back_a_row_of_an_older_layout_version(tmp_path: Path) -> None:
    sidestore = tmp_path / "sidestore"
    _site_rows(sidestore, 1, ["a", "b"])
    _site_rows(sidestore, 2, ["a", "b"], table=layout_read.FULL_TABLE)
    # a replan at 3 places only `c` under version 2
    _site_rows(sidestore, 3, ["c"], layout_version=2)
    assert set(layout_read.rows_at(sidestore, 3)) == {"site:c"}
    assert set(layout_read.rows_at(sidestore, 2)) == {"site:a", "site:b"}


def test_the_placement_at_a_run_is_read_once_and_read_again_when_its_files_change(
    tmp_path: Path, monkeypatch: Any
) -> None:
    sidestore = tmp_path / "sidestore"
    _site_rows(sidestore, 1, ["a"])
    reads = _count_reads(monkeypatch)
    first = layout_read.layout_at(sidestore, 1)
    assert layout_read.layout_at(sidestore, 1) is first
    assert set(layout_read.rows_at(sidestore, 1)) == {"site:a"}
    assert len(reads) == 1
    _site_rows(sidestore, 1, ["a", "b"])
    assert set(layout_read.rows_at(sidestore, 1)) == {"site:a", "site:b"}
    _site_rows(sidestore, 2, ["c"])
    assert set(layout_read.rows_at(sidestore, 2)) == {"site:a", "site:b", "site:c"}
    # only the two newest placements stay in memory
    layout_read.layout_at(sidestore, 1)
    assert len(layout_read._AT) <= layout_read.CACHE_SIZE


def test_the_tile_index_serves_the_rows_select_picks_for_a_tile_and_for_a_delta(tmp_path: Path) -> None:
    sidestore = tmp_path / "sidestore"
    est = synthetic_estate(9, 300)
    placed = layout.place(est, {}, 100)
    layout.write(store.table_path(sidestore, layout.TABLE, 100), placed.rows)
    at = layout_read.rows_at(sidestore, 100)
    index = layout_read.layout_at(sidestore, 100)
    assert {r["uid"] for r in index.rows(None)} == {
        r["uid"] for r in layout_read.select(at, at.values(), None)
    }
    blocks = [uid for uid, r in at.items() if r["kind"] == "block"]
    delta = layout_read.delta_at(sidestore, 100)
    for block in blocks:
        assert index.is_block(block)
        want = {r["uid"] for r in layout_read.select(at, at.values(), block)}
        assert {r["uid"] for r in index.rows(block)} == want
        assert {r["uid"] for r in index.delta(delta, block)} == want
    assert not index.is_block("dev:nowhere")


def test_the_projection_writes_a_layout_checkpoint_after_n_incremental_files(tmp_path: Path) -> None:
    sidestore = tmp_path / "sidestore"
    for key in (1, 2):
        _site_rows(sidestore, key, [f"k{key}"])
    gone = Placement("site:k1", "site", None, 0, 0, 1, 1, valid_from_ts=2, reason=layout.REMOVED)
    k2 = Placement("site:k2", "site", None, 0, 0, 1, 1, valid_from_ts=2)
    layout.write(store.table_path(sidestore, layout.TABLE, 2), [gone, k2])
    projection = Projection(sidestore, tmp_path / "markers", 3, 2, "full", checkpoint_every=3)
    current = {u: Placement.from_row(r) for u, r in layout_read.rows_at(sidestore, 2).items()}
    new = Placement("site:k3", "site", None, 5, 0, 1, 1, valid_from_ts=3)
    rows = projection._layout_checkpoint(current, layout.Result([new], False, 1))
    # the removed row stays: it keeps the older row of site:k1 from coming back
    assert {(r.uid, r.reason) for r in rows} == {
        ("site:k1", layout.REMOVED),
        ("site:k2", layout.FIRST_SEEN),
        ("site:k3", layout.FIRST_SEEN),
    }
    # fewer files than N since the last checkpoint: none
    assert (
        Projection(sidestore, tmp_path / "markers", 3, 2, "full", checkpoint_every=4)._layout_checkpoint(
            current, layout.Result([new], False, 1)
        )
        == []
    )
    # a replan places every element, so no row of the older version is carried
    replanned = layout.Result([replace(new, layout_version=2)], False, 2)
    assert [r.uid for r in projection._layout_checkpoint(current, replanned)] == ["site:k3"]


def test_the_runs_between_two_layout_files_share_one_placement_build(
    tmp_path: Path, monkeypatch: Any
) -> None:
    sidestore = tmp_path / "sidestore"
    _site_rows(sidestore, 1, ["a"])
    _site_rows(sidestore, 5, ["b"])
    reads = _count_reads(monkeypatch)
    window = [layout_read.layout_at(sidestore, t) for t in range(1, 10)]
    assert all(at is window[0] for at in window[:4])
    assert all(at is window[4] for at in window[4:])
    assert len(reads) == 1 + 2
    assert len(layout_read._AT) <= layout_read.CACHE_SIZE
