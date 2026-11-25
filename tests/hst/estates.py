"""Layout estates for the HST tests: the fixtures read without a database, and a seeded synthetic estate."""

from __future__ import annotations

import random
from pathlib import Path

from hst.core.fixtures import load_fixture
from hst.map.layout import Estate

FIXTURES = sorted((Path(__file__).parents[2] / "fixtures").glob("*.yaml"))
TIERS = ("internet-edge", "wan-edge", "firewall", "core", "distribution", "access", "spine", "leaf", None)


def fixture_estate() -> Estate:
    nodes, rels = {}, []
    for path in FIXTURES:
        batch = load_fixture(path)
        nodes.update({n.uid: n for n in batch.nodes})
        rels.extend(batch.rels)
    codes = {uid: n.props.get("code") for uid, n in nodes.items() if n.label == "Site"}
    located = {r.start_uid: codes.get(r.end_uid) for r in rels if r.rel_type == "LOCATED_IN"}
    devices = [
        {
            "uid": n.uid,
            "name": n.props.get("hostname") or n.uid,
            "role": n.props.get("role"),
            "tier": n.props.get("tier"),
            "site": located.get(n.uid),
        }
        for n in nodes.values()
        if n.label == "Device"
    ]
    on = {r.start_uid: r.end_uid for r in rels if r.rel_type == "ON" and r.start_label == "Port"}
    ports = [
        {"uid": n.uid, "device_uid": on[n.uid], "name": n.props.get("name") or n.uid}
        for n in nodes.values()
        if n.label == "Port" and n.uid in on
    ]
    cables = [{"a_port": r.start_uid, "b_port": r.end_uid} for r in rels if r.rel_type == "CONNECTED_TO"]
    members: dict[str, list[str]] = {}
    for r in rels:
        if r.rel_type == "MEMBER_OF" and r.end_label == "RedundancyGroup":
            members.setdefault(r.end_uid, []).append(r.start_uid)
    groups = [{"uid": g, "members": m} for g, m in members.items()]
    return Estate(
        devices=devices, ports=ports, cables=cables, groups=groups, sites=sorted(set(codes.values()))
    )


def synthetic_estate(
    seed: int, devices: int, *, sites: int = 6, orphan_share: float = 0.05, cross_share: float = 0.02
) -> Estate:
    rng = random.Random(seed)
    codes = [f"s{i:03d}" for i in range(sites)]
    rows, ports = [], []
    for i in range(devices):
        uid = f"dev:syn{i:05d}"
        tier = rng.choice(TIERS)
        site = None if rng.random() < orphan_share else rng.choice(codes)
        rows.append(
            {"uid": uid, "name": f"syn{i:05d}", "role": tier or "unknown", "tier": tier, "site": site}
        )
        for p in range(rng.randint(2, 10)):
            ports.append({"uid": f"{uid}/port/{p}", "device_uid": uid, "name": f"eth{p}"})
    by_site: dict[str | None, list[dict]] = {}
    for r in rows:
        by_site.setdefault(r["site"], []).append(r)
    free = {r["uid"]: [p["uid"] for p in ports if p["device_uid"] == r["uid"]] for r in rows}
    cables = []
    for _ in range(devices):
        a = rng.choice(rows)
        pool = rows if rng.random() < cross_share else by_site[a["site"]]
        b = rng.choice(pool)
        if a is b or not free[a["uid"]] or not free[b["uid"]]:
            continue
        cables.append({"a_port": free[a["uid"]].pop(), "b_port": free[b["uid"]].pop()})
    groups = []
    for i in range(0, devices // 20):
        a, b = rows[2 * i], rows[2 * i + 1]
        if a["site"] == b["site"] and a["tier"] == b["tier"]:
            groups.append({"uid": f"rgrp:syn:{i}", "members": [a["uid"], b["uid"]]})
    return Estate(devices=rows, ports=ports, cables=cables, groups=groups)
