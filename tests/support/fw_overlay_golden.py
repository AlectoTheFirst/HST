"""Estates for the policy change overlay's routing follow-on, and the recorded
answer of each (`fw_overlay_golden.json`).

`hst.app.fw_overlay_read` reads the recorded route table one VRF at a time
(`_RouteTable`). Every case here runs `simulate_change` over a fake graph
read, a fake tracer and a fake RibSource. tests/test_fw_overlay_route_table.py
compares the digest and the counts of the whole answer (`summarize`) with the
recorded ones.

The digest leaves out one field, `routing_consequence.recorded_routes_truncated`.
The golden file holds a text of that field beside the digest, and the test
checks the count that the text states.

Nothing in the repository writes the golden file.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

GOLDEN = Path(__file__).with_name("fw_overlay_golden.json")
# The field `digest` leaves out.
REWORDED = "recorded_routes_truncated"
# The model errors a flow's comparison basis adds to an answer.
BASIS_ERRORS = ("flow-result-not-established", "derived-flows-not-decided-by-the-change")

DENIED_V4 = ("192.168.2.35", "192.168.2.36")
DENIED_V6 = "2001:db8::35"


def _deny(source: Any, destination: Any) -> dict[str, Any]:
    return {
        "kind": "fw_rule.add",
        "params": {
            "rulebase": "fw:LAN",
            "position": 10,
            "action": "drop",
            "source": source,
            "destination": destination,
        },
    }


DENY_TO = _deny("any", [*DENIED_V4, DENIED_V6])
DENY_FROM = _deny(DENIED_V4[0], "any")
DENY_BOTH = _deny([DENIED_V4[1]], [DENIED_V4[0], "192.168.2.40/30"])


@dataclass
class Case:
    """One estate and one question put to it.

    `graph` is what `_LEARNED_NEXT_HOPS` answers; `vrf_devices` what
    `_VRF_DEVICES` answers; `rib` the side-store rows per (device, VRF), or
    None for a caller that passes no RibSource.
    """

    graph: list[dict[str, Any]]
    intents: list[dict[str, Any]]
    vrf_devices: list[dict[str, Any]] = field(default_factory=list)
    rib: dict[tuple[str, str | None], list[dict[str, Any]]] | None = None
    sites: list[dict[str, Any]] = field(default_factory=list)
    vrf_sites: list[dict[str, Any]] = field(default_factory=list)
    peers: list[dict[str, Any]] = field(default_factory=list)
    flows: list[dict[str, Any]] | None = None
    depth: int | None = None
    site_filter: list[str] | None = None
    detail: bool = False


class FakeRib:
    """A RibSource that answers `routes` from `rows`, per (device, VRF), with
    fresh row dicts on every call, as the real one reads them fresh."""

    def __init__(self, rows: dict[tuple[str, str | None], list[dict[str, Any]]]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, str | None]] = []

    def routes(
        self, device_uid: str, context_uid: str | None, *, legacy_vrf: str | None = None
    ) -> list[dict[str, Any]]:
        self.calls.append((device_uid, context_uid))
        return [dict(r) for r in self.rows.get((device_uid, context_uid), ())]


def _graph_row(context: str, prefix: str, next_hop: str, **extra: Any) -> dict[str, Any]:
    return {
        "kind": extra.pop("kind", "LEARNED_ROUTE"),
        "prefix": prefix,
        "next_hop": next_hop,
        "protocol": extra.pop("protocol", "bgp"),
        "interface": extra.pop("interface", "eth0"),
        "metric": extra.pop("metric", 20),
        "context_uid": context,
        **extra,
    }


def _rib_row(prefix: str, next_hop: str, **extra: Any) -> dict[str, Any]:
    return {
        "prefix": prefix,
        "next_hop": next_hop,
        "protocol": extra.pop("protocol", "bgp"),
        "interface": extra.pop("interface", "eth0"),
        "metric": extra.pop("metric", 20),
        **extra,
    }


def _vd(context: str | None, device: str, vrf: str = "default") -> dict[str, Any]:
    return {"context_uid": context, "vrf_name": vrf, "device_uid": device}


def _chain_case(depth: int | None) -> Case:
    """A dependency chain ten levels long, a cycle, a route whose next hop is
    in its own prefix, a less specific route that keeps one link resolved, and
    a next hop no prefix covers."""
    vrf = "vrf:dev:x:vyos:core1:default"
    rows = [_graph_row(vrf, "10.0.0.0/16", DENIED_V4[0]), _graph_row(vrf, "10.0.0.0/16", DENIED_V4[1])]
    for k in range(1, 10):
        rows.append(_graph_row(vrf, f"10.{k}.0.0/16", f"10.{k - 1}.0.1"))
    rows += [
        # 10.20/16 and 10.21/16 resolve through each other and through 10.0/16
        _graph_row(vrf, "10.20.0.0/16", "10.21.0.1"),
        _graph_row(vrf, "10.20.0.0/16", "10.0.0.9"),
        _graph_row(vrf, "10.21.0.0/16", "10.20.0.1"),
        _graph_row(vrf, "10.50.0.0/16", "10.50.0.1"),
        # 10.3.5.0/24 holds its next hop, so 10.60/16 keeps resolving
        _graph_row(vrf, "10.3.5.0/24", "172.31.0.1", protocol="ospf", interface="eth2"),
        _graph_row(vrf, "10.60.0.0/16", "10.3.5.7"),
        _graph_row(vrf, "10.70.0.0/16", "203.0.113.200"),
        _graph_row(vrf, "10.80.0.0/16", "10.9.0.1", kind="STATIC_ROUTE", protocol="static"),
    ]
    return Case(graph=rows, intents=[DENY_TO], flows=[{"src": "10.0.0.5", "dst": "10.9.0.1"}], depth=depth)


def _merge_case() -> Case:
    """Graph and side-store rows of the same route, a graph row that takes the
    side-store row's interface, side-store duplicates, a VRF read from two
    devices, `_VRF_DEVICES` rows out of VRF order and a VRF with no uid."""
    core = "vrf:dev:x:vyos:core1:default"
    blue = "vrf:dev:x:vyos:core1:blue"
    edge = "vrf:dev:x:iosxe:edge1:default"
    graph = [
        _graph_row(core, "10.10.10.1/32", DENIED_V4[0]),
        _graph_row(core, "10.10.10.1/32", DENIED_V4[1], interface=None),
        _graph_row(core, "10.20.0.0/16", DENIED_V4[0]),
        _graph_row(core, "10.20.0.0/16", "10.9.9.9", protocol="ospf"),
        _graph_row(blue, "10.30.0.0/16", DENIED_V4[0], interface=""),
        _graph_row(blue, "10.30.0.0/16", DENIED_V4[0], interface=""),
    ]
    rib = {
        ("dev:x:core1", core): [
            _rib_row("10.10.10.1/32", DENIED_V4[0]),
            _rib_row("10.10.10.1/32", DENIED_V4[1], interface="eth7"),
            _rib_row("10.20.0.0/16", "10.9.9.10"),
            _rib_row("10.40.0.0/16", "10.9.9.9"),
            _rib_row("10.41.0.0/16", DENIED_V4[1], protocol="static", interface=None),
            _rib_row("10.41.0.0/16", DENIED_V4[1], protocol="static", interface="eth4"),
        ],
        ("dev:x:core1", blue): [
            _rib_row("10.30.0.0/16", DENIED_V4[0], interface="eth3"),
            _rib_row("10.31.0.0/16", DENIED_V4[0], next_hop_context_uid=core),
            _rib_row("10.31.0.0/16", DENIED_V4[0]),
        ],
        # the edge VRF is read from two devices: its denied route comes from the
        # second, and the first holds another next hop of the same prefix
        ("dev:x:edge1", edge): [
            _rib_row("198.51.100.0/24", "10.1.1.1"),
            _rib_row("198.51.100.0/24", "10.1.1.2"),
        ],
        ("dev:x:edge1b", edge): [
            _rib_row("198.51.100.0/24", DENIED_V4[0], protocol="static"),
            _rib_row("198.51.100.0/24", "10.1.1.1"),
            _rib_row("198.51.101.0/24", DENIED_V4[0]),
        ],
        ("dev:x:lab1", None): [_rib_row("10.90.0.0/16", DENIED_V4[0])],
    }
    return Case(
        graph=graph,
        intents=[DENY_TO],
        vrf_devices=[
            _vd(edge, "dev:x:edge1"),
            _vd(core, "dev:x:core1"),
            _vd(blue, "dev:x:core1", "blue"),
            _vd(edge, "dev:x:edge1b"),
            _vd(None, "dev:x:lab1"),
        ],
        rib=rib,
        depth=3,
    )


def _odd_case() -> Case:
    """Prefixes `_intervals` reads unusually: IPv6, host bits set, a bare
    address, a range; next hops that are not addresses; rows with no prefix."""
    vrf = "vrf:dev:x:vyos:core1:default"
    graph = [
        _graph_row(vrf, "2001:db8:1::/48", DENIED_V6),
        _graph_row(vrf, "2001:db8:2::/48", "2001:db8:1::9"),
        _graph_row(vrf, "10.1.2.3/16", DENIED_V4[0]),
        _graph_row(vrf, "10.44.0.0/16", "10.1.200.1"),
        _graph_row(vrf, "10.9.9.9", DENIED_V4[0]),
        _graph_row(vrf, "10.45.0.0/16", "10.9.9.9"),
        _graph_row(vrf, "10.46.0.0-10.46.0.255", DENIED_V4[1]),
        _graph_row(vrf, "10.47.0.0/16", "10.46.0.7"),
        _graph_row(vrf, "10.48.0.0/16", "not-an-address"),
        _graph_row(vrf, "10.49.0.0/16", " 192.168.2.35 "),
        _graph_row(vrf, "", DENIED_V4[0]),
    ]
    rib = {
        ("dev:x:core1", vrf): [
            _rib_row("", DENIED_V4[1]),
            _rib_row("0.0.0.0/0", DENIED_V4[0]),
            _rib_row("::/0", DENIED_V6),
            _rib_row("10.200.0.0/16", ""),
            _rib_row("10.201.0.0/16", "10.46.0.9-10.46.0.12"),
        ]
    }
    return Case(
        graph=graph,
        intents=[DENY_TO],
        vrf_devices=[_vd(vrf, "dev:x:core1")],
        rib=rib,
        depth=4,
    )


_SITE_ROWS = [
    {"uid": "site:hq", "code": "HQ", "name": "Head office"},
    {"uid": "site:dc1", "code": "DC1", "name": "Data centre 1"},
]


def _sites_case(site_filter: list[str] | None, depth: int) -> Case:
    hq = "vrf:dev:x:vyos:core1:default"
    dc = "vrf:dev:x:vyos:dc1:default"
    lab = "vrf:dev:x:vyos:lab1:default"
    graph = [
        _graph_row(hq, "10.10.10.1/32", DENIED_V4[0]),
        _graph_row(hq, "172.16.0.0/16", "10.10.10.1"),
        _graph_row(dc, "10.30.0.0/16", DENIED_V4[0]),
        _graph_row(dc, "10.31.0.0/16", DENIED_V4[1]),
        _graph_row(dc, "10.31.0.0/16", "10.1.1.1"),
        _graph_row(lab, "10.40.0.0/16", DENIED_V4[0]),
        _graph_row(lab, "10.41.0.0/16", "10.9.9.9"),
    ]
    rib = {("dev:x:dc1", dc): [_rib_row("10.32.0.0/16", "10.30.0.1"), _rib_row("10.33.0.0/16", "10.8.8.8")]}
    return Case(
        graph=graph,
        intents=[DENY_TO],
        vrf_devices=[_vd(dc, "dev:x:dc1")],
        rib=rib,
        sites=_SITE_ROWS,
        vrf_sites=[
            {"context_uid": hq, "site_uids": ["site:hq"]},
            {"context_uid": dc, "site_uids": ["site:dc1"]},
        ],
        site_filter=site_filter,
        depth=depth,
    )


def _wide_case(detail: bool) -> Case:
    """More withdrawn routes and prefixes than a pane lists."""
    vrf = "vrf:dev:x:iosxe:edge1:default"
    rib = {
        ("dev:x:edge1", vrf): [
            _rib_row(f"198.{18 + i // 250}.{i % 250}.0/24", DENIED_V4[i % 2], metric=i) for i in range(140)
        ]
    }
    graph = [_graph_row(vrf, f"203.0.{i}.0/24", DENIED_V4[0]) for i in range(20)]
    return Case(
        graph=graph,
        intents=[DENY_TO],
        vrf_devices=[_vd(vrf, "dev:x:edge1")],
        rib=rib,
        detail=detail,
    )


def _direction_case(intent: dict[str, Any]) -> Case:
    vrf = "vrf:dev:x:vyos:core1:default"
    graph = [
        _graph_row(vrf, "10.10.10.1/32", DENIED_V4[0]),
        _graph_row(vrf, "10.11.0.0/16", DENIED_V4[0], kind="STATIC_ROUTE", protocol="static"),
        _graph_row(vrf, "10.12.0.0/16", DENIED_V4[1], kind="STATIC_ROUTE", protocol="static"),
        _graph_row(vrf, "10.13.0.0/16", "192.168.2.41"),
    ]
    rib = {
        ("dev:x:core1", vrf): [
            _rib_row("10.14.0.0/16", DENIED_V4[0], protocol="static"),
            _rib_row("10.15.0.0/16", DENIED_V4[1]),
            _rib_row("10.16.0.0/16", "192.168.2.42", protocol="Static"),
        ]
    }
    return Case(
        graph=graph,
        intents=[intent],
        vrf_devices=[_vd(vrf, "dev:x:core1")],
        rib=rib,
        peers=[
            {
                "uid": "bgp:a:1",
                "peer_ip": DENIED_V4[0],
                "peer_asn": 65002,
                "local_asn": 65001,
                "process_uid": "rp:a",
                "context_uid": vrf,
            }
        ],
        flows=None,
        depth=2,
    )


def _random_case(seed: int) -> Case:
    """A generated estate: nested IPv4 and IPv6 prefixes over six
    VRFs, split between the graph and the side store, with next hops drawn
    from the denied addresses, from inside the estate's own prefixes and from
    outside it."""
    rng = random.Random(seed)
    contexts = [f"vrf:dev:x:r{n}:{name}" for n in range(3) for name in ("default", "blue")]
    device_of = {c: f"dev:x:r{c.split(':')[3][1:]}" for c in contexts}
    graph: list[dict[str, Any]] = []
    rib: dict[tuple[str, str | None], list[dict[str, Any]]] = {}
    for context in contexts:
        prefixes = sorted(
            {f"10.{rng.randrange(8)}.0.0/16" for _ in range(6)}
            | {f"10.{rng.randrange(8)}.{rng.randrange(8)}.0/24" for _ in range(30)}
            | {f"10.{rng.randrange(8)}.{rng.randrange(8)}.{rng.randrange(4) * 64}/26" for _ in range(40)}
            | {f"2001:db8:{rng.randrange(4)}::/48" for _ in range(3)}
            | ({"10.0.0.0/8"} if rng.random() < 0.5 else set())
        )
        side: list[dict[str, Any]] = []
        for prefix in prefixes:
            v6 = ":" in prefix
            for _ in range(rng.choice((1, 1, 2, 3))):
                roll = rng.random()
                if roll < 0.2:
                    next_hop = DENIED_V6 if v6 else rng.choice(DENIED_V4)
                elif roll < 0.8:
                    next_hop = (
                        f"2001:db8:{rng.randrange(4)}::{rng.randrange(1, 9)}"
                        if v6
                        else f"10.{rng.randrange(8)}.{rng.randrange(8)}.{rng.randrange(1, 255)}"
                    )
                else:
                    next_hop = f"172.20.{rng.randrange(4)}.{rng.randrange(1, 255)}"
                kind = "STATIC_ROUTE" if rng.random() < 0.15 else "LEARNED_ROUTE"
                protocol = "static" if kind == "STATIC_ROUTE" else rng.choice(("bgp", "ospf"))
                interface = rng.choice(("eth0", "eth1", None))
                if rng.random() < 0.4:
                    graph.append(
                        _graph_row(
                            context, prefix, next_hop, kind=kind, protocol=protocol, interface=interface
                        )
                    )
                    if rng.random() < 0.3:
                        side.append(_rib_row(prefix, next_hop, protocol=protocol, interface="eth9"))
                else:
                    side.append(_rib_row(prefix, next_hop, protocol=protocol, interface=interface))
        rng.shuffle(side)
        rib[(device_of[context], context)] = side
    graph.sort(key=lambda r: (r["prefix"], r["context_uid"]))
    vrf_devices = [_vd(c, device_of[c], c.rsplit(":", 1)[1]) for c in contexts]
    rng.shuffle(vrf_devices)
    site_filter = rng.choice((None, None, ["HQ"], ["dc1", "nowhere"]))
    return Case(
        graph=graph,
        intents=[rng.choice((DENY_TO, DENY_FROM, DENY_BOTH))],
        vrf_devices=vrf_devices,
        rib=rib if rng.random() < 0.8 else None,
        sites=_SITE_ROWS,
        vrf_sites=[
            {"context_uid": contexts[0], "site_uids": ["site:hq"]},
            {"context_uid": contexts[1], "site_uids": ["site:hq"]},
            {"context_uid": contexts[2], "site_uids": ["site:dc1"]},
        ],
        flows=rng.choice((None, [{"src": "10.0.0.5", "dst": "10.1.1.1"}])),
        depth=rng.choice((None, 1, 2, 3, 5, 8, 12)),
        site_filter=site_filter,
        detail=rng.random() < 0.3,
    )


CASES: dict[str, Callable[[], Case]] = {
    "chain-default-depth": lambda: _chain_case(None),
    "chain-depth-4": lambda: _chain_case(4),
    "chain-depth-cap": lambda: _chain_case(12),
    "merge": _merge_case,
    "odd-prefixes": _odd_case,
    "sites-none": lambda: _sites_case(None, 2),
    "sites-hq": lambda: _sites_case(["HQ"], 2),
    "sites-not-found": lambda: _sites_case(["dc1", "Nowhere"], 3),
    "wide-pane": lambda: _wide_case(False),
    "wide-detail": lambda: _wide_case(True),
    "direction-to": lambda: _direction_case(DENY_TO),
    "direction-from": lambda: _direction_case(DENY_FROM),
    "direction-both": lambda: _direction_case(DENY_BOTH),
    **{f"generated-{seed}": (lambda seed=seed: _random_case(seed)) for seed in range(1, 9)},
}


def run_case(case: Case, rib: Any = None) -> dict[str, Any]:
    """`simulate_change` over `case`, with `hst.path`'s read and trace
    replaced for the call. `rib` replaces the case's own FakeRib."""
    from hst import path as pathmod
    from hst.app import fw_overlay_read

    answers = {
        fw_overlay_read._LEARNED_NEXT_HOPS: case.graph,
        fw_overlay_read._VRF_DEVICES: case.vrf_devices,
        fw_overlay_read._SITES: case.sites,
        fw_overlay_read._VRF_SITES: case.vrf_sites,
        fw_overlay_read._BGP_PEERS: case.peers,
    }

    def read(session: Any, query: str, **params: Any) -> list[dict[str, Any]]:
        routed = answer_route_reads(case.graph, query, params)
        if routed is not None:
            return routed
        return [dict(row) for row in answers.get(query, ())]

    def trace(
        session: Any, src: str, dst: str, port: Any = None, proto: str = "tcp", rib: Any = None, **kw: Any
    ) -> dict[str, Any]:
        overlaid = isinstance(session, fw_overlay_read.OverlaySession)
        return {
            "verdict": f"blocked {src}->{dst}" if overlaid else f"permitted {src}->{dst}",
            "indeterminate": False,
            "warnings": [],
            "legs": [{"firewall": "LAN drop by rule 10", "blocked": overlaid}],
            "hops": [{"kind": "Device", "uid": "dev:x:r1"}],
        }

    if rib is None and case.rib is not None:
        rib = FakeRib(case.rib)
    saved = pathmod._read, pathmod.trace
    pathmod._read, pathmod.trace = read, trace  # type: ignore[assignment]
    try:
        return fw_overlay_read.simulate_change(
            object(),
            intents=case.intents,
            flows=case.flows,
            depth=case.depth,
            sites=case.site_filter,
            detail=case.detail,
            rib=rib,
        )
    finally:
        pathmod._read, pathmod.trace = saved  # type: ignore[assignment]


def _recorded_names(value: Any) -> Any:
    """`value` with the flow fields under the names the recorded digests cover."""
    if isinstance(value, list):
        return [_recorded_names(item) for item in value]
    if not isinstance(value, dict):
        return value
    out = {key: _recorded_names(item) for key, item in value.items()}
    if "detail" in out and "result" in out and "blocked" in out:
        out["verdict"] = out.pop("detail")
        del out["result"]
    for new, old in (("result_changed", "verdict_changed"), ("results_changed", "verdicts_changed")):
        if new in out:
            out[old] = out.pop(new)
    # what a flow's comparison basis adds (a flow's `basis_uncertain` fields, the
    # count of flows not established and the model errors that state them)
    for added in ("basis_uncertain", "basis_uncertain_reasons", "results_not_established"):
        out.pop(added, None)
    if isinstance(out.get("model_errors"), list):
        out["model_errors"] = [e for e in out["model_errors"] if e.get("kind") not in BASIS_ERRORS]
    return out


def digest(body: dict[str, Any]) -> str:
    """SHA-256 of the answer as canonical JSON, without the field `REWORDED`,
    with the flow fields under the names the recorded digests cover
    (`_recorded_names`)."""
    body = _recorded_names(body)
    routing = body.get("routing_consequence")
    if isinstance(routing, dict):
        body["routing_consequence"] = {k: v for k, v in routing.items() if k != REWORDED}
    text = json.dumps(body, sort_keys=True, default=str, separators=(",", ":"))
    # The recorded digests cover the module path `strata.simul.`.
    text = text.replace("`hst.simul.", "`strata.simul.")
    return hashlib.sha256(text.encode()).hexdigest()


def summarize(body: dict[str, Any]) -> dict[str, Any]:
    """The fields the golden file holds of one answer: the digest, the
    `REWORDED` text and the counts."""
    routing = body.get("routing_consequence") or {}
    withdrawal = routing.get("next_hop_withdrawal") or {}
    return {
        "digest": digest(body),
        REWORDED: routing.get(REWORDED),
        "recorded_route_count": routing.get("recorded_route_count"),
        "prefix_count": withdrawal.get("prefix_count"),
        "levels_walked": (routing.get("walk") or {}).get("levels_walked"),
    }


def answer_route_reads(
    graph: list[dict[str, Any]], query: str, params: dict[str, Any]
) -> list[dict[str, Any]] | None:
    """What the graph's route-edge reads answer over `graph`, honoring the
    parameters as the queries do: `_NEXT_HOP_VALUES` and `_ROUTE_CONTEXTS`
    the distinct next hops and contexts, `_LEARNED_NEXT_HOPS` every route of each (context,
    prefix) that holds a hit (or of `$context`, or of `$prefixes`). `None`
    for any other query."""
    from hst.app import fw_overlay_read

    if query == fw_overlay_read._NEXT_HOP_VALUES:
        return [{"next_hop": h} for h in sorted({str(r["next_hop"]) for r in graph if r.get("next_hop")})]
    if query == fw_overlay_read._ROUTE_CONTEXTS:
        return [
            {"context_uid": c} for c in sorted({str(r["context_uid"]) for r in graph if r.get("context_uid")})
        ]
    if query == fw_overlay_read._LEARNED_NEXT_HOPS:
        hits, context, prefixes = params.get("hits"), params.get("context"), params.get("prefixes")
        kept = {
            (r.get("context_uid"), r.get("prefix"))
            for r in graph
            if (hits is None or r.get("next_hop") in hits)
            and (context is None or r.get("context_uid") == context)
            and (prefixes is None or r.get("prefix") in prefixes)
        }
        return [dict(r) for r in graph if (r.get("context_uid"), r.get("prefix")) in kept]
    return None
