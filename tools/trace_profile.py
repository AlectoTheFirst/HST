"""Read-only trace profiler. Piped into an app pod: python - < trace_profile.py

Times every Neo4j round trip (client wall time and the server's own
available/consumed times), every side-store lookup, and the rest of the
trace as Python time. Prints aggregates only; no addresses.
"""

from __future__ import annotations

import collections
import cProfile
import io
import os
import pstats
import random
import re
import sys
import time

import hst.path as P
import hst.path.session as PS
from hst.core import db, ribsource
from hst.core import snapshot as snapmod
from hst.core.config import Settings

N_PAIRS = int(os.environ.get("N_PAIRS", "40"))
SEED = 7


class Stats:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.neo_wall = 0.0
        self.neo_server = 0.0
        self.neo_calls = 0
        self.read_calls = 0
        self.side_wall = 0.0
        self.side_calls = 0
        self.per_query = collections.defaultdict(lambda: [0, 0.0, 0.0, 0])  # calls, wall, server, rows
        self.per_side = collections.defaultdict(lambda: [0, 0.0])


ST = Stats()

# name each query by the module constant whose text it is
NAMES: dict[str, str] = {}
for mname, mod in list(sys.modules.items()):
    if not mname.startswith("hst."):
        continue
    for k, v in list(vars(mod).items()):
        if isinstance(v, str) and "MATCH" in v and len(v) > 30:
            NAMES.setdefault(v, f"{mname.rsplit('.', 1)[-1]}.{k}")


def qname(q: str) -> str:
    if q in NAMES:
        return NAMES[q]
    head = re.sub(r"\s+", " ", q).strip()[:70]
    return "dyn:" + head


class _Res:
    def __init__(self, r, q):
        self._r, self._q = r, q

    def data(self):
        d = self._r.data()
        s = self._r.consume()
        server = ((s.result_available_after or 0) + (s.result_consumed_after or 0)) / 1000.0
        ST.neo_server += server
        rec = ST.per_query[qname(self._q)]
        rec[2] += server
        rec[3] += len(d)
        return d

    def __getattr__(self, a):
        return getattr(self._r, a)


class _Tx:
    def __init__(self, tx):
        self._tx = tx

    def run(self, q, **p):
        return _Res(self._tx.run(q, **p), q)

    def __getattr__(self, a):
        return getattr(self._tx, a)


_orig_exec = PS.CycleSession.execute_read
_cur_query: list[str] = [""]


def timed_exec(self, work, /):
    t = time.perf_counter()
    try:
        return _orig_exec(self, lambda tx: work(_Tx(tx)))
    finally:
        dt = time.perf_counter() - t
        ST.neo_wall += dt
        ST.neo_calls += 1
        rec = ST.per_query[qname(_cur_query[0])]
        rec[0] += 1
        rec[1] += dt


PS.CycleSession.execute_read = timed_exec

_orig_read = PS._read


def counted_read(session, query, **params):
    ST.read_calls += 1
    _cur_query[0] = query
    return _orig_read(session, query, **params)


for mod in list(sys.modules.values()):
    if getattr(mod, "__name__", "").startswith("hst.") and getattr(mod, "_read", None) is _orig_read:
        mod._read = counted_read

for meth in ("lpm", "overlapping"):
    orig = getattr(ribsource.RibSource, meth)

    def wrap(self, *a, _o=orig, _m=meth, **k):
        t = time.perf_counter()
        try:
            return _o(self, *a, **k)
        finally:
            dt = time.perf_counter() - t
            ST.side_wall += dt
            ST.side_calls += 1
            ST.per_side[_m][0] += 1
            ST.per_side[_m][1] += dt

    setattr(ribsource.RibSource, meth, wrap)


def pick_pairs(s, snap) -> list[tuple[str, str]]:
    rows = s.run(
        "MATCH (o)-[:HAS_IP]->(ip:IpAddress) "
        "WHERE (o:Interface OR o:Endpoint) AND coalesce(ip.collection_ts,$snap)=$snap AND ip.af = 4 "
        "OPTIONAL MATCH (o)-[:ON]->(d:Device) "
        "RETURN DISTINCT ip.ip AS ip, labels(o)[0] AS kind, d.uid AS dev",
        snap=snap.cts,
    ).data()
    rnd = random.Random(SEED)  # noqa: S311 - picks the sample address pairs of the profile run
    ips = [r for r in rows if r["ip"] and not r["ip"].startswith("127.")]
    rnd.shuffle(ips)
    pairs = []
    for a, b in zip(ips[0::2], ips[1::2], strict=False):
        if a["dev"] is not None and a["dev"] == b["dev"]:
            continue
        pairs.append((a["ip"], b["ip"]))
        if len(pairs) >= N_PAIRS:
            break
    return pairs, len(ips)


def counts(s, snap) -> dict:
    def q(c):
        return s.run(c, snap=snap.cts).single()[0]

    return {
        "devices": q("MATCH (d:Device) WHERE d.collection_ts=$snap RETURN count(d)"),
        "nodes": q("MATCH (n:Obj) WHERE n.collection_ts=$snap RETURN count(n)"),
        "rels": q("MATCH ()-[r]->() WHERE r.collection_ts=$snap RETURN count(r)"),
        "vrfs": q("MATCH (v:VrfInstance) WHERE v.collection_ts=$snap RETURN count(v)"),
        "fw_rules": q("MATCH (r:FwRule) WHERE r.collection_ts=$snap RETURN count(r)"),
        "graph_routes": q(
            "MATCH ()-[r:LEARNED_ROUTE|STATIC_ROUTE]->() WHERE r.collection_ts=$snap RETURN count(r)"
        ),
    }


def one(s, snap, src, dst, port, proto) -> dict:
    ST.reset()
    t = time.perf_counter()
    err = None
    try:
        res = P.trace(P.pinned(s, snap), src, dst, port=port, proto=proto, rib=ribsource.for_snapshot(snap))
    except Exception as exc:
        res, err = {}, type(exc).__name__
    total = time.perf_counter() - t
    return {
        "total": total,
        "neo_wall": ST.neo_wall,
        "neo_server": ST.neo_server,
        "neo_calls": ST.neo_calls,
        "reads": ST.read_calls,
        "side": ST.side_wall,
        "side_calls": ST.side_calls,
        "hops": len(res.get("hops", []) or []),
        "legs": len(res.get("legs", []) or []),
        "devices": len({h.get("uid") for h in res.get("hops", []) or [] if h.get("kind") == "Device"}),
        "err": err,
        "per_query": {k: list(v) for k, v in ST.per_query.items()},
        "per_side": {k: list(v) for k, v in ST.per_side.items()},
    }


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, round(p / 100 * (len(xs) - 1)))] if xs else 0.0


def report(label, results):
    ok = [r for r in results if not r["err"]]
    print(f"\n### {label}: {len(results)} traces, {len(results) - len(ok)} errors")
    if not ok:
        return
    T = sum(r["total"] for r in ok)
    NW = sum(r["neo_wall"] for r in ok)
    NS = sum(r["neo_server"] for r in ok)
    SD = sum(r["side"] for r in ok)
    tot = [r["total"] for r in ok]
    print(
        f"trace wall s: p50 {pct(tot, 50):.3f}  p90 {pct(tot, 90):.3f}"
        f"  max {max(tot):.3f}  mean {T / len(ok):.3f}"
    )
    print(
        f"share of total: neo4j round trips {NW / T:6.1%} (of which server-reported {NS / T:6.1%}),"
        f" side store {SD / T:6.1%}, python {1 - (NW + SD) / T:6.1%}"
    )
    for key in ("reads", "neo_calls", "side_calls", "hops", "devices", "legs"):
        xs = [r[key] for r in ok]
        print(f"  {key:10s} p50 {pct(xs, 50):6.0f}  p90 {pct(xs, 90):6.0f}  max {max(xs):6.0f}")
    dev = [r["neo_calls"] / r["devices"] for r in ok if r["devices"]]
    if dev:
        print(f"  neo4j round trips per device visited: p50 {pct(dev, 50):.1f}  p90 {pct(dev, 90):.1f}")
    hit = sum(r["reads"] - r["neo_calls"] for r in ok) / max(1, sum(r["reads"] for r in ok))
    print(f"  read-cache hit rate {hit:.1%}")
    agg = collections.defaultdict(lambda: [0, 0.0, 0.0, 0])
    for r in ok:
        for k, v in r["per_query"].items():
            for i in range(4):
                agg[k][i] += v[i]
    print("  top queries by client wall time: calls, wall s, server s, rows")
    for k, v in sorted(agg.items(), key=lambda kv: -kv[1][1])[:15]:
        print(f"    {v[1]:8.3f}s {v[2]:8.3f}s {v[0]:6d} calls {v[3]:8d} rows  {k}")
    sagg = collections.defaultdict(lambda: [0, 0.0])
    for r in ok:
        for k, v in r["per_side"].items():
            sagg[k][0] += v[0]
            sagg[k][1] += v[1]
    for k, v in sagg.items():
        print(f"  side store {k}: {v[0]} calls, {v[1]:.3f}s, {1000 * v[1] / max(1, v[0]):.1f} ms per call")


def main() -> None:
    settings = Settings()
    drv = db.get_driver(settings)
    with drv.session(database=settings.neo4j_database) as s:
        snap = snapmod.resolve(s, settings)
        print(f"snapshot {snap.cts}")
        print("estate", counts(s, snap))
        pairs, n_ips = pick_pairs(s, snap)
        print(f"candidate addresses {n_ips}, pairs {len(pairs)}")

        for src, dst in pairs[:3]:  # warm the Neo4j page cache and imports
            one(s, snap, src, dst, 443, "tcp")

        point = [one(s, snap, a, b, 443, "tcp") for a, b in pairs]
        report("point flow tcp/443", point)
        region = [one(s, snap, a, b, "1-1024", "tcp") for a, b in pairs]
        report("region flow tcp/1-1024", region)

        slow = sorted(range(len(pairs)), key=lambda i: -point[i]["total"])[:3]
        pr = cProfile.Profile()
        pr.enable()
        for i in slow:
            one(s, snap, *pairs[i], 443, "tcp")
        pr.disable()
        buf = io.StringIO()
        pstats.Stats(pr, stream=buf).sort_stats("tottime").print_stats(25)
        print("\n### cProfile, 3 slowest point traces, by own time")
        print("\n".join(line for line in buf.getvalue().splitlines() if line.strip())[:6000])
    drv.close()


main()
