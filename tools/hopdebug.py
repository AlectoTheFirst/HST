"""SD-WAN trace debug: one subnet-to-subnet trace and the graph data behind it.

Runs the same `GET /api/path` call the trace page makes and reports:

- the run the answer came from, the verdict, the warnings and the notes;
- where the lanes come from: the SD-WAN rule and candidate count at each
  forwarding boundary, the subnet split, the tunnels and ECMP next hops, the
  carrier verdict of each leg, and the device path of each lane;
- every lane that holds hops of more than one tunnel, hop by hop.

Read-only Cypher queries (`POST /api/cypher`, needs `cypher.run`) then report
the graph data the SD-WAN gate reads (`path/gates/sdwan.py`): the forwarding
boundaries of the branch and its hubs, the branch tunnels and every device that
holds each far address, the direct exits, the hub LAN prefixes, the hub tunnel
counts, the hub BGP sessions and the BGP neighbors the collector dropped. The
hubs are the ones the branch tunnels end on, or the one --hub names.

Last, `GET /api/explore/routes` lists the routes of the branch and of each hub
that cover the destination: the overlay route table (OFC) rows the collector
writes on the edge that advertises a prefix, longest prefix first.

The report is printed and written to hopdebug-<time>.txt, and the raw trace to
hopdebug-<time>.json, in the current directory (--out changes the prefix).

Standard library only, Python 3.10 or later:

    python3 tools/hopdebug.py --url https://hst.example.net --user ada \\
        BR-0421 10.20.30.0/24 10.1.0.0/16 --port 443

The password is read from HST_PASSWORD or asked for. With SSO, pass the
`hst_session` cookie value from the browser in HST_SESSION_COOKIE or with --cookie.
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

COOKIE = "hst_session"

# Every query is pinned to the current snapshot: /api/cypher binds $snap.
# `$hubs` is the hub list; empty means every device with sdwan_role 'hub'.
_HUB_FILTER = "(h.hostname IN $hubs OR (size($hubs) = 0 AND h.sdwan_role = 'hub'))"

_BOUNDARIES = """
MATCH (d:Device)-[:HAS_BOUNDARY]->(fb:ForwardingBoundary)-[:IN]->(seg:SdwanSegment)
WHERE (d.hostname = $branch OR d.hostname IN $hubs)
  AND NOT fb:Retired AND coalesce(fb.collection_ts, $snap) = $snap
RETURN d.hostname AS device, d.sdwan_role AS role, d.platform AS platform, seg.name AS segment,
       seg.segment_id AS segment_id, fb.candidate_set_complete AS complete,
       fb.unsupported_reason AS reason, fb.gaps AS gaps
ORDER BY device, segment"""

_BRANCH_TUNNELS = """
MATCH (d:Device {hostname: $branch})<-[:ON]-(wif:Interface)<-[:ENDPOINT]-(t:Tunnel)
      -[:CARRIES]->(seg:SdwanSegment)
WHERE NOT t:Retired AND coalesce(t.collection_ts, $snap) = $snap
OPTIONAL MATCH (t)-[:TERMINATES_ON]->(far)
OPTIONAL MATCH (far)<-[:HAS_IP]-(x)-[:ON*1..2]->(fd:Device)
WHERE x:Interface OR x:WanLink
RETURN seg.name AS segment, t.name AS tunnel, wif.name AS wan_if, t.peer_type AS peer_type,
       CASE WHEN far:SdwanGateway THEN 'gateway' WHEN far:IpAddress THEN 'address' ELSE null END
         AS far_kind,
       coalesce(far.ip, far.name) AS far, collect(DISTINCT fd.hostname) AS far_devices,
       collect(DISTINCT fd.sdwan_role) AS far_roles
ORDER BY segment, tunnel"""

_FAR_HOLDERS = """
MATCH (d:Device {hostname: $branch})<-[:ON]-(:Interface)<-[:ENDPOINT]-(t:Tunnel)
      -[:TERMINATES_ON]->(far:IpAddress)
WHERE NOT t:Retired AND coalesce(t.collection_ts, $snap) = $snap
MATCH (other:IpAddress)<-[:HAS_IP]-(x)-[:ON*1..2]->(fd:Device)
WHERE other.ip = far.ip AND (x:Interface OR x:WanLink)
  AND NOT other:Retired AND NOT x:Retired AND NOT fd:Retired
RETURN far.ip AS far_ip, t.name AS tunnel, fd.hostname AS holder, labels(x)[0] AS held_by,
       other.uid = far.uid AS is_tunnel_far_end, other.uid AS address_uid
ORDER BY far_ip, tunnel, holder"""

_DIRECT_EXITS = """
MATCH (:Device {hostname: $branch})-[:ENFORCES]->(:SdwanBusinessPolicy)-[sv:STEERS_VIA]->(w:WanLink)
WHERE sv.route_policy = 'direct' AND NOT w:Retired
OPTIONAL MATCH (w)-[:ON]->(wif:Interface)
RETURN w.name AS link, w.kind AS kind, wif.name AS wan_if, wif.next_hop AS next_hop,
       collect(DISTINCT sv.application_class) AS rules"""

_HUB_PREFIXES = f"""
MATCH (h:Device)<-[:OWNED_BY]-(v:VrfInstance)-[:ORIGINATES]->(p:Prefix)
WHERE {_HUB_FILTER} AND NOT p:Retired AND coalesce(p.collection_ts, $snap) = $snap
RETURN h.hostname AS hub, h.platform AS platform, v.name AS vrf, v.table_id AS table_id,
       collect(DISTINCT p.cidr) AS prefixes
ORDER BY hub, vrf"""

_HUB_TUNNELS = f"""
MATCH (h:Device)<-[:ON]-(:Interface)<-[:ENDPOINT]-(t:Tunnel)
WHERE {_HUB_FILTER} AND NOT t:Retired AND coalesce(t.collection_ts, $snap) = $snap
OPTIONAL MATCH (t)-[:TERMINATES_ON]->(far)
RETURN h.hostname AS hub, t.peer_type AS peer_type,
       CASE WHEN far:SdwanGateway THEN 'gateway' WHEN far:IpAddress THEN 'address' ELSE 'none' END
         AS far_kind,
       count(DISTINCT t) AS tunnels
ORDER BY hub, peer_type, far_kind"""

_HUB_BGP = f"""
MATCH (h:Device)<-[:OWNED_BY]-(v:VrfInstance)<-[:IN_VRF]-(:RoutingProcess)-[:HAS]->(s:BgpSession)
WHERE {_HUB_FILTER} AND NOT s:Retired AND coalesce(s.collection_ts, $snap) = $snap
RETURN h.hostname AS hub, v.name AS vrf, count(DISTINCT s) AS sessions
ORDER BY hub, vrf"""

_HUB_BGP_SESSIONS = f"""
MATCH (h:Device)<-[:OWNED_BY]-(v:VrfInstance)<-[:IN_VRF]-(:RoutingProcess)-[:HAS]->(s:BgpSession)
WHERE {_HUB_FILTER} AND NOT s:Retired AND coalesce(s.collection_ts, $snap) = $snap
RETURN h.hostname AS hub, v.name AS vrf, s.peer_ip AS peer, s.peer_asn AS peer_asn,
       s.local_ip AS local_ip, s.description AS tag
ORDER BY hub, vrf, peer"""

# `_bgp` in collectors/velocloud.py records a neighbor it drops as a gap on the
# edge's ForwardingBoundary
_HUB_BGP_GAPS = f"""
MATCH (h:Device)-[:HAS_BOUNDARY]->(fb:ForwardingBoundary)
WHERE {_HUB_FILTER} AND NOT fb:Retired AND coalesce(fb.collection_ts, $snap) = $snap
UNWIND coalesce(fb.gaps, []) AS gap
WITH h, gap WHERE gap CONTAINS 'bgp'
RETURN DISTINCT h.hostname AS hub, gap
ORDER BY hub, gap"""


# `_edge_tunnel` in collectors/velocloud.py keys a Tunnel by the two link
# logicalIds alone, so two devices with the same logicalId share one Tunnel node
_LINK_IDS = """
MATCH (d:Device)-[:HAS_LINK]->(w:WanLink)
WHERE (d.hostname = $branch OR d.hostname IN $hubs)
  AND NOT w:Retired AND coalesce(w.collection_ts, $snap) = $snap
RETURN w.link_logical_id AS logical_id, d.hostname AS device, w.name AS link, w.interface AS interface,
       w.kind AS kind, w.public_ip AS public_ip
ORDER BY logical_id, device"""

_SHARED_LINK_IDS = """
MATCH (d:Device)-[:HAS_LINK]->(w:WanLink)
WHERE NOT w:Retired AND coalesce(w.collection_ts, $snap) = $snap AND w.link_logical_id IS NOT NULL
WITH w.link_logical_id AS logical_id, collect(DISTINCT d.hostname) AS devices
WHERE size(devices) > 1
RETURN logical_id, size(devices) AS device_count, devices[..10] AS first_devices
ORDER BY device_count DESC, logical_id LIMIT 50"""

_MULTI_FAR_TUNNELS = """
MATCH (t:Tunnel)-[:TERMINATES_ON]->(far)
WHERE NOT t:Retired AND coalesce(t.collection_ts, $snap) = $snap
WITH t, count(DISTINCT far) AS far_ends
WHERE far_ends > 1
RETURN t.encap AS encap, count(t) AS tunnels, max(far_ends) AS most_far_ends
ORDER BY tunnels DESC"""


_DEVICE_UIDS = """
MATCH (d:Device)
WHERE (d.hostname = $branch OR d.hostname IN $hubs)
  AND NOT d:Retired AND coalesce(d.collection_ts, $snap) = $snap
RETURN d.hostname AS device, d.uid AS uid
ORDER BY device"""


class Tee:
    """Write to the terminal and to the report file."""

    def __init__(self, *streams: Any) -> None:
        self.streams = streams

    def write(self, text: str) -> None:
        for s in self.streams:
            s.write(text)

    def flush(self) -> None:
        for s in self.streams:
            s.flush()


class Client:
    """A session-cookie client for the HST API."""

    def __init__(self, url: str, *, insecure: bool) -> None:
        self.url = url.rstrip("/")
        self.cookie: str | None = None
        self.ctx = ssl._create_unverified_context() if insecure else None  # noqa: S323 - only with --insecure

    def _send(self, req: urllib.request.Request) -> tuple[int, Any, Any]:
        # app/main.py csrf_guard refuses a POST without it
        req.add_header("X-HST-CSRF", "1")
        if self.cookie:
            req.add_header("Cookie", f"{COOKIE}={self.cookie}")
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=600) as resp:  # noqa: S310 - base_url() admits only http and https
                return resp.status, resp.headers, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as exc:
            body = exc.read()
            try:
                detail = json.loads(body)
            except ValueError:
                detail = body.decode(errors="replace")
            return exc.code, exc.headers, detail

    def login(self, user: str, password: str) -> None:
        req = urllib.request.Request(  # noqa: S310 - base_url() admits only http and https
            f"{self.url}/api/login",
            data=json.dumps({"username": user, "password": password}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        status, headers, body = self._send(req)
        if status != 200:
            sys.exit(f"login failed: HTTP {status}: {body}")
        # a cookie jar drops a Secure cookie on plain http
        for raw in headers.get_all("Set-Cookie") or []:
            name, _, rest = raw.partition("=")
            if name.strip() == COOKIE:
                self.cookie = rest.split(";", 1)[0]
        if not self.cookie:
            sys.exit(f"login returned no {COOKIE} cookie")

    def get(self, path: str, params: dict[str, str]) -> tuple[int, Any]:
        req = urllib.request.Request(f"{self.url}{path}?{urllib.parse.urlencode(params)}")  # noqa: S310 - base_url() admits only http and https
        status, _, body = self._send(req)
        return status, body

    def cypher(self, query: str, params: dict[str, Any]) -> tuple[int, Any]:
        req = urllib.request.Request(  # noqa: S310 - base_url() admits only http and https
            f"{self.url}/api/cypher",
            data=json.dumps({"query": query, "params": params}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        status, _, body = self._send(req)
        return status, body


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def table(columns: list[str], rows: list[list[Any]]) -> None:
    """Print rows as aligned columns; lists and objects as compact JSON."""
    cells = [
        ["" if c is None else c if isinstance(c, str) else json.dumps(c, separators=(",", ":")) for c in row]
        for row in rows
    ]
    widths = [max(len(str(x)) for x in col) for col in zip(columns, *cells, strict=False)]
    for row in [columns, *cells]:
        print("  ".join(str(x).ljust(w) for x, w in zip(row, widths, strict=False)).rstrip())
    if not rows:
        print("(no rows)")


def counted(items: list[str]) -> None:
    """Print each distinct item once, with how often it occurs."""
    counts = Counter(items)
    if not counts:
        print("(none)")
    for text, n in counts.most_common():
        print(f"{n:>5}  {text}")


def _lane_hops(hops: list[dict[str, Any]]) -> dict[Any, list[dict[str, Any]]]:
    """Hops for each lane, in diagram column order."""
    by_lane: dict[Any, list[tuple[int, int, dict[str, Any]]]] = defaultdict(list)
    for i, h in enumerate(hops):
        by_lane[h.get("lane")].append((h.get("rank", i), i, h))
    return {lane: [h for _, _, h in sorted(rows, key=lambda r: r[:2])] for lane, rows in by_lane.items()}


def report_trace(trace: dict[str, Any]) -> None:
    hops: list[dict[str, Any]] = trace.get("hops") or []
    legs: list[dict[str, Any]] = trace.get("legs") or []
    lanes = _lane_hops(hops)

    section("1. Run, verdict, legs and lanes")
    run = trace.get("run") or {}
    print(f"snapshot: {run.get('snapshot')}  created: {run.get('created')}  degraded: {run.get('degraded')}")
    if run.get("sources_carried"):
        print(f"sources carried from an earlier run: {', '.join(run['sources_carried'])}")
    print(f"verdict: {trace.get('verdict')}")
    print(f"legs: {len(legs)}  lanes: {len(lanes)}  hops: {len(hops)}")

    section("2. SD-WAN rule and candidate count (branch and hub)")
    counted([h.get("note") or "" for h in hops if h.get("kind") == "ForwardingBoundary"])

    section("3. Legs for each source part and destination part (subnet split)")
    split = Counter((leg.get("src_label") or "-", leg.get("dst_label") or "-") for leg in legs)
    table(["legs", "src part", "dst part"], [[str(n), s, d] for (s, d), n in sorted(split.items())])

    section("4. Different tunnels and ECMP next hops across all lanes")
    for kind in ("Tunnel", "NextHop", "Device"):
        print(f"{kind}: {len({h.get('uid') for h in hops if h.get('kind') == kind})}")
    counted([h.get("label") or "" for h in hops if h.get("kind") == "Tunnel"])

    section("5. Carrier verdict for each leg")
    counted([(leg.get("carrier") or {}).get("verdict") for leg in legs if leg.get("carrier")])

    section("6. Leg outcome")
    counted(
        [
            ", ".join(k for k in ("blocked", "indeterminate", "boundary", "candidate_set") if leg.get(k))
            or "delivered"
            for leg in legs
        ]
    )

    section("7. Device path of each lane (identical paths counted once)")
    paths = []
    for lane_hops in lanes.values():
        steps = []
        for h in lane_hops:
            if h.get("kind") == "Device":
                step = h.get("label") or h.get("uid") or "?"
            elif h.get("kind") == "Tunnel":
                step = f"[{h.get('label')}: {h.get('note')}]"
            else:
                continue
            if not steps or steps[-1] != step:
                steps.append(step)
        paths.append(" > ".join(steps) or "(no device hop)")
    counted(paths)

    section("8. Lanes with hops of more than one tunnel (must be empty)")
    mixed = []
    for lane, lane_hops in lanes.items():
        tunnels = {h.get("label") or h.get("uid") for h in lane_hops if h.get("kind") == "Tunnel"}
        carriers = {h["tunnel"] for h in lane_hops if h.get("tunnel")}
        if len(tunnels) > 1 or len(carriers) > 1:
            mixed.append(lane)
    print(f"{len(mixed)} lane(s): {mixed}" if mixed else "(none)")
    for lane in mixed[:5]:
        print(f"\n--- lane {lane}, hop by hop ---")
        table(
            ["rank", "stage", "kind", "label", "note", "carrier"],
            [
                [
                    str(h.get("rank")),
                    h.get("stage"),
                    h.get("kind"),
                    h.get("label"),
                    h.get("note"),
                    h.get("tunnel"),
                ]
                for h in lanes[lane]
            ],
        )
    if len(mixed) > 5:
        print(f"\n(the other {len(mixed) - 5} lane(s) are in the raw trace JSON)")

    section("9. Warnings")
    counted(list(trace.get("warnings") or []))

    section("10. Notes")
    counted(list(trace.get("notes") or []))


def run_query(client: Client, title: str, query: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    """Run one query, print it as a table, and return its rows as dicts."""
    section(title)
    status, body = client.cypher(query, params)
    if status != 200:
        print(f"error: HTTP {status}: {body}")
        return []
    columns = body.get("columns") or []
    rows = [r.get("row") or [] for r in body.get("data") or []]
    table(columns, rows)
    if body.get("truncated"):
        print(f"warning: the API cut this result at {len(rows)} rows; --hub narrows it")
    return [dict(zip(columns, row, strict=False)) for row in rows]


def _probe_address(dst: str) -> str:
    """The address the route sections look up: the destination itself, or the
    first address of a destination network."""
    return str(ipaddress.ip_network(dst.strip(), strict=False).network_address)


def report_routes(client: Client, params: dict[str, Any], dst: str) -> None:
    """The routes of the branch and of each hub that cover the destination,
    from the side store the trace reads (`GET /api/explore/routes`)."""
    address = _probe_address(dst)
    section(f"23. Routes that cover {address} on the branch and each hub (overlay route table)")
    status, body = client.cypher(_DEVICE_UIDS, params)
    if status != 200:
        print(f"error: HTTP {status}: {body}")
        return
    devices = [(r["row"][0], r["row"][1]) for r in body.get("data") or []]
    best: list[list[Any]] = []
    for name, dev_uid in devices:
        status, page = client.get("/api/explore/routes", {"uid": dev_uid, "address": address, "limit": "50"})
        print(f"\n--- {name} ---")
        if status != 200:
            print(f"error: HTTP {status}: {page}")
            continue
        items = page.get("items") or []
        print(
            f"available: {page.get('available')}  coverage: {page.get('coverage')}  "
            f"approximate: {page.get('approximate')}  covering routes: {page.get('total')}"
        )
        columns = list(dict.fromkeys(k for item in items for k in item))
        table(columns, [[item.get(c) for c in columns] for item in items])
        if items:
            top = items[0]
            best.append(
                [
                    name,
                    top.get("vrf"),
                    top.get("prefix"),
                    top.get("protocol"),
                    top.get("metric"),
                    top.get("next_hop"),
                    top.get("interface"),
                    str(len(items)),
                ]
            )
    print(f"\n--- longest covering route of each device for {address} ---")
    table(["device", "vrf", "prefix", "protocol", "metric", "next_hop", "interface", "routes"], best)


def report_graph(client: Client, branch: str, hub: str | None, dst: str) -> None:
    params: dict[str, Any] = {"branch": branch, "hubs": [hub] if hub else []}
    tunnels = run_query(
        client, f"11. Tunnels of {branch}, with the far end and its devices", _BRANCH_TUNNELS, params
    )
    if not hub:
        # the hubs this branch's tunnels end on; none found means every hub
        params["hubs"] = sorted(
            {
                dev
                for row in tunnels
                if "hub" in (row.get("far_roles") or [])
                for dev in row.get("far_devices") or []
                if dev
            }
        )
    hubs = ", ".join(params["hubs"]) or "every hub"
    print(f"\nhubs for the sections below: {hubs}")

    run_query(client, f"12. Forwarding boundaries of {branch} and {hubs}", _BOUNDARIES, params)
    run_query(client, f"13. Every device that holds a far address of a {branch} tunnel", _FAR_HOLDERS, params)
    run_query(client, f"14. Direct exits of {branch}", _DIRECT_EXITS, params)
    run_query(client, f"15. LAN prefixes of {hubs} (SD-WAN rule 1)", _HUB_PREFIXES, params)
    run_query(client, f"16. Tunnel count on {hubs}", _HUB_TUNNELS, params)
    run_query(client, f"17. BGP session count on {hubs} for each VRF", _HUB_BGP, params)
    run_query(client, f"18. Every BGP session on {hubs}", _HUB_BGP_SESSIONS, params)
    run_query(client, f"19. BGP neighbors the collector dropped on {hubs}", _HUB_BGP_GAPS, params)
    run_query(client, f"20. WAN links of {branch} and {hubs}, by logicalId", _LINK_IDS, params)
    run_query(
        client,
        "21. WAN link logicalIds held by more than one device (must be empty)",
        _SHARED_LINK_IDS,
        params,
    )
    run_query(client, "22. Tunnels with more than one far end (must be empty)", _MULTI_FAR_TUNNELS, params)
    report_routes(client, params, dst)


def base_url(value: str) -> str:
    if urllib.parse.urlsplit(value).scheme not in ("http", "https"):
        raise argparse.ArgumentTypeError("the scheme must be http or https")
    return value


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("branch", help="hostname of the SD-WAN branch edge")
    ap.add_argument("src", help="source subnet or address, as typed on the trace page")
    ap.add_argument("dst", help="destination subnet or address, as typed on the trace page")
    ap.add_argument("--url", required=True, type=base_url, help="HST base URL, e.g. https://hst.example.net")
    ap.add_argument("--user", help="username for the password login")
    ap.add_argument(
        "--cookie", help=f"{COOKIE} cookie value from the browser for SSO (default: HST_SESSION_COOKIE)"
    )
    ap.add_argument("--port", help="destination port or range")
    ap.add_argument("--proto", default="tcp")
    ap.add_argument("--hub", help="report on this hub only (default: the hubs the branch tunnels end on)")
    ap.add_argument("--insecure", action="store_true", help="do not check the TLS certificate")
    ap.add_argument("--out", default=f"hopdebug-{time.strftime('%Y%m%d-%H%M%S')}", help="output file prefix")
    args = ap.parse_args(argv)

    client = Client(args.url, insecure=args.insecure)
    cookie = args.cookie or os.environ.get("HST_SESSION_COOKIE")
    if cookie:
        client.cookie = cookie
    elif args.user:
        password = os.environ.get("HST_PASSWORD") or getpass.getpass(f"Password for {args.user}: ")
        client.login(args.user, password)
    else:
        ap.error("give --user, --cookie or HST_SESSION_COOKIE")

    report_path, trace_path = f"{args.out}.txt", f"{args.out}.json"
    terminal = sys.stdout
    with Path(report_path).open("w") as report:
        sys.stdout = Tee(terminal, report)
        try:
            params = {"src": args.src, "dst": args.dst, "proto": args.proto}
            if args.port:
                params["port"] = args.port
            print(f"hopdebug {time.strftime('%Y-%m-%d %H:%M:%S')}  {args.url}")
            print(f"branch {args.branch}  {args.src} -> {args.dst}  {args.proto} {args.port or ''}")
            status, trace = client.get("/api/path", params)
            if status != 200:
                print(f"trace failed: HTTP {status}: {trace}")
            else:
                with Path(trace_path).open("w") as fh:
                    json.dump(trace, fh, indent=2)
                report_trace(trace)
            report_graph(client, args.branch, args.hub, args.dst)
        finally:
            sys.stdout = terminal
    print(f"\nreport: {report_path}")
    if status == 200:
        print(f"raw trace: {trace_path}")
    return 0 if status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
