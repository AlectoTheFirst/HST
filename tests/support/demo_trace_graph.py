"""A graph session that answers the reads `hst.path.trace` makes, from a loaded fixture.

`TraceGraph(load_fixture(...))` stands in for the Neo4j session a trace runs on, so
`path.trace(TraceGraph(batch), ...)` runs the real trace engine, every gate included, on
the demo estate without a database. It applies the model of
`tests/support/policy_route_graph.py` (a batch walked in Python, one answer per query
text) to the reads of a trace through a VyOS router.

Each answer is keyed by the exact query text the engine sends, a module constant or the
one string literal of a module that holds a marker (`inline_query`), and returns the rows that
query's Cypher returns: the same columns, the same order, the same filters. Nothing is
filtered by address family unless the Cypher filters by it.

What it does not cover:

- A read with no answer here is recorded in `refused` and raises `UnknownRead`; a read
  that reaches a shape this module does not model (a VSX context, a route-target import,
  an ATTACHED_TO edge, a carried ZIA tunnel) is recorded and raises `NotImplementedError`.
- The reasoner does not run. Of its derived edges only GATEWAY_FOR is written, by the
  rule `gateway-from-router-interface` (reasoner/catalog.py); the sole-firewall and
  sole-segment gateway rules, ATTACHED_TO, L3_ADJACENT and every other derived edge are
  absent.
- No side store: `rib` is None, so no observed-RIB confirmation or gap is read.
- Retirement and the run pin are not modelled: every node is live at one run (`cts`).
"""

from __future__ import annotations

import ast
import importlib
import inspect
import re
from collections.abc import Callable, Iterable
from types import SimpleNamespace
from typing import Any

from hst.core.labels import gate_binding_patterns
from hst.core.model import Batch
from hst.reasoner._constants import GATEWAY_ROLES

_path = importlib.import_module("hst.path")
_trace = importlib.import_module("hst.path.trace")
_session = importlib.import_module("hst.path.session")
_vsx = importlib.import_module("hst.path.vsx")
_gates = importlib.import_module("hst.path.gates")
_nat = importlib.import_module("hst.path.gates.nat")
_pbr = importlib.import_module("hst.path.gates.pbr")
_fw = importlib.import_module("hst.path.gates.firewall")
_local_zone = importlib.import_module("hst.path.gates.local_zone")
_routing = importlib.import_module("hst.path.gates.routing")
_sdwan = importlib.import_module("hst.path.gates.sdwan")
_lb = importlib.import_module("hst.path.gates.lb")
_cpi = importlib.import_module("hst.path.checkpoint_installation")

# labels `_GATE_KIND` leaves out of a gate's kind (path/gates/__init__.py)
_META_LABELS = frozenset(
    {
        "Obj",
        "Latest",
        "Gate",
        "Policy",
        "L3",
        "L2",
        "Phys",
        "Transport",
        "Service",
        "Workload",
        "App",
        "Cloud",
        "Meta",
    }
)
_STEP = re.compile(r"(<-|-)\[e\d+:([A-Z_|]+)\](->|-)\(([a-z]*)(?::([A-Za-z]+))?\)")


class UnknownRead(KeyError):
    """A read the session has no answer for."""


def inline_query(module: Any, marker: str) -> str:
    """The one string literal in `module`'s source that contains `marker`."""
    tree = ast.parse(inspect.getsource(module))
    found = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and marker in node.value
    }
    if len(found) != 1:
        raise LookupError(f"{module.__name__}: {len(found)} literals hold {marker!r}")
    return found.pop()


def _distinct(values: Iterable[Any]) -> list[Any]:
    out: list[Any] = []
    for value in values:
        if value is not None and value not in out:
            out.append(value)
    return out


def _each(items: Iterable[Any]) -> list[Any]:
    """The items, or one None when there are none: the row an OPTIONAL MATCH that finds
    nothing still returns."""
    return list(items) or [None]


def _nulls_last(*values: Any) -> tuple[tuple[bool, Any], ...]:
    """A Cypher ascending ORDER BY key: each value in its own order, nulls after every value.
    A column holds one type, so two values compared are of one type; two nulls are equal."""
    return tuple((v is None, v) for v in values)


class TraceGraph:
    """The session `path._read` runs on, over the nodes and relationships of `source`."""

    cts = 4000

    def __init__(self, source: Batch) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        for node in source.nodes:
            entry = self.nodes.setdefault(node.uid, {"uid": node.uid, "labels": set()})
            entry["labels"].add(node.label)
            entry.update({k: v for k, v in node.props.items() if v is not None})
        # a relationship's properties as the loader stores them: its key, then its props
        self.rels: list[tuple[str, str, str, dict[str, Any]]] = []
        seen: set[tuple[str, str, str, tuple[tuple[str, Any], ...]]] = set()
        for rel in source.rels:
            ident = (rel.rel_type, rel.start_uid, rel.end_uid, tuple(sorted(rel.key.items())))
            if ident in seen:
                continue
            seen.add(ident)
            props = {**rel.key, **{k: v for k, v in rel.props.items() if v is not None}}
            self.rels.append((rel.rel_type, rel.start_uid, rel.end_uid, props))
        self._derive_gateways()
        self._out: dict[str, list[tuple[str, str, dict[str, Any]]]] = {}
        self._in: dict[str, list[tuple[str, str, dict[str, Any]]]] = {}
        for kind, start, end, props in self.rels:
            self._out.setdefault(start, []).append((kind, end, props))
            self._in.setdefault(end, []).append((kind, start, props))
        self._by_label: dict[str, list[str]] = {}
        for uid, entry in self.nodes.items():
            for label in entry["labels"]:
                self._by_label.setdefault(label, []).append(uid)
        self.reads: list[tuple[str, dict[str, Any], list[dict[str, Any]]]] = []
        self.refused: list[str] = []
        self.answer: dict[str, Callable[..., list[dict[str, Any]]]] = self._answers()

    # the session protocol `path._read` uses

    def execute_read(self, work: Callable[[Any], Any]) -> Any:
        return work(self)

    def run(self, query: str, **params: Any) -> Any:
        handler = self.answer.get(query)
        if handler is None:
            self.refused.append(query.strip().splitlines()[0])
            raise UnknownRead(query)
        try:
            rows = handler(**params)
        except NotImplementedError as exc:
            self.refused.append(str(exc))
            raise
        self.reads.append((query, params, rows))
        return SimpleNamespace(data=lambda: rows)

    # graph walking

    def has(self, uid: str | None, label: str) -> bool:
        return uid is not None and uid in self.nodes and label in self.nodes[uid]["labels"]

    def get(self, uid: str | None, key: str) -> Any:
        return self.nodes.get(uid or "", {}).get(key)

    def out(self, uid: str | None, *types: str) -> list[tuple[str, str, dict[str, Any]]]:
        return [(k, e, p) for k, e, p in self._out.get(uid or "", []) if k in types]

    def into(self, uid: str | None, *types: str) -> list[tuple[str, str, dict[str, Any]]]:
        return [(k, s, p) for k, s, p in self._in.get(uid or "", []) if k in types]

    def labelled(self, label: str) -> list[str]:
        return self._by_label.get(label, [])

    def device_of(self, uid: str | None) -> str | None:
        return next((e for _k, e, _p in self.out(uid, "ON") if self.has(e, "Device")), None)

    def _derive_gateways(self) -> None:
        """GATEWAY_FOR as the reasoner rule `gateway-from-router-interface` writes it: an
        interface of a gateway-role device to each connected prefix one of its addresses is IN."""
        out: dict[str, list[tuple[str, str]]] = {}
        for kind, start, end, _props in self.rels:
            out.setdefault(start, []).append((kind, end))
        have = {(s, e) for k, s, e, _p in self.rels if k == "GATEWAY_FOR"}
        for uid in sorted(self.nodes):
            if not self.has(uid, "Interface"):
                continue
            if self.get(uid, "vsx_kind") in ("bridge", "virtual-switch", "management"):
                continue
            dev = next((e for k, e in out.get(uid, []) if k == "ON" and self.has(e, "Device")), None)
            if dev is None or self.get(dev, "role") not in GATEWAY_ROLES:
                continue
            for k, ip in out.get(uid, []):
                if k != "HAS_IP" or not self.has(ip, "IpAddress"):
                    continue
                for k2, pfx in out.get(ip, []):
                    connected = (
                        k2 == "IN" and self.has(pfx, "Prefix") and self.get(pfx, "kind") == "connected"
                    )
                    if connected and (uid, pfx) not in have:
                        have.add((uid, pfx))
                        self.rels.append(("GATEWAY_FOR", uid, pfx, {"source": "reasoner", "derived": True}))

    # the answers

    def _answers(self) -> dict[str, Callable[..., list[dict[str, Any]]]]:
        answers: dict[str, Callable[..., list[dict[str, Any]]]] = {
            _session._RUN_IDENTITY: self._run_identity,
            _session.GATEWAYS: self._gateways,
            _path._DST_INSTANCES_QUERY: self._dst_instances,
            _trace._SOURCE_QUERY: self._source,
            _trace._IFACE_SEGMENTS_QUERY: self._iface_segments,
            _trace._IFACE_SEGMENT_QUERY: self._iface_segment,
            _trace._TRUNK_BY_IF_UID_QUERY: self._trunk_by_if_uid,
            _trace._TRUNK_BY_PARENT_NAME_QUERY: self._trunk_by_parent_name,
            _trace._ROUTES_QUERY: self._routes,
            _trace._VRF_NAME_QUERY: self._vrf_name,
            _trace._OWN_ADDRS_QUERY: self._own_addrs,
            _trace._EGRESS_TUNNEL_QUERY: self._egress_tunnel,
            _trace._CARRIER_TUNNEL_QUERY: self._carrier_tunnel,
            _trace._PROVIDER_OF_LINK_QUERY: self._provider_of_link,
            _trace._EGRESS_UPLINK_QUERY: self._egress_uplink,
            _trace._LOCAL_VRF_QUERY: self._local_vrf,
            _trace._START_TABLE_QUERY: self._start_table,
            _trace._L2_CHAIN_QUERY: self._l2_chain,
            _trace._GATEWAY_FHRP_QUERY: self._gateway_fhrp,
            _trace._ESTATE_PREFIXES_QUERY: self._estate_prefixes,
            _trace._ROUTED_PREFIXES_QUERY: self._routed_prefixes,
            inline_query(
                _trace, "RETURN w.uid AS uid, w.name AS name, w.kind AS kind ORDER BY w.uid LIMIT 1"
            ): self._wan_link,
            _vsx.VSX_EDGES: self._vsx_edges,
            _vsx.EGRESS: self._vsx_egress,
            _nat._NAT_RULES_QUERY: self._nat_rules,
            _nat._IFACE_ROLE_QUERY: self._iface_role,
            _nat._NAT_IFACE_ADDR_QUERY: self._nat_iface_addr,
            _pbr._DEFAULT_TABLE_QUERY: self._default_table,
            _pbr._INTERFACE_POLICY_RULES: self._interface_policy_rules,
            _pbr.POLICY_RULES: self._policy_rules,
            _pbr._DEVICE_PBR_POLICIES: self._device_pbr_policies,
            _fw._RULEBASE_RULES: self._rulebase_rules,
            _fw._ZONE_OF_INTERFACE: self._zone_of_interface,
            _fw._ACCESS_VENDOR_QUERY: self._access_vendor,
            _fw._RULEBASE_CANDIDATES: self._rulebase_candidates,
            _fw._JUMP_TARGET: self._jump_target,
            _fw._DEVICE_CHAINS: self._device_chains,
            _fw._DEVICE_ZONE_RULEBASES: self._device_zone_rulebases,
            _fw._DEVICE_STATE_POLICY_QUERY: self._device_state_policy,
            _local_zone._LOCAL_ZONE_CONTEXT_QUERY: self._local_zone_context,
            _local_zone._OWNED_ZONES_QUERY: self._owned_zones,
            _local_zone._LOCAL_ZONE_RULEBASES_QUERY: self._local_zone_rulebases,
            _local_zone._LOCAL_RULES_QUERY: self._rulebase_rules,
            inline_query(_fw, "co:CONTAINS]-(dst:Zone)"): self._zone_pair,
            inline_query(_fw, "WHERE i.uid IN [$a, $b] AND i:Obj"): self._interface_names,
            _cpi.QUERY: self._absent("in_if", "IN_CONTEXT"),
            _routing._NEXT_HOP_DEVICE_QUERY: self._next_hop_device,
            _routing._LINK_PEER_QUERY: self._link_peer,
            _routing._NEXT_HOP_DOMAIN_QUERY: self._next_hop_domain,
            _routing._NEXT_HOP_CONTEXTS_QUERY: self._next_hop_contexts,
            _routing._CONNECTED_LOCAL_QUERY: self._connected_local,
            _routing._CONNECTED_INGRESS_QUERY: self._connected_ingress,
            _routing._CONNECTED_REMOTE_QUERY: self._connected_remote,
            _sdwan._BOUNDARY_QUERY: self._absent("dev", "HAS_BOUNDARY"),
            _lb._VIP_BINDING_QUERY: self._vip_binding,
            _lb._VIP_ANY_BINDING_QUERY: self._vip_any_binding,
            inline_query(
                importlib.import_module("hst.path.gates.aci"), "RETURN ip AS ip, g.uid AS epg_uid"
            ): (self._aci_ends),
            _gates.gate_safeguard_query(): self._gate_safeguard,
        }
        mirrored = getattr(_trace, "_RIB_MIRRORED_QUERY", None)
        if mirrored is not None:
            answers[mirrored] = self._rib_mirrored
        return answers

    def _absent(self, anchor: str, *rels: str) -> Callable[..., list[dict[str, Any]]]:
        """A read whose every row starts from an edge of `rels` on the `anchor` node: no
        rows when the node has none, refused when it has one (not modelled here)."""

        def answer(**params: Any) -> list[dict[str, Any]]:
            if self.out(params[anchor], *rels):
                raise NotImplementedError(f"{rels} on {params[anchor]} is not modelled by TraceGraph")
            return []

        return answer

    # session.py, trace.py: run, gateways, source and destination

    def _run_identity(self, uid: str, snap: int) -> list[dict[str, Any]]:
        return []  # a fixture graph holds no CycleRun node

    def _gateways(self, snap: int) -> list[dict[str, Any]]:
        rows = []
        for i in self.labelled("Interface"):
            dev = self.device_of(i)
            if dev is None:
                continue
            for _k, p, _q in self.out(i, "GATEWAY_FOR"):
                if not self.has(p, "Prefix"):
                    continue
                rows.append(
                    {
                        "cidr": self.get(p, "cidr"),
                        "l3dom": self.get(p, "l3dom"),
                        "anchor": self.get(p, "anchor"),
                        "if_uid": i,
                        "if_name": self.get(i, "name"),
                        "dev_uid": dev,
                        "dev_name": self.get(dev, "hostname"),
                        "dev_carried": bool(self.get(dev, "carried") or False),
                        **{
                            k: self.get(i, k)
                            for k in ("vsx_cluster", "vsx_state", "firewall_instance_uid", "vsid")
                        },
                        "vsx_kind": self.get(i, "vsx_kind"),
                    }
                )
        return rows

    def _dst_instances(self, ip: str, snap: int) -> list[dict[str, Any]]:
        rows = [
            {"uid": u, "anchor": self.get(u, "anchor"), "l3dom": self.get(u, "l3dom")}
            for u in self.labelled("IpAddress")
            if self.get(u, "ip") == ip
        ]
        return sorted(rows, key=lambda r: r["uid"])

    def _source(self, ip: str, snap: int) -> list[dict[str, Any]]:
        rows = []
        for u in self.labelled("IpAddress"):
            if self.get(u, "ip") != ip:
                continue
            owned = bool(self.into(u, "HAS_IP"))
            endpoints = [a for _k, a, _p in self.into(u, "HAS_IP") if self.has(a, "Endpoint")]
            for ep in _each(endpoints):
                atts: list[tuple[str | None, dict[str, Any]]] = [
                    (b, p) for _k, b, p in self.out(ep, "ATTACHED")
                ]
                atts = atts or [(None, {})]
                segs = [
                    b
                    for _k, b, _p in self.out(ep, "IN")
                    if self.has(b, "BridgeDomain") or self.has(b, "L2Segment")
                ]
                for att, att_props in atts:
                    sw = self.device_of(att) if self.has(att, "Port") else None
                    for seg in _each(segs):
                        rows.append(
                            {
                                "ip_uid": u,
                                "l3dom": self.get(u, "l3dom"),
                                "anchor": self.get(u, "anchor"),
                                "ep_uid": ep,
                                "ep_name": self.get(ep, "name")
                                or self.get(ep, "hostname")
                                or self.get(ep, "mac"),
                                "att_uid": att,
                                "att_name": self.get(att, "name") or self.get(att, "hostname"),
                                "att_is_port": self.has(att, "Port") if att else None,
                                "ssid": att_props.get("ssid"),
                                "sw_uid": sw,
                                "sw_name": self.get(sw, "hostname"),
                                "seg_uid": seg,
                                "owned": owned,
                            }
                        )
        return rows

    def _segments_of(self, i: str) -> list[str]:
        """BOUND_TO -> VlanInstance -> REALIZES -> BridgeDomain or L2Segment, and the
        EXTENDS closure (up to two hops) of each; ATTACHED_TO is a reasoner edge (absent)."""
        if self.out(i, "ATTACHED_TO"):
            raise NotImplementedError("ATTACHED_TO is reasoner-derived and not modelled by TraceGraph")
        held = set()
        for _k, v, _p in self.out(i, "BOUND_TO"):
            if self.has(v, "VlanInstance"):
                held |= {
                    s
                    for _k2, s, _q in self.out(v, "REALIZES")
                    if self.has(s, "BridgeDomain") or self.has(s, "L2Segment")
                }
        found = set(held)
        frontier = set(held)
        for _depth in range(2):
            nxt = set()
            for s in frontier:
                for _k, t, _p in self.out(s, "EXTENDS") + self.into(s, "EXTENDS"):
                    if (self.has(t, "BridgeDomain") or self.has(t, "L2Segment")) and t not in found:
                        nxt.add(t)
            found |= nxt
            frontier = nxt
        return sorted(found)

    def _iface_segments(self, us: list[str], snap: int) -> list[dict[str, Any]]:
        return [{"u": u, "segs": self._segments_of(u)} for u in sorted(set(us)) if self.has(u, "Interface")]

    def _iface_segment(self, u: str, snap: int) -> list[dict[str, Any]]:
        return [{"uid": s} for s in self._segments_of(u)] if self.has(u, "Interface") else []

    def _trunk_row(self, i: str) -> list[dict[str, Any]]:
        cables = []
        for _k, rp, _p in self.out(i, "REALIZED_BY"):
            if not self.has(rp, "Port"):
                continue
            for _c, swp, _q in self.out(rp, "CONNECTED_TO") + self.into(rp, "CONNECTED_TO"):
                if self.has(swp, "Port"):
                    dev = self.device_of(swp)
                    cables.append(
                        {
                            "rp": rp,
                            "rp_name": self.get(rp, "name"),
                            "swp": swp,
                            "swp_name": self.get(swp, "name"),
                            "swp_dev": (self.get(dev, "hostname") or dev) if dev else None,
                        }
                    )
        cables = sorted({(c["rp"], c["swp"]): c for c in cables}.values(), key=lambda c: (c["rp"], c["swp"]))
        head = cables[0] if cables else {}
        return [
            {
                **{k: head.get(k) for k in ("rp", "rp_name", "swp", "swp_name", "swp_dev")},
                "peers": [c["swp"] for c in cables],
            }
        ]

    def _trunk_by_if_uid(self, if_uid: str, snap: int) -> list[dict[str, Any]]:
        return self._trunk_row(if_uid) if self.has(if_uid, "Interface") else []

    def _trunk_by_parent_name(self, name: str, dev: str, snap: int) -> list[dict[str, Any]]:
        return [
            row
            for _k, i, _p in self.into(dev, "ON")
            if self.has(i, "Interface") and self.get(i, "name") == name
            for row in self._trunk_row(i)
        ]

    # trace.py: routes, own addresses, tunnels, tables

    def _routes(self, vrf: str, snap: int) -> list[dict[str, Any]]:
        if not self.has(vrf, "VrfInstance"):
            return []
        if self.out(vrf, "IMPORTS"):
            raise NotImplementedError("route-target imports are not modelled by TraceGraph")
        rows: list[dict[str, Any]] = []
        for kind, p, props in self.out(vrf, "STATIC_ROUTE", "LEARNED_ROUTE", "ORIGINATES"):
            if not self.has(p, "Prefix") or (
                kind == "ORIGINATES" and (props.get("proto") or "") == "network"
            ):
                continue
            ifname = props.get("interface") or props.get("rib_interface")
            egress = [
                e
                for _k, e, q in self.out(p, "VIA")
                if q.get("vrf") == vrf and self.has(e, "Interface") and self.get(e, "name") == ifname
            ]
            aggregate = kind == "ORIGINATES" and (props.get("proto") or "") == "aggregate"
            for e in _each(egress):
                row = {
                    "uid": p,
                    "cidr": self.get(p, "cidr"),
                    "kind": "AGGREGATE" if aggregate else kind,
                    "next_hop": props.get("next_hop"),
                    "ifname": ifname,
                    "egress_uid": e,
                    "egress_name": self.get(e, "name"),
                    "derived": props.get("derived"),
                    "via_rt": props.get("via_rt"),
                    "rib": props.get("rib_confirmed"),
                    "next_hop_vrf": props.get("next_hop_vrf"),
                    "discard": "blackhole" if aggregate else props.get("discard"),
                }
                if row not in rows:
                    rows.append(row)
        order = (
            "cidr",
            "kind",
            "next_hop",
            "egress_uid",
            "ifname",
            "next_hop_vrf",
            "derived",
            "via_rt",
            "rib",
        )
        return sorted(rows, key=lambda r: _nulls_last(*(r[k] for k in order), r["discard"], r["uid"]))

    def _vrf_name(self, u: str, snap: int) -> list[dict[str, Any]]:
        return [{"n": self.get(u, "name")}] if self.has(u, "VrfInstance") else []

    def _rib_mirrored(self, u: str, snap: int) -> list[dict[str, Any]]:
        return [{"m": self.get(u, "rib_mirrored")}] if self.has(u, "VrfInstance") else []

    def _own_addrs(self, dev: str, vrf: str | None, snap: int) -> list[dict[str, Any]]:
        if not self.has(dev, "Device"):
            return []
        pairs = [
            (i, ip)
            for _k, i, _p in self.into(dev, "ON")
            if self.has(i, "Interface")
            for _h, ip, _q in self.out(i, "HAS_IP")
            if self.has(ip, "IpAddress")
        ]
        for _k, link, _p in self.out(dev, "HAS_LINK"):
            if self.has(link, "WanLink"):
                ips = [ip for _h, ip, _q in self.out(link, "HAS_IP") if self.has(ip, "IpAddress")]
                pairs += [
                    (i, ip) for _o, i, _q in self.out(link, "ON") if self.has(i, "Interface") for ip in ips
                ]
        rows = []
        for i, ip in dict.fromkeys(pairs):
            tables = [v for _k, v, _p in self.out(i, "IN_VRF") if self.has(v, "VrfInstance")]
            if vrf is None or vrf in tables or not tables:
                rows.append(
                    {"ip": self.get(ip, "ip"), "ip_uid": ip, "if_uid": i, "if_name": self.get(i, "name")}
                )
        return sorted(rows, key=lambda r: (r["ip"], r["if_uid"]))

    def _egress_uplink(self, u: str, snap: int) -> list[dict[str, Any]]:
        if not self.has(u, "Interface"):
            return []
        links = sorted(w for _k, w, _p in self.into(u, "ON") if self.has(w, "WanLink")) or [None]
        devices = sorted(d for _k, d, _p in self.out(u, "ON") if self.has(d, "Device")) or [None]
        return [
            {
                "default_origin": self.get(u, "ipv4_default_origin"),
                "link_uid": links[0],
                "link_name": self.get(links[0], "name") if links[0] else None,
                "link_kind": self.get(links[0], "kind") if links[0] else None,
                "site_zone": self.get(devices[0], "site_zone") if devices[0] else None,
                "site_block": self.get(devices[0], "site_block") if devices[0] else None,
            }
        ]

    def _estate_prefixes(self, snap: int) -> list[dict[str, Any]]:
        """`_ESTATE_PREFIXES_QUERY`: one row per distinct (cidr, interface) of each Prefix a
        device's interface, or an FhrpGroup the interface is a MEMBER_OF, is GATEWAY_FOR, with
        the interface's WAN link kinds, access-client mark, its device's zone, and on a device
        of zone internet the default routes of the device's tables."""
        rows = []
        for i in self.labelled("Interface"):
            dev = self.device_of(i)
            if dev is None:
                continue
            cidrs = sorted(
                {
                    self.get(p, "cidr")
                    for start in [i, *(g for _m, g, _p in self.out(i, "MEMBER_OF"))]
                    for _k, p, _q in self.out(start, "GATEWAY_FOR")
                    if self.has(p, "Prefix") and self.get(p, "cidr") is not None
                }
            )
            if not cidrs:
                continue
            kinds = [
                str(self.get(w, "kind") or "").lower()
                for w in sorted(w for _k, w, _p in self.into(i, "ON") if self.has(w, "WanLink"))
            ]
            zone = self.get(dev, "site_zone")
            defaults: list[dict[str, Any]] = []
            # every table of the device: its interfaces' and the policy tables OWNED_BY it
            tables = {
                v
                for _o, j, _p in self.into(dev, "ON")
                if self.has(j, "Interface")
                for _k, v, _q in self.out(j, "IN_VRF")
                if self.has(v, "VrfInstance")
            } | {v for _k, v, _p in self.into(dev, "OWNED_BY") if self.has(v, "VrfInstance")}
            for v in sorted(tables):
                for _k, dp, props in self.out(v, "STATIC_ROUTE", "LEARNED_ROUTE"):
                    if self.get(dp, "cidr") in ("0.0.0.0/0", "::/0"):
                        hop = props.get("next_hop")
                        egress = props.get("interface") or props.get("rib_interface")
                        row = {
                            "cidr": self.get(dp, "cidr"),
                            "next_hop": hop,
                            "interface": egress,
                            "held": self._next_hop_held(dev, egress, hop),
                        }
                        if row not in defaults:
                            defaults.append(row)
            for cidr in cidrs:
                rows.append(
                    {
                        "cidr": cidr,
                        "if_uid": i,
                        "if_name": self.get(i, "name"),
                        "default_origin": self.get(i, "ipv4_default_origin"),
                        "link_kinds": kinds,
                        "site_zone": zone,
                        "defaults": defaults,
                    }
                )
        return sorted(rows, key=lambda r: (r["cidr"], r["if_uid"]))

    def _next_hop_held(self, dev: str, egress: str | None, hop: str | None) -> bool:
        """The `held` of `_ESTATE_PREFIXES_QUERY`'s default rows: a collected interface has the
        next hop; for a link-local one, an interface on the egress interface's own link (one that
        shares a connected prefix that is not link-local with it)."""
        if hop is None:
            return False
        if not str(hop).lower().startswith(("fe8", "fe9", "fea", "feb", "169.254.")):
            return hop in self._held_addresses()
        eg = next(
            (
                j
                for _o, j, _p in self.into(dev, "ON")
                if self.has(j, "Interface") and egress is not None and self.get(j, "name") == egress
            ),
            None,
        )
        if eg is None:
            return False

        def prefixes(i: str) -> set[str]:
            return {
                q
                for _h, ip, _p in self.out(i, "HAS_IP")
                for _k, q, _r in self.out(ip, "IN")
                if self.has(q, "Prefix")
                and not str(self.get(q, "cidr") or "").startswith(("fe80", "169.254."))
            }

        own = prefixes(eg)
        return any(
            j != eg and own & prefixes(j)
            for j in self.labelled("Interface")
            if any(self.get(ip, "ip") == hop for _h, ip, _p in self.out(j, "HAS_IP"))
        )

    def _held_addresses(self) -> set[str]:
        """Every address an interface has (HAS_IP from an Interface)."""
        return {
            self.get(ip, "ip")
            for i in self.labelled("Interface")
            for _k, ip, _p in self.out(i, "HAS_IP")
            if self.has(ip, "IpAddress")
        }

    def _routed_prefixes(self, spans: list[dict[str, Any]], snap: int) -> list[dict[str, Any]]:
        """`_ROUTED_PREFIXES_QUERY`: the cidr of each Prefix a VrfInstance has a STATIC_ROUTE,
        LEARNED_ROUTE or ORIGINATES edge to, whose keys meet a span the way the Cypher's do, with
        the device of each such table (OWNED_BY, else an interface in it, else the table)."""
        from hst.core.ipenc import graph_prefix_keys

        rows = []
        for p in sorted(self.labelled("Prefix")):
            keys = graph_prefix_keys(self.get(p, "cidr"))
            tables = sorted(
                {
                    v
                    for _k, v, _q in self.into(p, "STATIC_ROUTE", "LEARNED_ROUTE", "ORIGINATES")
                    if self.has(v, "VrfInstance")
                }
            )
            if keys is None or not tables:
                continue
            lo, hi = keys
            if not any(
                (lo in s["covering"] or s["lo"] <= lo <= s["hi"]) and hi >= s["lo"] and lo <= s["hi"]
                for s in spans
            ):
                continue
            devices = []
            for v in tables:
                owned = next((d for _k, d, _p in self.out(v, "OWNED_BY") if self.has(d, "Device")), None)
                member = next(
                    (
                        self.device_of(j)
                        for _k, j, _p in self.into(v, "IN_VRF")
                        if self.has(j, "Interface") and self.device_of(j)
                    ),
                    None,
                )
                dev = owned or member or v
                if dev not in devices:
                    devices.append(dev)
            rows.append({"cidr": self.get(p, "cidr"), "devices": devices})
        return sorted(rows, key=lambda r: r["cidr"])

    def _gateway_fhrp(self, interfaces: list[str], snap: int) -> list[dict[str, Any]]:
        """`_GATEWAY_FHRP_QUERY`: each HAS_IP of the named interfaces whose `fhrp` is hsrp or
        vrrp, with the FhrpGroup the interface is a MEMBER_OF for that address and kind."""
        rows = []
        for i in interfaces:
            if not self.has(i, "Interface"):
                continue
            for _k, ip, props in self.out(i, "HAS_IP"):
                fhrp = props.get("fhrp")
                if not self.has(ip, "IpAddress") or fhrp not in ("hsrp", "vrrp"):
                    continue
                vip = self.get(ip, "ip")
                groups = [
                    g
                    for _m, g, _p in self.out(i, "MEMBER_OF")
                    if self.has(g, "FhrpGroup") and self.get(g, "vip") == vip and self.get(g, "kind") == fhrp
                ]
                for group in _each(groups):
                    row = {
                        "if_uid": i,
                        "vip": vip,
                        "group_uid": group,
                        "fhrp": fhrp,
                        "fhrp_group": props.get("group"),
                        "fhrp_state": props.get("state"),
                    }
                    if row not in rows:
                        rows.append(row)
        return sorted(rows, key=lambda r: _nulls_last(r["if_uid"], r["vip"], r["group_uid"], r["fhrp_state"]))

    def _wan_link(self, dev: str, u: str, snap: int) -> list[dict[str, Any]]:
        links = sorted(
            e
            for _k, e, _p in self.out(dev, "HAS_LINK")
            if self.has(e, "WanLink") and any(i == u for _o, i, _q in self.out(e, "ON"))
        )
        return [
            {"uid": link, "name": self.get(link, "name"), "kind": self.get(link, "kind")}
            for link in links[:1]
        ]

    def _egress_tunnel(self, u: str, tunnel: str | None, far: str | None, snap: int) -> list[dict[str, Any]]:
        if not self.has(u, "Interface"):
            return []
        found: list[tuple[str, str, str | None]] = []
        for _k, t, _p in self.into(u, "ENDPOINT"):
            if not self.has(t, "Tunnel") or (tunnel is not None and t != tunnel):
                continue
            if (self.get(t, "encap") or "") == "velocloud-vcmp" and tunnel is None:
                ends = {
                    self.get(f, "ip")
                    for _k2, f, _q in self.out(t, "TERMINATES_ON")
                    if self.has(f, "IpAddress")
                }
                if far not in ends:
                    continue
            found.append((t, "endpoint", None))
        own = {self.get(ip, "ip") for _k, ip, _p in self.out(u, "HAS_IP") if self.has(ip, "IpAddress")}
        tunnel_kind = (self.get(u, "kind") or "") in ("tunnel", "vti", "wireguard")
        for t in self.labelled("Tunnel"):
            if self.get(t, "source_ip") is not None and self.get(t, "source_ip") in own:
                found.append((t, "tunnel" if tunnel_kind else "source", None))
        for _k, rt, _p in self.into(u, "ENDPOINT"):
            local = self.get(rt, "local_address")
            if self.has(rt, "Tunnel") and local is not None:
                for t in self.labelled("Tunnel"):
                    if (
                        t != rt
                        and self.get(t, "source_ip") == local
                        and self.get(t, "encap") == self.get(rt, "encap")
                    ):
                        raise NotImplementedError("a carried ZIA tunnel is not modelled by TraceGraph")
        rows = [
            {
                "uid": t,
                "name": self.get(t, "name"),
                "encap": self.get(t, "encap"),
                "allowed_ips": self.get(t, "allowed_ips"),
                "binding": binding,
                "via": via,
            }
            for t, binding, via in dict.fromkeys(found)
        ]
        return sorted(rows, key=lambda r: (r["uid"], r["binding"]))

    def _carrier_tunnel(self, uid: str, snap: int) -> list[dict[str, Any]]:
        if not self.has(uid, "Tunnel"):
            return []
        fars = sorted({f for _k, f, _p in self.out(uid, "TERMINATES_ON")})
        rank = {"primary": 0, "secondary": 1}
        ends = sorted(
            ((rank.get(str(p.get("role")), 2), f, p) for _k, f, p in self.out(uid, "TERMINATES_ON")),
            key=lambda x: (x[0], x[1]),
        )
        keys = (
            "endpoint", "endpoint_port", "local_address", "encap", "pair", "tunnel_mtu", "gre_key",
            "gre_checksum", "gre_sequence", "esp_encryption", "esp_hash", "esp_mode", "esp_proposals",
        )  # fmt: skip
        row: dict[str, Any] = {k: self.get(uid, k) for k in keys}
        row["carrier_proto"] = self.get(uid, "carrier_proto") or "udp"
        row["far_ends"] = len(fars)
        row["far_sample"] = [self.get(f, "ip") or self.get(f, "name") or f for f in fars][:5]
        if not ends:
            return [
                {**row, **dict.fromkeys(("far_ip", "far_uid", "far_name", "far_role", "far_vip", "far_kind"))}
            ]
        _rank, far, props = ends[0]
        return [
            {
                **row,
                "far_ip": self.get(far, "ip"),
                "far_uid": far,
                "far_name": self.get(far, "name"),
                "far_role": props.get("role"),
                "far_vip": props.get("vip"),
                "far_kind": next(
                    (k for k in ("ZscalerDc", "SdwanGateway", "IpAddress") if self.has(far, k)), None
                ),
            }
        ]

    def _provider_of_link(self, u: str, snap: int) -> list[dict[str, Any]]:
        rows = []
        for _h, ip, _p in self.out(u, "HAS_IP"):
            for _k, link, _q in self.into(ip, "HAS_IP"):
                if not self.has(link, "WanLink"):
                    continue
                for _b, pn, _r in self.out(link, "PROVIDED_BY"):
                    if self.has(pn, "ProviderNetwork"):
                        rows.append(
                            {
                                "link_uid": link,
                                "link_name": self.get(link, "name"),
                                "link_kind": self.get(link, "kind"),
                                "provider_uid": pn,
                                "provider_name": self.get(pn, "name"),
                                "provider_kind": self.get(pn, "kind"),
                            }
                        )
        return sorted(rows, key=lambda r: r["link_uid"])[:1] if self.has(u, "Interface") else []

    def _local_vrf(self, dev: str, snap: int) -> list[dict[str, Any]]:
        tables = {
            v
            for _k, i, _p in self.into(dev, "ON")
            if self.has(i, "Interface")
            for _k2, v, _q in self.out(i, "IN_VRF")
            if self.has(v, "VrfInstance") and self.get(v, "is_global") is True
        }
        return [{"vrf_uid": v, "vrf_name": self.get(v, "name")} for v in sorted(tables)[:1]]

    def _start_table(self, u: str, snap: int) -> list[dict[str, Any]]:
        if not self.has(u, "VrfInstance"):
            return []
        dev = next((e for _k, e, _p in self.out(u, "OWNED_BY") if self.has(e, "Device")), None)
        if dev is None:
            dev = next((self.device_of(i) for _k, i, _p in self.into(u, "IN_VRF") if self.device_of(i)), None)
        return (
            [{"uid": u, "name": self.get(u, "name"), "dev_uid": dev, "dev_name": self.get(dev, "hostname")}]
            if dev
            else []
        )

    def _l2_neighbours(self, n: str) -> list[tuple[str, str, dict[str, Any]]]:
        return [(e, k, p) for k, e, p in self.out(n, "ON", "CONNECTED_TO")] + [
            (s, k, p) for k, s, p in self.into(n, "ON", "CONNECTED_TO")
        ]

    def _shortest_paths(
        self, a: str, z: str, avoid: str | None, banned: frozenset[str] = frozenset(), limit: int = 12
    ) -> list[list[str]]:
        """Every shortest node path from a to z over undirected ON and CONNECTED_TO edges."""
        if a in banned or a == avoid:
            return []
        paths: dict[str, list[list[str]]] = {a: [[a]]}
        frontier = [a]
        for _depth in range(limit):
            nxt: dict[str, list[list[str]]] = {}
            for n in frontier:
                for m, _k, _p in self._l2_neighbours(n):
                    if m in paths or m in banned or m == avoid or m not in self.nodes:
                        continue
                    nxt.setdefault(m, []).extend([*path, m] for path in paths[n])
            if not nxt:
                return []
            if z in nxt:
                return nxt[z]
            paths.update(nxt)
            frontier = list(nxt)
        return []

    def _carried_bds(self, n: str, native: bool | None = None) -> list[str]:
        return [
            bd
            for _k, v, p in self.out(n, "CARRIES")
            if (native is None or p.get("native") is native) and self.has(v, "VlanInstance")
            for _r, bd, _q in self.out(v, "REALIZES")
        ]

    def _l2_chain(self, a: str, z: str, avoid: str, snap: int) -> list[dict[str, Any]]:
        if a not in self.nodes or z not in self.nodes:
            return []
        paths = self._shortest_paths(a, z, avoid or None)
        if not paths:
            return []
        path = sorted(paths)[0]

        def rel(x: str, y: str) -> tuple[str | None, dict[str, Any]]:
            return next(((k, p) for m, k, p in self._l2_neighbours(x) if m == y), (None, {}))

        chain = []
        for idx in range(1, len(path)):
            n, prev = path[idx], path[idx - 1]
            kind_in, props_in = rel(prev, n)
            kind_out, props_out = rel(n, path[idx + 1]) if idx + 1 < len(path) else (None, {})
            if kind_in == "CONNECTED_TO":
                conn = props_in.get("source")
            elif kind_out == "CONNECTED_TO":
                conn = props_out.get("source")
            elif kind_out is None:
                conn = next(
                    (
                        p.get("source")
                        for m, k, p in self._l2_neighbours(n)
                        if k == "CONNECTED_TO" and self.has(m, "Port")
                    ),
                    None,
                )
            else:
                conn = None
            before = frozenset(path[:idx])
            forked = any(
                m == z and m != n and m not in before for m, _k, _p in self._l2_neighbours(prev)
            ) or any(
                alt not in (z, n) and alt not in before and self._shortest_paths(alt, z, None, banned=before)
                for alt, _k, _p in self._l2_neighbours(prev)
            )
            dev = self.device_of(n)
            switched = [
                bd
                for _r, i, _p in self.into(n, "REALIZED_BY")
                if self.has(i, "Interface")
                for _s, v, _q in self.out(i, "SWITCHES")
                if self.has(v, "VlanInstance")
                for _z, bd, _t in self.out(v, "REALIZES")
            ]
            chain.append(
                {
                    "uid": n,
                    "is_port": self.has(n, "Port"),
                    "label": self.get(n, "name") or self.get(n, "hostname"),
                    "dev": (self.get(dev, "hostname") or dev) if dev else None,
                    "lag": next(
                        (lag for _m, lag, _p in self.out(n, "MEMBER_OF") if self.has(lag, "Lag")), None
                    ),
                    "native_bds": self._carried_bds(n, True),
                    "tagged_bds": self._carried_bds(n, False),
                    "bds": self._carried_bds(n) + switched,
                    "conn_source": conn,
                    "forked": forked,
                }
            )
        return [{"chain": chain}]

    # vsx.py

    def _vsx_edges(self, snap: int) -> list[dict[str, Any]]:
        present = any(
            (k == "CONNECTED_TO" and p.get("source") == "vsx-warp")
            or (k == "BRIDGED_TO" and p.get("source") == "vsx-bridge")
            for k, _s, _e, p in self.rels
        )
        return [{"present": True}] if present else []

    def _vsx_egress(self, u: str, snap: int) -> list[dict[str, Any]]:
        if not self.has(u, "Interface"):
            return []
        return [{"kind": self.get(u, "kind"), "complete": self.get(u, "vsx_topology_complete")}]

    # gates/nat.py

    def _column(self, rule: str, rel: str) -> tuple[bool, list[Any], bool]:
        """One NAT column as `_NAT_RULES_QUERY` aggregates it: each address property
        collected DISTINCT, then each object's RESOLVES_TO targets and each object's
        ranges, concatenated, nulls dropped."""
        targets = _distinct(e for _k, e, _p in self.out(rule, rel))
        addrs: list[Any] = []
        for key in ("cidr", "ip", "cidr6", "ip6"):
            addrs += _distinct(self.get(t, key) for t in targets)
        resolved = _distinct(
            tuple(self.get(r, "cidr") or self.get(r, "ip") for _k, r, _p in self.out(t, "RESOLVES_TO"))
            for t in targets
        )
        addrs += [x for group in resolved for x in group if x is not None]
        addrs += [x for ranges in _distinct(self.get(t, "ranges") for t in targets) for x in ranges]
        return bool(targets), addrs, any(self.get(t, "opaque") for t in targets)

    def _nat_rules(
        self, dev: str, in_if: str | None, snap: int, af: int | None = None
    ) -> list[dict[str, Any]]:
        if in_if and self.out(in_if, "IN_CONTEXT"):
            raise NotImplementedError(
                "the IN_CONTEXT branches of the NAT read are not modelled by TraceGraph"
            )
        bound: dict[str, list[tuple[bool, Any]]] = {}
        for _k, rb, p in self.out(dev, "ENFORCES"):
            if self.has(rb, "FwRulebase") and self.get(rb, "kind") == "nat":
                bound.setdefault(rb, []).append(
                    (bool(p.get("approximate") or False), self.get(dev, "cp_raw_uid"))
                )
        for _k, group, _p in self.out(dev, "MEMBER_OF"):
            if self.has(group, "RedundancyGroup"):
                for _k2, rb, p in self.out(group, "ENFORCES"):
                    if self.has(rb, "FwRulebase") and self.get(rb, "kind") == "nat":
                        owner = self.get(group, "cp_raw_uid")
                        bound.setdefault(rb, []).append((bool(p.get("approximate") or False), owner))
        rows = []
        for rb, owners in bound.items():
            approximate = min(1 if a else 0 for a, _o in owners) > 0
            for _k, n, _p in self.out(rb, "HAS_RULE"):
                if not self.has(n, "NatRule"):
                    continue
                cols = {
                    rel: self._column(n, rel) for rel in ("ORIG_SRC", "ORIG_DST", "XLATE_SRC", "XLATE_DST")
                }
                g = self.nodes[n]
                rows.append(
                    {
                        "rb_uid": rb,
                        "rb_name": self.get(rb, "name"),
                        "approximate": approximate,
                        "owners": _distinct(o for _a, o in owners),
                        "install_on": g.get("install_on") or [],
                        "install_on_unresolved": bool(g.get("install_on_unresolved") or False),
                        "auto_generated": g.get("auto_generated"),
                        **{f"{rel.lower()}_present": cols[rel][0] for rel in cols},
                        "uid": n,
                        "pos": g.get("position"),
                        "kind": g.get("kind"),
                        "method": g.get("method"),
                        "enabled": True if g.get("enabled") is None else g.get("enabled"),
                        "exclude": bool(g.get("exclude") or False),
                        "translation": g.get("translation"),
                        "translation_port": g.get("translation_port"),
                        "direction": g.get("direction"),
                        "static_flag": bool(g.get("static") or False),
                        "af": g.get("af"),
                        "orig_src_raw": g.get("orig_src"),
                        "orig_dst_raw": g.get("orig_dst"),
                        **{
                            k: g.get(k)
                            for k in (
                                "orig_src_port",
                                "orig_dst_port",
                                "orig_port",
                                "xlate_port",
                                "protocol",
                                "in_if",
                                "out_if",
                                "orig_service",
                                "xlate_service",
                                "service_unknown",
                                "translation_interface",
                                "approximate_reason",
                                "match_acl",
                                "match_route_map",
                                "pool",
                                "pool_start",
                                "pool_end",
                            )
                        },
                        "xlate_src_original": bool(g.get("xlate_src_original") or False),
                        "xlate_dst_original": bool(g.get("xlate_dst_original") or False),
                        "rule_approximate": bool(g.get("approximate") or False),
                        "overload": bool(g.get("overload") or False),
                        **{f"{rel.lower()}_addrs": cols[rel][1] for rel in cols},
                        **{f"{rel.lower()}_opaque": cols[rel][2] for rel in cols},
                    }
                )
        return sorted(rows, key=lambda r: (r["rb_uid"], *_nulls_last(r["pos"])))

    def _iface_role(self, u: str, snap: int) -> list[dict[str, Any]]:
        return [{"nat_role": self.get(u, "nat_role")}] if self.has(u, "Interface") else []

    def _nat_iface_addr(self, u: str, af: int, snap: int) -> list[dict[str, Any]]:
        if not self.has(u, "Interface"):
            return []
        # the Cypher's own family filter: `ip.ip CONTAINS ':'` for IPv6
        addrs = _distinct(
            self.get(ip, "ip")
            for _k, ip, _p in self.out(u, "HAS_IP")
            if self.has(ip, "IpAddress") and (":" in (self.get(ip, "ip") or "")) == (af == 6) and af in (4, 6)
        )
        return [{"ip": addrs[0]}] if len(addrs) == 1 else []

    # gates/pbr.py

    def _default_table(self, if_uid: str, snap: int) -> list[dict[str, Any]]:
        if not self.has(if_uid, "Interface"):
            return []
        tables = sorted(v for _k, v, _p in self.out(if_uid, "IN_VRF") if self.has(v, "VrfInstance"))
        return [{"uid": tables[0]}] if tables else []

    def _side(self, rule: str, rel: str) -> dict[str, Any]:
        objects = _distinct(e for _k, e, _p in self.out(rule, rel) if self.has(e, "NetObject"))
        targets = [t for o in objects for _k, t, _p in self.out(o, "RESOLVES_TO")]
        return {
            "cidrs": _distinct(self.get(t, "cidr") for t in targets),
            "ips": _distinct(self.get(t, "ip") for t in targets),
            "ranges": _distinct(self.get(o, "ranges") for o in objects),
            "reasons": _distinct(self.get(o, "opaque_reason") for o in objects),
            "count": len(objects),
            "opaque": any(self.get(o, "opaque") for o in objects),
        }

    def _pbr_rows(self, policies: Iterable[str]) -> list[dict[str, Any]]:
        rows = []
        for pol in policies:
            rules = [
                e
                for _k, e, _p in self.out(pol, "HAS_RULE")
                if self.has(e, "FwRule") and self.get(e, "enabled")
            ]
            head = {"pol_uid": pol, "pol_name": self.get(pol, "name"), "pol_af": self.get(pol, "af")}
            # the OPTIONAL MATCH keeps a policy with no rule as one row with a null rule
            for r in _each(rules):
                src, dst = self._side(r, "SRC"), self._side(r, "DST")
                members = _distinct(e for _k, e, _p in self.out(r, "SVC") if self.has(e, "SvcObject"))
                tables = [e for _k, e, _p in self.out(r, "REDIRECTS_VIA") if self.has(e, "VrfInstance")]
                for table in _each(tables):
                    rows.append(
                        {
                            **head,
                            "rule_uid": r,
                            "pos": self.get(r, "position"),
                            "rule_name": self.get(r, "name"),
                            "src_cidrs": src["cidrs"],
                            "src_ips": src["ips"],
                            "dst_cidrs": dst["cidrs"],
                            "dst_ips": dst["ips"],
                            "src_ranges": src["ranges"],
                            "dst_ranges": dst["ranges"],
                            "src_obj_count": src["count"],
                            "dst_obj_count": dst["count"],
                            "table_uid": table,
                            "table_name": self.get(table, "name"),
                            **self._svc_columns(members),
                            "svc_obj_count": len(members),
                            "svc_src_ports": [self.get(m, "src_port") for m in members],
                            "states_opaque": bool(self.get(r, "states_opaque") or False),
                            "states_opaque_reason": self.get(r, "states_opaque_reason"),
                            "src_negate": bool(self.get(r, "src_negate") or False),
                            "dst_negate": bool(self.get(r, "dst_negate") or False),
                            "addr_opaque_reasons": src["reasons"] + dst["reasons"],
                        }
                    )
        return sorted(rows, key=lambda r: (r["pol_name"] or "", *_nulls_last(r["pos"])))

    def _svc_columns(self, members: list[str]) -> dict[str, Any]:
        return {
            "svc_protos": [self.get(m, "proto") for m in members],
            "svc_port_specs": [self.get(m, "ports") for m in members],
            "svc_opaque": any(self.get(m, "opaque") for m in members),
            "svc_opaque_reasons": _distinct(self.get(m, "opaque_reason") for m in members),
            "svc_src_port": any((self.get(m, "src_port") or "") != "" for m in members),
        }

    def _interface_policy_rules(self, if_uid: str, snap: int) -> list[dict[str, Any]]:
        if not self.has(if_uid, "Interface"):
            return []
        return self._pbr_rows(
            _distinct(e for _k, e, _p in self.out(if_uid, "ENFORCES") if self.has(e, "PbrPolicy"))
        )

    def _policy_rules(self, pol_uids: list[str], snap: int) -> list[dict[str, Any]]:
        return self._pbr_rows(u for u in _distinct(pol_uids) if self.has(u, "PbrPolicy"))

    def _device_pbr_policies(self, dev: str, snap: int) -> list[dict[str, Any]]:
        rows = _distinct(
            (pol, i)
            for _k, i, _p in self.into(dev, "ON")
            if self.has(i, "Interface")
            for _e, pol, _q in self.out(i, "ENFORCES")
            if self.has(pol, "PbrPolicy")
        )
        return [{"pol_uid": pol, "if_uid": i} for pol, i in sorted(rows, key=lambda r: r[0])]

    # gates/firewall.py

    def _members_up(self, group: str, *, svc: bool) -> list[str]:
        """The nodes reaching `group` over MEMBER_OF*1..16 (member -> group): the SvcObject
        ones when `svc`, the others when not."""
        found: list[str] = []
        seen, frontier = {group}, [group]
        for _depth in range(16):
            nxt = []
            for g in frontier:
                for _k, m, _p in self.into(g, "MEMBER_OF"):
                    if m in seen:
                        continue
                    seen.add(m)
                    nxt.append(m)
                    if self.has(m, "SvcObject") == svc:
                        found.append(m)
            frontier = nxt
        return found

    def _rulebase_rules(self, rb: str, snap: int) -> list[dict[str, Any]]:
        if not self.has(rb, "FwRulebase"):
            return []
        rows = []
        for _k, r, _p in self.out(rb, "HAS_RULE"):
            if not self.has(r, "FwRule") or not self.get(r, "enabled"):
                continue
            targets = [e for _k2, e, _q in self.out(r, "SVC")]
            sv0 = _distinct(e for e in targets if self.has(e, "SvcObject"))
            foreign = [self.get(e, "name") or e for e in targets if not self.has(e, "SvcObject")]
            foreign += [self.get(m, "name") or m for s in sv0 for m in self._members_up(s, svc=False)]
            members = _distinct(m for s in sv0 for m in [s, *self._members_up(s, svc=True)])
            src, dst = self._side(r, "SRC"), self._side(r, "DST")
            g = self.nodes[r]
            rows.append(
                {
                    "uid": r,
                    "pos": g.get("position"),
                    "action": g.get("action"),
                    "name": g.get("name"),
                    "jump_target": g.get("jump_target"),
                    "out_if": g.get("out_interface"),
                    "in_if": g.get("in_interface"),
                    "out_if_group": g.get("out_interface_group"),
                    "in_if_group": g.get("in_interface_group"),
                    "states": g.get("states") or [],
                    "states_opaque": bool(g.get("states_opaque") or False),
                    "states_opaque_reason": g.get("states_opaque_reason"),
                    "unmodeled_fields": g.get("unmodeled_fields") or [],
                    "install_on": g.get("install_on") or [],
                    "install_on_unresolved": bool(g.get("install_on_unresolved") or False),
                    **{
                        k: bool(g.get(k) or False)
                        for k in ("src_any", "dst_any", "svc_any", "src_negate", "dst_negate", "svc_negate")
                    },
                    "src_cidrs": src["cidrs"],
                    "src_ips": src["ips"],
                    "dst_cidrs": dst["cidrs"],
                    "dst_ips": dst["ips"],
                    "protos": [self.get(m, "proto") for m in members],
                    "ports": [self.get(m, "ports") for m in members],
                    "svc_opaque": bool(foreign) or any(self.get(m, "opaque") for m in members),
                    "svc_opaque_reasons": [
                        self.get(m, "opaque_reason") for m in members if self.get(m, "opaque_reason")
                    ]
                    + [f"service object {x} is not modeled as a protocol and port" for x in foreign],
                    "svc_src_port": any((self.get(m, "src_port") or "") != "" for m in members),
                    "src_ports": [self.get(m, "src_port") for m in members],
                    "src_ranges": src["ranges"],
                    "dst_ranges": dst["ranges"],
                    "src_obj_count": src["count"],
                    "dst_obj_count": dst["count"],
                    "svc_obj_count": len(sv0) + len(foreign),
                    "src_opaque": src["opaque"],
                    "dst_opaque": dst["opaque"],
                    "src_opaque_reasons": src["reasons"],
                    "dst_opaque_reasons": dst["reasons"],
                }
            )
        return sorted(rows, key=lambda r: _nulls_last(r["pos"]))

    def _zone_row(self, z: str) -> dict[str, Any]:
        keys = ("name", "default_action", "default_action_unknown", "established_default_unknown")
        return {
            **{k: self.get(z, k) for k in keys},
            "intra_zone_filtering": self.get(z, "intra_zone_filtering"),
            "intra_zone_action": self.get(z, "intra_zone_action"),
        }

    def _zone_of_interface(self, in_if: str, snap: int) -> list[dict[str, Any]]:
        if not self.has(in_if, "Interface"):
            return []
        zones = sorted(
            (z for _k, z, _p in self.into(in_if, "CONTAINS") if self.has(z, "Zone")),
            key=lambda z: self.get(z, "name") or "",
        )
        return [self._zone_row(z) for z in zones[:1]]

    def _device_zones(self, dev: str) -> list[str]:
        return _distinct(
            z
            for _k, i, _p in self.into(dev, "ON")
            if self.has(i, "Interface")
            for _c, z, _q in self.into(i, "CONTAINS")
            if self.has(z, "Zone")
        )

    def _access(self, rb: str) -> bool:
        return self.has(rb, "FwRulebase") and (self.get(rb, "kind") or "access") == "access"

    def _enforced(self, dev: str) -> list[tuple[str, dict[str, Any], Any]]:
        """(rulebase, binding edge props, owner cp_raw_uid) of the Device and RedundancyGroup branches."""
        out = [(rb, p, self.get(dev, "cp_raw_uid")) for _k, rb, p in self.out(dev, "ENFORCES")]
        for _k, group, _p in self.out(dev, "MEMBER_OF"):
            if self.has(group, "RedundancyGroup"):
                out += [(rb, p, self.get(group, "cp_raw_uid")) for _k2, rb, p in self.out(group, "ENFORCES")]
        return out

    def _access_vendor(self, dev: str, snap: int) -> list[dict[str, Any]]:
        bound = [rb for rb, _p, _o in self._enforced(dev) if self._access(rb)]
        bound += [
            rb
            for z in self._device_zones(dev)
            for _k, rb, _p in self.into(z, "FROM_ZONE", "TO_ZONE")
            if self.has(rb, "FwRulebase")
        ]
        return _distinct(
            {"vendor": self.get(rb, "vendor"), "match_context": self.get(rb, "match_context")} for rb in bound
        )

    def _rulebase_candidates(
        self, dev: str, in_if: str | None, chain: str, strict_local: bool, snap: int
    ) -> list[dict[str, Any]]:
        if in_if and self.out(in_if, "IN_CONTEXT"):
            raise NotImplementedError(
                "the IN_CONTEXT branch of the rulebase read is not modelled by TraceGraph"
            )

        def takes(rb: str) -> bool:
            own = self.get(rb, "chain")
            in_chain = (own or "forward") == chain or (
                strict_local and own is None and chain in ("input", "output")
            )
            return self._access(rb) and in_chain and not self.out(rb, "FROM_ZONE", "TO_ZONE")

        picks = _distinct(
            (rb, bool(p.get("approximate") or False), owner)
            for rb, p, owner in self._enforced(dev)
            if takes(rb)
        )
        rows = []
        for rb, approximate, owner in picks:
            keys = (
                "vendor", "af", "default_action", "default_action_unknown", "global_state_policy",
                "state_policy_basis", "established_default_unknown", "match_context", "chain",
            )  # fmt: skip
            rows.append(
                {
                    "rb_uid": rb,
                    "rb_name": self.get(rb, "name"),
                    **{k: self.get(rb, k) for k in keys},
                    "approximate": approximate,
                    "owner_raw_uid": owner,
                    "acl_bindings": [
                        [self.get(i, "name"), p.get("direction")]
                        for _k, i, p in self.into(rb, "PROTECTED_BY")
                        if self.has(i, "Interface")
                    ],
                    "acl_unreported": self.get(rb, "unreported_bindings"),
                }
            )
        return sorted(rows, key=lambda r: _nulls_last(r["rb_name"]))

    def _jump_target(self, rb: str, snap: int) -> list[dict[str, Any]]:
        if not self.has(rb, "FwRulebase"):
            return []
        return [
            {
                "rb_uid": rb,
                "rb_name": self.get(rb, "name"),
                "default_action": self.get(rb, "default_action"),
                "default_action_unknown": bool(self.get(rb, "default_action_unknown") or False),
                "default_jump_target": self.get(rb, "default_jump_target"),
            }
        ]

    def _device_chains(self, dev: str, snap: int) -> list[dict[str, Any]]:
        chains = {
            self.get(rb, "chain")
            for _k, rb, _p in self.out(dev, "ENFORCES")
            if self._access(rb) and self.get(rb, "chain") is not None
        }
        return [{"chain": c} for c in sorted(chains)]

    def _zone_rulebases(self, dev: str) -> list[tuple[str, str, str]]:
        zones = self._device_zones(dev)
        rulebases = _distinct(
            rb
            for z in zones
            for _k, rb, _p in self.into(z, "FROM_ZONE", "TO_ZONE")
            if self.has(rb, "FwRulebase")
        )
        return [
            (rb, src, dst)
            for rb in rulebases
            for _f, src, _p in self.out(rb, "FROM_ZONE")
            for _t, dst, _q in self.out(rb, "TO_ZONE")
            if self.has(src, "Zone") and self.has(dst, "Zone") and (src in zones or dst in zones)
        ]

    def _device_zone_rulebases(self, dev: str, snap: int) -> list[dict[str, Any]]:
        rows = _distinct(
            {
                "rb_uid": rb,
                "af": self.get(rb, "af"),
                "src_zone": self.get(src, "name"),
                "dst_zone": self.get(dst, "name"),
                "dst_unbound": not any(self.has(i, "Interface") for _k, i, _p in self.out(dst, "CONTAINS")),
            }
            for rb, src, dst in self._zone_rulebases(dev)
        )
        return sorted(rows, key=lambda r: r["rb_uid"])

    def _device_state_policy(self, dev: str, snap: int) -> list[dict[str, Any]]:
        rulebases = [rb for _k, rb, _p in self.out(dev, "ENFORCES") if self.has(rb, "FwRulebase")]
        rulebases += [rb for rb, _s, _d in self._zone_rulebases(dev)]
        held = sorted({rb for rb in rulebases if self.get(rb, "global_state_policy") is not None})
        return [
            {
                "global_state_policy": self.get(rb, "global_state_policy"),
                "state_policy_basis": self.get(rb, "state_policy_basis"),
            }
            for rb in held[:1]
        ]

    # gates/local_zone.py: the local-zone reads the router-local path shares with impact

    def _owned(self, dev: str) -> list[str]:
        return sorted(z for _k, z, _p in self.into(dev, "OWNED_BY") if self.has(z, "Zone"))

    def _local_zone_context(self, dev: str, in_if: str, out_if: str, snap: int) -> list[dict[str, Any]]:
        rows = [
            {
                "if_uid": i,
                "if_name": self.get(i, "name"),
                "zone_uid": z,
                "zone_name": self.get(z, "name"),
            }
            for i in _distinct((in_if, out_if))
            if self.has(i, "Interface") and self.device_of(i) == dev
            for _k, z, _p in self.into(i, "CONTAINS")
            if self.has(z, "Zone")
        ]
        return sorted(rows, key=lambda r: (r["if_uid"], r["zone_uid"]))

    def _owned_zones(self, dev: str, snap: int) -> list[dict[str, Any]]:
        return [
            {
                "zone_uid": z,
                "zone_name": self.get(z, "name"),
                "local_zone": self.get(z, "local_zone"),
                "default_action": self.get(z, "default_action"),
                "default_action_unknown": self.get(z, "default_action_unknown"),
            }
            for z in self._owned(dev)
        ]

    def _local_zone_rulebases(self, dev: str, snap: int) -> list[dict[str, Any]]:
        owned = self._owned(dev)

        def local(z: str) -> Any:
            value = self.get(z, "local_zone")
            return value if value is not None else self.get(z, "is_local")

        rows = _distinct(
            {
                "rb_uid": rb,
                "rb_name": self.get(rb, "name"),
                "af": self.get(rb, "af"),
                "default_action": self.get(rb, "default_action"),
                "default_action_unknown": self.get(rb, "default_action_unknown"),
                "global_state_policy": self.get(rb, "global_state_policy"),
                "src_uid": src,
                "src_name": self.get(src, "name"),
                "src_local": local(src),
                "dst_uid": dst,
                "dst_name": self.get(dst, "name"),
                "dst_local": local(dst),
            }
            for src in owned
            for _f, rb, _p in self.into(src, "FROM_ZONE")
            if self.has(rb, "FwRulebase")
            for _t, dst, _q in self.out(rb, "TO_ZONE")
            if dst in owned
        )
        return sorted(rows, key=lambda r: r["rb_uid"])

    def _zone_pair(self, in_if: str, out_if: str, snap: int) -> list[dict[str, Any]]:
        if not (self.has(in_if, "Interface") and self.has(out_if, "Interface")):
            return []
        rows = []
        for _c, src, _p in self.into(in_if, "CONTAINS"):
            for _c2, dst, _q in self.into(out_if, "CONTAINS"):
                if not (self.has(src, "Zone") and self.has(dst, "Zone")):
                    continue
                for _f, rb, _r in self.into(src, "FROM_ZONE"):
                    if not self.has(rb, "FwRulebase") or dst not in {
                        e for _t, e, _s in self.out(rb, "TO_ZONE")
                    }:
                        continue
                    keys = (
                        "af", "default_action", "default_action_unknown", "global_state_policy",
                        "state_policy_basis", "established_default_unknown",
                    )  # fmt: skip
                    rows.append(
                        {
                            "rb_uid": rb,
                            "rb_name": self.get(rb, "name"),
                            **{k: self.get(rb, k) for k in keys},
                            "src_zone": self.get(src, "name"),
                            "dst_zone": self.get(dst, "name"),
                            "zone_default": self.get(dst, "default_action"),
                            "zone_default_unknown": self.get(dst, "default_action_unknown"),
                            "zone_established_default_unknown": self.get(dst, "established_default_unknown"),
                        }
                    )
        return sorted(rows, key=lambda r: r["rb_uid"])

    def _interface_names(self, a: str, b: str, snap: int) -> list[dict[str, Any]]:
        return [
            {"uid": u, "name": self.get(u, "name")} for u in _distinct((a, b)) if self.has(u, "Interface")
        ]

    # gates/routing.py

    def _next_hop_device(self, ip: str, snap: int) -> list[dict[str, Any]]:
        rows = []
        for address in self.labelled("IpAddress"):
            if self.get(address, "ip") != ip:
                continue
            for _k, i, h in self.into(address, "HAS_IP"):
                if not self.has(i, "Interface"):
                    continue
                for _o, dev, _p in self.out(i, "ON"):
                    if not self.has(dev, "Device"):
                        continue
                    rows.append(
                        {
                            "dev_uid": dev,
                            "dev_name": self.get(dev, "hostname"),
                            "if_uid": i,
                            "if_name": self.get(i, "name"),
                            "l3dom": self.get(address, "l3dom"),
                            "anchor": self.get(address, "anchor"),
                            "carried": bool(self.get(dev, "carried") or False),
                            "fhrp": h.get("fhrp"),
                            "fhrp_group": h.get("group"),
                            "fhrp_state": h.get("state"),
                            **{
                                k: self.get(i, k)
                                for k in ("vsx_cluster", "vsx_state", "firewall_instance_uid", "vsid")
                            },
                            "vsx_kind": self.get(i, "vsx_kind"),
                        }
                    )
        return sorted(rows, key=lambda r: (r["dev_uid"], r["if_uid"]))

    def _link_peer(self, u: str, ip: str, snap: int) -> list[dict[str, Any]]:
        if not self.has(u, "Interface"):
            return []
        if self.out(u, "ATTACHED_TO"):
            raise NotImplementedError("ATTACHED_TO is reasoner-derived and not modelled by TraceGraph")
        peers = [
            i
            for _h, a, _p in self.out(u, "HAS_IP")
            for _n, p, _q in self.out(a, "IN")
            if self.has(p, "Prefix")
            for _n2, b, _r in self.into(p, "IN")
            if self.has(b, "IpAddress")
            for _h2, i, _s in self.into(b, "HAS_IP")
            if self.has(i, "Interface")
        ]
        peers += [
            i
            for _r1, pe, _p in self.out(u, "REALIZED_BY")
            if self.has(pe, "Port")
            for _c, pf, _q in self.out(pe, "CONNECTED_TO") + self.into(pe, "CONNECTED_TO")
            if self.has(pf, "Port")
            for _r2, i, _s in self.into(pf, "REALIZED_BY")
            if self.has(i, "Interface")
        ]
        rows = []
        for i in _distinct(peers):
            if i == u or ip not in (self.get(i, "ipv6_link_local") or []):
                continue
            domains = _distinct(
                self.get(x, "l3dom") for _h, x, _p in self.out(i, "HAS_IP") if self.has(x, "IpAddress")
            )
            for _o, dev, _p in self.out(i, "ON"):
                if not self.has(dev, "Device"):
                    continue
                for table in _each(v for _k, v, _q in self.out(i, "IN_VRF") if self.has(v, "VrfInstance")):
                    rows.append(
                        {
                            "dev_uid": dev,
                            "dev_name": self.get(dev, "hostname"),
                            "if_uid": i,
                            "if_name": self.get(i, "name"),
                            "l3dom": domains[0] if domains else None,
                            "anchor": table,
                            "carried": bool(self.get(dev, "carried") or False),
                            **{
                                k: self.get(i, k)
                                for k in ("vsx_cluster", "vsx_state", "firewall_instance_uid", "vsid")
                            },
                            "vsx_kind": self.get(i, "vsx_kind"),
                        }
                    )
        return sorted(rows, key=lambda r: (r["dev_uid"], r["if_uid"]))

    def _next_hop_domain(self, table: str, anchors: list[str], snap: int) -> list[dict[str, Any]]:
        found = [
            v
            for _m, rd, p in self.out(table, "MEMBER_OF")
            if self.has(rd, "RoutingDomain") and (p.get("basis") or "declared") == "declared"
            for _m2, v, q in self.into(rd, "MEMBER_OF")
            if v in anchors and self.has(v, "VrfInstance") and (q.get("basis") or "declared") == "declared"
        ]
        found += [
            v
            for _r, ld, _p in self.out(table, "REALIZES")
            if self.has(ld, "L3Domain")
            for _r2, v, _q in self.into(ld, "REALIZES")
            if v in anchors and self.has(v, "VrfInstance")
        ]
        return [{"uid": v} for v in _distinct(found)] if self.has(table, "VrfInstance") else []

    def _next_hop_contexts(self, uids: list[str], snap: int) -> list[dict[str, Any]]:
        rows = []
        for v in sorted(u for u in set(uids) if self.has(u, "VrfInstance")):
            held = _distinct(
                self.get(ip, "l3dom")
                for _k, i, _p in self.into(v, "IN_VRF")
                if self.has(i, "Interface")
                for _h, ip, _q in self.out(i, "HAS_IP")
                if self.has(ip, "IpAddress")
            )
            routed = _distinct(
                self.get(p, "l3dom")
                for _k, p, _q in self.out(v, "STATIC_ROUTE", "LEARNED_ROUTE", "ORIGINATES")
                if self.has(p, "Prefix")
            )
            rows.append(
                {
                    "uid": v,
                    "name": self.get(v, "name"),
                    "is_global": self.get(v, "is_global"),
                    "l3doms": held + routed,
                }
            )
        return rows

    def _serving(self, p: str) -> list[str]:
        return sorted(i for _k, i, _q in self.into(p, "GATEWAY_FOR") if self.has(i, "Interface"))

    def _connected_local(self, p: str, dev: str, in_if: str, snap: int) -> list[dict[str, Any]]:
        found = [i for i in self._serving(p) if i != in_if and self.device_of(i) == dev]
        return [{"uid": i, "name": self.get(i, "name")} for i in found[:1]]

    def _connected_ingress(self, p: str, in_if: str, snap: int) -> list[dict[str, Any]]:
        return [{"uid": in_if, "name": self.get(in_if, "name")}] if in_if in self._serving(p) else []

    def _connected_remote(self, p: str, snap: int) -> list[dict[str, Any]]:
        return [{"uid": i, "name": self.get(i, "name")} for i in self._serving(p)]

    # gates/lb.py, gates/aci.py, the gate safeguard

    def _vips(self, ip: str) -> list[tuple[str, str]]:
        return [
            (vs, vip)
            for vip in self.labelled("IpAddress")
            if self.get(vip, "ip") == ip
            for _k, vs, _p in self.into(vip, "VIP")
            if self.has(vs, "VirtualService")
        ]

    def _vip_binding(self, ip: str, dev: str, snap: int) -> list[dict[str, Any]]:
        groups = {g for _m, g, _p in self.out(dev, "MEMBER_OF") if self.has(g, "RedundancyGroup")}
        rows = [
            {
                **{k: self.get(vs, k) for k in ("name", "kind", "proto", "port", "snat_mode")},
                "uid": vs,
                "ip_uid": vip,
            }
            for vs, vip in self._vips(ip)
            if any(t == dev or t in groups for _o, t, _q in self.out(vs, "ON"))
        ]
        return sorted(rows, key=lambda r: r["uid"])

    def _vip_any_binding(self, ip: str, snap: int) -> list[dict[str, Any]]:
        rows = [
            {**{k: self.get(vs, k) for k in ("name", "kind", "proto", "port")}, "uid": vs, "on_uid": t}
            for vs, _vip in self._vips(ip)
            for _o, t, _q in self.out(vs, "ON")
        ]
        return sorted(rows, key=lambda r: (r["uid"], r["on_uid"]))[:20]

    def _aci_ends(self, src: str, dst: str, snap: int) -> list[dict[str, Any]]:
        rows = []
        for ip in (src, dst):
            hits = []
            for address in self.labelled("IpAddress"):
                if self.get(address, "ip") != ip:
                    continue
                for _h, ep, _p in self.into(address, "HAS_IP"):
                    if not self.has(ep, "Endpoint"):
                        continue
                    for epg in _each(g for _r, g, _q in self.out(ep, "IN_EPG") if self.has(g, "Epg")):
                        tables = [
                            v
                            for _b, bd, _q in self.out(epg, "IN_BD")
                            if self.has(bd, "BridgeDomain")
                            for _v, v, _s in self.out(bd, "IN_VRF")
                            if self.has(v, "VrfInstance")
                        ]
                        for v in _each(tables):
                            hits.append(
                                {
                                    "ip": ip,
                                    "epg_uid": epg,
                                    "epg_name": self.get(epg, "name"),
                                    "vrf_uid": v,
                                    "pc_enf_pref": self.get(v, "pc_enf_pref"),
                                    "contract_bypass": self.get(v, "contract_bypass"),
                                }
                            )
            rows += hits or [
                {
                    "ip": ip,
                    **dict.fromkeys(("epg_uid", "epg_name", "vrf_uid", "pc_enf_pref", "contract_bypass")),
                }
            ]
        return rows

    def _walk_pattern(self, dev: str, pattern: str, label: str) -> set[str]:
        """The nodes `g` a GATE_BINDINGS fragment such as
        `(d)<-[e1:ON]-(:Interface)-[e2:ENFORCES]->(g)` reaches from the device `dev`."""
        steps = _STEP.findall(pattern.removeprefix("(d)"))
        if not pattern.startswith("(d)") or not steps:
            raise NotImplementedError(f"gate binding {pattern!r} is not modelled by TraceGraph")
        frontier = {dev}
        for left, types, right, var, node_label in steps:
            wanted = types.split("|")
            if (left, right) == ("-", "->"):
                reached = {e for n in frontier for _k, e, _p in self.out(n, *wanted)}
            elif (left, right) == ("<-", "-"):
                reached = {s for n in frontier for _k, s, _p in self.into(n, *wanted)}
            else:
                raise NotImplementedError(f"gate binding {pattern!r} is not modelled by TraceGraph")
            need = label if var == "g" else node_label
            frontier = {n for n in reached if not need or self.has(n, need)}
        return frontier

    def _gate_safeguard(self, devs: list[str], snap: int) -> list[dict[str, Any]]:
        gates = {
            g
            for dev in devs
            if self.has(dev, "Device")
            for label, patterns in gate_binding_patterns().items()
            for pattern in patterns
            for g in self._walk_pattern(dev, pattern, label)
        }
        rows = []
        for g in sorted(gates):
            kinds = sorted(self.nodes[g]["labels"] - _META_LABELS)
            if len(kinds) != 1:
                raise NotImplementedError(
                    f"gate {g} carries labels {kinds}; its kind is not modelled by TraceGraph"
                )
            rows.append({"uid": g, "name": self.get(g, "name"), "kind": kinds[0]})
        return rows
