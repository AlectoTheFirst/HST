from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from hst.core import uid
from hst.core.ipenc import prefix_bounds
from hst.core.l3domain import DomainPolicy, Vrf, display_name
from hst.core.l3domain import resolve as l3d_resolve
from hst.core.labels import check_identity
from hst.core.model import Batch, NodeRecord, RelRecord


def offset_paged[PageT](fetch: Callable[[int], tuple[PageT, int | None]]) -> list[PageT]:
    pages: list[PageT] = []
    offset: int | None = 0
    while offset is not None:
        page, offset = fetch(offset)
        pages.append(page)
    return pages


def renew_deadline(now: float, lifetime: Any, *, default: int, fraction: float, floor: int = 0) -> float:
    """`lifetime` is the server-reported validity in seconds."""
    try:
        seconds = int(lifetime or default)
    except (TypeError, ValueError):
        seconds = default
    return now + max(floor, seconds) * fraction


def without_keys(value: Any, words: tuple[str, ...]) -> Any:
    """Returns `value` without every mapping key that contains one of `words`,
    at any depth. The key is compared in lower case. A collector calls the
    function on an answer that holds a secret before `fetch()` returns. This
    keeps the secret out of the raw snapshot."""
    if isinstance(value, Mapping):
        return {
            k: without_keys(v, words) for k, v in value.items() if not any(w in str(k).lower() for w in words)
        }
    if isinstance(value, list):
        return [without_keys(v, words) for v in value]
    return value


def parse_pairs(text: str, *, field: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError(f"{field} line {number} must be `<key>, <value>`; got {line!r}")
        key = parts[0]
        if key in out:
            raise ValueError(f"{field} line {number} repeats {key!r}")
        out[key] = parts[1]
    return out


def listify(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def canonical_mac(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return uid.norm_mac(value)
    except ValueError:
        return None


class GraphBuilder:
    """`node` raises `IdentityCollision` for a second declaration with a different
    identity prop (core/labels.py `check_identity`)."""

    def __init__(self) -> None:
        self._nodes: dict[tuple[str, str], NodeRecord] = {}
        self._rels: dict[tuple[str, str, str, str], RelRecord] = {}
        self._identities: dict[str, dict[str, Any]] = {}

    def node(self, label: str, uid_: str, **props: Any) -> str:
        clean = {k: v for k, v in props.items() if v is not None}
        check_identity(self._identities, label, uid_, clean)
        rec = self._nodes.get((label, uid_))
        if rec is None:
            self._nodes[(label, uid_)] = NodeRecord(label=label, uid=uid_, props=clean)
        else:
            rec.props.update(clean)
        return uid_

    def props(self, label: str, uid_: str) -> dict[str, Any]:
        """A copy of the properties collected for one node. The dict is empty
        for a node that was not declared. `node` adds properties."""
        rec = self._nodes.get((label, uid_))
        return dict(rec.props) if rec else {}

    def rel(
        self,
        rtype: str,
        start_label: str,
        start_uid: str,
        end_label: str,
        end_uid: str,
        key: dict[str, Any] | None = None,
        **props: Any,
    ) -> None:
        dedup = (rtype, start_uid, end_uid, json.dumps(key or {}, sort_keys=True))
        clean = {k: v for k, v in props.items() if v is not None}
        rec = self._rels.get(dedup)
        if rec is None:
            self._rels[dedup] = RelRecord.model_validate(
                {
                    "type": rtype,
                    "start": [start_label, start_uid],
                    "end": [end_label, end_uid],
                    "key": key or {},
                    "props": clean,
                }
            )
        else:
            rec.props.update(clean)

    def batch(self, source: str, scope: str) -> Batch:
        batch = Batch(
            source=source, scope=scope, nodes=list(self._nodes.values()), rels=list(self._rels.values())
        )
        batch.validate_registry()
        return batch


@dataclass(frozen=True)
class OverlayEnd:
    """One end of an `OverlayConnection`, as `overlay_connection` takes it.

    `key` is the part of the connection identity for this end. Both sides of
    the connection compute the same value for it (a node uid, a tunnel address,
    an address and port). It is a local discriminator when the far side is not
    known. `label` and `uid` identify the node of the `BETWEEN` edge. An end
    with no node (a WireGuard peer with no address) has no `BETWEEN` edge.
    `reported` is true for the end whose configuration this batch read."""

    key: str
    label: str | None
    uid: str | None
    role: str
    reported: bool = False


def overlay_connection(
    b: GraphBuilder,
    technology: str,
    ends: tuple[OverlayEnd, OverlayEnd],
    tunnels: list[str],
    *,
    name: str,
) -> str | None:
    """Writes one `OverlayConnection` between 2 ends with a `REALIZED_BY` edge
    to each tunnel in `tunnels`. Returns None when `tunnels` is empty.

    The connection is undirected. Its uid is built from the technology and the
    2 end keys in sorted order (`uid.overlay_connection`). End `a` is the end
    with the lower key. 2 batches that each read one side of a connection
    write the same node with the same end letters. `observed_from` lists the
    ends that this batch reported. Each `BETWEEN` edge has `end`, `role` and
    `reported`. When 2 batches write one connection, the reasoner rule
    `overlay-connection-ends` sets `observed_from` and `name` from the
    reported ends of both. A connection has no bandwidth property and no QoS
    property."""
    if not tunnels:
        return None
    a, z = sorted(ends, key=lambda end: end.key)
    conn = b.node(
        "OverlayConnection",
        uid.overlay_connection(technology, a.key, z.key),
        kind="tunnel",
        technology=technology,
        name=name,
        observed_from=[letter for letter, end in (("a", a), ("b", z)) if end.reported],
    )
    for letter, end in (("a", a), ("b", z)):
        if end.label and end.uid:
            b.rel(
                "BETWEEN",
                "OverlayConnection",
                conn,
                end.label,
                end.uid,
                end=letter,
                role=end.role,
                reported=end.reported,
            )
    for tu in tunnels:
        b.rel("REALIZED_BY", "OverlayConnection", conn, "Tunnel", tu)
    return conn


class VrfDomains:
    """`add` resolves the domain from the policy scope and the VRF name alone."""

    def __init__(
        self,
        b: GraphBuilder,
        device_uid: str,
        policy: DomainPolicy,
        make_uid,
        *,
        owner_device_uid: str | None = None,
    ) -> None:
        self._b = b
        self._device = device_uid
        self._owner = owner_device_uid or device_uid
        self._policy = policy
        self._make_uid = make_uid
        self.uids: dict[str, str] = {}
        self.domains: dict[str, str] = {}

    def add(
        self,
        name: str,
        *,
        rd: str | None = None,
        rt_import: tuple[str, ...] = (),
        rt_export: tuple[str, ...] = (),
        table_id: str | None = None,
        is_global: bool | None = None,
        **props: Any,
    ) -> str:
        if name in self.uids:
            return self.uids[name]
        vu = self._b.node(
            "VrfInstance",
            self._make_uid(name),
            name=name,
            rd=rd,
            table_id=table_id or name,
            is_global=is_global,
            **props,
        )
        self._b.rel("OWNED_BY", "VrfInstance", vu, "Device", self._owner)
        for rt in sorted({r for r in rt_import if r}):
            ru = self._b.node("RouteTarget", uid.route_target(rt), value=rt)
            self._b.rel("IMPORTS", "VrfInstance", vu, "RouteTarget", ru)
        for rt in sorted({r for r in rt_export if r}):
            ru = self._b.node("RouteTarget", uid.route_target(rt), value=rt)
            self._b.rel("EXPORTS", "VrfInstance", vu, "RouteTarget", ru)
        domain = l3d_resolve(Vrf(device=self._device, name=name), self._policy)
        du = self._b.node("RoutingDomain", uid.routing_domain(domain), name=display_name(domain))
        self._b.rel("MEMBER_OF", "VrfInstance", vu, "RoutingDomain", du, basis="declared")
        self.uids[name] = vu
        self.domains[name] = domain
        return vu


def connected_address(
    b: GraphBuilder,
    address: str,
    *,
    anchor: str,
    dom: str,
    vrf_uid: str | None = None,
    ip_props: dict[str, Any] | None = None,
    prefix_props: dict[str, Any] | None = None,
) -> tuple[str, str | None]:
    """`anchor` is the owning VrfInstance uid, an l2seg uid or a source-scoped domain string."""
    iface = ipaddress.ip_interface(address)
    ipu = b.node(
        "IpAddress",
        uid.ip(anchor, str(iface.ip)),
        ip=str(iface.ip),
        af=iface.version,
        l3dom=dom,
        anchor=anchor,
        **(ip_props or {}),
    )
    if iface.network.prefixlen >= iface.network.max_prefixlen:
        return ipu, None
    pfu = b.node(
        "Prefix",
        uid.prefix(anchor, str(iface.network)),
        cidr=str(iface.network),
        af=iface.version,
        l3dom=dom,
        anchor=anchor,
        kind="connected",
        **(prefix_props or {}),
    )
    b.rel("IN", "IpAddress", ipu, "Prefix", pfu)
    if vrf_uid:
        # A BGP network or aggregate statement for the same prefix is a second
        # ORIGINATES edge.
        b.rel(
            "ORIGINATES", "VrfInstance", vrf_uid, "Prefix", pfu, key={"proto": "connected"}, proto="connected"
        )
    return ipu, pfu


def lpm_columns(prefix: str) -> dict[str, Any]:
    try:
        lo, hi, plen, af = prefix_bounds(prefix)
    except ValueError:
        return {}
    return {"af": af, "prefixlen": plen, "lo": lo, "hi": hi}


def as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


_ASN_RE = re.compile(r"(\d+)(?:\.(\d+))?")


def parse_asn(text: str) -> int | None:
    """Parses a BGP AS number in asplain (`4200000001`) or asdot
    (`64086.59904`) notation to the asplain int. RFC 5396 defines asdot
    `high.low` as high * 65536 + low. Returns None for any other text and for
    a value outside 32 bits."""
    m = _ASN_RE.fullmatch(text.strip())
    if not m:
        return None
    if m[2] is None:
        value = int(m[1])
        return value if value <= 0xFFFFFFFF else None
    high, low = int(m[1]), int(m[2])
    return high * 65536 + low if high <= 0xFFFF and low <= 0xFFFF else None


def parse_cluster_id(text: Any) -> str | None:
    """Returns a BGP route-reflector cluster id in dotted-quad form. The
    cluster list of a route and a router id are compared in this form. Every
    platform accepts the dotted quad (`10.0.0.1`) and the 32-bit number
    (`167772161`) for the cluster id. Returns None for any other text."""
    value = str(text or "").strip()
    try:
        if value.isdigit():
            return str(ipaddress.IPv4Address(int(value)))
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        return None


# --- BGP multipath -------------------------------------------------------------

_MAXIMUM_PATHS_RE = re.compile(r"^maximum-paths(?:\s+(ebgp|ibgp|eibgp|mixed))?(?:\s+unequal-cost)?\s+(\d+)\b")


def parse_maximum_paths(line: str) -> list[tuple[str, int]]:
    """Returns the (session type, path count) pairs of one Cisco
    `maximum-paths` line. `maximum-paths N` (IOS-XE and NX-OS) and
    `maximum-paths ebgp N` (IOS-XR) give eBGP. `maximum-paths ibgp
    [unequal-cost] N` gives iBGP. `maximum-paths eibgp N` and `maximum-paths
    mixed N` give both. Any other line and a count below 1 give an empty list."""
    m = _MAXIMUM_PATHS_RE.match(line.strip())
    if m is None or int(m[2]) < 1:
        return []
    kinds = {"ibgp": ("ibgp",), "eibgp": ("ebgp", "ibgp"), "mixed": ("ebgp", "ibgp")}.get(
        m[1] or "", ("ebgp",)
    )
    return [(kind, int(m[2])) for kind in kinds]


def bgp_multipath_props(maximum_paths: Mapping[str, int], relax: bool) -> dict[str, Any]:
    """The RoutingProcess properties for the multipath configuration of a BGP
    process. `maximum_paths` has keys of the form `<ebgp|ibgp>_v<4|6>`. Each
    count becomes the property `maximum_paths_<key>`. `multipath_relax` is set
    when `bestpath as-path multipath-relax` is configured.
    `multipath_config_recorded` is true for a process whose whole
    configuration the parse read. For such a process, a count that the
    configuration does not state has the platform default
    (simul/platforms.py `BGP_MAXIMUM_PATHS`)."""
    return {
        "multipath_config_recorded": True,
        "multipath_relax": True if relax else None,
        **{f"maximum_paths_{key}": count for key, count in sorted(maximum_paths.items())},
    }


# --- BGP aggregate-address options ---------------------------------------------

_AGGREGATE_FLAGS = frozenset({"summary-only", "as-set"})


def parse_aggregate_options(
    prefix: str | None, options: list[str], *, policy_keyword: str = "attribute-map"
) -> tuple[dict[str, Any], str | None]:
    tokens = list(options)
    recorded: dict[str, Any] = {
        "prefix": prefix,
        "summary_only": "summary-only" in tokens,
        "as_set": "as-set" in tokens,
    }
    if policy_keyword in tokens and tokens.index(policy_keyword) + 1 < len(tokens):
        at = tokens.index(policy_keyword)
        recorded["attribute_map"] = tokens[at + 1]
        del tokens[at : at + 2]
    unsupported = [token for token in tokens if token not in _AGGREGATE_FLAGS]
    if not unsupported:
        return recorded, None
    recorded["unsupported_options"] = unsupported
    return recorded, f"aggregate-address {prefix} options {' '.join(unsupported)} are not modeled"
