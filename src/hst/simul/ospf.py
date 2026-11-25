"""OSPF route calculation over an observed link-state database.

The input is the `ospf_lsdb` side-store rows of one device, one routing
context and one process, in the shape that `core/ospfsource.py` reads back.
`lsa_type` is router, network, summary, asbr-summary, external or
nssa-external. The `links` of a router LSA are structs of link_type, link_id,
link_data and metric. A network LSA has `attached_routers` and `mask`. The
types that describe a prefix have `mask` and `metric`. The external types have
`metric_type` and `forwarding_address`. The output is the routes that the OSPF
process of the device offers its main RIB when the database has settled. Each
prefix has a path type, a metric and a set of next hops.

The calculation follows RFC 2328 section 16 with the RFC 3101 changes for
not-so-stubby areas. The root is the router id of the calculating router.

  * 16.1 runs Dijkstra per attached area over router and network LSAs. A
    point-to-point or virtual link leads to a router vertex. A transit link
    leads to a network vertex. A vertex is entered only when its own LSA links
    back. At equal cost network vertices leave the candidate list before
    router vertices. The second stage adds the stub links and the prefixes of
    the transit networks. Next hops follow 16.1.1. Over a point-to-point link
    the next hop is the address of the neighbor from its link back. Over a
    directly attached transit network it is the address of the neighbor on
    the segment. Any other vertex takes the next hops of its parent.
  * 16.2 computes inter-area routes from summary LSAs (type 3) and
    ASBR-summary LSAs (type 4). The cost is the intra-area distance to the
    advertising area border router plus the metric of the LSA. An area border
    router examines only the summary LSAs of the backbone. A router with no
    active backbone attachment examines the summary LSAs of every attached
    area (RFC 3509, the default interpretation of Cisco and FRR). A summary
    LSA that the calculating router originates into the same area for the
    same prefix marks an active area range. The copy of another border router
    is then ignored (16.2 step 2).
  * 16.4 and RFC 3101 2.5 compute AS-external routes from type 5 LSAs and, in
    each attached NSSA, type 7 LSAs. A zero forwarding address selects the
    path to the advertising ASBR. A non-zero forwarding address is looked up
    in the intra-area and inter-area routes. The LSA is not used when no such
    route covers the address. A type 1 external costs the internal distance
    plus the LSA metric. A type 2 external costs the LSA metric, with the
    internal distance as the tie-break. The per-platform RFC 1583 setting
    (`platforms.ospf_rfc1583_compatible`) decides whether an intra-area path
    to the ASBR through a non-backbone area is preferred over a cheaper path
    through the backbone (16.4.1). The default route of a stub area is a
    summary LSA and the default route of an NSSA is a type 7 LSA. Both are
    computed like any other LSA of their type.

The path types rank intra-area, inter-area, type 1 external, type 2 external.
A cheaper path of a worse-ranked type does not displace a path of a
better-ranked type.

The rows do not hold the following:

  * The B and E bits of a router LSA (border and boundary router). Every
    router on a tree gets a router entry. A router that advertises an LSA is
    found with or without the bit.
  * The options field with the P bit of a type 7 LSA. A type 7 LSA with a
    non-zero forwarding address is treated as translatable. RFC 3101 2.4 makes
    a non-zero address a precondition of the bit. The bit decides only which
    of 2 LSAs that describe the same destination at the same cost through the
    same forwarding address is credited (RFC 3101 2.5 step 6e). Both LSAs give
    the same next hop.
  * The area types. An area that holds a type 7 LSA is an NSSA. Any other
    area takes its type from the `area_types` of the caller (`OspfArea.type`
    in the graph). An area that is not in `area_types` is normal.
  * Virtual links. A virtual link of another router is a plain backbone link.
    A virtual link of the calculating router needs the paths of the transit
    area (16.3), which are not computed. It is reported as not modeled and
    skipped.

An LSA that the calculation needs and the database does not hold is a gap of
kind `not-observed`. This applies to the router LSA of a router that a link or
a summary refers to, the network LSA that a transit link points at, and the
router LSA of the calculating router. No route is inferred for a gap. The
observed rows are read once and copied. A change (an interface cost, a lost
adjacency, an interface that moves area) returns a new `LsdbModel` and leaves
the rows and the source model unchanged.

Validation compares the computed routes with the observed `rib` rows of the
same device and context whose protocol is OSPF. A prefix is `validated` when
the 2 sides agree. A prefix is a `mismatch` and a model error in the sink when
the 2 sides disagree, or when only one side holds it and the database is
complete. A prefix is `not-observed` when the device holds it and the
calculation could not produce it from a database with gaps, or when the device
installed it from another protocol.

The order is fixed. LSAs are ordered by area, type, link-state id and
advertising router. Candidates are ordered by cost, vertex kind and id. Routes
are ordered by prefix. Next hops are ordered by address. Repeated runs over
the same rows produce identical output.
"""

from __future__ import annotations

import heapq
import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from . import platforms
from .errors import ErrorSink

BACKBONE = "0.0.0.0"  # noqa: S104 - the OSPF backbone area id
# A zero forwarding address means "forward to the advertising router itself"
# (RFC 2328 16.4 step 3).
NO_FORWARDING_ADDRESS = "0.0.0.0"  # noqa: S104 - an LSA field value
# The metric that means "unreachable" (RFC 2328 A.4.4 and A.4.5).
LS_INFINITY = 0xFFFFFF
# An LSA whose age reached MaxAge is being flushed and is not used (RFC 2328 appendix B).
MAX_AGE = 3600

ROUTER = "router"
NETWORK = "network"
SUMMARY = "summary"
ASBR_SUMMARY = "asbr-summary"
EXTERNAL = "external"
NSSA_EXTERNAL = "nssa-external"
LSA_TYPES = frozenset({ROUTER, NETWORK, SUMMARY, ASBR_SUMMARY, EXTERNAL, NSSA_EXTERNAL})
_AREA_SCOPED = frozenset({ROUTER, NETWORK, SUMMARY, ASBR_SUMMARY, NSSA_EXTERNAL})

POINT_TO_POINT = "point-to-point"
TRANSIT = "transit"
STUB = "stub"
VIRTUAL = "virtual"
# The link types of RFC 2328 A.4.2 by number, and their words in the side store.
_LINK_TYPES = {
    "1": POINT_TO_POINT,
    "p2p": POINT_TO_POINT,
    "point-to-point": POINT_TO_POINT,
    "point_to_point": POINT_TO_POINT,
    "2": TRANSIT,
    "transit": TRANSIT,
    "3": STUB,
    "stub": STUB,
    "4": VIRTUAL,
    "virtual": VIRTUAL,
}

INTRA_AREA = "intra-area"
INTER_AREA = "inter-area"
EXTERNAL_1 = "external-1"
EXTERNAL_2 = "external-2"
# The path types in order of preference, best first (RFC 2328 section 11).
PATH_PREFERENCE = {INTRA_AREA: 0, INTER_AREA: 1, EXTERNAL_1: 2, EXTERNAL_2: 3}

NORMAL = "normal"
STUB_AREA = "stub"
NSSA = "nssa"

VALIDATED = "validated"
MISMATCH = "mismatch"
NOT_OBSERVED = "not-observed"

LsaKey = tuple[str | None, str, str, str]


# --- helpers ------------------------------------------------------------------------


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _network(lsid: str | None, mask: str | None) -> str | None:
    """Return `lsid` under `mask` as a prefix string, or None when either is
    missing or does not parse. The link-state id of a summary or external LSA
    can have host bits set (RFC 2328 appendix E). The mask clears them."""
    if not lsid or not mask:
        return None
    try:
        return str(ipaddress.IPv4Network((lsid, mask), strict=False))
    except ValueError:
        return None


def _contains(net_id: str | None, mask: str | None, address: str | None) -> bool:
    prefix = _network(net_id, mask)
    if prefix is None or not address:
        return False
    try:
        return ipaddress.IPv4Address(address) in ipaddress.IPv4Network(prefix)
    except ValueError:
        return False


def _addr_key(value: str | None) -> tuple[int, int, str]:
    """A sort key that orders dotted quads numerically and anything else after
    them."""
    if value is None:
        return (2, 0, "")
    try:
        return (0, int(ipaddress.IPv4Address(value)), "")
    except ValueError:
        return (1, 0, value)


def _area_key(area: str | None) -> tuple[int, int, str]:
    if area is None:
        return (1, 0, "")
    try:
        return (0, int(ipaddress.IPv4Address(area)), area)
    except ValueError:
        return (0, 1 << 32, area)


def _prefix_key(prefix: str) -> tuple[int, int]:
    net = ipaddress.IPv4Network(prefix)
    return (int(net.network_address), net.prefixlen)


# --- the database model -------------------------------------------------------------


@dataclass(frozen=True)
class Link:
    """One link of a router LSA (RFC 2328 A.4.2). `link_data` is the router's
    own interface address on a point-to-point, transit or virtual link and
    the network mask on a stub link."""

    link_type: str
    link_id: str
    link_data: str | None
    metric: int


@dataclass(frozen=True)
class Lsa:
    """One LSA. A change replaces the LSA in a copied model."""

    lsa_type: str
    lsid: str
    adv_router: str
    area: str | None = None
    seq: int | None = None
    age: int | None = None
    metric: int | None = None
    links: tuple[Link, ...] = ()
    attached_routers: tuple[str, ...] = ()
    mask: str | None = None
    forwarding_address: str | None = None
    metric_type: int | None = None

    @property
    def key(self) -> LsaKey:
        return (self.area, self.lsa_type, self.lsid, self.adv_router)

    @property
    def expired(self) -> bool:
        return self.age is not None and self.age >= MAX_AGE

    @property
    def prefix(self) -> str | None:
        """The prefix a network, summary or external LSA describes."""
        return _network(self.lsid, self.mask)

    @property
    def sort_key(self) -> tuple[tuple[int, int, str], str, tuple[int, int, str], tuple[int, int, str]]:
        return (_area_key(self.area), self.lsa_type, _addr_key(self.lsid), _addr_key(self.adv_router))

    def describe(self) -> str:
        where = f" in area {self.area}" if self.area is not None else ""
        return f"{self.lsa_type} LSA {self.lsid} from {self.adv_router}{where}"


def _fresher(a: Lsa, b: Lsa) -> bool:
    """Return whether `a` is a newer instance than `b` (RFC 2328 13.1). The
    higher sequence number is newer. At equal sequence numbers the lower age
    is newer."""
    return ((a.seq if a.seq is not None else -1), -(a.age or 0)) > (
        (b.seq if b.seq is not None else -1),
        -(b.age or 0),
    )


def _links_from_row(raw: Any, subject: str, errors: ErrorSink) -> list[Link]:
    links: list[Link] = []
    for item in raw or ():
        if not isinstance(item, Mapping):
            errors.report("malformed-lsa", f"{subject}: a link that is not a struct was left out", subject)
            continue
        raw_type = str(item.get("link_type") or "").strip().lower()
        link_type = _LINK_TYPES.get(raw_type)
        link_id = _text(item.get("link_id"))
        link_data = _text(item.get("link_data"))
        metric = _int(item.get("metric"))
        if link_type is None or not link_id:
            errors.report(
                "malformed-lsa",
                f"{subject}: a link with type {item.get('link_type')!r} and id {link_id!r} was left out",
                subject,
            )
            continue
        if metric is None:
            errors.report(
                "malformed-lsa", f"{subject}: the {link_type} link to {link_id} has no metric", subject
            )
            continue
        if link_type == STUB and _network(link_id, link_data) is None:
            errors.report("malformed-lsa", f"{subject}: the stub link {link_id} has no usable mask", subject)
            continue
        links.append(Link(link_type, link_id, link_data, metric))
    return links


def _lsa_from_row(row: Mapping[str, Any], errors: ErrorSink) -> Lsa | None:
    lsa_type = str(row.get("lsa_type") or "").strip().lower()
    lsid = _text(row.get("lsid"))
    adv_router = _text(row.get("adv_router"))
    area = _text(row.get("area"))
    subject = f"{lsa_type or '?'} LSA {lsid or '?'} from {adv_router or '?'}"
    if lsa_type not in LSA_TYPES:
        errors.report(
            "unknown-lsa-type",
            f"{subject}: type {row.get('lsa_type')!r} is outside the ospf_lsdb vocabulary; left out",
            subject,
        )
        return None
    if lsa_type == ROUTER and lsid is None and adv_router is not None:
        lsid = adv_router
    if not lsid or not adv_router:
        errors.report(
            "malformed-lsa", f"{subject}: no link-state id or no advertising router; left out", subject
        )
        return None
    if lsa_type == ROUTER and lsid != adv_router:
        errors.report(
            "malformed-lsa",
            f"{subject}: a router LSA's link-state id is its advertising router; left out",
            subject,
        )
        return None
    if lsa_type in _AREA_SCOPED and area is None:
        errors.report("malformed-lsa", f"{subject}: an area-scoped LSA with no area; left out", subject)
        return None
    if lsa_type == EXTERNAL:
        # An external LSA is flooded domain-wide (RFC 2328 12.4.4). An area
        # that a platform prints beside it is the area of the command.
        area = None
    links = tuple(_links_from_row(row.get("links"), subject, errors)) if lsa_type == ROUTER else ()
    attached = (
        tuple(str(r).strip() for r in (row.get("attached_routers") or ()) if _text(r))
        if lsa_type == NETWORK
        else ()
    )
    return Lsa(
        lsa_type=lsa_type,
        lsid=lsid,
        adv_router=adv_router,
        area=area,
        seq=_int(row.get("seq")),
        age=_int(row.get("age")),
        metric=_int(row.get("metric")),
        links=links,
        attached_routers=attached,
        mask=_text(row.get("mask")),
        forwarding_address=_text(row.get("forwarding_address")),
        metric_type=_int(row.get("metric_type")),
    )


def _link_of_interface(link: Link, address: str) -> bool:
    """Return whether the interface at `address` originates the link. A
    point-to-point, transit or virtual link has the address as its link data.
    The stub link of the subnet of the interface contains the address."""
    if link.link_type == STUB:
        return _contains(link.link_id, link.link_data, address)
    return link.link_data == address


def _to_stub(link: Link, net: Lsa) -> Link | None:
    """The stub link a router advertises for a segment it has no adjacency on
    (RFC 2328 12.4.1.2), in place of its transit link to the network."""
    prefix = net.prefix
    if prefix is None:
        return None
    network = ipaddress.IPv4Network(prefix)
    return Link(STUB, str(network.network_address), str(network.netmask), link.metric)


@dataclass
class LsdbModel:
    """The link-state database of one process.

    `from_rows` builds it from the side-store rows and copies every value.
    Every change method returns a new model and leaves this model unchanged.

    `area_types` maps each area to its type as the caller states it
    (`OspfArea.type` in the graph). `area_type` reads it for an area with no
    type 7 LSA.
    """

    lsas: dict[LsaKey, Lsa] = field(default_factory=dict)
    area_types: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_rows(
        cls,
        rows: Iterable[Mapping[str, Any]],
        *,
        area_types: Mapping[str, str] | None = None,
        errors: ErrorSink | None = None,
    ) -> LsdbModel:
        """Build the model from rows in the `ospf_lsdb` column shape, for one
        process. A row outside the LSA vocabulary or without the fields that
        its type needs is reported and left out. Of 2 instances of one LSA the
        newer is kept (RFC 2328 13.1)."""
        errors = errors or ErrorSink()
        model = cls(area_types={str(k): str(v).strip().lower() for k, v in (area_types or {}).items()})
        for row in rows:
            lsa = _lsa_from_row(row, errors)
            if lsa is None:
                continue
            held = model.lsas.get(lsa.key)
            if held is None or _fresher(lsa, held):
                model.lsas[lsa.key] = lsa
        return model

    def copy(self) -> LsdbModel:
        return LsdbModel(lsas=dict(self.lsas), area_types=dict(self.area_types))

    def areas(self) -> list[str]:
        return sorted({key[0] for key in self.lsas if key[0] is not None}, key=_area_key)

    def of_type(self, lsa_type: str, area: str | None = None) -> list[Lsa]:
        """The LSAs of one type in one area (None for the domain-wide external
        LSAs), in LSA order."""
        return sorted(
            (lsa for lsa in self.lsas.values() if lsa.lsa_type == lsa_type and lsa.area == area),
            key=lambda lsa: lsa.sort_key,
        )

    def router_lsa(self, area: str, router_id: str) -> Lsa | None:
        return self.lsas.get((area, ROUTER, router_id, router_id))

    def area_type(self, area: str) -> str:
        """Return `normal`, `stub` or `nssa`. An area that holds a type 7 LSA
        is an NSSA. Any other area takes its type from `area_types`. An area
        that is not in `area_types` is normal."""
        if any(key[0] == area and key[1] == NSSA_EXTERNAL for key in self.lsas):
            return NSSA
        known = self.area_types.get(area)
        return known if known in (NORMAL, STUB_AREA, NSSA) else NORMAL

    # --- changes: each returns a new model ------------------------------------------

    def with_interface_cost(
        self, router_id: str, address: str, cost: int, errors: ErrorSink | None = None
    ) -> LsdbModel:
        """Return a model in which the links that `router_id` originates from
        the interface at `address` have the metric `cost`.

        The links are the point-to-point, transit or virtual link over the
        interface and the stub link of its subnet, in each area that holds
        them.
        """
        new = self.copy()
        matched = False
        for lsa in self._router_lsas(router_id):
            links = []
            for link in lsa.links:
                if _link_of_interface(link, address):
                    matched = True
                    links.append(replace(link, metric=cost))
                else:
                    links.append(link)
            if matched:
                new.lsas[lsa.key] = replace(lsa, links=tuple(links))
        if not matched and errors is not None:
            errors.report(
                "ospf-change-no-effect",
                f"router {router_id} advertises no link for interface address {address}; "
                "the cost change altered nothing",
                f"{router_id}/{address}",
            )
        return new

    def without_adjacency(self, router_a: str, router_b: str, errors: ErrorSink | None = None) -> LsdbModel:
        """Return a model without the adjacency between 2 routers.

        Over a point-to-point or virtual link each end drops its link to the
        other and keeps the stub link of the subnet. On a transit network the
        router that is not the designated router leaves the network LSA and
        advertises the segment as a stub link (RFC 2328 12.4.1.2). A
        designated router with no adjacent neighbor left withdraws the network
        LSA and advertises the segment as a stub link (12.4.2). A transit
        network on which neither router is the designated router is unchanged.
        """
        new = self.copy()
        changed = False
        for area in self.areas():
            lsa_a = self.router_lsa(area, router_a)
            lsa_b = self.router_lsa(area, router_b)
            if lsa_a is None or lsa_b is None:
                continue
            for lsa, other in ((lsa_a, router_b), (lsa_b, router_a)):
                kept = tuple(
                    link
                    for link in lsa.links
                    if not (link.link_type in (POINT_TO_POINT, VIRTUAL) and link.link_id == other)
                )
                if len(kept) != len(lsa.links):
                    new.lsas[lsa.key] = replace(lsa, links=kept)
                    changed = True
            for net in self.of_type(NETWORK, area):
                if router_a not in net.attached_routers or router_b not in net.attached_routers:
                    continue
                if net.adv_router == router_a:
                    leaving = router_b
                elif net.adv_router == router_b:
                    leaving = router_a
                else:
                    continue
                new._detach(net, leaving)
                changed = True
        if not changed and errors is not None:
            errors.report(
                "ospf-change-no-effect",
                f"routers {router_a} and {router_b} share no link whose loss changes the database",
                f"{router_a}/{router_b}",
            )
        return new

    def with_interface_in_area(
        self, router_id: str, address: str, area: str, errors: ErrorSink | None = None
    ) -> LsdbModel:
        """Return a model in which the interface at `address` on `router_id` is
        in `area`.

        The links that the interface originates move from the router LSA in
        their current area to the router LSA in `area`. The router LSA in
        `area` is created when the router has none there. A router LSA with no
        link left is removed. A network LSA that the router originates as the
        designated router of the segment moves with the links. Each far end of
        the segment moves with its own call. Before that call the adjacency
        has no neighbor in `area`, and the calculation reports the missing LSA
        as a gap.
        """
        new = self.copy()
        moved: list[Link] = []
        for lsa in self._router_lsas(router_id):
            if lsa.area == area:
                continue
            taken = [link for link in lsa.links if _link_of_interface(link, address)]
            if not taken:
                continue
            moved.extend(taken)
            stay = tuple(link for link in lsa.links if not _link_of_interface(link, address))
            if stay:
                new.lsas[lsa.key] = replace(lsa, links=stay)
            else:
                del new.lsas[lsa.key]
            for net in self.of_type(NETWORK, lsa.area):
                if net.lsid == address and net.adv_router == router_id:
                    del new.lsas[net.key]
                    relocated = replace(net, area=area)
                    new.lsas[relocated.key] = relocated
        if not moved:
            if errors is not None:
                errors.report(
                    "ospf-change-no-effect",
                    f"router {router_id} advertises no link for interface address {address} "
                    f"outside area {area}; nothing moved",
                    f"{router_id}/{address}",
                )
            return new
        target = new.router_lsa(area, router_id) or Lsa(ROUTER, router_id, router_id, area)
        new.lsas[target.key] = replace(target, links=target.links + tuple(moved))
        return new

    def _router_lsas(self, router_id: str) -> list[Lsa]:
        return sorted(
            (lsa for lsa in self.lsas.values() if lsa.lsa_type == ROUTER and lsa.adv_router == router_id),
            key=lambda lsa: lsa.sort_key,
        )

    def _detach(self, net: Lsa, leaving: str) -> None:
        """Detach `leaving` from `net` in this model, in place."""
        assert net.area is not None  # noqa: S101 - a network LSA is area-scoped by construction
        leaver = self.router_lsa(net.area, leaving)
        if leaver is not None:
            self.lsas[leaver.key] = replace(leaver, links=_restubbed(leaver.links, net))
        remaining = tuple(r for r in net.attached_routers if r != leaving)
        if len(remaining) >= 2:
            self.lsas[net.key] = replace(net, attached_routers=remaining)
            return
        self.lsas.pop(net.key, None)
        dr = self.router_lsa(net.area, net.adv_router)
        if dr is not None:
            self.lsas[dr.key] = replace(dr, links=_restubbed(dr.links, net))


def _restubbed(links: tuple[Link, ...], net: Lsa) -> tuple[Link, ...]:
    out: list[Link] = []
    for link in links:
        if link.link_type == TRANSIT and link.link_id == net.lsid:
            stub = _to_stub(link, net)
            if stub is not None:
                out.append(stub)
        else:
            out.append(link)
    return tuple(out)


# --- the calculation ----------------------------------------------------------------


@dataclass(frozen=True)
class OspfRoute:
    """One destination of the OSPF routing table (RFC 2328 section 11) as the
    process offers it to the main RIB.

    `metric` is the route metric that the platform shows. It is the total
    cost for an intra-area, inter-area or type 1 external path and the metric
    of the LSA for a type 2 external path. `forward_metric` is the internal
    distance of an external path.
    """

    prefix: str
    path_type: str
    metric: int
    next_hops: tuple[str, ...]
    area: str | None = None
    advertising_router: str | None = None
    forward_metric: int | None = None
    lsa_type: str | None = None


@dataclass
class OspfCalculation:
    """The output of the calculation.

    It holds the routes, the cost to every router that the calculating router
    can place (keyed by area and router id), the LSAs that the calculation
    needed and the database did not hold, and every model error of the run.
    """

    router_id: str
    routes: list[OspfRoute] = field(default_factory=list)
    router_costs: dict[tuple[str, str], int] = field(default_factory=dict)
    gaps: list[dict[str, str | None]] = field(default_factory=list)
    model_errors: list[dict[str, str | None]] = field(default_factory=list)
    area_border_router: bool = False


class _Gaps:
    """The LSAs the calculation needed and the database did not hold, each
    listed once."""

    def __init__(self) -> None:
        self._held: dict[tuple[str, str, str | None], dict[str, str | None]] = {}

    def add(self, lsa_type: str, lsid: str, area: str | None, detail: str) -> None:
        key = (lsa_type, lsid, area)
        if key in self._held:
            return
        where = f" in area {area}" if area is not None else ""
        self._held[key] = {
            "kind": NOT_OBSERVED,
            "lsa_type": lsa_type,
            "lsid": lsid,
            "area": area,
            "detail": f"{lsa_type} LSA {lsid}{where} is not in the observed database: {detail}",
        }

    def as_list(self) -> list[dict[str, str | None]]:
        return [
            self._held[k] for k in sorted(self._held, key=lambda k: (k[0], _addr_key(k[1]), _area_key(k[2])))
        ]


class _Index:
    """Lookups over one model for the duration of one calculation."""

    def __init__(self, model: LsdbModel) -> None:
        self._routers: dict[tuple[str, str], Lsa] = {}
        self._networks: dict[tuple[str, str], Lsa] = {}
        self._by_type: dict[tuple[str | None, str], list[Lsa]] = {}
        for lsa in sorted(model.lsas.values(), key=lambda lsa: lsa.sort_key):
            self._by_type.setdefault((lsa.area, lsa.lsa_type), []).append(lsa)
            if lsa.area is None:
                continue
            if lsa.lsa_type == ROUTER:
                self._routers[(lsa.area, lsa.adv_router)] = lsa
            elif lsa.lsa_type == NETWORK:
                # During a DR change 2 designated routers have a network LSA for
                # one segment. The newer instance is used.
                held = self._networks.get((lsa.area, lsa.lsid))
                if held is None or _fresher(lsa, held):
                    self._networks[(lsa.area, lsa.lsid)] = lsa

    def router(self, area: str, router_id: str) -> Lsa | None:
        return self._routers.get((area, router_id))

    def network(self, area: str, lsid: str) -> Lsa | None:
        return self._networks.get((area, lsid))

    def of_type(self, lsa_type: str, area: str | None) -> list[Lsa]:
        return self._by_type.get((area, lsa_type), [])


@dataclass
class _Vertex:
    cost: int
    # The set is empty for the root and for a transit network that the root is attached to.
    next_hops: frozenset[str]


@dataclass
class _Entry:
    """An intra-area path to a prefix within one area."""

    cost: int
    next_hops: frozenset[str]
    # True for a subnet of the calculating router. The route is not offered to
    # the RIB, which holds it as a connected route. It resolves forwarding
    # addresses.
    direct: bool


@dataclass
class _Tree:
    routers: dict[str, _Vertex] = field(default_factory=dict)
    networks: dict[str, _Vertex] = field(default_factory=dict)
    prefixes: dict[str, _Entry] = field(default_factory=dict)


@dataclass
class _RouterPath:
    """A routing table entry of destination type "router" (RFC 2328 section
    11), associated with one area."""

    cost: int
    next_hops: frozenset[str]
    area: str
    path_type: str


@dataclass
class _NetEntry:
    path_type: str
    cost: int
    next_hops: frozenset[str]
    area: str | None
    advertising_router: str | None = None
    lsa_type: str | None = None
    forward_cost: int | None = None
    direct: bool = False
    # The intra-area path per area, for RFC 2328 16.4.1.
    by_area: dict[str, _Entry] = field(default_factory=dict)
    forwarding_address: str | None = None
    # The class of RFC 2328 16.4.1. The class is 0 when the path to the ASBR or
    # the forwarding address is intra-area through a non-backbone area, and 1
    # for any other path.
    asbr_class: int = 1


def _offer_prefix(
    prefixes: dict[str, _Entry], prefix: str, cost: int, next_hops: frozenset[str], direct: bool
) -> None:
    held = prefixes.get(prefix)
    if held is None:
        prefixes[prefix] = _Entry(cost, next_hops, direct)
        return
    if held.direct:
        if direct and cost < held.cost:
            prefixes[prefix] = _Entry(cost, next_hops, True)
        return
    if direct:
        prefixes[prefix] = _Entry(cost, next_hops, True)
    elif cost < held.cost:
        prefixes[prefix] = _Entry(cost, next_hops, False)
    elif cost == held.cost:
        held.next_hops = held.next_hops | next_hops


def _p2p_next_hops(
    root_lsa: Lsa, link: Link, backs: list[Link], area: str, errors: ErrorSink
) -> frozenset[str]:
    """Return the next hops over a point-to-point link from the calculating
    router (RFC 2328 16.1.1).

    The next hop is the interface address of the neighbor, from the link data
    of its link back. Parallel links are paired by the stub subnet that the
    calculating router advertises for its own end.
    """
    far = link.link_id
    addresses = sorted({b.link_data for b in backs if b.link_data}, key=_addr_key)
    if not addresses:
        errors.report(
            "ospf-next-hop-unresolved",
            f"router {far}'s link back to {root_lsa.adv_router} in area {area} carries no interface "
            "address; routes through that link were left out",
            f"{area}/{far}",
        )
        return frozenset()
    if len(addresses) > 1 and link.link_data:
        for stub in root_lsa.links:
            if stub.link_type == STUB and _contains(stub.link_id, stub.link_data, link.link_data):
                paired = [a for a in addresses if _contains(stub.link_id, stub.link_data, a)]
                if paired:
                    addresses = paired
                break
        if len(addresses) > 1:
            errors.report(
                "ospf-ambiguous-next-hop",
                f"routers {root_lsa.adv_router} and {far} share {len(addresses)} point-to-point links in "
                f"area {area} and no stub link pairs {link.link_data} with one of them; every far-end "
                "address was taken as a next hop",
                f"{area}/{far}",
            )
    for address in addresses:
        if address.startswith("0.0.0."):
            errors.report(
                "ospf-unnumbered-link",
                f"the link from {root_lsa.adv_router} to {far} in area {area} is unnumbered: its link "
                f"data {address} is an interface index, not a next-hop address",
                f"{area}/{far}",
            )
    return frozenset(addresses)


def _spf(index: _Index, area: str, root: str, gaps: _Gaps, errors: ErrorSink) -> _Tree:
    """RFC 2328 16.1 over one area."""
    root_lsa = index.router(area, root)
    assert root_lsa is not None  # noqa: S101 - the caller runs SPF only in areas the root has an LSA in
    tree = _Tree()
    rank = {NETWORK: 0, ROUTER: 1}
    candidates: dict[tuple[str, str], _Vertex] = {}
    heap: list[tuple[int, int, tuple[int, int, str], str, str]] = []

    def offer(kind: str, vid: str, cost: int, next_hops: frozenset[str]) -> None:
        if vid in (tree.routers if kind == ROUTER else tree.networks):
            return
        held = candidates.get((kind, vid))
        if held is None or cost < held.cost:
            candidates[(kind, vid)] = _Vertex(cost, next_hops)
            heapq.heappush(heap, (cost, rank[kind], _addr_key(vid), vid, kind))
        elif cost == held.cost:
            held.next_hops = held.next_hops | next_hops

    offer(ROUTER, root, 0, frozenset())
    while heap:
        cost, _, _, vid, kind = heapq.heappop(heap)
        placed = tree.routers if kind == ROUTER else tree.networks
        if vid in placed:
            continue
        vertex = candidates[(kind, vid)]
        if vertex.cost != cost:
            continue
        placed[vid] = vertex
        if kind == ROUTER:
            lsa = index.router(area, vid)
            assert lsa is not None  # noqa: S101 - offered only after the lookup succeeded
            for link in lsa.links:
                if link.link_type == STUB:
                    continue
                if link.link_type == VIRTUAL and vid == root:
                    errors.report(
                        "ospf-virtual-link-not-modeled",
                        f"router {root} has a virtual link to {link.link_id} in area {area}; its next hop "
                        "needs the transit area's paths (RFC 2328 16.3), which this calculation does not "
                        "compute, so the link was skipped",
                        f"{area}/{link.link_id}",
                    )
                    continue
                if link.link_type == TRANSIT:
                    net = index.network(area, link.link_id)
                    if net is None:
                        gaps.add(NETWORK, link.link_id, area, f"named by a transit link of router {vid}")
                        continue
                    if net.expired or vid not in net.attached_routers:
                        continue
                    offer(
                        NETWORK,
                        net.lsid,
                        cost + link.metric,
                        frozenset() if vid == root else vertex.next_hops,
                    )
                    continue
                far = index.router(area, link.link_id)
                if far is None:
                    gaps.add(ROUTER, link.link_id, area, f"named by a {link.link_type} link of router {vid}")
                    continue
                if far.expired:
                    continue
                backs = [
                    b for b in far.links if b.link_type in (POINT_TO_POINT, VIRTUAL) and b.link_id == vid
                ]
                if not backs:
                    continue
                hops = (
                    _p2p_next_hops(root_lsa, link, backs, area, errors) if vid == root else vertex.next_hops
                )
                if not hops:
                    continue
                offer(ROUTER, far.adv_router, cost + link.metric, hops)
        else:
            net = index.network(area, vid)
            assert net is not None  # noqa: S101 - offered only after the lookup succeeded
            direct = not vertex.next_hops
            for rid in sorted(net.attached_routers, key=_addr_key):
                if rid == root:
                    continue
                far = index.router(area, rid)
                if far is None:
                    gaps.add(ROUTER, rid, area, f"attached to network {vid}")
                    continue
                if far.expired:
                    continue
                backs = [b for b in far.links if b.link_type == TRANSIT and b.link_id == vid]
                if not backs:
                    continue
                if direct:
                    hops = frozenset(b.link_data for b in backs if b.link_data)
                    if not hops:
                        errors.report(
                            "ospf-next-hop-unresolved",
                            f"router {rid}'s link to network {vid} in area {area} carries no interface "
                            "address; routes through it were left out",
                            f"{area}/{rid}",
                        )
                        continue
                else:
                    hops = vertex.next_hops
                offer(ROUTER, rid, cost, hops)

    # The second stage adds the stub networks and the prefixes of the transit networks.
    for rid in sorted(tree.routers, key=_addr_key):
        lsa = index.router(area, rid)
        assert lsa is not None  # noqa: S101 - placed only after the lookup succeeded
        vertex = tree.routers[rid]
        for link in lsa.links:
            if link.link_type != STUB:
                continue
            prefix = _network(link.link_id, link.link_data)
            if prefix is None:
                continue
            _offer_prefix(tree.prefixes, prefix, vertex.cost + link.metric, vertex.next_hops, rid == root)
    for lsid in sorted(tree.networks, key=_addr_key):
        net = index.network(area, lsid)
        assert net is not None  # noqa: S101 - placed only after the lookup succeeded
        vertex = tree.networks[lsid]
        prefix = net.prefix
        if prefix is None:
            errors.report(
                "malformed-lsa", f"{net.describe()} has no usable mask; its prefix was left out", lsid
            )
            continue
        _offer_prefix(tree.prefixes, prefix, vertex.cost, vertex.next_hops, not vertex.next_hops)
    return tree


def _install_intra(table: dict[str, _NetEntry], prefix: str, entry: _Entry, area: str) -> None:
    held = table.get(prefix)
    if held is None:
        table[prefix] = _NetEntry(INTRA_AREA, entry.cost, entry.next_hops, area, direct=entry.direct)
        table[prefix].by_area[area] = entry
        return
    held.by_area[area] = entry
    if held.direct:
        return
    if entry.direct or entry.cost < held.cost:
        held.cost, held.next_hops, held.area, held.direct = entry.cost, entry.next_hops, area, entry.direct
    elif entry.cost == held.cost:
        held.next_hops = held.next_hops | entry.next_hops


def _inter_area(
    index: _Index,
    area: str,
    root: str,
    table: dict[str, _NetEntry],
    routers: dict[str, dict[str, _RouterPath]],
    gaps: _Gaps,
    errors: ErrorSink,
) -> None:
    """RFC 2328 16.2 over one area's summary and ASBR-summary LSAs."""
    own = {lsa.prefix for lsa in index.of_type(SUMMARY, area) if lsa.adv_router == root}
    for lsa in [*index.of_type(SUMMARY, area), *index.of_type(ASBR_SUMMARY, area)]:
        if lsa.adv_router == root or lsa.expired or lsa.metric is None or lsa.metric >= LS_INFINITY:
            continue
        border = routers.get(lsa.adv_router, {}).get(area)
        if border is None or border.path_type != INTRA_AREA:
            if index.router(area, lsa.adv_router) is None:
                gaps.add(
                    ROUTER,
                    lsa.adv_router,
                    area,
                    f"the area border router advertising {lsa.describe()}; the route it describes "
                    "cannot be costed",
                )
            continue
        cost = border.cost + lsa.metric
        if lsa.lsa_type == SUMMARY:
            prefix = lsa.prefix
            if prefix is None:
                errors.report("malformed-lsa", f"{lsa.describe()} has no usable mask; left out", lsa.lsid)
                continue
            if prefix in own:
                continue
            held = table.get(prefix)
            if held is not None and held.path_type == INTRA_AREA:
                continue
            if held is None or held.path_type != INTER_AREA or cost < held.cost:
                table[prefix] = _NetEntry(INTER_AREA, cost, border.next_hops, area, lsa.adv_router, SUMMARY)
            elif cost == held.cost:
                held.next_hops = held.next_hops | border.next_hops
            continue
        entries = routers.setdefault(lsa.lsid, {})
        held_router = entries.get(area)
        if held_router is not None and held_router.path_type == INTRA_AREA:
            continue
        if held_router is None or cost < held_router.cost:
            entries[area] = _RouterPath(cost, border.next_hops, area, INTER_AREA)
        elif cost == held_router.cost:
            held_router.next_hops = held_router.next_hops | border.next_hops


def _pick(paths: list[_RouterPath], rfc1583: bool) -> tuple[int, frozenset[str], int]:
    """Return the cost, the next hops and the ASBR class of the best path
    (RFC 2328 16.4.1).

    Without RFC 1583 compatibility, only the intra-area paths through
    non-backbone areas are candidates when one exists. The cheapest candidate
    is chosen, with the next hops of all candidates of that cost.
    """
    preferred = [p for p in paths if p.path_type == INTRA_AREA and p.area != BACKBONE]
    asbr_class = 1
    if not rfc1583 and preferred:
        paths = preferred
        asbr_class = 0
    best = min(p.cost for p in paths)
    hops: frozenset[str] = frozenset()
    for p in paths:
        if p.cost == best:
            hops = hops | p.next_hops
    return best, hops, asbr_class


class _Resolver:
    """Forwarding-address lookups over the intra- and inter-area routes, by
    longest prefix match, cached per address."""

    def __init__(self, table: dict[str, _NetEntry]) -> None:
        self._entries = [
            (ipaddress.IPv4Network(prefix), entry)
            for prefix, entry in table.items()
            if entry.path_type in (INTRA_AREA, INTER_AREA)
        ]
        self._cache: dict[str, _NetEntry | None] = {}

    def lookup(self, address: str) -> _NetEntry | None:
        if address in self._cache:
            return self._cache[address]
        try:
            target = ipaddress.IPv4Address(address)
        except ValueError:
            self._cache[address] = None
            return None
        best: tuple[int, _NetEntry] | None = None
        for net, entry in self._entries:
            if target in net and (best is None or net.prefixlen > best[0]):
                best = (net.prefixlen, entry)
        found = None if best is None else best[1]
        self._cache[address] = found
        return found


def _external_path(
    lsa: Lsa,
    model: LsdbModel,
    resolver: _Resolver,
    routers: dict[str, dict[str, _RouterPath]],
    rfc1583: bool,
    gaps: _Gaps,
) -> tuple[int, frozenset[str], int] | None:
    """Return the internal distance, the next hops and the ASBR class of the
    path to the ASBR or to the forwarding address (RFC 2328 16.4 step 3 with
    RFC 3101 2.5). Return None when the LSA is not usable."""
    fa = lsa.forwarding_address
    if fa is None or fa == NO_FORWARDING_ADDRESS:
        entries = routers.get(lsa.adv_router, {})
        if lsa.lsa_type == NSSA_EXTERNAL:
            paths = [e for a, e in entries.items() if a == lsa.area and e.path_type == INTRA_AREA]
        else:
            paths = [e for a, e in entries.items() if model.area_type(a) == NORMAL]
        if not paths:
            if not entries:
                gaps.add(
                    ROUTER,
                    lsa.adv_router,
                    lsa.area,
                    f"the AS boundary router advertising {lsa.describe()}; no router LSA and no ASBR-summary "
                    "LSA places it, so the external route cannot be costed",
                )
            return None
        return _pick(paths, rfc1583)
    entry = resolver.lookup(fa)
    if entry is None:
        return None
    if entry.path_type == INTRA_AREA:
        by_area = entry.by_area
        if lsa.lsa_type == NSSA_EXTERNAL:
            areas = [a for a in by_area if a == lsa.area]
        else:
            areas = [a for a in by_area if model.area_type(a) == NORMAL]
        paths = [
            _RouterPath(
                by_area[a].cost,
                frozenset({fa}) if by_area[a].direct else by_area[a].next_hops,
                a,
                INTRA_AREA,
            )
            for a in sorted(areas, key=_area_key)
        ]
        if not paths:
            return None
        return _pick(paths, rfc1583)
    if lsa.lsa_type == NSSA_EXTERNAL or entry.area is None or model.area_type(entry.area) != NORMAL:
        return None
    return _pick([_RouterPath(entry.cost, entry.next_hops, entry.area, INTER_AREA)], rfc1583)


def _compare_external(new: _NetEntry, held: _NetEntry, rfc1583: bool) -> int:
    """Compare 2 external paths (RFC 2328 16.4 step 6). The result is negative
    when `new` is preferred, positive when `held` is preferred and zero at
    equal preference."""
    if new.path_type != held.path_type:
        return -1 if new.path_type == EXTERNAL_1 else 1
    if new.path_type == EXTERNAL_2 and new.cost != held.cost:
        return -1 if new.cost < held.cost else 1
    if not rfc1583 and new.asbr_class != held.asbr_class:
        return -1 if new.asbr_class < held.asbr_class else 1
    a = new.cost if new.path_type == EXTERNAL_1 else (new.forward_cost or 0)
    b = held.cost if held.path_type == EXTERNAL_1 else (held.forward_cost or 0)
    if a != b:
        return -1 if a < b else 1
    return 0


def _lsa_rank(entry: _NetEntry) -> tuple[int, int]:
    """Return the rank of an LSA among functionally equivalent LSAs (RFC 3101
    2.5 step 6e).

    A type 7 LSA ranks before a type 5 LSA. The P bit of a type 7 LSA is taken
    as set. Within one type the higher advertising router id ranks first. The
    lower rank is preferred.
    """
    rid = _addr_key(entry.advertising_router)
    return (0 if entry.lsa_type == NSSA_EXTERNAL else 1, -rid[1])


def _externals(
    index: _Index,
    model: LsdbModel,
    attached: list[str],
    root: str,
    table: dict[str, _NetEntry],
    routers: dict[str, dict[str, _RouterPath]],
    rfc1583: bool,
    gaps: _Gaps,
    errors: ErrorSink,
) -> None:
    """RFC 2328 16.4 and RFC 3101 2.5."""
    resolver = _Resolver(table)
    candidates = list(index.of_type(EXTERNAL, None))
    for area in attached:
        candidates.extend(index.of_type(NSSA_EXTERNAL, area))
    for lsa in candidates:
        if lsa.adv_router == root or lsa.expired or lsa.metric is None or lsa.metric >= LS_INFINITY:
            continue
        prefix = lsa.prefix
        if prefix is None:
            errors.report("malformed-lsa", f"{lsa.describe()} has no usable mask; left out", lsa.lsid)
            continue
        path = _external_path(lsa, model, resolver, routers, rfc1583, gaps)
        if path is None:
            continue
        distance, hops, asbr_class = path
        if lsa.metric_type not in (1, 2):
            errors.report(
                "malformed-lsa",
                f"{lsa.describe()} carries no metric type; it was costed as type 2, the type a Cisco "
                "redistribution produces by default",
                lsa.lsid,
            )
        type_1 = lsa.metric_type == 1
        new = _NetEntry(
            EXTERNAL_1 if type_1 else EXTERNAL_2,
            distance + lsa.metric if type_1 else lsa.metric,
            hops,
            None,
            lsa.adv_router,
            lsa.lsa_type,
            forward_cost=distance,
            forwarding_address=lsa.forwarding_address
            if lsa.forwarding_address != NO_FORWARDING_ADDRESS
            else None,
            asbr_class=asbr_class,
        )
        held = table.get(prefix)
        if held is None:
            table[prefix] = new
            continue
        if held.path_type in (INTRA_AREA, INTER_AREA):
            continue
        verdict = _compare_external(new, held, rfc1583)
        if verdict < 0:
            table[prefix] = new
        elif verdict == 0:
            if new.forwarding_address is not None and new.forwarding_address == held.forwarding_address:
                if _lsa_rank(new) < _lsa_rank(held):
                    table[prefix] = new
            else:
                held.next_hops = held.next_hops | new.next_hops


def _platform(platform: str | None, errors: ErrorSink) -> str:
    raw = (platform or "").strip().lower()
    if raw == "vyos":
        # The 2 FRR profiles have the same OSPF defaults.
        return platforms.FRR_TRADITIONAL
    resolved = platforms.known(raw)
    if resolved is not None:
        return resolved
    errors.report(
        "unknown-platform",
        f"platform {platform!r} has no recorded OSPF defaults; IOS-XE's were applied",
        platform,
    )
    return platforms.IOSXE


def calculate(
    model: LsdbModel,
    router_id: str,
    *,
    platform: str | None = platforms.IOSXE,
    errors: ErrorSink | None = None,
) -> OspfCalculation:
    """Return the OSPF routing table that the router `router_id` computes from
    `model`, its link-state database. `platform` selects the RFC 1583 setting."""
    errors = errors or ErrorSink()
    rfc1583 = platforms.ospf_rfc1583_compatible(_platform(platform, errors))
    root = str(router_id).strip()
    gaps = _Gaps()
    index = _Index(model)

    # The router is in every area that holds its router LSA. A database with
    # no router LSA of the router gives a gap and no routes.
    attached = [area for area in model.areas() if index.router(area, root) is not None]
    if not attached:
        gaps.add(ROUTER, root, None, "the calculating router's own LSA; the database yields no routes")
        return OspfCalculation(root, gaps=gaps.as_list(), model_errors=errors.as_dicts())

    trees = {area: _spf(index, area, root, gaps, errors) for area in attached}
    table: dict[str, _NetEntry] = {}
    routers: dict[str, dict[str, _RouterPath]] = {}
    for area in attached:
        tree = trees[area]
        for rid, vertex in tree.routers.items():
            routers.setdefault(rid, {})[area] = _RouterPath(vertex.cost, vertex.next_hops, area, INTRA_AREA)
        for prefix in sorted(tree.prefixes, key=_prefix_key):
            _install_intra(table, prefix, tree.prefixes[prefix], area)

    # An area border router has more than one area and an active backbone
    # attachment (RFC 3509 section 3.1). The attachment is active when the
    # backbone tree holds another router. A router with no active attachment
    # examines the summary LSAs of every attached area.
    active_backbone = BACKBONE in attached and len(trees[BACKBONE].routers) > 1
    is_abr = len(attached) > 1 and active_backbone
    for area in [BACKBONE] if is_abr else attached:
        _inter_area(index, area, root, table, routers, gaps, errors)
    _externals(index, model, attached, root, table, routers, rfc1583, gaps, errors)

    routes = []
    for prefix in sorted(table, key=_prefix_key):
        entry = table[prefix]
        if entry.direct:
            continue
        routes.append(
            OspfRoute(
                prefix=prefix,
                path_type=entry.path_type,
                metric=entry.cost,
                next_hops=tuple(sorted(entry.next_hops, key=_addr_key)),
                area=entry.area,
                advertising_router=entry.advertising_router,
                forward_metric=entry.forward_cost,
                lsa_type=entry.lsa_type,
            )
        )
    router_costs = {}
    for rid in sorted(routers, key=_addr_key):
        if rid == root:
            continue
        for area in sorted(routers[rid], key=_area_key):
            router_costs[(area, rid)] = routers[rid][area].cost
    return OspfCalculation(
        router_id=root,
        routes=routes,
        router_costs=router_costs,
        gaps=gaps.as_list(),
        model_errors=errors.as_dicts(),
        area_border_router=is_abr,
    )


# --- output and validation ----------------------------------------------------------


def rib_rows(
    context_uid: str, calculation: OspfCalculation, *, platform: str | None = platforms.IOSXE
) -> list[dict[str, Any]]:
    """Return per-context RIB rows, one per next hop, in the shape of
    `bestpath.rib_rows`. A row has `context_uid`, `prefix`, `next_hop`,
    `protocol`, `metric` and `admin`, and the OSPF fields `path_type`, `area`,
    `advertising_router` and `forward_metric`."""
    admin = platforms.ospf_admin_distance(_platform(platform, ErrorSink()))
    rows = []
    for route in calculation.routes:
        for next_hop in route.next_hops:
            rows.append(
                {
                    "context_uid": context_uid,
                    "prefix": route.prefix,
                    "next_hop": next_hop,
                    "protocol": "ospf",
                    "metric": route.metric,
                    "admin": admin,
                    "path_type": route.path_type,
                    "area": route.area,
                    "advertising_router": route.advertising_router,
                    "forward_metric": route.forward_metric,
                }
            )
    return rows


def _is_ospf(protocol: Any, process: str | None) -> bool:
    """Return whether the protocol of an observed `rib` row is OSPF. IOS-XE,
    IOS-XR and VyOS use the legend word `ospf`. NX-OS uses the client name
    `ospf-<tag>`."""
    text = str(protocol or "").strip().lower()
    if text == "ospf":
        return True
    if text.startswith("ospf-"):
        return process is None or text == f"ospf-{process}".lower()
    return False


def _observed_prefix(row: Mapping[str, Any]) -> str | None:
    prefix = _text(row.get("prefix"))
    if prefix is None:
        return None
    try:
        return str(ipaddress.ip_network(prefix, strict=False))
    except ValueError:
        return None


def validate(
    calculation: OspfCalculation,
    observed: Sequence[Mapping[str, Any]],
    *,
    process: str | None = None,
    errors: ErrorSink | None = None,
) -> list[dict[str, Any]]:
    """Compare the computed routes with the observed `rib` rows of the same
    device and context (`ribsource.RibSource.routes`), per prefix.

    A prefix is `validated` when the device holds it through OSPF with the
    same next hops and metric. A prefix is a `mismatch` when the 2 sides
    disagree, or when only one side holds it and the database is complete. A
    mismatch is reported as an `ospf-route-mismatch` model error. A prefix is
    `not-observed` when the device holds it through OSPF and the calculation
    could not produce it from a database with gaps, or when the calculation
    produced it and the device installed it from another protocol.
    """
    errors = errors or ErrorSink()
    observed_hops: dict[str, set[str | None]] = {}
    observed_metrics: dict[str, set[int | None]] = {}
    other_protocols: dict[str, set[str]] = {}
    for seen in observed:
        prefix = _observed_prefix(seen)
        if prefix is None:
            continue
        if _is_ospf(seen.get("protocol"), process):
            observed_hops.setdefault(prefix, set()).add(_text(seen.get("next_hop")))
            observed_metrics.setdefault(prefix, set()).add(_int(seen.get("metric")))
        else:
            other_protocols.setdefault(prefix, set()).add(str(seen.get("protocol") or "?").strip().lower())
    computed = {route.prefix: route for route in calculation.routes}
    incomplete = bool(calculation.gaps)

    out: list[dict[str, Any]] = []
    for prefix in sorted(set(computed) | set(observed_hops), key=_prefix_key):
        route = computed.get(prefix)
        hops = observed_hops.get(prefix)
        metrics = observed_metrics.get(prefix, set())
        row: dict[str, Any] = {
            "prefix": prefix,
            "status": VALIDATED,
            "computed_next_hops": list(route.next_hops) if route is not None else [],
            "observed_next_hops": sorted((h for h in hops if h is not None), key=_addr_key) if hops else [],
            "computed_metric": route.metric if route is not None else None,
            "observed_metric": min((m for m in metrics if m is not None), default=None),
            "detail": None,
        }
        if route is not None and hops is not None:
            same_hops = set(route.next_hops) == hops
            same_metric = metrics == {route.metric}
            if same_hops and same_metric:
                row["detail"] = f"{route.path_type} route, {len(route.next_hops)} next hop(s)"
            else:
                row["status"] = MISMATCH
                row["detail"] = (
                    f"computed {route.path_type} metric {route.metric} via "
                    f"{', '.join(route.next_hops) or '-'}; "
                    f"observed metric {', '.join(str(m) for m in sorted(metrics, key=str))} via "
                    f"{', '.join(sorted((h or '-' for h in hops), key=_addr_key))}"
                )
        elif route is not None:
            protocols = other_protocols.get(prefix)
            if protocols:
                row["status"] = NOT_OBSERVED
                row["detail"] = (
                    f"the device installed {prefix} from {', '.join(sorted(protocols))}, not OSPF; "
                    "the main RIB's choice is outside this calculation"
                )
            else:
                row["status"] = MISMATCH
                row["detail"] = (
                    f"computed {route.path_type} metric {route.metric} via {', '.join(route.next_hops)}; "
                    "the device holds no route for the prefix"
                )
        elif incomplete:
            row["status"] = NOT_OBSERVED
            row["detail"] = (
                f"the device holds {prefix} through OSPF and the calculation produced no route for it; "
                f"the database is missing {len(calculation.gaps)} LSA(s) (see gaps), so the calculation "
                "makes no claim about it"
            )
        else:
            row["status"] = MISMATCH
            row["detail"] = (
                f"the device holds {prefix} through OSPF via "
                f"{', '.join(sorted((h or '-' for h in hops or ()), key=_addr_key))}; the calculation "
                "produced no route for it from a complete database"
            )
        if row["status"] == MISMATCH:
            errors.report("ospf-route-mismatch", str(row["detail"]), prefix)
        out.append(row)
    return out
