"""The BGP route that the engine passes through policy evaluation, best-path
comparison and propagation.

The route holds only the attributes that the engine branches on. The comparison set is
weight, local preference, origin mechanism,
AS path, origin type, session type, MED, IGP cost, cluster list, originator,
received-from and path id.

`med` is `None` when the route has no MED. A missing MED compares as 0.
`as_path` is a flat tuple of AS numbers.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, replace

# The origin types rank internal (IGP), then external (EGP), then incomplete.
# The higher value wins.
ORIGIN_PREFERENCE = {"igp": 2, "egp": 1, "incomplete": 0}

# The rank of an origin mechanism in the local-origination tie-break. The
# higher value wins. A route from a `network` statement or from redistribution
# ranks above a locally generated aggregate. An aggregate ranks above a route
# learned from a neighbor.
ORIGINATION_RANK = {"network": 2, "redistribute": 2, "aggregate": 1, "learned": 0}

# The received-from kinds rank interface, then IP address, then self. The
# lower value wins.
RECEIVED_FROM_RANK = {"interface": 0, "ip": 1, "self": 2}

# The IOS default weight of a locally originated or redistributed route.
DEFAULT_LOCAL_WEIGHT = 32768

# An eBGP export resets the local preference to this default.
DEFAULT_LOCAL_PREFERENCE = 100

NO_ADVERTISE = "no-advertise"
NO_EXPORT = "no-export"


@dataclass(frozen=True)
class Route:
    """One BGP path. Every transform in the import and export pipeline returns a
    new route."""

    prefix: str
    next_hop: str | None = None
    # "bgp" for an eBGP-learned or locally originated path, "ibgp" for one
    # learned over an iBGP session.
    protocol: str = "bgp"
    src_protocol: str | None = None
    origin_mechanism: str = "learned"
    local_pref: int = DEFAULT_LOCAL_PREFERENCE
    med: int | None = None
    weight: int = 0
    as_path: tuple[int, ...] = ()
    origin: str = "igp"
    tag: int | None = None
    communities: frozenset[str] = frozenset()
    admin: int | None = None
    originator_ip: str | None = None
    cluster_list: tuple[str, ...] = ()
    received_from_kind: str = "self"
    received_from_ip: str | None = None
    received_from_interface: str | None = None
    # Cost from this router to `next_hop` through the IGP,
    # resolved by recursive main-RIB lookup. The comparator
    # skips the step when either side has no cost.
    igp_cost: int | None = None
    path_id: int | None = None
    # Per-RIB logical clock, for the ARRIVAL_ORDER tie-break.
    arrival: int = 0
    # The uid of the session that delivered the route. It is provenance for the
    # RIB rows and the identity of a path within a prefix (`propagate._merge`).
    learned_from_session: str | None = None
    # The forwarding context in which `next_hop` resolves. A leaked route holds
    # its exporting context here. None means the context of the route.
    next_hop_context_uid: str | None = None
    # The contexts that a leaked route has passed through, oldest first. A route
    # is not leaked into a context in this tuple. The tuple is empty for a route
    # that was never leaked.
    leak_path: tuple[str, ...] = ()

    def with_(self, **changes: object) -> Route:
        return replace(self, **changes)  # type: ignore[arg-type]

    @property
    def as_path_length(self) -> int:
        return len(self.as_path)

    @property
    def neighbor_as(self) -> int | None:
        """The leftmost AS of the path. The route was received from this AS.

        By default all four platforms compare MED only among routes received
        from the same neighboring AS.
        """
        return self.as_path[0] if self.as_path else None

    @property
    def effective_med(self) -> int:
        """The MED, with 0 for a missing MED."""
        return 0 if self.med is None else self.med

    @property
    def is_locally_originated(self) -> bool:
        return self.origin_mechanism != "learned"


def prefix_network(prefix: str) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(prefix, strict=False)  # type: ignore[return-value]


def prefix_length(prefix: str) -> int:
    return prefix_network(prefix).prefixlen
