"""Address-set interval math and rule/service match helpers.

The engine models a network-scoped query as a set of addresses. This module
holds the interval arithmetic that keeps that set exact through every gate.
"""

from __future__ import annotations

import functools
import ipaddress
from typing import Any, Literal, NamedTuple

# --- address sets -----------------------------------------------------------


def _intervals(specs: list[str]) -> list[tuple[int, int, int]]:
    """The merged `(version, lo, hi)` tuples of address specs such as '10.0.0.0/24' and
    '10.1.0.5-10.1.0.9'. An empty or unreadable spec is skipped."""
    out: list[tuple[int, int, int]] = []
    for spec in specs:
        if not spec:
            continue
        text = str(spec).strip()
        try:
            if "-" in text:
                lo_s, _, hi_s = text.partition("-")
                lo, hi = ipaddress.ip_address(lo_s.strip()), ipaddress.ip_address(hi_s.strip())
                if lo.version != hi.version or int(lo) > int(hi):
                    continue
                out.append((lo.version, int(lo), int(hi)))
            elif "/" in text:
                net = ipaddress.ip_network(text, strict=False)
                out.append((net.version, int(net.network_address), int(net.broadcast_address)))
            else:
                addr = ipaddress.ip_address(text)
                out.append((addr.version, int(addr), int(addr)))
        except ValueError:
            continue
    return _merge(out)


def _merge(items: list[tuple[int, int, int]]) -> list[tuple[int, int, int]]:
    merged: list[tuple[int, int, int]] = []
    for ver, lo, hi in sorted(items):
        if merged and merged[-1][0] == ver and lo <= merged[-1][2] + 1:
            prev = merged[-1]
            merged[-1] = (ver, prev[1], max(prev[2], hi))
        else:
            merged.append((ver, lo, hi))
    return merged


def _intersect(a: list[tuple[int, int, int]], b: list[tuple[int, int, int]]) -> list[tuple[int, int, int]]:
    out = []
    for av, alo, ahi in a:
        for bv, blo, bhi in b:
            if av != bv:
                continue
            lo, hi = max(alo, blo), min(ahi, bhi)
            if lo <= hi:
                out.append((av, lo, hi))
    return _merge(out)


def _subtract(a: list[tuple[int, int, int]], b: list[tuple[int, int, int]]) -> list[tuple[int, int, int]]:
    out = list(a)
    for bv, blo, bhi in b:
        nxt = []
        for av, alo, ahi in out:
            if av != bv or bhi < alo or blo > ahi:
                nxt.append((av, alo, ahi))
                continue
            if alo < blo:
                nxt.append((av, alo, blo - 1))
            if ahi > bhi:
                nxt.append((av, bhi + 1, ahi))
        out = nxt
    return _merge(out)


# Port intervals use the interval functions above. Their family is
# `_PORT_FAMILY`, a value that no address family uses.
_PORT_FAMILY = 0
_PORT_UNIVERSE: list[tuple[int, int, int]] = [(_PORT_FAMILY, 0, 65535)]

_UNIVERSE = {
    _PORT_FAMILY: _PORT_UNIVERSE,
    4: [(4, 0, 2**32 - 1)],
    6: [(6, 0, 2**128 - 1)],
}


def _complement(
    items: list[tuple[int, int, int]], families: set[int] | list[int]
) -> list[tuple[int, int, int]]:
    """The complement of an interval set within `families`.

    A family in `families` that has no interval in `items` yields the whole
    family. A family without an entry in `_UNIVERSE` is skipped."""
    out: list[tuple[int, int, int]] = []
    for af in sorted(set(families)):
        universe = _UNIVERSE.get(af)
        if universe is None:
            continue
        out.extend(_subtract(universe, [i for i in items if i[0] == af]))
    return out


def _to_cidrs(items: list[tuple[int, int, int]]) -> list[str]:
    """The prefixes an address interval set covers."""
    out: list[str] = []
    for ver, lo, hi in items:
        if ver == _PORT_FAMILY:
            raise ValueError("port interval passed to an address conversion")
        cls = ipaddress.IPv4Address if ver == 4 else ipaddress.IPv6Address
        for net in ipaddress.summarize_address_range(cls(lo), cls(hi)):
            out.append(str(net))
    return out


def _size(items: list[tuple[int, int, int]]) -> int:
    return sum(hi - lo + 1 for _, lo, hi in items)


def _describe(items: list[tuple[int, int, int]]) -> str:
    cidrs = _to_cidrs(items)
    if not cidrs:
        return "nothing"
    if _size(items) == 1:
        return cidrs[0].split("/")[0]
    if len(cidrs) <= 3:
        return ", ".join(cidrs)
    return f"{cidrs[0]} +{len(cidrs) - 1} more ({_size(items)} addresses)"


def _lpm_all(candidates: list[dict], ip: str) -> list[dict]:
    """Every candidate tied at the longest matching prefix (an ECMP set)."""
    addr = ipaddress.ip_address(ip)
    best_len, winners = -1, []
    for c in candidates:
        try:
            net = ipaddress.ip_network(c["cidr"])
        except (KeyError, ValueError):
            continue
        if addr.version != net.version or addr not in net:
            continue
        if net.prefixlen > best_len:
            best_len, winners = net.prefixlen, [c]
        elif net.prefixlen == best_len:
            winners.append(c)
    return winners


def _rule_intervals_status(
    cidrs: list[Any], ips: list[Any], ranges: list[Any]
) -> tuple[list[tuple[int, int, int]], bool]:
    """The address set of the SRC or DST objects of a rule, and a flag.

    The flag is True when the side lists addresses and none of them parses. `_first_match`
    answers a rule with the flag set as undecided."""
    raw = [c for c in cidrs if c] + [i for i in ips if i] + [x for grp in ranges if grp for x in grp]
    try:
        parsed = _parsed_rule_side(tuple(raw))
    except TypeError:
        # An unhashable value is parsed without the cache.
        parsed = tuple(_intervals(raw))
    return list(parsed), (bool(raw) and not parsed)


@functools.lru_cache(maxsize=65536)
def _parsed_rule_side(raw: tuple[Any, ...]) -> tuple[tuple[int, int, int], ...]:
    """`_intervals` of one rule side's address strings, cached."""
    return tuple(_intervals(list(raw)))


def _rule_intervals(cidrs: list[Any], ips: list[Any], ranges: list[Any]) -> list[tuple[int, int, int]]:
    """The address set a rule's collected SRC or DST objects describe."""
    return _rule_intervals_status(cidrs, ips, ranges)[0]


# Three-valued match states. A trace models a NEW flow as the tuple
# (source set, destination set, destination port, protocol). The comparison is
# unknown when a rule constrains a dimension that the tuple does not state.
_MatchState = Literal["match", "no_match", "unknown"]

_MATCH: _MatchState = "match"
_NO_MATCH: _MatchState = "no_match"
_UNKNOWN: _MatchState = "unknown"


def _combine_and(*states: _MatchState) -> _MatchState:
    """Three-valued AND for the (proto, port) pair of one service member.

    A non-match on either dimension decides the pair. Otherwise an unknown
    dimension leaves the pair undecided.
    """
    if _NO_MATCH in states:
        return _NO_MATCH
    if _UNKNOWN in states:
        return _UNKNOWN
    return _MATCH


def _combine_or(*states: _MatchState) -> _MatchState:
    """Three-valued OR across the members of a service.

    A member that matches decides the service side. Otherwise an undecided
    member leaves the side undecided.
    """
    if _MATCH in states:
        return _MATCH
    if _UNKNOWN in states:
        return _UNKNOWN
    return _NO_MATCH


class ServiceRegions(NamedTuple):
    """The service claim of a rule as a union of rectangles.

    `.claimed` holds one `(proto-set, port-intervals)` rectangle per member
    whose spec overlaps the query. The rectangle is the overlap of the member
    with the query. The protocol of a member is paired only with the port of
    the same member.

    `.unknown_dims` holds each of `"proto"` and `"port"` that a member is
    scoped to and the query does not state.
    """

    claimed: list[tuple[frozenset[int], list[tuple[int, int, int]]]]
    unknown_dims: set[str]


def _service_regions(
    pairs: list[tuple[str | None, Any]],
    proto_set: frozenset[int] | None,
    port_ivals: list[tuple[int, int, int]] | None,
) -> ServiceRegions:
    """The per-member (proto, port) pairs of a rule against a range query.

    `pairs` holds one `(protocol spec, port spec)` tuple per rule member. A
    spec is `None` where the member does not scope that dimension.
    `proto_set` and `port_ivals` are the ranges of the query (`_protoset` and
    `_ports` output). Each is `None` where the query does not state that
    dimension.

    Each member is judged on its 2 dimensions with the priority of
    `_combine_and`. The members are combined with the priority of
    `_combine_or`.

    A member spec that `_protoset` or `_ports` cannot read is undecided on
    that dimension.

    A member protocol or port of 'any' is the full range. A member protocol
    of '!any' is the empty range. The point functions `_proto_matches` and
    `_port_matches` do not read 'any' as a range. tests/test_header_space.py
    covers these cases.

    `_protoset` resolves a list with both '!tcp' and 'tcp' to the full range.
    `_proto_matches` leaves that list undecided against a query without a
    protocol.
    """
    claimed: list[tuple[frozenset[int], list[tuple[int, int, int]]]] = []
    unknown_dims: set[str] = set()
    for p, q in pairs:
        # No member claims a rectangle when a query side is stated and empty.
        if (proto_set is not None and not proto_set) or (port_ivals is not None and not port_ivals):
            continue
        proto_unreadable = False
        try:
            member_protos = _protoset([p]) if p else None
        except ValueError:
            member_protos, proto_unreadable = None, True
        port_unreadable = False
        try:
            member_ports = _ports(q)
        except ValueError:
            member_ports, port_unreadable = [], True

        if proto_unreadable:
            proto_rect: frozenset[int] | None = None
            proto_unknown, proto_empty = True, False
        elif member_protos is None or member_protos == _ALL_PROTOS:
            # The member is unscoped or scoped to 'all'. Its side is the
            # protocol range of the query.
            proto_rect = proto_set if proto_set is not None else _ALL_PROTOS
            proto_unknown = proto_empty = False
        elif not member_protos:
            # The member matches no protocol ('!all').
            proto_rect, proto_unknown, proto_empty = None, False, True
        elif proto_set is None:
            proto_rect, proto_unknown, proto_empty = None, True, False
        else:
            inter = member_protos & proto_set
            proto_rect, proto_unknown, proto_empty = (inter, False, False) if inter else (None, False, True)

        if port_unreadable:
            port_rect: list[tuple[int, int, int]] | None = None
            port_unknown, port_empty = True, False
        elif not member_ports:
            # The member states no port. Its side is the port range of the
            # query.
            port_rect = port_ivals if port_ivals is not None else _PORT_UNIVERSE
            port_unknown = port_empty = False
        elif port_ivals is None:
            port_rect, port_unknown, port_empty = None, True, False
        else:
            inter_p = _intersect(member_ports, port_ivals)
            port_rect, port_unknown, port_empty = (inter_p, False, False) if inter_p else (None, False, True)

        # A side without a rectangle is empty unless it is unknown.
        if not proto_rect:
            proto_rect, proto_empty = None, proto_empty or not proto_unknown
        if not port_rect:
            port_rect, port_empty = None, port_empty or not port_unknown

        if proto_empty or port_empty:
            continue
        if proto_unknown or port_unknown:
            if proto_unknown:
                unknown_dims.add("proto")
            if port_unknown:
                unknown_dims.add("port")
            continue
        # the check narrows the types only
        if proto_rect is None or port_rect is None:
            continue
        claimed.append((frozenset(proto_rect), list(port_rect)))
    return ServiceRegions(claimed=claimed, unknown_dims=unknown_dims)


def _proto_matches(specs: list[str], proto: str | None) -> _MatchState:
    """Match a protocol spec list in VyOS grammar ('tcp', 'udp', 'tcp_udp',
    'all') against one protocol word.

    A compound spec matches each of its members. A leading '!' negates one
    spec ('!tcp' covers every protocol except tcp). VyOS writes this form for
    `protocol !tcp`. Specs are ORed.

    An empty spec list matches. A list with 'all' matches. A list of only
    '!all' does not match. Any other list, negated or not, is `_UNKNOWN`
    against a query without a protocol.

    A spec token is first compared with the query word. If that comparison
    fails, both are resolved to IANA numbers by `_proto_tokens` and compared
    as number sets. The second comparison runs only when the query word
    resolves to exactly 1 protocol number.

    A rule token that `_proto_tokens` cannot resolve ('igrp', 'ipencap')
    decides nothing, negated or not. The answer is `_UNKNOWN` when no other
    token matches.
    """
    if not specs:
        return _MATCH
    parsed = []
    for spec in specs:
        s = str(spec).strip().lower()
        negate = s.startswith("!")
        if negate:
            s = s[1:].strip()
        parsed.append((negate, s))
    if any(not negate and s == "all" for negate, s in parsed):
        return _MATCH
    if all(negate and s == "all" for negate, s in parsed):
        return _NO_MATCH
    if not proto:
        return _UNKNOWN
    want = proto.lower()
    try:
        resolved = _proto_tokens(want)
        want_numbers = resolved if len(resolved) == 1 else None
    except ValueError:
        want_numbers = None
    unreadable = False
    for negate, s in parsed:
        hit = s == "all" or want in s.replace("-", "_").split("_")
        if not hit and want_numbers is not None:
            try:
                hit = bool(want_numbers & _proto_tokens(s))
            except ValueError:
                unreadable = True
                continue
        if hit != negate:
            return _MATCH
    return _UNKNOWN if unreadable else _NO_MATCH


# IANA protocol numbers for the names that the collectors write. The keys
# are sorted by number. The aliases of one protocol are on adjacent lines.
_PROTO_NUM: dict[str, int] = {
    "icmp": 1,
    "igmp": 2,
    "ipinip": 4,
    "tcp": 6,
    "udp": 17,
    "rsvp": 46,
    "gre": 47,
    "esp": 50,
    "ah": 51,
    "ahp": 51,
    "icmpv6": 58,
    "icmp6": 58,
    "ipv6-icmp": 58,
    "eigrp": 88,
    "ospf": 89,
    "nos": 94,
    "pim": 103,
    "pcp": 108,
    "vrrp": 112,
    "l2tp": 115,
    "sctp": 132,
}

_ALL_PROTOS: frozenset[int] = frozenset(range(256))


def _proto_tokens(s: str) -> frozenset[int]:
    """The IANA protocol numbers of one spec token. The token has no '!' and
    is not 'all' or 'any'.

    The whole token is looked up in `_PROTO_NUM` first. A token that is not a
    key of the table is split on '_' and '-' ('tcp_udp', 'tcp-udp'). A part is
    a key of the table or a number from 0 to 255.

    Any other token raises ValueError.
    """
    if s in _PROTO_NUM:
        return frozenset({_PROTO_NUM[s]})
    out: set[int] = set()
    for token in s.replace("-", "_").split("_"):
        token = token.strip()
        if not token:
            continue
        if token in _PROTO_NUM:
            out.add(_PROTO_NUM[token])
        elif token.isdigit() and 0 <= int(token) <= 255:
            out.add(int(token))
        else:
            raise ValueError(f"unknown protocol name or number: {token}")
    if not out:
        raise ValueError(f"protocol spec names no protocol: {s}")
    return frozenset(out)


def _protoset(specs: list[str]) -> frozenset[int] | None:
    """The concrete protocol numbers a VyOS-grammar spec list resolves to.

    `None` means the spec constrains nothing (an empty list).

    'all' resolves to the concrete `_ALL_PROTOS`. 'any' is a synonym.

    A leading '!' negates one spec, as in `_proto_matches`. Specs are ORed.

    An empty frozenset is an empty range. A list of only '!all' or '!any'
    gives it. A spec this grammar cannot read raises ValueError.
    """
    specs = [s for s in specs if str(s).strip()]
    if not specs:
        return None
    out: set[int] = set()
    for spec in specs:
        s = str(spec).strip().lower()
        negate = s.startswith("!")
        if negate:
            s = s[1:].strip()
        resolved = _ALL_PROTOS if s in ("all", "any") else _proto_tokens(s)
        out |= (_ALL_PROTOS - resolved) if negate else resolved
    return frozenset(out)


def _iface_name_matches(scope: str, actual: str | None) -> bool:
    """Whether the interface-name scope of a rule covers the interface of the leg.

    VyOS writes the scope as a literal name, a trailing-'*' wildcard ('eth2*'
    covers every name that starts with 'eth2', including 'eth2.30'), a
    leading-'!' negation ('!eth2'), or the two combined ('!eth2*').

    An unresolved leg interface (`actual` is None) matches nothing, negated or
    not.
    """
    negated = scope.startswith("!")
    pattern = scope[1:].strip() if negated else scope
    if actual is None or not pattern:
        return False
    hit = actual.startswith(pattern[:-1]) if pattern.endswith("*") else actual == pattern
    return not hit if negated else hit


def _ports(spec: Any) -> list[tuple[int, int, int]]:
    """A VyOS port spec as merged `(_PORT_FAMILY, lo, hi)` triples.

    The spec is '443', '80,443', '1000-2000', 'any', an int, or a list of
    those.

    An absent spec ('', None, []) returns an empty list. A spec that is
    present and holds no port ('>1023', 'abc', a reversed range) raises
    ValueError.

    A tuple is read as a list.
    """
    if spec in (None, "", [], ()):
        return []
    out: list[tuple[int, int, int]] = []
    for part in spec if isinstance(spec, (list, tuple)) else [spec]:
        for token in str(part).split(","):
            token = token.strip()
            if not token:
                continue
            if token.lower() == "any":
                out.append((_PORT_FAMILY, 0, 65535))
                continue
            if "-" in token:
                lo_s, _, hi_s = token.partition("-")
                try:
                    lo, hi = int(lo_s), int(hi_s)
                except ValueError:
                    raise ValueError(f"unreadable port range: {token}") from None
                if lo > hi:
                    raise ValueError(f"port range covers no port: {token}")
                out.append((_PORT_FAMILY, lo, hi))
            elif token.isdigit():
                out.append((_PORT_FAMILY, int(token), int(token)))
            else:
                raise ValueError(f"unreadable port token: {token}")
    if not out:
        raise ValueError(f"port spec names no port: {spec}")
    return _merge(out)


def _port_matches(spec: Any, port: int | None) -> _MatchState:
    """Match a VyOS port spec ('443', '80,443', '1000-2000', or a list of
    those) against one port.

    An empty spec matches. A non-empty spec is `_UNKNOWN` against a flow
    without a destination port.

    This grammar cannot read a named port such as 'http', an unreadable range
    or a reversed range. `_ports` raises on the same tokens. The answer is
    `_UNKNOWN` when the spec has such a token and no other token matches.
    """
    if spec in (None, "", [], ()):
        return _MATCH
    if port is None:
        return _UNKNOWN
    unreadable = False
    # A member without a port token ('', ' ', ',') is malformed. In a tuple,
    # the frozen form of the analysis model, it is undecided. In a list its
    # empty tokens are skipped.
    frozen = isinstance(spec, tuple)
    for part in spec if isinstance(spec, (list, tuple)) else [spec]:
        if frozen and not any(token.strip() for token in str(part).split(",")):
            unreadable = True
            continue
        for token in str(part).split(","):
            token = token.strip()
            if not token:
                continue
            if "-" in token:
                lo_s, _, hi_s = token.partition("-")
                try:
                    lo, hi = int(lo_s), int(hi_s)
                except ValueError:
                    unreadable = True
                    continue
                if lo > hi:
                    unreadable = True
                elif lo <= port <= hi:
                    return _MATCH
            elif token.isdigit():
                if int(token) == port:
                    return _MATCH
            else:
                unreadable = True
    return _UNKNOWN if unreadable else _NO_MATCH


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _set_bounds(items: list[tuple[int, int, int]]) -> tuple[bytes, bytes] | None:
    """The enclosing [lo, hi] of an interval set in the addr encoding of the
    side store. Only the intervals in the family of the first interval are
    read.

    The carve-out query takes the bounds as a superset of the set.
    """
    if not items:
        return None
    from hst.core.ipenc import addr_bytes

    af = items[0][0]
    make = ipaddress.IPv4Address if af == 4 else ipaddress.IPv6Address
    lo = min(i[1] for i in items if i[0] == af)
    hi = max(i[2] for i in items if i[0] == af)
    return addr_bytes(str(make(lo))), addr_bytes(str(make(hi)))
