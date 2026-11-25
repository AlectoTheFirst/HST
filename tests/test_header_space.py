"""Collapsed to a point query, `_service_regions` reproduces the three-valued verdict
of `_combine_and`/`_combine_or`."""

import pytest

from hst.path.addrsets import (
    _ALL_PROTOS,
    _MATCH,
    _NO_MATCH,
    _PORT_FAMILY,
    _PORT_UNIVERSE,
    _UNKNOWN,
    _combine_and,
    _combine_or,
    _complement,
    _intersect,
    _intervals,
    _merge,
    _port_matches,
    _ports,
    _proto_matches,
    _protoset,
    _service_regions,
    _subtract,
    _to_cidrs,
)
from hst.path.state import FlowRegion, Predicate, claim

# `None` on the query side means "not stated".


def _proto_point(proto):
    return None if proto is None else _protoset([proto])


def _port_point(port):
    return None if port is None else _ports(port)


class TestProtosetGrammar:
    """`_protoset` reads the same VyOS protocol grammar `_proto_matches` does,
    resolved to IANA numbers."""

    @pytest.mark.parametrize(
        ("specs", "expected"),
        [
            ([], None),
            (["tcp"], frozenset({6})),
            (["udp"], frozenset({17})),
            (["icmp"], frozenset({1})),
            (["icmpv6"], frozenset({58})),
            (["sctp"], frozenset({132})),
            (["tcp_udp"], frozenset({6, 17})),
            (["tcp-udp"], frozenset({6, 17})),
            (["all"], _ALL_PROTOS),
            (["any"], _ALL_PROTOS),
            (["!tcp"], _ALL_PROTOS - {6}),
            (["! tcp"], _ALL_PROTOS - {6}),
            (["!tcp_udp"], _ALL_PROTOS - {6, 17}),
            (["!all"], frozenset()),
            (["!any"], frozenset()),
            (["!tcp", "udp"], _ALL_PROTOS - {6}),
            (["icmp6"], frozenset({58})),
            (["ipv6-icmp"], frozenset({58})),
            (["eigrp"], frozenset({88})),
            (["ahp"], frozenset({51})),
            (["ipinip"], frozenset({4})),
            (["nos"], frozenset({94})),
            (["pcp"], frozenset({108})),
        ],
        ids=[
            "unconstrained",
            "plain-tcp",
            "plain-udp",
            "plain-icmp",
            "plain-icmpv6",
            "plain-sctp",
            "compound-underscore",
            "compound-hyphen",
            "all-is-the-full-range",
            "any-is-the-full-range",
            "negated-covers-everything-else",
            "negated-tolerates-a-space",
            "negated-compound-excludes-both",
            "negated-all-is-the-empty-set",
            "negated-any-is-the-empty-set",
            "negated-and-plain-are-ored",
            "check-point-spells-icmpv6-icmp6",
            "a-hyphenated-name-is-not-split-first",
            "cisco-ace-eigrp",
            "cisco-ace-ahp",
            "cisco-ace-ipinip",
            "cisco-ace-nos",
            "cisco-ace-pcp",
        ],
    )
    def test_protoset_values(self, specs, expected):
        assert _protoset(specs) == expected

    def test_numeric_token_for_an_unlisted_protocol_number(self):
        # a bare number names itself.
        assert _protoset(["253"]) == frozenset({253})

    def test_a_negated_bare_number_excludes_only_that_number(self):
        assert _protoset(["!253"]) == _ALL_PROTOS - {253}

    def test_an_unrecognized_alias_raises(self):
        with pytest.raises(ValueError):
            _protoset(["not-a-protocol"])

    def test_a_number_outside_the_protocol_range_raises(self):
        with pytest.raises(ValueError):
            _protoset(["300"])

    def test_a_hyphenated_name_is_looked_up_whole_before_it_is_split(self):
        assert _protoset(["ipv6-icmp"]) == frozenset({58})
        assert _protoset(["!ipv6-icmp"]) == _ALL_PROTOS - {58}


class TestPortsTokenizer:
    """`_ports` reads every token shape `_port_matches` reads, plus 'any' for
    the full range."""

    @pytest.mark.parametrize(
        ("spec", "expected"),
        [
            (443, [(0, 443, 443)]),
            ("443", [(0, 443, 443)]),
            ("80,443", [(0, 80, 80), (0, 443, 443)]),
            ("1000-2000", [(0, 1000, 2000)]),
            ("1-1024", [(0, 1, 1024)]),
            (["80", "443"], [(0, 80, 80), (0, 443, 443)]),
            ([80, 443], [(0, 80, 80), (0, 443, 443)]),
            ("any", [(0, 0, 65535)]),
            ("0-65535", [(0, 0, 65535)]),
            ("", []),
            (None, []),
            ([], []),
            ("80,80-90", [(0, 80, 90)]),
        ],
        ids=[
            "int",
            "plain-string",
            "comma-list",
            "range",
            "another-range",
            "list-of-strings",
            "list-of-ints",
            "any-is-the-full-range",
            "explicit-full-range-spelled-out",
            "empty-string",
            "none",
            "empty-list",
            "overlapping-tokens-merge",
        ],
    )
    def test_ports_tokenizes(self, spec, expected):
        assert _ports(spec) == expected

    @pytest.mark.parametrize("spec", [">1023", "abc", "2000-1000", "80,abc"])
    def test_a_spec_that_names_no_port_raises(self, spec):
        with pytest.raises(ValueError):
            _ports(spec)


class TestPortIntervalAlgebra:
    """Port triples use the address-family interval algebra with family 0."""

    def test_merge_combines_adjacent_ranges(self):
        assert _merge([(0, 1, 100), (0, 101, 200)]) == [(0, 1, 200)]

    def test_intersect_overlapping_ranges(self):
        assert _intersect([(0, 1, 1024)], [(0, 443, 443)]) == [(0, 443, 443)]

    def test_intersect_disjoint_ranges_is_empty(self):
        assert _intersect([(0, 1, 100)], [(0, 200, 300)]) == []

    def test_subtract_splits_a_range(self):
        rest = _subtract([(0, 1, 1024)], [(0, 443, 443)])
        assert rest == [(0, 1, 442), (0, 444, 1024)]

    def test_subtract_everything_is_empty(self):
        assert _subtract([(0, 1, 1024)], _PORT_UNIVERSE) == []

    def test_disjoint_subtract_is_a_noop(self):
        left = [(0, 1, 100)]
        assert _subtract(left, [(0, 200, 300)]) == left

    def test_complement_of_a_range_is_the_rest_of_the_port_space(self):
        comp = _complement([(0, 443, 443)], {0})
        assert comp == [(0, 0, 442), (0, 444, 65535)]

    def test_complement_of_nothing_is_the_whole_port_space(self):
        assert _complement([], {0}) == _PORT_UNIVERSE

    def test_a_port_triple_is_refused_by_the_address_conversion(self):
        with pytest.raises(ValueError):
            _to_cidrs([(_PORT_FAMILY, 0, 65535)])


# --- point-equivalence: `_service_regions` collapsed to a point reproduces
# the verdict of `_combine_and`/`_combine_or`.


def _old_verdict(pairs, proto, port):
    states = [_combine_and(_proto_matches([p] if p else [], proto), _port_matches(q, port)) for p, q in pairs]
    return _combine_or(*(states or [_MATCH]))


def _new_verdict(pairs, proto, port):
    if not pairs:
        # a rule with no SVC edge matches on its addresses alone
        return _MATCH
    regions = _service_regions(pairs, _proto_point(proto), _port_point(port))
    if regions.claimed:
        return _MATCH
    if regions.unknown_dims:
        return _UNKNOWN
    return _NO_MATCH


class TestPointEquivalence:
    """Every combination `_combine_and`/`_combine_or` can produce, reproduced
    by `_service_regions` collapsed to the same point query."""

    @pytest.mark.parametrize(
        ("pairs", "proto", "port"),
        [
            # no service constraint: matches on addresses alone.
            ([], "tcp", 443),
            ([], None, None),
            # unconstrained member.
            ([(None, None)], "tcp", 443),
            ([(None, None)], None, None),
            # a single member scoped to both dimensions.
            ([("tcp", "443")], "tcp", 443),
            ([("tcp", "443")], "udp", 443),
            ([("tcp", "443")], "tcp", 80),
            ([("tcp", "443")], None, 443),
            ([("tcp", "443")], "tcp", None),
            ([("tcp", "443")], None, None),
            ([("tcp", "443")], "udp", None),
            ([("tcp", "443")], None, 80),
            # a member scoped to protocol only.
            ([("!tcp", None)], "udp", None),
            ([("!tcp", None)], "tcp", None),
            ([("!tcp", None)], None, None),
            ([("all", None)], "tcp", None),
            ([("all", None)], None, None),
            ([("!all", None)], "tcp", None),
            ([("!all", None)], None, None),
            # a member scoped to port only.
            ([(None, "1000-2000")], None, 1500),
            ([(None, "1000-2000")], None, 500),
            ([(None, "1000-2000")], None, None),
            ([(None, "1000-2000")], "tcp", 1500),
            # a compound protocol member.
            ([("tcp_udp", "53")], "tcp", 53),
            ([("tcp_udp", "53")], "icmp", 53),
            ([("tcp_udp", "53")], "tcp", 80),
            # two members, each its own protocol with its own port.
            ([("tcp", "443"), ("udp", "53")], "tcp", 443),
            ([("tcp", "443"), ("udp", "53")], "udp", 53),
            ([("tcp", "443"), ("udp", "53")], "tcp", 53),
            ([("tcp", "443"), ("udp", "53")], "udp", 443),
            ([("tcp", "443"), ("udp", "53")], None, 443),
            ([("tcp", "443"), ("udp", "53")], "tcp", None),
            ([("tcp", "443"), ("udp", "53")], None, None),
            ([("tcp", "443"), ("udp", "53")], "icmp", 22),
            # a member scoped to nothing but a numbered protocol.
            ([("253", None)], "253", None),
            ([("253", None)], "254", None),
            ([("253", None)], None, None),
        ],
    )
    def test_point_equivalence(self, pairs, proto, port):
        assert _new_verdict(pairs, proto, port) == _old_verdict(pairs, proto, port)

    @pytest.mark.parametrize(
        ("pairs", "proto", "port", "expected"),
        [
            # 'any' is the explicit full range in the region grammar; the
            # point path compares it as a literal name and misses.
            ([("any", None)], "tcp", None, _MATCH),
            # '!any' is the empty range here; the point path reads the
            # negation of a name no flow carries and matches.
            ([("!any", None)], "tcp", None, _NO_MATCH),
            # a member port of 'any' is the full port range here; the point
            # path has no 'any' token and misses.
            ([(None, "any")], None, 443, _MATCH),
        ],
        ids=[
            "member-any-is-the-full-range-point-path-misses",
            "member-negated-any-is-the-empty-range-point-path-matches",
            "member-port-any-is-the-full-range-point-path-misses",
        ],
    )
    def test_documented_divergence_from_the_point_path(self, pairs, proto, port, expected):
        """The region grammar decides on protocol numbers."""
        assert _new_verdict(pairs, proto, port) == expected
        assert _old_verdict(pairs, proto, port) != expected

    def test_a_member_listing_a_protocol_and_its_negation_is_the_full_range(self):
        # region path: '!tcp' unioned with 'tcp' is every protocol, decided
        # without consulting the query; point path: undecided against a
        # protocol-less query.
        assert _protoset(["!tcp", "tcp"]) == _ALL_PROTOS
        assert _proto_matches(["!tcp", "tcp"], None) == _UNKNOWN

    def test_a_member_spec_outside_the_table_is_undecided_against_a_protocol_query(self):
        # the point path matches the member name to the query string on the spelling
        assert _proto_matches(["fooproto"], "fooproto") == _MATCH
        with pytest.raises(ValueError):
            _protoset(["fooproto"])
        regions = _service_regions([("fooproto", None)], _protoset(["tcp"]), None)
        assert regions.claimed == []
        assert regions.unknown_dims == {"proto"}

    def test_a_member_spec_outside_the_table_is_undecided_without_a_protocol_query(self):
        regions = _service_regions([("fooproto", None)], None, None)
        assert regions.claimed == []
        assert regions.unknown_dims == {"proto"}
        # the same undecided answer the point path gives a protocol-less query.
        assert _proto_matches(["fooproto"], None) == _UNKNOWN


class TestServiceRegionsRectanglePerMember:
    """A range query claims one rectangle per member."""

    def test_members_claim_their_own_rectangle_not_the_crossed_one(self):
        pairs = [("tcp", "443"), ("udp", "53")]
        proto_set = frozenset({6, 17})  # tcp_udp
        port_ivals = [(0, 1, 1024)]
        regions = _service_regions(pairs, proto_set, port_ivals)
        assert regions.claimed == [
            (frozenset({6}), [(0, 443, 443)]),
            (frozenset({17}), [(0, 53, 53)]),
        ]
        assert regions.unknown_dims == set()
        # never the single crossed rectangle {tcp,udp} x {443,53}.
        crossed = (frozenset({6, 17}), [(0, 53, 53), (0, 443, 443)])
        assert crossed not in regions.claimed

    def test_a_member_outside_the_query_range_contributes_no_rectangle(self):
        pairs = [("tcp", "443"), ("udp", "9000")]
        regions = _service_regions(pairs, frozenset({6, 17}), [(0, 1, 1024)])
        assert regions.claimed == [(frozenset({6}), [(0, 443, 443)])]


class TestServiceRegionsUnknownDims:
    """A member scoped to a dimension the query does not carry
    lands in `.unknown_dims`, never folded into a claimed rectangle."""

    def test_proto_not_carried_by_the_query(self):
        regions = _service_regions([("tcp", "443")], None, [(0, 1, 1024)])
        assert regions.claimed == []
        assert regions.unknown_dims == {"proto"}

    def test_port_not_carried_by_the_query(self):
        regions = _service_regions([(None, "443")], frozenset({6}), None)
        assert regions.claimed == []
        assert regions.unknown_dims == {"port"}

    def test_both_dimensions_not_carried(self):
        regions = _service_regions([("tcp", "443")], None, None)
        assert regions.claimed == []
        assert regions.unknown_dims == {"proto", "port"}

    def test_a_definite_miss_on_one_member_does_not_hide_an_unknown_sibling(self):
        # member 1 is a definite protocol miss (dropped, no unknown named);
        # member 2 is scoped to a port the query does not carry.
        pairs = [("udp", None), (None, "443")]
        regions = _service_regions(pairs, frozenset({6}), None)
        assert regions.claimed == []
        assert regions.unknown_dims == {"port"}

    def test_an_unconstrained_member_never_reports_unknown(self):
        # neither dimension is scoped by the member
        regions = _service_regions([(None, None)], None, None)
        assert regions.claimed == [(_ALL_PROTOS, _PORT_UNIVERSE)]
        assert regions.unknown_dims == set()

    def test_a_decisive_no_match_member_beats_an_unknown_other_dimension(self):
        # '!all' matches no protocol, whatever the query carries
        regions = _service_regions([("!all", "443")], None, None)
        assert regions.claimed == []
        assert regions.unknown_dims == set()


class TestUnreadableMemberSpecs:
    """A member spec this grammar cannot read is undecided, never a miss."""

    def test_an_unreadable_protocol_name_names_the_proto_dimension(self):
        regions = _service_regions([("fooproto", "443")], _protoset(["tcp"]), _ports("443"))
        assert regions.claimed == []
        assert regions.unknown_dims == {"proto"}

    def test_an_unreadable_port_spec_names_the_port_dimension(self):
        regions = _service_regions([("tcp", ">1023")], _protoset(["tcp"]), _ports("2000"))
        assert regions.claimed == []
        assert regions.unknown_dims == {"port"}

    def test_a_definite_miss_on_the_other_dimension_beats_an_unreadable_spec(self):
        # the protocol side decides the member outright, so the unreadable
        # port spec never leaves it undecided.
        regions = _service_regions([("tcp", ">1023")], _protoset(["udp"]), _ports("2000"))
        assert regions.claimed == []
        assert regions.unknown_dims == set()

    def test_a_readable_sibling_member_claims_its_rectangle(self):
        pairs = [("fooproto", "443"), ("tcp", "443")]
        regions = _service_regions(pairs, _protoset(["tcp"]), _ports("443"))
        assert regions.claimed == [(frozenset({6}), [(0, 443, 443)])]
        assert regions.unknown_dims == {"proto"}

    def test_a_collector_alias_outside_the_vyos_grammar_claims_a_rectangle(self):
        # Check Point writes "icmp6" where this table's canon is "icmpv6".
        regions = _service_regions([("icmp6", None)], frozenset({58}), None)
        assert regions.claimed == [(frozenset({58}), _PORT_UNIVERSE)]
        assert regions.unknown_dims == set()


class TestEmptyQuerySides:
    """An empty protocol set or an empty port range on the query side is an
    empty rectangle: it covers nothing, so no member may claim it."""

    def test_an_empty_query_protocol_set_claims_nothing(self):
        regions = _service_regions([(None, "443")], frozenset(), [(0, 443, 443)])
        assert regions.claimed == []
        assert regions.unknown_dims == set()

    def test_an_empty_query_port_range_claims_nothing(self):
        regions = _service_regions([("tcp", None)], frozenset({6}), [])
        assert regions.claimed == []
        assert regions.unknown_dims == set()

    def test_an_empty_query_protocol_set_beats_a_member_scoped_to_all(self):
        regions = _service_regions([("all", None)], frozenset(), _PORT_UNIVERSE)
        assert regions.claimed == []
        assert regions.unknown_dims == set()

    def test_an_empty_query_protocol_set_beats_an_unreadable_member_spec(self):
        # An empty query side decides before a member's own spec is read.
        regions = _service_regions([("fooproto", "443")], frozenset(), _ports("443"))
        assert regions.claimed == []
        assert regions.unknown_dims == set()


# --- FlowRegion: the same point-collapse property one level up. A point
# query is a one-rectangle region whose stated dimensions are singletons, and
# `claim` against a member's predicate reproduces `_combine_and`'s verdict for
# that member; ORed across members with `_combine_or` it reproduces the rule's.

_SRC = _intervals(["10.0.0.5"])
_DST = _intervals(["10.9.9.9"])


def _member_predicate(p, q):
    """One member's (proto spec, port spec) as the predicate `claim` reads.
    A member that scopes a dimension to its whole range ('all', 'any') is
    not scoped to it, the same reading `_service_regions` makes of it."""
    protos = _protoset([p]) if p else None
    ports = _ports(q) if q else []
    return Predicate(
        proto=None if protos is None or protos == _ALL_PROTOS else protos,
        dport=None if not ports or ports == _PORT_UNIVERSE else tuple(ports),
    )


def _point_rect(proto, port):
    region = FlowRegion.from_query(_SRC, _DST, _proto_point(proto), _port_point(port))
    assert len(region) == 1
    return region.rects[0]


def _claim_verdict(pairs, proto, port):
    if not pairs:
        return _MATCH
    rect = _point_rect(proto, port)
    states = []
    for p, q in pairs:
        c = claim(rect, _member_predicate(p, q))
        if c.hit is None:
            states.append(_NO_MATCH)
        elif c.unknown:
            states.append(_UNKNOWN)
        else:
            states.append(_MATCH)
    return _combine_or(*states)


class TestFlowRegionPointCollapse:
    """A `FlowRegion` built from a point query collapses to the point path:
    the region is one rectangle whose stated dimensions hold one value each,
    a predicate either takes the whole rectangle or none of it (never a
    remainder), and the three-valued answer is `_combine_and`/`_combine_or`'s."""

    @pytest.mark.parametrize(
        ("pairs", "proto", "port"),
        [
            ([], "tcp", 443),
            ([(None, None)], "tcp", 443),
            ([(None, None)], None, None),
            ([("tcp", "443")], "tcp", 443),
            ([("tcp", "443")], "udp", 443),
            ([("tcp", "443")], "tcp", 80),
            ([("tcp", "443")], None, 443),
            ([("tcp", "443")], "tcp", None),
            ([("tcp", "443")], None, None),
            ([("tcp", "443")], "udp", None),
            ([("tcp", "443")], None, 80),
            ([("!tcp", None)], "udp", None),
            ([("!tcp", None)], "tcp", None),
            ([("!tcp", None)], None, None),
            ([("all", None)], "tcp", None),
            ([("all", None)], None, None),
            ([("!all", None)], "tcp", None),
            ([("!all", None)], None, None),
            ([(None, "1000-2000")], None, 1500),
            ([(None, "1000-2000")], None, 500),
            ([(None, "1000-2000")], None, None),
            ([(None, "1000-2000")], "tcp", 1500),
            ([("tcp_udp", "53")], "tcp", 53),
            ([("tcp_udp", "53")], "icmp", 53),
            ([("tcp_udp", "53")], "tcp", 80),
            ([("tcp", "443"), ("udp", "53")], "tcp", 443),
            ([("tcp", "443"), ("udp", "53")], "udp", 53),
            ([("tcp", "443"), ("udp", "53")], "tcp", 53),
            ([("tcp", "443"), ("udp", "53")], "udp", 443),
            ([("tcp", "443"), ("udp", "53")], None, 443),
            ([("tcp", "443"), ("udp", "53")], "tcp", None),
            ([("tcp", "443"), ("udp", "53")], None, None),
            ([("tcp", "443"), ("udp", "53")], "icmp", 22),
            ([("253", None)], "253", None),
            ([("253", None)], "254", None),
            ([("253", None)], None, None),
        ],
    )
    def test_claim_collapses_to_the_point_verdict(self, pairs, proto, port):
        assert _claim_verdict(pairs, proto, port) == _old_verdict(pairs, proto, port)

    def test_a_point_query_is_one_rectangle_of_singletons(self):
        rect = _point_rect("tcp", 443)
        assert rect.af == 4
        assert rect.proto == frozenset({6})
        assert rect.dport == ((_PORT_FAMILY, 443, 443),)
        assert rect.sport is None
        assert rect.request is rect

    def test_a_point_hit_takes_the_whole_rectangle_and_leaves_no_remainder(self):
        rect = _point_rect("tcp", 443)
        c = claim(rect, _member_predicate("tcp", "1-1024"))
        assert c.hit == rect
        assert c.rest == ()
        assert c.unknown == frozenset()

    def test_a_point_miss_leaves_the_whole_rectangle_to_the_next_rule(self):
        rect = _point_rect("tcp", 443)
        c = claim(rect, _member_predicate("udp", "443"))
        assert c.hit is None
        assert c.rest == (rect,)

    def test_an_unstated_dimension_stays_none_on_the_claimed_part(self):
        rect = _point_rect(None, 443)
        c = claim(rect, _member_predicate("tcp", "443"))
        assert c.unknown == frozenset({"proto"})
        assert c.hit is not None
        assert c.hit.proto is None
        assert c.rest == ()
