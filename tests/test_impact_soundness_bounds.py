import importlib
import itertools

from hst.path.addrsets import _intervals, _subtract
from hst.simul import bestpath, rib
from hst.simul.route import Route

ev = importlib.import_module("hst.impact.evaluate")


def _route(**kwargs):
    return Route(prefix="10.0.0.0/24", **kwargs)


# --- the arrival-order tie-break -------------------------------------------


def test_an_arrival_decided_selection_is_reported():
    """The earlier path wins on arrival, and the later steps would have picked
    the other one, so the outcome depends on the message history."""
    early = _route(arrival=1, originator_ip="10.0.0.9")
    late = _route(arrival=2, originator_ip="10.0.0.1")
    best, by_arrival = bestpath.best_path_with_tie([early, late])
    assert best is early
    assert by_arrival is True


def test_later_tie_breaks_do_not_remove_arrival_uncertainty():
    """Reversing arrival selects the other path before originator-ID runs."""
    early = _route(arrival=1, originator_ip="10.0.0.1")
    late = _route(arrival=2, originator_ip="10.0.0.9")
    best, by_arrival = bestpath.best_path_with_tie([early, late])
    assert best is early
    assert by_arrival is True
    reversed_best, reversed_uncertain = bestpath.best_path_with_tie(
        [early.with_(arrival=2), late.with_(arrival=1)]
    )
    assert reversed_best.originator_ip == late.originator_ip
    assert reversed_uncertain is True


def test_a_selection_preference_decides_is_not_reported():
    """A selection preference decided it, so the arrival tie-break never ran."""
    preferred = _route(arrival=2, local_pref=200)
    other = _route(arrival=1, local_pref=100)
    best, by_arrival = bestpath.best_path_with_tie([preferred, other])
    assert best is preferred
    assert by_arrival is False


def test_a_single_candidate_has_no_tie():
    _best, by_arrival = bestpath.best_path_with_tie([_route(arrival=1)])
    assert by_arrival is False
    assert bestpath.best_path_with_tie([])[0] is None


def test_best_path_and_best_path_with_tie_select_the_same_route():
    routes = [_route(arrival=1, originator_ip="10.0.0.9"), _route(arrival=2, originator_ip="10.0.0.1")]
    assert bestpath.best_path(routes) is bestpath.best_path_with_tie(routes)[0]


# --- the disjoint report ---------------------------------------------------

_SETS = [frozenset(c) for n in range(5) for c in itertools.combinations(range(4), n)]
# Every bounded answer over a universe of four requests: a lower bound inside
# its upper bound.
_BOUNDS = [(lo, up) for lo in _SETS for up in _SETS if lo <= up]


def _triage_sets(lower_before, upper_before, lower_after, upper_after):
    return ev._triage(
        lower_before,
        upper_before,
        lower_after,
        upper_after,
        meet=lambda a, b: a & b,
        less=lambda a, b: a - b,
    )


def test_the_loss_parts_do_not_overlap_and_cover_possible_loss():
    for (lb, ub), (la, ua) in itertools.product(_BOUNDS, _BOUNDS):
        t = _triage_sets(lb, ub, la, ua)
        parts = [t.proven_loss, t.worked_now_unknown, t.unknown_now_broken, t.unknown_throughout]
        for a, b in itertools.combinations(parts, 2):
            assert not (a & b), (lb, ub, la, ua)
        assert set().union(*parts) == ub - la, (lb, ub, la, ua)


def test_the_gain_parts_do_not_overlap_and_cover_possible_gain():
    for (lb, ub), (la, ua) in itertools.product(_BOUNDS, _BOUNDS):
        t = _triage_sets(lb, ub, la, ua)
        parts = [t.proven_gain, t.unknown_now_works, t.broken_now_unknown, t.unknown_throughout]
        for a, b in itertools.combinations(parts, 2):
            assert not (a & b), (lb, ub, la, ua)
        assert set().union(*parts) == ua - lb, (lb, ub, la, ua)


def test_each_part_means_what_its_name_says():
    """One request per part, so the names are pinned to the four outcomes."""
    # 0 worked and is broken; 1 worked and is unproven; 2 was unproven and is
    # broken; 3 was unproven and is unproven still.
    t = _triage_sets(frozenset({0, 1}), frozenset({0, 1, 2, 3}), frozenset(), frozenset({1, 3}))
    assert t.proven_loss == {0}
    assert t.worked_now_unknown == {1}
    assert t.unknown_now_broken == {2}
    assert t.unknown_throughout == {3}


def test_proven_loss_sits_inside_possible_loss():
    """The overlap the disjoint parts exist to resolve."""
    t = _triage_sets(frozenset({0, 1}), frozenset({0, 1, 2, 3}), frozenset(), frozenset({1, 3}))
    assert t.proven_loss <= (frozenset({0, 1, 2, 3}) - frozenset())


def test_the_same_split_holds_over_address_intervals():
    """The evaluator's own set type, not only the algebra."""
    lb = tuple(_intervals(["10.0.0.0/25"]))
    ub = tuple(_intervals(["10.0.0.0/24"]))
    la: tuple = ()
    ua = tuple(_intervals(["10.0.0.64/26"]))
    t = ev._triage(
        lb,
        ub,
        la,
        ua,
        meet=lambda a, b: tuple(ev._intersect(list(a), list(b))),
        less=lambda a, b: tuple(_subtract(list(a), list(b))),
    )
    # 10.0.0.0/26 was proven and is now a proven failure; 10.0.0.64/26 was
    # proven and is now unproven; the upper half was never proven.
    assert t.proven_loss == tuple(_intervals(["10.0.0.0/26"]))
    assert t.worked_now_unknown == tuple(_intervals(["10.0.0.64/26"]))
    assert t.unknown_now_broken == tuple(_intervals(["10.0.0.128/25"]))
    assert t.unknown_throughout == ()


# --- the gap reaches the evaluator -----------------------------------------


class _FakeRoutes:
    """Only the parts `Network.incomplete` reads."""

    def __init__(self, gaps):
        self.gaps = gaps
        self.model_errors = ()
        self.validation = ()


def _network_with_gaps(gaps):
    net = ev.Network(rib.RibInput(), (), ev.GraphGates(session=None))
    # `routes` is a cached_property, so seeding the cache stands in for a run
    net.__dict__["routes"] = _FakeRoutes(gaps)
    return net


_ARRIVAL_GAP = {
    "kind": rib.HISTORY_DEPENDENT,
    "context_uid": "vrf:a",
    "process_uid": "bgp:r1",
    "prefix": "203.0.113.0/24",
    "detail": "arrival order decided the selection",
}


def test_an_arrival_decided_prefix_cannot_be_proven():
    net = _network_with_gaps([_ARRIVAL_GAP])
    assert "arrival order decided the selection" in net.incomplete(
        "vrf:a", tuple(_intervals(["203.0.113.0/24"]))
    )


def test_another_prefix_of_the_same_context_keeps_its_proof():
    """The gap is scoped to the prefix the tie-break decided."""
    net = _network_with_gaps([_ARRIVAL_GAP])
    assert net.incomplete("vrf:a", tuple(_intervals(["198.51.100.0/24"]))) == ()


def test_another_context_is_untouched():
    net = _network_with_gaps([_ARRIVAL_GAP])
    assert net.incomplete("vrf:b", tuple(_intervals(["203.0.113.0/24"]))) == ()
