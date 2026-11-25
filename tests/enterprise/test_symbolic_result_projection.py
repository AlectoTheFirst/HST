"""Independent concrete client quantifiers and bounded exact result presentation."""

from __future__ import annotations

import os
from dataclasses import replace
from ipaddress import ip_network

import pytest

from hst.analysis_model.model import ChoiceAssignment
from hst.assessment.symbolic_results import aggregate, comparison
from hst.impact.evaluate import Member, RequestSet, Service, every
from hst.impact.evaluate import member as condition_member
from hst.impact.symbolic_walk import ChoiceResult, WalkResult
from hst.policy.bounds import Bounds
from hst.symbolic import BackendUnavailableError, HeaderSchema, SymbolicManager, header
from hst.symbolic.address_render import address_prefixes
from hst.symbolic.predicates import masked, value_range


@pytest.fixture
def manager():
    try:
        native = SymbolicManager(HeaderSchema.ipv4())
    except BackendUnavailableError:
        if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
            pytest.fail("required native backend missing")
        pytest.skip("optional native backend missing")
    with native:
        yield native
    assert len(native._bdd) == 0


def test_prefix_pages_count_noncontiguous_masks_without_enumerating(manager):
    # Every even IPv4 address: 2**31 /32 prefixes, with only 32 DAG levels.
    packets = masked(manager, "source_address", 0, 1, bank="original")
    page = address_prefixes(packets, offset=2**31 - 3, limit=2)
    assert page.count == page.addresses == 2**31
    assert page.items == ("255.255.255.250/32", "255.255.255.252/32")
    assert page.next_offset == 2**31 - 1
    compact = address_prefixes(value_range(manager, "source_address", 0, 255, bank="original"))
    assert compact.items == ("0.0.0.0/24",) and compact.addresses == 256


def test_prefix_render_unions_and_page_concatenation(manager):
    packets = value_range(manager, "source_address", 1, 19, bank="original")
    full = address_prefixes(packets)
    pages = [address_prefixes(packets, offset=index, limit=1).items[0] for index in range(full.count)]
    assert tuple(pages) == full.items
    assert {int(ip) for cidr in pages for ip in ip_network(cidr)} == set(range(1, 20))
    assert address_prefixes(packets, offset=full.count).items == ()


def _request():
    members = (Member("a", ((4, 10, 11),)), Member("b", ((4, 20, 21),)))
    return RequestSet(
        "service",
        ((4, 1, 2),),
        "logical",
        members,
        every(condition_member("a"), condition_member("b")),
        Service(frozenset({6})),
    )


def _result(manager, request, member, successful):
    universe = header(
        manager,
        {
            "source_address": (1, 2),
            "destination_address": (member.addresses[0][1], member.addresses[0][2]),
            "protocol": 6,
            "fragment_offset": 0,
        },
        bank="original",
    )
    results = []
    for index, addresses in enumerate(successful):
        passed = manager.empty()
        for source, destination in addresses:
            passed = passed.union(
                header(
                    manager, {"source_address": source, "destination_address": destination}, bank="original"
                ).intersect(universe)
            )
        bound = Bounds(universe, passed, passed)
        results.append(ChoiceResult(ChoiceAssignment(str(index)), bound, True, (), ()))
    marginal = Bounds(universe, universe, universe)
    return WalkResult("a" * 64, "model", request.name, marginal, tuple(results), True, True, (), 1, 1)


def test_universal_flow_projection_happens_before_joint_member_choice(manager):
    request = _request()
    a = _result(manager, request, request.members[0], ({(1, 10), (1, 11), (2, 10)}, {(2, 10), (2, 11)}))
    b = _result(
        manager, request, request.members[1], ({(2, 20), (2, 21)}, {(1, 20), (1, 21), (2, 20), (2, 21)})
    )
    answer = aggregate(request, {"a": a, "b": b}, mode="possible")
    assert address_prefixes(answer.lower).items == ("0.0.0.2/32",)
    guaranteed = aggregate(request, {"a": a, "b": b}, mode="guaranteed")
    assert guaranteed.upper.is_empty()
    # A's marginal claimed all clients; the compound result must use per-choice evidence.
    assert answer.lower.equivalent(answer.upper)
    encoded = comparison(guaranteed, replace(answer, mode="guaranteed"))
    assert encoded["result_schema"] == 2 and encoded["symbolic"]["artifact"]["complete"] is True
    assert encoded["proven"]["gain"]["address_count_decimal"] == "1"


def test_narrowed_population_or_incomplete_choices_cannot_prove_service(manager):
    request = _request()
    a = _result(manager, request, request.members[0], ({(1, 10), (1, 11), (2, 10), (2, 11)},))
    b = _result(manager, request, request.members[1], ({(1, 20), (1, 21), (2, 20), (2, 21)},))
    uncertain = aggregate(request, {"a": replace(a, choices_complete=False), "b": b}, mode="possible")
    assert uncertain.lower.is_empty() and not uncertain.upper.is_empty()
    with pytest.raises(ValueError, match="declared source population"):
        aggregate(replace(request, sources=((4, 1, 3),)), {"a": a, "b": b}, mode="possible")
