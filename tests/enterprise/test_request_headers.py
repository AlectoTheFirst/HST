"""Public packet dimensions preserve explicit values and omitted knowledge."""

import pytest
from fastapi import HTTPException

from hst.assessment.evaluation import RequestBody, _request_from_body
from hst.assessment.request_document import request_document
from hst.assessment.symbolic_evaluation import (
    INITIAL_FRAGMENTS_ASSUMPTION,
    answer_assumptions,
    initial_fragments_assumed,
    member_packets,
)
from hst.impact.evaluate import SPREAD_ASSUMPTION

from .test_assessment_symbolic_bridge import native as native


def _body(**values):
    return RequestBody.model_validate(
        {
            "name": "web",
            "destination": "service",
            "sources": ["192.0.2.1"],
            "members": [{"name": "web", "addresses": ["198.51.100.1"]}],
            "condition": {"kind": "member", "member": "web"},
            "proto": "tcp",
            "port": "443",
            **values,
        }
    )


def test_explicit_header_values_round_trip_and_enter_native_packet_set(native):
    request = _request_from_body(
        _body(header_constraints={"fragment_offset": [[0, 0]], "tcp_flags": [[2, 2]]})
    )
    assert _request_from_body(RequestBody.model_validate(request_document(request))) == request
    packets = member_packets(native, request, request.members[0])
    assert {"fragment_offset", "tcp_flags"} <= packets.known_fields
    assert packets.cardinality(("fragment_offset", "tcp_flags")) == 1
    assert "dscp" not in packets.known_fields
    with pytest.raises(ValueError, match="symbolic analysis"):
        request.member_region(request.members[0])


def test_out_of_range_or_unknown_fields_are_rejected():
    for constraints in ({"fragment_offset": [[0, 8192]]}, {"unmodeled": [[0, 0]]}):
        with pytest.raises(HTTPException):
            _request_from_body(_body(header_constraints=constraints))


class _Schema:
    address_family = 4

    @staticmethod
    def canonical_field(name):
        return name


def _packets_call(monkeypatch, **values):
    """What `member_packets` hands the packet builder, without a native manager."""
    seen = {}

    def header(_manager, constraints, *, explicitly_all=()):
        seen["constraints"], seen["explicit"] = dict(constraints), set(explicitly_all)
        return type("Packets", (), {"is_empty": lambda self: False})()

    monkeypatch.setattr("hst.assessment.symbolic_evaluation.header", header)
    manager = type("Manager", (), {"schema": _Schema()})()
    request = _request_from_body(_body(**values))
    member_packets(manager, request, request.members[0])
    return seen, initial_fragments_assumed(manager, request, request.members[0])


def test_a_stated_nonzero_port_states_the_initial_fragment_it_implies(monkeypatch):
    # a nonzero port is valid only in an initial fragment, so a port-based
    # permit can be proven without the user adding a header constraint
    for values in ({"port": "443"}, {"port": "1024-65535"}, {"port": "443", "proto": "udp"}):
        seen, assumed = _packets_call(monkeypatch, **values)
        assert seen["explicit"] == {"fragment_offset"}
        assert "fragment_offset" not in seen["constraints"]
        assert assumed is False


def test_a_request_with_no_port_forcing_a_fragment_assumes_the_initial_fragment(monkeypatch):
    for values in ({"port": "0-100"}, {"port": None, "proto": "tcp"}):
        seen, assumed = _packets_call(monkeypatch, **values)
        assert (
            seen["constraints"]["fragment_offset"][0].lower
            == seen["constraints"]["fragment_offset"][0].upper
            == 0
        )
        assert seen["explicit"] == set()
        assert assumed is True
    assert "INITIAL_FRAGMENTS_ONLY" in INITIAL_FRAGMENTS_ASSUMPTION


def test_a_fragment_offset_the_user_states_is_never_assumed(monkeypatch):
    for port in (None, "443"):
        seen, assumed = _packets_call(
            monkeypatch, port=port, header_constraints={"fragment_offset": [[8, 8]]}
        )
        (stated,) = seen["constraints"]["fragment_offset"]
        assert (stated.lower, stated.upper) == (8, 8)
        assert assumed is False


def test_the_answer_names_the_initial_fragment_assumption_when_it_was_made():
    manager = type("Manager", (), {"schema": _Schema()})()
    for port, assumptions in (
        ("0-100", (SPREAD_ASSUMPTION, INITIAL_FRAGMENTS_ASSUMPTION)),
        ("443", (SPREAD_ASSUMPTION,)),
    ):
        request = _request_from_body(_body(port=port))
        assert answer_assumptions(manager, request) == assumptions
    stated = _request_from_body(_body(port="0-100", header_constraints={"fragment_offset": [[0, 0]]}))
    assert answer_assumptions(manager, stated) == (SPREAD_ASSUMPTION,)


def test_the_answer_names_the_contexts_whose_computed_routes_it_follows():
    manager = type("Manager", (), {"schema": _Schema()})()
    request = _request_from_body(_body(port="443"))
    assert answer_assumptions(manager, request, {"vrf:b", "vrf:a"}) == (
        SPREAD_ASSUMPTION,
        "COMPUTED_ROUTES: no collected routing table confirms the computed routes of vrf:a, vrf:b",
    )
