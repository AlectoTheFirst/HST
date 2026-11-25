"""Dual-stack request sets: a client pairs only with member addresses of its
own address family. An IPv4 host never connects directly to an IPv6 host, so
a client of a family no named member has is left out of the answer."""

from __future__ import annotations

import pytest
from tests.test_impact_evaluate import (
    APP,
    CLIENTS,
    R1,
    TCP,
    VRF_A,
    VRF_B,
    VRF_R1,
    B,
    _connected,
    _ctx,
    _firewall,
    _ivals,
    _network,
    _pts,
    _request,
    _static,
    ev,
)
from tests.test_impact_evaluate import graph as graph

from hst.assessment import evaluation
from hst.core.mtu import MtuRequest
from hst.simul import rib

CLIENTS6 = _ivals("2001:db8:10::/64")
APP6 = "2001:db8:30::10"


def _dual_stack_interfaces():
    return (
        ev.Interface(
            R1,
            "if:r1-eth0",
            "eth0",
            VRF_R1,
            ("10.0.0.0/24", "2001:db8:10::/64"),
            ("10.0.0.1", "2001:db8:10::1"),
        ),
        ev.Interface(
            R1,
            "if:r1-eth2",
            "eth2",
            VRF_R1,
            ("10.0.2.0/30", "2001:db8:2::/64"),
            ("10.0.2.1", "2001:db8:2::1"),
        ),
        ev.Interface(
            B, "if:b-eth0", "eth0", VRF_B, ("10.0.2.0/30", "2001:db8:2::/64"), ("10.0.2.2", "2001:db8:2::2")
        ),
        ev.Interface(
            B,
            "if:b-eth1",
            "eth1",
            VRF_B,
            ("203.0.113.0/24", "2001:db8:30::/64"),
            ("203.0.113.2", "2001:db8:30::2"),
        ),
    )


def _dual_stack_routing():
    return rib.RibInput(
        contexts=[_ctx(VRF_R1, R1), _ctx(VRF_A, "dev:a"), _ctx(VRF_B, B)],
        connected=[
            _connected(VRF_R1, "10.0.0.0/24", "eth0"),
            _connected(VRF_R1, "2001:db8:10::/64", "eth0"),
            _connected(VRF_R1, "10.0.2.0/30", "eth2"),
            _connected(VRF_R1, "2001:db8:2::/64", "eth2"),
            _connected(VRF_B, "10.0.2.0/30", "eth0"),
            _connected(VRF_B, "2001:db8:2::/64", "eth0"),
            _connected(VRF_B, "203.0.113.0/24", "eth1"),
            _connected(VRF_B, "2001:db8:30::/64", "eth1"),
        ],
        static=[
            _static("203.0.113.0/24", "10.0.2.2"),
            _static("2001:db8:30::/64", "2001:db8:2::2"),
            _static("10.0.0.0/24", "10.0.2.1", VRF_B),
            _static("2001:db8:10::/64", "2001:db8:2::1", VRF_B),
        ],
        platform="nxos",
    )


def _dual_stack_network():
    return _network(_dual_stack_routing(), _dual_stack_interfaces())


class TestPairing:
    def test_a_member_region_pairs_each_client_with_its_own_family(self):
        request = _request(sources=CLIENTS + CLIENTS6, members=(ev.Member("app", _ivals(APP, APP6)),))
        region = request.member_region(request.members[0])
        assert sorted(r.af for r in region) == [4, 6]
        for rect in region:
            assert {iv[0] for iv in rect.src} == {rect.af}
            assert {iv[0] for iv in rect.dst} == {rect.af}

    def test_clients_of_a_family_no_member_has_are_left_out(self):
        request = _request(sources=CLIENTS + CLIENTS6)
        assert request.sources == CLIENTS
        assert request.unpaired_sources == CLIENTS6
        # rebuilding keeps both halves of the population
        assert ev.replace(request, name="again").unpaired_sources == CLIENTS6

    def test_no_shared_family_is_refused(self):
        with pytest.raises(ValueError, match="never connect directly"):
            _request(sources=CLIENTS6)

    def test_a_member_without_the_clients_family_is_not_counted(self):
        h, f, na = ev.HOLDS, ev.FAILS, ev.NOT_APPLICABLE
        m = ev.member
        assert ev._evaluate(ev.every(m("a"), m("b")), {"a": h, "b": na}) == h
        assert ev._evaluate(ev.every(m("a"), m("b")), {"a": f, "b": na}) == f
        assert ev._evaluate(ev.any_one(m("a"), m("b")), {"a": na, "b": na}) == na
        # a threshold is not lowered: two of three with one backend in this family fails
        assert ev._evaluate(ev.n_of_m(2, m("a"), m("b"), m("c")), {"a": h, "b": na, "c": na}) == f

    def test_ipv4_df_applies_to_the_ipv4_part_only(self):
        mtu = ev.MtuRequirement.from_request(MtuRequest(mode="packet", ip_packet_bytes=1500, ipv4_df=True))
        request = ev.replace(
            _request(sources=CLIENTS + CLIENTS6, members=(ev.Member("app", _ivals(APP, APP6)),)), mtu=mtu
        )
        assert request.unpaired_sources == ()


class TestDualStackAnswer:
    def test_both_families_are_proven_in_one_answer(self, graph):
        _firewall(graph, B, "rb:b", [])
        request = _request(sources=CLIENTS + CLIENTS6, members=(ev.Member("app", _ivals(APP, APP6)),))
        answer = ev.answer(_dual_stack_network(), request)
        assert answer.lower == CLIENTS + CLIENTS6
        assert sorted({e.outcome for e in answer.members["app"].explanations}) == [ev.HOLDS]
        assert evaluation.outcome(answer) == {
            "verdict": ev.HOLDS,
            "isolated": False,
            "holds": ["10.0.0.0/24", "2001:db8:10::/64"],
            "fails": [],
            "unknown": [],
        }

    def test_ipv6_clients_to_an_ipv4_only_service_are_left_out_not_failed(self, graph):
        _firewall(graph, B, "rb:b", [])
        request = _request(sources=CLIENTS + CLIENTS6)
        answer = ev.answer(_dual_stack_network(), request)
        result = evaluation.outcome(answer)
        assert result["verdict"] == ev.HOLDS
        assert result["holds"] == ["10.0.0.0/24"]
        assert result["fails"] == []
        assert result["unpaired"] == ["2001:db8:10::/64"]

    def test_a_dual_stack_and_an_ipv4_only_member_under_every(self, graph):
        _firewall(graph, B, "rb:b", [])
        members = (ev.Member("web", _ivals(APP, APP6)), ev.Member("api", _ivals("203.0.113.20")))
        request = _request(
            sources=CLIENTS + CLIENTS6,
            members=members,
            condition=ev.every(ev.member("web"), ev.member("api")),
        )
        answer = ev.answer(_dual_stack_network(), request)
        # IPv6 clients are held to the dual-stack member only
        assert answer.lower == CLIENTS + CLIENTS6
        assert all(r.af == 4 for r in answer.members["api"].request)

    def test_an_ipv6_failure_is_not_hidden_by_the_ipv4_success(self, graph):
        _firewall(graph, B, "rb:b", [])
        routing = _dual_stack_routing()
        routing = rib.RibInput(
            contexts=routing.contexts,
            connected=routing.connected,
            static=[s for s in routing.static if s["prefix"] != "2001:db8:30::/64"],
            platform="nxos",
        )
        request = _request(sources=CLIENTS + CLIENTS6, members=(ev.Member("app", _ivals(APP, APP6)),))
        answer = ev.answer(_network(routing, _dual_stack_interfaces()), request)
        result = evaluation.outcome(answer)
        assert result["holds"] == ["10.0.0.0/24"]
        assert result["fails"] == ["2001:db8:10::/64"]
        assert result["verdict"] == ev.FAILS


def test_service_and_port_survive_the_split():
    request = _request(
        sources=CLIENTS + CLIENTS6, members=(ev.Member("app", _ivals(APP, APP6)),), port="443", proto=TCP
    )
    region = list(request.member_region(request.members[0]))
    assert region
    for rect in region:
        assert rect.proto == TCP
        assert tuple(rect.dport) == _pts("443")


def test_the_checkout_example_is_ready_and_the_engine_accepts_it():
    from pathlib import Path

    from hst.applications.resolution import StaticInventoryReader, resolve_application
    from hst.applications.yaml_format import parse_application_yaml

    example = Path(__file__).resolve().parents[1] / "docs" / "examples" / "business-application.yaml"
    resolved = resolve_application(
        parse_application_yaml(example.read_text()),
        revision=1,
        snapshot={"snapshot": "100", "manifest_sha256": "a", "estate": "test"},
        reader=StaticInventoryReader({}),
        connection_ids=["clients-to-frontend"],
    )
    connection = resolved["connections"][0]
    assert connection["readiness"] == "ready", connection["issues"]
    request = evaluation._request_from_body(evaluation.RequestBody.model_validate(connection["request"]))
    # the IPv4 branch clients pair with the IPv4 frontend; the IPv6 clients have no peer
    assert request.sources == _ivals("192.0.2.0/24")
    assert request.unpaired_sources == _ivals("2001:db8:10::/64")
