"""Pinned manifest evidence reaches compiled routing nodes by device UID."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from types import MappingProxyType, SimpleNamespace

import pytest

from hst.analysis_model.compile import compile_model
from hst.analysis_model.evidence import EvidencePolicy
from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.analysis_model.network import normalize_request_network
from hst.analysis_model.temporal import manifest_evidence
from hst.impact.evaluate import Interface, Member, Network, RequestSet, member
from hst.simul.rib import RibInput
from hst.symbolic import BackendUnavailableError, HeaderSchema, SymbolicManager


class _Gates:
    def with_changes(self, _changes):
        return self


def _intervals(value: str):
    import ipaddress

    address = ipaddress.ip_address(value)
    return ((address.version, int(address), int(address)),)


@pytest.fixture
def manager():
    try:
        symbolic = SymbolicManager(HeaderSchema.ipv4())
    except BackendUnavailableError:
        if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
            pytest.fail("required native backend missing")
        pytest.skip("optional native backend missing")
    with symbolic:
        yield symbolic


def test_manifest_device_uid_evidence_makes_partial_stale_routing_unknown(manager):
    observed = datetime(2026, 9, 13, 10, tzinfo=UTC)
    section = SimpleNamespace(status="partial")
    snapshot = SimpleNamespace(
        manifest=SimpleNamespace(
            devices=(
                SimpleNamespace(
                    source="nxos",
                    host="controller.example",
                    device_uids=("device:router-1",),
                    fetch_started_ms=int(observed.timestamp() * 1000),
                    fetch_finished_ms=int(observed.timestamp() * 1000),
                    source_clock_ms=None,
                    effective_run="run-1",
                    sections={"routes": section},
                ),
            )
        )
    )
    evidence = manifest_evidence(
        snapshot,
        analysis_time=observed + timedelta(hours=2),
        policy=EvidencePolicy(max_age_s=60),
    )
    graph = GraphInventory(
        "a" * 64,
        "graph",
        MappingProxyType({}),
        MappingProxyType({}),
        MappingProxyType({}),
        MappingProxyType({}),
        True,
        (),
        0,
    )
    network = Network(
        RibInput(
            contexts=[{"uid": "vrf:blue", "device_uid": "device:router-1", "platform": "nxos"}],
            connected=[{"context_uid": "vrf:blue", "prefix": "10.0.0.0/24", "interface": "lan"}],
        ),
        (Interface("device:router-1", "if:lan", "lan", "vrf:blue", ("10.0.0.0/24",), ("10.0.0.1",)),),
        _Gates(),
    )
    request = RequestSet(
        "temporal",
        _intervals("10.0.0.10"),
        "destination",
        (Member("destination", _intervals("10.0.0.20")),),
        member("destination"),
        source_context="vrf:blue",
    )

    source = normalize_request_network(network, graph, request, "estate", evidence=evidence)["destination"]
    compiled = compile_model(source, manager, manager.schema.field_names)
    routing = next(node for node in compiled.nodes if node.key.location == "routing:vrf:blue:ingress:none")

    source_routing = next(
        node for node in source.nodes if node.key.location == "routing:vrf:blue:ingress:none"
    )
    assert {reference.subject for reference in source_routing.evidence} == {"device:router-1"}
    assert {"partial-evidence", "stale-evidence", "clock-quality-uncertain"} <= set(routing.gap_refs)


def test_manifest_installation_window_uses_observed_configured_and_installed_revisions():
    observed = datetime(2026, 9, 13, 10, tzinfo=UTC)
    snapshot = SimpleNamespace(
        manifest=SimpleNamespace(
            devices=(
                SimpleNamespace(
                    source="checkpoint_gateway",
                    host="gaia.example",
                    device_uids=("device:gateway-1",),
                    fetch_started_ms=int(observed.timestamp() * 1000),
                    fetch_finished_ms=int(observed.timestamp() * 1000),
                    source_clock_ms=None,
                    effective_run="run-2",
                    sections={"installation": SimpleNamespace(status="complete")},
                ),
            )
        )
    )
    rulebase = GraphNode(
        "rulebase:one", frozenset({"FwRulebase"}), MappingProxyType({"configured_revision": "a"})
    )
    relation = GraphRelation(
        "installed:one",
        "ENFORCES",
        "device:gateway-1",
        "rulebase:one",
        MappingProxyType({"installed": True, "installed_revision": "b", "observation_uid": "observe-1"}),
    )
    graph = GraphInventory(
        "a" * 64,
        "graph",
        MappingProxyType({rulebase.uid: rulebase}),
        MappingProxyType({"FwRulebase": (rulebase.uid,)}),
        MappingProxyType({}),
        MappingProxyType({(rulebase.uid, "ENFORCES"): (relation,)}),
        True,
        (),
        0,
    )

    evidence = manifest_evidence(snapshot, analysis_time=observed, policy=EvidencePolicy(), graph=graph)

    assert evidence.windows[0].revision.configured_revision == "a"
    assert evidence.windows[0].revision.installed_revision == "b"
    assert evidence.windows[0].revision_scope == "rulebase:one"
    assert "installed-revision-mismatch" in {gap.code.value for gap in evidence.gaps}


def test_skew_is_judged_over_the_devices_the_model_depends_on():
    observed = datetime(2026, 9, 13, 10, tzinfo=UTC)

    def entry(device: str, at: datetime):
        ms = int(at.timestamp() * 1000)
        return SimpleNamespace(
            source="nxos",
            host=device,
            device_uids=(device,),
            fetch_started_ms=ms,
            fetch_finished_ms=ms,
            source_clock_ms=None,
            effective_run="run-1",
            sections={"routes": SimpleNamespace(status="ok")},
        )

    snapshot = SimpleNamespace(
        manifest=SimpleNamespace(
            devices=(
                entry("device:router-1", observed),
                entry("device:far", observed - timedelta(minutes=10)),
            )
        )
    )
    evidence = manifest_evidence(snapshot, analysis_time=observed, policy=EvidencePolicy())
    assert "excessive-skew" in {gap.code.value for gap in evidence.gaps if gap.subject == "device:router-1"}
    graph = GraphInventory(
        "a" * 64,
        "graph",
        MappingProxyType({}),
        MappingProxyType({}),
        MappingProxyType({}),
        MappingProxyType({}),
        True,
        (),
        0,
    )
    network = Network(
        RibInput(
            contexts=[{"uid": "vrf:blue", "device_uid": "device:router-1", "platform": "nxos"}],
            connected=[{"context_uid": "vrf:blue", "prefix": "10.0.0.0/24", "interface": "lan"}],
        ),
        (Interface("device:router-1", "if:lan", "lan", "vrf:blue", ("10.0.0.0/24",), ("10.0.0.1",)),),
        _Gates(),
    )
    request = RequestSet(
        "temporal",
        _intervals("10.0.0.10"),
        "destination",
        (Member("destination", _intervals("10.0.0.20")),),
        member("destination"),
        source_context="vrf:blue",
    )

    source = normalize_request_network(network, graph, request, "estate", evidence=evidence)["destination"]

    assert source.evidence is not None
    assert {window.subject for window in source.evidence.windows} == {"device:router-1"}
    assert "excessive-skew" not in {gap.code.value for gap in source.evidence.gaps}
