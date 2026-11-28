"""The demo estate's devices bind the policy each flow meets, read from the fixture graph alone.

fixtures/demo-enterprise/estate-v3.yaml as the analysis child loads it, without
a database. The Vienna FortiGate binds the zone pair a flow enters and leaves
by and never its NAT rulebase; the dc1 Check Point gateway binds its access
layer; neither carries installation evidence, which no collector writes for
them, so both remain INSTALLATION_UNKNOWN. The ACI PBR rule reads its campus
and server objects, and the ACI contract filters read their destination ports.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.support.batch_inventory import inventory

from hst.analysis_model.gates import _aci_contract_filter, _rule_predicate, expand_aci_contracts
from hst.analysis_model.model import StateKey
from hst.analysis_model.network import _bindings, _egress_scoped
from hst.core.fixtures import load_fixture
from hst.policy.ir import AllOf, AnyOf, Atom, ExecutionContext, Predicate, Unknown

DEMO = Path(__file__).parents[2] / "fixtures" / "demo-enterprise" / "estate-v3.yaml"
FGT = "dev:vie01-fgt-01"
FGT_POLICY = "fgt:FGT100F7084444526:root:policy"
CPFW = "dev:dc1-cpfw-01"
LEAF = "dev:dc1-leaf-05"
CTX1 = "vrf:aci:fab-dc1:tn-PROD:CTX1"


@pytest.fixture(scope="module")
def graph():
    return inventory(load_fixture(DEMO))


def _unknowns(predicate: Predicate) -> list[Unknown]:
    if isinstance(predicate, Unknown):
        return [predicate]
    return [item for term in getattr(predicate, "terms", ()) for item in _unknowns(term)]


def test_the_vienna_fortigate_binds_the_zone_pair_of_the_flow_and_never_its_nat_rulebase(graph):
    context = ExecutionContext("demo", "graph", "graph", FGT, "vrf:dev:vie01-fgt-01:root", 4)
    corp, guest, wan = (f"{FGT}/if/port{index}" for index in (1, 2, 3))

    assert _bindings(graph, context, corp, wan, 4) == (
        (f"{FGT_POLICY}:corp-wan",),
        Unknown("INSTALLATION_UNKNOWN", FGT),
    )
    assert _bindings(graph, context, guest, wan, 4)[0] == (f"{FGT_POLICY}:guest-internet",)
    for ingress, egress in ((corp, wan), (guest, wan), (corp, None), (None, None)):
        assert f"{FGT_POLICY}:nat" not in _bindings(graph, context, ingress, egress, 4)[0]
    assert _egress_scoped(graph, context, corp, 4) is True


def test_the_dc1_check_point_gateway_binds_its_layer_without_installation_evidence(graph):
    context = ExecutionContext("demo", "graph", "graph", CPFW, "vrf:dev:dc1-cpfw-01:default", 4)

    assert _bindings(graph, context, f"{CPFW}/if/eth1", None, 4) == (
        ("cp:cpmgmt-01:smc:pkg-dc1-access",),
        Unknown("INSTALLATION_UNKNOWN", CPFW),
    )


def test_the_aci_pbr_rule_reads_its_campus_and_server_objects(graph):
    (policy,) = [
        node for node in graph.targets(f"{LEAF}/if/vlan111", "ENFORCES") if "PbrPolicy" in node.labels
    ]
    (rule,) = graph.targets(policy.uid, "HAS_RULE")
    predicate = _rule_predicate(graph, rule, 4)

    assert _unknowns(predicate) == []
    assert isinstance(predicate, AllOf)
    fields = {atom.field for side in predicate.terms if isinstance(side, AnyOf) for atom in side.terms}
    assert fields == {"source_address", "destination_address"}


def test_the_webshop_api_to_db_contract_filter_reads_its_destination_port(graph):
    contract = "aci:fab-dc1:uni/tn-PROD/brc-webshop-api-to-db"
    assert _aci_contract_filter(graph, contract) == AnyOf(
        (AllOf((Atom("protocol", "eq", 6), Atom("destination_port", "range", 5432, 5432))),)
    )


def test_the_aci_gate_state_is_complete_on_the_demo_estate(graph):
    context = ExecutionContext("demo", "graph", "graph", LEAF, CTX1, 4)
    expansion = expand_aci_contracts(graph, context, StateKey("routing", context))
    gate = next(node for node in expansion.nodes if node.key == expansion.entry)

    assert gate.complete is True
    assert "ACI_INTRA_EPG_ISOLATION_UNKNOWN" in expansion.gaps
