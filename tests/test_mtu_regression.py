"""Typed MTU survives immutable exports; semantic evidence does not become configuration."""

from copy import deepcopy
from dataclasses import replace

from tests.test_mtu_assessment import network

from hst.assessment import adapters, package, semantic
from hst.assessment.store import input_digest


def test_export_and_fingerprint_preserve_requirement_and_evidence():
    mtu = {"mode": "packet", "ip_packet_bytes": 1501, "ipv4_df": True, "reply_ip_packet_bytes": 900}
    refs = [{"snapshot": "1000", "manifest_sha256": "synthetic-mtu-manifest"}]
    values = {
        "assessment_id": "mtu",
        "assessment_revision": 1,
        "kind": "evaluate",
        "inputs": {"definition": {"request": {"mtu": mtu}}, "snapshot_refs": refs},
        "snapshot_refs": refs,
        "engine_version": "mtu-v1",
        "limits": {},
        "input_schema_version": 1,
    }
    changed = deepcopy(values)
    changed["inputs"]["definition"]["request"]["mtu"]["ip_packet_bytes"] = 1500
    assert input_digest(values) != input_digest(changed)
    run = {
        **values,
        "input_digest": input_digest(values),
        "id": "mtu-run",
        "state": "completed",
        "result": {"mtu": {"outcome": "unknown", "coverage": {"complete": False}}},
    }
    document = package.export_document(run)
    assert document["run"]["inputs"] == values["inputs"]
    assert document["run"]["result"] == run["result"]
    assert package._validate_document(document) == document


def test_mtu_observation_category_distinguishes_intent():
    for kind in ("operational", "measurement", "hardware"):
        assert (
            semantic._category({"labels": ["MtuObservation"], "props": {"assertion_kind": kind}})
            == "observation"
        )
    for kind in ("configured", "intent"):
        assert (
            semantic._category({"labels": ["MtuObservation"], "props": {"assertion_kind": kind}})
            == "configuration"
        )


def test_counterfactual_interface_edits_preserve_receiving_snapshot_mtu():
    before = network({"if:r1-eth1": 1500})
    after = replace(
        before,
        interfaces=tuple(
            replace(i, addresses=("10.0.1.9",)) if i.uid == "if:r1-eth1" else i for i in before.interfaces
        ),
    )
    changes = adapters.model_changes(
        before, after, {}, {}, complete_fw=[], complete_nat=[], complete_contexts=["vrf:r1", "vrf:a", "vrf:b"]
    )
    projected = adapters.apply_model_edits(before, changes["edits"], direction="forward")
    assert (
        next(i for i in projected.interfaces if i.uid == "if:r1-eth1").mtu_observations_json
        == next(i for i in before.interfaces if i.uid == "if:r1-eth1").mtu_observations_json
    )
