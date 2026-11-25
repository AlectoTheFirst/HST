"""Synthetic NX-OS interface payload MTU evidence through graph and path evaluation."""

import json

import pytest

import test_nxos as nx
from hst.assessment.mtu import audit_neighbors
from hst.collectors import nxos
from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.collectors.cisco_common import MTU_COMMANDS
from hst.core import uid
from hst.core.mtu import MtuContext, MtuCoverage, MtuEncapsulation, MtuObservation, MtuRequest, MtuStage
from hst.core.mtu_profiles import restate_ip_bytes
from hst.core.mtu_read import resolve_constraints
from hst.path.mtu import constraint_budget, evaluate_stage
from hst.simul.fw_overlay import ChangeSet
from test_nxos_mtu_qos import capture


def normalize_port(name="Ethernet1/1", value="1500", *, field="eth_mtu", release="10.5(4)"):
    raw = capture(release=release)
    raw[nxos.CMD_INTERFACE] = json.dumps(
        {
            "TABLE_interface": {
                "ROW_interface": {
                    "interface": name,
                    "state": "down",
                    "admin_state": "down",
                    "eth_hw_desc": "Ethernet",
                    "encapsulation": "ARPA",
                    field: value,
                }
            }
        }
    )
    # The interface evidence is JSON only.
    for role in ("media", "ipv4"):
        command = MTU_COMMANDS["nxos"][role]
        raw.pop(command)
        raw[RAW_OUTCOMES_KEY].pop(command)
    raw.pop(nxos.CMD_INTERFACE_CONFIG, None)
    return nx._collector().normalize(raw)


def observations(batch):
    return [MtuObservation(uid=n.uid, **n.props) for n in batch.nodes if n.label == "MtuObservation"]


@pytest.mark.parametrize("name", ["Ethernet1/1", "Port-channel3", "mgmt0"])
@pytest.mark.parametrize("value", [1500, "1500", 9216, "9216"])
def test_json_payload_mtu_resolves_without_gaps(name, value):
    batch = normalize_port(name, value)
    assert not batch.validate_registry()
    obs = observations(batch)
    assert len(obs) == 1
    assert obs[0].metric == "l2_payload_mtu_bytes"
    assert obs[0].raw_basis == "ethernet_payload"
    assert obs[0].normalized_value == int(value)
    assert obs[0].gaps == []
    assert json.loads(obs[0].raw_value_json) == value
    dev = next(n.uid for n in batch.nodes if n.label == "Device")
    assert obs[0].subject_uid == uid.port(dev, name)
    result = resolve_constraints(obs, MtuContext(af=4, enforcement="l2"))
    assert result.gaps == []
    assert result.constraints[0].value_bytes == int(value)
    assert audit_neighbors(result, result) == []


@pytest.mark.parametrize("af", [4, 6])
@pytest.mark.parametrize("direction", ["tx", "rx"])
@pytest.mark.parametrize("tags", [None, 0, 1])
def test_payload_budget_at_the_boundary_for_both_families_and_directions(af, direction, tags):
    obs = observations(normalize_port())
    context = MtuContext(af=af, direction=direction, enforcement="l2", tag_depth=tags)
    resolved = resolve_constraints(obs, context)
    stage = MtuStage(
        stage_id="synthetic-port",
        egress_subject_uid=obs[0].subject_uid,
        enforcement="l2",
        context=context,
        constraints=resolved.constraints,
        selection="selected",
        coverage=MtuCoverage(complete=True, constraints_complete=True, candidate_set_complete=True),
    )
    assert constraint_budget(stage.constraints[0], stage) == (1500, [])
    assert evaluate_stage(stage, MtuRequest(mode="unfragmented", ip_packet_bytes=1500)).outcome == "pass"
    oversize = evaluate_stage(stage, MtuRequest(mode="unfragmented", ip_packet_bytes=1501))
    assert oversize.outcome == "fail"
    assert oversize.known_ceiling_bytes == 1500
    assert oversize.coverage.gaps == []


def test_payload_budget_charges_pppoe_overhead():
    obs = observations(normalize_port())
    context = MtuContext(af=4, enforcement="l2", tag_depth=1)
    resolved = resolve_constraints(obs, context)
    stage = MtuStage(
        stage_id="pppoe-carrier",
        context=context,
        enforcement="l2",
        constraints=resolved.constraints,
        encapsulation=[
            MtuEncapsulation(
                kind="pppoe",
                profile_id="pppoe_rfc2516_v1",
                parameters_json='{"version":1,"options_complete":true,"ppp_protocol_bytes":2}',
            )
        ],
    )
    assert constraint_budget(stage.constraints[0], stage) == (1492, [])


@pytest.mark.parametrize("value", ["broken", "", 0, -1, True])
def test_invalid_payload_is_preserved_without_a_numeric_limit(value):
    obs = observations(normalize_port(value=value))
    assert len(obs) == 1
    assert obs[0].normalized_value is None
    assert "MTU_SEMANTICS_UNKNOWN" in obs[0].gaps


@pytest.mark.parametrize(
    ("name", "field", "release"),
    [
        ("Ethernet1/1", "eth_mtu", "9.3(5)"),
        ("Ethernet1/1", "other_mtu", "10.5(4)"),
        ("Ethernet1/1.20", "eth_mtu", "10.5(4)"),
        ("Tunnel1", "eth_mtu", "10.5(4)"),
    ],
)
def test_unknown_profile_or_field_stays_unresolved(name, field, release):
    obs = observations(normalize_port(name, field=field, release=release))
    interface = [o for o in obs if o.raw_evidence_ref == nxos.CMD_INTERFACE]
    assert interface
    assert all(o.normalized_value is None and "MTU_SEMANTICS_UNKNOWN" in o.gaps for o in interface)


def test_no_interface_mtu_is_invented_from_system_preset():
    obs = observations(normalize_port(field="unrelated_field"))
    assert obs == []


def test_payload_profile_can_be_restated_without_adding_ethernet_headers():
    obs = observations(normalize_port())[0]
    assert restate_ip_bytes(obs, ip_bytes=9000) == ("9000", 9000)


def test_change_simulation_restates_the_payload_limit_for_both_families_only():
    obs = observations(normalize_port())[0]
    row = obs.model_dump()
    change = ChangeSet(intents=[])
    assert change._restate_mtu_row(row, {4: 9000}, source_iface="synthetic") is None
    restated = change._restate_mtu_row(row, {4: 9000, 6: 9000}, source_iface="synthetic")
    assert restated["normalized_value"] == 9000
    assert restated["raw_value_json"] == "9000"
    assert restated["gaps"] == []


def test_configured_and_text_interface_mtu_have_the_same_payload_coordinate():
    raw = capture()
    raw[nxos.CMD_INTERFACE_CONFIG] = "interface Ethernet1/1\n mtu 1500\n"
    obs = observations(nx._collector().normalize(raw))
    media = [o for o in obs if o.enforcement_key == "media"]
    assert {o.source_field for o in media} == {
        "show interface:MTU",
        f"{nxos.CMD_INTERFACE_CONFIG}:media mtu",
    }
    assert {o.assertion_kind for o in media} == {"configured", "operational"}
    assert all(
        o.metric == "l2_payload_mtu_bytes" and o.normalized_value == 1500 and not o.gaps for o in media
    )
    resolved = resolve_constraints(media, MtuContext(af=4, enforcement="l2"))
    assert resolved.gaps == []
    assert resolved.findings == []
    assert len(resolved.constraints) == 1
