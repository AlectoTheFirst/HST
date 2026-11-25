"""UniFi per-port L2 frame ceiling from `device.jumboframe_enabled`."""

import copy

from tests.test_mtu_budget import request as size_request

from hst.collectors.unifi import normalize_unifi
from hst.core.mtu import MtuContext, MtuCoverage, MtuObservation, MtuStage
from hst.core.mtu_read import resolve_constraints
from hst.path.mtu import constraint_budget, evaluate_stage

RAW = {
    "devices": [
        {
            "type": "usw",
            "mac": "aa:bb:cc:00:00:01",
            "serial": "SW1234567",
            "name": "Rack-Switch",
            "model": "USW-24-POE",
            "jumboframe_enabled": False,
            "port_table": [
                {"port_idx": 1, "name": "Port 1", "up": True, "speed": 1000, "jumbo": True},
                {"port_idx": 2, "name": "Port 2", "up": True, "speed": 1000, "jumbo": False},
            ],
        },
        {
            "type": "usw",
            "mac": "aa:bb:cc:00:00:02",
            "serial": "SW7654321",
            "name": "Closet-Switch",
            "model": "USW-24-POE",
            "jumboframe_enabled": True,
            "port_table": [
                {"port_idx": 1, "name": "Port 1", "up": True, "speed": 1000},
            ],
        },
    ],
    "networks": [],
    "wlans": [],
    "clients": [],
}


def _batch(raw=None):
    return normalize_unifi(
        raw or RAW, site_code="home", l3dom="home", unifi_site="default", include_clients=False
    )


def _port_uid(batch, mac_suffix, name):
    """The Port uid for `name` on the device with the given serial."""
    dev_serial = {"01": "SW1234567", "02": "SW7654321"}[mac_suffix]
    target_duid = next(
        n.uid for n in batch.nodes if n.label == "Device" and n.props.get("serial") == dev_serial
    )
    port_uids_on_device = {
        r.start_uid
        for r in batch.rels
        if r.rel_type == "ON" and r.start_label == "Port" and r.end_uid == target_duid
    }
    for n in batch.nodes:
        if n.label == "Port" and n.uid in port_uids_on_device and n.props.get("name") == name:
            return n.uid
    raise AssertionError(f"no port {name!r} on device serial {dev_serial}")


def frame_observation(batch, port_uid):
    return next(
        MtuObservation(uid=n.uid, **n.props)
        for n in batch.nodes
        if n.label == "MtuObservation"
        and n.props.get("subject_uid") == port_uid
        and n.props.get("metric") == "l2_max_frame_bytes"
    )


def _l2_stage(port_uid, constraint, *, direction="tx", tag_depth):
    return MtuStage(
        stage_id="port",
        egress_subject_uid=port_uid if direction == "tx" else None,
        ingress_subject_uid=port_uid if direction == "rx" else None,
        enforcement="l2",
        context=MtuContext(af=4, direction=direction, tag_depth=tag_depth),
        constraints=[constraint],
        selection="selected",
        coverage=MtuCoverage(
            complete=True, candidate_set_complete=True, constraints_complete=True, exact_path_known=True
        ),
    )


def _budget(frame, tag_depth, *, direction="tx"):
    constraint = resolve_constraints(
        [frame], MtuContext(af=4, enforcement="l2", direction=direction, tag_depth=tag_depth)
    ).constraints[0]
    stage = _l2_stage(frame.subject_uid, constraint, direction=direction, tag_depth=tag_depth)
    return constraint_budget(constraint, stage), stage


def test_a_jumbo_disabled_port_frame_ceiling_is_the_documented_1518():
    batch = _batch()
    port_uid = _port_uid(batch, "01", "Port 2")
    frame = frame_observation(batch, port_uid)
    assert frame.normalized_value == 1518
    assert frame.tag_accounting == "extra_allowance"
    assert frame.tag_allowance_bytes == 4
    assert frame.source_field == "device.jumboframe_enabled"


def test_a_jumbo_disabled_port_resolves_1504_untagged_and_1500_with_one_tag():
    batch = _batch()
    port_uid = _port_uid(batch, "01", "Port 2")
    frame = frame_observation(batch, port_uid)
    (budget_untagged, gaps_untagged), _ = _budget(frame, 0)
    assert (budget_untagged, gaps_untagged) == (1504, [])
    (budget_tagged, gaps_tagged), _ = _budget(frame, 1)
    assert (budget_tagged, gaps_tagged) == (1500, [])


def test_a_jumbo_disabled_port_resolves_1500_with_two_tags():
    """Linux allows the VLAN overhead above the MTU for each tag."""
    batch = _batch()
    port_uid = _port_uid(batch, "01", "Port 2")
    frame = frame_observation(batch, port_uid)
    (budget, gaps), _ = _budget(frame, 2)
    assert (budget, gaps) == (1500, [])


def test_a_jumbo_enabled_port_resolves_9194_with_one_tag():
    batch = _batch()
    port_uid = _port_uid(batch, "02", "Port 1")
    frame = frame_observation(batch, port_uid)
    assert frame.normalized_value == 9212  # 9216 including FCS, minus the 4-byte FCS
    assert frame.tag_accounting != "extra_allowance"
    (budget, gaps), _ = _budget(frame, 1)
    assert (budget, gaps) == (9194, [])


def test_a_1600_byte_packet_fails_at_the_jumbo_disabled_port_in_both_df_states_and_names_it():
    batch = _batch()
    port_uid = _port_uid(batch, "01", "Port 2")
    frame = frame_observation(batch, port_uid)
    (_, _), stage = _budget(frame, 0, direction="rx")
    for df in (True, False):
        result = evaluate_stage(stage, size_request(1600, mode="packet", ipv4_df=df))
        assert result.outcome == "fail"
        assert port_uid in result.findings[0].subject_uids


def test_port_table_jumbo_does_not_override_the_device_flag():
    """Ubiquiti documents jumbo frames as a device-wide setting."""
    batch = _batch()
    port1_uid = _port_uid(batch, "01", "Port 1")  # port_table.jumbo True, device flag False
    port2_uid = _port_uid(batch, "01", "Port 2")  # port_table.jumbo False, device flag False
    assert (
        frame_observation(batch, port1_uid).normalized_value
        == frame_observation(batch, port2_uid).normalized_value
        == 1518
    )


def test_section_outcome_does_not_report_a_missing_byte_basis():
    batch = _batch()
    assert "no validated numeric byte basis" not in batch.sections["mtu"].detail
    assert batch.sections["mtu"].status == "partial"


def test_a_device_without_the_jumbo_flag_stays_unresolved():
    raw = copy.deepcopy(RAW)
    del raw["devices"][0]["jumboframe_enabled"]
    batch = _batch(raw)
    port_uid = _port_uid(batch, "01", "Port 2")
    frames = [
        n
        for n in batch.nodes
        if n.label == "MtuObservation"
        and n.props.get("subject_uid") == port_uid
        and n.props.get("metric") == "l2_max_frame_bytes"
    ]
    assert frames == []
