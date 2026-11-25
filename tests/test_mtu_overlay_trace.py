"""`interface.set_mtu` traced end to end over the synthetic estate fixture."""

from __future__ import annotations

from tests.test_mtu_end_to_end import ADDR, DEV_XE, IF_XE_VLAN10, IF_XR_GI1, estate, estate_observations

from hst import path
from hst.app import fw_overlay_read
from hst.simul.fw_overlay import Catalog, ChangeSet, parse_intents

__all__ = ["estate"]  # re-exported fixture

_PACKET = {"mode": "packet", "ip_packet_bytes": 9000, "ipv4_df": True}


def _entry_stage(result):
    return next(
        s
        for s in result["stages"]
        if s["ingress_subject_uid"] == IF_XE_VLAN10 and s["context"]["direction"] == "rx"
    )


def _core_egress_stage(result):
    return next(
        s
        for s in result["stages"]
        if s["egress_subject_uid"] == IF_XR_GI1 and s["context"]["direction"] == "tx"
    )


def _traced_after(estate, monkeypatch, *, new_mtu: int, packet: dict):
    """The overlay session for one `interface.set_mtu` on `IF_XE_VLAN10`."""
    catalog = Catalog(
        interfaces={
            IF_XE_VLAN10: {
                "uid": IF_XE_VLAN10,
                "device_uid": DEV_XE,
                "vendor": "cisco",
                "platform": "iosxe",
                "parent_interface_uid": None,
                "parent_source_command": None,
                "port_uid": None,
                "observations": [o for o in estate_observations() if o.subject_uid == IF_XE_VLAN10],
                "parent_uid": None,
                "configured_tag_depth": None,
            }
        }
    )
    intents = [{"kind": "interface.set_mtu", "params": {"interface": IF_XE_VLAN10, "mtu": new_mtu}}]
    parsed = parse_intents(intents, catalog)  # IOS-XE, no parent: accepted
    changes = ChangeSet(intents=parsed, catalog=catalog)
    assert changes.mtu_subjects() == {IF_XE_VLAN10}

    overlaid_session = fw_overlay_read.OverlaySession(estate.session(), changes)

    def overlaid_read(session, query, **params):
        rows = estate.read(session, query, **params)
        overlay = getattr(session, "overlay", None)
        return rows if overlay is None else overlay(query, params, rows)

    monkeypatch.setattr(path, "_read", overlaid_read)

    return path.trace(
        overlaid_session,
        ADDR["client"],
        ADDR["server"],
        port=443,
        proto="tcp",
        gateways=estate.gateways,
        mtu=packet,
    )["mtu"]


def test_raising_the_entry_interface_moves_the_9000_byte_failure_from_entry_to_exit(estate, monkeypatch):
    before = estate.trace(mtu=_PACKET)["mtu"]
    assert before["outcome"] == "fail"
    entry_before = _entry_stage(before)
    assert entry_before["stage_id"] in before["bottleneck_stage_ids"]
    assert [c["value_bytes"] for c in entry_before["constraints"]] == [1500]
    exit_before = _core_egress_stage(before)
    assert exit_before["stage_id"] in before["bottleneck_stage_ids"]
    assert [c["value_bytes"] for c in exit_before["constraints"]] == [1500]

    after = _traced_after(estate, monkeypatch, new_mtu=9000, packet=_PACKET)

    # The entry resolves to a proven 9000-byte ceiling.
    entry_after = _entry_stage(after)
    assert [c["value_bytes"] for c in entry_after["constraints"]] == [9000]
    assert entry_after["stage_id"] not in after["bottleneck_stage_ids"]
    assert entry_after["coverage"]["gaps"] == []

    assert after["outcome"] == "fail"
    exit_after = _core_egress_stage(after)
    assert exit_after["stage_id"] in after["bottleneck_stage_ids"]
    assert [c["value_bytes"] for c in exit_after["constraints"]] == [1500]


def test_lowering_the_entry_interface_moves_the_bottleneck_to_the_new_ceiling(estate, monkeypatch):
    """A 1400-byte DF packet clears the 1500-byte entry ceiling before the change."""
    packet = {"mode": "packet", "ip_packet_bytes": 1400, "ipv4_df": True}
    before = estate.trace(mtu=packet)["mtu"]
    entry_before = _entry_stage(before)
    assert [c["value_bytes"] for c in entry_before["constraints"]] == [1500]

    after = _traced_after(estate, monkeypatch, new_mtu=600, packet=packet)

    entry_after = _entry_stage(after)
    assert [c["value_bytes"] for c in entry_after["constraints"]] == [600]
    assert entry_after["coverage"]["gaps"] == []
    assert entry_after["stage_id"] in after["bottleneck_stage_ids"]
    assert after["outcome"] == "fail"
    assert after["known_ceiling_bytes"] == 600
