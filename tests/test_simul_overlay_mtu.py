"""The `interface.set_mtu` change intent: platform validation
(`hst.simul.fw_overlay.parse_intents`) and the MTU evidence overlay
(`ChangeSet.rewrite` over `hst.core.mtu_read.MTU_QUERY` rows)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from hst.core.mtu import MtuObservation, canonical_json
from hst.core.mtu_profiles import observation_from_raw
from hst.core.mtu_read import MtuContext, resolve_constraints
from hst.simul.fw_overlay import Catalog, ChangeSet, ProposalError, parse_intents

# --- fixtures --------------------------------------------------------------


def _row(obs: MtuObservation, cts: int = 1) -> dict[str, Any]:
    """One `MTU_QUERY` row for an already-built observation."""
    return {
        "subject_uid": obs.subject_uid,
        "observation_uid": obs.uid,
        "legacy_mtu": None,
        "observation": dict(obs.graph_props(), uid=obs.uid, collection_ts=cts),
    }


def _vyos_if_obs(subject: str, af: int, value: int, assertion: str, **selector: Any) -> MtuObservation:
    return observation_from_raw(
        subject_uid=subject,
        source="vyos:test",
        source_target="dev:vyos1",
        source_field=f"config.interfaces.ethernet.{subject}.mtu"
        if assertion == "configured"
        else f"links.ifname={subject}.mtu",
        raw_value=value,
        profile_id="ip_packet",
        metric=f"ipv{af}_mtu_bytes",
        direction="both",
        bound_kind="ceiling",
        enforcement="l3",
        enforcement_key="netdevice",
        assertion_kind=assertion,
        resolution_state="explicit",
        collector_version="1",
        raw_evidence_ref="test",
        selector_json=canonical_json({"version": 1, **selector}),
    )


def _vyos_port_frame(subject: str, ip_value: int) -> MtuObservation:
    return observation_from_raw(
        subject_uid=subject,
        source="vyos:test",
        source_target="dev:vyos1",
        source_field="links.ifname=eth0.mtu",
        raw_value=ip_value + 14,
        profile_id="ethernet_frame_excluding_fcs",
        metric="l2_max_frame_bytes",
        direction="both",
        bound_kind="ceiling",
        enforcement="l2",
        enforcement_key="netdevice",
        assertion_kind="operational",
        resolution_state="explicit",
        collector_version="1",
        raw_evidence_ref="ip -j link show",
        tag_accounting="extra_allowance",
        tag_allowance_bytes=4,
        selector_json=canonical_json({"version": 1, "derivation": "mtu_plus_ethernet_header"}),
    )


def _cisco_if_obs(
    subject: str, af: int, value: int, assertion: str, *, enforcement_key: str = "protocol", **selector: Any
) -> MtuObservation:
    return observation_from_raw(
        subject_uid=subject,
        source="iosxr",
        source_target="estate:iosxr",
        source_field=f"show {'ipv6' if af == 6 else 'ipv4'} interface:available_to_ip",
        raw_value=value,
        profile_id="ip_packet",
        metric=f"ipv{af}_mtu_bytes",
        direction="both",
        bound_kind="ceiling",
        enforcement="l3",
        enforcement_key=enforcement_key,
        assertion_kind=assertion,
        resolution_state="explicit",
        collector_version="1",
        raw_evidence_ref=f"show {'ipv6' if af == 6 else 'ipv4'} interface",
        selector_json=canonical_json({"version": 1, **selector}),
    )


def _cisco_media_obs(subject: str, ip_value: int, **selector: Any) -> MtuObservation:
    return observation_from_raw(
        subject_uid=subject,
        source="iosxr",
        source_target="estate:iosxr",
        source_field="show interfaces:MTU",
        raw_value=ip_value + 14,
        profile_id="ethernet_frame_excluding_fcs",
        metric="l2_max_frame_bytes",
        direction="both",
        bound_kind="ceiling",
        enforcement="l2",
        enforcement_key="media",
        assertion_kind="operational",
        resolution_state="explicit",
        collector_version="1",
        raw_evidence_ref="show interfaces",
        tag_depth=0,
        tag_accounting="included",
        tag_allowance_bytes=0,
        selector_json=canonical_json({"version": 1, **selector}),
    )


def _unifi_jumbo_obs(subject: str, value: int) -> MtuObservation:
    return observation_from_raw(
        subject_uid=subject,
        source="unifi",
        source_target="unifi:site",
        source_field="device.jumboframe_enabled",
        raw_value=value,
        profile_id="ethernet_payload",
        metric="l2_max_frame_bytes",
        direction="both",
        bound_kind="ceiling",
        enforcement="l2",
        enforcement_key="port",
        assertion_kind="configured",
        resolution_state="explicit",
        collector_version="1",
        raw_evidence_ref="device.jumboframe_enabled",
        tag_depth=0,
        tag_accounting="included",
        tag_allowance_bytes=0,
        selector_json=canonical_json({"version": 1}),
    )


def _nxos_queue_obs(subject: str, value: int, *, configured: bool = False) -> MtuObservation:
    return observation_from_raw(
        subject_uid=subject,
        source="nxos",
        source_target="estate:nxos",
        source_field="show queuing interface:HW MTU",
        raw_value=value,
        profile_id="unknown",
        metric="l2_max_frame_bytes",
        direction="tx",
        bound_kind="unknown",
        enforcement="l2",
        enforcement_key="queue",
        assertion_kind="configured" if configured else "operational",
        resolution_state="unknown",
        collector_version="1",
        raw_evidence_ref="show queuing interface",
        selector_json=canonical_json({"version": 1}),
    )


def _hardware_max_obs(subject: str, value: int) -> MtuObservation:
    return observation_from_raw(
        subject_uid=subject,
        source="nxos",
        source_target="estate:nxos",
        source_field="hardware limit",
        raw_value=value,
        profile_id="ip_packet",
        metric="ipv4_mtu_bytes",
        direction="both",
        bound_kind="ceiling",
        enforcement="l3",
        enforcement_key="netdevice",
        assertion_kind="hardware_max",
        resolution_state="explicit",
        collector_version="1",
        raw_evidence_ref="hardware limit",
        selector_json=canonical_json({"version": 1}),
    )


def _system_policy_obs(subject: str, value: int) -> MtuObservation:
    return observation_from_raw(
        subject_uid=subject,
        source="nxos",
        source_target="estate:nxos",
        source_field="show running-config all | i jumbomtu:system",
        raw_value=value,
        profile_id="ip_packet",
        metric="ipv4_mtu_bytes",
        direction="both",
        bound_kind="ceiling",
        enforcement="l3",
        enforcement_key="system",
        assertion_kind="configured",
        resolution_state="explicit",
        collector_version="1",
        raw_evidence_ref="show running-config all | i jumbomtu",
        scope="system_policy",
        policy_ref="system",
        selector_json=canonical_json({"version": 1}),
    )


def _operator_import_obs(subject: str, value: int) -> MtuObservation:
    return observation_from_raw(
        subject_uid=subject,
        source="manual:carrier-survey",
        source_target="carrier-survey.csv",
        source_field="row 4",
        raw_value=value,
        profile_id="ip_packet",
        metric="ipv4_mtu_bytes",
        direction="both",
        bound_kind="ceiling",
        enforcement="l3",
        enforcement_key="netdevice",
        assertion_kind="configured",
        resolution_state="explicit",
        collector_version="1",
        raw_evidence_ref="manual import",
        selector_json=canonical_json({"version": 1}),
    )


def vyos_catalog() -> Catalog:
    """eth0 (physical, port:eth0) and eth0.10 (a vif of eth0), both at 1500."""
    eth0_obs = [
        _vyos_if_obs("if:eth0", 4, 1500, "configured"),
        _vyos_if_obs("if:eth0", 4, 1500, "operational"),
        _vyos_if_obs("if:eth0", 6, 1500, "configured"),
        _vyos_if_obs("if:eth0", 6, 1500, "operational"),
    ]
    vif_obs = [
        _vyos_if_obs(
            "if:eth0.10", 4, 1500, "configured", parent_subject_uid="if:eth0", configured_tag_depth=1
        ),
        _vyos_if_obs(
            "if:eth0.10", 6, 1500, "configured", parent_subject_uid="if:eth0", configured_tag_depth=1
        ),
    ]
    return Catalog(
        interfaces={
            "if:eth0": {
                "uid": "if:eth0",
                "device_uid": "dev:vyos1",
                "vendor": "vyos",
                "platform": "vyos",
                "os_version": "1.4",
                "parent_interface_uid": None,
                "parent_source_command": None,
                "port_uid": "port:eth0",
                "observations": eth0_obs,
                "parent_uid": None,
                "configured_tag_depth": None,
            },
            "if:eth0.10": {
                "uid": "if:eth0.10",
                "device_uid": "dev:vyos1",
                "vendor": "vyos",
                "platform": "vyos",
                "os_version": "1.4",
                "parent_interface_uid": None,
                "parent_source_command": None,
                "port_uid": None,
                "observations": vif_obs,
                "parent_uid": "if:eth0",
                "configured_tag_depth": 1,
            },
        }
    )


def iosxr_catalog() -> Catalog:
    """A physical GigabitEthernet0/0/0/0 (port:xr-gi0) and its .20 subinterface, both at 1500."""
    parent_obs = [
        _cisco_if_obs("if:xr-gi0", 4, 1500, "operational"),
        _cisco_if_obs("if:xr-gi0", 4, 1500, "configured"),
    ]
    sub_obs = [
        _cisco_if_obs("if:xr-gi0.20", 4, 1500, "operational", derived_from_subject_uid="if:xr-gi0"),
    ]
    return Catalog(
        interfaces={
            "if:xr-gi0": {
                "uid": "if:xr-gi0",
                "device_uid": "dev:xr1",
                "vendor": "cisco",
                "platform": "iosxr",
                "os_version": "7.3.2",
                "parent_interface_uid": None,
                "parent_source_command": None,
                "port_uid": "port:xr-gi0",
                "observations": parent_obs,
                "parent_uid": None,
                "configured_tag_depth": None,
            },
            "if:xr-gi0.20": {
                "uid": "if:xr-gi0.20",
                "device_uid": "dev:xr1",
                "vendor": "cisco",
                "platform": "iosxr",
                "os_version": "7.3.2",
                "parent_interface_uid": "if:xr-gi0",
                "parent_source_command": "show running-config interface",
                "port_uid": None,
                "observations": sub_obs,
                "parent_uid": "if:xr-gi0",
                "configured_tag_depth": None,
            },
        }
    )


def _intent(interface: str, mtu: int, af: str | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {"interface": interface, "mtu": mtu}
    if af is not None:
        params["af"] = af
    return {"kind": "interface.set_mtu", "params": params}


# --- parse_intents validation -----------------------------------------------


def test_missing_interface_is_refused():
    with pytest.raises(ProposalError, match="needs an interface"):
        parse_intents([{"kind": "interface.set_mtu", "params": {"mtu": 1500}}], vyos_catalog())


def test_missing_mtu_is_refused():
    with pytest.raises(ProposalError, match="needs an mtu"):
        parse_intents([{"kind": "interface.set_mtu", "params": {"interface": "if:eth0"}}], vyos_catalog())


def test_out_of_range_mtu_is_refused():
    with pytest.raises(ProposalError, match="between 68 and 65535"):
        parse_intents([_intent("if:eth0", 67)], vyos_catalog())
    with pytest.raises(ProposalError, match="between 68 and 65535"):
        parse_intents([_intent("if:eth0", 65536)], vyos_catalog())


def test_vyos_vif_above_its_parent_is_refused_naming_the_fix():
    with pytest.raises(ProposalError) as exc:
        parse_intents([_intent("if:eth0.10", 9000)], vyos_catalog())
    message = str(exc.value)
    assert "if:eth0.10" in message
    assert "if:eth0" in message
    assert "raise the parent's MTU to at least 9000 in the same change" in message


def test_vyos_vif_accepted_when_the_parent_is_raised_in_the_same_change():
    parsed = parse_intents([_intent("if:eth0", 9000), _intent("if:eth0.10", 9000)], vyos_catalog())
    assert [i.kind for i in parsed] == ["interface.set_mtu", "interface.set_mtu"]
    # the vif ahead of its parent is accepted
    parsed = parse_intents([_intent("if:eth0.10", 9000), _intent("if:eth0", 9000)], vyos_catalog())
    assert len(parsed) == 2


def test_vyos_physical_ethernet_accepts_any_in_range_value():
    parse_intents([_intent("if:eth0", 9000)], vyos_catalog())


def _device_sources_catalog(sources: list[str], source_kinds: dict[str, str] | None) -> Catalog:
    """One vyos-platformed interface whose Device holds `sources` as its `_sources`."""
    return Catalog(
        interfaces={
            "if:eth0": {
                "uid": "if:eth0",
                "device_uid": "dev:vyos1",
                "vendor": "vyos",
                "platform": "vyos",
                "device_sources": sources,
                "parent_interface_uid": None,
                "port_uid": "port:eth0",
                "observations": [],
                "parent_uid": None,
                "configured_tag_depth": None,
            },
        },
        source_kinds=source_kinds,
    )


def test_device_known_only_from_nautobot_is_refused_no_collected_evidence():
    """A Device whose `_sources` names only the configured Nautobot row (an
    inventory-only source) shares its uid with a Device a collector writes in
    another cycle."""
    catalog = _device_sources_catalog(["nautobot1"], {"nautobot1": "nautobot", "vyos-lts-1": "vyos"})
    with pytest.raises(
        ProposalError, match="no collected MTU evidence for this device; the twin holds it from Nautobot only"
    ):
        parse_intents([_intent("if:eth0", 9000)], catalog)


def test_device_also_seen_by_its_collector_is_accepted_despite_the_shared_uid():
    catalog = _device_sources_catalog(
        ["nautobot1", "vyos-lts-1"], {"nautobot1": "nautobot", "vyos-lts-1": "vyos"}
    )
    parse_intents([_intent("if:eth0", 9000)], catalog)


def test_device_sources_with_no_kind_mapping_is_not_checked():
    """A caller with no sources configuration leaves `Catalog.source_kinds` at its default of `None`."""
    catalog = _device_sources_catalog(["nautobot1"], None)
    parse_intents([_intent("if:eth0", 9000)], catalog)


def test_iosxe_subinterface_is_refused_naming_the_parent():
    catalog = Catalog(
        interfaces={
            "if:xe-vlan10": {
                "uid": "if:xe-vlan10",
                "device_uid": "dev:xe1",
                "vendor": "cisco",
                "platform": "iosxe",
                "port_uid": None,
                "observations": [],
                "parent_interface_uid": None,
            },
            "if:xe-gi1-0-1.10": {
                "uid": "if:xe-gi1-0-1.10",
                "device_uid": "dev:xe1",
                "vendor": "cisco",
                "platform": "iosxe",
                "port_uid": None,
                "observations": [],
                "parent_interface_uid": "if:xe-gi1-0-1",
            },
        }
    )
    with pytest.raises(ProposalError) as exc:
        parse_intents([_intent("if:xe-gi1-0-1.10", 9000)], catalog)
    message = str(exc.value)
    assert "no MTU of its own for a subinterface" in message
    assert "if:xe-gi1-0-1" in message
    # a parent/physical IOS-XE interface accepts any in-range value
    parse_intents([_intent("if:xe-vlan10", 9000)], catalog)


def test_iosxr_subinterface_above_its_parent_is_refused():
    with pytest.raises(ProposalError) as exc:
        parse_intents([_intent("if:xr-gi0.20", 9000)], iosxr_catalog())
    message = str(exc.value)
    assert "if:xr-gi0.20" in message
    assert "if:xr-gi0" in message


def test_unifi_is_refused_no_mtu_intent_for_this_platform():
    catalog = Catalog(
        interfaces={
            "if:unifi-sw1-p1": {
                "uid": "if:unifi-sw1-p1",
                "device_uid": "dev:unifi-sw1",
                "vendor": "ubiquiti",
                "platform": "unifi-usw",
                "port_uid": None,
                "observations": [],
            }
        }
    )
    with pytest.raises(ProposalError, match="no MTU intent for this platform"):
        parse_intents([_intent("if:unifi-sw1-p1", 9000)], catalog)


def test_apic_controller_is_refused_no_mtu_intent_for_this_platform():
    """`apic.py` writes `platform="apic"` for a controller."""
    catalog = Catalog(
        interfaces={
            "if:apic1-mgmt": {
                "uid": "if:apic1-mgmt",
                "device_uid": "dev:apic1",
                "vendor": None,
                "platform": "apic",
                "port_uid": None,
                "observations": [],
            }
        }
    )
    with pytest.raises(ProposalError, match="no MTU intent for this platform"):
        parse_intents([_intent("if:apic1-mgmt", 9000)], catalog)


def test_netscaler_is_refused_no_mtu_intent_for_this_platform():
    """The interface is recognised by `mtu_source`, the Interface marker of `_netscaler_mtu`."""
    catalog = Catalog(
        interfaces={
            "if:ns1-1-1": {
                "uid": "if:ns1-1-1",
                "device_uid": "dev:ns1",
                "vendor": None,
                "platform": None,
                "mtu_source": "NITRO Interface",
                "port_uid": None,
                "observations": [],
            }
        }
    )
    with pytest.raises(ProposalError, match="no MTU intent for this platform"):
        parse_intents([_intent("if:ns1-1-1", 9000)], catalog)


def test_unknown_platform_is_refused():
    catalog = Catalog(
        interfaces={
            "if:mystery1": {
                "uid": "if:mystery1",
                "device_uid": "dev:mystery1",
                "vendor": "acme",
                "platform": "widget-os",
                "port_uid": None,
                "observations": [],
            }
        }
    )
    with pytest.raises(ProposalError, match="unknown platform"):
        parse_intents([_intent("if:mystery1", 9000)], catalog)


def test_an_interface_the_catalog_never_loaded_is_refused_as_not_in_this_snapshot():
    with pytest.raises(ProposalError, match="not in this snapshot"):
        parse_intents([_intent("if:ghost", 9000)], Catalog())


# --- the MTU overlay: row rewriting ----------------------------------------


def test_vyos_raising_the_vif_and_its_parent_restates_both_interfaces_rows_and_the_port_frame_row():
    catalog = vyos_catalog()
    changes = ChangeSet(
        intents=parse_intents([_intent("if:eth0", 9000), _intent("if:eth0.10", 9000)], catalog),
        catalog=catalog,
    )
    port_frame = _vyos_port_frame("port:eth0", 1500)
    rows = (
        [_row(o) for o in catalog.interfaces["if:eth0"]["observations"]]
        + [_row(o) for o in catalog.interfaces["if:eth0.10"]["observations"]]
        + [_row(port_frame)]
        + [_row(_unifi_jumbo_obs("port:unrelated", 9216))]
        + [_row(_nxos_queue_obs("port:eth0", 1500))]
        + [_row(_system_policy_obs("dev:vyos1", 9216))]
        + [_row(_hardware_max_obs("if:eth0", 9216))]
        + [_row(_operator_import_obs("if:eth0", 1500))]
    )
    out = changes._rewrite_mtu(rows)
    assert len(out) == len(rows)

    by_uid = {r["observation_uid"]: r["observation"] for r in out}

    for obs in catalog.interfaces["if:eth0"]["observations"]:
        restated = by_uid[obs.uid]
        assert restated["normalized_value"] == 9000
        assert json.loads(restated["raw_value_json"]) == 9000
        assert restated["assertion_kind"] == "intent"
        assert restated["resolution_state"] == "explicit"
        assert restated["source"] == "intent:interface.set_mtu"
        assert restated["direction"] == "both"
        assert restated["profile_id"] == "ip_packet"
        selector = json.loads(restated["selector_json"])
        assert selector["intent"] == {"kind": "interface.set_mtu", "interface": "if:eth0", "mtu": 9000}

    for obs in catalog.interfaces["if:eth0.10"]["observations"]:
        restated = by_uid[obs.uid]
        assert restated["normalized_value"] == 9000
        assert restated["direction"] == "both"

    frame_row = by_uid[port_frame.uid]
    assert json.loads(frame_row["raw_value_json"]) == 9014
    assert frame_row["normalized_value"] == 9014 + 4  # the 4-byte tag allowance, unchanged
    assert frame_row["assertion_kind"] == "intent"

    # legacy_mtu (s.mtu) of the changed subjects holds the changed value
    for r in out:
        if r["subject_uid"] == "if:eth0" or r["subject_uid"] == "if:eth0.10":
            assert r["legacy_mtu"] == 9000

    # preserved rows: byte-identical to the input
    input_by_uid = {r["observation_uid"]: r["observation"] for r in rows}
    unifi_uid = _unifi_jumbo_obs("port:unrelated", 9216).uid
    queue_uid = _nxos_queue_obs("port:eth0", 1500).uid
    policy_uid = _system_policy_obs("dev:vyos1", 9216).uid
    hwmax_uid = _hardware_max_obs("if:eth0", 9216).uid
    import_uid = _operator_import_obs("if:eth0", 1500).uid
    for uid in (unifi_uid, queue_uid, policy_uid, hwmax_uid, import_uid):
        assert by_uid[uid] == input_by_uid[uid], uid


def test_af_4_changes_only_the_ipv4_rows():
    catalog = vyos_catalog()
    changes = ChangeSet(
        intents=parse_intents([_intent("if:eth0", 9000, af="4")], catalog),
        catalog=catalog,
    )
    rows = [_row(o) for o in catalog.interfaces["if:eth0"]["observations"]]
    out = changes._rewrite_mtu(rows)
    by_uid = {r["observation_uid"]: r["observation"] for r in out}
    for obs in catalog.interfaces["if:eth0"]["observations"]:
        restated = by_uid[obs.uid]
        if obs.af == 4:
            assert restated["normalized_value"] == 9000
        else:
            assert restated["normalized_value"] == 1500  # untouched


def test_af_4_leaves_the_shared_frame_ceiling_untouched():
    catalog = vyos_catalog()
    changes = ChangeSet(
        intents=parse_intents([_intent("if:eth0", 9000, af="4")], catalog),
        catalog=catalog,
    )
    port_frame = _vyos_port_frame("port:eth0", 1500)
    rows = [_row(o) for o in catalog.interfaces["if:eth0"]["observations"]] + [_row(port_frame)]
    out = changes._rewrite_mtu(rows)
    by_uid = {r["observation_uid"]: r["observation"] for r in out}
    assert by_uid[port_frame.uid] == dict(port_frame.graph_props(), uid=port_frame.uid, collection_ts=1)


def test_iosxr_raising_the_parent_restates_media_and_protocol_and_the_subinterface_row():
    catalog = iosxr_catalog()
    changes = ChangeSet(
        intents=parse_intents([_intent("if:xr-gi0", 9000)], catalog),
        catalog=catalog,
    )
    media = _cisco_media_obs("port:xr-gi0", 1500)
    rows = (
        [_row(o) for o in catalog.interfaces["if:xr-gi0"]["observations"]]
        + [_row(media)]
        + [_row(o) for o in catalog.interfaces["if:xr-gi0.20"]["observations"]]
    )
    out = changes._rewrite_mtu(rows)
    by_uid = {r["observation_uid"]: r["observation"] for r in out}

    for obs in catalog.interfaces["if:xr-gi0"]["observations"]:
        assert by_uid[obs.uid]["normalized_value"] == 9000

    media_row = by_uid[media.uid]
    assert json.loads(media_row["raw_value_json"]) == 9014
    assert media_row["normalized_value"] == 9014  # tag_accounting "included", allowance 0

    for obs in catalog.interfaces["if:xr-gi0.20"]["observations"]:
        restated = by_uid[obs.uid]
        assert restated["normalized_value"] == 9000
        selector = json.loads(restated["selector_json"])
        assert selector["intent"]["interface"] == "if:xr-gi0"


def test_resolve_constraints_over_the_rewritten_vif_rows_yields_a_9000_ceiling_in_both_directions():
    catalog = vyos_catalog()
    changes = ChangeSet(
        intents=parse_intents([_intent("if:eth0", 9000), _intent("if:eth0.10", 9000)], catalog),
        catalog=catalog,
    )
    rows = [_row(o) for o in catalog.interfaces["if:eth0.10"]["observations"]]
    out = changes._rewrite_mtu(rows)
    fields = MtuObservation.model_fields
    restated = [
        MtuObservation.model_validate({k: v for k, v in r["observation"].items() if k in fields}) for r in out
    ]

    for direction in ("tx", "rx"):
        resolution = resolve_constraints(restated, MtuContext(af=4, direction=direction))
        assert [c.value_bytes for c in resolution.intent] == [9000]
        assert resolution.intent[0].direction == "both"


def test_mtu_subjects_names_the_changed_interfaces_and_the_physical_port():
    catalog = vyos_catalog()
    changes = ChangeSet(
        intents=parse_intents([_intent("if:eth0", 9000), _intent("if:eth0.10", 9000)], catalog),
        catalog=catalog,
    )
    assert changes.mtu_subjects() == {"if:eth0", "if:eth0.10", "port:eth0"}
