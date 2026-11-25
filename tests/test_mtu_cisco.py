"""Synthetic Cisco captures through the parser into graph evidence."""

import asyncio
import copy
import json
from pathlib import Path

import pytest

import test_iosxe as xe
import test_iosxr as xr
import test_nxos as nx
from hst.collectors import iosxe, iosxr, nxos, ssh
from hst.collectors.base import RAW_OUTCOMES_KEY, raw_sha
from hst.collectors.cisco_common import MTU_COMMANDS, capture_mtu, normalize_cisco, parse_mtu
from hst.core import uid
from hst.core.mtu import MTU_NORMALIZATION_VERSION, MtuContext, MtuCoverage, MtuObservation, MtuStage
from hst.core.mtu_read import resolve_constraints
from hst.path.mtu import constraint_budget

# the intermediate below has no hostname, so the in-memory registry names the
# device `unknown` with the last 4 characters of its serial
DEV = "dev:unknown-etic"

FIXTURE = json.loads((Path(__file__).parents[1] / "fixtures/mtu/cisco/observations-v1.json").read_text())


def observations(batch):
    return [n for n in batch.nodes if n.label == "MtuObservation"]


def augmented(family, baseline):
    raw = copy.deepcopy(baseline)
    raw.update(FIXTURE[family])
    raw[RAW_OUTCOMES_KEY] = {command: {"status": "ok"} for command in raw}
    return raw


@pytest.mark.parametrize(("fixture", "family"), [(xe, "iosxe"), (xr, "iosxr"), (nx, "nxos")])
def test_protocol_capture_is_normalized_and_mtu_capture_is_opt_in(fixture, family):
    collector = fixture._collector()
    assert collector.config.capture_mtu is False
    expected = {
        "mtu": MTU_NORMALIZATION_VERSION,
        "bgp_dynamic_peers": "1",
        "port_description": "1",
        # stored payloads re-derive their read-failure outcomes
        "read-failures": "1",
        "iface_uid": uid.IFACE_UID_VERSION,
        # interface access lists carry their installation evidence
        "acl_installation": "1",
        # BgpSession states route-reflector-client, and on IOS-XE and
        # NX-OS a filter-list and a prefix-list beside a route-map
        "bgp_session_filters": "1",
        # placeholder serials name no chassis
        "serial": "1",
        # BgpSession carries the cluster id, RoutingProcess the neighbors it
        # writes no session for, and IOS-XE neighbors their templates
        "bgp_cluster_id": "1",
        # RoutingProcess records maximum-paths and multipath-relax
        "bgp_multipath": "1",
        # BgpSession carries the peer's router id from the neighbor output
        "bgp_peer_router_id": "1",
        # an OSPF process is keyed by its id
        "ospf_process": "1",
    }
    if family in ("iosxe", "iosxr"):
        # the ARP table of every VRF
        expected["arp_vrf"] = "1"
    if family in ("iosxr", "nxos"):
        # a path that is not the unicast best path has no RIB row
        expected["rib_best"] = "1"
    if family == "iosxe":
        # a static translation to an interface address keeps its rule
        expected["nat_static_interface"] = "1"
        expected["prefix_list_exact"] = "1"
        # a zone-member interface binds an opaque zone-based firewall rulebase
        expected["zbfw_gap"] = "1"
    if family in ("iosxe", "nxos"):
        # a NAT rule's position is its evaluation order
        expected["nat_position"] = "1"
    if family in ("iosxr", "nxos"):
        # a refused interface binding extract, access list or VLAN filter read reads unauthorized
        expected["read-failures"] = "2"
    if family == "iosxr":
        # the origins under the process address family
        expected["bgp_af_origins"] = "1"
    if family == "nxos":
        # a leaked route's `<address>%<vrf>` next hop is split
        expected["rib_next_hop_vrf"] = "1"
        # the OSPF commands ask for every VRF
        expected["ospf_vrf_scope"] = "1"
        # redistribution keeps its address family and instance tag, and a
        # neighbor states the families it activates
        expected["bgp_address_family"] = "1"
    assert expected == collector.NORMALIZATION_VERSIONS
    batch = collector.normalize(augmented(family, fixture.RAW))
    assert not batch.validate_registry()
    values = [
        o.props.get("normalized_value") for o in observations(batch) if o.props["metric"] == "ipv4_mtu_bytes"
    ]
    assert (9000 if family == "nxos" else 1500) in values
    # An interface MTU is a ceiling in both directions.
    assert all(
        o.props["direction"] == "both"
        for o in observations(batch)
        if o.props.get("enforcement_key") != "queue"
    )
    assert all(
        o.props["direction"] in {"tx", "rx", "unknown"}
        for o in observations(batch)
        if o.props.get("enforcement_key") == "queue"
    )
    assert batch.sections["mtu_ipv4"].status in {"ok", "partial"}
    assert all(c not in collector.VOLATILE_RAW_KEYS for c in MTU_COMMANDS[family].values())


@pytest.mark.parametrize(("fixture", "family"), [(xe, "iosxe"), (xr, "iosxr"), (nx, "nxos")])
def test_interface_mtu_observation_is_both_directions_and_rx_context_resolves_a_ceiling(fixture, family):
    collector = fixture._collector()
    batch = collector.normalize(augmented(family, fixture.RAW))
    rows = [
        MtuObservation(uid=n.uid, **n.props)
        for n in observations(batch)
        if n.props["metric"] == "ipv4_mtu_bytes"
    ]
    assert rows and all(o.direction == "both" for o in rows)
    rx = resolve_constraints(rows, MtuContext(af=4, direction="rx"))
    assert rx.constraints and rx.constraints[0].bound_kind == "ceiling"
    assert rx.constraints[0].value_bytes == (9000 if family == "nxos" else 1500)


def test_documented_untagged_xe_and_xr_media_coordinates_agree():
    xe_media = [
        o
        for o in observations(xe._collector().normalize(dict(xe.RAW)))
        if o.props["metric"] == "l2_max_frame_bytes" and o.props.get("normalized_value")
    ]
    xr_media = [
        o
        for o in observations(xr._collector().normalize(dict(xr.RAW)))
        if o.props["metric"] == "l2_max_frame_bytes" and o.props.get("normalized_value")
    ]
    assert xe_media and xr_media
    assert {o.props["normalized_value"] for o in xe_media + xr_media} == {1514}
    assert all(o.props["tag_depth"] == 0 for o in xe_media + xr_media)
    assert all(o.props["direction"] == "both" for o in xe_media + xr_media)


@pytest.mark.parametrize(
    ("fixture", "family", "ifname", "expected_budget"),
    [
        (xe, "iosxe", "GigabitEthernet1/0/1", 1500),
        (xr, "iosxr", "GigabitEthernet0/0/0/0", 1500),
        (nx, "nxos", "Ethernet1/1", None),
    ],
)
def test_a_port_stage_resolves_the_media_frame_ceiling_where_the_twin_holds_a_byte_basis(
    fixture, family, ifname, expected_budget
):
    """The media MTU's l2_max_frame_bytes evidence lands on the Port subject."""
    collector = fixture._collector()
    batch = collector.normalize(augmented(family, fixture.RAW))
    port_uid = uid.port(fixture.DEV, ifname)
    frame_nodes = [
        n
        for n in observations(batch)
        if n.props.get("subject_uid") == port_uid and n.props["metric"] == "l2_max_frame_bytes"
    ]
    assert frame_nodes, f"no l2_max_frame_bytes observation attached to the {family} Port"
    subjects = {
        r.start_label
        for r in batch.rels
        if r.rel_type == "HAS_MTU" and r.end_uid in {n.uid for n in frame_nodes}
    }
    assert subjects == {"Port"}
    if expected_budget is None:
        assert all(n.props.get("normalized_value") is None for n in frame_nodes)
        return
    constraint = resolve_constraints(
        [MtuObservation(uid=n.uid, **n.props) for n in frame_nodes],
        MtuContext(af=4, enforcement="l2", tag_depth=0),
    ).constraints[0]
    stage = MtuStage(
        stage_id="port",
        egress_subject_uid=port_uid,
        enforcement="l2",
        context=MtuContext(af=4, tag_depth=0),
        constraints=[constraint],
        selection="selected",
        coverage=MtuCoverage(
            complete=True, candidate_set_complete=True, constraints_complete=True, exact_path_known=True
        ),
    )
    assert constraint_budget(constraint, stage) == (expected_budget, [])


def test_unknown_release_and_non_ethernet_stay_raw():
    raw = dict(xr.RAW)
    raw[iosxr.CMD_VERSION] = raw[iosxr.CMD_VERSION].replace("7.3.2", "99.9.9")
    obs = observations(xr._collector().normalize(raw))
    assert obs and all(o.props.get("normalized_value") is None for o in obs)
    assert all("MTU_SEMANTICS_UNKNOWN" in o.props["gaps"] for o in obs)


def test_nxos_actual_json_field_is_preserved_without_assumed_units():
    raw = copy.deepcopy(nx.RAW)
    body = json.loads(raw[nxos.CMD_INTERFACE])
    body["TABLE_interface"]["ROW_interface"][0]["eth_mtu"] = "MTU 9216 bytes"
    raw[nxos.CMD_INTERFACE] = json.dumps(body)
    obs = observations(nx._collector().normalize(raw))
    assert len(obs) == 1
    assert json.loads(obs[0].props["raw_value_json"]) == "MTU 9216 bytes"
    assert obs[0].props.get("normalized_value") is None
    assert obs[0].props["source_field"].endswith(":eth_mtu")


def intermediate(family):
    names = {
        "iosxe": [
            "GigabitEthernet1/0/1",
            "GigabitEthernet1/0/2",
            "GigabitEthernet1/0/3",
            "Port-channel1",
            "Vlan10",
        ],
        "iosxr": [
            "GigabitEthernet0/0/0/0",
            "GigabitEthernet0/0/0/1",
            "GigabitEthernet0/0/0/2",
            "GigabitEthernet0/0/0/0.20",
            "Bundle-Ether10",
        ],
        "nxos": ["Ethernet1/1", "Ethernet1/2", "Port-channel1", "Vlan10"],
    }[family]
    return {
        "device": {"serial": "MTU-SYNTHETIC", "platform": family},
        "interfaces": [
            {
                "name": name,
                "kind": "subif"
                if "." in name
                else "lag"
                if name.startswith(("Port-channel", "Bundle-Ether"))
                else "svi"
                if name.startswith("Vlan")
                else "phys",
            }
            for name in names
        ],
    }


def parse_fixture(family, *, raw=None):
    inter = intermediate(family)
    raw = raw if raw is not None else augmented(family, {})
    config = (
        iosxe.CMD_INTERFACE_CONFIG
        if family == "iosxe"
        else nxos.CMD_INTERFACE_CONFIG
        if family == "nxos"
        else MTU_COMMANDS[family]["config"]
    )
    parse_mtu(raw, inter, family=family, config_command=config)
    return normalize_cisco(inter, source=family, scope=f"{family}:test", l3dom="test"), inter


@pytest.mark.parametrize("family", ["iosxe", "iosxr", "nxos"])
def test_operational_membership_keeps_active_standby_and_unknown(family):
    batch, _ = parse_fixture(family)
    members = [r for r in batch.rels if r.rel_type == "MEMBER_OF" and r.end_label == "Lag"]
    assert sorted(r.props.get("eligible") for r in members if "eligible" in r.props) == [False, True]
    if family == "iosxe":
        assert len(members) == 3 and sum("eligible" not in r.props for r in members) == 1
    else:
        assert len(members) == 2
    assert not batch.validate_registry()
    assert any(
        n.uid == uid.lag(DEV, "Bundle-Ether10" if family == "iosxr" else "Po1")
        for n in batch.nodes
        if n.label == "Lag"
    )


def test_configured_membership_never_invents_eligibility():
    raw = augmented("iosxr", {})
    raw.pop("show bundle")
    raw[RAW_OUTCOMES_KEY].pop("show bundle")
    batch, _ = parse_fixture("iosxr", raw=raw)
    members = [r for r in batch.rels if r.end_label == "Lag" and r.rel_type == "MEMBER_OF"]
    assert len(members) == 1 and "eligible" not in members[0].props


def test_xr_protocol_parenthetical_not_media_number_and_config_remains_distinct():
    batch, _ = parse_fixture("iosxr")
    dev = DEV
    obs = [
        o
        for o in observations(batch)
        if o.props["subject_uid"] == uid.interface(dev, "GigabitEthernet0/0/0/0.20")
        and o.props["metric"] == "ipv4_mtu_bytes"
    ]
    assert {(o.props["assertion_kind"], o.props.get("normalized_value")) for o in obs} == {
        ("configured", 1450),
        ("operational", 1500),
    }
    child = next(n for n in batch.nodes if n.uid == uid.interface(dev, "GigabitEthernet0/0/0/0.20"))
    assert child.props["parent_interface_uid"] == uid.interface(dev, "GigabitEthernet0/0/0/0")
    assert all(json.loads(o.props["selector_json"])["configured_tag_depth"] == 1 for o in obs)


def test_subinterface_with_no_mtu_of_its_own_carries_the_derived_from_marker():
    """`hst.simul.fw_overlay._derived_mtu_target` reads `derived_from_subject_uid` in its selector."""
    raw = augmented("iosxr", {})
    raw["show running-config interface"] = raw["show running-config interface"].replace(
        " ipv4 mtu 1450\n", ""
    )
    batch, _ = parse_fixture("iosxr", raw=raw)
    dev = DEV
    parent = uid.interface(dev, "GigabitEthernet0/0/0/0")
    child = uid.interface(dev, "GigabitEthernet0/0/0/0.20")
    obs = [o for o in observations(batch) if o.props["subject_uid"] == child]
    assert obs
    assert all(json.loads(o.props["selector_json"])["derived_from_subject_uid"] == parent for o in obs)


def test_subinterface_with_its_own_mtu_carries_no_derived_from_marker():
    """The fixture's `GigabitEthernet0/0/0/0.20` config stanza states `ipv4 mtu 1450`."""
    batch, _ = parse_fixture("iosxr")
    dev = DEV
    child = uid.interface(dev, "GigabitEthernet0/0/0/0.20")
    obs = [o for o in observations(batch) if o.props["subject_uid"] == child]
    assert obs
    assert all("derived_from_subject_uid" not in json.loads(o.props["selector_json"]) for o in obs)


def test_system_qos_and_driver_limits_keep_scope_class_and_receive_uncertainty():
    batch, _ = parse_fixture("nxos")
    obs = observations(batch)
    policies = [o for o in obs if o.props["scope"] == "system_policy"]
    assert len(policies) == 3
    assert {o.props.get("traffic_class") for o in policies} == {None, "default", "storage"}
    assert all(o.props["subject_uid"] == DEV for o in policies)
    assert all(o.props.get("normalized_value") is None for o in policies)
    queues = [o for o in obs if o.props["enforcement_key"] == "queue"]
    assert len(queues) == 4
    assert {o.props["traffic_class"] for o in queues} == {"qos-group:0", "qos-group:1"}
    assert all(o.props["direction"] == "rx" and o.props["bound_kind"] == "unknown" for o in queues)


@pytest.mark.parametrize("status", ["unauthorized", "unsupported", "failed", "malformed"])
def test_refused_command_is_not_reinterpreted_as_success(status):
    raw = augmented("iosxe", xe.RAW)
    raw[RAW_OUTCOMES_KEY]["show ip interface"] = {"status": status, "detail": "synthetic failure"}
    batch = xe._collector().normalize(raw)
    assert batch.sections["mtu_ipv4"].status == status
    assert not any(o.props["source_field"].startswith("show ip interface:") for o in observations(batch))


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("", "empty"),
        ("unrecognized format", "partial"),
        ("GigabitEthernet1/0/1 is up, line protocol is up\n  MTU is broken bytes\n", "malformed"),
    ],
)
def test_capture_shape_and_numeric_failures_remain_distinct(body, expected):
    raw = augmented("iosxe", xe.RAW)
    raw["show ip interface"] = body
    batch = xe._collector().normalize(raw)
    assert batch.sections["mtu_ipv4"].status == expected
    if expected == "malformed":
        assert any(json.loads(o.props["raw_value_json"]) == "broken" for o in observations(batch))


def test_a_zero_mtu_is_well_formed_and_sets_no_limit():
    """NX-OS states `MTU 0 bytes` for a port-channel with no operational member."""
    raw = augmented("nxos", nx.RAW)
    raw["show interface"] += "port-channel1 is down (No operational members)\n  MTU 0 bytes, BW 100000 Kbit\n"
    batch = nx._collector().normalize(raw)
    assert batch.sections["mtu_media"].status == "ok"
    (zero,) = [
        o
        for o in observations(batch)
        if o.props["source_field"] == "show interface:MTU" and json.loads(o.props["raw_value_json"]) == "0"
    ]
    assert zero.props.get("normalized_value") is None


def test_raw_without_mtu_capture_is_unknown_without_defaults():
    batch = nx._collector().normalize(dict(nx.RAW))
    assert not observations(batch)
    assert batch.sections["mtu_ipv4"].status == "unknown"
    assert batch.sections["mtu_ipv4"].detail == "MTU_NOT_CAPTURED"


def test_normalization_digest_changes_with_command_outcome_and_mtu_value():
    collector = xe._collector()
    raw = augmented("iosxe", xe.RAW)
    changed = copy.deepcopy(raw)
    changed[RAW_OUTCOMES_KEY]["show ip interface"]["status"] = "unauthorized"
    assert raw_sha(collector, raw) != raw_sha(collector, changed)
    changed = copy.deepcopy(raw)
    changed["show ip interface"] = changed["show ip interface"].replace("1500", "1492")
    assert raw_sha(collector, raw) != raw_sha(collector, changed)


@pytest.mark.parametrize("family", ["iosxe", "iosxr", "nxos"])
def test_optional_capture_records_each_refusal_and_continues(family):
    class Session:
        async def run(self, command):
            if command == MTU_COMMANDS[family]["ipv4"]:
                raise ssh.CommandFailed("% Invalid input detected")
            if command == MTU_COMMANDS[family]["ipv6"]:
                raise ssh.CommandFailed("not authorized")
            return ""

    raw = {}
    asyncio.run(capture_mtu(Session(), raw, family=family))
    assert set(raw) == {*MTU_COMMANDS[family].values(), RAW_OUTCOMES_KEY}
    assert raw[RAW_OUTCOMES_KEY][MTU_COMMANDS[family]["ipv4"]]["status"] == "unsupported"
    assert raw[RAW_OUTCOMES_KEY][MTU_COMMANDS[family]["ipv6"]]["status"] == "unauthorized"


@pytest.mark.parametrize(("fixture", "family"), [(xe, "iosxe"), (xr, "iosxr"), (nx, "nxos")])
def test_collector_opt_in_runs_extra_commands_after_existing_capture(fixture, family):
    collector = fixture._collector()
    collector.config.capture_mtu = True
    collector.config.capture_bgp = "none"
    commands = []

    class Session:
        async def run(self, command):
            commands.append(command)
            return fixture.RAW.get(command, FIXTURE[family].get(command, ""))

    raw = asyncio.run(collector._afetch_over(Session()))
    # IOS-XE reads the ARP table of each VRF before the MTU capture
    arp_vrfs = iosxe.arp_vrf_commands(fixture.RAW[iosxe.CMD_VRF]) if family == "iosxe" else []
    assert commands == [*collector.COMMANDS, *arp_vrfs, *MTU_COMMANDS[family].values()]
    assert (
        raw[RAW_OUTCOMES_KEY]["show ip interface" if family != "iosxr" else "show ipv4 interface"]["status"]
        == "ok"
    )


def test_changed_mtu_value_keeps_observation_identity():
    raw = augmented("iosxe", xe.RAW)
    changed = copy.deepcopy(raw)
    changed["show ip interface"] = changed["show ip interface"].replace("1500", "1492")
    before = {n.uid for n in observations(xe._collector().normalize(raw))}
    after = {n.uid for n in observations(xe._collector().normalize(changed))}
    assert before == after


def test_unknown_bundle_state_does_not_assert_eligible_or_cross_remote_members():
    raw = augmented("iosxr", {})
    raw["show bundle"] = raw["show bundle"].replace("Status: Up", "Status: Down")
    batch, _ = parse_fixture("iosxr", raw=raw)
    members = [r for r in batch.rels if r.rel_type == "MEMBER_OF" and r.end_label == "Lag"]
    assert len(members) == 2 and all(r.props["eligible"] is False for r in members)


def test_tagged_media_is_not_untagged_profile_even_when_protocol_mtu_known():
    inter = intermediate("iosxr")
    inter["device"].update(model="R-IOSXRV9000-CC", os_version="7.3.2")
    child = next(i for i in inter["interfaces"] if i["kind"] == "subif")
    child.update(media_mtu="1518", hardware_type="GigabitEthernet", encapsulation="ARPA")
    raw = augmented("iosxr", {})
    raw["show interfaces"] = "synthetic present"
    parse_mtu(raw, inter, family="iosxr", config_command=MTU_COMMANDS["iosxr"]["config"])
    batch = normalize_cisco(inter, source="iosxr", scope="iosxr:test", l3dom="test")
    media = [o for o in observations(batch) if o.props["source_field"] == "show interfaces:MTU"]
    assert len(media) == 1 and media[0].props.get("normalized_value") is None
