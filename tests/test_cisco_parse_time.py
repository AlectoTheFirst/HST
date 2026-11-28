"""The Cisco parsers read each crafted device line below in under 1 s."""

import time
from collections.abc import Callable
from typing import Any

import test_mtu_cisco as mtu
from hst.collectors import cisco_bgp_table, iosxe, nxos
from hst.collectors.cisco_common import (
    _number_of,
    cdp_device_id,
    parse_access_groups,
    parse_vlan_filters,
)

# The bound is loose for a loaded host. Each input takes seconds or more with
# a pattern that backtracks.
LIMIT_S = 1.0
SPACES = " " * 40_000


def timed(fn: Callable[..., Any], *args: Any) -> tuple[Any, float]:
    started = time.perf_counter()
    result = fn(*args)
    return result, time.perf_counter() - started


def test_a_vlan_filter_line_with_spaced_commas_and_an_inner_space_is_read_in_time():
    result, elapsed = timed(parse_vlan_filters, ["vlan filter M vlan-list 1" + " , " * 16 + "a b"])
    assert result == []
    assert elapsed < LIMIT_S


def test_a_vlan_filter_line_with_spaced_commas_binds_each_vlan():
    assert parse_vlan_filters(["vlan filter M vlan-list 10 , 20,30 ,  40-41"]) == [
        {"interface": f"Vlan{vid}", "direction": side, "acl": "M", "family": "vlan-map"}
        for vid in (10, 20, 30, 40, 41)
        for side in ("in", "out")
    ]


def test_an_interface_line_with_a_long_inner_space_run_is_read_in_time():
    name = "a" + SPACES + "b"
    result, elapsed = timed(parse_access_groups, ["interface " + name, " ip access-group X in"])
    assert result == [{"interface": name, "direction": "in", "acl": "X"}]
    assert elapsed < LIMIT_S


def test_an_interface_number_with_a_long_inner_space_run_is_read_in_time():
    result, elapsed = timed(_number_of, "Eth1" + SPACES + "X")
    assert result == "1" + SPACES + "x"
    assert elapsed < LIMIT_S


def test_a_cdp_device_id_with_a_long_space_run_and_no_serial_is_read_in_time():
    value = "a" + SPACES + "b"
    result, elapsed = timed(cdp_device_id, value)
    assert result == (value, None)
    assert elapsed < LIMIT_S


def test_a_long_digit_run_in_a_port_list_is_read_in_time():
    result, elapsed = timed(nxos.expand_port_list, "1" * 40_000)
    assert result == ["1" * 40_000]
    assert elapsed < LIMIT_S


def test_a_long_colon_run_in_a_bgp_table_network_is_read_in_time():
    result, elapsed = timed(cisco_bgp_table._network_ok, ":" * 40_000)
    assert result is False
    assert elapsed < LIMIT_S
    result, elapsed = timed(cisco_bgp_table._next_hop_ok, ":" * 40_000 + "x")
    assert result is False
    assert elapsed < LIMIT_S


def test_a_bgp_summary_of_blank_lines_is_read_in_time():
    # The first parse loads the TextFSM template.
    iosxe.parse_bgp_sessions("")
    result, elapsed = timed(iosxe.parse_bgp_sessions, ("\n" + " " * 40) * 20_000)
    assert result == []
    assert elapsed < LIMIT_S


def test_a_route_map_of_blank_lines_is_read_in_time():
    result, elapsed = timed(iosxe.match_list_commands, "\n" * 80_000)
    assert result == []
    assert elapsed < LIMIT_S


def mtu_parse(family: str, command: str, line: str) -> tuple[dict[str, Any], float]:
    raw = mtu.augmented(family, {})
    raw[command] += line + "\n"
    started = time.perf_counter()
    _, inter = mtu.parse_fixture(family, raw=raw)
    return inter, time.perf_counter() - started


def mtu_baseline(family: str) -> dict[str, Any]:
    _, inter = mtu.parse_fixture(family)
    return inter


def test_an_iosxr_bundle_status_with_a_long_inner_space_run_is_read_in_time():
    inter, elapsed = mtu_parse("iosxr", "show bundle", "  Status: a" + SPACES + "b")
    assert inter["mtu_memberships"] == mtu_baseline("iosxr")["mtu_memberships"]
    assert elapsed < LIMIT_S


def test_an_iosxr_bundle_line_of_one_long_digit_run_is_read_in_time():
    inter, elapsed = mtu_parse("iosxr", "show bundle", "1" * 40_000)
    assert inter["mtu_memberships"] == mtu_baseline("iosxr")["mtu_memberships"]
    assert elapsed < LIMIT_S


def test_an_nxos_port_channel_line_of_letters_and_digits_is_read_in_time():
    inter, elapsed = mtu_parse("nxos", "show port-channel summary", "a1" * 1_500)
    assert inter["mtu_memberships"] == mtu_baseline("nxos")["mtu_memberships"]
    assert elapsed < LIMIT_S


def test_an_nxos_qos_line_of_open_service_policy_brackets_is_read_in_time():
    inter, elapsed = mtu_parse("nxos", "show policy-map system type network-qos", "Service-policy (" * 30_000)
    assert inter["mtu_observations"] == mtu_baseline("nxos")["mtu_observations"]
    assert elapsed < LIMIT_S


def test_an_nxos_qos_line_of_open_class_map_brackets_is_read_in_time():
    inter, elapsed = mtu_parse("nxos", "show policy-map system type network-qos", "Class-map (" * 30_000)
    assert inter["mtu_observations"] == mtu_baseline("nxos")["mtu_observations"]
    assert elapsed < LIMIT_S
