"""Synthetic protocol boundaries; no captured configurations or vendor defaults."""

import json
from pathlib import Path

import pytest
from tests.test_mtu_budget import stage

from hst.core.mtu import MtuEncapsulation, canonical_json
from hst.path.mtu import constraint_budget
from hst.path.mtu_encap import PROFILES, carrier_af, inner_budget, packet_size


def encap(kind, af=None, **params):
    return MtuEncapsulation(
        kind=kind,
        profile_id=PROFILES[kind],
        outer_af=af,
        parameters_json=canonical_json({"version": 1, "options_complete": True, **params}),
    )


def vxlan(af=4, tags=0):
    return encap(
        "vxlan",
        af,
        outer_header_bytes=20 if af == 4 else 40,
        retained_inner_tags=tags,
        inner_min_frame_bytes=0,
    )


def esp(af=4, **changes):
    p = {
        "outer_header_bytes": 20 if af == 4 else 40,
        "mode": "tunnel",
        "cipher": "aes_gcm",
        "iv_bytes": 8,
        "icv_bytes": 16,
        "nat_t": False,
        "tfc_padding_bytes": 0,
    }
    p.update(changes)
    return encap("ipsec", af, **p)


def test_conformance_vectors_of_the_encapsulation_profiles():
    cases = json.loads(Path("fixtures/mtu/conformance.json").read_text())["cases"]
    profiles = {
        "vxlan_ipv4_boundary": vxlan(),
        "vxlan_ipv6_tagged": vxlan(6, 1),
        "esp_gcm_native": esp(),
        "esp_gcm_natt": esp(nat_t=True),
    }
    for case in cases:
        if case["id"] not in profiles:
            continue
        stack = [profiles[case["id"]]]
        assert inner_budget(case["input"]["outer_ip_limit"], stack, original_af=4) == (
            case["expected"]["original_ip_budget_bytes"],
            [],
        )
        for n, expected in zip(
            case["input"]["samples_original_ip"], case["expected"]["outer_ip_sizes"], strict=True
        ):
            assert packet_size(n, stack, original_af=4) == (expected, [])


def test_nested_and_decapsulated_coordinates_and_families():
    a, b = vxlan(), vxlan(6)
    operations = [
        a,
        b,
        b.model_copy(update={"operation": "decapsulate"}),
        a.model_copy(update={"operation": "decapsulate"}),
    ]
    for count, expected, af in [(0, 1400, 4), (1, 1450, 4), (2, 1520, 6), (3, 1450, 4), (4, 1400, 4)]:
        assert packet_size(1400, operations[:count], original_af=4) == (expected, [])
        assert carrier_af(operations[:count], original_af=4) == (af, [])
    assert inner_budget(1500, operations[:2], original_af=4) == (1380, [])
    assert inner_budget(1500, operations, original_af=4) == (1500, [])
    assert inner_budget(1500, operations[2:], original_af=4) == (None, ["MTU_ENCAP_UNKNOWN"])


@pytest.mark.parametrize(
    "checksum,key,sequence",
    [(False, False, False), (True, False, False), (False, True, True), (True, True, True)],
)
def test_gre_options(checksum, key, sequence):
    tunnel = encap(
        "gre",
        4,
        outer_header_bytes=20,
        checksum=checksum,
        key=key,
        sequence=sequence,
        routing=False,
        payload_kind="ip",
    )
    expected = 1500 - 24 - 4 * sum((checksum, key, sequence))
    assert inner_budget(1500, [tunnel], original_af=6) == (expected, [])
    assert packet_size(expected + 1, [tunnel], original_af=6) == (1501, [])


@pytest.mark.parametrize("af,ceiling", [(4, 1440), (6, 1408)])
def test_wireguard_padding_staircase(af, ceiling):
    tunnel = encap(
        "wireguard",
        af,
        outer_header_bytes=20 if af == 4 else 40,
        padding_mode="multiple_16",
        inner_mtu_bytes=None,
    )
    assert inner_budget(1500, [tunnel], original_af=4) == (ceiling, [])
    assert packet_size(ceiling, [tunnel], original_af=4)[0] <= 1500
    assert packet_size(ceiling + 1, [tunnel], original_af=4)[0] > 1500


def test_wireguard_linux_cap_is_padding_rule_not_invented_rejection_ceiling():
    tunnel = encap("wireguard", 6, outer_header_bytes=40, padding_mode="linux_mtu_cap", inner_mtu_bytes=1420)
    assert inner_budget(1500, [tunnel], original_af=4) == (1420, [])
    assert packet_size(1421, [tunnel], original_af=4) == (1516, [])
    assert packet_size(2840, [tunnel], original_af=4) == (2920, [])


def test_cbc_staircase_transport_and_tfc():
    cbc = esp(cipher="aes_cbc", iv_bytes=16, icv_bytes=12)
    assert inner_budget(1500, [cbc], original_af=4) == (1438, [])
    assert packet_size(1438, [cbc], original_af=4) == (1496, [])
    assert packet_size(1439, [cbc], original_af=4) == (1512, [])
    assert inner_budget(1500, [esp(mode="transport")], original_af=4) == (1466, [])
    assert inner_budget(1500, [esp(tfc_padding_bytes=8)], original_af=4) == (1438, [])
    assert inner_budget(1500, [esp(6, mode="transport")], original_af=4) == (None, ["MTU_ENCAP_UNKNOWN"])
    # Lower original lengths can be invalid when explicit IPv4 options are present.
    assert inner_budget(96, [esp(mode="transport", outer_header_bytes=60)], original_af=4) == (62, [])


@pytest.mark.parametrize(
    "shim,overhead",
    [
        (encap("pppoe", ppp_protocol_bytes=2), 8),
        (encap("mpls", label_count=3), 12),
        (encap("macsec", sectag_bytes=16, icv_bytes=16, minimum_payload_bytes=0), 32),
    ],
)
def test_link_shims_only_charge_frame_budget(shim, overhead):
    assert inner_budget(1500, [shim], original_af=4) == (1500, [])
    assert inner_budget(1500, [shim], original_af=4, coordinate="ethernet_payload") == (1500 - overhead, [])
    assert inner_budget(1500, [shim, vxlan()], original_af=4) == (1450 - overhead, [])


def test_macsec_minimum_payload_and_vxlan_minimum_frame_are_explicit():
    shim = encap("macsec", sectag_bytes=8, icv_bytes=16, minimum_payload_bytes=48)
    assert packet_size(20, [shim], original_af=4, coordinate="ethernet_payload") == (72, [])
    v = vxlan()
    p = json.loads(v.parameters_json)
    p["inner_min_frame_bytes"] = 60
    v.parameters_json = canonical_json(p)
    assert packet_size(20, [v], original_af=4) == (96, [])
    assert inner_budget(95, [v], original_af=4) == (0, [])


def test_outer_tags_are_charged_once_and_inner_tags_only_inside_vxlan():
    s = stage(encapsulation=[encap("vlan", tag_count=1)])
    c = s.constraints[0]
    c.metric, c.value_bytes = "l2_max_frame_bytes", 1518
    s.context.tag_depth = 1
    assert constraint_budget(c, s) == (1500, [])
    s.context.tag_depth = 0
    assert constraint_budget(c, s) == (None, ["MTU_SEMANTICS_UNKNOWN"])
    s.encapsulation = [encap("vlan", tag_count=1), vxlan(4, 1)]
    c.value_bytes = 1514
    assert constraint_budget(c, s) == (1446, [])


@pytest.mark.parametrize("original_af,outer_af", [(4, 6), (6, 4)])
def test_constraint_uses_current_carrier_family(original_af, outer_af):
    s = stage(encapsulation=[vxlan(outer_af)])
    s.context.af = original_af
    c = s.constraints[0]
    c.af, c.metric = outer_af, f"ipv{outer_af}_mtu_bytes"
    expected = 1450 if outer_af == 4 else 1430
    assert constraint_budget(c, s) == (expected, [])
    c.metric, c.value_bytes = "l2_max_frame_bytes", 1514
    assert constraint_budget(c, s) == (expected, [])
    c.af = original_af
    assert constraint_budget(c, s) == (None, ["MTU_SEMANTICS_UNKNOWN"])


@pytest.mark.parametrize(
    "changes",
    [
        {"options_complete": False},
        {"retained_inner_tags": None},
        {"extra_option": 4},
        {"outer_header_bytes": True},
    ],
)
def test_incomplete_options_never_become_zero_overhead(changes):
    v = vxlan()
    p = json.loads(v.parameters_json)
    p.update(changes)
    v.parameters_json = canonical_json(p)
    assert inner_budget(1500, [v], original_af=4) == (None, ["MTU_ENCAP_UNKNOWN"])


def test_unknown_profiles_stack_bounds_and_unsupported_lengths():
    unknown = MtuEncapsulation(kind="unknown")
    assert inner_budget(1500, [unknown], original_af=4) == (None, ["MTU_ENCAP_UNKNOWN"])
    assert inner_budget(1500, [vxlan()] * 33, original_af=4) == (None, ["MTU_ENCAP_UNKNOWN"])
    assert packet_size(65576, [], original_af=6) == (None, ["MTU_LENGTH_UNSUPPORTED"])
    assert packet_size(65535, [vxlan()], original_af=4) == (None, ["MTU_LENGTH_UNSUPPORTED"])
    assert inner_budget(20, [vxlan()], original_af=4) == (0, [])


def test_inverse_is_maximal_across_esp_and_wireguard_staircases():
    stacks = [
        [esp()],
        [esp(cipher="aes_cbc", iv_bytes=16, icv_bytes=12)],
        [vxlan(6), esp(nat_t=True)],
        [encap("wireguard", 4, outer_header_bytes=20, padding_mode="linux_mtu_cap", inner_mtu_bytes=1420)],
    ]
    for stack in stacks:
        for limit in range(1350, 1521):
            budget, gaps = inner_budget(limit, stack, original_af=4)
            assert not gaps and budget
            assert packet_size(budget, stack, original_af=4)[0] <= limit
            assert packet_size(budget + 1, stack, original_af=4)[0] > limit


def test_explicit_package_vectors():
    vectors = json.loads(Path("fixtures/mtu/encapsulation/size-vectors.json").read_text())["vectors"]
    for vector in vectors:
        tunnel = encap(vector["kind"], vector["outer_af"], **vector["parameters"])
        assert inner_budget(vector["outer_ip_budget"], [tunnel], original_af=4) == (
            vector["original_ip_budget"],
            [],
        )
