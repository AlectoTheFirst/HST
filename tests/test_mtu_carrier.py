"""Carrier encapsulation stacks built from Tunnel evidence."""

from types import SimpleNamespace

from tests.test_mtu_contract import observation
from tests.test_mtu_snapshot import row

import hst.path as path
from hst.core.mtu import MtuRequest, canonical_json
from hst.path.gates import _Trail
from hst.path.mtu_encap import inner_budget
from hst.path.mtu_topology import build_carrier_stack, carrier_crossing, crossing, mtu_request, trace_scope

WG0, PPPOE0 = "if:wg0", "if:pppoe0"


def graph_reads(monkeypatch, observations=()):
    def read(session, query, **params):
        if "HAS_MTU" in query:
            return [row(o) for o in observations if o.subject_uid in params["subject_uids"]]
        return []

    monkeypatch.setattr(path, "_read", read)


def _wireguard_over_pppoe(monkeypatch, *, wg_mtu, request_bytes, reverse=False):
    tunnel = {
        "encap": "wireguard",
        "local_address": "203.0.113.2",
        "tunnel_mtu": wg_mtu,
        "uid": "tun:wireguard:gw~peer1",
        "interface_uid": WG0,
    }
    graph_reads(
        monkeypatch,
        [
            observation(wg_mtu, subject_uid=WG0, enforcement="tunnel"),
            observation(1492, subject_uid=PPPOE0, enforcement="l3"),
        ],
    )

    @trace_scope(reverse=reverse)
    def walk(session):
        trail = _Trail()
        crossing(trail, WG0, enforcement="tunnel")
        carrier_crossing(trail, PPPOE0, tunnel=tunnel)
        return {"hops": trail.hops, "trail": trail}

    request = MtuRequest(
        mode="packet", ip_packet_bytes=request_bytes, reply_ip_packet_bytes=request_bytes, ipv4_df=True
    )
    with mtu_request(request, 4):
        result = walk(SimpleNamespace(cts=42))
    return result["mtu"], tunnel


# --- WireGuard over PPPoE ------------------------------------------------------


def test_wireguard_over_pppoe_passes_carrier_and_fails_the_tunnel_ceiling(monkeypatch):
    tunnel_stub = {"encap": "wireguard", "local_address": "203.0.113.2", "tunnel_mtu": 1370}
    stack, detail = build_carrier_stack(tunnel_stub)
    assert detail is None
    carrier_budget, gaps = inner_budget(1492, stack, original_af=4)
    assert gaps == []
    assert carrier_budget == 1418  # 1492 - WireGuard/IPv4 overhead as mtu_encap computes it

    result, _ = _wireguard_over_pppoe(monkeypatch, wg_mtu=1370, request_bytes=1400)
    assert result["outcome"] == "fail"
    stage_by_subject = {s["egress_subject_uid"] or s["ingress_subject_uid"]: s for s in result["stages"]}
    assert not any("MTU_ENCAP_UNKNOWN" in s["coverage"]["gaps"] for s in result["stages"])
    deficits = [f for f in result["findings"] if f["code"] == "MTU_CAPACITY_DEFICIT"]
    assert {tuple(f["subject_uids"]) for f in deficits} == {(WG0,)}
    assert stage_by_subject[PPPOE0]["encapsulation"][0]["kind"] == "wireguard"


def test_wireguard_over_pppoe_fails_at_the_carrier_once_the_tunnel_ceiling_is_raised(monkeypatch):
    stack, _ = build_carrier_stack({"encap": "wireguard", "local_address": "203.0.113.2", "tunnel_mtu": 1450})
    carrier_budget, _ = inner_budget(1492, stack, original_af=4)
    assert carrier_budget == 1424

    result, _ = _wireguard_over_pppoe(monkeypatch, wg_mtu=1450, request_bytes=1440)
    assert result["outcome"] == "fail"
    deficits = [f for f in result["findings"] if f["code"] == "MTU_CAPACITY_DEFICIT"]
    assert {tuple(f["subject_uids"]) for f in deficits} == {(PPPOE0,)}
    assert deficits[0]["deficit_bytes"] == 1440 - carrier_budget
    assert not any("MTU_ENCAP_UNKNOWN" in s["coverage"]["gaps"] for s in result["stages"])
    assert all(s["egress_subject_uid"] or s["ingress_subject_uid"] for s in result["stages"])


# --- IPv6 outer WireGuard -------------------------------------------------------


def test_ipv6_outer_wireguard_uses_the_forty_byte_header():
    v4_stack, _ = build_carrier_stack(
        {"encap": "wireguard", "local_address": "203.0.113.2", "tunnel_mtu": 1400}
    )
    v6_stack, detail = build_carrier_stack(
        {"encap": "wireguard", "local_address": "2001:db8::1", "tunnel_mtu": 1400}
    )
    assert detail is None
    assert v6_stack[0].outer_af == 6
    v4_budget, _ = inner_budget(1492, v4_stack, original_af=4)
    v6_budget, gaps = inner_budget(1492, v6_stack, original_af=4)
    assert gaps == []
    # WireGuard's 16-byte padding quantum can make the difference larger than 20.
    assert v6_budget < v4_budget


def test_ipv6_outer_wireguard_over_pppoe_walks_the_full_trace(monkeypatch):
    tunnel = {
        "encap": "wireguard",
        "local_address": "2001:db8::1",
        "tunnel_mtu": 1600,  # above the carrier budget
        "uid": "tun:wireguard:gw~peer-v6",
        "interface_uid": WG0,
    }
    graph_reads(
        monkeypatch,
        [
            observation(1600, subject_uid=WG0, enforcement="tunnel"),
            # A VyOS netdevice MTU applies to both address families.
            observation(1492, subject_uid=PPPOE0, enforcement="l3"),
            observation(1492, subject_uid=PPPOE0, enforcement="l3", metric="ipv6_mtu_bytes", af=6),
        ],
    )

    @trace_scope()
    def walk(session):
        trail = _Trail()
        crossing(trail, WG0, enforcement="tunnel")
        carrier_crossing(trail, PPPOE0, tunnel=tunnel)
        return {}

    v6_stack, _ = build_carrier_stack(tunnel)
    carrier_budget, gaps = inner_budget(1492, v6_stack, original_af=4)
    assert gaps == []

    request = MtuRequest(mode="packet", ip_packet_bytes=carrier_budget + 1, ipv4_df=True)
    with mtu_request(request, 4):
        result = walk(SimpleNamespace(cts=42))["mtu"]
    assert not any("MTU_ENCAP_UNKNOWN" in s["coverage"]["gaps"] for s in result["stages"])
    stage_by_subject = {s["egress_subject_uid"] or s["ingress_subject_uid"]: s for s in result["stages"]}
    assert stage_by_subject[PPPOE0]["encapsulation"][0]["outer_af"] == 6
    deficits = [f for f in result["findings"] if f["code"] == "MTU_CAPACITY_DEFICIT"]
    assert {tuple(f["subject_uids"]) for f in deficits} == {(PPPOE0,)}


# --- GRE with key -----------------------------------------------------------------


def test_gre_with_a_key_costs_four_more_bytes_than_without():
    with_key, detail1 = build_carrier_stack(
        {
            "encap": "gre",
            "local_address": "203.0.113.2",
            "gre_key": True,
            "gre_checksum": False,
            "gre_sequence": False,
        }
    )
    without_key, detail2 = build_carrier_stack(
        {
            "encap": "gre",
            "local_address": "203.0.113.2",
            "gre_key": False,
            "gre_checksum": False,
            "gre_sequence": False,
        }
    )
    assert detail1 is None and detail2 is None
    budget_with_key, _ = inner_budget(1500, with_key, original_af=4)
    budget_without_key, _ = inner_budget(1500, without_key, original_af=4)
    assert budget_without_key - budget_with_key == 4


# --- VXLAN --------------------------------------------------------------------------


def test_vxlan_budget_follows_the_profile():
    stack, detail = build_carrier_stack({"encap": "vxlan", "local_address": "203.0.113.1"})
    assert detail is None
    budget, gaps = inner_budget(1500, stack, original_af=4)
    assert gaps == []
    assert budget == 1450  # 1500 - (14 inner Ethernet + 8 VXLAN + 8 UDP + 20 IPv4)


# --- IPsec ESP ------------------------------------------------------------------------


def test_ipsec_gcm128_tunnel_mode_budget_follows_mtu_encap():
    stack, detail = build_carrier_stack(
        {
            "encap": "ipsec",
            "local_address": "203.0.113.2",
            "esp_encryption": "aes256gcm128",
            "esp_mode": "tunnel",
        }
    )
    assert detail is None
    assert stack[0].kind == "ipsec"
    assert stack[0].proposal_basis == "single"
    budget, gaps = inner_budget(1500, stack, original_af=4)
    assert gaps == []
    assert budget > 0


def test_ipsec_nat_t_adds_the_eight_byte_udp_encapsulation():
    """endpoint_port 4500 states that this ESP SA rides UDP/4500 NAT-T (RFC 3948 SS2)."""
    base_params = {
        "encap": "ipsec",
        "local_address": "203.0.113.2",
        "esp_encryption": "aes256gcm128",
        "esp_mode": "tunnel",
    }
    plain_stack, plain_detail = build_carrier_stack(base_params)
    nat_t_stack, nat_t_detail = build_carrier_stack({**base_params, "endpoint_port": 4500})
    assert plain_detail is None and nat_t_detail is None
    assert plain_stack[0].parameters_json != nat_t_stack[0].parameters_json
    plain_budget, plain_gaps = inner_budget(1500, plain_stack, original_af=4)
    nat_t_budget, nat_t_gaps = inner_budget(1500, nat_t_stack, original_af=4)
    assert plain_gaps == [] and nat_t_gaps == []
    assert nat_t_budget == plain_budget - 8

    non_udp_stack, _ = build_carrier_stack({**base_params, "endpoint_port": 500})
    non_udp_budget, _ = inner_budget(1500, non_udp_stack, original_af=4)
    assert non_udp_budget == plain_budget


def test_ipsec_aes256_sha256_budget_follows_mtu_encap():
    stack, detail = build_carrier_stack(
        {
            "encap": "ipsec",
            "local_address": "203.0.113.2",
            "esp_encryption": "aes256",
            "esp_hash": "sha256",
            "esp_mode": "tunnel",
        }
    )
    assert detail is None
    budget, gaps = inner_budget(1500, stack, original_af=4)
    assert gaps == []
    assert budget > 0


def test_ipsec_esp_proposals_with_one_entry_is_basis_single():
    stack, detail = build_carrier_stack(
        {
            "encap": "ipsec",
            "local_address": "203.0.113.2",
            "esp_encryption": "aes256gcm128",
            "esp_mode": "tunnel",
            "esp_proposals": canonical_json([{"encryption": "aes256gcm128", "hash": None}]),
        }
    )
    assert detail is None
    assert stack[0].proposal_basis == "single"
    assert stack[0].esp_encryption == "aes256gcm128"


def test_ipsec_esp_proposals_with_differing_overhead_takes_the_largest():
    """The peer can select either proposal of the esp-group."""
    stack, detail = build_carrier_stack(
        {
            "encap": "ipsec",
            "local_address": "203.0.113.2",
            "esp_encryption": "aes256gcm128",
            "esp_mode": "tunnel",
            "esp_proposals": canonical_json(
                [
                    {"encryption": "aes256gcm128", "hash": None},
                    {"encryption": "aes256", "hash": "sha256"},
                ]
            ),
        }
    )
    assert detail is None
    assert stack[0].proposal_basis == "largest-overhead-of-2"
    assert stack[0].esp_encryption == "aes256"
    assert stack[0].esp_hash == "sha256"
    budget, gaps = inner_budget(1500, stack, original_af=4)
    assert gaps == []
    assert budget == 1438  # the CBC/sha256 budget; gcm128 alone gives 1446

    gcm_only_stack, _ = build_carrier_stack(
        {
            "encap": "ipsec",
            "local_address": "203.0.113.2",
            "esp_encryption": "aes256gcm128",
            "esp_mode": "tunnel",
        }
    )
    gcm_only_budget, _ = inner_budget(1500, gcm_only_stack, original_af=4)
    assert gcm_only_budget == 1446
    assert budget < gcm_only_budget


def test_ipsec_esp_proposals_drops_an_unsupported_cipher_before_ranking():
    stack, detail = build_carrier_stack(
        {
            "encap": "ipsec",
            "local_address": "203.0.113.2",
            "esp_encryption": "3des",
            "esp_mode": "tunnel",
            "esp_proposals": canonical_json(
                [
                    {"encryption": "3des", "hash": "sha1"},
                    {"encryption": "aes256gcm128", "hash": None},
                ]
            ),
        }
    )
    assert detail is None
    assert stack[0].proposal_basis == "single"
    assert stack[0].esp_encryption == "aes256gcm128"
    budget, gaps = inner_budget(1500, stack, original_af=4)
    assert gaps == []
    assert budget == 1446


def test_a_vti_with_no_resolvable_esp_group_keeps_the_unknown_stack_and_states_why():
    stack, detail = build_carrier_stack(
        {"encap": "ipsec", "local_address": "203.0.113.2", "uid": "tun:ipsec:vti0", "name": "vti0"}
    )
    assert stack == []
    assert detail == "IPsec proposal not collected for tunnel vti0"


def test_an_unresolvable_carrier_never_treats_its_own_ceiling_as_a_zero_overhead_inner_budget(
    monkeypatch,
):
    """mtu.constraint_budget inverts through mtu_encap only when `stage.encapsulation` is truthy."""
    graph_reads(monkeypatch, [observation(1492, subject_uid=PPPOE0, enforcement="l3")])
    tunnel = {
        "encap": "ipsec",
        "local_address": "203.0.113.2",
        "uid": "tun:ipsec:zia",
        "name": "zia-primary",
    }

    @trace_scope()
    def walk(session):
        carrier_crossing(_Trail(), PPPOE0, tunnel=tunnel)
        return {}

    for size in (1450, 1500):
        request = MtuRequest(mode="packet", ip_packet_bytes=size, ipv4_df=False)
        with mtu_request(request, 4):
            result = walk(SimpleNamespace(cts=42))["mtu"]
        stage = result["stages"][0]
        assert stage["encapsulation"] == [
            {
                "kind": "unknown",
                "operation": "encapsulate",
                "profile_id": "unknown",
                "outer_af": None,
                "parameters_json": '{"version":1}',
                "proposal_basis": None,
                "esp_encryption": None,
                "esp_hash": None,
                "evidence_uids": [],
            }
        ]
        assert "MTU_ENCAP_UNKNOWN" in stage["coverage"]["gaps"]
        assert result["known_ceiling_bytes"] is None
        assert result["outcome"] == "unknown"


# --- reply direction --------------------------------------------------------------


def test_reply_across_the_same_tunnel_judges_the_carrier_without_a_new_gap(monkeypatch):
    forward, _ = _wireguard_over_pppoe(monkeypatch, wg_mtu=1370, request_bytes=1400, reverse=False)
    reply, _ = _wireguard_over_pppoe(monkeypatch, wg_mtu=1370, request_bytes=1400, reverse=True)
    assert reply["direction"] == "reverse"
    assert reply["coverage"]["gaps"] == forward["coverage"]["gaps"]
    assert not any("MTU_ENCAP_UNKNOWN" in s["coverage"]["gaps"] for s in reply["stages"])
    carrier_stage = next(s for s in reply["stages"] if s["egress_subject_uid"] == PPPOE0)
    assert carrier_stage["encapsulation"][0]["kind"] == "wireguard"
    assert carrier_stage["encapsulation"][0]["operation"] == "encapsulate"
