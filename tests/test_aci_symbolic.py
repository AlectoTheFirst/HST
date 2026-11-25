"""The strict ACI gate partitions endpoints and all service dimensions."""

from hst.path.addrsets import _intervals, _ports
from hst.path.gates import aci_symbolic
from hst.path.gates.aci_symbolic import AciTransition
from hst.path.state import FlowRegion

TCP = frozenset({6})


def _region(*, src="10.0.0.1", dst="10.0.0.2", sport="1000-1001", dport="80-81"):
    return FlowRegion.from_query(
        _intervals([src]),
        _intervals([dst]),
        TCP,
        None if dport is None else _ports(dport),
        None if sport is None else _ports(sport),
    )


def _endpoint(ip, epg, *, vrf="vrf:one", pref="enforced"):
    return {
        "ip": ip,
        "epg_uid": epg,
        "epg_name": epg,
        "vrf_uid": vrf,
        "pc_enf_pref": pref,
        "contract_bypass": "",
    }


def _entry(*, action="permit", sport="unspecified", dport="80", graph=None):
    return {
        "src_epg": "epg:src",
        "dst_epg": "epg:dst",
        "contract_uid": "contract:web",
        "contract_name": "web",
        "subject_uid": "subject:web",
        "entry_uid": f"entry:{action}:{sport}:{dport}",
        "proto": "tcp",
        "ether_type": "ipv4",
        "s_from_port": sport,
        "s_to_port": sport,
        "d_from_port": dport,
        "d_to_port": dport,
        # the fields apic.py writes on every vzEntry
        "tcp_rules": "unspecified",
        "apply_to_frag": "no",
        "action": action,
        "directives": None,
        "graph_uid": graph,
        "graph_name": graph,
    }


def _gate(monkeypatch, endpoints, contracts=(), *, context=None):
    def read(_session, query, **_params):
        if query == aci_symbolic._ENDPOINTS:
            return list(endpoints)
        if query == aci_symbolic._CONTRACTS:
            return list(contracts)
        raise AssertionError("unexpected query")

    monkeypatch.setattr(aci_symbolic._path, "_read", read)
    return AciTransition(None, context_uid=context)


def test_no_aci_endpoints_is_an_explicit_pass(monkeypatch):
    out = _gate(monkeypatch, []).apply(_region())
    assert [(effect.kind, effect.terminal) for _region_, effect in out] == [("pass", False)]


def test_partition_preserves_an_existing_request_origin(monkeypatch):
    original = _region().rects[0]
    translated = original.rewrite(src=tuple(_intervals(["192.0.2.1"])))
    out = _gate(monkeypatch, []).apply(FlowRegion.single(translated))
    assert out[0][0].rects[0].request == original


def test_partial_endpoint_membership_is_indeterminate_only_for_that_address_pair(monkeypatch):
    gate = _gate(monkeypatch, [_endpoint("10.0.0.1", "epg:src")])
    out = gate.apply(_region(src="10.0.0.0/30", dst="10.0.0.2"))
    kinds = {effect.kind for _region_, effect in out}
    assert kinds == {"pass", "indeterminate"}


def test_duplicate_epg_identity_is_not_arbitrarily_selected(monkeypatch):
    endpoints = [
        _endpoint("10.0.0.1", "epg:a", vrf="vrf:a"),
        _endpoint("10.0.0.1", "epg:b", vrf="vrf:b"),
        _endpoint("10.0.0.2", "epg:dst", vrf="vrf:a"),
    ]
    out = _gate(monkeypatch, endpoints).apply(_region())
    assert out[0][1].kind == "indeterminate"
    assert "multiple EPG identities" in out[0][1].reason


def test_context_with_no_unique_identity_match_keeps_endpoint_ambiguous(monkeypatch):
    endpoints = [
        _endpoint("10.0.0.1", "epg:a", vrf="vrf:a"),
        _endpoint("10.0.0.1", "epg:b", vrf="vrf:b"),
        _endpoint("10.0.0.2", "epg:dst", vrf="vrf:c"),
    ]
    out = _gate(monkeypatch, endpoints, context="vrf:c").apply(_region())
    assert out[0][1].kind == "indeterminate"
    assert "multiple EPG identities" in out[0][1].reason


def test_duplicate_identity_with_conflicting_enforcement_is_indeterminate(monkeypatch):
    endpoints = [
        _endpoint("10.0.0.1", "epg:src", pref="enforced"),
        _endpoint("10.0.0.1", "epg:src", pref="unenforced"),
        _endpoint("10.0.0.2", "epg:dst"),
    ]
    out = _gate(monkeypatch, endpoints).apply(_region())
    assert out[0][1].kind == "indeterminate"
    assert "conflicting VRF enforcement" in out[0][1].reason


def test_same_known_unenforced_vrf_permits_without_contracts(monkeypatch):
    endpoints = [
        _endpoint("10.0.0.1", "epg:src", pref="unenforced"),
        _endpoint("10.0.0.2", "epg:dst", pref="unenforced"),
    ]
    out = _gate(monkeypatch, endpoints).apply(_region())
    assert [(effect.kind, effect.terminal) for _region_, effect in out] == [("permit", False)]


def test_contract_partitions_source_and_destination_ports(monkeypatch):
    endpoints = [_endpoint("10.0.0.1", "epg:src"), _endpoint("10.0.0.2", "epg:dst")]
    contracts = [
        _entry(action="permit", sport="1000", dport="80"),
        _entry(action="deny", sport="1001", dport="81"),
    ]
    out = _gate(monkeypatch, endpoints, contracts).apply(_region())
    by_service = {(region.rects[0].sport, region.rects[0].dport): effect.kind for region, effect in out}
    assert by_service[(tuple(_ports("1000")), tuple(_ports("80")))] == "permit"
    assert by_service[(tuple(_ports("1001")), tuple(_ports("81")))] == "deny"
    assert any(effect.kind == "deny" for _region_, effect in out)


def test_conflicting_filters_without_collected_precedence_are_indeterminate(monkeypatch):
    endpoints = [_endpoint("10.0.0.1", "epg:src"), _endpoint("10.0.0.2", "epg:dst")]
    out = _gate(
        monkeypatch,
        endpoints,
        [_entry(action="permit"), _entry(action="deny")],
    ).apply(_region(sport="1000", dport="80"))
    assert out[0][1].kind == "indeterminate"
    assert "precedence" in out[0][1].reason


def test_service_graph_and_missing_source_port_are_unknown(monkeypatch):
    endpoints = [_endpoint("10.0.0.1", "epg:src"), _endpoint("10.0.0.2", "epg:dst")]
    graphed = _entry(graph="graph:inspect")
    missing_source = {**_entry(dport="81"), "s_from_port": None, "s_to_port": None}
    out = _gate(monkeypatch, endpoints, [graphed, missing_source]).apply(_region())
    unknown = [(region.rects[0], effect) for region, effect in out if effect.kind == "indeterminate"]
    assert any("service graph" in effect.reason for _rect, effect in unknown)
    assert any("sport" in effect.unknown for _rect, effect in unknown)


def test_cross_vrf_pair_is_indeterminate(monkeypatch):
    endpoints = [
        _endpoint("10.0.0.1", "epg:src", vrf="vrf:a"),
        _endpoint("10.0.0.2", "epg:dst", vrf="vrf:b"),
    ]
    out = _gate(monkeypatch, endpoints).apply(_region())
    assert out[0][1].kind == "indeterminate"
    assert "cross-VRF" in out[0][1].reason


def test_a_reverse_orientation_contract_makes_no_contract_indeterminate(monkeypatch):
    """The destination EPG consumes a contract the source EPG provides."""
    endpoints = [_endpoint("10.0.0.1", "epg:src"), _endpoint("10.0.0.2", "epg:dst")]
    reverse = {**_entry(), "src_epg": "epg:dst", "dst_epg": "epg:src"}
    out = _gate(monkeypatch, endpoints, [reverse]).apply(_region())
    assert {effect.kind for _region_, effect in out} == {"indeterminate"}
    assert "provider-to-consumer" in out[0][1].reason


def test_a_reverse_contract_leaves_the_unmatched_rest_indeterminate(monkeypatch):
    endpoints = [_endpoint("10.0.0.1", "epg:src"), _endpoint("10.0.0.2", "epg:dst")]
    reverse = {**_entry(), "src_epg": "epg:dst", "dst_epg": "epg:src", "contract_uid": "contract:back"}
    out = _gate(monkeypatch, endpoints, [_entry(dport="80"), reverse]).apply(_region())
    by_port = {region.rects[0].dport: effect.kind for region, effect in out}
    assert by_port[tuple(_ports("80"))] == "permit"
    assert by_port[tuple(_ports("81"))] == "indeterminate"


def test_a_vrf_using_vzany_does_not_implicitly_deny(monkeypatch):
    """vzAny, the preferred group or an ESG may permit the pair."""
    endpoints = [
        {**_endpoint("10.0.0.1", "epg:src"), "contract_bypass": "vzany"},
        {**_endpoint("10.0.0.2", "epg:dst"), "contract_bypass": "vzany"},
    ]
    out = _gate(monkeypatch, endpoints).apply(_region())
    assert [effect.kind for _region_, effect in out] == ["indeterminate"]
    assert "vzAny" in out[0][1].reason


def test_a_vrf_whose_bypass_inputs_were_not_collected_does_not_implicitly_deny(monkeypatch):
    endpoints = [
        {**_endpoint("10.0.0.1", "epg:src"), "contract_bypass": None},
        {**_endpoint("10.0.0.2", "epg:dst"), "contract_bypass": None},
    ]
    out = _gate(monkeypatch, endpoints).apply(_region())
    assert [effect.kind for _region_, effect in out] == ["indeterminate"]
    assert "not collected" in out[0][1].reason


def test_a_sibling_permit_entry_with_tcp_rules_does_not_undo_a_known_permit(monkeypatch):
    endpoints = [_endpoint("10.0.0.1", "epg:src"), _endpoint("10.0.0.2", "epg:dst")]
    known = _entry(dport="80")
    flagged = {**_entry(dport="80"), "entry_uid": "entry:est", "tcp_rules": "est"}
    out = _gate(monkeypatch, endpoints, [known, flagged]).apply(_region(dport="80"))
    assert [effect.kind for _region_, effect in out] == ["permit"]
