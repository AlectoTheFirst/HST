"""Routing model errors invalidate only their dependent proof contexts."""

from hst.simul import certainty
from hst.simul.proof import _Dependencies, affected_contexts
from hst.simul.propagate import SimulationInput
from hst.simul.rib import RibInput


def _input():
    bgp = SimulationInput(
        processes=[
            {"uid": "bgp:a", "context_uid": "vrf:a", "proto": "bgp"},
            {"uid": "bgp:b", "context_uid": "vrf:b", "proto": "bgp"},
        ],
        sessions=[
            {
                "uid": "session:a-b",
                "process_uid": "bgp:a",
                "local_ip": "192.0.2.1",
                "peer_ip": "192.0.2.2",
                "import_policy_name": "EDGE-IN",
            },
            {
                "uid": "session:b-a",
                "process_uid": "bgp:b",
                "local_ip": "192.0.2.2",
                "peer_ip": "192.0.2.1",
            },
        ],
        policies=[
            {
                "name": "EDGE-IN",
                "kind": "rpl",
                "entries": [{"seq": 10, "calls_policy": "SHARED"}],
            },
            {
                "name": "SHARED",
                "kind": "rpl",
                "entries": [{"seq": 10, "match_as_path_lists": ["AS-FILTER"]}],
            },
        ],
    )
    return RibInput(
        contexts=[
            {"uid": "vrf:a", "device_uid": "dev:a", "platform": "nxos"},
            {"uid": "vrf:b", "device_uid": "dev:b", "platform": "nxos"},
            {"uid": "vrf:c", "device_uid": "dev:c", "platform": "mystery-os"},
            {"uid": "vrf:d", "device_uid": "dev:d", "platform": "iosxe"},
        ],
        connected=[{"context_uid": "vrf:d", "prefix": "not-a-prefix", "interface": "eth0"}],
        ospf=[
            {
                "uid": "ospf:c",
                "context_uid": "vrf:c",
                "rows": [
                    {
                        "lsa_type": "router",
                        "lsid": "10.0.0.3",
                        "adv_router": "10.0.0.3",
                        "area": "0.0.0.1",
                    }
                ],
            }
        ],
        bgp=bgp,
        rt_pairs=[{"importer": "vrf:d", "exporter": "vrf:b", "via_rt": "65000:1"}],
        platform="iosxe",
    )


def _error(kind, subject=None, detail="model detail"):
    return {"kind": kind, "detail": detail, "subject": subject}


def test_known_vendor_default_diagnostics_do_not_invalidate_proofs():
    inp = _input()
    errors = [
        _error("undefined-neighbor-route-map", "MISSING"),
        _error("undefined-policy-call", "MISSING-CALL"),
        _error("ospf-next-hop-unresolved", "10.0.0.9"),
    ]
    assert affected_contexts(inp, errors) == {}


def test_unmodeled_policy_matches_hold_the_contexts_that_attach_the_policy():
    """A community or AS-path list match evaluates false whatever the device
    holds, and an unsupported match line cannot be evaluated at all: each one
    makes the attaching session's context and its dependents uncertain."""
    inp = _input()
    inp.bgp.policies[1]["entries"].append({"seq": 20, "set_comm_list_delete": "STRIP"})
    for error in (
        _error("undefined-as-path-list", "AS-FILTER"),
        _error("undefined-community-list", "STRIP"),
        _error("unsupported-match", "SHARED"),
    ):
        assert set(affected_contexts(inp, [error])) == {"vrf:a", "vrf:b", "vrf:d"}, error["kind"]


def test_unknown_platform_is_scoped_to_contexts_using_that_profile():
    result = affected_contexts(_input(), [_error("unknown-platform", "mystery-os")])
    assert set(result) == {"vrf:c"}
    assert result["vrf:c"][0]["kind"] == "unknown-platform"


def test_malformed_route_is_derived_from_input_provenance_without_parsing_error_text():
    result = affected_contexts(
        _input(),
        [_error("malformed-route", detail="wording may change without changing provenance")],
    )
    assert set(result) == {"vrf:d"}


def test_session_error_reaches_the_peer_and_route_target_importer():
    result = affected_contexts(_input(), [_error("unpaired-bgp-session", "session:a-b")])
    assert set(result) == {"vrf:a", "vrf:b", "vrf:d"}


def test_unknown_reflection_and_an_unmodeled_filter_list_hold_their_bgp_contexts():
    """The process or session the engine names is uncertain,
    with the contexts that depend on it, and no other context."""
    for error in (
        _error("bgp-reflection-unknown", "bgp:b"),
        _error("neighbor-filter-list-not-modeled", "session:a-b"),
    ):
        assert set(affected_contexts(_input(), [error])) == {"vrf:a", "vrf:b", "vrf:d"}, error["kind"]


def test_ospf_lsa_subject_maps_to_its_process_context():
    subject = "router LSA 10.0.0.3 from 10.0.0.3"
    result = affected_contexts(_input(), [_error("malformed-lsa", subject)])
    assert set(result) == {"vrf:c"}
    assert result["vrf:c"][0]["subject"] == subject


def test_unknown_future_error_is_conservatively_global_and_keeps_provenance():
    error = _error("future-model-gap", "new-object", "future semantics are not modeled")
    result = affected_contexts(_input(), [error])
    assert set(result) == {"vrf:a", "vrf:b", "vrf:c", "vrf:d"}
    assert all(reasons == [error] for reasons in result.values())


def test_unsupported_set_and_list_lines_hold_the_contexts_that_attach_the_policy():
    """A set line or a list line the engine does not model leaves the
    route the policy produces unknown, so the attaching contexts and their
    dependents are uncertain; a policy named only inside an IOS-XR guard
    (`match_policies`, an `apply`) is followed the same way."""
    inp = _input()
    inp.bgp.policies[1]["entries"].append({"seq": 20, "match_policies": ["GUARD-SUB"]})
    for error in (
        _error("unsupported-set", "SHARED"),
        _error("unsupported-list-entry", "AS-FILTER"),
        _error("unsupported-match", "GUARD-SUB"),
    ):
        assert set(affected_contexts(inp, [error])) == {"vrf:a", "vrf:b", "vrf:d"}, error["kind"]


def test_an_nxos_policy_based_routing_match_is_a_diagnostic():
    """NX-OS route filtering ignores the line, which the engine models, so the
    proof stands."""
    assert affected_contexts(_input(), [_error("pbr-only-match", "SHARED")]) == {}


def _scoped_input():
    """Two devices that both attach a policy `EDGE-IN`. A's calls `SHARED`; B's
    calls `OTHER`."""
    bgp = SimulationInput(
        processes=[
            {"uid": "bgp:a", "context_uid": "vrf:a", "proto": "bgp", "device_uid": "dev:a"},
            {"uid": "bgp:b", "context_uid": "vrf:b", "proto": "bgp", "device_uid": "dev:b"},
        ],
        sessions=[
            {
                "uid": "session:a-b",
                "process_uid": "bgp:a",
                "local_ip": "192.0.2.1",
                "peer_ip": "192.0.2.2",
                "import_policy_name": "EDGE-IN",
            },
            {
                "uid": "session:b-a",
                "process_uid": "bgp:b",
                "local_ip": "192.0.2.2",
                "peer_ip": "192.0.2.1",
                "import_policy_name": "EDGE-IN",
            },
        ],
        policies=[
            {
                "name": "EDGE-IN",
                "kind": "rpl",
                "device_uid": "dev:a",
                "entries": [{"seq": 10, "calls_policy": "SHARED"}],
            },
            {
                "name": "SHARED",
                "kind": "rpl",
                "device_uid": "dev:a",
                "entries": [{"seq": 10, "set_next_hop": "198.51.100.1"}],
            },
            {
                "name": "EDGE-IN",
                "kind": "rpl",
                "device_uid": "dev:b",
                "entries": [{"seq": 10, "calls_policy": "OTHER"}],
            },
            {"name": "OTHER", "kind": "rpl", "device_uid": "dev:b", "entries": [{"seq": 10}]},
        ],
    )
    return RibInput(
        contexts=[
            {"uid": "vrf:a", "device_uid": "dev:a", "platform": "nxos"},
            {"uid": "vrf:b", "device_uid": "dev:b", "platform": "nxos"},
        ],
        bgp=bgp,
        platform="nxos",
    )


def test_a_policy_reaches_the_contexts_of_the_device_that_calls_it():
    """A policy name two devices both attach reaches only the contexts
    of the device whose policy calls the referenced name, not the union of
    every device that uses the name."""
    deps = _Dependencies(_scoped_input())
    assert deps.policy_contexts[("dev:a", "SHARED")] == {"vrf:a"}
    assert deps.policy_contexts[("dev:b", "OTHER")] == {"vrf:b"}
    assert ("dev:b", "SHARED") not in deps.policy_contexts
    assert ("dev:a", "OTHER") not in deps.policy_contexts


def test_an_error_naming_a_policy_reaches_every_device_that_has_one_of_that_name():
    """The error subject is the bare name, so it holds the contexts of every
    device with a policy of that name."""
    deps = _Dependencies(_scoped_input())
    assert deps.direct({"kind": "unsupported-set", "subject": "EDGE-IN"}) == {"vrf:a", "vrf:b"}
    assert deps.direct({"kind": "unsupported-set", "subject": "SHARED"}) == {"vrf:a"}


def test_the_next_hop_a_policy_sets_roots_only_the_contexts_of_its_own_device():
    owners = certainty._policy_owners(_scoped_input(), {"bgp:a": "vrf:a", "bgp:b": "vrf:b"})
    assert owners[("dev:a", "SHARED")] == {"vrf:a"}
    assert ("dev:b", "SHARED") not in owners


def _virtual_system_input():
    """`_scoped_input` with both processes on one gateway, each in a virtual
    system that defines its own `EDGE-IN` (the policy rows state the routing
    context, as Check Point's do)."""
    inp = _scoped_input()
    assert inp.bgp is not None
    for process in inp.bgp.processes:
        process["device_uid"] = "dev:gw"
    for policy in inp.bgp.policies:
        policy["context_uid"] = "vrf:a" if policy["device_uid"] == "dev:a" else "vrf:b"
        policy["device_uid"] = "dev:gw"
    inp.contexts = [
        {"uid": "vrf:a", "device_uid": "dev:gw", "platform": "nxos"},
        {"uid": "vrf:b", "device_uid": "dev:gw", "platform": "nxos"},
    ]
    return inp


def test_a_policy_reaches_the_contexts_of_the_virtual_system_that_calls_it():
    """Two virtual systems of one gateway both attach `EDGE-IN`; each
    policy reaches only the context of the virtual system that defines it,
    not every context of the gateway."""
    deps = _Dependencies(_virtual_system_input())
    assert deps.policy_contexts[("vrf:a", "SHARED")] == {"vrf:a"}
    assert deps.policy_contexts[("vrf:b", "OTHER")] == {"vrf:b"}
    assert ("vrf:b", "SHARED") not in deps.policy_contexts
    assert ("dev:gw", "SHARED") not in deps.policy_contexts
    owners = certainty._policy_owners(_virtual_system_input(), {"bgp:a": "vrf:a", "bgp:b": "vrf:b"})
    assert owners[("vrf:a", "SHARED")] == {"vrf:a"}
    assert ("vrf:b", "SHARED") not in owners


def test_a_policy_reached_outside_its_virtual_system_holds_only_that_process_context():
    """The read names the process that reached a policy defined in another
    context; the error is not a diagnostic, and it holds that process's
    context directly (and what that context feeds)."""
    inp = _virtual_system_input()
    error = _error("policy-context-ambiguous", "bgp:a")
    assert _Dependencies(inp).direct(error) == {"vrf:a"}
    assert "vrf:a" in affected_contexts(inp, [error])
