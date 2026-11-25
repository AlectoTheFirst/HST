"""BGP configuration becomes a route only when its main-RIB condition holds."""

from hst.simul import rib
from hst.simul.errors import ErrorSink
from hst.simul.propagate import SimulationInput
from hst.simul.route import Route

CTX = "vrf:edge:default"
PROC = "bgp:edge:default"


def _input(local_routes, *, connected=(), static=(), process=None):
    process = process or {
        "uid": PROC,
        "context_uid": CTX,
        "proto": "bgp",
        "asn": 65000,
        "router_id": "192.0.2.1",
    }
    return rib.RibInput(
        contexts=[{"uid": CTX, "device_uid": "device:edge", "platform": "iosxe"}],
        connected=list(connected),
        static=list(static),
        bgp=SimulationInput(processes=[process], local_routes=local_routes, platform="iosxe"),
    )


def _bgp_prefixes(result):
    assert result.bgp is not None
    return {row["prefix"] for row in result.bgp.rib if row["context_uid"] == CTX}


def test_network_statement_requires_an_exact_non_bgp_main_rib_route():
    intent = [{"process_uid": PROC, "prefix": "10.0.0.0/24", "origin_mechanism": "network", "intent": True}]

    absent = rib.compute(
        _input(intent, connected=[{"context_uid": CTX, "prefix": "10.0.0.0/25", "interface": "Gi1"}]),
        validate_observed=False,
    )
    present = rib.compute(
        _input(intent, connected=[{"context_uid": CTX, "prefix": "10.0.0.0/24", "interface": "Gi1"}]),
        validate_observed=False,
    )

    assert "10.0.0.0/24" not in _bgp_prefixes(absent)
    assert "10.0.0.0/24" in _bgp_prefixes(present)


def test_recorded_disabled_network_import_check_originates_without_main_rib_route():
    process = {
        "uid": PROC,
        "context_uid": CTX,
        "proto": "bgp",
        "asn": 65000,
        "router_id": "192.0.2.1",
        "platform": "vyos-traditional",
        "network_import_check": False,
    }
    intent = [{"process_uid": PROC, "prefix": "10.0.0.0/24", "origin_mechanism": "network", "intent": True}]

    result = rib.compute(_input(intent, process=process), validate_observed=False)

    assert "10.0.0.0/24" in _bgp_prefixes(result)


def test_aggregate_requires_a_more_specific_bgp_contributor():
    routes = [
        {"process_uid": PROC, "prefix": "10.1.0.0/24"},
        {"process_uid": PROC, "prefix": "10.0.0.0/8", "origin_mechanism": "aggregate", "intent": True},
    ]

    result = rib.compute(
        _input(
            routes,
            static=[
                {
                    "context_uid": CTX,
                    "prefix": "10.1.0.0/24",
                    "discard": "null",
                    "admin": 1,
                }
            ],
        ),
        validate_observed=False,
    )

    assert _bgp_prefixes(result) == {"10.0.0.0/8", "10.1.0.0/24"}
    installed = next(row for row in result.rib if row["prefix"] == "10.1.0.0/24")
    assert installed["protocol"] == "static"


def test_network_intent_cannot_sustain_itself_from_a_prior_bgp_candidate():
    intent = {
        "process_uid": PROC,
        "prefix": "10.0.0.0/24",
        "origin_mechanism": "network",
        "intent": True,
    }
    calculation = rib._Run(_input([intent]), ErrorSink())
    prior = rib.Table()
    prior.set(
        CTX,
        "10.0.0.0/24",
        [
            rib.Installed(
                rib.Candidate(
                    CTX,
                    "10.0.0.0/24",
                    rib.BGP,
                    20,
                    0,
                    route=Route(
                        prefix="10.0.0.0/24",
                        protocol="bgp",
                        origin_mechanism="network",
                    ),
                ),
                0,
            )
        ],
    )

    assert calculation.local_originations(prior, None) == []


def test_unsupported_aggregate_attributes_are_uncertain_and_fail_closed():
    routes = [
        {"process_uid": PROC, "prefix": "10.1.0.0/24"},
        {
            "process_uid": PROC,
            "prefix": "10.0.0.0/8",
            "origin_mechanism": "aggregate",
            "intent": True,
            "as_set": True,
        },
    ]

    result = rib.compute(_input(routes), validate_observed=False)

    assert _bgp_prefixes(result) == {"10.1.0.0/24"}
    assert any("unsupported attributes as_set" in gap["detail"] for gap in result.gaps)


def test_summary_only_aggregate_originates_and_keeps_its_contributor_in_the_table():
    # summary-only changes what is advertised (propagate), not whether the
    # aggregate exists: with a contributor present, both are in the table.
    routes = [
        {"process_uid": PROC, "prefix": "10.1.0.0/24"},
        {
            "process_uid": PROC,
            "prefix": "10.0.0.0/8",
            "origin_mechanism": "aggregate",
            "intent": True,
            "summary_only": True,
        },
    ]

    result = rib.compute(_input(routes), validate_observed=False)

    assert _bgp_prefixes(result) == {"10.0.0.0/8", "10.1.0.0/24"}
    assert not any("10.0.0.0/8" in gap.get("detail", "") for gap in result.gaps)


def test_process_redistribution_is_computed_from_the_main_rib():
    process = {
        "uid": PROC,
        "context_uid": CTX,
        "proto": "bgp",
        "asn": 65000,
        "router_id": "192.0.2.1",
        "redistribute_protocols": ["connected"],
    }

    result = rib.compute(
        _input(
            [],
            process=process,
            connected=[{"context_uid": CTX, "prefix": "10.2.0.0/24", "interface": "Gi1"}],
        ),
        validate_observed=False,
    )

    assert "10.2.0.0/24" in _bgp_prefixes(result)


def _aggregate_with_map(route_map):
    return [
        {"process_uid": PROC, "prefix": "10.1.0.0/24"},
        {
            "process_uid": PROC,
            "prefix": "10.0.0.0/8",
            "origin_mechanism": "aggregate",
            "intent": True,
            "attribute_map": route_map,
            "route_map": route_map,
        },
    ]


def test_aggregate_attribute_map_shapes_the_originated_route():
    policy = {
        "name": "RM_AGG",
        "kind": "route-map",
        "entries": [
            {
                "seq": 10,
                "kind": "clause",
                "action": "permit",
                "set_as_path_prepend": [65000, 65000],
                "set_local_pref": 150,
                "set_communities": ["65000:100"],
            }
        ],
    }
    inp = _input(_aggregate_with_map("RM_AGG"))
    inp.bgp.policies = [policy]

    result = rib.compute(inp, validate_observed=False)

    assert _bgp_prefixes(result) == {"10.0.0.0/8", "10.1.0.0/24"}
    aggregate = next(row for row in result.bgp.rib if row["prefix"] == "10.0.0.0/8")
    assert aggregate["as_path"] == [65000, 65000]
    assert aggregate["local_pref"] == 150
    assert "65000:100" in aggregate["communities"]
    assert not any("10.0.0.0/8" in gap.get("detail", "") for gap in result.gaps)


def test_aggregate_attribute_map_deny_is_uncertain_not_silent():
    policy = {
        "name": "RM_AGG",
        "kind": "route-map",
        "entries": [{"seq": 10, "kind": "clause", "action": "deny"}],
    }
    inp = _input(_aggregate_with_map("RM_AGG"))
    inp.bgp.policies = [policy]

    result = rib.compute(inp, validate_observed=False)

    assert _bgp_prefixes(result) == {"10.1.0.0/24"}
    assert any("attribute-map 'RM_AGG' denied the route" in gap["detail"] for gap in result.gaps)


def test_aggregate_undefined_attribute_map_follows_the_platform_rule():
    # IOS-XE: an undefined redistribution route-map means the redistribution
    # does not occur (platforms.redistribute_undefined_permits); the aggregate
    # is not originated and the reference is reported, not dropped silently.
    result = rib.compute(_input(_aggregate_with_map("RM_GHOST")), validate_observed=False)

    assert _bgp_prefixes(result) == {"10.1.0.0/24"}
    assert "undefined-redistribute-route-map" in [error["kind"] for error in result.model_errors]
