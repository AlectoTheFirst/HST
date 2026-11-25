"""Provider 1 of the route-delta interface: the operator-declared delta
(src/hst/app/changes_delta.py)."""

from __future__ import annotations

from hst.app.changes_delta import (
    RIB_SHAPING_KINDS,
    STAGE_2_KINDS,
    STAGE_3_KINDS,
    compute_route_delta,
)
from hst.simul.propagate import RouteDelta


def test_static_add_and_declared_rows_predict_exactly_these_rows_and_flag_the_rest():
    intents = [
        {
            "kind": "static_route.add",
            "params": {
                "context_uid": "vrf:r1:default",
                "prefix": "10.0.0.0/24",
                "next_hop": "10.0.0.1",
                "tag": 5,
            },
        },
        {
            "kind": "static_route.remove",
            "params": {"context_uid": "vrf:r1:default", "prefix": "10.1.0.0/24"},
        },
        {
            "kind": "route_delta.declared",
            "params": {
                "rows": [
                    {
                        "context_uid": "vrf:r1:default",
                        "prefix": "10.2.0.0/24",
                        "next_hop": "10.2.0.1",
                        "local_pref": 200,
                        "as_path": [65001, 65002],
                        "communities": ["65001:100"],
                    }
                ]
            },
        },
        {"kind": "device.exclude", "params": {"device_uid": "dev:edge1"}},
    ]

    expected = RouteDelta(
        rib=[
            {
                "context_uid": "vrf:r1:default",
                "prefix": "10.0.0.0/24",
                "next_hop": "10.0.0.1",
                "protocol": "static",
                "metric": None,
                "local_pref": None,
                "med": None,
                "weight": None,
                "as_path": [],
                "origin": None,
                "origin_mechanism": "static",
                "session_protocol": "static",
                "admin": 1,
                "communities": [],
                "originator_ip": None,
                "cluster_list": [],
                "tag": 5,
            },
            {
                "context_uid": "vrf:r1:default",
                "prefix": "10.2.0.0/24",
                "next_hop": "10.2.0.1",
                "protocol": "declared",
                "metric": None,
                "local_pref": 200,
                "med": None,
                "weight": None,
                "as_path": [65001, 65002],
                "origin": None,
                "origin_mechanism": None,
                "session_protocol": None,
                "admin": None,
                "communities": ["65001:100"],
                "originator_ip": None,
                "cluster_list": [],
                "tag": None,
            },
        ],
        model_errors=[
            {
                "kind": "declared-not-simulatable",
                "detail": "provider 1 (the declared route-delta) cannot express intent kind 'device.exclude'",
                "subject": "device.exclude",
            }
        ],
    )

    assert compute_route_delta(intents) == expected


def test_static_route_remove_alone_predicts_an_empty_delta():
    intents = [{"kind": "static_route.remove", "params": {"prefix": "10.1.0.0/24"}}]
    result = compute_route_delta(intents)
    assert result == RouteDelta(rib=[], model_errors=[])


def test_a_static_add_missing_a_required_param_is_a_named_error_not_a_crash():
    intents = [{"kind": "static_route.add", "params": {"prefix": "10.0.0.0/24"}}]  # no context_uid
    result = compute_route_delta(intents)
    assert result.rib == []
    (error,) = result.model_errors
    assert error["kind"] == "declared-missing-param"
    assert "context_uid" in error["detail"]


def test_a_declared_intent_with_no_rows_is_a_named_error():
    intents = [{"kind": "route_delta.declared", "params": {"rows": []}}]
    result = compute_route_delta(intents)
    assert result.rib == []
    (error,) = result.model_errors
    assert error["kind"] == "declared-empty-rows"


def test_a_stage_3_kind_is_reported_as_not_yet_simulatable():
    intents = [{"kind": "bgp_session.shut", "params": {"session_uid": "sess:1"}}]
    result = compute_route_delta(intents)
    assert result.rib == []
    (error,) = result.model_errors
    assert error["kind"] == "declared-not-simulatable"
    assert error["subject"] == "bgp_session.shut"


def test_an_empty_change_predicts_an_empty_delta():
    assert compute_route_delta([]) == RouteDelta(rib=[], model_errors=[])


def test_the_catalog_splits_stage_2_from_stage_3_with_no_overlap():
    assert frozenset() == STAGE_2_KINDS & STAGE_3_KINDS
    assert {
        "device.exclude",
        "static_route.add",
        "static_route.remove",
        "route_delta.declared",
    } == STAGE_2_KINDS


def test_device_exclude_is_stage_2_but_not_rib_shaping():
    """`device.exclude` is a graph-level exclusion, not a route-delta op."""
    assert "device.exclude" not in RIB_SHAPING_KINDS
    assert "device.exclude" in STAGE_2_KINDS
    assert {
        "static_route.add",
        "static_route.remove",
        "route_delta.declared",
    } == RIB_SHAPING_KINDS
