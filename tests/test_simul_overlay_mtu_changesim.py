"""Part B: MTU-aware change simulation."""

from __future__ import annotations

from typing import Any

import pytest

from hst import path as pathmod
from hst.app import fw_overlay_read
from hst.simul.fw_overlay import Catalog, ProposalError, compare_paths, path_rows

# --- fw_overlay.path_rows / compare_paths, over synthetic MtuResult dicts --


def _mtu_result(
    outcome: str, ceiling: int | None, bottleneck_uid: str | None, *, uncovered: tuple[str, ...] = ()
) -> dict[str, Any]:
    """A minimal `hst.core.mtu.MtuResult`, JSON-shaped, naming one
    bottleneck stage on the given subject."""
    stages = (
        [
            {
                "stage_id": "s1",
                "ingress_subject_uid": bottleneck_uid,
                "egress_subject_uid": None,
                "context": {"af": 4, "direction": "rx"},
            }
        ]
        if bottleneck_uid
        else []
    )
    return {
        "outcome": outcome,
        "known_ceiling_bytes": ceiling,
        "bottleneck_stage_ids": ["s1"] if bottleneck_uid else [],
        "coverage": {"uncovered": list(uncovered)},
        "stages": stages,
    }


_LEG = {
    "dst_label": "0.0.0.0/0",
    "cidr": "0.0.0.0/0",
    "egress": "if:eth0",
    "next_hop": "10.0.0.1",
    "table": "vrf:default",
    "firewall": None,
    "fw_uid": None,
    "blocked": False,
}


def test_path_rows_carries_the_mtu_fields_when_the_flow_asked():
    rows = path_rows([_LEG], mtu=_mtu_result("fail", 1500, "if:entry"))
    assert rows[0]["mtu_outcome"] == "fail"
    assert rows[0]["mtu_known_ceiling_bytes"] == 1500
    assert rows[0]["mtu_bottleneck"] == ["if:entry"]
    assert rows[0]["mtu_uncovered"] == []


def test_path_rows_omits_the_mtu_fields_when_the_flow_never_asked():
    rows = path_rows([_LEG])
    assert "mtu_outcome" not in rows[0]
    assert "mtu_bottleneck" not in rows[0]


def test_uncovered_codes_are_carried_through():
    rows = path_rows(
        [_LEG], mtu=_mtu_result("fits_known_limits", 1500, "if:eth0", uncovered=("destination-endpoint",))
    )
    assert rows[0]["mtu_uncovered"] == ["destination-endpoint"]


def test_a_moved_mtu_bottleneck_counts_as_changed_even_with_an_unchanged_firewall_verdict():
    before = path_rows([_LEG], mtu=_mtu_result("fail", 1500, "if:entry"))
    after = path_rows([_LEG], mtu=_mtu_result("fail", 1500, "if:exit"))
    paths = compare_paths(before, after)
    assert paths["changed"] == 1
    group = paths["groups"][0]
    assert group["before"]["blocked"] is False
    assert group["after"]["blocked"] is False
    assert group["changed"] is True
    assert group["mtu_before"] == {
        "outcome": "fail",
        "known_ceiling_bytes": 1500,
        "bottleneck": ["if:entry"],
        "uncovered": [],
    }
    assert group["mtu_after"] == {
        "outcome": "fail",
        "known_ceiling_bytes": 1500,
        "bottleneck": ["if:exit"],
        "uncovered": [],
    }


def test_an_unchanged_mtu_verdict_does_not_by_itself_mark_the_group_changed():
    before = path_rows([_LEG], mtu=_mtu_result("fail", 1500, "if:entry"))
    after = path_rows([_LEG], mtu=_mtu_result("fail", 1500, "if:entry"))
    paths = compare_paths(before, after)
    assert paths["changed"] == 0
    assert paths["groups"][0]["changed"] is False


def test_a_clear_df_reads_as_fragmentation_required_not_fail():
    after = path_rows([_LEG], mtu=_mtu_result("fragmentation_required", 1500, "if:exit"))
    assert after[0]["mtu_outcome"] == "fragmentation_required"
    paired = compare_paths(path_rows([_LEG], mtu=_mtu_result("fail", 1500, "if:entry")), after)
    assert paired["groups"][0]["mtu_after"]["outcome"] == "fragmentation_required"


# --- fw_overlay._mtu_side: folding a proxy-split trace's own `connections` --
#
# A path that crosses a proxy (a NetScaler SNIP/DNAT hop) splits into two
# `connections`, each its own MtuResult.


def _mtu_connections_result(outcome: str, connections: list[dict[str, Any]]) -> dict[str, Any]:
    """The shape `hst.path.mtu`'s own proxy-split combine leaves at the
    top level: `outcome` folded, everything else empty, the per-connection
    detail underneath in `connections`."""
    return {
        "outcome": outcome,
        "known_ceiling_bytes": None,
        "bottleneck_stage_ids": [],
        "coverage": {"uncovered": []},
        "stages": [],
        "connections": connections,
    }


def test_mtu_side_folds_the_minimum_ceiling_both_bottlenecks_and_every_uncovered_code_across_connections():
    first = _mtu_result("fail", 1500, "if:entry", uncovered=("source-endpoint",))
    second = _mtu_result("fits_known_limits", 9000, "if:exit", uncovered=("destination-endpoint",))
    rows = path_rows([_LEG], mtu=_mtu_connections_result("fail", [first, second]))
    assert rows[0]["mtu_outcome"] == "fail"  # the top-level fold, untouched
    assert rows[0]["mtu_known_ceiling_bytes"] == 1500  # the minimum of the two
    assert rows[0]["mtu_bottleneck"] == ["if:entry", "if:exit"]  # both connections' own subjects
    assert rows[0]["mtu_uncovered"] == ["destination-endpoint", "source-endpoint"]  # sorted union


def test_mtu_side_still_reads_the_top_level_when_there_are_no_connections():
    rows = path_rows([_LEG], mtu=_mtu_result("fail", 1500, "if:entry"))
    assert rows[0]["mtu_known_ceiling_bytes"] == 1500
    assert rows[0]["mtu_bottleneck"] == ["if:entry"]
    assert rows[0]["mtu_uncovered"] == []


# --- fw_overlay_read.simulate_change: the flow's mtu request, and mtu_subjects


def _vyos_pair_catalog() -> Catalog:
    """eth0 (physical) and eth0.10 (its vif), the pair
    `tests/test_simul_overlay_mtu.py::vyos_catalog` builds, without the
    observations."""
    return Catalog(
        interfaces={
            "if:eth0": {
                "uid": "if:eth0",
                "vendor": "vyos",
                "platform": "vyos",
                "parent_interface_uid": None,
                "parent_uid": None,
                "configured_tag_depth": None,
                "port_uid": "port:eth0",
                "observations": [],
            },
            "if:eth0.10": {
                "uid": "if:eth0.10",
                "vendor": "vyos",
                "platform": "vyos",
                "parent_interface_uid": None,
                "parent_uid": "if:eth0",
                "configured_tag_depth": 1,
                "port_uid": None,
                "observations": [],
            },
        }
    )


_INTENTS = [
    {"kind": "interface.set_mtu", "params": {"interface": "if:eth0.10", "mtu": 9000}},
    {"kind": "interface.set_mtu", "params": {"interface": "if:eth0", "mtu": 9000}},
]


def _install_fake_trace(monkeypatch, before_mtu, after_mtu):
    """A `pathmod.trace` fake that records every `mtu` kwarg it received."""
    calls: list[dict[str, Any]] = []

    def trace(
        session: Any,
        src: str,
        dst: str,
        port: Any = None,
        proto: str = "tcp",
        rib: Any = None,
        mtu: Any = None,
        gateways: Any = None,
    ) -> dict[str, Any]:
        overlaid = isinstance(session, fw_overlay_read.OverlaySession)
        calls.append({"overlaid": overlaid, "mtu": mtu})
        return {
            "verdict": f"{src} -> {dst}",
            "indeterminate": False,
            "warnings": [],
            "legs": [dict(_LEG)],
            "mtu": after_mtu if overlaid else before_mtu,
        }

    monkeypatch.setattr(pathmod, "trace", trace)
    return calls


def _install_catalog(monkeypatch, catalog: Catalog) -> None:
    monkeypatch.setattr(
        fw_overlay_read, "read_catalog", lambda session, intents=(), source_kinds=None: catalog
    )
    monkeypatch.setattr(pathmod, "load_gateways", lambda session: [])


_FLOW = {
    "src": "10.0.0.5",
    "dst": "0.0.0.0/0",
    "mtu": {"mode": "packet", "ip_packet_bytes": 9000, "ipv4_df": True},
}


def test_simulate_change_threads_the_flows_own_mtu_request_into_the_tracer(monkeypatch):
    _install_catalog(monkeypatch, _vyos_pair_catalog())
    calls = _install_fake_trace(
        monkeypatch,
        _mtu_result("fail", 1500, "if:eth0.10"),
        _mtu_result("fail", 1500, "if:eth0.10"),
    )
    fw_overlay_read.simulate_change(object(), intents=_INTENTS, flows=[_FLOW])
    assert len(calls) == 2
    for call in calls:
        assert call["mtu"] is not None
        assert call["mtu"].mode == "packet"
        assert call["mtu"].ip_packet_bytes == 9000
        assert call["mtu"].ipv4_df is True


def test_simulate_change_lists_both_raised_interfaces_and_the_port_under_mtu_subjects(monkeypatch):
    _install_catalog(monkeypatch, _vyos_pair_catalog())
    _install_fake_trace(
        monkeypatch, _mtu_result("fail", 1500, "if:eth0.10"), _mtu_result("fail", 1500, "if:eth0.10")
    )
    body = fw_overlay_read.simulate_change(object(), intents=_INTENTS, flows=[_FLOW])
    assert body["mtu_subjects"] == ["if:eth0", "if:eth0.10", "port:eth0"]


def test_mtu_subjects_is_empty_for_a_change_set_with_no_mtu_intent(monkeypatch):
    monkeypatch.setattr(
        fw_overlay_read,
        "read_catalog",
        lambda session, intents=(), source_kinds=None: Catalog(interfaces={"if:eth0": {"uid": "if:eth0"}}),
    )
    monkeypatch.setattr(pathmod, "_read", lambda session, query, **params: [])
    calls = []

    def trace(session, src, dst, port=None, proto="tcp", rib=None, mtu=None, gateways=None):
        calls.append(mtu)
        return {"verdict": "x", "indeterminate": False, "warnings": [], "legs": []}

    monkeypatch.setattr(pathmod, "trace", trace)
    body = fw_overlay_read.simulate_change(
        object(),
        intents=[
            {"kind": "fw_rule.add", "params": {"rulebase": "fw:LAN", "action": "accept", "position": 0}}
        ],
        flows=[{"src": "10.0.0.5", "dst": "10.0.0.6"}],
    )
    assert body["mtu_subjects"] == []
    # a flow with no mtu adds no kwarg to the before or the after trace
    assert calls == [None, None]


def test_simulate_change_over_the_vyos_pair_moves_the_9000_byte_failure_from_entry_to_exit(monkeypatch):
    """`if:eth0.10` (the entry the before-trace fails at) and its parent
    `if:eth0` are both raised to 9000 in the same change set."""
    _install_catalog(monkeypatch, _vyos_pair_catalog())
    _install_fake_trace(
        monkeypatch,
        _mtu_result("fail", 1500, "if:eth0.10"),
        _mtu_result("fail", 1500, "if:downstream"),
    )
    body = fw_overlay_read.simulate_change(object(), intents=_INTENTS, flows=[_FLOW])

    assert body["mtu_subjects"] == ["if:eth0", "if:eth0.10", "port:eth0"]
    flow = body["flows"][0]
    group = flow["paths"]["groups"][0]
    assert group["changed"] is True
    assert group["mtu_before"]["outcome"] == "fail"
    assert group["mtu_before"]["bottleneck"] == ["if:eth0.10"]
    assert group["mtu_after"]["outcome"] == "fail"
    assert group["mtu_after"]["bottleneck"] == ["if:downstream"]


def test_with_df_clear_the_after_side_is_fragmentation_required(monkeypatch):
    _install_catalog(monkeypatch, _vyos_pair_catalog())
    _install_fake_trace(
        monkeypatch,
        _mtu_result("fail", 1500, "if:eth0.10"),
        _mtu_result("fragmentation_required", 1500, "if:downstream"),
    )
    flow = dict(_FLOW, mtu={"mode": "packet", "ip_packet_bytes": 9000, "ipv4_df": False})
    body = fw_overlay_read.simulate_change(object(), intents=_INTENTS, flows=[flow])

    group = body["flows"][0]["paths"]["groups"][0]
    assert group["mtu_after"]["outcome"] == "fragmentation_required"
    assert group["changed"] is True


def test_a_malformed_flow_mtu_request_is_refused_as_a_proposal_error(monkeypatch):
    """The same validation `GET /api/path` applies
    (`hst.core.mtu.MtuRequest`): a size mode with no packet bytes is refused."""
    _install_catalog(monkeypatch, Catalog())
    with pytest.raises(ProposalError, match=r"10\.0\.0\.5"):
        fw_overlay_read.simulate_change(
            object(),
            intents=[],
            flows=[{"src": "10.0.0.5", "dst": "10.0.0.6", "mtu": {"mode": "packet"}}],
        )
