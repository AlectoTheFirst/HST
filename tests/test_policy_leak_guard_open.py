"""The leak guard analysis (`path/leak_guard.py`) when its route reads are not
complete: the device's RIB is not consulted, or a cap cuts the analysis.

The router is the VyOS batch of `tests/support/policy_route_graph.py`
(tests/test_policy_leak_guard.py describes it).
"""

from __future__ import annotations

from typing import Any

import pytest
from tests.support import policy_route_graph as fixture

from hst.path import leak_guard
from hst.path.session import CycleSession
from hst.twin_tools.policy import explanation


class Rib:
    """A side-store RIB reader with the attributes `trace._rib_gap` reads.
    It holds no rows for any table lookup."""

    def __init__(self, coverage: str | None, rows: bool = True, available: bool = True) -> None:
        self._coverage, self._rows, self.available = coverage, rows, available

    def coverage(self, _dev: str) -> str | None:
        return self._coverage

    def has_rows(self, _dev: str) -> bool:
        return self._rows

    def lpm(self, *_args: Any, **_kwargs: Any) -> list[Any]:
        return []

    def overlapping(self, *_args: Any, **_kwargs: Any) -> list[Any]:
        return []


def session(patch=None) -> CycleSession:
    graph = fixture.BatchGraph(fixture.batch(patch))
    return CycleSession(graph, fixture.BatchGraph.cts)


def analyse(patch=None, rib: Rib | None = None) -> dict[str, Any]:
    return leak_guard.leak_guards(
        session(patch), fixture.LAN_WAN, fixture.GUARD, 4, rib=(lambda: rib) if rib else None
    )


def lines(patch=None, rib: Rib | None = None) -> list[str]:
    pinned = session(patch)
    intent = leak_guard.leak_guards(
        pinned, fixture.LAN_WAN, fixture.GUARD, 4, rib=(lambda: rib) if rib else None
    )
    return explanation(leak_guard.rule_facts(pinned, fixture.LAN_WAN, fixture.GUARD, 4), intent)["lines"]


def no_main_default(cfg: dict[str, Any]) -> None:
    # the main table's default route is not configured: DHCP or a routing
    # protocol installs it, so only the RIB holds it
    del cfg["protocols"]["static"]["route"]["0.0.0.0/0"]


def many_main_routes(cfg: dict[str, Any]) -> None:
    # 40 more-specific routes in the main table; the last 9 leave by eth2,
    # a WAN exit rule 10 does not match
    cfg["interfaces"]["ethernet"]["eth2"] = {"address": ["192.0.2.2/24"], "description": "second WAN"}
    cfg["firewall"]["zone"]["WAN"]["member"]["interface"].append("eth2")
    routes = cfg["protocols"]["static"]["route"]
    for i in range(40):
        routes[f"20.0.{i}.0/24"] = {"interface": {("eth0" if i < 31 else "eth2"): {}}}


def codes(record: dict[str, Any]) -> list[str]:
    return [m["code"] for m in record.get("missing") or ()]


# with the RIB not consulted, the policy route table's default route into
# wg44 is graph edges only as well as the main table's routes
BOTH_TABLES = [("rib-not-consulted", "table table144"), ("rib-not-consulted", "table default")]


def reasons(record: dict[str, Any]) -> list[tuple[str, str]]:
    return [(m["code"], m["subject"]) for m in record.get("missing") or ()]


# --- the RIB of the device ------------------------------------------------------------------


@pytest.mark.parametrize("outcome", ["failed", "partial", "missing", "complete-empty", "unknown"])
def test_a_recorded_rib_that_cannot_answer_leaves_a_table_with_no_graph_route_open(outcome):
    found = analyse(no_main_default, Rib(outcome, rows=False))

    assert found["leak_guards"] == []
    (gap,) = found["guard_gaps"]
    assert gap["decided"] is False and reasons(gap) == BOTH_TABLES
    assert gap["tunnel"]["interface"] == "wg44"
    assert gap["exits_not_covered"] == []
    assert gap["detail"]["destinations"] == fixture.NOT_LOCAL
    # the "holds no route" note is replaced by the record
    assert found["notes"] == [] and "missing" not in found
    last = lines(no_main_default, Rib(outcome, rows=False))[-1]
    assert (
        last.startswith("Not decided: ") and "; table default: the RIB of the device is not consulted" in last
    )


def test_a_recorded_rib_that_failed_leaves_the_graph_default_route_guard_open():
    found = analyse(rib=Rib("failed", rows=False))

    (guard,) = found["leak_guards"]
    assert guard["decided"] is False and reasons(guard) == BOTH_TABLES
    assert guard["exits_covered"] == ["eth0"]


def test_a_rib_that_answered_reads_as_no_rib_reader():
    assert analyse(rib=Rib("complete")) == analyse()
    assert analyse(rib=Rib(None)) == analyse()  # approximate mode: rows, nothing recorded
    assert analyse(no_main_default, Rib("complete")) == analyse(no_main_default)


def test_no_rib_reader_keeps_the_no_route_note():
    found = analyse(no_main_default)

    assert found["leak_guards"] == found["guard_gaps"] == []
    assert len(found["notes"]) == 1 and "holds no route for" in found["notes"][0]


def test_no_recorded_rib_and_no_dynamic_routing_keeps_the_graph_answer(monkeypatch):
    # nothing records a RIB for the device: the graph is its whole answer
    monkeypatch.setattr(leak_guard, "_runs_dynamic_routing", lambda _session, _table: False)

    assert analyse(rib=Rib(None, rows=False)) == analyse()
    assert analyse(no_main_default, Rib(None, rows=False)) == analyse(no_main_default)


def test_no_recorded_rib_with_dynamic_routing_leaves_the_default_route_open(monkeypatch):
    monkeypatch.setattr(leak_guard, "_runs_dynamic_routing", lambda _session, _table: True)

    (guard,) = analyse(rib=Rib(None, rows=False))["leak_guards"]
    assert guard["decided"] is False and reasons(guard) == BOTH_TABLES
    (gap,) = analyse(no_main_default, Rib(None, rows=False))["guard_gaps"]
    assert gap["decided"] is False and reasons(gap) == BOTH_TABLES


def test_an_unavailable_side_store_leaves_the_default_route_open():
    (guard,) = analyse(rib=Rib(None, rows=False, available=False))["leak_guards"]

    assert guard["decided"] is False and reasons(guard) == BOTH_TABLES
    assert "side store unavailable" in guard["missing"][0]["detail"]


# --- the caps ----------------------------------------------------------------------------------


def test_routes_past_the_parts_cap_leave_their_destinations_open():
    found = analyse(many_main_routes)

    (guard,) = found["leak_guards"]
    assert guard["decided"] is True and guard["exits_covered"] == ["eth0"]
    (gap,) = found["guard_gaps"]
    assert gap["decided"] is False and codes(gap) == ["routes-not-evaluated"]
    assert gap["detail"]["destinations"] == ["20.0.31.0/24", "20.0.32.0/21", "192.0.2.0/24"]
    assert lines(many_main_routes)[-1].startswith(
        "Not decided: table default: the destinations past the first"
    )


def test_routes_past_the_parts_cap_of_the_policy_route_table_leave_every_record_open():
    def patch(cfg):
        routes = cfg["protocols"]["static"]["table"]["144"]["route"]
        for i in range(40):
            routes[f"20.0.{i}.0/24"] = {"interface": {"wg44": {}}}

    found = analyse(patch)

    assert found["leak_guards"]
    assert all(r["decided"] is False for r in found["leak_guards"] + found["guard_gaps"])
    assert [m["code"] for m in found["missing"]] == ["routes-not-evaluated"]
    assert found["missing"][0]["subject"] == "table table144"


def test_devices_past_the_cap_leave_the_answer_open(monkeypatch):
    monkeypatch.setattr(leak_guard, "MAX_DEVICES", 0)

    found = analyse()

    assert found["leak_guards"] == found["guard_gaps"] == []
    assert [m["code"] for m in found["missing"]] == ["analysis-cut"]


def test_findings_past_the_cap_leave_the_listed_records_open(monkeypatch):
    monkeypatch.setattr(leak_guard, "MAX_FINDINGS", 0)

    found = analyse()

    assert found["leak_guards"] == []
    assert "only the first 0 of 1 leak guards" in found["missing"][0]["detail"]


def test_interfaces_past_the_cap_leave_every_record_open(monkeypatch):
    monkeypatch.setattr(leak_guard, "MAX_INTERFACES", 1)

    found = analyse()

    (guard,) = found["leak_guards"]
    assert guard["decided"] is False and codes(guard) == ["analysis-cut"]
    assert found["missing"] == guard["missing"]
    assert lines()[-1].startswith("Not decided: device ")


def test_a_complete_analysis_has_no_missing_key():
    found = analyse()

    assert set(found) == {"leak_guards", "guard_gaps", "notes"}
    assert found["leak_guards"][0]["decided"] is True


@pytest.mark.parametrize(
    "route",
    [{"interface": {"wg44": {}}}, {"blackhole": {}}],
    ids=["normal-route-into-the-tunnel", "normal-route-discards"],
)
def test_a_failed_rib_leaves_a_normal_route_with_no_exit_to_check_open(route):
    def patch(cfg):
        cfg["protocols"]["static"]["route"]["0.0.0.0/0"] = route

    assert analyse(patch) == {"leak_guards": [], "guard_gaps": [], "notes": []}
    found = analyse(patch, Rib("failed", rows=False))
    (gap,) = found["guard_gaps"]
    assert gap["decided"] is False and reasons(gap) == BOTH_TABLES


def test_a_failed_rib_leaves_a_policy_route_table_with_no_graph_route_open():
    def patch(cfg):
        del cfg["protocols"]["static"]["table"]["144"]["route"]["0.0.0.0/0"]

    assert analyse(patch) == {"leak_guards": [], "guard_gaps": [], "notes": []}
    found = analyse(patch, Rib("failed", rows=False))
    assert found["leak_guards"] == found["guard_gaps"] == []
    assert [(m["code"], m["subject"]) for m in found["missing"]] == [("rib-not-consulted", "table table144")]


def test_notes_past_the_cap_are_counted(monkeypatch):
    def patch(cfg):
        many_main_routes(cfg)
        no_main_default(cfg)

    assert len(analyse(patch)["notes"]) == 2
    monkeypatch.setattr(leak_guard, "MAX_NOTES", 1)
    assert analyse(patch)["notes"] == ["2 more notes are not listed"]


def test_the_explanation_of_a_failed_rib_names_the_tunnel_and_what_is_not_decided():
    found = lines(no_main_default, Rib("failed", rows=False))

    assert found[1] == (
        "These sources are normally policy-routed into wg44 by VPN-PBR rule 30. "
        "Rule 10 applies when that routing does not."
    )
    assert found[2].startswith("Not decided: table table144: the RIB of the device is not consulted")
    assert len(found) == 3


def test_the_explanation_names_a_cut_that_leaves_no_record(monkeypatch):
    complete = lines()
    monkeypatch.setattr(leak_guard, "MAX_DEVICES", 0)

    found = lines()

    assert found[:-1] == complete[:1]
    assert found[-1] == "Not decided: rule 10: only the first 0 of 1 devices of the rulebase are analysed."
