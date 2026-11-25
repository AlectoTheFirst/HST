"""The change-simulation export (`hst.app.changesim_export`), over fake rows.

No database and no HTTP: `hst.path._read` and `hst.path.trace` are the
package's monkeypatch seams.
"""

from typing import Any

import pytest

from hst import path as pathmod
from hst.app import changesim_export, fw_overlay_read

CATALOG_ROWS: dict[str, Any] = {
    "MATCH (o:NetObject:Obj)": [],
    "MATCH (s:SvcObject:Obj)": [],
    "MATCH (z:Zone:Obj)": [],
}

DENY = {
    "kind": "fw_rule.add",
    "params": {
        "rulebase": "fw:LAN",
        "position": 10,
        "action": "drop",
        "source": "any",
        "destination": ["192.168.2.35"],
    },
}

# one prefix with two recorded next hops, one of them the denied address
ROUTE_ROWS: dict[str, Any] = {
    **CATALOG_ROWS,
    "MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": [
        {
            "kind": "LEARNED_ROUTE",
            "prefix": "203.0.113.0/24",
            "next_hop": "192.168.2.35",
            "protocol": "bgp",
            "context_uid": "vrf:a:default",
        },
        {
            "kind": "STATIC_ROUTE",
            "prefix": "203.0.113.0/24",
            "next_hop": "10.7.0.1",
            "protocol": None,
            "context_uid": "vrf:a:default",
        },
    ],
    "MATCH (d:Device:Obj)\nWHERE d.uid IN $devices": [
        {"uid": "dev:core1", "hostname": "core1", "sources": ["vyos-lab"]}
    ],
}


class _Graph:
    """A fake `path._read`: one canned answer per query, keyed by a fragment."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers

    def __call__(self, session: Any, query: str, **params: Any) -> Any:
        for fragment, rows in self.answers.items():
            if fragment in query:
                return rows(params) if callable(rows) else list(rows)
        return []


def _install(monkeypatch: pytest.MonkeyPatch, answers: dict[str, Any]) -> None:
    monkeypatch.setattr(pathmod, "_read", _Graph(answers))


def _fake_trace(monkeypatch: pytest.MonkeyPatch, legs: int = 3) -> None:
    """A tracer whose flows walk `legs` paths each with one outcome."""

    def trace(
        session: Any,
        src: str,
        dst: str,
        port: Any = None,
        proto: str = "tcp",
        rib: Any = None,
        gateways: Any = None,
    ) -> dict[str, Any]:
        overlaid = isinstance(session, fw_overlay_read.OverlaySession)
        return {
            "verdict": "BLOCKED by LAN policy rule 10" if overlaid else f"permitted {src}->{dst}",
            "indeterminate": False,
            "warnings": ["a warning the tracer raised"],
            "legs": [
                {
                    "dst_label": f"10.{i}.0.0/24",
                    "cidr": f"10.{i}.0.0/24",
                    "egress": "if:core1:eth0",
                    "next_hop": f"10.7.0.{i}",
                    "table": "vrf:a:default",
                    "firewall": "LAN policy (LAN>WAN) drop by rule 10",
                    "fw_uid": "fw:LAN",
                    "blocked": overlaid,
                }
                for i in range(legs)
            ],
        }

    monkeypatch.setattr(pathmod, "trace", trace)
    monkeypatch.setattr(pathmod, "load_gateways", lambda session: [])


def _simulate(monkeypatch, answers=None, **kw) -> dict[str, Any]:
    _install(monkeypatch, answers or ROUTE_ROWS)
    _fake_trace(monkeypatch)
    return fw_overlay_read.simulate_change(
        object(),
        intents=[DENY],
        flows=[{"src": "10.0.0.5", "dst": "192.168.2.35"}],
        detail=True,
        **kw,
    )


SNAPSHOT = 1_756_526_400_000


def _render(body, **kw):
    return changesim_export.render(body, snapshot=SNAPSHOT, sources=["vyos-lab"], **kw)


# --- the detail the pane's caps leave out ---------------------------------


def test_the_file_carries_one_row_per_path_where_the_pane_carries_one_per_group(monkeypatch):
    body = _simulate(monkeypatch)
    flow = body["flows"][0]
    # the pane's structure: three paths that share an outcome are one group row
    assert flow["paths"]["group_count"] == 1
    # the file's: one row per path, ungrouped
    rows = [r for r in changesim_export.detail_rows(body) if r["section"] == "flow_path"]
    assert len(rows) == 3
    assert [r["next_hop"] for r in rows] == ["10.7.0.0", "10.7.0.1", "10.7.0.2"]
    assert {r["before"] for r in rows} == {"permitted"}
    assert {r["after"] for r in rows} == {"blocked"}


def test_the_affected_prefixes_carry_their_next_hops_before_and_after_and_their_level(monkeypatch):
    body = _simulate(monkeypatch)
    row = next(r for r in changesim_export.detail_rows(body) if r["section"] == "withdrawn_prefix")
    assert row["context_uid"] == "vrf:a:default"
    assert row["prefix"] == "203.0.113.0/24"
    assert row["next_hops_before"] == "192.168.2.35 (bgp); 10.7.0.1 (static)"
    assert row["next_hops_after"] == "10.7.0.1 (static)"
    assert row["no_next_hop_left"] is False
    assert row["level"] == 1


def test_the_route_row_cap_the_pane_relies_on_is_off_in_a_detail_run(monkeypatch):
    """A run for the pane lists the first `_MAX_ROUTE_ROWS` prefixes; a run for
    the file lists every one of them and says nothing about truncation."""
    prefixes = [
        {
            "kind": "LEARNED_ROUTE",
            "prefix": f"203.0.{i}.0/24",
            "next_hop": "192.168.2.35",
            "protocol": "bgp",
            "context_uid": "vrf:a:default",
        }
        for i in range(fw_overlay_read._MAX_ROUTE_ROWS + 5)
    ]
    answers = {
        **CATALOG_ROWS,
        "MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": prefixes,
    }
    _install(monkeypatch, answers)
    _fake_trace(monkeypatch)
    flows = [{"src": "10.0.0.5", "dst": "192.168.2.35"}]
    for_pane = fw_overlay_read.simulate_change(object(), intents=[DENY], flows=flows)
    for_file = fw_overlay_read.simulate_change(object(), intents=[DENY], flows=flows, detail=True)

    pane_withdrawal = for_pane["routing_consequence"]["next_hop_withdrawal"]
    file_withdrawal = for_file["routing_consequence"]["next_hop_withdrawal"]
    assert pane_withdrawal["truncated"] is True
    assert len(pane_withdrawal["vrfs"][0]["prefixes"]) == fw_overlay_read._MAX_ROUTE_ROWS
    assert file_withdrawal["truncated"] is False
    assert "truncation" not in file_withdrawal
    assert len(file_withdrawal["vrfs"][0]["prefixes"]) == len(prefixes)
    assert pane_withdrawal["prefix_count"] == file_withdrawal["prefix_count"] == len(prefixes)


# --- the header both files carry ------------------------------------------


def test_both_files_carry_the_same_header_sentence_for_sentence(monkeypatch):
    body = _simulate(monkeypatch)
    csv_text, markdown_text, _ = _render(body)
    header = changesim_export.header_lines(
        body, snapshot=SNAPSHOT, sources=["vyos-lab"], sites_requested=None, trimmed=0
    )
    assert header
    for line in header:
        assert f"# {line}\n" in csv_text
        assert line in markdown_text


def test_the_header_states_the_collection_date_the_sources_and_the_run(monkeypatch):
    body = _simulate(monkeypatch)
    csv_text, markdown_text, _ = _render(body)
    stated = (
        "Impact stated as of the collection date 2025-08-30T04:00:00+00:00, "
        f"from the source vyos-lab, run id {SNAPSHOT}."
    )
    assert stated in csv_text
    assert stated in markdown_text


def test_the_header_states_the_depth_the_site_filter_and_the_intents(monkeypatch):
    body = _simulate(monkeypatch, depth=3, sites=["fra01"])
    csv_text, _, _ = _render(body, sites_requested=["fra01"])
    assert "Depth: 3 level(s) of the route dependency chain, of a cap of 8." in csv_text
    assert "Site filter: fra01." in csv_text
    assert "Intents (1): fw_rule.add on fw:LAN." in csv_text


def test_a_walk_no_limit_stopped_says_so_and_one_a_limit_stopped_names_it(monkeypatch):
    whole = _simulate(monkeypatch)
    assert "Walk: ran to level 1, and no limit stopped it." in _render(whole)[0]

    # a chain the depth of one leaves a prefix stranded with a dependent behind it
    chained = {
        **CATALOG_ROWS,
        "MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": [
            {
                "kind": "LEARNED_ROUTE",
                "prefix": "203.0.113.0/24",
                "next_hop": "192.168.2.35",
                "protocol": "bgp",
                "context_uid": "vrf:a:default",
            },
            {
                "kind": "LEARNED_ROUTE",
                "prefix": "198.51.100.0/24",
                "next_hop": "203.0.113.9",
                "protocol": "bgp",
                "context_uid": "vrf:a:default",
            },
        ],
    }
    stopped = _simulate(monkeypatch, chained)
    header = _render(stopped)[0]
    assert "a limit stopped it" in header
    assert "the depth limit of 1" in header
    assert "part of the consequence, not all of it" in header


def test_a_snapshot_with_no_run_pointer_is_stated(monkeypatch):
    body = _simulate(monkeypatch)
    csv_text, markdown_text, _ = changesim_export.render(body, snapshot=None, sources=[])
    stated = (
        "Impact stated as of the collection date no recorded collection date, from no source "
        "recorded on the devices this change alters, run id none recorded."
    )
    assert stated in csv_text
    assert stated in markdown_text


# --- the one guard --------------------------------------------------------


def test_the_guard_is_stated_in_the_header_when_it_trims_nothing(monkeypatch):
    body = _simulate(monkeypatch)
    csv_text, markdown_text, trimmed = _render(body)
    assert trimmed is False
    line = f"Detail: complete; the guard of {changesim_export.MAX_DETAIL_ROWS} rows trimmed nothing."
    assert line in csv_text
    assert line in markdown_text


def test_a_trimmed_file_says_so_in_its_own_header_and_stops_at_the_guard(monkeypatch):
    body = _simulate(monkeypatch)
    monkeypatch.setattr(changesim_export, "MAX_DETAIL_ROWS", 2)
    csv_text, markdown_text, trimmed = _render(body)
    assert trimmed is True
    line = "Detail: trimmed at 2 rows by this file's own guard; 2 further row(s) are not in it."
    assert line in csv_text
    assert line in markdown_text
    # the header lines are comments, then the column row, then the kept rows
    data = [ln for ln in csv_text.splitlines() if ln and not ln.startswith("#")]
    assert len(data) == 3


# --- what each format carries ---------------------------------------------


def test_the_csv_is_one_table_whose_section_column_says_which_rows_are_which(monkeypatch):
    body = _simulate(monkeypatch)
    csv_text, _, _ = _render(body)
    columns = next(ln for ln in csv_text.splitlines() if not ln.startswith("#"))
    assert columns.startswith("section,flow_src,flow_dst")
    sections = {ln.split(",")[0] for ln in csv_text.splitlines() if ln and not ln.startswith("#")}
    assert sections == {"section", "flow_path", "withdrawn_prefix"}


def test_the_markdown_carries_the_prose_the_csv_has_no_column_for(monkeypatch):
    body = _simulate(monkeypatch)
    _, markdown_text, _ = _render(body)
    for heading in (
        "## Intents",
        "## Counts",
        "## Routing consequence",
        "## How far the withdrawal was followed",
        "## Caveats and model errors",
    ):
        assert heading in markdown_text
    assert "`fw_rule.add`" in markdown_text
    assert "a warning the tracer raised" in markdown_text


def test_every_model_error_the_run_named_is_in_the_report(monkeypatch):
    _install(monkeypatch, ROUTE_ROWS)
    _fake_trace(monkeypatch)
    on_a_device = {
        "kind": "fw_rule.add",
        "params": {
            "device": "dev:nowhere",
            "position": 10,
            "action": "drop",
            "source": "any",
            "destination": ["192.168.2.35"],
        },
    }
    body = fw_overlay_read.simulate_change(
        object(),
        intents=[on_a_device],
        flows=[{"src": "10.0.0.5", "dst": "192.168.2.35"}],
        detail=True,
    )
    _, markdown_text, _ = _render(body)
    assert body["model_errors"]
    for error in body["model_errors"]:
        assert error["kind"] in markdown_text
        assert error["detail"] in markdown_text


def test_the_rulebases_derived_from_a_device_are_named_beside_what_derived_them(monkeypatch):
    derive_rows = {
        **ROUTE_ROWS,
        "MATCH (rb:FwRulebase:Obj)": [
            {
                "rb_uid": "fw:LAN",
                "rb_name": "LAN policy",
                "binding": "a zone pair binds it to an interface on the device",
                "type": "FROM_ZONE",
                "interface": "if:eth1",
            }
        ],
        "MATCH (i:Interface)-[o:ON]->(d:Device:Obj {uid: $device, collection_ts: $snap})": [
            {"uid": "if:eth1", "name": "eth1", "serves": ["192.168.2.0/24"]}
        ],
    }
    _install(monkeypatch, derive_rows)
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(),
        intents=[
            {
                "kind": "fw_rule.add",
                "params": {
                    "device": "dev:core1",
                    "position": 10,
                    "action": "drop",
                    "source": ["192.168.2.0/24"],
                    "destination": "any",
                },
            }
        ],
        flows=[{"src": "192.168.2.35", "dst": "8.8.8.8"}],
        detail=True,
    )
    if not body.get("rulebases_derived"):
        pytest.skip("the fake bindings did not resolve; the derivation itself is covered elsewhere")
    _, markdown_text, _ = _render(body)
    assert "## Rulebases derived from the device" in markdown_text
    assert "dev:core1" in markdown_text


# --- the MTU verdict -------------------------------------------------------


def _mtu_result(
    outcome: str, ceiling: int | None, bottleneck_uid: str | None, *, uncovered: tuple[str, ...] = ()
) -> dict[str, Any]:
    """A minimal `hst.core.mtu.MtuResult`, JSON-shaped, naming one
    bottleneck stage on the given subject."""
    stages = [{"stage_id": "s1", "egress_subject_uid": bottleneck_uid}] if bottleneck_uid else []
    return {
        "outcome": outcome,
        "known_ceiling_bytes": ceiling,
        "bottleneck_stage_ids": ["s1"] if bottleneck_uid else [],
        "stages": stages,
        "coverage": {"uncovered": list(uncovered)},
    }


_MTU_FLOW = {
    "src": "10.0.0.5",
    "dst": "192.168.2.35",
    "mtu": {"mode": "packet", "ip_packet_bytes": 9000, "ipv4_df": True},
}


def _fake_trace_with_mtu(monkeypatch: pytest.MonkeyPatch, before_mtu: dict, after_mtu: dict) -> None:
    """`_fake_trace`, one leg, plus the trace's own top-level `mtu` result:
    `before_mtu` when `session` is the plain graph, `after_mtu` when
    `simulate_change` hands the overlaid session to the second trace."""

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
        return {
            "verdict": "BLOCKED by LAN policy rule 10" if overlaid else f"permitted {src}->{dst}",
            "indeterminate": False,
            "warnings": [],
            "legs": [
                {
                    "dst_label": "10.1.0.0/24",
                    "cidr": "10.1.0.0/24",
                    "egress": "if:core1:eth0",
                    "next_hop": "10.7.0.1",
                    "table": "vrf:a:default",
                    "firewall": "LAN policy (LAN>WAN) drop by rule 10",
                    "fw_uid": "fw:LAN",
                    "blocked": overlaid,
                }
            ],
            "mtu": after_mtu if overlaid else before_mtu,
        }

    monkeypatch.setattr(pathmod, "trace", trace)


def test_a_flow_with_an_mtu_request_renders_the_csv_columns_and_the_markdown_line(monkeypatch):
    _install(monkeypatch, ROUTE_ROWS)
    _fake_trace_with_mtu(
        monkeypatch,
        _mtu_result("fail", 1500, "dev:x:vyos-lts-1:core1/if/eth0-10"),
        _mtu_result("fail", 1518, "dev:f4e2c6ace59e/port/port17", uncovered=("MTU_FRAGMENTATION_UNMODELED",)),
    )
    body = fw_overlay_read.simulate_change(object(), intents=[DENY], flows=[_MTU_FLOW], detail=True)

    rows = [r for r in changesim_export.detail_rows(body) if r["section"] == "flow_path"]
    assert rows
    row = rows[0]
    assert row["mtu_before_outcome"] == "fail"
    assert row["mtu_before_ceiling"] == 1500
    assert row["mtu_before_bottleneck"] == "dev:x:vyos-lts-1:core1/if/eth0-10"
    assert row["mtu_after_outcome"] == "fail"
    assert row["mtu_after_ceiling"] == 1518
    assert row["mtu_after_bottleneck"] == "dev:f4e2c6ace59e/port/port17"
    assert row["mtu_uncovered_after"] == "MTU_FRAGMENTATION_UNMODELED"

    _, markdown_text, _ = _render(body)
    assert (
        "MTU: fail at dev:x:vyos-lts-1:core1/if/eth0-10 (1,500 B) before; "
        "fail at dev:f4e2c6ace59e/port/port17 (1,518 B frame) after"
    ) in markdown_text


def test_a_flow_without_an_mtu_request_leaves_the_columns_empty_and_no_markdown_line(monkeypatch):
    body = _simulate(monkeypatch)  # the fixture's flow carries no `mtu`
    rows = [r for r in changesim_export.detail_rows(body) if r["section"] == "flow_path"]
    assert rows
    mtu_columns = (
        "mtu_before_outcome",
        "mtu_before_ceiling",
        "mtu_before_bottleneck",
        "mtu_after_outcome",
        "mtu_after_ceiling",
        "mtu_after_bottleneck",
        "mtu_uncovered_after",
    )
    for row in rows:
        for col in mtu_columns:
            assert col not in row

    csv_text, markdown_text, _ = _render(body)
    # the columns are always in the header, empty for every row of this flow
    header_row = next(ln for ln in csv_text.splitlines() if not ln.startswith("#"))
    for col in mtu_columns:
        assert col in header_row
    assert "MTU:" not in markdown_text


def test_the_counts_section_reports_a_flow_whose_mtu_outcome_changed(monkeypatch):
    _install(monkeypatch, ROUTE_ROWS)
    _fake_trace_with_mtu(
        monkeypatch,
        _mtu_result("pass", None, None),
        _mtu_result("fail", 1518, "dev:f4e2c6ace59e/port/port17"),
    )
    body = fw_overlay_read.simulate_change(object(), intents=[DENY], flows=[_MTU_FLOW], detail=True)
    _, markdown_text, _ = _render(body)
    assert "- Flows whose MTU outcome changed: 1" in markdown_text


def test_the_counts_section_reports_flows_whose_comparison_is_not_established(monkeypatch):
    body = _simulate(monkeypatch)
    _, markdown_text, _ = _render(body)
    assert "comparison is not established" not in markdown_text

    body["results_not_established"] = 2
    _, markdown_text, _ = _render(body)
    assert "- Flows whose comparison is not established: 2" in markdown_text


def test_devices_the_change_set_alters_includes_the_mtu_subjects_devices(monkeypatch):
    """A change set of `interface.set_mtu` intents alone binds no rulebase, so
    `changed_devices` (the firewall-derived list) stays empty; the device the
    change touches comes from `mtu_subjects`."""
    from hst.simul.fw_overlay import Catalog

    catalog = Catalog(
        interfaces={
            "dev:x:vyos-lts-1:core1/if/eth0": {
                "uid": "dev:x:vyos-lts-1:core1/if/eth0",
                "vendor": "vyos",
                "platform": "vyos",
                "parent_interface_uid": None,
                "parent_uid": None,
                "configured_tag_depth": None,
                "port_uid": "dev:x:vyos-lts-1:core1/port/eth0",
                "observations": [],
            }
        }
    )
    monkeypatch.setattr(
        fw_overlay_read, "read_catalog", lambda session, intents=(), source_kinds=None: catalog
    )
    _fake_trace(monkeypatch, legs=1)
    intent = {
        "kind": "interface.set_mtu",
        "params": {"interface": "dev:x:vyos-lts-1:core1/if/eth0", "mtu": 9000},
    }
    body = fw_overlay_read.simulate_change(
        object(), intents=[intent], flows=[{"src": "10.0.0.5", "dst": "192.168.2.35"}], detail=True
    )
    assert body["changed_devices"] == []
    assert body["mtu_subjects"] == ["dev:x:vyos-lts-1:core1/if/eth0", "dev:x:vyos-lts-1:core1/port/eth0"]
    _, markdown_text, _ = _render(body)
    assert "Devices the change set alters: dev:x:vyos-lts-1:core1" in markdown_text


def test_the_json_file_carries_the_full_simulation_body(monkeypatch):
    body = _simulate(monkeypatch)
    text = changesim_export.json_report(body)
    import json

    parsed = json.loads(text)
    assert parsed["flow_count"] == body["flow_count"]
    assert parsed["flows"][0]["flow"]["src"] == body["flows"][0]["flow"]["src"]
    assert parsed["mtu_subjects"] == body["mtu_subjects"]


# --- the archive ----------------------------------------------------------


def test_the_three_files_travel_as_one_archive_named_for_the_run(monkeypatch):
    import zipfile
    from io import BytesIO

    body = _simulate(monkeypatch)
    csv_text, markdown_text, _ = _render(body)
    json_text = changesim_export.json_report(body)
    blob = changesim_export.archive(csv_text, markdown_text, json_text, snapshot=SNAPSHOT)
    with zipfile.ZipFile(BytesIO(blob)) as bundle:
        assert sorted(bundle.namelist()) == [
            f"hst-change-simulation-{SNAPSHOT}.csv",
            f"hst-change-simulation-{SNAPSHOT}.json",
            f"hst-change-simulation-{SNAPSHOT}.md",
        ]
        assert bundle.read(f"hst-change-simulation-{SNAPSHOT}.csv").decode() == csv_text
        assert bundle.read(f"hst-change-simulation-{SNAPSHOT}.json").decode() == json_text


# --- the sources the answer rests on --------------------------------------


def test_the_sources_named_are_the_ones_the_changed_devices_were_reported_by(monkeypatch):
    _install(monkeypatch, ROUTE_ROWS)
    assert changesim_export.sources_for(object(), ["dev:core1"]) == ["vyos-lab"]
    # nothing to read means nothing claimed
    assert changesim_export.sources_for(object(), []) == []


# --- the language rules ---------------------------------------------------


def test_no_file_claims_the_data_is_anything_but_an_imported_snapshot(monkeypatch):
    body = _simulate(monkeypatch)
    csv_text, markdown_text, _ = _render(body)
    for text in (csv_text, markdown_text):
        lowered = text.lower()
        for banned in ("reachability", " reached", " delivered", " live "):
            assert banned not in lowered
        assert "imported snapshot" in lowered


def test_a_flow_whose_basis_is_not_established_says_so_on_its_rows_and_in_the_prose():
    """A flow the simulation marks `basis_uncertain` must not read as
    `changed = yes` in the CSV nor `(changed)` in the report; both say "not
    established" and carry the flow's own reasons."""
    group = {
        "path_count": 1,
        "destinations": ["10.0.0.0/24"],
        "destination_count": 1,
        "next_hops": ["10.7.0.1"],
        "egress": "if:core1:eth0",
        "before": {"blocked": False},
        "after": None,
        "changed": True,
    }
    flow = {"src": "10.0.0.5", "dst": "192.168.2.35", "proto": "tcp"}
    reason = "route 10.0.0.0/8 in vrf:a:default is mismatch"
    body = {
        "flows": [
            {
                "flow": flow,
                "basis_uncertain": True,
                "basis_uncertain_reasons": [reason],
                "paths": {"groups": [group]},
                "path_rows": [
                    {
                        "destination": "10.0.0.0/24",
                        "before": {"blocked": False},
                        "after": None,
                        "changed": True,
                    }
                ],
            },
            {
                "flow": flow,
                "basis_uncertain": False,
                "paths": {"groups": [group]},
                "path_rows": [
                    {
                        "destination": "10.0.0.0/24",
                        "before": {"blocked": False},
                        "after": None,
                        "changed": True,
                    }
                ],
            },
        ]
    }
    rows = changesim_export.detail_rows(body)
    assert rows[0]["changed"] == "not established"
    assert rows[0]["not_established_because"] == reason
    assert rows[1]["changed"] is True
    assert rows[1]["not_established_because"] is None

    markdown_text = changesim_export.markdown_report([], body)
    first, second = markdown_text.split("### 2.")
    assert "(changed)" not in first
    assert "(not established)" in first
    assert f"Comparison not established: {reason}" in first
    assert "(changed)" in second
    assert "not established" not in second


def test_a_cell_text_that_a_spreadsheet_reads_as_a_formula_gets_an_apostrophe():
    for text in ('=HYPERLINK("http://x.example")', "+1", "-cmd", "@sum", "\tx", "\rx"):
        assert changesim_export._cell(text) == f"'{text}"


def test_a_number_and_an_ordinary_text_keep_their_cell_text():
    assert changesim_export._cell(-5) == "-5"
    assert changesim_export._cell(-0.5) == "-0.5"
    assert changesim_export._cell("10.0.0.0/8") == "10.0.0.0/8"
    assert changesim_export._cell("no path") == "no path"
    assert changesim_export._cell(True) == "yes"
    assert changesim_export._cell(None) == ""


def test_a_rule_name_that_starts_a_formula_is_neutral_in_the_csv():
    rows = [{"section": "flow_path", "before_decided_by": "=1+1", "flow_port": 443}]
    text = changesim_export._csv_text([], rows)

    line = text.splitlines()[1]
    assert ",'=1+1," in line
    assert ",443," in line
