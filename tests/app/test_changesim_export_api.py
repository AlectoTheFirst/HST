"""POST /api/changesim/export, the change-simulation download, with Neo4j faked at
the route's session seam and at the tracer's own monkeypatch seams."""

import zipfile
from contextlib import contextmanager
from io import BytesIO
from typing import Any

import pytest
from tests.app.conftest import login

import hst.app.routes.changesim as changesim_route
from hst import path as pathmod
from hst.app import fw_overlay_read

SNAPSHOT = 1_756_526_400_000

INTENT = {
    "kind": "fw_rule.add",
    "params": {
        "rulebase": "fw:LAN",
        "position": 10,
        "action": "drop",
        "source": "any",
        "destination": ["192.168.2.35"],
    },
}

ROWS: dict[str, Any] = {
    "MATCH (o:NetObject)": [],
    "MATCH (s:SvcObject)": [],
    "MATCH (z:Zone)": [],
    "MATCH (v:VrfInstance)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": [
        {
            "kind": "LEARNED_ROUTE",
            "prefix": "203.0.113.0/24",
            "next_hop": "192.168.2.35",
            "protocol": "bgp",
            "context_uid": "vrf:a:default",
        }
    ],
    "MATCH (d:Device)\nWHERE d.uid IN $devices": [
        {"uid": "dev:core1", "hostname": "core1", "sources": ["vyos-lab"]}
    ],
}


class _FakeGraphSession:
    """Answers only the cycle-pointer read; every other read goes through the
    monkeypatched `path._read` below."""

    def __init__(self, current: int | None = SNAPSHOT) -> None:
        self._current = current

    def run(self, query: str, **params: Any) -> Any:
        rows = [{"current": self._current}] if self._current is not None else []

        class _Result:
            def data(_self) -> list:
                return rows

        return _Result()


@pytest.fixture(autouse=True)
def _graph(monkeypatch):
    calls: list[dict[str, Any]] = []

    def read(session: Any, query: str, **params: Any) -> Any:
        for fragment, rows in ROWS.items():
            if fragment in query:
                return [dict(r) for r in rows]
        return []

    def trace(
        session: Any,
        src: str,
        dst: str,
        port: Any = None,
        proto: str = "tcp",
        rib: Any = None,
        gateways: Any = None,
    ) -> dict[str, Any]:
        calls.append({"rib": rib})
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
        }

    monkeypatch.setattr(pathmod, "_read", read)
    monkeypatch.setattr(pathmod, "trace", trace)
    return calls


def _seam(monkeypatch, current: int | None = SNAPSHOT) -> None:
    @contextmanager
    def cm(settings):
        yield _FakeGraphSession(current)

    monkeypatch.setattr(changesim_route, "_session", cm)


def _body(**kw: Any) -> dict[str, Any]:
    return {"intents": [INTENT], "flows": [{"src": "10.0.0.5", "dst": "192.168.2.35"}], **kw}


async def _post(client, **kw):
    return await client.post("/api/changesim/export", json=_body(**kw))


async def test_the_export_is_one_archive_holding_the_csv_and_the_report(client, monkeypatch):
    _seam(monkeypatch)
    await login(client, "vera")
    r = await _post(client)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/zip"
    assert f'filename="hst-change-simulation-{SNAPSHOT}.zip"' in r.headers["content-disposition"]
    with zipfile.ZipFile(BytesIO(r.content)) as bundle:
        names = sorted(bundle.namelist())
        assert names == [
            f"hst-change-simulation-{SNAPSHOT}.csv",
            f"hst-change-simulation-{SNAPSHOT}.json",
            f"hst-change-simulation-{SNAPSHOT}.md",
        ]
        csv_text = bundle.read(names[0]).decode()
        json_text = bundle.read(names[1]).decode()
        markdown_text = bundle.read(names[2]).decode()
    assert "section,flow_src,flow_dst" in csv_text
    assert "# HST change simulation" in markdown_text
    # the same header, in both
    stated = f"run id {SNAPSHOT}."
    assert stated in csv_text
    assert stated in markdown_text
    # the JSON is the full body the other two were rendered from
    import json

    parsed = json.loads(json_text)
    assert parsed["flow_count"] == 1


async def test_the_simulation_runs_on_a_worker_thread(client, monkeypatch):
    import threading

    _seam(monkeypatch)
    loop_thread = threading.current_thread()
    seen: list[threading.Thread] = []
    real = fw_overlay_read.simulate_change

    def simulate(*args: Any, **kwargs: Any) -> Any:
        seen.append(threading.current_thread())
        return real(*args, **kwargs)

    monkeypatch.setattr(fw_overlay_read, "simulate_change", simulate)
    await login(client, "vera")
    assert (await _post(client)).status_code == 200
    assert seen and loop_thread not in seen


async def test_the_run_the_export_pinned_is_on_the_response(client, monkeypatch):
    _seam(monkeypatch)
    await login(client, "vera")
    r = await _post(client)
    assert r.headers["x-hst-snapshot"] == str(SNAPSHOT)
    assert r.headers["x-hst-export-trimmed"] == "false"
    assert r.headers["x-hst-degraded"] == "false"


async def test_the_degraded_header_carries_the_pinned_runs_degraded_flag(client, monkeypatch):
    _seam(monkeypatch)
    status = {
        "snapshot": str(SNAPSHOT),
        "created": None,
        "degraded": True,
        "sources_carried": ["vyos-lab"],
        "sources_failed": [],
        "sources_partial": [],
    }
    monkeypatch.setattr(changesim_route.cyclemod, "run_status", lambda session, snap: status)
    await login(client, "vera")
    r = await _post(client)
    assert r.status_code == 200, r.text
    assert r.headers["x-hst-degraded"] == "true"


async def test_the_export_threads_a_ribsource_into_every_trace(client, monkeypatch, _graph):
    from hst.core.ribsource import RibSource

    _seam(monkeypatch)
    await login(client, "vera")
    r = await _post(client)
    assert r.status_code == 200, r.text
    assert _graph
    assert all(call["rib"] is not None for call in _graph)
    assert all(isinstance(call["rib"], RibSource) for call in _graph)


async def test_the_depth_and_the_sites_given_with_the_request_drive_the_run(client, monkeypatch):
    _seam(monkeypatch)
    await login(client, "vera")
    r = await _post(client, depth=4, sites=["fra01"])
    assert r.status_code == 200, r.text
    with zipfile.ZipFile(BytesIO(r.content)) as bundle:
        csv_text = bundle.read(f"hst-change-simulation-{SNAPSHOT}.csv").decode()
    assert "Depth: 4 level(s) of the route dependency chain, of a cap of 8." in csv_text
    assert "Site filter: fra01." in csv_text


async def test_a_depth_outside_the_engines_own_bounds_is_refused(client, monkeypatch):
    _seam(monkeypatch)
    await login(client, "vera")
    assert (await _post(client, depth=0)).status_code == 422
    assert (await _post(client, depth=99)).status_code == 422


async def test_a_change_set_that_cannot_be_applied_is_a_bad_request(client, monkeypatch):
    _seam(monkeypatch)
    await login(client, "vera")
    r = await client.post(
        "/api/changesim/export",
        json={"intents": [{"kind": "fw_rule.add", "params": {"rulebase": "fw:LAN"}}]},
    )
    assert r.status_code == 400


async def test_a_refused_interface_set_mtu_intent_is_a_bad_request_naming_why(client, monkeypatch):
    """`interface.set_mtu` validation refusals (`fw_overlay.ProposalError`)
    take the error path of every other refused intent kind."""
    _seam(monkeypatch)
    await login(client, "vera")
    r = await client.post(
        "/api/changesim/export",
        json={"intents": [{"kind": "interface.set_mtu", "params": {"interface": "if:eth0"}}]},
    )
    assert r.status_code == 400
    assert "needs an mtu" in r.text


async def test_an_empty_change_set_is_refused_rather_than_exported(client, monkeypatch):
    _seam(monkeypatch)
    await login(client, "vera")
    r = await client.post("/api/changesim/export", json={"intents": []})
    assert r.status_code == 422


async def test_a_graph_with_no_run_pointer_answers_and_says_so(client, monkeypatch):
    _seam(monkeypatch, current=None)
    await login(client, "vera")
    r = await _post(client)
    assert r.status_code == 200, r.text
    assert r.headers["x-hst-snapshot"] == ""
    with zipfile.ZipFile(BytesIO(r.content)) as bundle:
        csv_text = bundle.read("hst-change-simulation-unpinned.csv").decode()
    assert "run id none recorded." in csv_text


async def test_the_export_takes_no_snapshot_so_it_cannot_be_pinned_to_an_older_run(client, monkeypatch):
    _seam(monkeypatch)
    await login(client, "vera")
    r = await client.post("/api/changesim/export", json=_body(snapshot="1"))
    assert r.status_code == 200, r.text
    assert r.headers["x-hst-snapshot"] == str(SNAPSHOT)


async def test_the_endpoint_is_behind_the_same_gate_the_tool_is(client, monkeypatch):
    """`graph.read`, which every role holds."""
    _seam(monkeypatch)
    r = await client.post("/api/changesim/export", json=_body())
    assert r.status_code == 401


def _mtu_result(outcome: str, ceiling: int | None, bottleneck_uid: str | None) -> dict[str, Any]:
    stages = [{"stage_id": "s1", "egress_subject_uid": bottleneck_uid}] if bottleneck_uid else []
    return {
        "outcome": outcome,
        "known_ceiling_bytes": ceiling,
        "bottleneck_stage_ids": ["s1"] if bottleneck_uid else [],
        "stages": stages,
        "coverage": {"uncovered": []},
    }


async def test_a_flow_with_an_mtu_request_exports_the_mtu_columns_the_line_and_the_json(client, monkeypatch):
    """`ExportFlow.mtu` (routes/changesim.py) reaches `simulate_change` intact
    (`model_dump(exclude_none=True)` does not drop a set `mtu`), and the
    export renders it: the CSV's `mtu_*` columns, the Markdown's
    `MTU:` line, and the same body in the JSON file."""

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
            "mtu": (
                _mtu_result("fail", 1518, "dev:f4e2c6ace59e/port/port17")
                if overlaid
                else _mtu_result("fail", 1500, "dev:x:vyos-lts-1:core1/if/eth0-10")
            ),
        }

    _seam(monkeypatch)
    monkeypatch.setattr(pathmod, "trace", trace)
    await login(client, "vera")
    r = await client.post(
        "/api/changesim/export",
        json={
            "intents": [INTENT],
            "flows": [
                {
                    "src": "10.0.0.5",
                    "dst": "192.168.2.35",
                    "mtu": {"mode": "packet", "ip_packet_bytes": 9000, "ipv4_df": True},
                }
            ],
        },
    )
    assert r.status_code == 200, r.text
    with zipfile.ZipFile(BytesIO(r.content)) as bundle:
        csv_text = bundle.read(f"hst-change-simulation-{SNAPSHOT}.csv").decode()
        markdown_text = bundle.read(f"hst-change-simulation-{SNAPSHOT}.md").decode()
        json_text = bundle.read(f"hst-change-simulation-{SNAPSHOT}.json").decode()

    assert "mtu_before_outcome,mtu_before_ceiling,mtu_before_bottleneck" in csv_text
    data_lines = [ln for ln in csv_text.splitlines() if ln and not ln.startswith("#")][1:]
    assert any("fail" in ln and "1500" in ln and "1518" in ln for ln in data_lines)
    assert (
        "MTU: fail at dev:x:vyos-lts-1:core1/if/eth0-10 (1,500 B) before; "
        "fail at dev:f4e2c6ace59e/port/port17 (1,518 B frame) after"
    ) in markdown_text

    import json

    parsed = json.loads(json_text)
    assert parsed["flows"][0]["flow"]["mtu"]["mode"] == "packet"


async def test_a_flow_without_an_mtu_request_carries_the_columns_empty_and_no_mtu_line(client, monkeypatch):
    _seam(monkeypatch)
    await login(client, "vera")
    r = await _post(client)  # the default body's flow carries no `mtu`
    assert r.status_code == 200, r.text
    with zipfile.ZipFile(BytesIO(r.content)) as bundle:
        csv_text = bundle.read(f"hst-change-simulation-{SNAPSHOT}.csv").decode()
        markdown_text = bundle.read(f"hst-change-simulation-{SNAPSHOT}.md").decode()
    header_row = next(ln for ln in csv_text.splitlines() if not ln.startswith("#"))
    assert "mtu_before_outcome" in header_row  # the column exists
    data_lines = [ln for ln in csv_text.splitlines() if ln and not ln.startswith("#")][1:]
    assert data_lines
    columns = header_row.split(",")
    before_idx = columns.index("mtu_before_outcome")
    for line in data_lines:
        assert line.split(",")[before_idx] == ""
    assert "MTU:" not in markdown_text
