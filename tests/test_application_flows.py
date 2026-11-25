"""Application flows from stored evaluation evidence (hst/applications/flows.py)."""

from __future__ import annotations

from types import SimpleNamespace

from hst.applications import flows
from hst.results.project import condition_result, engine_value, missing_from_lines


def step(device, stage="route", kind="via", unknown=(), detail=""):
    return {"device_uid": device, "stage": stage, "kind": kind, "detail": detail, "unknown": list(unknown)}


def part(outcome, steps, member="db", side="before", missing=()):
    """One evaluated part as a stored run records it: the engine's outcome
    written as its result."""
    result = condition_result(
        engine_value(outcome) or "not-established", missing=missing_from_lines(missing)
    ).model_dump(mode="json")
    return {"side": side, "member": member, "result": result, "steps": steps, "missing": list(missing)}


WALK = [
    step("a", "entry", "attach"),
    step("a", "filter", "permit"),
    step("b"),
    step("c", "next-hop", "arrive"),
]


def test_parts_on_one_device_sequence_with_one_outcome_are_one_path():
    result = flows.connection_paths(
        "web",
        [
            part("holds", WALK, member="db1"),
            part("holds", WALK, member="db2"),
            part("holds", [step("a"), step("d"), step("c")], member="db1"),
            # the change set's side is not the run as it is
            part("does-not-hold", WALK, side="after"),
        ],
    )

    assert result["counts"] == {"passes": 3, "fails": 0, "open": 0}
    assert [(path["devices"], path["count"], path["members"]) for path in result["paths"]] == [
        (["a", "b", "c"], 2, ["db1", "db2"]),
        (["a", "d", "c"], 1, ["db1"]),
    ]
    assert result["more_paths"] == 0
    first = result["paths"][0]
    assert [(s["from"], s["to"], s["state"]) for s in first["segments"]] == [
        ("a", "b", "passes"),
        ("b", "c", "passes"),
    ]
    assert first["stop_device"] is None and first["unknown_device"] is None


def test_a_failing_path_stops_at_the_device_of_its_deciding_step():
    steps = [
        step("a", "entry", "attach"),
        step("b"),
        step("b", "filter", "deny"),
        step(None, "fabric", "drop"),
    ]
    path = flows.connection_paths("web", [part("does-not-hold", steps)])["paths"][0]

    assert path["result"]["answer"] == "false"
    assert path["result"]["word"] == "fails" and path["result"]["missing"] == []
    assert path["stop_index"] == 3
    # the last step names no device: the stop is on the device before it
    assert path["stop_device"] == "b"
    assert [s["state"] for s in path["segments"]] == ["fails"]


def test_a_path_that_is_not_established_is_established_up_to_its_first_unknown():
    steps = [step("a"), step("b"), step("c", "route", "incomplete", unknown=["rib:c"]), step("d")]
    result = flows.connection_paths("web", [part("not-established", steps, missing=["rib:c"])])
    path = result["paths"][0]

    assert path["unknown_index"] == 2
    assert path["unknown_device"] == "c"
    assert [(s["from"], s["to"], s["state"]) for s in path["segments"]] == [
        ("a", "b", "decided"),
        ("b", "c", "decided"),
        ("c", "d", "open"),
    ]
    assert path["missing"] == ["rib:c"]
    assert result["missing"] == ["rib:c"]
    # the path's answer in the result vocabulary, with the missing line
    assert path["result"]["statement"] == "condition-holds"
    assert path["result"]["word"] == "not decided"
    assert path["result"]["missing"] == [{"code": "missing-evidence", "subject": None, "detail": "rib:c"}]


def test_an_unknown_outcome_word_is_not_established_and_no_evidence_proves_nothing():
    result = flows.connection_paths("web", [part("unknown", [step("a")])])
    assert result["counts"]["open"] == 1
    assert flows.path_state({"passes": 0, "fails": 0, "open": 0}) == "open"
    assert flows.path_state({"passes": 3, "fails": 1, "open": 2}) == "false"
    assert flows.path_state({"passes": 3, "fails": 0, "open": 1}) == "open"
    assert flows.path_state({"passes": 3, "fails": 0, "open": 0}) == "true"


def test_paths_are_capped_worst_first_and_the_rest_are_counted():
    evidence = [part("holds", [step("a"), step(f"p{i:02d}"), step("z")]) for i in range(55)]
    evidence += [part("does-not-hold", [step("a"), step("x")]) for _ in range(2)]
    evidence += [part("not-established", [step("a"), step("y", unknown=["u"])])]
    result = flows.connection_paths("web", evidence)

    assert len(result["paths"]) == flows.MAX_PATHS
    assert result["more_paths"] == 57 - flows.MAX_PATHS
    assert [path["result"]["answer"] for path in result["paths"][:2]] == ["false", "open"]
    assert result["paths"][0]["count"] == 2
    assert result["counts"] == {"passes": 55, "fails": 2, "open": 1}


def test_the_response_of_a_round_trip_is_its_own_phase():
    steps = [
        step("a", "entry", "attach"),
        step("a", "filter", "permit"),
        step("b"),
        step("c", "next-hop", "arrive"),
        step("c", "session", "reply", detail="evaluate the response with reversed addresses and ports"),
        step("c", "reply-filter", "permit"),
        step("b"),
        step("a", "reply-nat", "inverse"),
    ]
    path = flows.connection_paths("web", [part("holds", steps)])["paths"][0]

    assert [s["phase"] for s in path["steps"]] == ["forward"] * 4 + ["reply"] * 4
    assert path["devices"] == ["a", "b", "c", "c", "b", "a"]
    assert path["phases"] == ["forward", "forward", "forward", "reply", "reply", "reply"]
    # the turn on the destination device is no segment
    assert [(s["from"], s["to"], s["phase"]) for s in path["segments"]] == [
        ("a", "b", "forward"),
        ("b", "c", "forward"),
        ("c", "b", "reply"),
        ("b", "a", "reply"),
    ]


def test_gates_are_the_decisions_not_the_movement():
    assert flows.is_gate(step("a", "filter", "permit"))
    assert flows.is_gate(step("a", "reply-filter", "permit"))
    assert flows.is_gate(step("a", "carrier/snat", "masquerade"))
    assert flows.is_gate(step("a", "reply-nat", "inverse"))
    assert flows.is_gate(step("a", "load-balancer", "select"))
    assert not flows.is_gate(step("a", "route", "via"))
    assert not flows.is_gate(step("a", "entry", "attach"))
    assert not flows.is_gate(step("a", "session", "reply"))


DEFINITION = {
    "id": "shop",
    "name": "Shop",
    "groups": [
        {"id": "clients", "name": "Clients", "members": [{"id": "lan", "address": "10.9.0.0/24"}]},
        {
            "id": "servers",
            "name": "Servers",
            "members": [{"id": "db", "inventory": {"kind": "ip", "uid": "ip:1"}}],
        },
    ],
    "connections": [
        {"id": "web", "name": "Web", "source": "clients", "destination": "servers", "success": "round-trip"},
        {"id": "admin", "name": "Admin", "source": "clients", "destination": "servers"},
        {"id": "backup", "name": "Backup", "source": "clients", "destination": "servers"},
    ],
    "services": [{"id": "front", "name": "Front", "connection_ids": ["web", "admin"]}],
}
RESOLUTION = {
    "digest": "r" * 64,
    "groups": {
        "clients": {"lan": {"bindings": [{"address": "10.9.0.0/24"}], "inventory_uid": None}},
        "servers": {"db": {"bindings": [{"address": "10.0.0.5"}], "inventory_uid": "ip:1"}},
    },
    "connections": [
        {"id": "web", "readiness": "ready", "issues": []},
        {"id": "admin", "readiness": "ready", "issues": []},
        {
            "id": "backup",
            "readiness": "unresolved",
            "issues": [
                {"code": "destination-empty", "path": "connections.backup.destination", "detail": "x"}
            ],
        },
    ],
}
REFERENCE = {"snapshot": "4000", "manifest_sha256": "a" * 64, "estate": "test"}


def _overlay(evaluations, connection_ids=None):
    return flows.overlay(
        application={"id": "shop", "revision": 3, "digest": "d" * 64, "name": "Shop"},
        definition=DEFINITION,
        reference=REFERENCE,
        resolution=RESOLUTION,
        anchors={"ip:1": ["dev-db"]},
        evaluations=evaluations,
        connection_ids=connection_ids,
    )


def test_the_overlay_states_each_connection_and_never_shows_a_missing_evaluation_as_success():
    evaluations = {
        "web": {
            "session_id": "s1",
            "run_id": "r1",
            "execution": "completed",
            "snapshot": "4000",
            "revision": 3,
            "finished_at": "now",
            "result": {"evidence": {"count": 1, "items": [part("holds", WALK)], "truncated": False}},
        },
        "admin": {
            "session_id": "s2",
            "run_id": "r2",
            "execution": "queued",
            "snapshot": "4000",
            "revision": 3,
        },
    }
    body = _overlay(evaluations)
    states = {item["id"]: item["state"] for item in body["connections"]}

    assert states == {"web": "evaluated", "admin": "not-evaluated", "backup": "unresolved"}
    assert [item["result"] and item["result"]["answer"] for item in body["connections"]] == [
        "true",
        None,
        None,
    ]
    web, admin, backup = body["connections"]
    assert web["service_id"] == "front" and web["success"] == "round-trip"
    assert web["paths"][0]["devices"] == ["a", "b", "c"]
    assert admin["evaluation"]["execution"] == "queued" and admin["paths"] == []
    assert backup["issues"][0]["code"] == "destination-empty" and backup["paths"] == []
    assert backup["endpoints"]["destination"] == [
        {"member": "db", "inventory_uid": "ip:1", "devices": ["dev-db"], "addresses": ["10.0.0.5"]}
    ]
    assert body["stale"] == {"snapshot": False, "revision": False}
    assert body["resolution_digest"] == "r" * 64


def test_the_overlay_marks_an_evaluation_of_another_run_or_revision():
    evaluations = {
        "web": {
            "session_id": "s1",
            "run_id": "r1",
            "execution": "completed",
            "snapshot": "3900",
            "revision": 2,
            "result": {"evidence": {"items": []}},
        }
    }
    body = _overlay(evaluations, ["web"])

    assert [item["id"] for item in body["connections"]] == ["web"]
    assert body["connections"][0]["evaluation"]["stale"] == {"snapshot": True, "revision": True}
    assert body["stale"] == {"snapshot": True, "revision": True}
    assert body["evaluated"] == {"snapshots": ["3900"], "revisions": [2]}
    # an evaluation with no evidence proves nothing
    assert body["connections"][0]["result"]["answer"] == "open"


def _session(identifier, snapshot, revision, runs, application="shop"):
    return SimpleNamespace(
        id=identifier,
        definition={
            "input": {
                "kind": "connection",
                "snapshot": {"snapshot": snapshot},
                "connections": [
                    {
                        "id": f"sel-{connection}",
                        "source": {
                            "kind": "application_connection",
                            "reference": {
                                "application": {"id": application, "revision": revision},
                                "connection_id": connection,
                            },
                            "resolved_scope_digest": "r" * 64,
                        },
                    }
                    for connection in ("web", "admin")
                ],
            },
            "runs": [{"id": run_id, "item_id": f"sel-{connection}"} for connection, run_id in runs],
        },
    )


class LookupStore:
    def __init__(self, sessions, runs):
        self.sessions = sessions
        self.runs = runs
        self.read = []

    async def list_application_analysis_sessions(self, application_id, limit):
        return list(self.sessions)

    async def get_analysis_run(self, run_id):
        self.read.append(run_id)
        state = self.runs[run_id]
        return SimpleNamespace(id=run_id, state=state, finished_at=None, result={"evidence": {}})


async def test_the_lookup_prefers_the_map_run_and_revision_then_the_map_run_then_the_newest():
    store = LookupStore(
        # newest first
        [
            _session("newest-other-run", "3900", 3, [("web", "r-other"), ("admin", "r-other-admin")]),
            _session("map-run-old-revision", "4000", 2, [("web", "r-old-rev")]),
            _session("exact", "4000", 3, [("web", "r-exact")]),
            _session("queued-at-run", "4000", 3, [("admin", "r-queued")]),
        ],
        {
            "r-other": "completed",
            "r-other-admin": "completed",
            "r-old-rev": "completed",
            "r-exact": "completed",
            "r-queued": "queued",
        },
    )
    chosen = await flows.find_evaluations(
        store, "shop", snapshot="4000", revision=3, connection_ids=["web", "admin"]
    )

    assert chosen["web"]["run_id"] == "r-exact"
    assert chosen["web"]["execution"] == "completed"
    # a run under way at the map's run wins over a completed run of another run
    assert chosen["admin"]["run_id"] == "r-queued"
    assert chosen["admin"]["result"] is None


async def test_the_lookup_falls_back_to_the_newest_completed_run_and_skips_failed_runs():
    store = LookupStore(
        [
            _session("failed", "4000", 3, [("web", "r-failed")]),
            _session("older-run", "3800", 1, [("web", "r-older")]),
            _session("other-app", "4000", 3, [("web", "r-app")], application="billing"),
        ],
        {"r-failed": "failed", "r-older": "completed", "r-app": "completed"},
    )
    chosen = await flows.find_evaluations(store, "shop", snapshot="4000", revision=3, connection_ids=["web"])

    assert chosen["web"]["run_id"] == "r-older"
    assert chosen["web"]["snapshot"] == "3800"
    assert "r-app" not in store.read
