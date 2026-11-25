"""Application flows on a map.

The module turns the stored evaluation evidence of each connection of a
Business Application into the paths that a map draws. It runs no evaluation
and no trace. The input is the evidence that an Analysis run stored. Each
evaluated part of each destination member has its `result` and the ordered
`steps` that decided it (`assessment/evaluation.py` `_evidence`). The side
`before` is the network as the run holds it. The side `after` adds the change
set of the run. A flow on the map reads `before` only.

Parts that took the same device sequence to the same answer form one path
with a count. A connection keeps at most `MAX_PATHS` distinct paths, worst
answer first, and reports the count of the other paths. The `result` of each
path and of each evaluated connection states that the connection condition
passes, fails, or is not decided with the missing lines.

A round-trip or session connection evaluates the response as a second walk
with reversed addresses. The evaluator marks its start with a step of stage
`session` and kind `reply`. Every reply-only gate has a `reply-` stage. Each
step of a path holds the `phase` that it belongs to.

A path hop is a device that the evaluated packet crossed. The module presents
no hop as an application component.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Literal

from hst.results.project import VALUE_OF_ANSWER, answer_of, condition_result, missing_from_lines

MAX_PATHS = 50

# The answer of a path. "true" passes the connection condition, "false" fails
# it and "open" leaves it not decided.
PathAnswer = Literal["true", "false", "open"]
# The state of a connection on the map. Only an evaluated connection has an
# answer in `result`.
ConnectionState = Literal["evaluated", "unresolved", "not-evaluated"]
# The state in which a map draws one segment. A segment of a path that passes
# or fails takes the answer of the path. A segment of a path that is not decided
# is `decided` up to the device of its first unknown step and `open` after it.
SegmentState = Literal["passes", "fails", "decided", "open"]
# The key in `counts` for each answer of an evaluated part.
_COUNT_OF_ANSWER: dict[str, str] = {"true": "passes", "false": "fails", "open": "open"}
# The sort rank of an answer. A failing path sorts first, then a path that is
# not decided.
_RANK: dict[str, int] = {"false": 0, "open": 1, "true": 2}

# The stages at which a gate decides. They are filters, translation, policy
# routing, session state, brokers, load balancers and the MTU check. A route
# lookup, an arrival and the entry move the walk and decide nothing.
_GATE_STAGES = frozenset(
    {
        "filter",
        "input-filter",
        "output-filter",
        "firewall",
        "nat",
        "snat",
        "dnat",
        "pbr",
        "session",
        "broker",
        "load-balancer",
        "mtu",
        "zone",
        "policy",
    }
)


def _base_stage(stage: str) -> str:
    """The stage without its `carrier/` and `reply-` prefixes."""
    base = stage.removeprefix("carrier/")
    return base.removeprefix("reply-")


def is_reply_start(step: Mapping[str, Any]) -> bool:
    """True for the step that starts the evaluation of the response."""
    return step.get("stage") == "session" and step.get("kind") == "reply"


def step_phases(steps: Sequence[Mapping[str, Any]]) -> list[Literal["forward", "reply"]]:
    """Return the phase of each step. The phase is `forward` until the
    response starts and `reply` after it. A `reply-` stage also starts the
    reply phase, for evidence that holds no start step."""
    phase: Literal["forward", "reply"] = "forward"
    out: list[Literal["forward", "reply"]] = []
    for step in steps:
        stage = str(step.get("stage") or "").removeprefix("carrier/")
        if is_reply_start(step) or stage.startswith("reply-"):
            phase = "reply"
        out.append(phase)
    return out


def is_gate(step: Mapping[str, Any]) -> bool:
    """True when a gate decided at this step."""
    if is_reply_start(step):
        return False
    base = _base_stage(str(step.get("stage") or ""))
    return base in _GATE_STAGES or "filter" in base or base.endswith("nat")


def _answer(item: Mapping[str, Any]) -> PathAnswer:
    """The answer of one evaluated part from its result. A part without a
    decided result is not decided."""
    answer = answer_of(item.get("result"))
    return answer if answer in ("true", "false") else "open"  # type: ignore[return-value]


def _steps(raw: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    items = [dict(step) for step in raw]
    phases = step_phases(items)
    return [
        {
            "device_uid": str(step["device_uid"]) if step.get("device_uid") else None,
            "stage": str(step.get("stage") or ""),
            "kind": str(step.get("kind") or ""),
            "detail": str(step.get("detail") or ""),
            "unknown": [str(value) for value in step.get("unknown") or []],
            "phase": phase,
            "gate": is_gate(step),
        }
        for step, phase in zip(items, phases, strict=True)
    ]


def _hops(steps: list[dict[str, Any]]) -> tuple[list[tuple[str, str]], list[int | None]]:
    """Return the hops of the walk in order and the hop index of each step.

    A hop is a (device uid, phase) pair. Consecutive steps on one device in
    one phase form one hop. A step with no device (a shared segment) adds no
    hop. It belongs to the hop before it, or to no hop at the start."""
    hops: list[tuple[str, str]] = []
    of_step: list[int | None] = []
    for step in steps:
        device = step["device_uid"]
        if device is not None:
            hop = (device, step["phase"])
            if not hops or hops[-1] != hop:
                hops.append(hop)
        of_step.append(len(hops) - 1 if hops else None)
    return hops, of_step


def _path_id(connection_id: str, hops: list[tuple[str, str]], outcome: str) -> str:
    key = json.dumps([connection_id, hops, outcome], separators=(",", ":"))
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _marker_hop(hops: list[tuple[str, str]], of_step: list[int | None], index: int | None) -> int | None:
    """Return the hop of step `index`. A step before the first device takes the first hop."""
    if index is None or not hops:
        return None
    hop = of_step[index]
    return 0 if hop is None else hop


def _segments(
    hops: list[tuple[str, str]], outcome: PathAnswer, unknown_hop: int | None
) -> list[dict[str, Any]]:
    """Return each pair of consecutive hops on different devices with the
    state in which a map draws it. Every segment of a path that passes is
    `passes`, and every segment of a failing path is `fails`. A segment of a
    path that is not decided is `decided` up to the device of its first
    unknown step and `open` after it."""
    out = []
    for index in range(len(hops) - 1):
        (left, _), (right, phase) = hops[index], hops[index + 1]
        if left == right:
            continue
        state: SegmentState
        if outcome == "true":
            state = "passes"
        elif outcome == "false":
            state = "fails"
        else:
            state = "decided" if unknown_hop is not None and index + 1 <= unknown_hop else "open"
        out.append({"from": left, "to": right, "phase": phase, "state": state})
    return out


def connection_paths(
    connection_id: str, evidence: Iterable[Mapping[str, Any]], *, side: str = "before"
) -> dict:
    """The distinct paths of one connection's evidence on `side`.

    Returns `paths` (at most `MAX_PATHS`, worst answer first, then the most
    parts first), `more_paths`, the number of evidence parts that pass, fail
    or are open in `counts`, and the union of what is missing in `missing`.
    """
    grouped: dict[tuple[Any, ...], dict[str, Any]] = {}
    counts: dict[str, int] = {"passes": 0, "fails": 0, "open": 0}
    missing_all: set[str] = set()
    for item in evidence:
        if str(item.get("side", side)) != side:
            continue
        outcome = _answer(item)
        counts[_COUNT_OF_ANSWER[outcome]] += 1
        steps = _steps(item.get("steps") or [])
        missing = sorted({str(value) for value in item.get("missing") or []})
        missing_all.update(missing)
        hops, of_step = _hops(steps)
        key = (tuple(hops), outcome)
        path = grouped.get(key)
        if path is None:
            stop_index = len(steps) - 1 if outcome == "false" and steps else None
            unknown_index = (
                next(
                    (i for i, step in enumerate(steps) if step["unknown"]), len(steps) - 1 if steps else None
                )
                if outcome == "open"
                else None
            )
            stop_hop = _marker_hop(hops, of_step, stop_index)
            unknown_hop = _marker_hop(hops, of_step, unknown_index)
            path = grouped[key] = {
                "id": _path_id(connection_id, hops, outcome),
                "outcome": outcome,
                "count": 0,
                "members": set(),
                "devices": [device for device, _ in hops],
                "phases": [phase for _, phase in hops],
                "segments": _segments(hops, outcome, unknown_hop),
                "steps": steps,
                "stop_index": stop_index,
                "stop_device": hops[stop_hop][0] if stop_hop is not None else None,
                "unknown_index": unknown_index,
                "unknown_device": hops[unknown_hop][0] if unknown_hop is not None else None,
                "missing": set(),
            }
        path["count"] += 1
        if item.get("member") is not None:
            path["members"].add(str(item["member"]))
        path["missing"].update(missing)
    ordered = sorted(
        grouped.values(),
        key=lambda path: (_RANK[path["outcome"]], -path["count"], path["devices"], path["id"]),
    )
    # The `result` of a path replaces its `outcome`.
    paths = [
        {
            **{key: value for key, value in path.items() if key != "outcome"},
            "result": path_result(path["outcome"], sorted(path["missing"])),
            "members": sorted(path["members"]),
            "missing": sorted(path["missing"]),
        }
        for path in ordered[:MAX_PATHS]
    ]
    return {
        "paths": paths,
        "more_paths": max(0, len(ordered) - MAX_PATHS),
        "counts": counts,
        "missing": sorted(missing_all),
    }


def path_result(answer: str, missing: Sequence[str]) -> dict[str, Any] | None:
    """Return the connection condition answer of one path or one connection
    in the result vocabulary. The answer passes, fails, or is not decided with
    the missing lines. Returns None for a value that is not an answer."""
    value = VALUE_OF_ANSWER.get(str(answer))
    if value is None:
        return None
    return condition_result(
        value, missing=missing_from_lines(missing), fallback="the evaluation of this part is open"
    ).model_dump(mode="json")


def path_state(counts: Mapping[str, int]) -> PathAnswer:
    """Return the answer of an evaluated connection from its evidence counts.
    The connection fails when a part fails. It is open when a part is open or
    when no part passes. It passes when every part passes."""
    if counts.get("fails"):
        return "false"
    if counts.get("open") or not counts.get("passes"):
        return "open"
    return "true"


def _endpoints(
    group_id: str, resolution: Mapping[str, Any], anchors: Mapping[str, list[str]]
) -> list[dict[str, Any]]:
    members = (resolution.get("groups") or {}).get(group_id) or {}
    out = []
    for member_id in sorted(members):
        member = members[member_id]
        uid = member.get("inventory_uid")
        out.append(
            {
                "member": member_id,
                "inventory_uid": uid,
                "devices": sorted(set(anchors.get(uid, []))) if uid else [],
                "addresses": sorted({str(binding["address"]) for binding in member.get("bindings") or []}),
            }
        )
    return out


def _evaluation_summary(evaluation: Mapping[str, Any], snapshot: str, revision: int) -> dict[str, Any]:
    evaluated_snapshot = str(evaluation.get("snapshot") or "")
    evaluated_revision = evaluation.get("revision")
    return {
        "session_id": evaluation.get("session_id"),
        "run_id": evaluation.get("run_id"),
        "execution": evaluation.get("execution"),
        "snapshot": evaluated_snapshot,
        "revision": evaluated_revision,
        "finished_at": evaluation.get("finished_at"),
        "stale": {
            "snapshot": evaluated_snapshot != snapshot,
            "revision": evaluated_revision != revision,
        },
    }


def overlay(
    *,
    application: Mapping[str, Any],
    definition: Mapping[str, Any],
    reference: Mapping[str, Any],
    resolution: Mapping[str, Any],
    anchors: Mapping[str, list[str]],
    evaluations: Mapping[str, Mapping[str, Any]],
    connection_ids: list[str] | None = None,
) -> dict:
    """Return the flow overlay of `application` at the run of `reference`.

    `resolution` is the resolution of the definition at that run. An
    unresolved connection shows its endpoints and issues only. `anchors` maps
    a resolved inventory uid to the uids of the devices that hold it.
    `evaluations` maps a connection id to the stored evaluation chosen for it
    (`find_evaluations`). An evaluation holds `execution`, `snapshot`,
    `revision` and, after completion, `result`. A resolved connection without
    a completed evaluation has the state `not-evaluated` and no result.
    """
    snapshot = str(reference.get("snapshot") or "")
    revision = int(application["revision"])
    services = {
        connection_id: service["id"]
        for service in definition.get("services") or []
        for connection_id in service.get("connection_ids") or []
    }
    resolved = {item["id"]: item for item in resolution.get("connections") or []}
    wanted = set(connection_ids or [])
    connections = []
    for connection in definition.get("connections") or []:
        if wanted and connection["id"] not in wanted:
            continue
        identifier = connection["id"]
        item = resolved.get(identifier) or {}
        evaluation = evaluations.get(identifier)
        body: dict[str, Any] = {
            "id": identifier,
            "name": connection.get("name", identifier),
            "service_id": services.get(identifier),
            "source": connection["source"],
            "destination": connection["destination"],
            "protocol": connection.get("protocol"),
            "destination_ports": connection.get("destination_ports"),
            "success": connection.get("success", "forward"),
            "readiness": item.get("readiness", "unresolved"),
            "issues": list(item.get("issues") or []),
            "endpoints": {
                "source": _endpoints(connection["source"], resolution, anchors),
                "destination": _endpoints(connection["destination"], resolution, anchors),
            },
            "evaluation": _evaluation_summary(evaluation, snapshot, revision) if evaluation else None,
            "paths": [],
            "more_paths": 0,
            "counts": {"passes": 0, "fails": 0, "open": 0},
            "missing": [],
            "evidence_truncated": False,
        }
        result = evaluation.get("result") if evaluation else None
        if body["readiness"] != "ready":
            body["state"] = "unresolved"
        elif not evaluation or evaluation.get("execution") != "completed" or not isinstance(result, dict):
            body["state"] = "not-evaluated"
        else:
            evidence = result.get("evidence") or {}
            items = evidence.get("items") if isinstance(evidence, dict) else evidence
            aggregated = connection_paths(identifier, items or [])
            body.update(aggregated)
            body["evidence_truncated"] = bool(isinstance(evidence, dict) and evidence.get("truncated"))
            body["state"] = "evaluated"
            body["result"] = path_result(path_state(aggregated["counts"]), body.get("missing") or [])
        body.setdefault("result", None)
        connections.append(body)
    shown = [item["evaluation"] for item in connections if item["evaluation"]]
    return {
        "application": {
            "id": application["id"],
            "revision": revision,
            "digest": application.get("digest"),
            "name": application.get("name"),
        },
        "snapshot": {key: reference.get(key) for key in ("snapshot", "manifest_sha256", "estate")},
        "resolution_digest": resolution.get("digest"),
        "connections": connections,
        "evaluated": {
            "snapshots": sorted({item["snapshot"] for item in shown}),
            "revisions": sorted({item["revision"] for item in shown if item["revision"] is not None}),
        },
        "stale": {
            "snapshot": any(item["stale"]["snapshot"] for item in shown),
            "revision": any(item["stale"]["revision"] for item in shown),
        },
        "max_paths": MAX_PATHS,
    }


def _session_application_items(definition: Mapping[str, Any], application_id: str) -> dict[str, dict]:
    """Return the application connections of one stored connection session
    that belong to `application_id`, keyed by selection id. An item holds the
    connection id, the application revision, the resolution digest, the
    snapshot and the change flag."""
    value = definition.get("input") or {}
    if value.get("kind") != "connection":
        return {}
    out = {}
    for selection in value.get("connections") or []:
        source = selection.get("source") or {}
        reference = source.get("reference") or {}
        application = reference.get("application") or {}
        if source.get("kind") != "application_connection" or application.get("id") != application_id:
            continue
        out[str(selection.get("id"))] = {
            "connection_id": reference.get("connection_id"),
            "revision": application.get("revision"),
            "resolution_digest": source.get("resolved_scope_digest"),
            "snapshot": str((value.get("snapshot") or {}).get("snapshot") or ""),
            # a session with a change set evaluates the run as it is on side `before`
            "changes": bool(value.get("changes")),
        }
    return out


# The most sessions one lookup reads, newest first.
MAX_SESSIONS = 200


async def find_evaluations(
    store: Any,
    application_id: str,
    *,
    snapshot: str,
    revision: int,
    connection_ids: Iterable[str],
) -> dict[str, dict]:
    """Return the stored evaluation to show for each of `connection_ids`, from
    the newest Analysis connection sessions of `application_id`.

    Per connection, the first choice is the newest completed run at
    `snapshot` and `revision`. The second choice is the newest completed run
    at `snapshot`. The third choice is a run still queued or running at
    `snapshot`. The last choice is the newest completed run at any snapshot.
    The function reads at most `MAX_SESSIONS` sessions. It stops when every
    connection has a completed run at `snapshot` and `revision`.
    """
    from hst.app.routes.analysis_sessions import older_run

    wanted = set(connection_ids)
    best: dict[str, tuple[int, dict]] = {}
    sessions = await store.list_application_analysis_sessions(application_id, MAX_SESSIONS)
    for record in sessions:
        if wanted and all(best.get(identifier, (9, {}))[0] == 0 for identifier in wanted):
            break
        items = _session_application_items(record.definition, application_id)
        for summary in (record.definition or {}).get("runs") or []:
            if older_run(summary):
                continue
            item = items.get(str(summary.get("item_id")))
            if item is None or item["connection_id"] not in wanted:
                continue
            identifier = item["connection_id"]
            same_snapshot = item["snapshot"] == snapshot
            same_revision = item["revision"] == revision
            current = best.get(identifier, (9, {}))[0]
            if current == 0:
                continue
            run = await store.get_analysis_run(summary["id"])
            if run is None:
                continue
            if run.state == "completed":
                rank = 0 if same_snapshot and same_revision else 1 if same_snapshot else 3
            elif run.state in {"queued", "running"} and same_snapshot:
                rank = 2
            else:
                continue
            if rank < current:
                best[identifier] = (
                    rank,
                    {
                        "session_id": record.id,
                        "run_id": run.id,
                        "execution": run.state,
                        "snapshot": item["snapshot"],
                        "revision": item["revision"],
                        "resolution_digest": item["resolution_digest"],
                        "finished_at": run.finished_at,
                        "result": run.result if run.state == "completed" else None,
                    },
                )
    return {identifier: value for identifier, (_, value) in best.items()}
