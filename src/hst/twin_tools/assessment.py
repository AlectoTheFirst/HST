"""The assessment tool `assessment_read`.

`assessment_read` reads saved assessments from the app store. It does not run
an assessment. `mode: list` lists the saved assessments with their freshness and
their five newest runs, through `read_saved`. `mode: run` reads one recorded
run without its lease fields, also through `read_saved`. Both modes read
through `read_saved_assessments`. `mode: findings` pages one result bucket of
a run that retains a symbolic result artifact, through the analysis child
process that `GET /api/assessments/{id}/runs/{run_id}/buckets` uses. A run
without that artifact is a `conflict`, as the route answers 409.

`mode: finding` reads one entry of the stored result of a run. The entry is a
finding, an evidence gap, a failure domain, the outcome or the verification
comparison. The reference that the web client sends selects it
(`hst.assessment.findings`). An entry that the stored result does not hold is
`not_found`. The record is cut to `MAX_RECORD_CHARS`. The answer also lists an
evidence gap under `evidence.gaps`, and the record of a gap is cut to half of
`MAX_RECORD_CHARS`. `mode: analysis_session` reads one analysis session
revision with its input, its runs with their execution, outcome and coverage,
and its review. The record is cut in the same way.

A run records the snapshots that it was computed from. `snapshot_matches` is
true when the selected run is one of them. The answer is the stored answer in
both cases.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from hst.app.ai.registry import AGENT_MODEL_CHARS, ToolContext, ToolError, ToolRegistry
from hst.assessment import findings as findings_mod
from hst.core import db as dbmod
from hst.results.words import Result, from_engine
from hst.results.words import record as completeness
from hst.twin_tools import selectors
from hst.twin_tools.envelope import (
    Call,
    Evidence,
    ItemEvidence,
    Missing,
    PageOut,
    catalogue_spec,
    gap_list,
    http_error,
    jsonable,
    missing_of,
    unknowns_missing,
    whole_result,
)
from hst.twin_tools.stores import read_store, require, store_error

# `read_saved` lists at most 100 assessments.
MAX_ASSESSMENTS = 100
# The most characters of one record that `mode: finding` and `mode:
# analysis_session` return. With the envelope around it, the answer stays
# below `AGENT_MODEL_CHARS`, the smallest model bound of any surface.
MAX_RECORD_CHARS = AGENT_MODEL_CHARS * 3 // 4
# The first cut of a record that is too long. Lists and objects keep 100 items
# and strings keep 2000 characters. Each further cut halves both bounds.
_FIRST_CUT = (100, 2000)

Bucket = Literal[
    "evidence",
    "decided_change.loss",
    "decided_change.gain",
    "open_change.loss",
    "open_change.gain",
    "open.before",
    "open.after",
    "passes.before",
    "passes.after",
    "fails.before",
    "fails.after",
    "triage.decided_loss",
    "triage.passes_then_open",
    "triage.open_then_fails",
    "triage.open_throughout",
    "triage.decided_gain",
    "triage.open_then_passes",
    "triage.fails_then_open",
]


def snapshot_matches(refs: Any, snapshot_id: str | None) -> bool | None:
    """Whether the selected run is one of the runs that the stored run was
    computed from. None when the run records no snapshot."""
    named = [str(ref.get("snapshot")) for ref in refs or () if isinstance(ref, dict) and ref.get("snapshot")]
    if not named:
        return None
    return snapshot_id in named


def bucket_evidence(bucket: str) -> ItemEvidence | None:
    """The evidence that the bucket name gives each of its items, or None for
    the `evidence` bucket."""
    if bucket in ("decided_change.loss", "triage.decided_loss", "fails.before", "fails.after"):
        # the condition fails after the change (a loss), or on the named side
        return ItemEvidence.of(from_engine("condition-holds", "does-not-hold"), basis="computed")
    if bucket in ("decided_change.gain", "triage.decided_gain", "passes.before", "passes.after"):
        return ItemEvidence.of(from_engine("condition-holds", "holds"), basis="computed")
    if bucket == "evidence":
        return None
    # possible.*, not_established.* and the triage classes with an open side
    open_on = [
        Missing(
            code="side-not-decided",
            detail="the address is not decided on at least one side of the change; the run's gaps name why",
        )
    ]
    open_result = from_engine("condition-holds", "not-established", missing=open_on)
    return ItemEvidence.of(open_result, basis="computed")


def _not_completed(state: str) -> Result:
    return from_engine(
        "condition-holds",
        "not-established",
        missing=[Missing(code="run-not-completed", detail=f"the run is {state}, so it records no result")],
    )


def _stored_result(value: Any) -> Result | None:
    """A result a stored run records, or None for anything else."""
    if isinstance(value, dict) and "word" in value:
        return Result.model_validate(value)
    return None


def run_result(state: str, result: dict[str, Any] | None) -> Result:
    """The answer of one stored run.

    A completed run answers with its result, or with the result after the
    change. A completed run without either answers as a stored record. A run
    that has not completed is not decided."""
    if state != "completed" or not isinstance(result, dict):
        return _not_completed(state)
    after = (result.get("outcomes") or {}).get("after")
    for value in (result.get("result"), after.get("result") if isinstance(after, dict) else None):
        answer = _stored_result(value)
        if answer is not None:
            return answer
    return completeness("stored")


def entry_result(located: findings_mod.Located, state: str, result: dict[str, Any]) -> Result:
    """The answer of one entry of a stored result."""
    if state != "completed":
        return _not_completed(state)
    entry = located.record
    if located.kind == "finding":
        return _stored_result(entry.get("result")) or completeness("stored")
    if located.kind == "gap":
        return completeness("stored", missing=missing_of([entry]))
    if located.kind == "domain":
        if entry.get("evidence_complete") is True:
            return completeness("validated")
        return completeness(
            "incomplete",
            missing=[
                Missing(code="domain-incomplete", detail="the recorded domain membership is not validated")
            ],
        )
    if located.kind == "verification":
        if result.get("state") in ("agreement", "deviation"):
            return completeness("stored")
        return completeness(
            "stored",
            missing=[
                Missing(
                    code="insufficient-evidence", detail="the collected model does not decide the comparison"
                )
            ],
        )
    return run_result(state, result)


def _compact(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str)


def _cut(value: Any, items: int, chars: int) -> Any:
    if isinstance(value, dict):
        return {key: _cut(entry, items, chars) for key, entry in list(value.items())[:items]}
    if isinstance(value, list):
        return [_cut(entry, items, chars) for entry in value[:items]]
    if isinstance(value, str) and len(value) > chars:
        return value[:chars]
    return value


def bounded_record(record: Any, limit: int = MAX_RECORD_CHARS) -> tuple[Any, int, bool]:
    """`record` within `limit` characters of compact JSON, the length of the
    whole record, and whether it was cut.

    A record that is too long keeps the first items of every list and object
    and the start of every string. The first cut keeps `_FIRST_CUT`, and each
    further cut halves both bounds until the record fits.
    """
    full = len(_compact(record))
    if full <= limit:
        return record, full, False
    items, chars = _FIRST_CUT
    while True:
        cut = _cut(record, items, chars)
        if len(_compact(cut)) <= limit or (items, chars) == (0, 0):
            return cut, full, True
        items, chars = items // 2, chars // 2


def _other_runs(snapshot_id: str | None) -> str:
    return f"the run was computed from other runs than the selected snapshot {snapshot_id}"


def _cut_note(full: int, limit: int = MAX_RECORD_CHARS) -> str:
    return f"the record is cut to {limit} of its {full} characters; the run's export holds the whole record"


class AssessmentListInput(selectors.ToolInput):
    """The saved assessments, newest first, each with its five newest runs."""

    mode: Literal["list"]
    limit: int = Field(default=20, ge=1, le=MAX_ASSESSMENTS, description="Assessments listed, at most 100.")


class AssessmentRunInput(selectors.ToolInput):
    """One recorded assessment run."""

    mode: Literal["run"]
    run_id: str = Field(min_length=1, max_length=200, description="The run id, from mode: list.")


class AssessmentFindingsInput(selectors.PagedInput):
    """One result bucket of a run, a page at a time."""

    mode: Literal["findings"]
    assessment_id: str = Field(min_length=1, max_length=200, description="The assessment id.")
    run_id: str = Field(min_length=1, max_length=200, description="The run id.")
    bucket: Bucket = Field(
        description=(
            "decided_change.* is what the change decidedly costs or adds, open_change.* what it can "
            "cost or add, open.* where the data decides nothing, passes.* and fails.* the sources for "
            "which the condition passes or fails, triage.* one class of the before and after "
            "comparison, and evidence the proof steps."
        )
    )


class AssessmentFindingInput(selectors.ToolInput):
    """One entry of a run's stored result."""

    mode: Literal["finding"]
    run_id: str = Field(min_length=1, max_length=200, description="The run id.")
    finding_id: str = Field(
        min_length=1,
        max_length=200,
        description=(
            "The entry's reference, as the page context names it: finding:<id>, or finding:@<n> for "
            "the finding at position n counted from 0; gap:<id> or gap:@<n>; domain:<name>; "
            "outcome:@0; verification:@0. An id without a kind names a finding."
        ),
    )
    assessment_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        description="The assessment id; when given, the run must be one of its runs.",
    )


class AssessmentSessionInput(selectors.ToolInput):
    """One analysis session revision."""

    mode: Literal["analysis_session"]
    session_id: str = Field(min_length=1, max_length=200, description="The analysis session id.")
    revision: int | None = Field(
        default=None, ge=1, le=2**31 - 1, description="The session revision; the newest when omitted."
    )


class AssessmentReadInput(
    RootModel[
        Annotated[
            # `AssessmentFindingsInput` is the first member. A flat signature keeps the
            # bound of the first mode on a shared field, and the paged limit of
            # findings is wider than the list limit.
            AssessmentFindingsInput
            | AssessmentRunInput
            | AssessmentListInput
            | AssessmentFindingInput
            | AssessmentSessionInput,
            Field(discriminator="mode"),
        ]
    ]
):
    """mode: list lists saved assessments; mode: run reads one run; mode: findings pages one result
    bucket of a run; mode: finding reads one entry of a run's result; mode: analysis_session reads
    one analysis session."""


class AssessmentReadResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    mode: Literal["list", "run", "findings", "finding", "analysis_session"]
    items: list[Any] | None = None
    run: dict[str, Any] | None = None
    finding: dict[str, Any] | None = Field(
        default=None, description="mode: finding; the entry, its reference and its record"
    )
    session: dict[str, Any] | None = Field(default=None, description="mode: analysis_session; the session")
    snapshot_matches: bool | None = Field(
        default=None, description="whether the selected snapshot is one the run was computed from"
    )


async def read_saved_assessments(
    settings: Any, run_id: str | None, limit: int, *, store: Any = None, snapshot_refs: bool = False
) -> dict[str, Any]:
    """`read_saved`, the body of `mode: list` and `mode: run`, with every
    failure raised as a `ToolError`.

    With `store`, the given app store is read. Without it, `read_saved`
    opens a `PgStore` and disposes of it. A limit outside 1 to 100
    is `invalid_argument`, a run id with no record is `not_found`, a run past
    the tool byte limit is `limit_exceeded`, and a failed store read is
    mapped by `store_error`. Another exception propagates.
    """
    from hst.assessment.read import read_saved

    if not 1 <= limit <= MAX_ASSESSMENTS:
        raise ToolError("invalid_argument", f"limit must be between 1 and {MAX_ASSESSMENTS}", field="limit")
    if store is not None:
        require(store, "list_assessments", "saved assessments")
    try:
        body = await read_saved(settings, run_id, limit, store=store, snapshot_refs=snapshot_refs)
    except Exception as exc:
        error = store_error(exc)
        if error is None:
            raise
        raise error from None
    if "error" in body:
        if "not found" in str(body["error"]):
            raise ToolError("not_found", f"no assessment run {run_id!r}", field="run_id")
        raise ToolError("limit_exceeded", str(body["error"]), field="run_id")
    return body


def _read_saved(ctx: ToolContext, run_id: str | None, limit: int) -> dict[str, Any]:
    async def work(store: Any) -> dict[str, Any]:
        return await read_saved_assessments(ctx.settings, run_id, limit, store=store, snapshot_refs=True)

    return jsonable(read_store(ctx, work))


def _list(ctx: ToolContext, params: AssessmentListInput) -> str:
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "assessment_read", params, session)
        body = _read_saved(ctx, None, params.limit)
        selected = call.snapshot.snapshot_id
        stored = ItemEvidence.of(completeness("stored"), basis="stored").model_dump(mode="json")
        items = [
            {
                **{key: value for key, value in record.items() if key != "runs"},
                "runs": [
                    {
                        **{key: value for key, value in run.items() if key != "snapshot_refs"},
                        "snapshot_matches": snapshot_matches(run.get("snapshot_refs"), selected),
                    }
                    for run in record.get("runs", [])
                ],
                "evidence": stored,
            }
            for record in body["assessments"]
        ]
        truncated = len(items) >= params.limit
        return call.finish(
            session,
            result={"mode": "list", "items": items},
            evidence=Evidence(result=whole_result(i["evidence"]["result"] for i in items)),
            page=PageOut(truncated=truncated, total=None if truncated else len(items), limit=params.limit),
            engine_function="hst.assessment.read.read_saved",
        )


def _run(ctx: ToolContext, params: AssessmentRunInput) -> str:
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "assessment_read", params, session)
        body = _read_saved(ctx, params.run_id, 1)
        run = body["run"]
        matches = snapshot_matches(run.get("snapshot_refs"), call.snapshot.snapshot_id)
        unknowns = []
        if matches is False:
            unknowns.append(
                f"the run was computed from other runs than the selected snapshot {call.snapshot.snapshot_id}"
            )
        if run.get("state") != "completed":
            unknowns.append(f"the run is {run.get('state')}, so it records no complete result")
        result = run.get("result") if isinstance(run.get("result"), dict) else {}
        gaps, gaps_truncated = gap_list(g for g in result.get("gaps") or () if isinstance(g, dict))
        return call.finish(
            session,
            result={
                "mode": "run",
                "run": run,
                "freshness": body.get("freshness"),
                "snapshot_matches": matches,
            },
            evidence=Evidence(
                result=run_result(str(run.get("state")), result),
                gaps=gaps,
                gaps_truncated=gaps_truncated,
                unknowns=unknowns,
            ),
            engine_function="hst.assessment.read.read_saved",
        )


def _findings(ctx: ToolContext, params: AssessmentFindingsInput) -> str:
    from fastapi import HTTPException

    from hst.assessment.direct import run_isolated

    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "assessment_read", params, session)

        async def work(store: Any) -> Any:
            require(store, "get_analysis_run", "assessment runs")
            return await store.get_analysis_run(params.run_id)

        run = read_store(ctx, work)
        if run is None or run.assessment_id != params.assessment_id:
            raise ToolError(
                "not_found",
                f"no run {params.run_id!r} of assessment {params.assessment_id!r}",
                field="run_id",
            )
        reference = (run.result or {}).get("symbolic", {}).get("artifact_ref")
        if reference is None:
            raise ToolError(
                "conflict",
                "this run retains no symbolic result artifact, so it has no result buckets; "
                "mode: run returns its stored result",
                field="run_id",
            )
        try:
            page = run_isolated(
                ctx.settings,
                {
                    "analysis": {"kind": "symbolic-page"},
                    "snapshot_refs": run.snapshot_refs,
                    "artifact_ref": reference,
                    "bucket": params.bucket,
                    "offset": call.pager.offset,
                    "limit": params.limit,
                },
            )
        except HTTPException as exc:
            raise http_error(exc, field="run_id") from None
        page = jsonable(page)
        evidence = bucket_evidence(params.bucket)
        next_offset = page.get("next_offset")
        count = page.get("count")
        items, page_out = call.pager.take(
            [
                {"item": item, "evidence": evidence.model_dump(mode="json")} if evidence is not None else item
                for item in page.get("items") or []
            ],
            total=count if isinstance(count, int) else None,
            more=next_offset is not None,
        )
        matches = snapshot_matches(run.snapshot_refs, call.snapshot.snapshot_id)
        unknowns = []
        if matches is False:
            unknowns.append(
                f"the run was computed from other runs than the selected snapshot {call.snapshot.snapshot_id}"
            )
        whole = (
            completeness("stored")
            if evidence is None
            else evidence.result
            if items
            else completeness("empty", missing=unknowns_missing(unknowns))
        )
        return call.finish(
            session,
            result={
                "mode": "findings",
                "bucket": params.bucket,
                "items": items,
                "count": count,
                "count_decimal": page.get("count_decimal"),
                "artifact_sha256": page.get("artifact_sha256"),
                "snapshot_matches": matches,
            },
            evidence=Evidence(result=whole, unknowns=unknowns),
            page=page_out,
            engine="symbolic-v2",
            engine_function="hst.assessment.result_page.execute_page",
        )


def _finding(ctx: ToolContext, params: AssessmentFindingInput) -> str:
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "assessment_read", params, session)

        async def work(store: Any) -> Any:
            require(store, "get_analysis_run", "assessment runs")
            return await store.get_analysis_run(params.run_id)

        run = read_store(ctx, work)
        if run is None or (params.assessment_id is not None and run.assessment_id != params.assessment_id):
            owner = f" of assessment {params.assessment_id!r}" if params.assessment_id is not None else ""
            raise ToolError("not_found", f"no run {params.run_id!r}{owner}", field="run_id")
        if not isinstance(run.result, dict):
            raise ToolError(
                "conflict",
                f"the run is {run.state} and records no result, so it has no findings",
                field="run_id",
            )
        located = findings_mod.locate(run.result, run.kind, params.finding_id)
        if located is None:
            raise ToolError(
                "not_found", f"run {params.run_id!r} holds no entry {params.finding_id!r}", field="finding_id"
            )
        # The answer also lists a gap entry under evidence.gaps.
        limit = MAX_RECORD_CHARS // 2 if located.kind == "gap" else MAX_RECORD_CHARS
        record, chars, cut = bounded_record(jsonable(located.record), limit)
        matches = snapshot_matches(run.snapshot_refs, call.snapshot.snapshot_id)
        unknowns = [_other_runs(call.snapshot.snapshot_id)] if matches is False else []
        if run.state != "completed":
            unknowns.append(f"the run is {run.state}, so it records no complete result")
        if cut:
            unknowns.append(_cut_note(chars, limit))
        gaps, gaps_truncated = (
            gap_list([record]) if located.kind == "gap" and isinstance(record, dict) else ([], False)
        )
        return call.finish(
            session,
            result={
                "mode": "finding",
                "run": {
                    "id": run.id,
                    "assessment_id": run.assessment_id,
                    "assessment_revision": run.assessment_revision,
                    "kind": run.kind,
                    "state": run.state,
                    "snapshot_refs": jsonable(run.snapshot_refs),
                },
                "finding": {
                    "id": params.finding_id,
                    "reference": located.reference,
                    "kind": located.kind,
                    "index": located.index,
                    "record": record,
                    "record_chars": chars,
                    "record_truncated": cut,
                },
                "snapshot_matches": matches,
            },
            evidence=Evidence(
                result=entry_result(located, run.state, run.result),
                gaps=gaps,
                gaps_truncated=gaps_truncated,
                unknowns=unknowns,
            ),
            engine_function="hst.assessment.findings.locate",
        )


def _analysis_session(ctx: ToolContext, params: AssessmentSessionInput) -> str:
    from hst.app.routes.analysis_sessions import (
        _coverage,
        _result,
        older_run,
        stored_session,
    )

    def read(record: Any) -> Any:
        try:
            return stored_session(record.definition)
        except ValueError as exc:
            raise ToolError(
                "internal",
                f"the stored analysis session {record.id} revision {record.revision} cannot be read: {exc}",
                field="session_id",
            ) from None

    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "assessment_read", params, session)

        async def work(store: Any) -> tuple[Any, list[tuple[dict[str, Any], Any]]]:
            require(store, "get_analysis_session", "analysis sessions")
            record = await store.get_analysis_session(params.session_id, params.revision)
            runs: list[tuple[dict[str, Any], Any]] = []
            if record is None:
                return None, runs
            # read as the session routes read it
            for item in read(record).runs:
                summary = item.model_dump(mode="json")
                runs.append((summary, await store.get_analysis_run(item.id)))
            return record, runs

        record, runs = read_store(ctx, work)
        if record is None:
            at = f" at revision {params.revision}" if params.revision is not None else ""
            raise ToolError("not_found", f"no analysis session {params.session_id!r}{at}", field="session_id")
        # the input as the session routes present it (a field outside the model left out)
        definition = read(record).model_dump(mode="json")
        results = record.results if isinstance(record.results, dict) else {}
        stated = definition.get("input")
        analysis_input: dict[str, Any] = stated if isinstance(stated, dict) else {}
        rows = []
        for summary, run in runs:
            if run is None:
                rows.append(
                    {key: summary.get(key) for key in ("id", "item_id", "execution", "result", "coverage")}
                )
                continue
            completed = run.state == "completed"
            rows.append(
                {
                    "id": run.id,
                    "item_id": summary.get("item_id"),
                    "execution": run.state,
                    "result": _result(run.result) if completed else None,
                    "coverage": _coverage(run.result) if completed else "not_started",
                }
            )
        body, chars, cut = bounded_record(
            jsonable(
                {
                    "id": record.id,
                    "revision": record.revision,
                    "title": record.title,
                    "created_at": record.created_at,
                    "created_by": record.created_by,
                    "kind": analysis_input.get("kind"),
                    "input": analysis_input,
                    "legacy_assessment": definition.get("legacy_assessment"),
                    "runs": rows,
                    "review": results.get("review"),
                    "bindings": results.get("bindings"),
                }
            )
        )
        pinned = analysis_input.get("snapshot")
        recorded = pinned.get("snapshot") if isinstance(pinned, dict) else None
        matches = None if recorded is None else str(recorded) == call.snapshot.snapshot_id
        unknowns = [_other_runs(call.snapshot.snapshot_id)] if matches is False else []
        unknowns += [
            f"run {row['id']} is {row['execution']}, so it records no complete result"
            for row in rows
            if row.get("execution") != "completed"
        ]
        # runs every session read leaves out (`stored_session`)
        left_out = sum(1 for run in record.definition.get("runs") or [] if older_run(run))
        if left_out:
            unknowns.append(
                f"{left_out} run stored with an outcome and no result is not shown"
                if left_out == 1
                else f"{left_out} runs stored with an outcome and no result are not shown"
            )
        if cut:
            unknowns.append(_cut_note(chars))
        answers = [answer for row in rows if isinstance(answer := row.get("result"), dict)]
        whole = (
            whole_result(answers) if answers else completeness("stored", missing=unknowns_missing(unknowns))
        )
        return call.finish(
            session,
            result={
                "mode": "analysis_session",
                "session": body,
                "session_chars": chars,
                "session_truncated": cut,
                "snapshot_matches": matches,
            },
            evidence=Evidence(result=whole, unknowns=unknowns),
            engine_function="hst.assessment.store.AssessmentStoreMixin.get_analysis_session",
        )


def assessment_read(
    ctx: ToolContext,
    params: AssessmentListInput
    | AssessmentRunInput
    | AssessmentFindingsInput
    | AssessmentFindingInput
    | AssessmentSessionInput,
) -> str:
    if isinstance(params, AssessmentListInput):
        return _list(ctx, params)
    if isinstance(params, AssessmentRunInput):
        return _run(ctx, params)
    if isinstance(params, AssessmentFindingInput):
        return _finding(ctx, params)
    if isinstance(params, AssessmentSessionInput):
        return _analysis_session(ctx, params)
    return _findings(ctx, params)


def register(registry: ToolRegistry) -> None:
    registry.register(
        catalogue_spec(
            name="assessment_read",
            version=4,
            description=(
                "Read saved assessments; nothing is computed again. mode: list lists the saved "
                "assessments, newest first, with freshness and their five newest runs, each with "
                "snapshot_matches. mode: run reads one recorded run: its inputs, state, snapshot "
                "references and stored result. mode: findings pages one result bucket of a run that "
                "retains a symbolic result artifact (decided_change, open_change, open, passes, fails, "
                "triage or evidence); a run without one is the error conflict. The "
                "bucket name gives each item's evidence. mode: finding reads one finding, evidence gap, "
                "failure domain, outcome or verification comparison of a run by the reference the page "
                "context names, looked up in the run's stored result; an entry the run does not hold "
                "is the error not_found. mode: analysis_session reads one analysis session: its input, "
                "its runs with execution, result and coverage, and its review; change_get_simulation "
                "reads a simulation run's flows. Both cut a long record so the answer fits one read."
            ),
            input_model=AssessmentReadInput,
            result_model=AssessmentReadResult,
            run=assessment_read,
        )
    )
