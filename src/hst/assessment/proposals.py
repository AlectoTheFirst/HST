"""Save a verified repair finding as a change proposal that references its source run."""

from __future__ import annotations

from typing import Any

from hst.assessment.store import ChangeRevision, input_digest, verified_answer


async def save_proposal(
    store: Any,
    run_id: str,
    *,
    finding_index: int,
    title: str,
    actor: int | None,
    change_id: str | None = None,
    expected_revision: int = 0,
) -> ChangeRevision:
    run = await store.get_analysis_run(run_id)
    if run is None or run.kind != "repair" or not run.result:
        raise ValueError("a recorded repair result is required")
    findings = run.result.get("findings", [])
    if type(finding_index) is not int or not 0 <= finding_index < len(findings):
        raise ValueError("proposal finding does not exist")
    proposal = findings[finding_index]
    if proposal.get("verified") is not True or not verified_answer(proposal):
        raise ValueError(
            "only a result that verifies the desired requirement and every protection "
            "can be saved as a proposal"
        )
    definition = {
        "intents": proposal["intents"],
        "preconditions": proposal.get("preconditions", []),
        "source_run_id": run.id,
        "source_assessment_id": run.assessment_id,
        "source_assessment_revision": run.assessment_revision,
        "finding_index": finding_index,
        "finding_digest": input_digest(proposal),
        "result_digest": input_digest(run.result),
        "snapshot_refs": run.snapshot_refs,
        "engine_version": run.engine_version,
        "requirements": run.inputs.get("definition", {}),
        "protected": run.inputs.get("analysis", {}).get("protected", []),
        "verified_result": proposal,
        "candidate_ids": proposal.get("candidates", []),
    }
    return await store.create_change_revision(
        title=title,
        definition=definition,
        created_by=actor,
        change_id=change_id,
        expected_revision=expected_revision,
    )
