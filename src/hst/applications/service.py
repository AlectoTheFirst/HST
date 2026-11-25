"""Application revision and import orchestration above the generic store."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from hst.applications.merge import merge_application, preview_changes
from hst.applications.models import (
    BusinessApplicationDefinition,
    BusinessApplicationPatch,
    RemovalSet,
    check_application_id,
    stored_definition,
)
from hst.applications.yaml_format import (
    canonical_yaml,
    definition_digest,
    normalized_document,
    parse_application_yaml,
)
from hst.assessment.store import RevisionConflict

ImportMode = Literal["merge", "replace"]
# The source of a revision is the YAML import, the visual editor, a direct API
# call, a trace connection or a generated draft.
RevisionSource = Literal["import", "editor", "api", "trace", "generator"]


@dataclass(frozen=True)
class ImportPreview:
    application_id: str
    base_revision: int
    base_digest: str
    result_digest: str
    preview_digest: str
    definition: dict
    changes: dict[str, list[str]]
    mapping_issues: list[dict]
    no_op: bool

    def as_dict(self) -> dict:
        return {
            "application_id": self.application_id,
            "base_revision": self.base_revision,
            "base_digest": self.base_digest,
            "result_digest": self.result_digest,
            "preview_digest": self.preview_digest,
            "definition": self.definition,
            "changes": self.changes,
            "mapping_issues": self.mapping_issues,
            "no_op": self.no_op,
        }


async def preview_import(
    store: Any,
    yaml_text: str,
    removals: RemovalSet,
    mode: ImportMode = "merge",
    *,
    resolution: dict | None = None,
    validation_digest: str | None = None,
) -> ImportPreview:
    """Preview an import without writing.

    ``merge`` applies a partial document as a keyed merge onto the current
    revision. ``replace`` requires a complete definition and uses it as the
    next revision. Every omitted entity and field is removed.

    The preview does not read the graph. Without a resolution, `mapping_issues`
    holds one note for each inventory member. The note states that a pinned
    snapshot must resolve the member. `resolution` is the resolution document
    of the same definition. `validation_digest` names an
    `application-validation` record of the same definition. With either of
    them, `mapping_issues` holds the resolution issues of each inventory
    member at the snapshot of the resolution. A member of a group that the
    resolution did not read has the note `inventory-not-resolved`.
    """
    document = parse_application_yaml(yaml_text, partial=mode == "merge")
    if mode == "replace":
        if not isinstance(document, BusinessApplicationDefinition):
            raise TypeError("replace import did not produce a complete application definition")
        if removals != RemovalSet():
            raise ValueError("removals apply only to merge imports")
    elif not isinstance(document, BusinessApplicationPatch):
        raise TypeError("partial import did not produce an application patch")
    current_record = await store.get_application(document.id)
    current = stored_definition(current_record.definition) if current_record is not None else None
    merged = (
        document
        if isinstance(document, BusinessApplicationDefinition)
        else merge_application(current, document, removals)
    )
    definition = normalized_document(merged)
    result_digest = definition_digest(definition)
    base_revision = current_record.revision if current_record else 0
    base_digest = current_record.digest if current_record else ""
    token_value = {
        "application_id": document.id,
        "base_revision": base_revision,
        "base_digest": base_digest,
        "result_digest": result_digest,
        "removals": removals.model_dump(mode="json"),
        "mode": mode,
    }
    preview_digest = hashlib.sha256(
        json.dumps(token_value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if validation_digest is not None:
        record = await store.get_application_validation(validation_digest)
        if record is None:
            raise ValueError(f"unknown application validation {validation_digest}")
        if record.get("definition_digest") != result_digest:
            raise ValueError(
                f"application validation {validation_digest} was computed for another definition"
            )
        resolution = record.get("resolution")
    mapping_issues = _mapping_issues(merged, resolution)
    changes = preview_changes(current, merged)
    removes = any(values for key, values in changes.items() if key.endswith("_removed"))
    return ImportPreview(
        application_id=document.id,
        base_revision=base_revision,
        base_digest=base_digest,
        result_digest=result_digest,
        preview_digest=preview_digest,
        definition=definition,
        changes=changes,
        mapping_issues=mapping_issues,
        no_op=current_record is not None and current_record.digest == result_digest and not removes,
    )


def _mapping_issues(definition: BusinessApplicationDefinition, resolution: dict | None) -> list[dict]:
    """The notes of the inventory members of `definition` (`preview_import`)."""
    if resolution is None:
        return [
            {
                "code": "inventory-resolution-required",
                "path": f"groups.{group.id}.members.{member.id}.inventory",
                "detail": "Select a pinned snapshot to resolve this inventory reference.",
            }
            for group in definition.groups
            for member in group.members
            if member.inventory is not None
        ]
    snapshot = str((resolution.get("snapshot") or {}).get("snapshot") or "")
    resolved = resolution.get("groups") or {}
    issues: dict[str, list[dict]] = {}
    for issue in resolution.get("issues") or []:
        issues.setdefault(str(issue.get("path")), []).append(issue)
    out = []
    for group in definition.groups:
        for member in group.members:
            if member.inventory is None:
                continue
            path = f"groups.{group.id}.members.{member.id}"
            if member.id not in (resolved.get(group.id) or {}):
                # resolution reads the groups of the selected connections only
                out.append(
                    {
                        "code": "inventory-not-resolved",
                        "path": f"{path}.inventory",
                        "detail": f"No connection uses group {group.id}, so the validation at snapshot "
                        f"{snapshot} did not resolve this inventory reference.",
                    }
                )
                continue
            out.extend(
                {
                    "code": str(issue.get("code")),
                    "path": f"{path}.inventory",
                    "detail": str(issue.get("detail")),
                }
                for issue in issues.get(path, [])
            )
    return out


async def commit_import(
    store: Any,
    yaml_text: str,
    removals: RemovalSet,
    *,
    base_revision: int,
    base_digest: str,
    preview_digest: str,
    actor: int | None,
    mode: ImportMode = "merge",
    origin: dict | None = None,
) -> Any:
    preview = await preview_import(store, yaml_text, removals, mode)
    if (
        preview.base_revision != base_revision
        or preview.base_digest != base_digest
        or preview.preview_digest != preview_digest
    ):
        raise RevisionConflict("import preview is stale; preview the YAML again")
    return await store.create_application_revision(
        definition=preview.definition,
        digest=preview.result_digest,
        created_by=actor,
        expected_revision=base_revision,
        expected_digest=base_digest,
        origin=origin,
    )


async def save_definition(
    store: Any,
    definition: BusinessApplicationDefinition,
    *,
    expected_revision: int,
    actor: int | None,
    origin: dict | None = None,
) -> Any:
    """Save `definition` as the next revision. A reserved application id is
    refused with `ValueError`."""
    check_application_id(definition.id)
    value = normalized_document(definition)
    return await store.create_application_revision(
        definition=value,
        digest=definition_digest(value),
        created_by=actor,
        expected_revision=expected_revision,
        origin=origin,
    )


async def revision_origin(
    store: Any,
    source: RevisionSource,
    *,
    generation_id: str | None = None,
    validation_digest: str | None = None,
    actor: int | None = None,
) -> dict:
    """The origin a new revision records.

    A revision saved with a `generation_id` comes from a generated draft.
    `generated_digest` is the definition digest the `application-generation`
    record of that id holds when `actor`, the committing user, created that
    record. It is null when no such record is stored or another user created
    it. The `validation` summary is read from the stored
    `application-validation` record that `validation_digest` names.
    The store checks that the record was computed for the saved definition.
    """
    generated_digest = None
    if generation_id is not None and actor is not None and hasattr(store, "get_application_generation"):
        generation = await store.get_application_generation(generation_id)
        if generation is not None and generation.get("created_by") == actor:
            generated_digest = generation.get("definition_digest")
    validation = None
    if validation_digest is not None:
        record = await store.get_application_validation(validation_digest)
        if record is None:
            raise ValueError(f"unknown application validation {validation_digest}")
        snapshot = record["snapshot"]
        validation = {
            "validation_digest": record["digest"],
            "snapshot": {key: snapshot.get(key) for key in ("snapshot", "manifest_sha256", "estate")},
            "definition_digest": record["definition_digest"],
            "ready": record["ready"],
            "blocking_count": len(record["blocking"]),
        }
    return {
        "source": "generator" if generation_id is not None else source,
        "generation_id": generation_id,
        "generated_digest": generated_digest,
        "validation": validation,
    }


async def check_edit_base(
    store: Any, generation_id: str | None, *, base_revision: int, base_digest: str
) -> None:
    """Raise `RevisionConflict` when `generation_id` names an edit of a saved
    revision and the commit states another base. An edit commits only onto
    the revision it started from."""
    if generation_id is None or not hasattr(store, "get_application_generation"):
        return
    generation = await store.get_application_generation(generation_id)
    source = generation.get("source") if generation is not None else None
    if not isinstance(source, dict) or source.get("kind") != "edit":
        return
    started = source.get("base_revision")
    if (base_revision, base_digest) != (started, source.get("base_digest")):
        raise RevisionConflict(
            f"the edit started from revision {started} of {source.get('application_id')}; "
            "start the edit again from the current revision"
        )


def export_revision(record: Any) -> str:
    return canonical_yaml(stored_definition(record.definition))
