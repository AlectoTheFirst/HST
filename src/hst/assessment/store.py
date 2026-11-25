"""Immutable assessment revisions and a separately budgeted durable analysis queue."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import uuid
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_PENDING_PER_ACTOR = 8
RUN_STATES = ("queued", "running", "completed", "failed", "cancelled")
# Keys the store sets on a content-addressed record. A caller's values for them are dropped.
_RECORD_KEYS = frozenset({"id", "revision", "digest"})


def utcnow() -> datetime:
    return datetime.now(UTC)


def bounded_json(value: Any) -> Any:
    """Copy JSON values and reject non-finite numbers and oversized documents."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode()) > MAX_DOCUMENT_BYTES:
        raise ValueError("assessment document exceeds 8 MiB")
    return json.loads(encoded)


def input_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(bounded_json(value), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def verified_answer(finding: Any) -> bool:
    """Whether the combined result, the desired requirement and each protection of a
    stored repair finding answer `true`."""
    from hst.results.project import answer_of

    if not isinstance(finding, dict):
        return False
    protected = finding.get("protected", {})
    return (
        answer_of(finding.get("result")) == "true"
        and answer_of(finding.get("desired")) == "true"
        and isinstance(protected, dict)
        and all(answer_of(value) == "true" for value in protected.values())
    )


class RevisionConflict(ValueError):
    """The author edited an obsolete revision."""


class AnalysisCapacityError(ValueError):
    """The actor already has the maximum admitted unfinished work."""


@dataclass(frozen=True)
class RequirementRevision:
    id: str
    revision: int
    title: str
    definition: dict
    created_by: int | None
    created_at: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class AssessmentRevision(RequirementRevision):
    purpose: str = "evaluation"


@dataclass(frozen=True)
class ChangeRevision(RequirementRevision):
    """Ordered change inputs, including immutable verified-proposal provenance."""


@dataclass(frozen=True)
class ApplicationRevision:
    id: str
    revision: int
    name: str
    definition: dict
    digest: str
    created_by: int | None
    created_at: str
    origin: dict | None = None

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class AnalysisSessionRevision:
    id: str
    revision: int
    title: str
    definition: dict
    results: dict
    created_by: int | None
    created_at: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class AnalysisRun:
    id: str
    assessment_id: str
    assessment_revision: int
    kind: str
    inputs: dict
    input_digest: str
    snapshot_refs: list[dict]
    engine_version: str
    created_by: int | None
    created_at: str
    limits: dict = field(default_factory=dict)
    retry_of: str | None = None
    input_schema_version: int = 1
    state: str = "queued"
    attempt: int = 0
    lease_token: str | None = None
    lease_expires_at: str | None = None
    claimed_by: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    cancel_requested: bool = False
    progress: dict = field(default_factory=dict)
    checkpoint: dict = field(default_factory=dict)
    result: dict | None = None
    error: str | None = None
    dependencies: list[dict] = field(default_factory=list)
    replay: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


class AssessmentTransaction(Protocol):
    async def get(self, kind: str, identifier: str, revision: int | None = None) -> dict | None: ...
    async def list(
        self, kind: str, *, filters: dict | None = None, limit: int = 100, latest: bool = False
    ) -> list[dict]: ...
    async def put(self, kind: str, document: dict, *, replace: bool = False) -> None: ...


class AssessmentStore(Protocol):
    async def create_analysis_session(
        self,
        *,
        title: str,
        definition: dict,
        results: dict,
        created_by: int | None,
        session_id: str | None = None,
        expected_revision: int = 0,
    ) -> AnalysisSessionRevision: ...
    async def get_analysis_session(
        self, session_id: str, revision: int | None = None
    ) -> AnalysisSessionRevision | None: ...
    async def list_analysis_sessions(self, limit: int = 100) -> list[AnalysisSessionRevision]: ...
    async def list_application_analysis_sessions(
        self, application_id: str, limit: int = 100
    ) -> list[AnalysisSessionRevision]: ...
    async def list_analysis_session_revisions(
        self, session_id: str, limit: int = 100
    ) -> list[AnalysisSessionRevision]: ...

    async def create_application_revision(
        self,
        *,
        definition: dict,
        digest: str,
        created_by: int | None,
        expected_revision: int = 0,
        expected_digest: str | None = None,
        origin: dict | None = None,
    ) -> ApplicationRevision: ...
    async def get_application(
        self, application_id: str, revision: int | None = None
    ) -> ApplicationRevision | None: ...
    async def list_applications(self, limit: int = 100) -> list[ApplicationRevision]: ...
    async def list_application_revisions(
        self, application_id: str, limit: int = 100
    ) -> list[ApplicationRevision]: ...
    async def save_application_resolution(self, resolution: dict) -> dict: ...
    async def get_application_resolution(self, digest: str) -> dict | None: ...
    async def save_application_validation(self, validation: dict) -> dict: ...
    async def get_application_validation(self, digest: str) -> dict | None: ...
    async def save_application_generation(self, generation: dict) -> dict: ...
    async def get_application_generation(self, generation_id: str) -> dict | None: ...

    async def create_requirement(
        self,
        *,
        title: str,
        definition: dict,
        created_by: int | None,
        requirement_id: str | None = None,
        expected_revision: int = 0,
    ) -> RequirementRevision: ...
    async def get_requirement(
        self, requirement_id: str, revision: int | None = None
    ) -> RequirementRevision | None: ...
    async def list_requirements(self, limit: int = 100) -> list[RequirementRevision]: ...
    async def create_assessment(
        self,
        *,
        title: str,
        purpose: str,
        definition: dict,
        created_by: int | None,
        assessment_id: str | None = None,
        expected_revision: int = 0,
    ) -> AssessmentRevision: ...
    async def get_assessment(
        self, assessment_id: str, revision: int | None = None
    ) -> AssessmentRevision | None: ...
    async def list_assessments(self, limit: int = 100) -> list[AssessmentRevision]: ...
    async def create_change_revision(
        self,
        *,
        title: str,
        definition: dict,
        created_by: int | None,
        change_id: str | None = None,
        expected_revision: int = 0,
    ) -> ChangeRevision: ...
    async def get_change_revision(
        self, change_id: str, revision: int | None = None
    ) -> ChangeRevision | None: ...
    async def list_change_revisions(self, change_id: str, limit: int = 100) -> list[ChangeRevision]: ...
    async def list_assessment_proposals(self, assessment_id: str) -> list[ChangeRevision]: ...

    async def set_assessment_retention(
        self,
        assessment_id: str,
        *,
        actor: int | None,
        reason: str,
        retain_until: str | None = None,
        release: bool = False,
    ) -> dict: ...
    async def get_assessment_retention(self, assessment_id: str) -> dict: ...

    async def list_assessment_batch(
        self, after_id: str = "", limit: int = 100
    ) -> list[AssessmentRevision]: ...

    async def enqueue_analysis(
        self,
        *,
        assessment_id: str,
        assessment_revision: int,
        kind: str,
        inputs: dict,
        snapshot_refs: list[dict],
        engine_version: str,
        created_by: int | None,
        limits: dict | None = None,
        retry_of: str | None = None,
    ) -> AnalysisRun: ...
    async def ensure_analysis_capacity(self, created_by: int | None, requested: int = 1) -> None: ...
    async def analysis_capacity(self, created_by: int | None) -> int: ...
    async def get_analysis_run(self, run_id: str) -> AnalysisRun | None: ...
    async def list_analysis_runs(
        self, assessment_id: str | None = None, limit: int = 100
    ) -> list[AnalysisRun]: ...
    async def claim_analysis(self, worker_id: str, lease_seconds: int = 60) -> AnalysisRun | None: ...
    async def heartbeat_analysis(
        self,
        run_id: str,
        lease_token: str,
        *,
        progress: dict | None = None,
        checkpoint: dict | None = None,
        lease_seconds: int = 60,
    ) -> bool: ...
    async def finish_analysis(
        self,
        run_id: str,
        lease_token: str,
        *,
        result: dict,
        state: str = "completed",
        dependencies: list[dict] | None = None,
        replay: dict | None = None,
        error: str | None = None,
    ) -> bool: ...
    async def cancel_analysis(self, run_id: str) -> AnalysisRun | None: ...
    async def invalidate_assessments(
        self, event_id: str, snapshot_ref: dict, changed_scopes: list[dict], engine_version: str | None = None
    ) -> list[str]: ...
    async def get_assessment_freshness(self, assessment_id: str) -> dict: ...
    async def retained_snapshot_refs(self) -> list[dict]: ...


class AssessmentStoreMixin:
    """Backend-independent invariants of the assessment store.

    An adapter supplies the atomic transactions.
    """

    def assessment_transaction(self) -> AbstractAsyncContextManager[AssessmentTransaction]:
        raise NotImplementedError

    async def create_analysis_session(
        self,
        *,
        title: str,
        definition: dict,
        results: dict,
        created_by: int | None,
        session_id: str | None = None,
        expected_revision: int = 0,
    ) -> AnalysisSessionRevision:
        document = await self._create_revision(
            "analysis-session",
            session_id,
            expected_revision,
            {
                "title": title,
                "definition": bounded_json(definition),
                "results": bounded_json(results),
                "created_by": created_by,
            },
        )
        return AnalysisSessionRevision(**document)

    async def get_analysis_session(
        self, session_id: str, revision: int | None = None
    ) -> AnalysisSessionRevision | None:
        async with self.assessment_transaction() as tx:
            value = await tx.get("analysis-session", session_id, revision)
        return AnalysisSessionRevision(**value) if value else None

    async def list_analysis_sessions(self, limit: int = 100) -> list[AnalysisSessionRevision]:
        async with self.assessment_transaction() as tx:
            values = await tx.list("analysis-session", limit=_limit(limit), latest=True)
        return [AnalysisSessionRevision(**value) for value in values]

    async def list_application_analysis_sessions(
        self, application_id: str, limit: int = 100
    ) -> list[AnalysisSessionRevision]:
        """The newest revision of each connection session that selects a
        connection of Business Application `application_id`, newest first."""
        selection = {
            "source": {"kind": "application_connection", "reference": {"application": {"id": application_id}}}
        }
        filters = {"definition": {"input": {"kind": "connection", "connections": [selection]}}}
        async with self.assessment_transaction() as tx:
            values = await tx.list("analysis-session", filters=filters, limit=_limit(limit), latest=True)
        return [AnalysisSessionRevision(**value) for value in values]

    async def list_analysis_session_revisions(
        self, session_id: str, limit: int = 100
    ) -> list[AnalysisSessionRevision]:
        async with self.assessment_transaction() as tx:
            values = await tx.list("analysis-session", filters={"id": session_id}, limit=_limit(limit))
        return [AnalysisSessionRevision(**value) for value in values]

    async def create_application_revision(
        self,
        *,
        definition: dict,
        digest: str,
        created_by: int | None,
        expected_revision: int = 0,
        expected_digest: str | None = None,
        origin: dict | None = None,
    ) -> ApplicationRevision:
        """Append a revision, or return the current one when its digest is equal.

        `origin` is stored on the revision record outside `definition`. The digest
        and the export do not include it. When `origin` names a validation, the
        `application-validation` record must exist and must hold this digest as
        `definition_digest`. If the check fails, nothing is written.
        """
        identifier = str(definition.get("id", ""))
        name = str(definition.get("name", ""))
        if not identifier or not name or len(name) > 200:
            raise ValueError("application definition requires a bounded id and name")
        if len(digest) != 64:
            raise ValueError("application digest must be SHA-256")
        definition = bounded_json(definition)
        validation = (origin or {}).get("validation")
        async with self.assessment_transaction() as tx:
            previous = await tx.get("application", identifier)
            actual = previous["revision"] if previous else 0
            if actual != expected_revision:
                raise RevisionConflict(f"expected revision {expected_revision}, current revision {actual}")
            if expected_digest is not None and (previous or {}).get("digest", "") != expected_digest:
                raise RevisionConflict("application content changed after preview")
            if validation is not None:
                validation_digest = str(validation.get("validation_digest", ""))
                record = await tx.get("application-validation", validation_digest, 1)
                if record is None:
                    raise ValueError(f"unknown application validation {validation_digest}")
                if record["definition_digest"] != digest:
                    raise ValueError(f"application validation {validation_digest} is for another definition")
            if previous and previous["digest"] == digest:
                return ApplicationRevision(**previous)
            values = {
                "id": identifier,
                "revision": actual + 1,
                "name": name,
                "definition": definition,
                "digest": digest,
                "created_by": created_by,
                "created_at": utcnow().isoformat(),
            }
            if origin is not None:
                values["origin"] = origin
            document = bounded_json(values)
            await tx.put("application", document)
        return ApplicationRevision(**document)

    async def get_application(
        self, application_id: str, revision: int | None = None
    ) -> ApplicationRevision | None:
        async with self.assessment_transaction() as tx:
            value = await tx.get("application", application_id, revision)
        return ApplicationRevision(**value) if value else None

    async def list_applications(self, limit: int = 100) -> list[ApplicationRevision]:
        async with self.assessment_transaction() as tx:
            values = await tx.list("application", limit=_limit(limit), latest=True)
        return [ApplicationRevision(**value) for value in values]

    async def list_application_revisions(
        self, application_id: str, limit: int = 100
    ) -> list[ApplicationRevision]:
        async with self.assessment_transaction() as tx:
            values = await tx.list("application", filters={"id": application_id}, limit=_limit(limit))
        return [ApplicationRevision(**value) for value in values]

    async def save_application_resolution(self, resolution: dict) -> dict:
        digest = str(resolution.get("digest", ""))
        if len(digest) != 64:
            raise ValueError("resolved scope requires a SHA-256 digest")
        document = bounded_json({"id": digest, "revision": 1, **resolution})
        async with self.assessment_transaction() as tx:
            existing = await tx.get("application-resolution", digest, 1)
            if existing is not None:
                if existing != document:
                    raise ValueError("resolved scope digest collision")
                return existing
            await tx.put("application-resolution", document)
        return document

    async def get_application_resolution(self, digest: str) -> dict | None:
        async with self.assessment_transaction() as tx:
            return await tx.get("application-resolution", digest, 1)

    async def save_application_validation(self, validation: dict) -> dict:
        """Store a validation result as an `application-validation` record.

        The store computes the digest of the content and uses it as the record
        id. An equal validation returns the stored record.
        """
        if len(str(validation.get("definition_digest", ""))) != 64:
            raise ValueError("application validation requires a SHA-256 definition digest")
        if not isinstance(validation.get("snapshot"), dict) or not validation["snapshot"].get("snapshot"):
            raise ValueError("application validation requires a pinned snapshot reference")
        content = bounded_json({key: value for key, value in validation.items() if key not in _RECORD_KEYS})
        digest = input_digest(content)
        document = bounded_json({"id": digest, "revision": 1, "digest": digest, **content})
        async with self.assessment_transaction() as tx:
            existing = await tx.get("application-validation", digest, 1)
            if existing is not None:
                return existing
            await tx.put("application-validation", document)
        return document

    async def get_application_validation(self, digest: str) -> dict | None:
        async with self.assessment_transaction() as tx:
            return await tx.get("application-validation", digest, 1)

    async def save_application_generation(self, generation: dict) -> dict:
        """Store a generation as an `application-generation` record under its id.

        The record is revision 1. A second record with the same id is refused.
        """
        identifier = str(generation.get("id", ""))
        if not identifier or len(identifier) > 128:
            raise ValueError("application generation requires a bounded id")
        document = bounded_json({**generation, "id": identifier, "revision": 1})
        async with self.assessment_transaction() as tx:
            if await tx.get("application-generation", identifier) is not None:
                raise ValueError(f"application generation {identifier} already exists")
            await tx.put("application-generation", document)
        return document

    async def get_application_generation(self, generation_id: str) -> dict | None:
        async with self.assessment_transaction() as tx:
            return await tx.get("application-generation", generation_id)

    async def _create_revision(
        self, kind: str, identifier: str | None, expected_revision: int, values: dict
    ) -> dict:
        identifier = identifier or str(uuid.uuid4())
        if expected_revision < 0:
            raise ValueError("expected_revision must be nonnegative")
        if not values["title"].strip() or len(values["title"]) > 240:
            raise ValueError("title must contain 1 to 240 characters")
        async with self.assessment_transaction() as tx:
            previous = await tx.get(kind, identifier)
            actual = previous["revision"] if previous else 0
            if actual != expected_revision:
                raise RevisionConflict(f"expected revision {expected_revision}, current revision {actual}")
            document = bounded_json(
                {"id": identifier, "revision": actual + 1, "created_at": utcnow().isoformat(), **values}
            )
            await tx.put(kind, document)
            if (
                kind == "assessment"
                and previous
                and not _same_definition(previous["definition"], document["definition"])
            ):
                await tx.put(
                    "freshness",
                    {
                        "id": identifier,
                        "revision": 1,
                        "state": "needs-reassessment",
                        "causes": ["assessment-revision"],
                        "updated_at": utcnow().isoformat(),
                    },
                    replace=True,
                )
        return document

    async def create_requirement(
        self,
        *,
        title: str,
        definition: dict,
        created_by: int | None,
        requirement_id: str | None = None,
        expected_revision: int = 0,
    ) -> RequirementRevision:
        return RequirementRevision(
            **await self._create_revision(
                "requirement",
                requirement_id,
                expected_revision,
                {"title": title, "definition": definition, "created_by": created_by},
            )
        )

    async def get_requirement(
        self, requirement_id: str, revision: int | None = None
    ) -> RequirementRevision | None:
        async with self.assessment_transaction() as tx:
            doc = await tx.get("requirement", requirement_id, revision)
        return RequirementRevision(**doc) if doc else None

    async def list_requirements(self, limit: int = 100) -> list[RequirementRevision]:
        async with self.assessment_transaction() as tx:
            rows = await tx.list("requirement", limit=_limit(limit), latest=True)
        return [RequirementRevision(**row) for row in rows]

    async def create_assessment(
        self,
        *,
        title: str,
        purpose: str,
        definition: dict,
        created_by: int | None,
        assessment_id: str | None = None,
        expected_revision: int = 0,
    ) -> AssessmentRevision:
        return AssessmentRevision(
            **await self._create_revision(
                "assessment",
                assessment_id,
                expected_revision,
                {"title": title, "purpose": purpose, "definition": definition, "created_by": created_by},
            )
        )

    async def get_assessment(
        self, assessment_id: str, revision: int | None = None
    ) -> AssessmentRevision | None:
        async with self.assessment_transaction() as tx:
            doc = await tx.get("assessment", assessment_id, revision)
        return AssessmentRevision(**doc) if doc else None

    async def list_assessments(self, limit: int = 100) -> list[AssessmentRevision]:
        async with self.assessment_transaction() as tx:
            rows = await tx.list("assessment", limit=_limit(limit), latest=True)
        return [AssessmentRevision(**row) for row in rows]

    async def create_change_revision(
        self,
        *,
        title: str,
        definition: dict,
        created_by: int | None,
        change_id: str | None = None,
        expected_revision: int = 0,
    ) -> ChangeRevision:
        intents = definition.get("intents")
        if (
            not isinstance(intents, list)
            or len(intents) > 50
            or any(not isinstance(i, dict) for i in intents)
        ):
            raise ValueError("a change revision requires at most 50 ordered intent objects")
        definition = bounded_json(definition)
        proof = None
        if definition.get("source_run_id"):
            source = await self.get_analysis_run(definition["source_run_id"])
            index = definition.get("finding_index")
            findings = source.result.get("findings", []) if source and source.result else []
            if (
                source is not None
                and source.kind == "repair"
                and type(index) is int
                and 0 <= index < len(findings)
            ):
                candidate = findings[index]
                if (
                    candidate.get("verified") is True
                    and verified_answer(candidate)
                    and candidate.get("intents") == intents
                    and candidate.get("preconditions", []) == definition.get("preconditions", [])
                    and input_digest(candidate) == definition.get("finding_digest")
                    and input_digest(source.result) == definition.get("result_digest")
                    and definition.get("source_assessment_id") == source.assessment_id
                    and definition.get("source_assessment_revision") == source.assessment_revision
                    and definition.get("snapshot_refs") == source.snapshot_refs
                    and definition.get("engine_version") == source.engine_version
                    and definition.get("requirements") == source.inputs.get("definition", {})
                    and definition.get("protected") == source.inputs.get("analysis", {}).get("protected", [])
                ):
                    proof = candidate
        definition["verification_state"] = "verified" if proof is not None else "needs-evaluation"
        definition["verified_result"] = proof
        return ChangeRevision(
            **await self._create_revision(
                "change",
                change_id,
                expected_revision,
                {"title": title, "definition": definition, "created_by": created_by},
            )
        )

    async def get_change_revision(self, change_id: str, revision: int | None = None) -> ChangeRevision | None:
        async with self.assessment_transaction() as tx:
            value = await tx.get("change", change_id, revision)
        return ChangeRevision(**value) if value else None

    async def list_change_revisions(self, change_id: str, limit: int = 100) -> list[ChangeRevision]:
        async with self.assessment_transaction() as tx:
            values = await tx.list("change", filters={"id": change_id}, limit=_limit(limit))
        return [ChangeRevision(**value) for value in values]

    async def list_assessment_proposals(self, assessment_id: str) -> list[ChangeRevision]:
        # Nested JSON references are deliberately filtered before applying a UI limit.
        async with self.assessment_transaction() as tx:
            values = await tx.list("change", limit=0, latest=True)
        return [
            ChangeRevision(**value)
            for value in values
            if value["definition"].get("source_assessment_id") == assessment_id
        ]

    async def set_assessment_retention(
        self,
        assessment_id: str,
        *,
        actor: int | None,
        reason: str,
        retain_until: str | None = None,
        release: bool = False,
    ) -> dict:
        if not reason.strip() or len(reason) > 500 or (release and retain_until is not None):
            raise ValueError("retention changes require a reason and one explicit retention policy")
        if retain_until is not None:
            timestamp = datetime.fromisoformat(retain_until)
            if timestamp.tzinfo is None:
                raise ValueError("retention deadline requires a timezone")
            retain_until = timestamp.astimezone(UTC).isoformat()
        async with self.assessment_transaction() as tx:
            if await tx.get("assessment", assessment_id) is None:
                raise ValueError("assessment does not exist")
            previous = await tx.get("retention", assessment_id)
            value = {
                "id": assessment_id,
                "revision": previous["revision"] + 1 if previous else 1,
                "created_at": utcnow().isoformat(),
                "actor": actor,
                "reason": reason,
                "retain_until": retain_until,
                "release": release,
            }
            await tx.put("retention", value)
        return value

    async def get_assessment_retention(self, assessment_id: str) -> dict:
        async with self.assessment_transaction() as tx:
            if await tx.get("assessment", assessment_id) is None:
                raise ValueError("assessment does not exist")
            value = await tx.get("retention", assessment_id)
            active = await tx.list(
                "run", filters={"assessment_id": assessment_id, "state": ["queued", "running"]}, limit=0
            )
        return {
            "policy": value or {"release": False, "retain_until": None, "revision": 0},
            "retained": _retains(value) or bool(active),
            "active_run_pins": [run["id"] for run in active],
            "state": "active-work-protected"
            if active and not _retains(value)
            else "retained"
            if _retains(value)
            else "released",
            "release_effect": (
                "Evidence becomes eligible for normal retention; recorded results remain immutable."
            ),
        }

    async def list_assessment_batch(self, after_id: str = "", limit: int = 100) -> list[AssessmentRevision]:
        async with self.assessment_transaction() as tx:
            rows = await tx.list(
                "assessment", filters={"after_id": after_id}, limit=_limit(limit), latest=True
            )
        return [AssessmentRevision(**row) for row in rows]

    async def has_pending_analysis(self, assessment_id: str) -> bool:
        async with self.assessment_transaction() as tx:
            return bool(
                await tx.list(
                    "run", filters={"assessment_id": assessment_id, "state": ["queued", "running"]}, limit=1
                )
            )

    async def analysis_capacity(self, created_by: int | None) -> int:
        """The count of further analyses that `created_by` may queue (0 to
        MAX_PENDING_PER_ACTOR). The call reserves no capacity."""
        async with self.assessment_transaction() as tx:
            pending = await tx.list(
                "run",
                filters={"created_by": created_by, "state": ["queued", "running"]},
                limit=MAX_PENDING_PER_ACTOR,
            )
        return max(0, MAX_PENDING_PER_ACTOR - len(pending))

    async def ensure_analysis_capacity(self, created_by: int | None, requested: int = 1) -> None:
        """Reserve-free admission check used inside the caller's cycle lock."""
        if requested < 1 or requested > MAX_PENDING_PER_ACTOR:
            raise AnalysisCapacityError("at most 8 unfinished analyses per actor")
        async with self.assessment_transaction() as tx:
            pending = await tx.list(
                "run",
                filters={"created_by": created_by, "state": ["queued", "running"]},
                limit=MAX_PENDING_PER_ACTOR,
            )
        if len(pending) + requested > MAX_PENDING_PER_ACTOR:
            raise AnalysisCapacityError("at most 8 unfinished analyses per actor")

    async def enqueue_analysis(
        self,
        *,
        assessment_id: str,
        assessment_revision: int,
        kind: str,
        inputs: dict,
        snapshot_refs: list[dict],
        engine_version: str,
        created_by: int | None,
        limits: dict | None = None,
        retry_of: str | None = None,
    ) -> AnalysisRun:
        if kind not in {
            "evaluation",
            "troubleshooting",
            "regression",
            "repair",
            "resilience",
            "verification",
            "evaluate",
            "troubleshoot",
            "verify",
            "simulation",
        }:
            raise ValueError("unsupported analysis kind")
        if not snapshot_refs or len(snapshot_refs) > 16 or not engine_version:
            raise ValueError("analysis requires 1 to 16 pinned snapshots and an engine version")
        if any(
            not isinstance(ref, dict)
            or not any(
                ref.get(key) is not None and str(ref[key]).strip() not in {"", "latest"}
                for key in ("snapshot", "collection_ts", "snapshot_key")
            )
            for ref in snapshot_refs
        ):
            raise ValueError("snapshot references must contain a pinned snapshot identity")
        values = bounded_json(
            {
                "assessment_id": assessment_id,
                "assessment_revision": assessment_revision,
                "kind": kind,
                "inputs": inputs,
                "snapshot_refs": snapshot_refs,
                "engine_version": engine_version,
                "limits": limits or {},
                "input_schema_version": 1,
            }
        )
        digest = input_digest(values)
        async with self.assessment_transaction() as tx:
            owner_kind = "analysis-session" if kind == "simulation" else "assessment"
            if not await tx.get(owner_kind, assessment_id, assessment_revision):
                raise ValueError(f"{owner_kind} revision does not exist")
            if retry_of:
                prior = await tx.get("run", retry_of)
                if not prior or prior["assessment_id"] != assessment_id:
                    raise ValueError("retry must reference a run of this assessment")
            else:
                matches = await tx.list("run", filters={"input_digest": digest}, limit=100)
                for match in matches:
                    if match["state"] in {"queued", "running", "completed"}:
                        return AnalysisRun(**_without_revision(match))
            pending = await tx.list(
                "run",
                filters={"created_by": created_by, "state": ["queued", "running"]},
                limit=MAX_PENDING_PER_ACTOR,
            )
            if len(pending) >= MAX_PENDING_PER_ACTOR:
                raise AnalysisCapacityError("at most 8 unfinished analyses per actor")
            run = AnalysisRun(
                id=str(uuid.uuid4()),
                input_digest=digest,
                created_at=utcnow().isoformat(),
                created_by=created_by,
                retry_of=retry_of,
                **values,
            )
            await tx.put("run", _run_document(run))
        return run

    async def get_analysis_run(self, run_id: str) -> AnalysisRun | None:
        async with self.assessment_transaction() as tx:
            doc = await tx.get("run", run_id)
        return AnalysisRun(**_without_revision(doc)) if doc else None

    async def list_analysis_runs(
        self, assessment_id: str | None = None, limit: int = 100
    ) -> list[AnalysisRun]:
        async with self.assessment_transaction() as tx:
            rows = await tx.list(
                "run",
                filters={"assessment_id": assessment_id} if assessment_id else None,
                limit=_limit(limit),
            )
        return [AnalysisRun(**_without_revision(row)) for row in rows]

    async def claim_analysis(self, worker_id: str, lease_seconds: int = 60) -> AnalysisRun | None:
        _lease(lease_seconds)
        if not worker_id:
            raise ValueError("worker identity required")
        now = utcnow()
        async with self.assessment_transaction() as tx:
            # Each process has a separate analysis concurrency budget. The
            # `claimable_at` filter returns queued runs and running runs with an expired
            # lease.
            rows = await tx.list("run", filters={"claimable_at": now.isoformat()}, limit=100)
            for doc in rows:
                if doc["cancel_requested"] or doc["attempt"] >= 3:
                    doc.update(
                        state="cancelled" if doc["cancel_requested"] else "failed",
                        finished_at=now.isoformat(),
                        lease_token=None,
                        lease_expires_at=None,
                        error=None if doc["cancel_requested"] else "Analysis worker retry limit reached.",
                    )
                    await tx.put("run", doc, replace=True)
                    continue
                break
            else:
                return None
            doc.update(
                state="running",
                claimed_by=worker_id,
                lease_token=str(uuid.uuid4()),
                lease_expires_at=(now + timedelta(seconds=lease_seconds)).isoformat(),
                started_at=doc["started_at"] or now.isoformat(),
                attempt=doc["attempt"] + 1,
            )
            await tx.put("run", doc, replace=True)
        return AnalysisRun(**_without_revision(doc))

    async def heartbeat_analysis(
        self,
        run_id: str,
        lease_token: str,
        *,
        progress: dict | None = None,
        checkpoint: dict | None = None,
        lease_seconds: int = 60,
    ) -> bool:
        _lease(lease_seconds)
        async with self.assessment_transaction() as tx:
            doc = await tx.get("run", run_id)
            if doc is None or not _owns_lease(doc, lease_token) or doc["cancel_requested"]:
                return False
            doc["lease_expires_at"] = (utcnow() + timedelta(seconds=lease_seconds)).isoformat()
            if progress is not None:
                doc["progress"] = bounded_json(progress)
            if checkpoint is not None:
                doc["checkpoint"] = bounded_json(checkpoint)
            await tx.put("run", doc, replace=True)
        return True

    async def finish_analysis(
        self,
        run_id: str,
        lease_token: str,
        *,
        result: dict,
        state: str = "completed",
        dependencies: list[dict] | None = None,
        replay: dict | None = None,
        error: str | None = None,
    ) -> bool:
        if state not in {"completed", "failed", "cancelled"}:
            raise ValueError("completion state must be completed, failed or cancelled")
        async with self.assessment_transaction() as tx:
            doc = await tx.get("run", run_id)
            if doc is None or not _owns_lease(doc, lease_token):
                return False
            # A cancelled run keeps its verified partial findings. Its result does not
            # claim a complete search.
            if doc["cancel_requested"]:
                result = {
                    **result,
                    "search_complete": False,
                    "scoped_search_complete": False,
                    "stop_reason": "cancelled",
                }
            doc.update(
                state="cancelled" if doc["cancel_requested"] else state,
                result=bounded_json(result),
                dependencies=bounded_json(dependencies or []),
                replay=bounded_json(
                    replay or {"available": False, "reason": "evidence package has not been verified"}
                ),
                error=error,
                finished_at=utcnow().isoformat(),
                lease_expires_at=None,
                lease_token=None,
            )
            await tx.put("run", doc, replace=True)
            if doc["state"] == "completed":
                current = await tx.get("assessment", doc["assessment_id"])
                fresh = await tx.get("freshness", doc["assessment_id"])
                original = await tx.get("assessment", doc["assessment_id"], doc["assessment_revision"])
                # A result computed from inputs older than a publication does not clear
                # that publication. A run clears the freshness state only if it
                # evaluates the saved definition with its intents and the definition of
                # its revision equals the current definition. A verify run evaluates the
                # definition of the deployed revision. Regression, repair and resilience
                # runs evaluate the request without intents. They clear the state only
                # when the saved definition has no intents.
                if (
                    current
                    and original
                    and clears_freshness(doc["kind"], current["definition"])
                    and _same_definition(current["definition"], original["definition"])
                    and (
                        not fresh
                        or (
                            fresh["updated_at"] <= doc["created_at"]
                            and _covers_publication(doc["snapshot_refs"], fresh.get("snapshot_ref"))
                            and (
                                not fresh.get("engine_version")
                                or fresh["engine_version"] == doc["engine_version"]
                            )
                        )
                    )
                ):
                    await tx.put(
                        "freshness",
                        {
                            "id": doc["assessment_id"],
                            "revision": 1,
                            "state": "current",
                            "causes": [],
                            "run_id": run_id,
                            "updated_at": utcnow().isoformat(),
                        },
                        replace=True,
                    )
        return True

    async def cancel_analysis(self, run_id: str) -> AnalysisRun | None:
        async with self.assessment_transaction() as tx:
            doc = await tx.get("run", run_id)
            if doc and doc["state"] in {"queued", "running"}:
                doc["cancel_requested"] = True
                if doc["state"] == "queued":
                    doc.update(state="cancelled", finished_at=utcnow().isoformat())
                await tx.put("run", doc, replace=True)
        return AnalysisRun(**_without_revision(doc)) if doc else None

    async def invalidate_assessments(
        self, event_id: str, snapshot_ref: dict, changed_scopes: list[dict], engine_version: str | None = None
    ) -> list[str]:
        if not event_id:
            raise ValueError("publication event identity required")
        changed_scopes = bounded_json(changed_scopes)
        async with self.assessment_transaction() as tx:
            if await tx.get("publication", event_id):
                return []
            affected: list[str] = []
            # A run with no dependencies is invalidated.
            assessments = await tx.list("assessment", latest=True, limit=0)
            for assessment in assessments:
                runs = await tx.list(
                    "run", filters={"assessment_id": assessment["id"], "state": "completed"}, limit=1
                )
                if not runs:
                    runs = await tx.list("run", filters={"assessment_id": assessment["id"]}, limit=1)
                if not runs:
                    continue
                run = runs[0]
                deps = run["dependencies"]
                if (engine_version is None or run["engine_version"] == engine_version) and any(
                    ref == snapshot_ref for ref in run["snapshot_refs"]
                ):
                    continue
                engine_changed = engine_version is not None and run["engine_version"] != engine_version
                delta_bases = {scope["from_snapshot"] for scope in changed_scopes if "from_snapshot" in scope}
                missed_publication = bool(delta_bases) and not any(
                    str(ref.get("snapshot")) in delta_bases for ref in run["snapshot_refs"]
                )
                relevant = (
                    missed_publication
                    or not deps
                    or not changed_scopes
                    or any(_scopes_overlap(dep, scope) for dep in deps for scope in changed_scopes)
                )
                if engine_changed or relevant:
                    affected.append(assessment["id"])
                    await tx.put(
                        "freshness",
                        {
                            "id": assessment["id"],
                            "revision": 1,
                            "state": "needs-reassessment",
                            "causes": ["engine-version" if engine_changed else "published-evidence"],
                            "event_id": event_id,
                            "engine_version": engine_version,
                            "snapshot_ref": bounded_json(snapshot_ref),
                            "updated_at": utcnow().isoformat(),
                        },
                        replace=True,
                    )
            await tx.put(
                "publication",
                {
                    "id": event_id,
                    "revision": 1,
                    "created_at": utcnow().isoformat(),
                    "assessment_ids": affected,
                    "snapshot_ref": bounded_json(snapshot_ref),
                },
            )
        return affected

    async def get_assessment_freshness(self, assessment_id: str) -> dict:
        async with self.assessment_transaction() as tx:
            assessment = await tx.get("assessment", assessment_id)
            if not assessment:
                raise ValueError("assessment does not exist")
            fresh = await tx.get("freshness", assessment_id)
            result: dict = _without_revision(fresh) if fresh else {"state": "unevaluated", "causes": []}
            seconds = assessment["definition"].get("freshness_s")
            if seconds is not None and result["state"] == "current":
                run = await tx.get("run", result["run_id"])
                observed = (
                    [ref.get("observation_floor_ms", ref.get("observed_ms")) for ref in run["snapshot_refs"]]
                    if run
                    else []
                )
                if not observed or any(value is None for value in observed):
                    result.update(state="needs-reassessment", causes=["freshness-unavailable"])
                elif utcnow().timestamp() * 1000 >= min(observed) + seconds * 1000:
                    result.update(state="needs-reassessment", causes=["freshness-expired"])
            definition = assessment["definition"]
            for kind in ("requirement", "change"):
                if not definition.get(f"{kind}_id"):
                    continue
                referenced = await tx.get(kind, definition[f"{kind}_id"])
                cause = None
                if referenced is None:
                    cause = f"{kind}-unavailable"
                elif referenced["revision"] != definition.get(f"{kind}_revision"):
                    cause = f"{kind}-revision"
                if cause:
                    result.update(
                        state="needs-reassessment",
                        causes=list(dict.fromkeys([*result.get("causes", []), cause])),
                    )
            return result

    async def retained_snapshot_refs(self) -> list[dict]:
        """Return the snapshot references that retention keeps.

        A queued or running run keeps its references. A finished run keeps its
        references unless the retention policy of its assessment releases them or
        `retain_until` has passed.
        """
        async with self.assessment_transaction() as tx:
            runs = await tx.list("run", limit=0)
            policies: dict[str, dict | None] = {}
            refs: dict[str, dict] = {}
            for run in runs:
                identifier = run["assessment_id"]
                if identifier not in policies:
                    policies[identifier] = await tx.get("retention", identifier)
                if run["state"] in {"queued", "running"} or _retains(policies[identifier]):
                    refs.update({input_digest(ref): ref for ref in run["snapshot_refs"]})
        return list(refs.values())


def _retains(policy: dict | None) -> bool:
    if policy is None:
        return True
    if policy["release"]:
        return False
    return policy["retain_until"] is None or datetime.fromisoformat(policy["retain_until"]) > utcnow()


# The run kinds that evaluate the saved definition of an assessment with its intents.
# Stored runs use "evaluation" and "troubleshooting" for the same kinds.
_FRESHNESS_KINDS = frozenset({"evaluate", "evaluation", "troubleshoot", "troubleshooting"})
# The run kinds whose baseline is the saved request without its intents.
_BASELINE_KINDS = frozenset({"regression", "repair", "resilience"})


def clears_freshness(kind: str, definition: dict) -> bool:
    """Whether a completed run of `kind` evaluates `definition` as saved."""
    return kind in _FRESHNESS_KINDS or (kind in _BASELINE_KINDS and not definition.get("intents"))


def _same_definition(left: dict, right: dict) -> bool:
    metadata = {"collection_actions", "deployments"}
    return {k: v for k, v in left.items() if k not in metadata} == {
        k: v for k, v in right.items() if k not in metadata
    }


def _covers_publication(refs: list[dict], published: dict | None) -> bool:
    """A newly queued historical run cannot clear a newer publication's staleness."""
    if not published:
        return True
    for ref in refs:
        if any(
            ref.get(key) and published.get(key) and ref[key] != published[key]
            for key in ("namespace", "estate")
        ):
            continue
        for key in ("snapshot", "collection_ts", "snapshot_key"):
            if key in published and key in ref:
                if str(ref[key]) == str(published[key]):
                    return True
                try:
                    if int(ref[key]) >= int(published[key]):
                        return True
                except (TypeError, ValueError):
                    pass
    return False


def _scopes_overlap(left: dict, right: dict) -> bool:
    # Unknown keys are not safe exclusion evidence. Omitting a dimension means
    # all values, including objects which did not exist at evaluation time.
    keys = ("namespace", "estate", "source", "host", "device", "vrf", "section", "table", "af")
    return all(not left.get(key) or not right.get(key) or left[key] == right[key] for key in keys)


def _run_document(run: AnalysisRun) -> dict:
    return {**run.as_dict(), "revision": 1}


def _without_revision(doc: dict) -> dict:
    return {key: value for key, value in doc.items() if key != "revision"}


def _owns_lease(doc: dict | None, token: str) -> bool:
    return bool(
        doc
        and doc["state"] == "running"
        and token
        and doc["lease_token"] == token
        and doc["lease_expires_at"]
        and datetime.fromisoformat(doc["lease_expires_at"]) > utcnow()
    )


def _lease(seconds: int) -> None:
    if not 1 <= seconds <= 3600:
        raise ValueError("lease must be between 1 and 3600 seconds")


def _limit(limit: int) -> int:
    if not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")
    return limit


def _contains(value: Any, pattern: Any) -> bool:
    """JSONB containment (`@>`) as the Postgres adapter applies it to a filter value.

    A mapping pattern matches when the value contains each of its keys with a contained
    item. A list pattern matches when some element of the value contains each of its
    elements."""
    if isinstance(pattern, dict):
        return isinstance(value, dict) and all(
            key in value and _contains(value[key], item) for key, item in pattern.items()
        )
    if isinstance(pattern, list):
        return isinstance(value, list) and all(
            any(_contains(element, item) for element in value) for item in pattern
        )
    return value == pattern


class _MemoryTransaction:
    def __init__(self, records: dict[tuple[str, str, int], dict]) -> None:
        self.records = records

    async def get(self, kind: str, identifier: str, revision: int | None = None) -> dict | None:
        rows = [
            doc
            for (k, i, r), doc in self.records.items()
            if k == kind and i == identifier and (revision is None or r == revision)
        ]
        return copy.deepcopy(max(rows, key=lambda row: row["revision"])) if rows else None

    async def list(
        self, kind: str, *, filters: dict | None = None, limit: int = 100, latest: bool = False
    ) -> list[dict]:
        rows = [doc for (k, _, _), doc in self.records.items() if k == kind]
        if latest:
            newest: dict[str, dict] = {}
            for row in rows:
                if row["id"] not in newest or newest[row["id"]]["revision"] < row["revision"]:
                    newest[row["id"]] = row
            rows = list(newest.values())
        for key, value in (filters or {}).items():
            if key == "after_id":
                rows = [row for row in rows if row["id"] > value]
            elif key == "claimable_at":
                now = datetime.fromisoformat(value)
                rows = [
                    row
                    for row in rows
                    if row["state"] == "queued"
                    or (
                        row["state"] == "running"
                        and row["lease_expires_at"]
                        and datetime.fromisoformat(row["lease_expires_at"]) <= now
                    )
                ]
            elif isinstance(value, dict):
                rows = [row for row in rows if _contains(row.get(key), value)]
            else:
                rows = (
                    [row for row in rows if row.get(key) in value]
                    if isinstance(value, list)
                    else [row for row in rows if row.get(key) == value]
                )
        if "after_id" in (filters or {}):
            rows.sort(key=lambda row: row["id"])
        else:
            rows.sort(
                key=lambda row: (row.get("created_at", ""), row["id"]),
                reverse="claimable_at" not in (filters or {}),
            )
        return copy.deepcopy(rows[:limit] if limit else rows)

    async def put(self, kind: str, document: dict, *, replace: bool = False) -> None:
        key = kind, document["id"], document["revision"]
        if not replace and key in self.records:
            raise RevisionConflict("revision already exists")
        self.records[key] = bounded_json(document)


class MemoryAssessmentStore(AssessmentStoreMixin):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._assessment_records: dict[tuple[str, str, int], dict] = {}
        self._assessment_lock = asyncio.Lock()

    async def get_job(self, job_id: int) -> Any:
        return copy.deepcopy(getattr(self, "jobs", {}).get(job_id))

    @asynccontextmanager
    async def assessment_transaction(self) -> AsyncIterator[AssessmentTransaction]:
        async with self._assessment_lock:
            staged = copy.deepcopy(self._assessment_records)
            yield _MemoryTransaction(staged)
            self._assessment_records = staged
