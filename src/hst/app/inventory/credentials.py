"""Sealing, drafts, rotation and repair of credential material."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from hst.app.crypto import SecretKeyError, decrypt_secrets, encrypt_secrets
from hst.app.inventory import field_metadata as _fm
from hst.app.inventory.contracts import REDACTED, FieldCategory
from hst.app.inventory.repository import InventoryTx
from hst.app.store import CollectionCredentialVersion, CollectionProfileVersion


class CredentialUnreadable(Exception):
    """The sealed blob does not open under the current data key. The message
    holds the credential id and the revision."""

    def __init__(self, credential_id: UUID, revision: int):
        self.credential_id = credential_id
        self.revision = revision
        super().__init__(
            f"credential {credential_id} revision {revision} cannot be decrypted; repair required"
        )


class SecretsRejected(ValueError):
    """A submitted secret map is invalid. `problems` maps each path to a reason."""

    def __init__(self, problems: dict[str, str]):
        self.problems = problems
        listed = ", ".join(f"{p}: {r}" for p, r in sorted(problems.items()))
        super().__init__(f"invalid secrets: {listed}")


# --- sealing ------------------------------------------------------------------------------


def seal(key: str, secrets: Mapping[str, str]) -> bytes:
    return encrypt_secrets(key, dict(secrets))


def open_sealed(key: str, version: CollectionCredentialVersion) -> dict[str, str]:
    try:
        return decrypt_secrets(key, version.sealed)
    except SecretKeyError as exc:
        raise CredentialUnreadable(version.credential_id, version.revision) from exc


def is_readable(key: str, version: CollectionCredentialVersion) -> bool:
    try:
        open_sealed(key, version)
    except CredentialUnreadable:
        return False
    return True


# --- validation -----------------------------------------------------------------------------


def validate_secret_map(collector_types: Iterable[str], secrets: Mapping[str, Any]) -> dict[str, str]:
    """Checks a submitted secret map. The map holds at least 1 secret. Every
    path is a credential-category path of every collector type in
    `collector_types`. Every value is a non-empty string. Returns the map as
    `dict[str, str]`. Raises `SecretsRejected` with the problems."""
    types = sorted(set(collector_types))
    problems: dict[str, str] = {}
    out: dict[str, str] = {}
    if not secrets:
        problems["*"] = "at least one secret is required"
    for path, value in secrets.items():
        if not isinstance(path, str) or not path:
            problems[str(path)] = "path must be a non-empty string"
            continue
        if not isinstance(value, str) or value == "":
            problems[path] = "value must be a non-empty string"
            continue
        for ctype in types:
            coll = _fm.COLLECTORS.get(ctype)
            if coll is None:
                problems[path] = f"unknown collector type {ctype!r}"
                continue
            if not any(f.path == path and f.category == FieldCategory.CREDENTIAL.value for f in coll.fields):
                problems[path] = f"not a credential field of {ctype}"
        out[path] = value
    if problems:
        raise SecretsRejected(problems)
    return out


def secret_paths_for(collector_type: str) -> frozenset[str]:
    return _fm.secret_paths(collector_type)


# --- drafts and digests -----------------------------------------------------------------------


def _bind(actor_id: int, token_hint: str) -> str:
    return f"{actor_id}:{token_hint}"


def seal_draft(key: str, actor_id: int, secrets: Mapping[str, str], *, hint: str) -> bytes:
    """Seal new material for a preview together with the actor and a
    per-preview hint."""
    body = {"bind": _bind(actor_id, hint), "secrets": dict(secrets)}
    return encrypt_secrets(key, {"draft": json.dumps(body, sort_keys=True)})


def open_draft(key: str, actor_id: int, sealed: bytes, *, hint: str) -> dict[str, str]:
    try:
        outer = decrypt_secrets(key, sealed)
    except SecretKeyError as exc:
        raise ValueError("secret draft cannot be opened") from exc
    body = json.loads(outer.get("draft", "{}"))
    if body.get("bind") != _bind(actor_id, hint):
        raise ValueError("secret draft is bound to another preview")
    secrets = body.get("secrets")
    if not isinstance(secrets, dict):
        raise ValueError("secret draft is malformed")
    return {str(k): str(v) for k, v in secrets.items()}


def request_digest(key: str, parts: Mapping[str, Any]) -> str:
    """The keyed digest of a request for the idempotency comparison. It is the
    HMAC-SHA256 under the data key over the canonical JSON of `parts`."""
    canonical = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str)
    return hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def redact_secret_names(paths: Iterable[str]) -> dict[str, str]:
    """The shape of a secret map in an event and in a preview. Every path maps
    to the mask `REDACTED`."""
    return dict.fromkeys(sorted(paths), REDACTED)


# --- rotation and repair ----------------------------------------------------------------------


async def rotate(
    tx: InventoryTx,
    key: str,
    credential_id: UUID,
    secrets: Mapping[str, str],
    *,
    expected_revision: int,
    actor_id: int | None,
    now: datetime,
    request_id: str | None = None,
    profile_revisions: Mapping[UUID, int] | None = None,
) -> tuple[CollectionCredentialVersion, list[CollectionProfileVersion]]:
    """Write a new credential version and re-pin every profile that pins the
    credential, in the transaction of the caller. `profile_revisions` holds
    the expected profile revisions of a preview. `add_profile_version` raises
    StaleRevision for a profile at another revision, and the rotation rolls
    back. A repair is the same call. The new version supersedes the unreadable
    version. The unreadable version stays in the store as ciphertext."""
    credential = await tx.get_credential(credential_id)
    if credential is None:
        from hst.app.inventory.repository import NotFound

        raise NotFound("credential not found")
    version = await tx.add_credential_version(
        credential_id,
        expected_revision=expected_revision,
        sealed=seal(key, secrets),
        secret_paths=sorted(secrets),
        actor_id=actor_id,
        now=now,
    )
    repinned: list[CollectionProfileVersion] = []
    for profile_id in await tx.profiles_pinning_credential(credential_id):
        profile = await tx.get_profile(profile_id)
        if profile is None or profile.archived_at is not None:
            continue
        current = await tx.get_profile_version(profile_id, profile.current_revision)
        if current is None or current.credential_id != credential_id:
            continue
        expected = (
            profile_revisions.get(profile_id, profile.current_revision)
            if profile_revisions is not None
            else profile.current_revision
        )
        new_version = await tx.add_profile_version(
            profile_id,
            expected_revision=expected,
            settings=dict(current.settings),
            credential_id=credential_id,
            credential_revision=version.revision,
            actor_id=actor_id,
            now=now,
        )
        repinned.append(new_version)
        await tx.append_event(
            entity_type="profile",
            entity_id=str(profile_id),
            actor_id=actor_id,
            action="credential_rotated",
            now=now,
            before={"revision": current.revision, "credential_revision": current.credential_revision},
            after={"revision": new_version.revision, "credential_revision": version.revision},
            request_id=request_id,
        )
    await tx.append_event(
        entity_type="credential",
        entity_id=str(credential_id),
        actor_id=actor_id,
        action="rotated",
        now=now,
        before={"revision": credential.current_revision},
        after={"revision": version.revision, "secrets": redact_secret_names(secrets)},
        request_id=request_id,
        sensitive=True,
    )
    return version, repinned


async def affected_profiles(tx: InventoryTx, credential_id: UUID) -> list[UUID]:
    """The profiles whose current revision pins the credential. A rotation
    re-pins them and a preview lists them."""
    out: list[UUID] = []
    for profile_id in await tx.profiles_pinning_credential(credential_id):
        profile = await tx.get_profile(profile_id)
        if profile is None or profile.archived_at is not None:
            continue
        current = await tx.get_profile_version(profile_id, profile.current_revision)
        if current is not None and current.credential_id == credential_id:
            out.append(profile_id)
    return out


def collector_types_of(profiles: Sequence[Any]) -> set[str]:
    return {p.collector_type for p in profiles}
