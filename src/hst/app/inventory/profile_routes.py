"""Profiles, credentials and field metadata."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request

from hst import collectors as coll
from hst.app.auth import require_permission
from hst.app.inventory import collection, credentials
from hst.app.inventory.connection_routes import (
    Validation,
    _FleetIndex,
    _generation,
    _key,
    _now,
    _profile_targets,
    _store,
    _validate_profile_shape,
    apply_profile_edit,
)
from hst.app.inventory.contracts import (
    API_PREFIX,
    CollectorFieldMetadata,
    CredentialCreate,
    CredentialPatch,
    CredentialView,
    ImpactTarget,
    ProfileCreate,
    ProfileImpact,
    ProfilePatch,
    ProfileUsage,
    ProfileVersionView,
    ProfileView,
    all_field_metadata,
)
from hst.app.inventory.repository import Conflict, InventoryTx, NotFound, StaleRevision
from hst.app.store import CollectionCredential, CollectionProfile, User

router = APIRouter(prefix=API_PREFIX)
require_runs_manage = require_permission("runs.manage")
require_sources_write = require_permission("sources.write")


# --- views ---------------------------------------------------------------------------------------


async def profile_view(tx: InventoryTx, profile: CollectionProfile) -> ProfileView:
    version = await tx.get_profile_version(profile.id, profile.current_revision)
    refs = await tx.profile_references(profile.id)
    return ProfileView(
        id=profile.id,
        display_name=profile.display_name,
        collector_type=profile.collector_type,
        current_revision=profile.current_revision,
        archived_at=profile.archived_at,
        credential_id=version.credential_id if version else None,
        credential_revision=version.credential_revision if version else None,
        settings=dict(version.settings) if version else {},
        usage=ProfileUsage(targets=len(refs.target_ids), connections=len(refs.source_ids)),
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


async def credential_view(tx: InventoryTx, cred: CollectionCredential) -> CredentialView:
    version = await tx.get_credential_version(cred.id, cred.current_revision)
    return CredentialView(
        id=cred.id,
        display_name=cred.display_name,
        current_revision=cred.current_revision,
        secret_paths=sorted(version.secret_paths) if version else [],
        archived_at=cred.archived_at,
        profiles_using=len(await credentials.affected_profiles(tx, cred.id)),
        created_at=cred.created_at,
        updated_at=cred.updated_at,
    )


async def _profile_or_404(tx: InventoryTx, profile_id: uuid.UUID) -> CollectionProfile:
    profile = await tx.get_profile(profile_id)
    if profile is None:
        raise NotFound("profile not found")
    return profile


async def _credential_or_404(tx: InventoryTx, credential_id: uuid.UUID) -> CollectionCredential:
    cred = await tx.get_credential(credential_id)
    if cred is None:
        raise NotFound("credential not found")
    return cred


# --- field metadata ---------------------------------------------------------------------------------


@router.get("/field-metadata", response_model=list[CollectorFieldMetadata])
async def field_metadata(user: User = Depends(require_runs_manage)) -> list[CollectorFieldMetadata]:
    return all_field_metadata()


# --- profiles ------------------------------------------------------------------------------------------


@router.get("/profiles", response_model=list[ProfileView])
async def list_profiles(
    request: Request,
    collector_type: str | None = None,
    include_archived: bool = False,
    user: User = Depends(require_sources_write),
) -> list[ProfileView]:
    store = _store(request)
    async with store.inventory().transaction() as tx:
        rows = await tx.list_profiles(collector_type, include_archived=include_archived)
        return [await profile_view(tx, p) for p in rows]


@router.get("/profiles/{profile_id}", response_model=ProfileView)
async def get_profile(
    request: Request, profile_id: uuid.UUID, user: User = Depends(require_sources_write)
) -> ProfileView:
    store = _store(request)
    async with store.inventory().transaction() as tx:
        return await profile_view(tx, await _profile_or_404(tx, profile_id))


@router.get("/profiles/{profile_id}/versions", response_model=list[ProfileVersionView])
async def list_profile_versions(
    request: Request, profile_id: uuid.UUID, user: User = Depends(require_sources_write)
) -> list[ProfileVersionView]:
    store = _store(request)
    async with store.inventory().transaction() as tx:
        await _profile_or_404(tx, profile_id)
        return [
            ProfileVersionView(
                profile_id=v.profile_id,
                revision=v.revision,
                settings=dict(v.settings),
                credential_id=v.credential_id,
                credential_revision=v.credential_revision,
                created_at=v.created_at,
                actor_id=str(v.actor_id) if v.actor_id is not None else None,
            )
            for v in await tx.list_profile_versions(profile_id)
        ]


@router.post("/profiles", status_code=201, response_model=ProfileView)
async def create_profile(
    request: Request, body: ProfileCreate, user: User = Depends(require_sources_write)
) -> ProfileView:
    store = _store(request)
    if body.collector_type not in coll.REGISTRY:
        raise Validation(f"unknown collector type {body.collector_type!r}")
    try:
        settings = collection.validate_profile_settings(body.collector_type, body.settings)
    except collection.SettingsRejected as exc:
        raise Validation(str(exc)) from exc
    now = _now()
    async with store.inventory().transaction() as tx:
        credential_revision: int | None = None
        secret_paths: list[str] = []
        if body.credential_id is not None:
            cred = await _credential_or_404(tx, body.credential_id)
            if cred.archived_at is not None:
                raise Validation("credential is archived")
            credential_revision = cred.current_revision
            version = await tx.get_credential_version(cred.id, cred.current_revision)
            secret_paths = list(version.secret_paths) if version else []
        _validate_profile_shape(body.collector_type, settings, secret_paths)
        profile, _version = await tx.create_profile(
            display_name=body.display_name,
            collector_type=body.collector_type,
            settings=settings,
            credential_id=body.credential_id,
            credential_revision=credential_revision,
            actor_id=user.id,
            now=now,
        )
        await tx.append_event(
            entity_type="profile",
            entity_id=str(profile.id),
            actor_id=user.id,
            action="created",
            now=now,
            after={
                "display_name": profile.display_name,
                "collector_type": profile.collector_type,
                "settings": settings,
                "credential_id": str(body.credential_id) if body.credential_id else None,
            },
        )
        return await profile_view(tx, profile)


@router.patch("/profiles/{profile_id}", response_model=ProfileView)
async def patch_profile(
    request: Request, profile_id: uuid.UUID, body: ProfilePatch, user: User = Depends(require_sources_write)
) -> ProfileView:
    """Edit a profile directly.

    A change of the settings or of the credential of a profile that more than 1 target or
    connection follows needs the `edit_profile` preview."""
    store = _store(request)
    now = _now()
    async with store.inventory().transaction() as tx:
        profile = await _profile_or_404(tx, profile_id)
        if profile.archived_at is not None:
            raise Conflict("profile is archived")
        if body.expected_revision != profile.current_revision:
            raise StaleRevision(
                f"profile is at revision {profile.current_revision}, not {body.expected_revision}",
                current_revision=profile.current_revision,
            )
        changes_revision = (
            body.settings is not None or body.credential_id is not None or body.clear_credential
        )
        if changes_revision:
            targets, connections = await _profile_targets(tx, profile_id)
            if len(targets) + len(connections) > 1:
                raise Conflict(
                    "profile is shared; edit it through the edit_profile preview",
                    references=[f"target:{t.id}" for t in targets]
                    + [f"connection:{c.source_id}" for c in connections],
                )
        if body.settings is not None:
            try:
                collection.validate_profile_settings(profile.collector_type, body.settings)
            except collection.SettingsRejected as exc:
                raise Validation(str(exc)) from exc
        await apply_profile_edit(
            tx,
            profile_id,
            expected_revision=body.expected_revision,
            display_name=body.display_name,
            settings=body.settings,
            credential_id=body.credential_id,
            clear_credential=body.clear_credential,
            actor_id=user.id,
            now=now,
        )
        return await profile_view(tx, await _profile_or_404(tx, profile_id))


@router.delete("/profiles/{profile_id}", response_model=ProfileView)
async def delete_profile(
    request: Request,
    profile_id: uuid.UUID,
    expected_revision: int,
    user: User = Depends(require_sources_write),
) -> ProfileView:
    """Archive an unused profile.

    The response is 409 with references while a target or a connection follows the profile.
    The versions of the profile stay."""
    store = _store(request)
    now = _now()
    async with store.inventory().transaction() as tx:
        profile = await _profile_or_404(tx, profile_id)
        archived = await tx.archive_profile(profile.id, expected_revision=expected_revision, now=now)
        await tx.append_event(
            entity_type="profile",
            entity_id=str(profile.id),
            actor_id=user.id,
            action="archived",
            now=now,
            before={"display_name": profile.display_name},
        )
        return await profile_view(tx, archived)


@router.get("/profiles/{profile_id}/impact", response_model=ProfileImpact)
async def profile_impact(
    request: Request, profile_id: uuid.UUID, user: User = Depends(require_sources_write)
) -> ProfileImpact:
    """Return every target that is bound to the profile explicitly or through its connection,
    every such connection and every device that those targets observe."""
    store = _store(request)
    async with store.inventory().transaction() as tx:
        profile = await _profile_or_404(tx, profile_id)
        targets, connections = await _profile_targets(tx, profile_id)
        items: list[ImpactTarget] = []
        all_devices: dict[uuid.UUID, None] = {}
        ordered = sorted(targets, key=lambda t: (t.source_key, t.host))
        observed = await _FleetIndex(tx, store).device_ids(ordered)
        for target in ordered:
            ids = observed[target.id]
            for id_ in ids:
                all_devices.setdefault(id_)
            items.append(
                ImpactTarget(
                    target_id=target.id,
                    connection_id=str(target.source_id)
                    if target.source_id is not None
                    else target.source_key,
                    host=target.host,
                    device_ids=ids,
                )
            )
        connection_ids = sorted({i.connection_id for i in items} | {str(c.source_id) for c in connections})
        return ProfileImpact(
            profile_id=profile.id,
            revision=profile.current_revision,
            targets=items,
            connection_ids=connection_ids,
            device_ids=list(all_devices),
            total_targets=len(items),
            total_devices=len(all_devices),
            generation=await _generation(tx),
        )


# --- credentials -------------------------------------------------------------------------------------------


@router.get("/credentials", response_model=list[CredentialView])
async def list_credentials(
    request: Request, include_archived: bool = False, user: User = Depends(require_sources_write)
) -> list[CredentialView]:
    store = _store(request)
    async with store.inventory().transaction() as tx:
        rows = await tx.list_credentials(include_archived=include_archived)
        return [await credential_view(tx, c) for c in rows]


@router.get("/credentials/{credential_id}", response_model=CredentialView)
async def get_credential(
    request: Request, credential_id: uuid.UUID, user: User = Depends(require_sources_write)
) -> CredentialView:
    store = _store(request)
    async with store.inventory().transaction() as tx:
        return await credential_view(tx, await _credential_or_404(tx, credential_id))


@router.post("/credentials", status_code=201, response_model=CredentialView)
async def create_credential(
    request: Request, body: CredentialCreate, user: User = Depends(require_sources_write)
) -> CredentialView:
    """Create a credential with a complete secret map.

    Each value of the map must be a non-empty string. The paths of the map are checked against
    a collector type when a profile of that type pins the credential."""
    store = _store(request)
    key = _key(request)
    secrets = body.secret_values()
    try:
        validated = credentials.validate_secret_map((), secrets)
    except credentials.SecretsRejected as exc:
        raise Validation(str(exc)) from exc
    now = _now()
    async with store.inventory().transaction() as tx:
        cred, _version = await tx.create_credential(
            display_name=body.display_name,
            sealed=credentials.seal(key, validated),
            secret_paths=sorted(validated),
            actor_id=user.id,
            now=now,
        )
        await tx.append_event(
            entity_type="credential",
            entity_id=str(cred.id),
            actor_id=user.id,
            action="created",
            now=now,
            after={"display_name": cred.display_name, "secrets": credentials.redact_secret_names(validated)},
            sensitive=True,
        )
        return await credential_view(tx, cred)


@router.patch("/credentials/{credential_id}", response_model=CredentialView)
async def patch_credential(
    request: Request,
    credential_id: uuid.UUID,
    body: CredentialPatch,
    user: User = Depends(require_sources_write),
) -> CredentialView:
    """Rename a credential, or rotate it with a complete secret map.

    A credential that more than 1 profile pins rotates through the `rotate_credential` preview.
    A rotation repairs an unreadable version. The new version supersedes the unreadable one."""
    store = _store(request)
    key = _key(request)
    now = _now()
    async with store.inventory().transaction() as tx:
        cred = await _credential_or_404(tx, credential_id)
        if cred.archived_at is not None:
            raise Conflict("credential is archived")
        if body.expected_revision != cred.current_revision:
            raise StaleRevision(
                f"credential is at revision {cred.current_revision}, not {body.expected_revision}",
                current_revision=cred.current_revision,
            )
        revision = cred.current_revision
        if body.display_name is not None and body.display_name != cred.display_name:
            cred = await tx.rename_credential(
                credential_id, body.display_name, expected_revision=revision, now=now
            )
            await tx.append_event(
                entity_type="credential",
                entity_id=str(credential_id),
                actor_id=user.id,
                action="renamed",
                now=now,
                after={"display_name": body.display_name},
            )
        secrets = body.secret_values()
        if secrets is not None:
            profile_ids = await credentials.affected_profiles(tx, credential_id)
            if len(profile_ids) > 1:
                raise Conflict(
                    "credential is pinned by several profiles; "
                    "rotate it through the rotate_credential preview",
                    references=[f"profile:{p}" for p in profile_ids],
                )
            profiles = [p for p in [await tx.get_profile(pid) for pid in profile_ids] if p is not None]
            try:
                validated = credentials.validate_secret_map(credentials.collector_types_of(profiles), secrets)
            except credentials.SecretsRejected as exc:
                raise Validation(str(exc)) from exc
            await credentials.rotate(
                tx, key, credential_id, validated, expected_revision=revision, actor_id=user.id, now=now
            )
        return await credential_view(tx, await _credential_or_404(tx, credential_id))


@router.delete("/credentials/{credential_id}", response_model=CredentialView)
async def delete_credential(
    request: Request,
    credential_id: uuid.UUID,
    expected_revision: int,
    user: User = Depends(require_sources_write),
) -> CredentialView:
    store = _store(request)
    now = _now()
    async with store.inventory().transaction() as tx:
        cred = await _credential_or_404(tx, credential_id)
        pinned = await tx.profiles_pinning_credential(credential_id)
        if pinned:
            raise Conflict("credential is in use", references=[f"profile:{p}" for p in pinned])
        archived = await tx.archive_credential(cred.id, expected_revision=expected_revision, now=now)
        await tx.append_event(
            entity_type="credential",
            entity_id=str(cred.id),
            actor_id=user.id,
            action="archived",
            now=now,
            before={"display_name": cred.display_name},
        )
        return await credential_view(tx, archived)


async def credential_repair_state(tx: InventoryTx, key: str, credential_id: uuid.UUID) -> bool:
    """Return True when the current version of the credential does not open under the current
    data key."""
    cred = await tx.get_credential(credential_id)
    if cred is None:
        return False
    version = await tx.get_credential_version(cred.id, cred.current_revision)
    return version is not None and not credentials.is_readable(key, version)
