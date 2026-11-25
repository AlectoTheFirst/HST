"""Keyed merge and explicit removal for application imports."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from hst.applications.models import BusinessApplicationDefinition, BusinessApplicationPatch, RemovalSet


def merge_application(
    current: BusinessApplicationDefinition | None,
    patch: BusinessApplicationPatch,
    removals: RemovalSet | None = None,
) -> BusinessApplicationDefinition:
    if current is not None and current.id != patch.id:
        raise ValueError("import id does not match the selected application")
    if current is None and patch.name is None:
        raise ValueError("a new application import requires name")
    base = (
        current.model_dump(mode="json")
        if current
        else {
            "schema_version": 1,
            "kind": "BusinessApplication",
            "id": patch.id,
            "name": patch.name,
            "state": "draft",
            "services": [],
            "groups": [],
            "connections": [],
        }
    )
    # The merged schema version is the higher of the revision version and the patch version.
    base["schema_version"] = max(base["schema_version"], patch.schema_version)
    supplied = patch.model_fields_set
    for field in ("name", "description", "owner", "environment", "state"):
        if field in supplied:
            base[field] = getattr(patch, field)
    for field in ("services", "groups", "connections"):
        incoming = getattr(patch, field)
        if incoming is not None:
            base[field] = _keyed_models(base.get(field, []), incoming)
    remove = removals or RemovalSet()
    for field in ("services", "groups", "connections"):
        doomed = set(getattr(remove, field))
        base[field] = [entry for entry in base[field] if entry["id"] not in doomed]
    if remove.members:
        for group in base["groups"]:
            doomed = set(remove.members.get(group["id"], []))
            group["members"] = [member for member in group.get("members", []) if member["id"] not in doomed]
    return BusinessApplicationDefinition.model_validate(base)


def preview_changes(
    current: BusinessApplicationDefinition | None, merged: BusinessApplicationDefinition
) -> dict[str, list[str]]:
    """List the entities that differ between the current and the merged definition.

    ``members_removed`` names each member that is missing from a group present in
    both definitions. Members of a removed group are covered by ``groups_removed``.
    A removal that names an absent entity changes nothing and is not listed.
    """
    before = current.model_dump(mode="json") if current else {"services": [], "groups": [], "connections": []}
    after = merged.model_dump(mode="json")
    result: dict[str, list[str]] = {}
    for field in ("services", "groups", "connections"):
        left = {entry["id"]: entry for entry in before.get(field, [])}
        right = {entry["id"]: entry for entry in after[field]}
        result[f"{field}_created"] = sorted(right.keys() - left.keys())
        result[f"{field}_updated"] = sorted(
            key for key in right.keys() & left.keys() if right[key] != left[key]
        )
        result[f"{field}_unchanged"] = sorted(
            key for key in right.keys() & left.keys() if right[key] == left[key]
        )
        result[f"{field}_removed"] = sorted(left.keys() - right.keys())
    members_removed: set[str] = set()
    kept_groups = {group["id"]: group for group in after["groups"]}
    for group in before.get("groups", []):
        if group["id"] in kept_groups:
            kept = {member["id"] for member in kept_groups[group["id"]].get("members", [])}
            members_removed.update(
                f"{group['id']}:{member['id']}"
                for member in group.get("members", [])
                if member["id"] not in kept
            )
    result["members_removed"] = sorted(members_removed)
    return result


def _merge_model(existing: dict[str, Any], incoming: BaseModel) -> dict[str, Any]:
    """Apply only fields present in a partial YAML object.

    An omitted field keeps the current value at every keyed level.
    """
    result = dict(existing)
    for field in incoming.model_fields_set:
        value = getattr(incoming, field)
        if field == "members" and isinstance(value, list):
            result[field] = _keyed_models(existing.get(field, []), value)
        else:
            result[field] = _json_value(value)
    return result


def _json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    return value


def _keyed_models(existing: list[dict[str, Any]], incoming: list[BaseModel]) -> list[dict[str, Any]]:
    updates = {str(item.model_dump()["id"]): item for item in incoming}
    result = [
        _merge_model(entry, updates.pop(entry["id"])) if entry["id"] in updates else entry
        for entry in existing
    ]
    result.extend(item.model_dump(mode="json") for item in updates.values())
    return result
