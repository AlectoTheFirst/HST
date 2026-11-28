"""The frozen inventory contracts.

Pure unit tests: serialization, unknown-field rejection, redaction, pagination
validation, the cursor, the frozen operation enum and error codes, the field
classification registry against every registered ConfigModel's JSON schema, the
vocabulary parity between contracts, tables and migration 0028, and the name
parity between contracts.py and web/src/api/inventory.ts.
"""

from __future__ import annotations

import enum
import importlib.util
import inspect
import re
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, SecretStr, ValidationError

import hst.app.sources as glue
from hst import collectors as coll
from hst.app.inventory import contracts as c
from hst.app.inventory import field_metadata as fm
from hst.app.inventory import tables as t
from hst.app.store.pg import metadata

ROOT = Path(__file__).resolve().parents[2]
TS_FILE = ROOT / "web" / "src" / "api" / "inventory.ts"
MIGRATION = ROOT / "src" / "hst" / "app" / "store" / "migrations" / "versions" / "0028_device_inventory.py"
NOW = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)


def _models() -> dict[str, type[BaseModel]]:
    return {
        n: o
        for n, o in vars(c).items()
        if inspect.isclass(o)
        and issubclass(o, BaseModel)
        and o.__module__ == c.__name__
        and n not in ("Request", "Response")
    }


def _enums() -> dict[str, type[enum.StrEnum]]:
    return {
        n: o
        for n, o in vars(c).items()
        if inspect.isclass(o) and issubclass(o, enum.StrEnum) and o.__module__ == c.__name__
    }


# --- serialization and unknown fields ---------------------------------------------------


def test_response_models_serialize_ids_as_strings_and_timestamps_as_iso():
    device_id = uuid.uuid4()
    summary = c.DeviceSummary(
        id=device_id,
        graph_uid="dev:x:r1",
        hostname="r1",
        platform="vyos",
        management_address="10.0.0.1",
        lifecycle=c.Lifecycle.ACTIVE,
        revision=1,
        collection_state=c.CollectionState.CURRENT,
        last_success_at=NOW,
        site_id="7",
        site_code="fra",
        placement_state=c.PlacementState.ASSIGNED,
        latest_snapshot_key="1758283200000",
        first_seen=NOW,
        last_seen=NOW,
    )
    dumped = summary.model_dump(mode="json")
    assert dumped["id"] == str(device_id) and isinstance(dumped["site_id"], str)
    assert dumped["last_success_at"] == "2026-09-19T12:00:00Z"
    assert dumped["lifecycle"] == "active" and dumped["connections"] == []
    assert c.DeviceSummary.model_validate(dumped) == summary


@pytest.mark.parametrize("name", sorted(n for n, m in _models().items() if issubclass(m, c.Request)))
def test_every_request_model_rejects_unknown_fields(name):
    model = _models()[name]
    assert model.model_config.get("extra") == "forbid", name
    minimal = _minimal_payload(model)
    if minimal is not None:
        model.model_validate(minimal)  # the payload itself is valid
        with pytest.raises(ValidationError) as exc:
            model.model_validate({**minimal, "not_a_field": 1})
        assert "not_a_field" in str(exc.value)


_SAMPLES: dict[str, dict[str, Any]] = {
    "PlacementPatch": {"mode": "auto", "expected_revision": 1},
    "LifecyclePatch": {"action": "archive", "expected_revision": 1},
    "CollectRequest": {"target_ids": [str(uuid.uuid4())]},
    "ConnectionCreate": {"name": "lab", "collector_type": "vyos"},
    "ConnectionPatch": {"expected_revision": 1},
    "TargetCreate": {"connection_id": "1", "host": "r1"},
    "TargetPatch": {"expected_revision": 1},
    "TargetReplaceRequest": {"token": str(uuid.uuid4()), "idempotency_key": "k"},
    "ProfileCreate": {"display_name": "p", "collector_type": "vyos"},
    "ProfilePatch": {"expected_revision": 1},
    "CredentialCreate": {"display_name": "c", "secrets": {"auth.password": "pw"}},
    "CredentialPatch": {"expected_revision": 1},
    "SiteCreate": {"code": "fra"},
    "SitePatch": {"expected_revision": 1},
    "LocationPatch": {"site_id": None, "expected_revision": 1},
    "SiteSearchQuery": {},
    "SiteImportRow": {"code": "fra"},
    "SiteImport": {"sites": [{"code": "fra"}]},
    "LocationSearchQuery": {},
    "LocationBinding": {},
    "LocationBindings": {"bindings": [{}]},
    "SavedViewCreate": {"name": "v"},
    "SavedViewPatch": {"expected_revision": 1},
    "RoutingGroupCreate": {"display_name": "g"},
    "RoutingGroupPatch": {"expected_revision": 1},
    "Selection": {"ids": ["a"]},
    "PlacementChange": {"mode": "unplaced"},
    "ProfileAssignmentChange": {"profile_id": None},
    "RoutingMembersChange": {"group_id": str(uuid.uuid4())},
    "ReplacementChange": {"endpoint_config": {"host": "r2"}},
    "PreviewRequest": {"operation": "archive_devices", "selection": {"ids": ["a"]}},
    "ApplyRequest": {"token": str(uuid.uuid4()), "idempotency_key": "k"},
    "DeviceListQuery": {},
    "ConnectionListQuery": {},
    "DeviceRoutingQuery": {},
    "PageQuery": {},
    "ProbeRequest": {},
    "ViewFilter": {},
}


def _minimal_payload(model: type[BaseModel]) -> dict[str, Any] | None:
    return _SAMPLES.get(model.__name__)


def test_every_request_model_has_a_sample():
    requests = {n for n, m in _models().items() if issubclass(m, c.Request)}
    assert requests <= set(_SAMPLES), requests - set(_SAMPLES)


# --- redaction ------------------------------------------------------------------------------


def test_connection_name_and_site_code_take_the_legacy_route_validation():
    """A connection key is validated like a source name; a site code keeps the
    shape the legacy site route enforces so it stays usable inside a graph uid."""
    from hst.app.routes import sites as legacy_sites

    assert c.CONNECTION_NAME_PATTERN == glue.NAME_PATTERN
    assert legacy_sites.CODE_RE.pattern == c.SITE_CODE_PATTERN
    for name in ("lab", "core-01", "ab"):
        assert c.ConnectionCreate(name=name, collector_type="vyos").name == name
    for name in ("a", "core_01", "Core", "x" * 33, ""):
        with pytest.raises(ValidationError):
            c.ConnectionCreate(name=name, collector_type="vyos")
    for code in ("fra", "FRA-01", "dc1.core:a", "x" * 64):
        assert c.SiteCreate(code=code).code == code
    for code in ("", "fra 1", "-fra", "x" * 65, "fr\u00e4"):
        with pytest.raises(ValidationError):
            c.SiteCreate(code=code)


def test_credential_material_is_write_only_and_redacted_on_dump():
    body = c.CredentialCreate(
        display_name="lab", secrets={"auth.password": "hunter2", "auth.passphrase": "p"}
    )
    assert isinstance(body.secrets["auth.password"], SecretStr)
    dumped = body.model_dump(mode="json")
    assert dumped["secrets"] == {"auth.password": "**********", "auth.passphrase": "**********"}
    assert "hunter2" not in repr(body) and "hunter2" not in str(body)
    assert body.secret_values() == {"auth.password": "hunter2", "auth.passphrase": "p"}
    patch = c.CredentialPatch(expected_revision=1)
    assert patch.secret_values() is None
    for name, model in _models().items():
        if issubclass(model, c.Response):
            assert not {"secrets", "password", "private_key", "secret_draft", "sealed"} & set(
                model.model_fields
            ), name


def test_redact_config_masks_classified_secret_paths_and_nothing_else():
    config = {
        "host": "r1",
        "auth": {"method": "password", "username": "ro", "password": "pw"},
        "jump_host": {
            "host": "bastion",
            "auth": {"method": "private_key", "private_key": "KEY", "passphrase": ""},
        },
    }
    out = c.redact_config("iosxe", config)
    assert out["auth"] == {"method": "password", "username": "ro", "password": "***"}
    assert out["jump_host"]["auth"] == {"method": "private_key", "private_key": "***", "passphrase": ""}
    assert out["host"] == "r1" and out["jump_host"]["host"] == "bastion"
    assert config["auth"]["password"] == "pw"  # the input is untouched
    assert c.redact_by_key({"nested": [{"token": "t", "name": "n"}], "client_secret": "s"}) == {
        "nested": [{"token": "***", "name": "n"}],
        "client_secret": "***",
    }


def test_preview_request_change_is_validated_and_redacted():
    req = c.PreviewRequest(
        operation=c.PreviewOperation.ROTATE_CREDENTIAL,
        selection={"ids": [str(uuid.uuid4())]},
        change={"expected_revision": 2, "secrets": {"auth.password": "new"}},
    )
    assert req.redacted_change() == {
        "display_name": None,
        "expected_revision": 2,
        "secrets": {"auth.password": "**********"},
    }
    with pytest.raises(ValidationError):
        c.PreviewRequest(operation="archive_devices", selection={"ids": ["a"]}, change={"mode": "auto"})
    with pytest.raises(ValidationError):
        c.PreviewRequest(operation="place_devices", selection={"ids": ["a"]})
    with pytest.raises(ValidationError):  # assigned needs a site
        c.PreviewRequest(operation="place_devices", selection={"ids": ["a"]}, change={"mode": "assigned"})
    with pytest.raises(ValidationError):  # one selection form only
        c.Selection(ids=["a"], filter={})
    with pytest.raises(ValidationError):  # a filter selection pins its generation
        c.Selection(filter={})
    with pytest.raises(ValidationError):
        c.Selection(ids=["a"] * 1001)
    assert c.Selection(filter={"q": "x"}, intent_generation=4).filter.q == "x"


# --- pagination and cursor -------------------------------------------------------------------


def test_list_query_validates_limit_sort_and_direction():
    assert c.DeviceListQuery().limit == 50
    assert c.DeviceListQuery(limit=200).limit == 200
    for bad in (
        {"limit": 0},
        {"limit": 201},
        {"sort": "hostname"},
        {"direction": "up"},
        {"lifecycle": ["gone"]},
    ):
        with pytest.raises(ValidationError):
            c.DeviceListQuery(**bad)
    q = c.DeviceListQuery(site_id=["1", "2"], q="r1", sort="site", cursor="x", limit=10)
    assert q.filter_fields() == {
        "q": "r1",
        "site_id": ["1", "2"],
        "connection_id": [],
        "platform": [],
        "collection_state": [],
        "placement_state": [],
        "lifecycle": [],
    }
    assert set(c.SortField) == {"name", "platform", "site", "last_success", "collection_state"}


def test_cursor_round_trips_and_rejects_tampering():
    cursor = c.ListCursor(
        snapshot_key="1758283200000",
        intent_generation=7,
        sort=c.SortField.NAME,
        direction=c.SortDirection.ASC,
        filter_digest=c.filter_digest({"q": "r"}),
        last_value="r1",
        last_id=uuid.uuid4(),
    )
    text = c.encode_cursor(cursor)
    assert re.fullmatch(r"[A-Za-z0-9_-]+", text)
    assert c.decode_cursor(text) == cursor
    for bad in ("", "not base64!", text[:-4] + "zzzz", c.encode_cursor.__name__):
        with pytest.raises(c.CursorError):
            c.decode_cursor(bad)
    assert c.filter_digest({"a": 1, "b": [2]}) == c.filter_digest({"b": [2], "a": 1})
    assert c.filter_digest({"a": 1}) != c.filter_digest({"a": 2})


# --- frozen enums, codes, permissions ---------------------------------------------------------


def test_operation_enum_error_codes_and_permissions_are_frozen():
    assert [op.value for op in c.PreviewOperation] == [
        "place_devices",
        "assign_target_profile",
        "edit_profile",
        "rotate_credential",
        "delete_site",
        "delete_connection",
        "delete_target",
        "replace_target",
        "edit_routing_members",
        "archive_devices",
        "restore_devices",
    ]
    assert set(c.OPERATION_PERMISSIONS) == set(c.PreviewOperation) == set(c.OPERATION_CHANGE)
    assert [e.value for e in c.ErrorCode] == [
        "inventory_changed",
        "normalization_migrated",
        "stale_revision",
        "preview_expired",
        "forbidden",
        "not_found",
        "validation",
        "observed_store_unavailable",
        "conflict",
        "idempotency_conflict",
    ]
    assert set(c.ERROR_STATUS) == set(c.ErrorCode)
    assert (
        c.ERROR_STATUS[c.ErrorCode.FORBIDDEN] == 403
        and c.ERROR_STATUS[c.ErrorCode.OBSERVED_STORE_UNAVAILABLE] == 503
    )
    assert c.CONTRACT_VERSION == 1
    from hst.app.permissions import PERMISSIONS

    known = PERMISSIONS | {c.INVENTORY_WRITE}
    assert set(c.OPERATION_PERMISSIONS.values()) <= known
    assert set(c.ROUTE_PERMISSIONS.values()) <= known
    # Reads are graph.read or runs.manage, writes are a .write permission.
    for (method, route), perm in c.ROUTE_PERMISSIONS.items():
        if route.startswith("/views"):
            assert perm == "graph.read", route  # ownership, not role, gates personal views
        elif method == "GET":
            assert perm in ("graph.read", "runs.manage", "sources.write"), (route, perm)
        else:
            assert (
                perm.endswith(".write")
                or (route == "/devices/{id}/collect" and perm == "runs.manage")
                or (route == "/targets/{id}/probe" and perm == "runs.manage")
            ), (route, perm)
    assert c.ROUTE_PERMISSIONS[("PATCH", "/devices/{id}/lifecycle")] == c.INVENTORY_WRITE


def test_error_response_shape_carries_current_revision_and_references():
    body = c.ErrorResponse(error="stale", code=c.ErrorCode.STALE_REVISION, current_revision=4)
    assert body.model_dump(mode="json") == {
        "error": "stale",
        "code": "stale_revision",
        "current_revision": 4,
        "references": [],
        "detail": None,
    }


# --- tables and migration parity ----------------------------------------------------------------


def test_check_vocabularies_agree_between_contracts_tables_and_migration():
    spec = importlib.util.spec_from_file_location("migration_0028", MIGRATION)
    assert spec and spec.loader
    mig = importlib.util.module_from_spec(spec)
    sys.modules["migration_0028"] = mig
    spec.loader.exec_module(mig)
    assert mig.revision == "0028" and mig.down_revision == "0027"
    for name in (
        "LIFECYCLES",
        "TARGET_KINDS",
        "OBSERVATION_STATES",
        "AUTHORITIES",
        "PLACEMENT_MODES",
        "PLACEMENT_ORIGINS",
        "PLACEMENT_STATES",
        "COLLECTION_STATES",
        "PUBLICATION_STATES",
        "OUTBOX_KINDS",
        "OUTBOX_STATES",
        "ACTIVATION_STATES",
        "PREVIEW_OPERATIONS",
    ):
        assert getattr(t, name) == getattr(mig, name), name
    assert tuple(op.value for op in c.PreviewOperation) == t.PREVIEW_OPERATIONS
    assert t.PREVIEW_TTL_S == 600 and t.OUTBOX_DONE_RETENTION_DAYS == 7


def test_every_inventory_table_is_on_the_store_metadata_with_its_required_fields():
    names = {x.name for x in metadata.sorted_tables}
    assert {x.name for x in t.INVENTORY_TABLES} <= names
    required = {
        "inventory_devices": {
            "id",
            "graph_uid",
            "first_seen",
            "last_seen",
            "latest_snapshot_key",
            "hostname",
            "platform",
            "management_address",
            "lifecycle",
            "revision",
        },
        "inventory_targets": {
            "id",
            "source_id",
            "source_key",
            "host",
            "kind",
            "legacy_device_id",
            "profile_id",
            "onboarding_site_id",
            "enabled",
            "revision",
            "archived_at",
        },
        "inventory_observations": {
            "target_id",
            "device_id",
            "reported_location_handle",
            "last_success_at",
            "last_seen_snapshot_key",
            "state",
            "authority",
            "notes",
        },
        "inventory_placements": {
            "device_id",
            "mode",
            "site_id",
            "origin",
            "revision",
            "actor_id",
            "updated_at",
            "applied_revision",
            "published_site_id",
            "published_snapshot_key",
        },
        "collection_profiles": {"id", "display_name", "collector_type", "current_revision", "archived_at"},
        "collection_profile_versions": {
            "profile_id",
            "revision",
            "settings",
            "credential_id",
            "credential_revision",
            "created_at",
            "actor_id",
        },
        "collection_credentials": {"id", "current_revision", "display_name", "archived_at"},
        "collection_credential_versions": {"credential_id", "revision", "sealed", "secret_paths"},
        "inventory_events": {
            "id",
            "entity_type",
            "entity_id",
            "actor_id",
            "action",
            "at",
            "before",
            "after",
            "request_id",
            "snapshot_key",
        },
        "inventory_saved_views": {
            "id",
            "owner_id",
            "name",
            "filter_version",
            "filter",
            "sort",
            "columns",
            "revision",
        },
        "inventory_routing_groups": {"id", "display_name", "description", "revision", "archived_at"},
        "inventory_routing_members": {"group_id", "context_uid", "owner_uid", "added_at", "actor_id"},
        "inventory_state": {
            "resolver_version",
            "schema_version",
            "backfill_version",
            "activation_state",
            "read_model_snapshot_key",
            "intent_generation",
        },
        "inventory_publications": {
            "snapshot_key",
            "parent_snapshot_key",
            "state",
            "intent_generation",
            "staged_changes",
            "placement_revisions",
            "created_at",
            "applied_at",
        },
        "inventory_operation_previews": {
            "token",
            "actor_id",
            "expires_at",
            "operation",
            "members",
            "impact",
            "secret_draft",
            "result_id",
        },
        "inventory_operation_results": {
            "actor_id",
            "idempotency_key",
            "request_digest",
            "status",
            "response",
            "created_at",
        },
        "inventory_outbox": {
            "id",
            "dedup_key",
            "kind",
            "payload",
            "state",
            "attempt",
            "lease_expires_at",
            "next_attempt_at",
            "last_error",
        },
    }
    for table, cols in required.items():
        assert cols <= set(metadata.tables[table].c.keys()), table
    for table, column in t.LEGACY_ADDITIONS:
        assert column in metadata.tables[table].c, (table, column)
    assert "device_sites" not in names  # the table is site_members
    obs_fk = {
        fk.column.table.name: fk.ondelete for fk in metadata.tables["inventory_observations"].foreign_keys
    }
    assert obs_fk["inventory_targets"] == "RESTRICT" and obs_fk["inventory_devices"] == "RESTRICT"
    assert "password" not in " ".join(metadata.tables["inventory_observations"].c.keys())


# --- field metadata registry ---------------------------------------------------------------


def _schema_leaves(schema: dict) -> list[tuple[str, str | None]]:
    """Every (dotted path, variant) leaf of a ConfigModel JSON schema. A leaf reached
    through a union member ($defs name in anyOf/oneOf) carries that member's name
    as its variant; the innermost union wins; a direct $ref carries none."""
    defs = schema.get("$defs", {})
    out: list[tuple[str, str | None]] = []

    def resolve(node: dict) -> tuple[str, dict]:
        name = node["$ref"].rsplit("/", 1)[-1]
        return name, defs[name]

    def props(node: dict, prefix: str, variant: str | None) -> None:
        for name, sub in node.get("properties", {}).items():
            leaf(sub, f"{prefix}{name}", variant)

    def leaf(node: dict, path: str, variant: str | None) -> None:
        if "$ref" in node:
            _, target = resolve(node)
            props(target, path + ".", variant)
            return
        members = [m for m in node.get("anyOf", node.get("oneOf", [])) if m.get("type") != "null"]
        refs = [m for m in members if "$ref" in m]
        if refs:
            for m in refs:
                name, target = resolve(m)
                props(target, path + ".", name)
            return
        if "allOf" in node:
            for m in node["allOf"]:
                leaf(m, path, variant)
            return
        out.append((path, variant))

    props(schema, "", None)
    return out


def test_every_registered_collector_field_is_classified_and_nothing_else_is():
    assert set(coll.REGISTRY) == set(fm.COLLECTORS), (
        "collector registered without a classification, or vice versa"
    )
    for name, cls in sorted(coll.REGISTRY.items()):
        leaves = _schema_leaves(cls.ConfigModel.model_json_schema())
        assert len(leaves) == len(set(leaves)), f"{name}: duplicate schema leaf"
        classified = [(f.path, f.variant) for f in fm.COLLECTORS[name].fields]
        assert len(classified) == len(set(classified)), f"{name}: duplicate classification"
        missing = set(leaves) - set(classified)
        extra = set(classified) - set(leaves)
        assert not missing, f"{name}: ConfigModel leaves without a classification: {sorted(missing)}"
        assert not extra, f"{name}: classifications without a ConfigModel leaf: {sorted(extra)}"
        model_path = f"{cls.ConfigModel.__module__}.{cls.ConfigModel.__qualname__}"
        assert fm.COLLECTORS[name].config_model == model_path
        assert fm.COLLECTORS[name].kind == cls.KIND
        secret_paths = glue.secret_paths(cls.ConfigModel)
        for f in fm.COLLECTORS[name].fields:
            assert f.secret == (f.path in secret_paths), (name, f.path)
            if f.secret:
                assert f.category == "credential", (name, f.path)
            assert f.category in fm.CATEGORIES and f.identity_sensitivity in fm.IDENTITY_SENSITIVITIES
            # Profile settings and the credential paths injected into them apply
            # to exactly this collector type; other categories never do.
            if f.category in ("profile", "credential"):
                assert f.profile_applicability == name, (name, f.path)
            else:
                assert f.profile_applicability == "n/a", (name, f.path)
            if f.category == "profile":
                assert f.identity_sensitivity != "identity", (name, f.path)
        assert fm.secret_paths(name) == frozenset(secret_paths)
    assert sum(len(x.fields) for x in fm.COLLECTORS.values()) == 401


def test_field_metadata_contract_shape():
    everything = c.all_field_metadata()
    assert [x.collector_type for x in everything] == sorted(coll.REGISTRY)
    iosxe = c.field_metadata_for("iosxe")
    assert iosxe.kind == c.ConnectionKind.DIRECT
    pw = next(f for f in iosxe.fields if f.path == "auth.password" and f.variant == "SshPassword")
    assert pw.model_dump(mode="json") == {
        "path": "auth.password",
        "variant": "SshPassword",
        "category": "credential",
        "secret": True,
        "identity_sensitivity": "none",
        "profile_applicability": "iosxe",
        "label": pw.label,
        "endpoint": "",
    }
    assert c.field_metadata_for("velocloud").kind == c.ConnectionKind.CONTROLLER
    # management_host/management_domain are connection fields.
    gw = {f.path: f.category for f in c.field_metadata_for("checkpoint_gateway").fields if f.variant is None}
    assert gw["management_host"] == "connection" and gw["management_domain"] == "connection"


# --- TypeScript parity ------------------------------------------------------------------------------


TS_ONLY = {"InventoryErrorBody", "InventoryApi"}


def test_typescript_mirror_declares_every_contract_name():
    text = TS_FILE.read_text()
    exported = set(re.findall(r"^export (?:interface|type) (\w+)", text, flags=re.MULTILINE))
    python_names = set(_models()) | set(_enums())
    missing = python_names - exported
    assert not missing, f"contracts.py names missing from inventory.ts: {sorted(missing)}"
    unknown = exported - python_names - TS_ONLY
    assert not unknown, f"inventory.ts names with no contracts.py model: {sorted(unknown)}"
    assert re.search(rf"^export const CONTRACT_VERSION = {c.CONTRACT_VERSION};", text, flags=re.MULTILINE)
    # Enum members match value for value.
    for name, enum_cls in _enums().items():
        block = re.search(rf"^export type {name} =\n((?:  \| \"[^\"]+\"\n?)+);", text, flags=re.MULTILINE)
        assert block, name
        values = re.findall(r'"([^"]+)"', block.group(1))
        assert values == [m.value for m in enum_cls], name
    # Every model field appears in the TypeScript interface of the same name.
    for name, model in _models().items():
        if not model.model_fields:
            continue
        block = re.search(rf"^export interface {name} \{{\n(.*?)\n\}}", text, flags=re.MULTILINE | re.DOTALL)
        assert block, name
        ts_fields = set(re.findall(r"^  (\w+)\??:", block.group(1), flags=re.MULTILINE))
        assert ts_fields == set(model.model_fields), (name, ts_fields ^ set(model.model_fields))
    # One client function per route: every api(p(...)) call yields a
    # (method, path template) pair once `${seg(x)}` stands for `{id}` and the
    # query suffix is dropped; each ROUTE_PERMISSIONS key must appear among them.
    client = text[text.index("export const inventoryApi = {") :]
    called: set[tuple[str, str]] = set()
    for match in re.finditer(
        r"api<[^>]*>\(p\((?:`(?P<tpl>[^`]*)`|\"(?P<lit>[^\"]*)\")\)(?:, \{(?P<opts>[^}]*)\})?\)", client
    ):
        path = match.group("tpl") or match.group("lit") or ""
        path = re.sub(r"\$\{query\([^`]*?\)\}", "", path)
        path = re.sub(r"\$\{seg\(\w+\)\}", "{id}", path)
        method_match = re.search(r'method: "(\w+)"', match.group("opts") or "")
        method = method_match.group(1) if method_match else "GET"
        called.add((method, path))
    missing = set(c.ROUTE_PERMISSIONS) - called
    assert not missing, sorted(missing)
    for op in ("/operations/preview", "/operations/apply", "/operations/previews/{id}/impact"):
        assert any(path == op for _, path in called), op
