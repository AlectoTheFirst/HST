"""Portable, bounded packet-set artifacts for the native symbolic backend.

A stored root denotes exactly
the packet set supplied by its caller.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from .manager import PacketSet, SymbolicManager

_FORMAT: Final = "strata-symbolic-packet-sets"
_VERSION: Final = 1
_TERMINAL: Final = 0
_DEFAULT_MAX_BYTES: Final = 8 * 1024 * 1024
_DEFAULT_MAX_NODES: Final = 200_000
_DEFAULT_MAX_ROOTS: Final = 4_096


class SymbolicArtifactError(ValueError):
    """A portable symbolic artifact is malformed, incompatible, or incomplete."""


@dataclass(frozen=True, slots=True)
class ArtifactLimits:
    """Hard input/output limits applied before native DAG construction."""

    max_bytes: int = _DEFAULT_MAX_BYTES
    max_nodes: int = _DEFAULT_MAX_NODES
    max_roots: int = _DEFAULT_MAX_ROOTS

    def __post_init__(self) -> None:
        for name in ("max_bytes", "max_nodes", "max_roots"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


_DEFAULT_LIMITS: Final = ArtifactLimits()


def encode_packet_sets(roots: Mapping[str, PacketSet], *, limits: ArtifactLimits = _DEFAULT_LIMITS) -> bytes:
    """Encode named packet-set roots as canonical, portable format-1 JSON bytes.

    Root names are sorted. Equivalent mappings produce identical bytes. The
    `known_fields` metadata is encoded with each root.
    """

    _require_limits(limits)
    if not isinstance(roots, Mapping):
        raise TypeError("roots must be a mapping of names to packet sets")
    if len(roots) > limits.max_roots:
        raise SymbolicArtifactError("artifact root count exceeds limit")

    entries = list(roots.items())
    if any(not isinstance(name, str) or not name for name, _packet_set in entries):
        raise TypeError("artifact root names must be non-empty strings")
    entries.sort(key=lambda item: item[0])
    manager: SymbolicManager | None = None
    checked: list[tuple[str, PacketSet]] = []
    for name, packet_set in entries:
        if not isinstance(packet_set, PacketSet):
            raise TypeError("artifact roots must be PacketSet values")
        if manager is None:
            manager = packet_set.manager
        manager._assert_sets(packet_set)
        checked.append((name, packet_set))
    if manager is None:
        raise ValueError("an artifact needs at least one root")

    nodes: list[dict[str, Any]] = []
    node_ids: dict[Any, int] = {}
    pending: list[tuple[Any, bool]] = []

    def reference(node: Any) -> dict[str, Any]:
        complemented = bool(node.negated)
        base = ~node if complemented else node
        if base == manager._bdd.true:
            return {"node": _TERMINAL, "complement": complemented}
        return {"node": node_ids[base], "complement": complemented}

    def append_postorder(root: Any) -> None:
        """Iteratively emit an uncomplemented CUDD DAG in child-first order."""

        complemented = bool(root.negated)
        base = ~root if complemented else root
        if base == manager._bdd.true or base in node_ids:
            return
        pending.append((base, False))
        while pending:
            current, children_done = pending.pop()
            if current in node_ids:
                continue
            if children_done:
                _level, low, high = manager._bdd.succ(current)
                low_reference = reference(low)
                high_reference = reference(high)
                if low_reference == high_reference:
                    raise SymbolicArtifactError("native DAG contains a non-reduced node")
                if len(nodes) >= limits.max_nodes:
                    raise SymbolicArtifactError("artifact node count exceeds limit")
                node_ids[current] = len(nodes) + 1
                nodes.append(
                    {
                        "id": len(nodes) + 1,
                        "variable": manager._bdd.var_at_level(current.level),
                        "low": low_reference,
                        "high": high_reference,
                    }
                )
                continue
            pending.append((current, True))
            _level, low, high = manager._bdd.succ(current)
            # The traversal order is low, then high.
            for child in (high, low):
                child_base = ~child if child.negated else child
                if child_base != manager._bdd.true and child_base not in node_ids:
                    pending.append((child_base, False))

    try:
        for _name, packet_set in checked:
            append_postorder(packet_set._node)
        encoded_roots = [
            {
                "knowledge": sorted(packet_set.known_fields),
                "name": name,
                "ref": reference(packet_set._node),
            }
            for name, packet_set in checked
        ]
        content: dict[str, Any] = {
            "complete": True,
            "family": manager.schema.address_family,
            "format": _FORMAT,
            "nodes": nodes,
            "ordering_version": manager.schema.ordering_version,
            "roots": encoded_roots,
            "schema_version": manager.schema.schema_version,
            "variables": list(manager.schema.variables),
            "version": _VERSION,
        }
        document = {**content, "digest": _digest(content)}
        data = _canonical_json(document)
        if len(data) > limits.max_bytes:
            raise SymbolicArtifactError("artifact byte length exceeds limit")
        return data
    finally:
        # Function keys are native roots. They are only traversal scratch state.
        node_ids.clear()
        pending.clear()


def decode_packet_sets(
    data: bytes | bytearray | memoryview,
    manager: SymbolicManager,
    *,
    limits: ArtifactLimits = _DEFAULT_LIMITS,
) -> dict[str, PacketSet]:
    """Validate and rebuild named packet sets into `manager`.

    Validation completes before ``BDD.find_or_add`` is called. A malformed
    child reference, a cycle, an ordering mismatch or a digest failure
    allocates no native node.
    """

    _require_limits(limits)
    if not isinstance(manager, SymbolicManager):
        raise TypeError("manager must be a SymbolicManager")
    manager._ensure_open()
    content = _validate_document(data, manager, limits)

    built: list[Any] = [manager._bdd.true]
    result: dict[str, PacketSet] = {}
    try:
        for record in content["nodes"]:
            low = _native_reference(record["low"], built)
            high = _native_reference(record["high"], built)
            built.append(manager._bdd.find_or_add(record["variable"], low, high))
        for root in content["roots"]:
            result[root["name"]] = manager._wrap(_native_reference(root["ref"], built), root["knowledge"])
        return result
    finally:
        # PacketSet owns its root.  The construction table must not keep native
        # nodes alive after successful load or an exception during wrapping.
        built.clear()


def _validate_document(
    data: bytes | bytearray | memoryview,
    manager: SymbolicManager,
    limits: ArtifactLimits,
) -> dict[str, Any]:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("artifact data must be bytes")
    byte_length = data.nbytes if isinstance(data, memoryview) else len(data)
    if byte_length > limits.max_bytes:
        raise SymbolicArtifactError("artifact byte length exceeds limit")
    raw = data if isinstance(data, bytes) else bytes(data)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, SymbolicArtifactError) as exc:
        raise SymbolicArtifactError("artifact is not valid canonical JSON") from exc
    try:
        if not isinstance(document, dict):
            raise SymbolicArtifactError("artifact document must be an object")
        expected_keys = {
            "complete",
            "digest",
            "family",
            "format",
            "nodes",
            "ordering_version",
            "roots",
            "schema_version",
            "variables",
            "version",
        }
        _exact_keys(document, expected_keys, "artifact document")
        digest = document["digest"]
        if not _is_sha256(digest):
            raise SymbolicArtifactError("artifact digest must be lowercase SHA-256 hex")
        content = {key: value for key, value in document.items() if key != "digest"}
        if _digest(content) != digest:
            raise SymbolicArtifactError("artifact content digest mismatch")
        if raw != _canonical_json(document):
            raise SymbolicArtifactError("artifact JSON is not canonical")
        _validate_header(content, manager)
        _validate_dag(content, manager, limits)
        return content
    except RecursionError as exc:
        raise SymbolicArtifactError("artifact JSON nesting exceeds implementation limit") from exc


def _validate_header(content: Mapping[str, Any], manager: SymbolicManager) -> None:
    if content["format"] != _FORMAT or type(content["format"]) is not str:
        raise SymbolicArtifactError("unsupported artifact format")
    if type(content["version"]) is not int or content["version"] != _VERSION:
        raise SymbolicArtifactError("unsupported artifact version")
    if type(content["complete"]) is not bool or not content["complete"]:
        raise SymbolicArtifactError("incomplete symbolic artifacts are rejected")
    if type(content["family"]) is not int or content["family"] != manager.schema.address_family:
        raise SymbolicArtifactError("artifact address family does not match manager schema")
    for key, expected in (
        ("schema_version", manager.schema.schema_version),
        ("ordering_version", manager.schema.ordering_version),
    ):
        if type(content[key]) is not str or content[key] != expected:
            raise SymbolicArtifactError(f"artifact {key} does not match manager schema")
    variables = content["variables"]
    if not isinstance(variables, list) or any(type(value) is not str for value in variables):
        raise SymbolicArtifactError("artifact variables must be a string list")
    if variables != list(manager.schema.variables):
        raise SymbolicArtifactError("artifact variable ordering does not match manager schema")


def _validate_dag(content: dict[str, Any], manager: SymbolicManager, limits: ArtifactLimits) -> None:
    nodes = content["nodes"]
    roots = content["roots"]
    if not isinstance(nodes, list) or len(nodes) > limits.max_nodes:
        raise SymbolicArtifactError("artifact node count exceeds limit")
    if not isinstance(roots, list) or not roots or len(roots) > limits.max_roots:
        raise SymbolicArtifactError("artifact root count is invalid or exceeds limit")
    variables = set(manager.schema.variables)
    levels = {variable: manager._bdd.level_of_var(variable) for variable in variables}
    node_signatures: set[tuple[str, int, bool, int, bool]] = set()
    for expected_id, record in enumerate(nodes, start=1):
        if not isinstance(record, dict):
            raise SymbolicArtifactError("artifact node must be an object")
        _exact_keys(record, {"high", "id", "low", "variable"}, "artifact node")
        if type(record["id"]) is not int or record["id"] != expected_id:
            raise SymbolicArtifactError("artifact node identifiers must be contiguous")
        variable = record["variable"]
        if type(variable) is not str or variable not in variables:
            raise SymbolicArtifactError("artifact node references an unknown variable")
        for branch in ("low", "high"):
            child = _validate_reference(record[branch], expected_id - 1, "node child")
            if child["node"] and levels[nodes[child["node"] - 1]["variable"]] <= levels[variable]:
                raise SymbolicArtifactError("artifact children are out of variable order")
        if record["high"]["complement"]:
            raise SymbolicArtifactError("artifact node is not complement-normalized")
        if record["low"] == record["high"]:
            raise SymbolicArtifactError("artifact DAG contains a non-reduced node")
        signature = (
            variable,
            record["low"]["node"],
            record["low"]["complement"],
            record["high"]["node"],
            record["high"]["complement"],
        )
        if signature in node_signatures:
            raise SymbolicArtifactError("artifact DAG contains duplicate nodes")
        node_signatures.add(signature)
    names: set[str] = set()
    previous_name: str | None = None
    field_names = set(manager.schema.field_names)
    for root in roots:
        if not isinstance(root, dict):
            raise SymbolicArtifactError("artifact root must be an object")
        _exact_keys(root, {"knowledge", "name", "ref"}, "artifact root")
        name = root["name"]
        if type(name) is not str or not name or name in names:
            raise SymbolicArtifactError("artifact roots need unique non-empty names")
        if previous_name is not None and name <= previous_name:
            raise SymbolicArtifactError("artifact roots are not in canonical name order")
        names.add(name)
        previous_name = name
        _validate_reference(root["ref"], len(nodes), "root reference")
        knowledge = root["knowledge"]
        if not isinstance(knowledge, list) or any(type(field) is not str for field in knowledge):
            raise SymbolicArtifactError("artifact knowledge must be a string list")
        if knowledge != sorted(set(knowledge)) or not set(knowledge) <= field_names:
            raise SymbolicArtifactError("artifact knowledge fields are not canonical schema fields")
    reachable: set[int] = set()
    pending = [root["ref"]["node"] for root in roots]
    while pending:
        node_id = pending.pop()
        if node_id == _TERMINAL or node_id in reachable:
            continue
        reachable.add(node_id)
        record = nodes[node_id - 1]
        pending.extend((record["low"]["node"], record["high"]["node"]))
    if len(reachable) != len(nodes):
        raise SymbolicArtifactError("artifact DAG contains unreachable nodes")


def _validate_reference(reference: Any, maximum_node: int, what: str) -> dict[str, Any]:
    if not isinstance(reference, dict):
        raise SymbolicArtifactError(f"{what} must be an object")
    _exact_keys(reference, {"complement", "node"}, what)
    node = reference["node"]
    complement = reference["complement"]
    if type(node) is not int or node < _TERMINAL or node > maximum_node:
        raise SymbolicArtifactError(f"{what} has an invalid node reference")
    if type(complement) is not bool:
        raise SymbolicArtifactError(f"{what} complement must be a boolean")
    return reference


def _native_reference(reference: Mapping[str, Any], built: list[Any]) -> Any:
    node = built[reference["node"]]
    return ~node if reference["complement"] else node


def _require_limits(limits: ArtifactLimits) -> None:
    if not isinstance(limits, ArtifactLimits):
        raise TypeError("limits must be ArtifactLimits")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _digest(content: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(content)).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _exact_keys(value: Mapping[str, Any], expected: set[str], what: str) -> None:
    if set(value) != expected:
        raise SymbolicArtifactError(f"{what} has unknown or missing fields")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SymbolicArtifactError("artifact JSON contains duplicate object keys")
        result[key] = value
    return result
