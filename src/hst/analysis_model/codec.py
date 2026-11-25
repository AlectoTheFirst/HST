"""Portable, exact encoding of compiled analysis models.

The artifact contains metadata and a canonical symbolic decision DAG.  It never
contains Python objects, pickle data, or native CUDD pointers.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Final

from hst.policy.ir import ExecutionContext
from hst.symbolic import PacketSet, SymbolicManager
from hst.symbolic.artifacts import (
    ArtifactLimits,
    SymbolicArtifactError,
    decode_packet_sets,
    encode_packet_sets,
)
from hst.symbolic.relations import PacketRelation, _RelationStep

from .compile import AnalysisModel, CompiledEdge, CompiledEntry, CompiledNode
from .model import ChoiceAssignment, StateKey

FORMAT: Final = "strata-analysis-model"
VERSION: Final = 1
# The metadata limit is half of the 64 MiB artifact limit of model_cache.LIMITS.
MAX_METADATA_BYTES: Final = 32 * 1024 * 1024
DEFAULT_LIMITS: Final = ArtifactLimits()


class ModelCodecError(ValueError):
    """A model artifact is corrupt, incomplete, or bound to another context."""


@dataclass(frozen=True, slots=True)
class ModelBinding:
    estate: str
    manifest_digest: str
    semantic_version: str
    header_schema: str
    ordering_version: str
    normalization_versions: tuple[tuple[str, str], ...] = ()
    vendor_profiles: tuple[tuple[str, str], ...] = ()
    assumptions_digest: str = ""
    analysis_time: str = ""
    population_digest: str = ""
    backend: str = "dd.cudd"
    backend_version: str = ""
    model_fingerprint: str = ""
    known_fields: tuple[str, ...] = ()
    build_identity: str = ""

    def __post_init__(self) -> None:
        if not self.estate or not _sha256(self.manifest_digest):
            raise ValueError("estate and a SHA-256 manifest digest are required")
        for name in ("semantic_version", "header_schema", "ordering_version", "backend"):
            if not getattr(self, name):
                raise ValueError(f"{name} is required")
        for name in ("normalization_versions", "vendor_profiles"):
            value = tuple(sorted(tuple(item) for item in getattr(self, name)))
            if len({key for key, _ in value}) != len(value):
                raise ValueError(f"duplicate {name} keys")
            object.__setattr__(self, name, value)
        object.__setattr__(self, "known_fields", tuple(sorted(set(self.known_fields))))
        if self.model_fingerprint and not _sha256(self.model_fingerprint):
            raise ValueError("model_fingerprint must be a SHA-256 digest")

    @property
    def key(self) -> str:
        return hashlib.sha256(_json(asdict(self))).hexdigest()


def encode_model(
    model: AnalysisModel, binding: ModelBinding, *, limits: ArtifactLimits = DEFAULT_LIMITS
) -> bytes:
    """Encode an immutable native model and all relation pipeline steps."""
    if model.manifest_digest != binding.manifest_digest:
        raise ModelCodecError("model and binding manifest digests differ")
    if binding.model_fingerprint and model.fingerprint != binding.model_fingerprint:
        raise ModelCodecError("model and binding fingerprints differ")
    if binding.known_fields and tuple(sorted(model.universe.known_fields)) != binding.known_fields:
        raise ModelCodecError("model and binding knowledge masks differ")
    manager = model.universe.manager
    if (
        binding.header_schema != manager.capabilities.schema_version
        or binding.ordering_version != manager.capabilities.ordering_version
    ):
        raise ModelCodecError("binding does not identify the model schema and ordering")
    roots: dict[str, PacketSet] = {"universe": model.universe}
    nodes = []
    for ni, node in enumerate(model.nodes):
        edges = []
        terminals = []
        for ei, edge in enumerate(node.edges):
            guard, uncertain = f"n/{ni}/e/{ei}/guard", f"n/{ni}/e/{ei}/uncertain"
            roots[guard], roots[uncertain] = edge.guard, edge.uncertain
            steps = []
            for si, step in enumerate(edge.relation._steps):
                name = f"n/{ni}/e/{ei}/relation/{si}"
                roots[name] = manager._wrap(step.node)
                steps.append(name)
            edges.append(
                {
                    "uid": edge.uid,
                    "target": _key(edge.target),
                    "guard": guard,
                    "uncertain": uncertain,
                    "relation": steps,
                    "choices": list(map(list, edge.choices)),
                }
            )
        for ti, (outcome, packets) in enumerate(node.terminals):
            name = f"n/{ni}/terminal/{ti}"
            roots[name] = packets
            terminals.append([outcome, name])
        nodes.append(
            {
                "key": _key(node.key),
                "edges": edges,
                "terminals": terminals,
                "complete": node.complete,
                "gap_refs": list(node.gap_refs),
            }
        )
    entries = []
    for ei, entry in enumerate(model.entries):
        guard, uncertain = f"entry/{ei}/guard", f"entry/{ei}/uncertain"
        roots[guard], roots[uncertain] = entry.guard, entry.uncertain
        entries.append(
            {
                "key": _key(entry.key),
                "guard": guard,
                "uncertain": uncertain,
                "choices": list(map(list, entry.choices)),
            }
        )
    metadata = {
        "binding": asdict(binding),
        "choices": [{"uid": c.uid, "bindings": list(map(list, c.bindings))} for c in model.choices],
        "choices_complete": model.choices_complete,
        "entries": entries,
        "fingerprint": model.fingerprint,
        "manifest_digest": model.manifest_digest,
        "nodes": nodes,
    }
    metadata_bytes = _json(metadata)
    if len(metadata_bytes) > MAX_METADATA_BYTES:
        raise ModelCodecError("model metadata exceeds limit")
    dag = encode_packet_sets(roots, limits=limits)
    content = {
        "complete": True,
        "format": FORMAT,
        "version": VERSION,
        "metadata": metadata,
        "dag": dag.decode("ascii"),
    }
    document = {**content, "digest": hashlib.sha256(_json(content)).hexdigest()}
    return _json(document)


def decode_model(
    data: bytes,
    manager: SymbolicManager,
    expected: ModelBinding,
    *,
    limits: ArtifactLimits = DEFAULT_LIMITS,
) -> AnalysisModel:
    """Validate the whole envelope before rebuilding native roots."""
    try:
        if (
            expected.header_schema != manager.capabilities.schema_version
            or expected.ordering_version != manager.capabilities.ordering_version
            or expected.backend != manager.capabilities.backend
            or expected.backend_version != manager.capabilities.backend_version
        ):
            raise ModelCodecError("requested binding does not match the native manager")
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_unique)
        if not isinstance(document, dict) or set(document) != {
            "complete",
            "format",
            "version",
            "metadata",
            "dag",
            "digest",
        }:
            raise ModelCodecError("invalid model artifact envelope")
        content = {key: document[key] for key in ("complete", "format", "version", "metadata", "dag")}
        if document["format"] != FORMAT or document["version"] != VERSION or document["complete"] is not True:
            raise ModelCodecError("unsupported or incomplete model artifact")
        if data != _json(document) or document["digest"] != hashlib.sha256(_json(content)).hexdigest():
            raise ModelCodecError("model artifact digest or canonical encoding mismatch")
        metadata = document["metadata"]
        expected_binding = json.loads(_json(asdict(expected)))
        if len(_json(metadata)) > MAX_METADATA_BYTES or metadata.get("binding") != expected_binding:
            raise ModelCodecError("model artifact binding mismatch")
        if metadata.get("manifest_digest") != expected.manifest_digest:
            raise ModelCodecError("model artifact manifest mismatch")
        _validate_metadata(metadata)
        roots = decode_packet_sets(document["dag"].encode("ascii"), manager, limits=limits)
        nodes = []
        for raw in metadata["nodes"]:
            edges = []
            for edge in raw["edges"]:
                relation = PacketRelation(
                    manager, tuple(_RelationStep(roots[name]._node) for name in edge["relation"])
                )
                edges.append(
                    CompiledEdge(
                        edge["uid"],
                        _state(edge["target"]),
                        roots[edge["guard"]],
                        roots[edge["uncertain"]],
                        relation,
                        _pairs(edge["choices"]),
                    )
                )
            nodes.append(
                CompiledNode(
                    _state(raw["key"]),
                    tuple(edges),
                    tuple((outcome, roots[name]) for outcome, name in raw["terminals"]),
                    _bool(raw["complete"]),
                    tuple(_strings(raw["gap_refs"])),
                )
            )
        entries = tuple(
            CompiledEntry(
                _state(raw["key"]), roots[raw["guard"]], roots[raw["uncertain"]], _pairs(raw["choices"])
            )
            for raw in metadata["entries"]
        )
        choices = tuple(ChoiceAssignment(raw["uid"], _pairs(raw["bindings"])) for raw in metadata["choices"])
        return AnalysisModel(
            expected.manifest_digest,
            _string(metadata["fingerprint"]),
            roots["universe"],
            tuple(nodes),
            entries,
            choices,
            _bool(metadata["choices_complete"]),
        )
    except (
        KeyError,
        TypeError,
        UnicodeError,
        json.JSONDecodeError,
        SymbolicArtifactError,
        RecursionError,
    ) as exc:
        if isinstance(exc, ModelCodecError):
            raise
        raise ModelCodecError("malformed model artifact") from exc


def _key(value: StateKey) -> dict[str, Any]:
    return {
        "location": value.location,
        "context": asdict(value.context),
        "stage": value.stage,
        "tunnel_stack": list(value.tunnel_stack),
        "binding_scope": list(value.binding_scope),
    }


def _validate_metadata(metadata: Any) -> None:
    expected = {
        "binding",
        "choices",
        "choices_complete",
        "entries",
        "fingerprint",
        "manifest_digest",
        "nodes",
    }
    if not isinstance(metadata, dict) or set(metadata) != expected:
        raise ModelCodecError("invalid model metadata")
    _string(metadata["fingerprint"])
    _bool(metadata["choices_complete"])
    for collection in (metadata["choices"], metadata["entries"], metadata["nodes"]):
        if not isinstance(collection, list):
            raise ModelCodecError("model metadata collections must be lists")
    for choice in metadata["choices"]:
        if not isinstance(choice, dict) or set(choice) != {"uid", "bindings"}:
            raise ModelCodecError("invalid model choice")
        _string(choice["uid"])
        _pairs(choice["bindings"])
    for entry in metadata["entries"]:
        if not isinstance(entry, dict) or set(entry) != {"key", "guard", "uncertain", "choices"}:
            raise ModelCodecError("invalid model entry")
        _state(entry["key"])
        _string(entry["guard"])
        _string(entry["uncertain"])
        _pairs(entry["choices"])
    for node in metadata["nodes"]:
        if not isinstance(node, dict) or set(node) != {"key", "edges", "terminals", "complete", "gap_refs"}:
            raise ModelCodecError("invalid model node")
        _state(node["key"])
        _bool(node["complete"])
        _strings(node["gap_refs"])
        if not isinstance(node["edges"], list) or not isinstance(node["terminals"], list):
            raise ModelCodecError("invalid node collections")
        for edge in node["edges"]:
            if not isinstance(edge, dict) or set(edge) != {
                "uid",
                "target",
                "guard",
                "uncertain",
                "relation",
                "choices",
            }:
                raise ModelCodecError("invalid model edge")
            _string(edge["uid"])
            _state(edge["target"])
            _string(edge["guard"])
            _string(edge["uncertain"])
            _strings(edge["relation"])
            _pairs(edge["choices"])
        for terminal in node["terminals"]:
            if not isinstance(terminal, list) or len(terminal) != 2:
                raise ModelCodecError("invalid terminal binding")
            if terminal[0] not in {"permit", "deny", "no_route", "unknown"}:
                raise ModelCodecError("invalid terminal outcome")
            _string(terminal[1])


def _state(raw: Any) -> StateKey:
    if (
        not isinstance(raw, dict)
        or set(raw) != {"location", "context", "stage", "tunnel_stack", "binding_scope"}
        or not isinstance(raw["context"], dict)
    ):
        raise ModelCodecError("invalid state key")
    if set(raw["context"]) != {"estate", "authority", "domain", "firewall_instance", "vrf", "address_family"}:
        raise ModelCodecError("invalid execution context")
    return StateKey(
        _string(raw["location"]),
        ExecutionContext(**raw["context"]),
        _string(raw["stage"]),
        tuple(_strings(raw["tunnel_stack"])),
        tuple(_strings(raw["binding_scope"])),
    )


def _pairs(value: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list) or any(not isinstance(v, list) or len(v) != 2 for v in value):
        raise ModelCodecError("invalid pair list")
    return tuple((_string(a), _string(b)) for a, b in value)


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ModelCodecError("expected string list")
    return [_string(item) for item in value]


def _string(value: Any) -> str:
    if type(value) is not str or not value:
        raise ModelCodecError("expected nonempty string")
    return value


def _bool(value: Any) -> bool:
    if type(value) is not bool:
        raise ModelCodecError("expected boolean")
    return value


def _json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ModelCodecError("duplicate JSON key")
        result[key] = value
    return result


def _sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
