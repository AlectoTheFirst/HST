"""Bounded, revision-checked acquisition of one Check Point policy package."""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal

type ApiCall = Callable[[str, Mapping[str, object]], dict[str, Any]]
type RevisionProbe = Callable[[], str | None]
type ChunkSink = Callable[[bytes], str]
type GapCode = Literal[
    "api-error",
    "budget-exceeded",
    "duplicate-uid",
    "implied-rule-unproven",
    "malformed-entry",
    "missing-object",
    "missing-package",
    "pagination",
    "revision-changed",
    "revision-unproven",
]


@dataclass(frozen=True, slots=True)
class CaptureEnvelope:
    authority_uid: str
    domain_uid: str
    manifest_digest: str
    snapshot_revision: str


@dataclass(frozen=True, slots=True)
class CaptureBudgets:
    total_pages: int = 10_000
    rules: int = 1_000_000
    objects: int = 1_000_000
    bytes: int = 1_000_000_000
    depth: int = 32
    page_limit: int = 100

    def __post_init__(self) -> None:
        for name in ("total_pages", "rules", "objects", "bytes", "depth", "page_limit"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


DEFAULT_CAPTURE_BUDGETS = CaptureBudgets()


@dataclass(frozen=True, slots=True)
class CaptureGap:
    code: GapCode
    subject: str
    detail: str


@dataclass(frozen=True, slots=True)
class PolicyCapture:
    envelope: CaptureEnvelope
    package_uid: str
    complete: bool
    bundle: Mapping[str, object]
    gaps: tuple[CaptureGap, ...]
    raw_metadata: Mapping[str, object]
    chunk_receipts: tuple[str, ...]


class _StopCapture(Exception):
    pass


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({str(k): _freeze(v) for k, v in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze(v) for v in value)
    return value


def _uid(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping) and isinstance(value.get("uid"), str):
        return value["uid"]
    return None


_REFERENCE_FIELDS = frozenset(
    {
        "source",
        "destination",
        "service",
        "action",
        "time",
        "vpn",
        "content",
        "install-on",
        "members",
        "include",
        "except",
    }
)


def _canonical_id(name: str, value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or not value.isprintable():
        raise ValueError(f"{name} must be a non-empty canonical identifier")
    return value


def collect_checkpoint_policy(
    api: ApiCall,
    *,
    authority_uid: str,
    domain_uid: str,
    package_uid: str,
    manifest_digest: str,
    snapshot_revision: str,
    revision_probe: RevisionProbe,
    chunk_sink: ChunkSink,
    implied_rules_complete: bool | None = None,
    budgets: CaptureBudgets = DEFAULT_CAPTURE_BUDGETS,
) -> PolicyCapture:
    """``chunk_sink`` must synchronously seal/copy its bytes and return an opaque
    receipt.
    """
    authority_uid = _canonical_id("authority_uid", authority_uid)
    domain_uid = _canonical_id("domain_uid", domain_uid)
    package_uid = _canonical_id("package_uid", package_uid)
    manifest_digest = _canonical_id("manifest_digest", manifest_digest)
    snapshot_revision = _canonical_id("snapshot_revision", snapshot_revision)
    if not isinstance(implied_rules_complete, bool | None):
        raise TypeError("implied_rules_complete must be bool or None")
    envelope = CaptureEnvelope(authority_uid, domain_uid, manifest_digest, snapshot_revision)
    gaps: list[CaptureGap] = []
    receipts: list[str] = []
    pages_used = rules_used = objects_used = bytes_used = 0
    raw_calls: list[dict[str, object]] = []

    def gap(code: GapCode, subject: str, detail: str) -> None:
        gaps.append(CaptureGap(code, subject, detail))

    def call(command: str, payload: dict[str, object], *, page: bool = False) -> dict[str, Any] | None:
        nonlocal pages_used, bytes_used
        if page:
            pages_used += 1
            if pages_used > budgets.total_pages:
                gap("budget-exceeded", command, "total page budget exceeded")
                raise _StopCapture
        try:
            reply = api(command, MappingProxyType(dict(payload)))
        except Exception as exc:
            gap("api-error", command, f"{type(exc).__name__}: {exc}")
            return None
        encoded = json.dumps(reply, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        bytes_used += len(encoded)
        if bytes_used > budgets.bytes:
            gap("budget-exceeded", command, "serialized byte budget exceeded")
            raise _StopCapture
        receipts.append(chunk_sink(encoded))
        raw_calls.append({"command": command, "payload": dict(payload), "bytes": len(encoded)})
        return reply

    def probe_revision(when: str) -> str | None:
        try:
            return revision_probe()
        except Exception as exc:
            gap(
                "revision-unproven",
                package_uid,
                f"{when} revision probe failed: {type(exc).__name__}: {exc}",
            )
            return None

    before = probe_revision("pre-capture")
    if before is None or not snapshot_revision:
        gap("revision-unproven", package_uid, "a monotonic/global revision was not supplied by the probe")
    elif before != snapshot_revision:
        gap(
            "revision-changed",
            package_uid,
            f"expected {snapshot_revision!r}, observed {before!r} before capture",
        )
    if implied_rules_complete is not True:
        gap(
            "implied-rule-unproven",
            package_uid,
            "show-access-rulebase does not itself prove implied/default rule coverage",
        )

    package: dict[str, Any] | None = None
    layers: dict[str, dict[str, Any]] = {}
    rulebases: dict[str, list[dict[str, Any]]] = {}
    objects: dict[str, dict[str, Any]] = {}
    object_envelopes: dict[str, dict[str, Any]] = {}
    pending_layers: deque[tuple[str, int]] = deque()
    pending_objects: deque[tuple[str, int]] = deque()
    try:
        package = call("show-package", {"uid": package_uid, "details-level": "full"})
        if package is None or package.get("uid") != package_uid:
            got = None if package is None else package.get("uid")
            gap("missing-package", package_uid, f"show-package returned UID {got!r}")
            package = None
            raise _StopCapture

        access = package.get("access-layers", package.get("access-layers-uid", [])) or []
        if not isinstance(access, list):
            access = [access]
        for value in access:
            layer_uid = _uid(value)
            if layer_uid:
                pending_layers.append((layer_uid, 0))
            else:
                gap("malformed-entry", package_uid, "package contains an access-layer without a UID")

        seen_layers: set[str] = set()
        while pending_layers:
            layer_uid, depth = pending_layers.popleft()
            if layer_uid in seen_layers:
                continue
            if depth > budgets.depth:
                gap("budget-exceeded", layer_uid, "inline layer depth budget exceeded")
                continue
            seen_layers.add(layer_uid)
            layer = call("show-access-layer", {"uid": layer_uid, "details-level": "full"})
            if layer is None:
                continue
            if layer.get("uid") != layer_uid:
                gap("duplicate-uid", layer_uid, f"show-access-layer returned UID {layer.get('uid')!r}")
                continue
            offset = 0
            expected_total: int | None = None
            items: list[dict[str, Any]] = []
            captured_pages: list[dict[str, Any]] = []
            seen_item: dict[str, dict[str, Any]] = {}
            while True:
                payload: dict[str, object] = {
                    "uid": layer_uid,
                    "details-level": "full",
                    "use-object-dictionary": True,
                    "offset": offset,
                    "limit": budgets.page_limit,
                }
                page = call("show-access-rulebase", payload, page=True)
                if page is None:
                    break
                captured_pages.append(deepcopy(page))
                total, first, last = page.get("total"), page.get("from"), page.get("to")
                rows = page.get("rulebase")
                if (
                    isinstance(total, bool)
                    or not isinstance(total, int)
                    or isinstance(first, bool)
                    or not isinstance(first, int)
                    or isinstance(last, bool)
                    or not isinstance(last, int)
                    or not isinstance(rows, list)
                ):
                    gap("pagination", layer_uid, "page lacks integer from/to/total or a rulebase list")
                    break
                if expected_total is None:
                    expected_total = total

                def page_position_count(
                    values: list[Any], section_depth: int = 0, subject: str = layer_uid
                ) -> int:
                    count = 0
                    for value in values:
                        if not isinstance(value, dict):
                            count += 1
                            continue
                        children = value.get("rulebase")
                        if "-section" in str(value.get("type", "")) and isinstance(children, list):
                            if section_depth >= budgets.depth:
                                gap("budget-exceeded", subject, "section depth budget exceeded")
                                continue
                            count += page_position_count(children, section_depth + 1)
                        else:
                            count += 1
                    return count

                position_count = page_position_count(rows)
                if (
                    total != expected_total
                    or first != (offset + 1 if total else 0)
                    or last != offset + position_count
                ):
                    gap(
                        "pagination",
                        layer_uid,
                        f"discontinuous page from={first} to={last} total={total} offset={offset}",
                    )
                    break
                dictionary = page.get("objects-dictionary", []) or []
                if not isinstance(dictionary, list):
                    gap("pagination", layer_uid, "objects-dictionary is not a list")
                    break
                for obj in dictionary:
                    if not isinstance(obj, dict) or not isinstance(obj.get("uid"), str):
                        gap("malformed-entry", layer_uid, "object dictionary entry lacks a string UID")
                        continue
                    objects_used += 1
                    if objects_used > budgets.objects:
                        gap(
                            "budget-exceeded",
                            layer_uid,
                            "object budget exceeded, including dictionary entries",
                        )
                        raise _StopCapture
                    prior = objects.get(obj["uid"])
                    if prior is not None and prior != obj:
                        gap("duplicate-uid", obj["uid"], "object dictionary definitions disagree")
                    elif prior is None:
                        objects[obj["uid"]] = obj

                row_queue: deque[tuple[Any, int, list[dict[str, Any]]]] = deque(
                    (item, 0, items) for item in rows
                )
                page_rule_entries = 0
                while row_queue:
                    item, section_depth, destination = row_queue.popleft()
                    if not isinstance(item, dict):
                        gap("malformed-entry", layer_uid, "rulebase entry is not an object")
                        continue
                    item_uid = item.get("uid")
                    if not isinstance(item_uid, str):
                        gap("malformed-entry", layer_uid, "rulebase entry lacks a string UID")
                        continue
                    prior = seen_item.get(item_uid) if isinstance(item_uid, str) else None
                    if prior is not None:
                        is_section = "-section" in str(item.get("type", ""))
                        same_header = {k: v for k, v in prior.items() if k != "rulebase"} == {
                            k: v for k, v in item.items() if k != "rulebase"
                        }
                        if not is_section or not same_header:
                            gap(
                                "duplicate-uid",
                                str(item_uid),
                                "duplicate rule UID is not a consistent section continuation",
                            )
                            continue
                        continuation = item.get("rulebase", [])
                        if not isinstance(continuation, list):
                            gap("malformed-entry", item_uid, "section rulebase is not a list")
                            continue
                        prior_children = prior.setdefault("rulebase", [])
                        row_queue.extend((child, section_depth + 1, prior_children) for child in continuation)
                        continue
                    copied = deepcopy(item)
                    page_rule_entries += 1
                    destination.append(copied)
                    if isinstance(item_uid, str):
                        seen_item[item_uid] = copied
                    inline_uid = _uid(item.get("inline-layer"))
                    if inline_uid:
                        pending_layers.append((inline_uid, depth + 1))
                    children = item.get("rulebase")
                    if children is not None:
                        if not isinstance(children, list):
                            gap("malformed-entry", item_uid, "section rulebase is not a list")
                        elif section_depth >= budgets.depth:
                            gap("budget-exceeded", item_uid, "section depth budget exceeded")
                        else:
                            copied_children: list[dict[str, Any]] = []
                            copied["rulebase"] = copied_children
                            row_queue.extend(
                                (child, section_depth + 1, copied_children) for child in children
                            )

                rules_used += page_rule_entries
                if rules_used > budgets.rules:
                    gap("budget-exceeded", layer_uid, "rule budget exceeded")
                    raise _StopCapture
                if last == total:
                    break
                if not rows or last <= offset or last > total:
                    gap("pagination", layer_uid, "page did not advance to a valid terminal offset")
                    break
                offset = last
            rulebases[layer_uid] = items
            layers[layer_uid] = {
                "metadata": layer,
                "rulebase": items,
                "rulebase-pages": captured_pages,
            }

        def queue_refs(value: Any, depth: int) -> None:
            if isinstance(value, str):
                if value not in objects:
                    pending_objects.append((value, depth))
            elif isinstance(value, Mapping):
                ref = _uid(value)
                if ref and ref not in objects:
                    pending_objects.append((ref, depth))
            elif isinstance(value, list):
                for member in value:
                    queue_refs(member, depth)

        for rows in rulebases.values():
            stack = list(rows)
            while stack:
                row = stack.pop()
                stack.extend(x for x in row.get("rulebase", []) if isinstance(x, dict))
                for field in _REFERENCE_FIELDS:
                    queue_refs(row.get(field), 0)
        for obj in tuple(objects.values()):
            for field in ("members", "include", "except"):
                queue_refs(obj.get(field), 0)

        attempted: set[str] = set(objects)
        while pending_objects:
            object_uid, depth = pending_objects.popleft()
            if object_uid in attempted:
                continue
            attempted.add(object_uid)
            if depth > budgets.depth:
                gap("budget-exceeded", object_uid, "object reference depth budget exceeded")
                continue
            objects_used += 1
            if objects_used > budgets.objects:
                gap("budget-exceeded", object_uid, "object budget exceeded")
                raise _StopCapture
            response = call("show-object", {"uid": object_uid, "details-level": "full"})
            if response is None:
                gap("missing-object", object_uid, "referenced object was not returned authoritatively")
                continue
            if "object" in response:
                candidate = response.get("object")
                response_shape = "api-envelope"
                envelope_reply = response
            else:
                candidate = response
                response_shape = "caller-unwrapped"
                envelope_reply = {
                    "object": deepcopy(response),
                    "response-shape": response_shape,
                }
            raw_calls[-1]["response_shape"] = response_shape
            if not isinstance(candidate, dict) or candidate.get("uid") != object_uid:
                gap(
                    "missing-object",
                    object_uid,
                    "show-object response has no authoritative object with the requested UID",
                )
                continue
            obj = candidate
            object_envelopes[object_uid] = envelope_reply
            objects[object_uid] = obj
            for field in ("members", "include", "except"):
                queue_refs(obj.get(field), depth + 1)
    except _StopCapture:
        pass

    after = probe_revision("post-capture")
    if after is None:
        gap("revision-unproven", package_uid, "the post-capture monotonic/global revision is missing")
    elif before is not None and (after != before or after != snapshot_revision):
        gap("revision-changed", package_uid, f"revision changed from {before!r} to {after!r}")

    bundle = {
        "envelope": {
            "authority_uid": authority_uid,
            "domain_uid": domain_uid,
            "manifest_digest": manifest_digest,
            "snapshot_revision": snapshot_revision,
        },
        "package": package,
        "layers": layers,
        "rulebases": rulebases,
        "objects": objects,
        "object_envelopes": object_envelopes,
        "object_namespaces": {
            uid: {
                "authority_uid": authority_uid,
                "domain_uid": (
                    obj.get("domain", {}).get("uid", domain_uid)
                    if isinstance(obj.get("domain"), Mapping)
                    else domain_uid
                ),
            }
            for uid, obj in objects.items()
        },
    }
    metadata = {
        "calls": raw_calls,
        "pages": pages_used,
        "rules": rules_used,
        "objects_fetched": objects_used,
        "serialized_bytes": bytes_used,
        "revision_before": before,
        "revision_after": after,
    }
    return PolicyCapture(
        envelope,
        package_uid,
        len(gaps) == 0,
        _freeze(bundle),
        tuple(gaps),
        _freeze(metadata),
        tuple(receipts),
    )
