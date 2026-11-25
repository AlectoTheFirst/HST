"""One entry of a stored analysis result, named the way the web client presents it.

The analysis result view (`web/src/assessments/AnalysisResult.tsx`) lists the
entries of a result. The entries are its findings and evidence gaps and, for a
resilience analysis, the expanded failure domains. A verification presents one
comparison, and a result with none of these entries presents one outcome.
`entries` groups a result the same way.

A reference names one entry:

- `<kind>:<id>` is the entry of that kind whose own id is `<id>`. The own id is
  the first of `finding_id`, `id`, `uid`, `digest` and `diff_sha256` that the
  record holds, when it is a non-empty string. A domain is also named by its
  name.
- `<kind>:@<n>` is the entry at position `n` of that kind, counted from 0 in
  the stored order.
- `<id>` without a kind is the finding whose own id is `<id>`.

The kinds are `finding`, `gap`, `domain`, `outcome` and `verification`. A
recorded run keeps its result unchanged. A position names the same entry for
as long as the run is kept.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

FindingKind = Literal["finding", "gap", "domain", "outcome", "verification"]
KINDS: tuple[FindingKind, ...] = ("finding", "gap", "domain", "outcome", "verification")
# The keys the client reads an entry's own id from, in order.
ID_KEYS = ("finding_id", "id", "uid", "digest", "diff_sha256")
_POSITION = re.compile(r"@([0-9]{1,9})")


@dataclass(frozen=True)
class Located:
    """One entry of a result, with its kind, its position and its record."""

    kind: FindingKind
    index: int
    record: dict[str, Any]

    @property
    def reference(self) -> str:
        """The reference the client sends for this entry."""
        own = own_id(self.record)
        if own is not None:
            return f"{self.kind}:{own}"
        name = self.record.get("name")
        if self.kind == "domain" and isinstance(name, str):
            return f"domain:{name}"
        return f"{self.kind}:@{self.index}"


def _record(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def own_id(record: dict[str, Any]) -> str | None:
    """The own id of the entry. It is the value of the first id key that holds
    a value, when that value is a non-empty string."""
    for key in ID_KEYS:
        value = record.get(key)
        if value is not None:
            return value if isinstance(value, str) and value else None
    return None


def entries(result: dict[str, Any], run_kind: str | None = None) -> dict[FindingKind, list[dict[str, Any]]]:
    """The entries of `result` by kind. `run_kind` is the kind of the run,
    used when the result names none."""
    kind = result.get("kind", run_kind)
    findings = [_record(v) for v in result["findings"]] if isinstance(result.get("findings"), list) else []
    gaps = [_record(v) for v in result["gaps"]] if isinstance(result.get("gaps"), list) else []
    if str(kind) == "verify":
        return {"verification": [result], "gap": gaps}
    groups: dict[FindingKind, list[dict[str, Any]]] = {"finding": findings, "gap": gaps}
    if str(kind) == "resilience":
        domains = result.get("expanded_domains")
        groups["domain"] = (
            [{"name": name, **_record(entry)} for name, entry in domains.items()]
            if isinstance(domains, dict)
            else []
        )
    if not any(groups.values()):
        return {"outcome": [result]}
    return groups


def locate(result: Any, run_kind: str | None, reference: str) -> Located | None:
    """The entry of `result` that `reference` names, or None when the result
    holds no such entry."""
    if not isinstance(result, dict) or not reference:
        return None
    groups = entries(result, run_kind)
    head, separator, rest = reference.partition(":")
    if separator and head in KINDS:
        kind: FindingKind = head
        items = groups.get(kind, [])
        position = _POSITION.fullmatch(rest)
        if position is not None:
            index = int(position.group(1))
            return Located(kind, index, items[index]) if index < len(items) else None
        for index, record in enumerate(items):
            if own_id(record) == rest or (kind == "domain" and record.get("name") == rest):
                return Located(kind, index, record)
        return None
    for index, record in enumerate(groups.get("finding", [])):
        if own_id(record) == reference:
            return Located("finding", index, record)
    return None
