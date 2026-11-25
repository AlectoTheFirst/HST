"""Bounded routing iteration with exact repeated-state certificates."""

from __future__ import annotations

from collections.abc import Hashable, Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ConvergenceBudget:
    """Independent limits for the three routing fixed points."""

    outer_rounds: int = 128
    bgp_rounds: int = 256
    resolution_passes: int = 256

    def __post_init__(self) -> None:
        for name, value in (
            ("outer_rounds", self.outer_rounds),
            ("bgp_rounds", self.bgp_rounds),
            ("resolution_passes", self.resolution_passes),
        ):
            if not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")


@dataclass
class RepeatedStateDetector:
    """Stores each observed state with the round of its first observation."""

    _seen: dict[Hashable, int] = field(default_factory=dict)

    def observe(self, state: Hashable, round_number: int) -> int | None:
        previous = self._seen.get(state)
        if previous is None:
            self._seen[state] = round_number
        return previous


@dataclass(frozen=True)
class ConvergenceCertificate:
    """Serializable evidence for settled, cyclic, or budget-limited work."""

    status: str
    rounds: int
    affected_contexts: tuple[str, ...] = ()
    affected_prefixes: tuple[tuple[str, str], ...] = ()
    repeated_from_round: int | None = None
    repeated_at_round: int | None = None
    downstream_contexts: tuple[str, ...] = ()
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "rounds": self.rounds,
            "affected_contexts": list(self.affected_contexts),
            "affected_prefixes": [
                {"context_uid": context_uid, "prefix": prefix}
                for context_uid, prefix in self.affected_prefixes
            ],
            "repeated_from_round": self.repeated_from_round,
            "repeated_at_round": self.repeated_at_round,
            "downstream_contexts": list(self.downstream_contexts),
            "detail": self.detail,
        }


def freeze(value: Any) -> Hashable:
    """Canonical immutable representation used for exact state equality."""
    if isinstance(value, Mapping):
        return tuple(sorted((str(key), freeze(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(freeze(item) for item in value)
    return value
