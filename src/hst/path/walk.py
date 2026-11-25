from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .gates import _Trail


@dataclass(frozen=True)
class WalkContext:
    session: Any
    trail: _Trail
    port: Any
    proto: Any
    rib: Any | None
    max_hops: int
    depth: int = 0
    visited: frozenset[str] = frozenset()
    conn_state: str = "new"

    def but(self, **changes: Any) -> WalkContext:
        """This context with `changes` applied."""
        return dataclasses.replace(self, **changes)
