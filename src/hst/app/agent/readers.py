"""Side-store readers for one tool call, closed when the call ends.

Each RIB, BGP or OSPF reader holds its own DuckDB connection. `ReaderPool`
builds each reader through the `for_snapshot` factory of its module. The
factory bounds the side store to the run of the pinned graph session. The pool
closes each reader that it built when the `with` block ends.
"""

from __future__ import annotations

import logging
from types import TracebackType
from typing import TYPE_CHECKING, Protocol, TypeVar

from hst.core import bgpsource, ospfsource, ribsource

if TYPE_CHECKING:
    from hst.core.bgpsource import BgpSource
    from hst.core.ospfsource import OspfSource
    from hst.core.ribsource import RibSource
    from hst.core.snapshot import Snapshot

log = logging.getLogger("hst.ai")


class _Closeable(Protocol):
    def close(self) -> None: ...


_Reader = TypeVar("_Reader", bound=_Closeable)


class ReaderPool:
    """Hands out side-store readers and closes all of them on exit.

    Every call to `rib`, `bgp` or `ospf` builds a new reader for the snapshot
    it is given. The pool logs a `close` that raises and closes the remaining
    readers. `close` and `__exit__` do not raise for it.
    """

    def __init__(self) -> None:
        self._opened: list[_Closeable] = []

    def __enter__(self) -> ReaderPool:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def rib(self, snap: Snapshot) -> RibSource:
        """A RIB reader bounded to the run `snap` resolved."""
        return self._track(ribsource.for_snapshot(snap))

    def bgp(self, snap: Snapshot) -> BgpSource:
        """A BGP reader bounded to the run `snap` resolved."""
        return self._track(bgpsource.for_snapshot(snap))

    def ospf(self, snap: Snapshot) -> OspfSource:
        """An OSPF reader bounded to the run `snap` resolved."""
        return self._track(ospfsource.for_snapshot(snap))

    def close(self) -> None:
        """Close every reader this pool built. Repeated closes are safe."""
        opened, self._opened = self._opened, []
        for reader in opened:
            try:
                reader.close()
            except Exception:
                log.warning("closing a side-store reader failed", exc_info=True)

    def _track(self, reader: _Reader) -> _Reader:
        self._opened.append(reader)
        return reader
