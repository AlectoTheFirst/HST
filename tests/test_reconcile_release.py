"""The derived-data repair holds one payload at a time (core/reconcile.py
`repair_derived`).

Each lost side-store file is regenerated from the raw payload its manifest
names. A file's payload, its rows and the collector's parse of it are done with
once that file is written or reported, so the repair releases them before it
reads the next payload, on every path out of a file, and releases the
collector's per-payload cache (`Collector.release_payload`) as a load does.
"""

from __future__ import annotations

import gc
import weakref
from typing import Any

from tests.test_reconcile_row_errors import ARP, MAC, _lost_tables

from hst.app.crypto import dek
from hst.core import rawstore, reconcile


class _Payload(dict):
    """A payload a weakref can watch."""


class _Rows(list):
    """Rows that hold the payload they were built from, as a row view over a
    parse does."""

    def __init__(self, rows: list[dict[str, Any]], payload: Any) -> None:
        super().__init__(rows)
        self.payload = payload


class _Caching:
    """A collector whose parse cache holds the payload it last read, as
    `CiscoCliCollector._inter` does, and releases it on `release_payload`.
    One instance serves every file, as one collector serves every device of
    its source."""

    def __init__(self, fail: bool = False) -> None:
        self._parsed_for: Any = None
        self.released = 0
        self.fail = fail

    def side_tables(self, raw: Any) -> dict[str, Any]:
        self._parsed_for = raw
        if self.fail:
            raise KeyError("interface")
        return {"arp": _Rows(ARP, raw), "mac": _Rows(MAC, raw)}

    def release_payload(self) -> None:
        self.released += 1
        self._parsed_for = None


def _watch_reads(monkeypatch) -> tuple[list[weakref.ref], list[list[bool]]]:
    """Wrap `rawstore.read` so each payload it returns is watched."""
    real = rawstore.read
    seen: list[weakref.ref] = []
    alive_at_read: list[list[bool]] = []

    def read(path, key):
        gc.collect()
        alive_at_read.append([ref() is not None for ref in seen])
        payload = _Payload(real(path, key))
        seen.append(weakref.ref(payload))
        return payload

    monkeypatch.setattr(rawstore, "read", read)
    return seen, alive_at_read


def test_each_file_releases_its_payload_before_the_next_is_read(tmp_path, monkeypatch):
    settings, report, relative = _lost_tables(tmp_path)
    seen, alive_at_read = _watch_reads(monkeypatch)
    collector = _Caching()

    lines = reconcile.repair_derived(
        settings, report, tmp_path / "repair", collector_for=lambda s, h: collector, key=dek(settings)
    )

    assert [line.endswith("the recorded row digest matches") for line in lines] == [True, True]
    assert report.rebuilt_paths == sorted(relative.values())
    assert alive_at_read == [[], [False]]
    assert collector._parsed_for is None
    assert collector.released == 2
    gc.collect()
    assert [ref() is None for ref in seen] == [True, True]


def test_a_file_that_cannot_be_regenerated_releases_its_payload_too(tmp_path, monkeypatch):
    settings, report, relative = _lost_tables(tmp_path)
    seen, alive_at_read = _watch_reads(monkeypatch)
    collector = _Caching(fail=True)

    lines = reconcile.repair_derived(
        settings, report, tmp_path / "repair", collector_for=lambda s, h: collector, key=dek(settings)
    )

    assert lines == [
        f"{path}: could not regenerate (KeyError: 'interface')" for path in sorted(relative.values())
    ]
    assert alive_at_read == [[], [False]]
    assert collector._parsed_for is None
    assert collector.released == 2
    gc.collect()
    assert [ref() is None for ref in seen] == [True, True]


def test_a_collector_without_release_payload_repairs_both_tables(tmp_path):
    settings, report, relative = _lost_tables(tmp_path)

    class _Plain:
        def side_tables(self, raw: Any) -> dict[str, Any]:
            return {"arp": list(ARP), "mac": list(MAC)}

    lines = reconcile.repair_derived(
        settings, report, tmp_path / "repair", collector_for=lambda s, h: _Plain(), key=dek(settings)
    )

    assert [line.endswith("the recorded row digest matches") for line in lines] == [True, True]
    assert report.rebuilt_paths == sorted(relative.values())


def test_a_source_no_longer_configured_releases_nothing_and_goes_on(tmp_path, monkeypatch):
    settings, report, relative = _lost_tables(tmp_path)
    seen, _alive = _watch_reads(monkeypatch)

    lines = reconcile.repair_derived(
        settings, report, tmp_path / "repair", collector_for=lambda s, h: None, key=dek(settings)
    )

    assert lines == [
        f"{path}: no such source configured; cannot regenerate" for path in sorted(relative.values())
    ]
    assert seen == []
