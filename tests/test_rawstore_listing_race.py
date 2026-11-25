"""A raw file or trace that retention removes while the store lists it is left
out of the listing (core/rawstore.py `raw_files`, `traces`)."""

from __future__ import annotations

import gzip
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

from hst.core import rawstore

KEY = Fernet.generate_key().decode()
KEPT = "1700000000000-aaaaaaaa"
PRUNED = "1700000000001-bbbbbbbb"


def _pruned_on_stat(monkeypatch) -> None:
    """Remove every file of the `PRUNED` run just before its size is read."""
    stat = Path.stat

    def racing(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name.startswith(PRUNED):
            self.unlink(missing_ok=True)
        return stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", racing)


def test_a_raw_file_removed_while_it_is_listed_is_left_out(tmp_path, monkeypatch):
    kept = rawstore.write(tmp_path, "edge", KEPT, {"x": 1}, host="r1", key=KEY)
    rawstore.write(tmp_path, "edge", PRUNED, {"x": 2}, host="r2", key=KEY)
    _pruned_on_stat(monkeypatch)

    listed = rawstore.raw_files(tmp_path, "edge", 10)

    assert [(f.host, f.run_id, f.path, f.size) for f in listed] == [("r1", KEPT, kept, kept.stat().st_size)]


def test_a_trace_removed_while_it_is_listed_is_left_out(tmp_path, monkeypatch):
    kept = rawstore.write(tmp_path, "edge", KEPT, {"x": 1}, host="r1", key=KEY)
    pruned = rawstore.write(tmp_path, "edge", PRUNED, {"x": 2}, host="r2", key=KEY)
    kept_trace = rawstore.write_trace(kept, gzip.compress(b"{}\n"), key=KEY)
    rawstore.write_trace(pruned, gzip.compress(b"{}\n"), key=KEY)
    _pruned_on_stat(monkeypatch)

    listed = rawstore.traces(tmp_path)

    assert [(t.source, t.host, t.run_id, t.path) for t in listed] == [("edge", "r1", KEPT, kept_trace)]
