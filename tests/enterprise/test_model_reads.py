from __future__ import annotations

import pytest

from hst.analysis_model.dependencies import AbsenceSelector, DependencyIndex, QualifiedRef
from hst.analysis_model.read import BoundedTableReader, ReadError, ReadPage


def pages(items, *, digest="m", table="routes", page=2):
    return [
        ReadPage(
            digest,
            table,
            start,
            len(items),
            None if start + len(chunk) == len(items) else start + len(chunk),
            start + len(chunk) == len(items),
            tuple(chunk),
        )
        for start in range(0, len(items), page)
        for chunk in (items[start : start + page],)
    ]


def test_pinned_read_is_immutable_and_fingerprinted():
    source = pages([{"id": "a", "nested": {"x": [1]}}])
    result = BoundedTableReader(lambda d, t, o, n: source[o // 2], "m", page_size=2).read("routes")
    assert result.status == "complete"
    same = BoundedTableReader(lambda d, t, o, n: source[0], "m", page_size=2).read("routes")
    assert result.fingerprint == same.fingerprint
    with pytest.raises(TypeError):
        result.rows[0]["id"] = "b"  # type: ignore[index]


@pytest.mark.parametrize(
    "mutator, message",
    [
        (
            lambda p: ReadPage("other", p.table, p.offset, p.total, p.next_offset, p.complete, p.rows),
            "manifest",
        ),
        (
            lambda p: ReadPage(
                p.manifest_digest, "other", p.offset, p.total, p.next_offset, p.complete, p.rows
            ),
            "table",
        ),
        (
            lambda p: ReadPage(p.manifest_digest, p.table, 1, p.total, p.next_offset, p.complete, p.rows),
            "offset",
        ),
    ],
)
def test_page_pinning_errors(mutator, message):
    page = ReadPage("m", "routes", 0, 1, None, True, ({"id": "a"},))
    with pytest.raises(ReadError, match=message):
        BoundedTableReader(lambda d, t, o, n: mutator(page), "m").read("routes")


def test_duplicate_total_and_discontinuity_rejected():
    first = ReadPage("m", "t", 0, 3, 1, False, ({"id": "a"},))
    duplicate = ReadPage("m", "t", 1, 3, None, True, ({"id": "a"},))
    with pytest.raises(ReadError, match="duplicate"):
        BoundedTableReader(lambda d, t, o, n: first if o == 0 else duplicate, "m").read("t")
    bad = ReadPage("m", "t", 0, 4, None, True, ({"id": "a"},))
    with pytest.raises(ReadError, match="total"):
        BoundedTableReader(lambda d, t, o, n: bad, "m").read("t")


def test_budgets_checked_before_retaining_rows():
    page = ReadPage("m", "t", 0, 2, 2, False, ({"id": "a"}, {"id": "b"}))
    with pytest.raises(ReadError, match="budget"):
        BoundedTableReader(lambda d, t, o, n: page, "m", max_rows=1).read("t")


def test_complete_empty_is_distinct_from_partial():
    empty = ReadPage("m", "empty", 0, 0, None, True, ())
    partial = ReadPage("m", "partial", 0, 3, None, False, ({"id": "a"},))
    reader = BoundedTableReader(lambda d, t, o, n: empty if t == "empty" else partial, "m")
    assert reader.read("empty").status == "complete-empty"
    assert reader.read("partial").status == "partial"


def test_provider_receives_manifest_and_missing_is_explicit():
    calls = []
    missing = ReadPage("m", "t", 0, None, None, False, (), "missing")

    def provider(digest, table, offset, limit):
        calls.append((digest, table, offset, limit))
        return missing

    result = BoundedTableReader(provider, "m").read("t")
    assert result.status == "missing"
    assert calls == [("m", "t", 0, 1000)]


def test_strict_rows_and_none_total_drift():
    with pytest.raises(ReadError, match="stable"):
        BoundedTableReader(lambda d, t, o, n: ReadPage("m", "t", 0, 1, None, True, ({"x": 1},)), "m").read(
            "t"
        )
    first = ReadPage("m", "t", 0, None, 1, False, ({"id": "a"},))
    second = ReadPage("m", "t", 1, 1, None, True, ({"id": "b"},))
    with pytest.raises(ReadError, match="totals"):
        BoundedTableReader(lambda d, t, o, n: first if o == 0 else second, "m").read("t")


def test_fingerprint_is_order_independent_but_completion_sensitive():
    complete = ReadPage("m", "t", 0, 2, None, True, ({"id": "b"}, {"id": "a"}))
    partial = ReadPage("m", "t", 0, 2, None, False, ({"id": "b"}, {"id": "a"}))
    a = BoundedTableReader(lambda d, t, o, n: complete, "m").read("t")
    b = BoundedTableReader(lambda d, t, o, n: complete, "m").read("t")
    c = BoundedTableReader(lambda d, t, o, n: partial, "m").read("t")
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint != c.fingerprint


def test_dependencies_transitively_invalidate_old_and_new_graphs_and_absence():
    a = QualifiedRef("rule", "pkg", "a")
    b = QualifiedRef("object", "pkg", "b")
    c = QualifiedRef("route", "vrf", "c")
    old = DependencyIndex()
    old.add(a, [b])
    old.add(b, [c])
    new = DependencyIndex()
    new.add(a, [b])
    new.add(b, [c])
    new.record_absence(a, AbsenceSelector("route", "vrf", "new"))
    assert {a, b, c} <= new.invalidate([c], old=old)
    assert a in new.invalidate([QualifiedRef("route", "vrf", "new")])
