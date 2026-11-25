from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

import pytest

from hst.collectors.checkpoint_policy import CaptureBudgets, collect_checkpoint_policy


def run_capture(
    rows: list[Any],
    *,
    extra: dict[tuple[str, str], dict[str, Any]] | None = None,
    dictionary: list[Any] | None = None,
    total: int | None = None,
    last: int | None = None,
    depth: int = 32,
    implied: bool | None = True,
):
    replies: dict[tuple[str, str], dict[str, Any]] = {
        ("show-package", "pkg"): {"uid": "pkg", "access-layers": ["root"]},
        ("show-access-layer", "root"): {"uid": "root"},
        ("show-access-rulebase", "root"): {
            "from": 1 if rows else 0,
            "to": len(rows) if last is None else last,
            "total": len(rows) if total is None else total,
            "rulebase": rows,
            "objects-dictionary": dictionary or [],
        },
    }
    replies.update(extra or {})

    def api(command: str, payload: Mapping[str, object]) -> dict[str, Any]:
        return replies[(command, str(payload.get("uid", "")))]

    return collect_checkpoint_policy(
        api,
        authority_uid="manager",
        domain_uid="domain",
        package_uid="pkg",
        manifest_digest="manifest",
        snapshot_revision="revision",
        revision_probe=lambda: "revision",
        chunk_sink=lambda _: "sealed",
        implied_rules_complete=implied,
        budgets=CaptureBudgets(depth=depth),
    )


def test_nested_section_inline_layer_is_queued_and_section_positions_drive_paging():
    rows = [
        {
            "uid": "section",
            "type": "access-section",
            "rulebase": [
                {"uid": "r1"},
                {"uid": "r2", "inline-layer": "inline"},
            ],
        }
    ]
    extra = {
        ("show-access-layer", "inline"): {"uid": "inline"},
        ("show-access-rulebase", "inline"): {
            "from": 0,
            "to": 0,
            "total": 0,
            "rulebase": [],
            "objects-dictionary": [],
        },
    }
    result = run_capture(rows, extra=extra, total=2, last=2)
    assert result.complete
    assert set(result.bundle["layers"]) == {"root", "inline"}


def test_section_depth_is_bounded_without_recursive_overflow():
    row: dict[str, Any] = {"uid": "leaf"}
    for index in range(20):
        row = {"uid": f"section-{index}", "type": "access-section", "rulebase": [row]}
    result = run_capture([row], total=0, last=0, depth=2)
    assert any(g.code == "budget-exceeded" and "section depth" in g.detail for g in result.gaps)


def test_group_with_exclusion_fetches_include_and_except_references():
    extra = {
        ("show-object", "included"): {"uid": "included", "type": "group", "members": []},
        ("show-object", "excluded"): {"uid": "excluded", "type": "host"},
    }
    dictionary = [
        {
            "uid": "gwe",
            "type": "group-with-exclusion",
            "include": "included",
            "except": {"uid": "excluded"},
        }
    ]
    result = run_capture([{"uid": "rule", "source": ["gwe"]}], extra=extra, dictionary=dictionary)
    assert result.complete
    assert {"gwe", "included", "excluded"} == set(result.bundle["objects"])


@pytest.mark.parametrize(
    ("rows", "dictionary"),
    [([{"type": "access-rule"}], []), (["not-an-object"], []), ([{"uid": "r"}], ["bad-object"])],
)
def test_malformed_entries_are_retained_as_incompleteness(rows, dictionary):
    result = run_capture(rows, dictionary=dictionary)
    assert any(g.code == "malformed-entry" for g in result.gaps)


def test_section_continuation_does_not_mutate_raw_page_evidence():
    pages = [
        {
            "from": 1,
            "to": 1,
            "total": 2,
            "rulebase": [{"uid": "s", "type": "access-section", "rulebase": [{"uid": "first"}]}],
            "objects-dictionary": [],
        },
        {
            "from": 2,
            "to": 2,
            "total": 2,
            "rulebase": [{"uid": "s", "type": "access-section", "rulebase": [{"uid": "second"}]}],
            "objects-dictionary": [],
        },
    ]

    def api(command: str, payload: Mapping[str, object]) -> dict[str, Any]:
        if command == "show-package":
            return {"uid": "pkg", "access-layers": ["root"]}
        if command == "show-access-layer":
            return {"uid": "root"}
        return pages[0 if payload.get("offset") == 0 else 1]

    result = collect_checkpoint_policy(
        api,
        authority_uid="manager",
        domain_uid="domain",
        package_uid="pkg",
        manifest_digest="manifest",
        snapshot_revision="revision",
        revision_probe=lambda: "revision",
        chunk_sink=lambda _: "sealed",
        implied_rules_complete=True,
    )
    raw_pages = result.bundle["layers"]["root"]["rulebase-pages"]
    assert len(raw_pages[0]["rulebase"][0]["rulebase"]) == 1
    assert len(result.bundle["rulebases"]["root"][0]["rulebase"]) == 2


def test_conflicting_namespaces_never_overwrite_first_object():
    first = {"uid": "same", "type": "host", "domain": {"uid": "local"}}
    second = {"uid": "same", "type": "host", "domain": {"uid": "global"}}
    result = run_capture([{"uid": "r"}], dictionary=[first, second])
    assert any(g.code == "duplicate-uid" for g in result.gaps)
    assert result.bundle["objects"]["same"]["domain"]["uid"] == "local"


@pytest.mark.parametrize("field", ["total_pages", "rules", "objects", "bytes", "depth", "page_limit"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_budgets_require_positive_strict_integers(field, value):
    values = {
        "total_pages": 1,
        "rules": 1,
        "objects": 1,
        "bytes": 1,
        "depth": 1,
        "page_limit": 1,
    }
    values[field] = value
    with pytest.raises(ValueError, match="positive integer"):
        CaptureBudgets(**values)


def test_identifiers_are_canonical_and_completeness_requires_a_real_bool():
    with pytest.raises(ValueError, match="canonical identifier"):
        collect_checkpoint_policy(
            lambda _c, _p: {},
            authority_uid=" manager ",
            domain_uid="domain",
            package_uid="pkg",
            manifest_digest="manifest",
            snapshot_revision="revision",
            revision_probe=lambda: "revision",
            chunk_sink=lambda _: "sealed",
        )
    with pytest.raises(TypeError, match="bool or None"):
        run_capture([], implied=cast(Any, 1))
