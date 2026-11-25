from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from hst.collectors.checkpoint_policy import CaptureBudgets, collect_checkpoint_policy


class FakeApi:
    def __init__(self, replies: dict[tuple[str, str], Any]):
        self.replies = replies
        self.calls: list[tuple[str, dict[str, object]]] = []

    def __call__(self, command: str, payload: Mapping[str, object]) -> dict[str, Any]:
        copied = dict(payload)
        self.calls.append((command, copied))
        discriminator = str(payload.get("uid", payload.get("offset", "")))
        value = self.replies[(command, discriminator)]
        if isinstance(value, Exception):
            raise value
        if isinstance(value, list):
            return value.pop(0)
        return value


def base_replies(*rows: dict[str, Any], dictionary: list[dict[str, Any]] | None = None):
    return {
        ("show-package", "pkg"): {"uid": "pkg", "access-layers": [{"uid": "layer"}], "future": 9},
        ("show-access-layer", "layer"): {"uid": "layer", "name": "Network", "future-layer": True},
        ("show-access-rulebase", "layer"): {
            "from": 1 if rows else 0,
            "to": len(rows),
            "total": len(rows),
            "rulebase": list(rows),
            "objects-dictionary": dictionary or [],
            "future-page": {"kept": True},
        },
    }


def capture(api, *, revision=lambda: "r1", **kwargs):
    sealed: list[bytes] = []

    def sink(chunk: bytes) -> str:
        sealed.append(chunk)
        return f"sealed:{len(sealed)}"

    result = collect_checkpoint_policy(
        api,
        authority_uid="manager",
        domain_uid="domain-a",
        package_uid="pkg",
        manifest_digest="manifest",
        snapshot_revision="r1",
        revision_probe=revision,
        chunk_sink=sink,
        implied_rules_complete=True,
        **kwargs,
    )
    return result, sealed


def test_capture_retains_sections_disabled_install_on_and_unknown_fields():
    section = {
        "uid": "section",
        "type": "access-section",
        "name": "s",
        "rulebase": [{"uid": "rule", "enabled": False, "install-on": ["target"], "future-rule": {"x": 1}}],
    }
    replies = base_replies(section)
    replies[("show-object", "target")] = {"uid": "target", "type": "simple-gateway"}
    result, sealed = capture(FakeApi(replies))
    assert result.complete
    assert result.bundle["package"]["future"] == 9
    assert result.bundle["rulebases"]["layer"][0]["rulebase"][0]["enabled"] is False
    assert result.bundle["rulebases"]["layer"][0]["rulebase"][0]["future-rule"]["x"] == 1
    assert result.raw_metadata["rules"] == 2
    assert len(sealed) == len(result.chunk_receipts)
    with pytest.raises(TypeError):
        result.bundle["package"]["uid"] = "changed"


def test_missing_package_never_falls_back_to_standard():
    api = FakeApi({("show-package", "pkg"): {"uid": "other"}})
    result, _ = capture(api)
    assert not result.complete
    assert any(g.code == "missing-package" for g in result.gaps)
    assert all(call[1].get("uid") != "Standard" for call in api.calls)


@pytest.mark.parametrize(
    "page, detail",
    [
        ({"from": 2, "to": 2, "total": 1, "rulebase": [{}]}, "discontinuous"),
        ({"from": 1, "to": 1, "rulebase": [{}]}, "lacks integer"),
        ({"from": 1, "to": 0, "total": 2, "rulebase": []}, "advance"),
    ],
)
def test_missing_or_reordered_pages_are_incomplete(page, detail):
    replies = base_replies()
    replies[("show-access-rulebase", "layer")] = page
    result, _ = capture(FakeApi(replies))
    assert not result.complete
    assert any(g.code == "pagination" and detail in g.detail for g in result.gaps)


def test_duplicate_rule_rejected_but_matching_section_continuation_is_merged():
    replies = base_replies()
    replies[("show-access-rulebase", "layer")] = [
        {"from": 1, "to": 1, "total": 2, "rulebase": [{"uid": "x", "type": "access-rule"}]},
        {"from": 2, "to": 2, "total": 2, "rulebase": [{"uid": "x", "type": "access-rule"}]},
    ]
    result, _ = capture(FakeApi(replies))
    assert any(g.code == "duplicate-uid" for g in result.gaps)

    replies = base_replies()
    replies[("show-access-rulebase", "layer")] = [
        {
            "from": 1,
            "to": 1,
            "total": 2,
            "rulebase": [{"uid": "s", "type": "access-section", "rulebase": [{"uid": "r1"}]}],
        },
        {
            "from": 2,
            "to": 2,
            "total": 2,
            "rulebase": [{"uid": "s", "type": "access-section", "rulebase": [{"uid": "r2"}]}],
        },
    ]
    result, _ = capture(FakeApi(replies))
    assert result.complete
    assert len(result.bundle["rulebases"]["layer"][0]["rulebase"]) == 2


def test_recursive_inline_layer_and_cyclic_groups_fetch_missing_members():
    rule = {"uid": "r", "inline-layer": "inline", "source": ["group-a"]}
    replies = base_replies(rule)
    replies.update(
        {
            ("show-access-layer", "inline"): {"uid": "inline", "name": "inline"},
            ("show-access-rulebase", "inline"): {
                "from": 1,
                "to": 1,
                "total": 1,
                "rulebase": [{"uid": "ir", "destination": ["host"]}],
                "objects-dictionary": [],
            },
            ("show-object", "group-a"): {"uid": "group-a", "type": "group", "members": ["group-b"]},
            ("show-object", "group-b"): {"uid": "group-b", "type": "group", "members": ["group-a", "host"]},
            ("show-object", "host"): {"uid": "host", "type": "host", "ipv4-address": "192.0.2.1"},
        }
    )
    result, _ = capture(FakeApi(replies))
    assert result.complete
    assert set(result.bundle["layers"]) == {"layer", "inline"}
    assert set(result.bundle["objects"]) == {"group-a", "group-b", "host"}
    assert result.bundle["object_namespaces"]["host"]["domain_uid"] == "domain-a"


def test_object_only_revision_change_and_missing_revision_are_incomplete():
    revisions = iter(["r1", "r2"])
    result, _ = capture(FakeApi(base_replies()), revision=lambda: next(revisions))
    assert any(g.code == "revision-changed" for g in result.gaps)
    result, _ = capture(FakeApi(base_replies()), revision=lambda: None)
    assert [g.code for g in result.gaps].count("revision-unproven") == 2


def test_implied_rules_need_separate_positive_evidence():
    result = collect_checkpoint_policy(
        FakeApi(base_replies()),
        authority_uid="a",
        domain_uid="d",
        package_uid="pkg",
        manifest_digest="m",
        snapshot_revision="r1",
        revision_probe=lambda: "r1",
        chunk_sink=lambda _: "sealed",
    )
    assert any(g.code == "implied-rule-unproven" for g in result.gaps)


def test_budgets_count_duplicate_dictionary_entries():
    duplicate = {"uid": "o", "type": "host", "ipv4-address": "192.0.2.1"}
    result, _ = capture(
        FakeApi(base_replies(dictionary=[duplicate, duplicate])), budgets=CaptureBudgets(objects=1)
    )
    assert any(g.code == "budget-exceeded" for g in result.gaps)


def test_domain_uid_qualifies_same_vendor_uid_in_independent_captures():
    obj = {"uid": "same", "type": "host", "ipv4-address": "192.0.2.1"}
    first, _ = capture(FakeApi(base_replies(dictionary=[obj])))
    second = collect_checkpoint_policy(
        FakeApi(base_replies(dictionary=[obj])),
        authority_uid="manager",
        domain_uid="domain-b",
        package_uid="pkg",
        manifest_digest="manifest",
        snapshot_revision="r1",
        revision_probe=lambda: "r1",
        chunk_sink=lambda _: "sealed",
        implied_rules_complete=True,
    )
    assert first.bundle["object_namespaces"]["same"] != second.bundle["object_namespaces"]["same"]


def test_missing_referenced_object_is_a_typed_gap():
    result, _ = capture(FakeApi(base_replies({"uid": "r", "source": ["missing"]})))
    assert any(g.code == "missing-object" and g.subject == "missing" for g in result.gaps)
