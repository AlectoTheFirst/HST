from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from hst.collectors.checkpoint_policy import collect_checkpoint_policy


def capture(object_response: dict[str, Any]):
    sealed: list[bytes] = []

    def sink(chunk: bytes) -> str:
        sealed.append(chunk)
        return f"sealed:{len(sealed)}"

    def api(command: str, payload: Mapping[str, object]) -> dict[str, Any]:
        if command == "show-package":
            return {"uid": "package", "access-layers": ["layer"]}
        if command == "show-access-layer":
            return {"uid": "layer"}
        if command == "show-access-rulebase":
            return {
                "from": 1,
                "to": 1,
                "total": 1,
                "rulebase": [{"uid": "rule", "source": ["host"]}],
                "objects-dictionary": [],
                "unknown-page-field": "retained in sealed page",
            }
        assert command == "show-object"
        return object_response

    return (
        collect_checkpoint_policy(
            api,
            authority_uid="manager",
            domain_uid="domain",
            package_uid="package",
            manifest_digest="manifest",
            snapshot_revision="revision",
            revision_probe=lambda: "revision",
            chunk_sink=sink,
            implied_rules_complete=True,
        ),
        sealed,
    )


def test_official_show_object_envelope_is_unwrapped_but_retained_and_sealed():
    result, sealed = capture(
        {
            "object": {"uid": "host", "type": "host", "ipv4-address": "192.0.2.1"},
            "unknown-envelope-field": {"future": True},
        }
    )
    assert result.complete
    assert result.bundle["objects"]["host"]["ipv4-address"] == "192.0.2.1"
    assert result.bundle["object_envelopes"]["host"]["unknown-envelope-field"]["future"] is True
    assert b'"unknown-envelope-field"' in sealed[-1]
    assert result.raw_metadata["calls"][-1]["response_shape"] == "api-envelope"


def test_direct_object_shape_is_supported_and_explicitly_labeled_as_adapter_shape():
    result, _ = capture({"uid": "host", "type": "host", "future": 1})
    assert result.complete
    assert result.bundle["object_envelopes"]["host"]["response-shape"] == "caller-unwrapped"
    assert result.raw_metadata["calls"][-1]["response_shape"] == "caller-unwrapped"


@pytest.mark.parametrize(
    "response",
    [
        {"object": "not-an-object"},
        {"object": {"uid": "different"}},
        {"object": None, "unknown": "preserved in sealed bytes"},
    ],
)
def test_malformed_or_wrong_show_object_envelope_is_a_gap(response):
    result, sealed = capture(response)
    assert not result.complete
    assert any(g.code == "missing-object" and g.subject == "host" for g in result.gaps)
    assert sealed
