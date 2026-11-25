import json

from tools.enterprise_private_acceptance import (
    REQUIRED_SCOPES,
    execute,
    load_manifest,
    qualification_scope,
)


def test_private_manifest_scope_and_retained_capture(tmp_path):
    capture = tmp_path / "capture.json"
    capture.write_text(
        json.dumps(
            {
                "outcome": "permit",
                "classification": "pass",
                "release": "recorded-release",
            }
        )
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema": "strata-private-acceptance-v1",
                "authorization": "read-only",
                "cases": [
                    {
                        "name": "retained-case",
                        "scopes": sorted(REQUIRED_SCOPES),
                        "source": str(capture),
                        "expected": ["permit"],
                    }
                ],
            }
        )
    )

    manifest, cases = load_manifest(manifest_path)
    assert qualification_scope(cases)["pending"] == ()
    report = execute(manifest, cases)
    assert report["qualified"] is True
    assert report["cases"][0]["release"] == "recorded-release"


def test_mismatch_is_not_reclassified_as_expected_unknown(tmp_path):
    capture = tmp_path / "capture.json"
    capture.write_text(json.dumps({"outcome": "unknown"}))
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema": "strata-private-acceptance-v1",
                "authorization": "read-only",
                "cases": [
                    {
                        "name": "known-permit",
                        "scopes": ["standalone-firewall"],
                        "source": str(capture),
                        "expected": ["permit"],
                    }
                ],
            }
        )
    )

    manifest, cases = load_manifest(manifest_path)
    report = execute(manifest, cases)
    assert report["qualified"] is False
    assert report["cases"][0]["classification"] == "implementation-defect"
