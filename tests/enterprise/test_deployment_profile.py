import json
from pathlib import Path

ROOT = Path(__file__).parents[2]


def test_analysis_profiles_are_bounded_and_render_explicit_engine_settings():
    values = (ROOT / "deploy/helm/hst/values.yaml").read_text()
    template = (ROOT / "deploy/helm/hst/templates/deployment.yaml").read_text()
    schema = json.loads((ROOT / "deploy/helm/hst/values.schema.json").read_text())

    assert "profile: standard" in values
    assert "enterprise: { engine: symbolic-v2" in values
    assert "memory: 4Gi" in values
    assert "mergeOverwrite" in template
    for name in (
        "ANALYSIS_ENGINE",
        "ANALYSIS_MEMORY_MB",
        "ANALYSIS_TIMEOUT_S",
        "ANALYSIS_CACHE_MB",
        "ANALYSIS_RESULT_MB",
    ):
        assert name in template
    analysis = schema["properties"]["analysis"]
    assert analysis["properties"]["profile"]["enum"] == ["standard", "enterprise"]
    profile = schema["definitions"]["analysisProfile"]
    assert profile["properties"]["workers"]["maximum"] == 1
    assert profile["properties"]["resultMb"]["minimum"] == 64


def test_analysis_profiles_set_the_clock_declaration_and_the_evidence_policy():
    values = (ROOT / "deploy/helm/hst/values.yaml").read_text()
    helpers = (ROOT / "deploy/helm/hst/templates/_helpers.tpl").read_text()
    validate = (ROOT / "deploy/helm/hst/templates/_validate.tpl").read_text()
    schema = json.loads((ROOT / "deploy/helm/hst/values.schema.json").read_text())

    keys = {
        "clockQuality": "COLLECTOR_CLOCK_QUALITY",
        "clockAssumption": "COLLECTOR_CLOCK_ASSUMPTION",
        "evidenceMaxAgeSeconds": "ANALYSIS_EVIDENCE_MAX_AGE_S",
        "evidenceMaxSkewSeconds": "ANALYSIS_EVIDENCE_MAX_SKEW_S",
        "evidenceConsistency": "ANALYSIS_EVIDENCE_CONSISTENCY_MODE",
        "evidenceStableWindowAssumption": "ANALYSIS_EVIDENCE_STABLE_WINDOW_ASSUMPTION",
    }
    profile = schema["definitions"]["analysisProfile"]["properties"]
    for key, env in keys.items():
        assert key in profile
        assert f"name: {env}" in helpers
        assert values.count(f"{key}:") == 2
    assert profile["clockQuality"]["enum"] == ["unknown", "trusted"]
    assert profile["evidenceConsistency"]["enum"] == ["bounded-window", "stable-window-assumption"]
    assert "clockQuality=trusted requires clockAssumption" in validate
    assert "stable-window-assumption requires evidenceStableWindowAssumption" in validate
