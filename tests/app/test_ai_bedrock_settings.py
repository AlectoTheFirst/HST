"""Bedrock setup errors must identify the missing region, not an absent key."""

import pytest
from tests.app.conftest import login

from hst.app.agent.registry import BY_ID


@pytest.mark.parametrize("region", ["", "   "])
async def test_bedrock_probe_names_the_missing_region_without_calling_aws(client, monkeypatch, region):
    def unexpected_probe(*args):
        pytest.fail("a missing region must be rejected before contacting AWS")

    monkeypatch.setattr("hst.app.routes.ai._probe", unexpected_probe)
    await login(client, "ada")
    response = await client.post(
        "/api/settings/ai/test",
        json={
            "provider": "bedrock",
            "model": "anthropic.claude-opus-5",
            "options": {"aws_region": region},
            "secrets": {"aws_bedrock_api_key": "ABSK-test"},
        },
    )
    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert response.json()["error"] == "an AWS region is required to test Bedrock"


def test_bedrock_descriptor_requires_a_region_and_explains_the_default_endpoint():
    options = {field.name: field for field in BY_ID["bedrock"].options}
    assert options["aws_region"].required
    assert "every auth mode" in options["aws_region"].help
    assert not options["base_url"].required
    assert "blank for the Bedrock Runtime endpoint" in options["base_url"].help
