"""VeloCloud paging follows `metaData.nextPageLink` tokens and bounds a
malformed or cyclic continuation before another request."""

import httpx
import pytest

from hst.collectors.velocloud import VeloCloudCollector, VeloCloudConfig
from hst.core.config import Settings

from .test_velocloud import _config


def _page(token):
    return {"data": [], "metaData": {"nextPageLink": token, "more": token is not None}}


def test_the_token_goes_back_as_the_only_query_parameter():
    """The server ignores every other parameter with the token, so the second
    request sends the token alone."""
    seen = []

    def respond(request):
        seen.append(dict(request.url.params))
        return httpx.Response(200, json=_page("second" if len(seen) == 1 else None))

    collector = VeloCloudCollector(_config(), Settings(_env_file=None))
    with httpx.Client(base_url="https://vco.example", transport=httpx.MockTransport(respond)) as client:
        assert len(collector._pages(client, "/edges", limit=50)) == 2
    assert seen == [{"limit": "50"}, {"nextPageLink": "second"}]


@pytest.mark.parametrize("meta", [7, {"nextPageLink": 7}])
def test_malformed_metadata_is_rejected_before_another_request(meta):
    seen = []

    def respond(request):
        seen.append(request)
        return httpx.Response(200, json={"data": [], "metaData": meta})

    collector = VeloCloudCollector(_config(), Settings(_env_file=None))
    with (
        httpx.Client(base_url="https://vco.example", transport=httpx.MockTransport(respond)) as client,
        pytest.raises(ValueError, match="pagination"),
    ):
        collector._pages(client, "/edges")
    assert len(seen) == 1


def test_cyclic_continuation_is_bounded():
    collector = VeloCloudCollector(_config(), Settings(_env_file=None))
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=_page("again")))
    with (
        httpx.Client(base_url="https://vco.example", transport=transport) as client,
        pytest.raises(ValueError, match="cyclic"),
    ):
        collector._pages(client, "/api/sdwan/v2/edges")


def test_a_bare_array_is_one_page():
    collector = VeloCloudCollector(_config(), Settings(_env_file=None))
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=[{"status": "STABLE"}]))
    with httpx.Client(base_url="https://vco.example", transport=transport) as client:
        assert collector._pages(client, "/edges") == [[{"status": "STABLE"}]]


def test_three_component_minimum_release_is_accepted():
    values = _config().model_dump()
    values["orchestrator_release"] = "5.0.0"
    assert VeloCloudConfig.model_validate(values).orchestrator_release == "5.0.0"


def test_enterprise_ids_accept_lines_and_commas():
    assert _config(enterprise_logical_ids="a\n b ,c\n").enterprise_ids == ["a", "b", "c"]
    assert _config(enterprise_logical_ids="").enterprise_ids == []


def test_a_stored_single_enterprise_config_validates():
    values = _config().model_dump()
    del values["enterprise_logical_ids"]
    values["enterprise_logical_id"] = "ent-old"
    assert VeloCloudConfig.model_validate(values).enterprise_ids == ["ent-old"]
