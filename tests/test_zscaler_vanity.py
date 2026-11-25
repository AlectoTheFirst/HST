"""The Zscaler vanity domain is one DNS label: it is the first label of the token host."""

from __future__ import annotations

import httpx
import pytest
from pydantic import ValidationError

from hst.collectors.auth import OAuthClientCredentials
from hst.collectors.zia import ZiaConfig
from hst.collectors.zpa import ZpaConfig
from hst.collectors.zscaler_auth import ZscalerSession

AUTH = OAuthClientCredentials(client_id="cid", client_secret="not-a-real-secret")
CONFIGS = [
    pytest.param(ZiaConfig, {"tenant": "acme", "auth": AUTH}, id="zia"),
    pytest.param(ZpaConfig, {"tenant": "acme", "customer_id": "cust-1", "auth": AUTH}, id="zpa"),
]


@pytest.mark.parametrize(("model", "base"), CONFIGS)
@pytest.mark.parametrize("vanity", ["acme", "Acme", "acme-eu", "a1", "a" * 63])
def test_a_vanity_domain_is_one_dns_label(model, base, vanity):
    assert model(vanity_domain=vanity, **base).vanity_domain == vanity


@pytest.mark.parametrize(("model", "base"), CONFIGS)
@pytest.mark.parametrize(
    "vanity",
    [
        "acme.zslogin.net",
        "evil.example#",
        "user@evil.example:443/#",
        "",
        " acme",
        "acme\n",
        "-acme",
        "acme-",
        "a" * 64,
    ],
)
def test_a_host_name_or_url_text_is_refused(model, base, vanity):
    with pytest.raises(ValidationError) as caught:
        model(vanity_domain=vanity, **base)
    first = caught.value.errors()[0]
    assert first["loc"] == ("vanity_domain",)
    assert "zslogin.net" in first["msg"]


def test_the_session_refuses_a_vanity_that_is_not_one_label():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={})

    with pytest.raises(ValueError):
        ZscalerSession("evil.example#", "cid", "not-a-real-secret", transport=httpx.MockTransport(handler))
    assert seen == []


def test_one_sentence_case_label_per_zscaler_field():
    from hst.app.inventory import field_metadata as fm
    from hst.collectors.zia import ZiaConfig

    zia = {f.path: f.label for f in fm.COLLECTORS["zia"].fields}
    zpa = {f.path: f.label for f in fm.COLLECTORS["zpa"].fields}
    assert zia["location_sites"] == ZiaConfig.model_fields["location_sites"].title == "Location to site"
    assert zpa["auth.method"] == zia["auth.method"] == "Authentication method"
    assert not [c for c in fm.COLLECTORS.values() for f in c.fields if f.label == "Auth method"]


def test_a_tenant_whose_key_is_empty_is_refused():
    import pytest
    from pydantic import ValidationError

    from hst.collectors.auth import OAuthClientCredentials
    from hst.collectors.zia import ZiaConfig
    from hst.collectors.zpa import ZpaConfig

    auth = OAuthClientCredentials(client_id="cid", client_secret="sec")
    with pytest.raises(ValidationError, match="empty tenant key"):
        ZiaConfig(vanity_domain="acme", tenant="   ", auth=auth)
    with pytest.raises(ValidationError, match="customer_id is empty"):
        ZpaConfig(vanity_domain="acme", tenant="acme", customer_id=" ", auth=auth)
    assert ZiaConfig(vanity_domain="acme", tenant="Acme Corp", auth=auth).tenant == "Acme Corp"
    for model in (ZiaConfig, ZpaConfig):
        for name in ("vanity_domain", "tenant"):
            text = model.model_fields[name].description or ""
            assert text and "`" not in text, (model.__name__, name)
