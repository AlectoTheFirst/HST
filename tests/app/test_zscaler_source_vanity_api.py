"""The sources API refuses a Zscaler vanity domain that is not one DNS label."""

from __future__ import annotations

from tests.app.conftest import login
from tests.app.test_sources_api import make_app_client

ZIA_BODY = {
    "name": "zia-acme",
    "type": "zia",
    "config": {
        "vanity_domain": "acme",
        "tenant": "acme",
        "auth": {"method": "oauth_client", "client_id": "cid", "client_secret": "not-a-real-secret"},
    },
}


async def test_the_api_refuses_a_vanity_domain_that_is_not_one_label(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        bad = {**ZIA_BODY, "config": {**ZIA_BODY["config"], "vanity_domain": "acme.zslogin.net"}}
        r = await client.post("/api/sources", json=bad)
        assert r.status_code == 422
        assert r.json()["error"].startswith("invalid config: vanity_domain")
        assert (await client.post("/api/sources", json=ZIA_BODY)).status_code == 201
        r = await client.patch("/api/sources/zia-acme", json={"config": {"vanity_domain": "evil.example#"}})
        assert r.status_code == 422
        [row] = [s for s in (await client.get("/api/sources")).json()["sources"] if s["name"] == "zia-acme"]
        assert row["config"]["vanity_domain"] == "acme"
