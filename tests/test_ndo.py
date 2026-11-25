"""NDO intent collector: schemas and templates to NdoSchema, NdoTemplate and DEFINES."""

import json

import httpx

from hst.collectors.ndo import NdoCollector, NdoConfig, normalize_ndo
from hst.core import Settings
from hst.core import uid as uidmod

RAW = {
    "sites": [{"id": "s1", "name": "dc1-site", "apicSiteId": "1"}],
    "schemas": [
        {
            "id": "sch-1",
            "displayName": "prod-schema",
            "templates": [
                {
                    "name": "web-tpl",
                    "displayName": "web-tpl",
                    "tenantId": "tn-1",
                    "tenantName": "prod",
                    "anps": [{"name": "web", "epgs": [{"name": "fe"}, {"name": "be"}]}],
                    "bds": [{"name": "web-bd"}],
                    "sites": ["s1"],
                }
            ],
        }
    ],
}


def _cfg(**over):
    base = {
        "url": "https://ndo.example",
        "auth": {"method": "user_password", "username": "ro", "password": "pw"},
        "site_fabrics": {"dc1-site": "fab1"},
    }
    base.update(over)
    return NdoConfig(**base)


def _norm(raw=None, site_fabrics=None):
    return normalize_ndo(
        raw or RAW,
        host="ndo.example",
        site_fabrics=site_fabrics if site_fabrics is not None else {"dc1-site": "fab1"},
    )


def test_uid_builder():
    assert uidmod.ndo("ndo.example", "sch-1") == "ndo:ndo-example:sch-1"


def test_schema_and_template_nodes():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    sch = uidmod.ndo("ndo.example", "sch-1")
    tpl = uidmod.ndo("ndo.example", "sch-1/web-tpl")
    assert nodes[sch].label == "NdoSchema"
    assert nodes[sch].props["name"] == "prod-schema"
    assert nodes[tpl].label == "NdoTemplate"
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert ("HAS", sch, tpl) in rels


def test_defines_edges_toward_apic_uids():
    batch = _norm()
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    tpl = uidmod.ndo("ndo.example", "sch-1/web-tpl")
    fe = uidmod.aci("fab1", "uni/tn-prod/ap-web/epg-fe")
    bd = uidmod.aci("fab1", "uni/tn-prod/BD-web-bd")
    assert ("DEFINES", tpl, fe) in rels
    assert ("DEFINES", tpl, bd) in rels
    # The APIC source owns the DEFINES targets.
    assert all(n.label != "Epg" for n in batch.nodes)


def test_unmapped_site_emits_no_defines():
    batch = _norm(site_fabrics={})
    assert not [r for r in batch.rels if r.rel_type == "DEFINES"]


def test_probe_and_fetch(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            body = json.loads(request.content)
            assert body["username"] == "ro"
            return httpx.Response(200, json={"token": "tok"})
        if request.url.path == "/api/v1/platform/version":
            return httpx.Response(200, json={"version": "4.2(1a)"})
        if request.url.path == "/api/v1/schemas":
            return httpx.Response(200, json={"schemas": RAW["schemas"]})
        if request.url.path == "/api/v1/sites":
            return httpx.Response(200, json={"sites": RAW["sites"]})
        raise AssertionError(f"unexpected path {request.url.path}")

    monkeypatch.setattr("hst.collectors.ndo._transport", lambda config: httpx.MockTransport(handler))
    c = NdoCollector(_cfg(), Settings(_env_file=None))
    assert "4.2(1a)" in c.probe()
    raw = c.fetch()
    assert set(raw) == {"schemas", "sites"}
