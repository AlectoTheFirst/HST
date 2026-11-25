"""The NDO collector reads the intent schemas and templates of an NDO."""

from __future__ import annotations

from typing import Any

import httpx

from hst.core import uid
from hst.core.model import Batch

from . import http
from .auth import TlsConfig, UserPassword
from .base import Collector, SourceConfig, register
from .util import GraphBuilder

LOGIN_PATH = "/login"
VERSION_PATH = "/api/v1/platform/version"


def _transport(config: NdoConfig) -> httpx.BaseTransport | None:
    return None  # A test replaces this function.


def _scope(host: str) -> str:
    """The scope partition matches the host slug of uid.ndo."""
    return f"ndo:{uid.slug(host).replace('.', '-')}"


class NdoConfig(SourceConfig):
    url: str
    auth: UserPassword
    tls: TlsConfig = TlsConfig()
    # The key is an NDO site name. The value is the `fabric` namespace of the matching apic source.
    # A template on an unmapped site gets nodes and no DEFINES edges.
    site_fabrics: dict[str, str] = {}  # noqa: RUF012 - pydantic field


@register
class NdoCollector(Collector):
    name = "ndo"
    ConfigModel = NdoConfig
    KIND = "orchestrator"

    def __init__(self, config: NdoConfig, settings):
        super().__init__(config, settings)
        self.scope = _scope(httpx.URL(config.url).host or config.url)

    def _login(self, client: httpx.Client) -> None:
        c = self.config
        resp = client.post(
            LOGIN_PATH, json={"username": c.auth.username, "password": c.auth.password.get_secret_value()}
        )
        if resp.status_code != 200:
            raise RuntimeError(f"NDO login failed: HTTP {resp.status_code}")
        client.headers["Authorization"] = f"Bearer {resp.json()['token']}"

    def _client(self) -> httpx.Client:
        c = self.config
        return http.logged_in_client(c.url, c.tls, self._login, timeout=60, transport=_transport(c))

    def probe(self) -> str:
        # The client of `http.logged_in_client` raises when it is entered as a context manager.
        client = self._client()
        try:
            v = client.get(VERSION_PATH)
            v.raise_for_status()
            return f"login ok: NDO {v.json().get('version', '?')} at {self.config.url}"
        finally:
            client.close()

    def fetch(self) -> dict[str, Any]:
        client = self._client()
        try:
            schemas = client.get("/api/v1/schemas")
            schemas.raise_for_status()
            sites = client.get("/api/v1/sites")
            sites.raise_for_status()
            return {"schemas": schemas.json().get("schemas", []), "sites": sites.json().get("sites", [])}
        finally:
            client.close()

    def normalize(self, raw: dict[str, Any]) -> Batch:
        host = httpx.URL(self.config.url).host or self.config.url
        return normalize_ndo(raw, host=host, site_fabrics=self.config.site_fabrics)


def normalize_ndo(raw: dict[str, Any], *, host: str, site_fabrics: dict[str, str]) -> Batch:
    b = GraphBuilder()
    site_names = {s.get("id"): s.get("name") for s in raw.get("sites", [])}
    for schema in raw.get("schemas", []):
        sch = b.node("NdoSchema", uid.ndo(host, schema["id"]), name=schema.get("displayName"))
        for tpl in schema.get("templates", []):
            tuid = b.node(
                "NdoTemplate",
                uid.ndo(host, f"{schema['id']}/{tpl['name']}"),
                name=tpl.get("displayName") or tpl["name"],
                tenant=tpl.get("tenantName"),
            )
            b.rel("HAS", "NdoSchema", sch, "NdoTemplate", tuid)
            # `fabrics` holds the mapped fabric of each site of the template.
            fabrics = [
                site_fabrics[site_names[sid]]
                for sid in tpl.get("sites", [])
                if site_names.get(sid) in site_fabrics
            ]
            tenant = tpl.get("tenantName")
            if not tenant:
                continue
            for fabric in fabrics:
                for anp in tpl.get("anps", []):
                    for epg in anp.get("epgs", []):
                        dn = f"uni/tn-{tenant}/ap-{anp['name']}/epg-{epg['name']}"
                        b.rel("DEFINES", "NdoTemplate", tuid, "Epg", uid.aci(fabric, dn))
                for bd in tpl.get("bds", []):
                    dn = f"uni/tn-{tenant}/BD-{bd['name']}"
                    b.rel("DEFINES", "NdoTemplate", tuid, "BridgeDomain", uid.aci(fabric, dn))
    return b.batch("ndo", _scope(host))
