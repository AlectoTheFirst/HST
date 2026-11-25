"""collectors/http_trace.py: the HTTP exchange trace of one fetch. Off by
default, on per source through `HST_HTTP_TRACE`, attached to every client
`collectors.http.client` builds while a fetch is traced, sealed beside the
raw file, credentials never written, pruned with the raw file."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from tests.app.fakes import FakeStore
from tests.test_collector_execute import FakeSession
from tests.test_rawstore_prune import _manifest, _retained

from hst import collectors as coll
from hst.app.crypto import SecretKeyError, dek, generate_key
from hst.collectors import http as http_client
from hst.collectors import http_trace
from hst.collectors.auth import TlsConfig
from hst.collectors.base import Collector, SourceConfig
from hst.collectors.util import GraphBuilder
from hst.core import Settings, rawstore
from hst.worker import maintenance as maint


def _settings(tmp_path, **kw) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key(), **kw)


def _respond(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/login":
        return httpx.Response(
            200, json={"token": "session-secret", "user": "ada"}, headers={"Set-Cookie": "sid=abc"}
        )
    if request.url.path == "/big":
        return httpx.Response(
            200, content=b"x" * (http_trace.BODY_LIMIT + 10), headers={"Content-Type": "text/plain"}
        )
    if request.url.path == "/refused":
        return httpx.Response(400, json={"error": {"message": "unknown parameter logicalId"}})
    return httpx.Response(200, json={"data": [{"logicalId": "e1"}]}, headers={"X-Request-Id": "r-1"})


class TracedCfg(SourceConfig):
    pass


class TracedCollector(Collector):
    """A fetch that makes four exchanges through the shared client factory,
    including a login with a password and a refused read."""

    name = "traced"
    ConfigModel = TracedCfg

    def __init__(self, config: TracedCfg, settings: Settings):
        super().__init__(config, settings)
        self.scope = "traced:x"

    def fetch(self):
        client = http_client.client(
            "https://api.example", TlsConfig(), transport=httpx.MockTransport(_respond)
        )
        client.headers["Authorization"] = "Token api-secret"
        try:
            client.post("/login", json={"user": "ada", "password": "hunter2"})
            client.get("/edges", params={"include": "links.*"})
            client.post("/refused", json={"logicalId": "e1"})
            client.get("/big")
        finally:
            client.close()
        return {"edges": 1}

    def normalize(self, raw):
        b = GraphBuilder()
        b.node("Device", "dev:traced", hostname="h", role="router")
        return b.batch(self.config.source_name or self.name, self.scope)

    def probe(self) -> str:
        return "ok"

    def side_tables(self, raw):
        return {}


def _collector(settings: Settings, source_name: str = "vco-1") -> TracedCollector:
    return TracedCollector(TracedCfg(source_name=source_name), settings)


def _lines(settings: Settings, raw_path) -> list[dict]:
    body = rawstore.read_trace(rawstore.trace_path(raw_path), dek(settings))
    return [json.loads(line) for line in body.decode().splitlines() if line]


def _raw_files(settings: Settings):
    return sorted(settings.raw_dir.rglob(f"*{rawstore.SUFFIX}"))


# --- the switch ---------------------------------------------------------------------------


def test_tracing_is_off_by_default_and_leaves_no_file(tmp_path):
    settings = _settings(tmp_path)
    assert not settings.http_trace_enabled("vco-1")
    coll.execute(_collector(settings), FakeSession(), collection_ts=100)
    [raw_path] = _raw_files(settings)
    assert not rawstore.trace_path(raw_path).exists()
    assert not list(settings.raw_dir.rglob(".http-trace-*"))


@pytest.mark.parametrize("setting", ["vco-1", " vco-1 , other", "*"])
def test_the_setting_names_sources_or_all(tmp_path, setting):
    settings = _settings(tmp_path, hst_http_trace=setting)
    assert settings.http_trace_enabled("vco-1")
    assert settings.http_trace_enabled("other") == ("other" in setting or setting == "*")


def test_a_named_source_is_traced_and_another_is_not(tmp_path):
    settings = _settings(tmp_path, hst_http_trace="vco-1")
    coll.execute(_collector(settings, "vco-1"), FakeSession(), collection_ts=100)
    coll.execute(_collector(settings, "vco-2"), FakeSession(), collection_ts=100)
    by_source = {p.parent.name: p for p in _raw_files(settings)}
    assert rawstore.trace_path(by_source["vco-1"]).exists()
    assert not rawstore.trace_path(by_source["vco-2"]).exists()


# --- what a trace records -----------------------------------------------------------------


def test_every_exchange_of_the_fetch_is_recorded_in_order(tmp_path):
    settings = _settings(tmp_path, hst_http_trace="*")
    coll.execute(_collector(settings), FakeSession(), collection_ts=100)
    [raw_path] = _raw_files(settings)
    lines = _lines(settings, raw_path)
    assert [(x["method"], x["url"], x["status"]) for x in lines] == [
        ("POST", "https://api.example/login", 200),
        ("GET", "https://api.example/edges?include=links.%2A", 200),
        ("POST", "https://api.example/refused", 400),
        ("GET", "https://api.example/big", 200),
    ]
    assert all(isinstance(x["elapsed_ms"], int) and x["elapsed_ms"] >= 0 for x in lines)
    assert lines[2]["request"]["body"]["json"] == {"logicalId": "e1"}
    assert lines[2]["response"]["body"]["json"] == {"error": {"message": "unknown parameter logicalId"}}
    assert lines[1]["request"]["body"] is None
    assert lines[1]["response"]["headers"] == {
        "content-type": "application/json",
        "content-length": "29",
        "x-request-id": "r-1",
    }


def test_credentials_never_reach_the_trace(tmp_path):
    settings = _settings(tmp_path, hst_http_trace="*")
    coll.execute(_collector(settings), FakeSession(), collection_ts=100)
    [raw_path] = _raw_files(settings)
    body = rawstore.read_trace(rawstore.trace_path(raw_path), dek(settings)).decode()
    assert "api-secret" not in body
    assert "hunter2" not in body
    assert "session-secret" not in body
    assert "sid=abc" not in body
    login = _lines(settings, raw_path)[0]
    assert "authorization" not in login["request"]["headers"]
    assert login["request"]["body"]["json"] == {"user": "ada", "password": http_trace.REDACTED}
    assert login["response"]["body"]["json"] == {"token": http_trace.REDACTED, "user": "ada"}
    assert "set-cookie" not in login["response"]["headers"]


def test_redaction_reaches_nested_keys_and_leaves_the_rest():
    assert http_trace.redact({"a": [{"apiKey": "k", "name": "n"}], "Password": "p", "n": 1}) == {
        "a": [{"apiKey": http_trace.REDACTED, "name": "n"}],
        "Password": http_trace.REDACTED,
        "n": 1,
    }


def test_a_body_past_the_bound_is_cut_and_marked(tmp_path):
    settings = _settings(tmp_path, hst_http_trace="*")
    coll.execute(_collector(settings), FakeSession(), collection_ts=100)
    [raw_path] = _raw_files(settings)
    big = _lines(settings, raw_path)[3]["response"]["body"]
    assert big["truncated"] is True
    assert big["bytes"] == http_trace.BODY_LIMIT + 10
    assert len(big["text"]) == http_trace.BODY_LIMIT


def test_the_trace_is_sealed_like_the_raw_file(tmp_path):
    settings = _settings(tmp_path, hst_http_trace="*")
    coll.execute(_collector(settings), FakeSession(), collection_ts=100)
    [raw_path] = _raw_files(settings)
    path = rawstore.trace_path(raw_path)
    assert path.name.endswith(rawstore.TRACE_SUFFIX)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert b"api.example" not in path.read_bytes()
    with pytest.raises(SecretKeyError):
        rawstore.read_trace(path, generate_key())


# --- lifecycle ----------------------------------------------------------------------------


def test_a_failed_fetch_discards_its_spool(tmp_path):
    settings = _settings(tmp_path, hst_http_trace="*")

    class Failing(TracedCollector):
        def fetch(self):
            super().fetch()
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        coll.fetch_traced(Failing(TracedCfg(source_name="vco-1"), settings))
    assert not list(settings.raw_dir.rglob("*"))


def test_fetch_traced_returns_the_trace_and_park_seals_it(tmp_path):
    settings = _settings(tmp_path, hst_http_trace="*")
    c = _collector(settings)
    raw, trace = coll.fetch_traced(c)
    assert trace is not None and trace.exchanges == 4
    assert trace.spool_path.exists()
    path = coll.park(c, raw, trace=trace)
    assert not trace.spool_path.exists()
    assert rawstore.trace_path(path).exists()
    assert [x["status"] for x in _lines(settings, path)] == [200, 200, 400, 200]


def test_a_skipped_payload_discards_its_trace(tmp_path):
    settings = _settings(tmp_path, hst_http_trace="*")
    _raw, trace = coll.fetch_traced(_collector(settings))
    assert trace is not None
    trace.discard()
    assert not trace.spool_path.exists()
    trace.discard()  # twice is harmless


def test_a_client_built_outside_a_traced_fetch_has_no_trace_hooks():
    client = http_client.client("https://api.example", TlsConfig(), transport=httpx.MockTransport(_respond))
    try:
        assert client.event_hooks["request"] == []
        assert len(client.event_hooks["response"]) == 1
    finally:
        client.close()


# --- listing and pruning ------------------------------------------------------------------


def test_traces_are_listed_newest_first_with_their_path_segments(tmp_path):
    settings = _settings(tmp_path, hst_http_trace="*")
    coll.execute(_collector(settings, "vco-1"), FakeSession(), collection_ts=100)
    coll.execute(_collector(settings, "vco-2"), FakeSession(), collection_ts=200)
    found = rawstore.traces(settings.raw_dir)
    assert [t.source for t in found] == ["vco-2", "vco-1"] or [t.source for t in found] == ["vco-1", "vco-2"]
    assert all(t.host == "" and t.size > 0 and t.path.is_file() for t in found)
    assert found[0].fetch_ts_ms >= found[1].fetch_ts_ms


async def test_the_prune_deletes_the_trace_with_its_raw_file(tmp_path, monkeypatch):
    settings = _settings(tmp_path, hst_http_trace="*", evidence_retention_days=30)
    old = datetime.now(UTC) - timedelta(days=400)
    run_id = f"{int(old.timestamp() * 1000)}-aaaaaaaa"
    raw_path = rawstore.write(settings.raw_dir, "nxos", run_id, {"x": 1}, host="h1", key=dek(settings))
    trace = http_trace.HttpTrace("nxos", settings.raw_dir)
    trace.record({"ts": 1, "method": "GET", "url": "https://x/y", "status": 200})
    trace_path = trace.seal(raw_path, dek(settings))
    rawstore.mark_joined(raw_path, snapshot_ts=1000)
    _manifest(settings, 1000)
    _manifest(settings, 5000)
    _retained(monkeypatch, [5000])

    victims = await maint.prune_rawstore(settings, FakeStore(), keep=2)

    assert victims == [raw_path]
    assert not raw_path.exists()
    assert not trace_path.exists()


# --- credentials in form bodies, URLs, compound keys and oversize JSON ---------------------


def test_a_zscaler_token_exchange_keeps_no_client_secret(tmp_path):
    from hst.collectors.zscaler_auth import ZscalerSession

    settings = _settings(tmp_path)
    api_calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            return httpx.Response(
                200, json={"access_token": "tok-1", "token_type": "Bearer", "expires_in": 3600}
            )
        api_calls.append(request.url.path)
        return httpx.Response(401 if len(api_calls) == 1 else 200, json={"status": "ok"})

    trace = http_trace.HttpTrace("zia-1", settings.raw_dir)
    with http_trace.activate(trace):
        session = ZscalerSession(
            "acme",
            "cid",
            "not-a-real-secret",
            transport=httpx.MockTransport(handler),
            sleep=lambda s: None,
            clock=lambda: 0.0,
        )
        try:
            session.get("/zia/api/v1/status")
        finally:
            session.close()
    raw_path = rawstore.write(
        settings.raw_dir, "zia-1", "1000-aaaaaaaa", {"x": 1}, host="", key=dek(settings)
    )
    trace.seal(raw_path, dek(settings))

    lines = _lines(settings, raw_path)
    tokens = [x for x in lines if x["method"] == "POST" and "zslogin.net" in x["url"]]
    assert len(tokens) == 2
    for line in tokens:
        assert line["request"]["body"]["form"] == [
            ["grant_type", "client_credentials"],
            ["client_id", "cid"],
            ["client_secret", http_trace.REDACTED],
        ]
        assert "text" not in line["request"]["body"]
    body = rawstore.read_trace(rawstore.trace_path(raw_path), dek(settings)).decode()
    assert "not-a-real-secret" not in body
    assert "tok-1" not in body


def test_a_form_body_keeps_order_and_repeats_and_redacts_credentials():
    assert http_trace._body(b"a=1&password=x&a=2", "application/x-www-form-urlencoded; charset=utf-8") == {
        "bytes": 18,
        "form": [["a", "1"], ["password", http_trace.REDACTED], ["a", "2"]],
    }


def test_a_form_body_past_the_bound_drops_the_cut_pair():
    raw = b"client_secret=not-a-real-secret&pad=" + b"x" * http_trace.BODY_LIMIT
    record = http_trace._body(raw, "application/x-www-form-urlencoded")
    assert record["truncated"] is True
    assert record["form"] == [["client_secret", http_trace.REDACTED]]
    assert "text" not in record


def test_the_url_keeps_no_userinfo_and_no_credential_query_value(tmp_path):
    settings = _settings(tmp_path)
    trace = http_trace.HttpTrace("t", settings.raw_dir)
    with http_trace.activate(trace):
        client = http_client.client(
            "https://api.example", TlsConfig(), transport=httpx.MockTransport(_respond)
        )
        try:
            client.get("https://user:pw@api.example/x?apiKey=abc&page=2")
        finally:
            client.close()
    raw_path = rawstore.write(settings.raw_dir, "t", "1000-aaaaaaaa", {"x": 1}, host="", key=dek(settings))
    trace.seal(raw_path, dek(settings))
    [line] = _lines(settings, raw_path)
    assert line["url"] == "https://api.example/x?apiKey=%5Bredacted%5D&page=2"


def test_keys_that_contain_a_credential_word_are_redacted():
    device = {
        "name": "XX-EDGE-FW-01",
        "uuid": "u-1",
        "logicalId": "l-1",
        "aSide": "a",
        "inside": "i",
        "keepalive": 10,
        "session-timeout": 30,
        "vendorConfig": {"adminPassword": "p"},
        "interfaces": [{"name": "eth0", "sshPassword": "p"}],
        "rootPassword": "p",
        "licenseSecret": "p",
        "privateKey": "p",
        "panoramaAuthKey": "p",
        "clientSecret": "p",
        "accessToken": "p",
        "preSharedKey": "p",
    }
    out = http_trace.redact(device)
    for key in (
        "vendorConfig",
        "rootPassword",
        "licenseSecret",
        "privateKey",
        "panoramaAuthKey",
        "clientSecret",
        "accessToken",
        "preSharedKey",
    ):
        assert out[key] == http_trace.REDACTED, key
    assert out["interfaces"][0] == {"name": "eth0", "sshPassword": http_trace.REDACTED}
    for key in ("name", "uuid", "logicalId", "aSide", "inside", "keepalive", "session-timeout"):
        assert out[key] == device[key], key


def test_snmp_communities_are_redacted_and_bgp_communities_are_kept():
    out = http_trace.redact(
        {
            "snmp": {"snmpv2c": {"community": "c", "enabled": True}},
            "bgp": {"community": "65000:100"},
            "snmpCommunity": "c",
        }
    )
    assert out == {
        "snmp": {"snmpv2c": {"community": http_trace.REDACTED, "enabled": True}},
        "bgp": {"community": "65000:100"},
        "snmpCommunity": http_trace.REDACTED,
    }


def test_unifi_x_fields_are_credentials_except_the_public_ones():
    fields = {"x_passphrase": "p", "x_iapp_key": "k", "x_has_ssh_hostkey": True, "x_fingerprint": "f"}
    assert http_trace.redact(fields) == {
        "x_passphrase": http_trace.REDACTED,
        "x_iapp_key": http_trace.REDACTED,
        "x_has_ssh_hostkey": True,
        "x_fingerprint": "f",
    }
    assert http_trace.redact({"cak": "c", "ckn": "n", "cake": "x"}) == {
        "cak": http_trace.REDACTED,
        "ckn": http_trace.REDACTED,
        "cake": "x",
    }


def test_a_json_body_past_the_bound_is_redacted_before_it_is_cut():
    raw = json.dumps(
        {"vendorConfig": {"adminPassword": "not-a-real-password"}, "pad": "x" * http_trace.BODY_LIMIT}
    ).encode()
    record = http_trace._body(raw, "application/json")
    assert record["truncated"] is True
    assert record["bytes"] == len(raw)
    assert len(record["text"]) <= http_trace.BODY_LIMIT
    assert "not-a-real-password" not in record["text"]


def test_json_with_another_content_type_is_redacted():
    assert http_trace._body(b'{"password": "x"}', "text/plain") == {
        "bytes": 17,
        "json": {"password": http_trace.REDACTED},
    }


def test_the_trace_redacts_every_word_a_collector_strips_from_the_raw_store():
    import re
    from pathlib import Path

    from hst.collectors import equinix, zpa

    root = Path(coll.__file__).parent
    found = set()
    for path in sorted(root.rglob("*.py")):
        if path.name == "util.py":
            continue
        found |= set(
            re.findall(
                r"without_keys\([^,()]+(?:\([^()]*\))?[^,()]*,\s*([A-Za-z_][A-Za-z0-9_]*)\)", path.read_text()
            )
        )
    assert found == {"_EDGE_SECRET_KEYS", "_PROVISIONING_SECRET_KEYS"}
    for word in (*equinix._EDGE_SECRET_KEYS, *zpa._PROVISIONING_SECRET_KEYS):
        for key in (word, "admin" + word.capitalize(), f"x_{word}_y"):
            assert http_trace.redact({key: "v"}) == {key: http_trace.REDACTED}, key


def test_a_traced_network_edge_fetch_keeps_no_device_password(tmp_path, monkeypatch):
    from tests.test_equinix_network_edge import EDGE_DEVICE, LINK_PAIR, _config, _transport

    from hst.collectors import equinix
    from hst.collectors.equinix import EquinixCollector

    transport, _calls = _transport([EDGE_DEVICE], [LINK_PAIR])
    monkeypatch.setattr(equinix, "_transport", lambda config: transport)
    settings = _settings(tmp_path, hst_http_trace="*")
    c = EquinixCollector(_config(network_edge=True, source_name="eqx-1"), settings)
    raw, trace = coll.fetch_traced(c)
    assert trace is not None
    path = coll.park(c, raw, trace=trace)
    lines = _lines(settings, path)
    text = json.dumps(lines)
    assert "not-a-real-password" not in text
    assert "XX-EDGE-FW-01" in text


def test_the_rate_limit_headers_are_kept(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"ok": True},
            headers={"x-ratelimit-limit": "5000", "x-ratelimit-remaining": "4990", "x-ratelimit-reset": "42"},
        )

    settings = _settings(tmp_path)
    trace = http_trace.HttpTrace("t", settings.raw_dir)
    with http_trace.activate(trace):
        client = http_client.client(
            "https://api.example", TlsConfig(), transport=httpx.MockTransport(handler)
        )
        client.headers["Authorization"] = "Bearer not-a-real-token"
        try:
            client.get("/x")
        finally:
            client.close()
    raw_path = rawstore.write(settings.raw_dir, "t", "1000-aaaaaaaa", {"x": 1}, host="", key=dek(settings))
    trace.seal(raw_path, dek(settings))
    [line] = _lines(settings, raw_path)
    headers = line["response"]["headers"]
    assert headers["x-ratelimit-limit"] == "5000"
    assert headers["x-ratelimit-remaining"] == "4990"
    assert headers["x-ratelimit-reset"] == "42"
    assert "authorization" not in line["request"]["headers"]
