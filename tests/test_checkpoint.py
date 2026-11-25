"""Check Point collector: Web API client mechanics (fixture-first, MockTransport)."""

import base64
import json
import re

import httpx
import pytest

from hst.app.crypto import generate_key
from hst.collectors.checkpoint import CpCollector, CpConfig
from hst.core import Settings

CP_OBJECTS = [
    {"uid": "h-fe", "name": "web-fe", "type": "host", "ipv4-address": "10.1.1.10"},
    {"uid": "n-be", "name": "be-net", "type": "network", "subnet4": "10.1.2.0", "mask-length4": 24},
    {"uid": "g-web", "name": "web-grp", "type": "group", "members": ["h-fe"]},
    {"uid": "svc-https", "name": "https", "type": "service-tcp", "port": "443"},
    {"uid": "act-accept", "name": "Accept", "type": "RulebaseAction"},
    {"uid": "act-drop", "name": "Drop", "type": "RulebaseAction"},
    {"uid": "obj-any", "name": "Any", "type": "CpmiAnyObject"},
]
CP_RULEBASE_PAGE = {
    # Web API rulebases nest rules inside an access-section container.
    "rulebase": [
        {
            "uid": "sec-1",
            "type": "access-section",
            "name": "Section A",
            "rulebase": [
                {
                    "uid": "r-1",
                    "type": "access-rule",
                    "rule-number": 1,
                    "name": "web",
                    "enabled": True,
                    "action": "act-accept",
                    "source": ["g-web"],
                    "destination": ["n-be"],
                    "service": ["svc-https"],
                },
                {
                    "uid": "r-2",
                    "type": "access-rule",
                    "rule-number": 2,
                    "name": "cleanup",
                    "enabled": True,
                    "action": "act-drop",
                    "source": ["obj-any"],
                    "destination": ["obj-any"],
                    "service": ["obj-any"],
                },
            ],
        },
    ],
    "objects-dictionary": CP_OBJECTS,
    "total": 2,
    "to": 2,
}


# The reads fetch() makes besides the policy itself: the published session
# that keys the replay cache, and the global properties that say whether
# implied rules apply. Neither is required for a collection.
_OPTIONAL_READS = {
    "show-last-published-session": lambda: httpx.Response(200, json={"uid": "pub-1"}),
    "show-global-properties": lambda: httpx.Response(
        200, json={"firewall": {"accept-control-connections": True}}
    ),
    "show-api-versions": lambda: httpx.Response(200, json={"current-version": "1.9"}),
}


def _cfg(**over):
    base = {"host": "cp-mgmt.example", "auth": {"method": "api_key", "key": "key1"}}
    base.update(over)
    return CpConfig(**base)


def make_mock(
    rulebase_pages: int = 1,
    rules_per_page: int = 2,
    nat_response: httpx.Response | None = None,
    packages: list[str] | None = None,
):
    packages = packages if packages is not None else ["Standard"]
    calls = {"login": [], "cmds": []}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        cmd = request.url.path.removeprefix("/web_api/")
        body = json.loads(request.content or b"{}")
        if cmd == "login":
            calls["login"].append(body)
            return httpx.Response(200, json={"sid": "SID1", "api-server-version": "1.9"})
        assert request.headers.get("X-chkp-sid") == "SID1"
        calls["cmds"].append((cmd, body))
        if cmd == "logout":
            calls["logout"] = calls.get("logout", 0) + 1
            return httpx.Response(200, json={"message": "OK"})
        if cmd == "show-api-versions":
            return httpx.Response(200, json={"current-version": "1.9", "supported-versions": ["1.8", "1.9"]})
        if cmd in _OPTIONAL_READS:
            return _OPTIONAL_READS[cmd]()
        if cmd == "show-gateways-and-servers":
            return httpx.Response(
                200,
                json={
                    "objects": [
                        {"uid": "gw-1", "name": "fw1", "type": "simple-gateway", "ipv4-address": "10.9.0.1"}
                    ],
                    "total": 1,
                },
            )
        if cmd == "show-access-layers":
            return httpx.Response(
                200, json={"access-layers": [{"uid": "lay-1", "name": "Network"}], "total": 1}
            )
        if cmd == "show-access-rulebase":
            offset = body.get("offset", 0)
            assert body["details-level"] == "full"
            assert body["use-object-dictionary"] is True
            if rulebase_pages == 1 and rules_per_page == 2:
                # The default shape serves the one fixed CP_RULEBASE_PAGE.
                return httpx.Response(200, json=CP_RULEBASE_PAGE)
            total = rulebase_pages * rules_per_page
            rules = [
                {"uid": f"r-{offset + i}", "rule-number": offset + i + 1, "type": "access-rule"}
                for i in range(rules_per_page)
                if offset + i < total
            ]
            return httpx.Response(
                200,
                json={
                    "rulebase": rules,
                    "objects-dictionary": [],
                    "total": total,
                    "to": min(offset + rules_per_page, total),
                },
            )
        if cmd == "show-packages":
            return httpx.Response(
                200,
                json={
                    "packages": [{"name": p, "uid": f"pkg-{i}"} for i, p in enumerate(packages, 1)],
                    "total": len(packages),
                },
            )
        if cmd == "show-package":
            package_uid = body["uid"]
            return httpx.Response(
                200,
                json={
                    "uid": package_uid,
                    "name": next(
                        name for index, name in enumerate(packages, 1) if package_uid == f"pkg-{index}"
                    ),
                    "access-layers": [{"uid": "lay-1"}],
                },
            )
        if cmd == "show-nat-rulebase":
            assert body["package"] in packages
            if nat_response is not None:
                return nat_response
            return httpx.Response(200, json={"rulebase": [], "total": 0, "objects-dictionary": []})
        raise AssertionError(f"unexpected cmd {cmd}")

    return httpx.MockTransport(handler), calls


def test_config_scope_and_domain():
    c = CpCollector(_cfg(), Settings(_env_file=None))
    assert c.scope == "cp:cp-mgmt.example"
    c2 = CpCollector(_cfg(domain="dom-a"), Settings(_env_file=None))
    assert c2.scope == "cp:cp-mgmt.example:dom-a"


def test_login_prefers_api_key_and_sets_sid(monkeypatch):
    transport, calls = make_mock()
    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: transport)
    out = CpCollector(_cfg(), Settings(_env_file=None)).probe()
    assert "1.9" in out
    assert calls["login"] == [{"api-key": "key1", "read-only": True}]


def test_login_falls_back_to_user_password_with_domain(monkeypatch):
    transport, calls = make_mock()
    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: transport)
    CpCollector(
        _cfg(auth={"method": "user_password", "username": "ro", "password": "pw"}, domain="dom-a"),
        Settings(_env_file=None),
    ).probe()
    assert calls["login"] == [{"user": "ro", "password": "pw", "domain": "dom-a", "read-only": True}]


def test_fetch_paginates_rulebases(monkeypatch):
    transport, calls = make_mock(rulebase_pages=3, rules_per_page=2)
    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: transport)
    raw = CpCollector(_cfg(), Settings(_env_file=None)).fetch()
    assert [g["name"] for g in raw["gateways"]] == ["fw1"]
    assert [layer["uid"] for layer in raw["layers"]] == ["lay-1"]
    pages = raw["rulebases"]["lay-1"]
    assert len(pages) == 3  # three pages fetched
    got = [r["uid"] for p in pages for r in p["rulebase"]]
    assert got == [f"r-{i}" for i in range(6)]
    offsets = [b.get("offset", 0) for c, b in calls["cmds"] if c == "show-access-rulebase"]
    assert offsets == [0, 2, 4]
    assert raw["replayed_layers"] == []


def test_login_failure_raises_a_login_error(monkeypatch):
    def handler(request):
        return httpx.Response(403, json={"message": "auth failure"})

    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: httpx.MockTransport(handler))
    with pytest.raises(RuntimeError, match="login"):
        CpCollector(_cfg(), Settings(_env_file=None)).probe()


def test_nat_error_degrades_to_empty(monkeypatch, caplog):
    """A management whose show-nat-rulebase 4xxs for a discovered package
    (here the mock's one "Standard" package) degrades that package to an
    empty NAT list."""
    nat_404 = httpx.Response(404, json={"message": "no such package"})
    transport, _calls = make_mock(nat_response=nat_404)
    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: transport)
    raw = CpCollector(_cfg(), Settings(_env_file=None)).fetch()
    assert raw["nat"] == {"Standard": []}
    assert [g["name"] for g in raw["gateways"]] == ["fw1"]
    assert [layer["uid"] for layer in raw["layers"]] == ["lay-1"]
    assert raw["rulebases"]["lay-1"]
    assert "show-nat-rulebase failed" in caplog.text
    assert "continuing with an empty NAT list" in caplog.text


def test_replay_skips_unchanged_layers(monkeypatch, tmp_path):
    transport, calls = make_mock(rulebase_pages=2, rules_per_page=2)
    from hst.core import Settings as S

    settings = S(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())

    def layers_with_rev(request_handler):  # wrap: add revision to the layer
        def h(request):
            resp = request_handler(request)
            if request.url.path.endswith("show-access-layers"):
                data = resp.json()
                data["access-layers"][0]["last-modify-time"] = {"posix": 111}
                data["access-layers"][0]["last-modifier"] = "admin"
                return httpx.Response(200, json=data)
            return resp

        return h

    monkeypatch.setattr(
        "hst.collectors.checkpoint._transport",
        lambda config: httpx.MockTransport(layers_with_rev(transport.handler)),
    )
    c = CpCollector(_cfg(), settings)
    first = c.fetch()
    assert first["replayed_layers"] == []
    n_rb_calls = sum(1 for cmd, _ in calls["cmds"] if cmd == "show-access-rulebase")
    assert n_rb_calls == 2

    second = c.fetch()
    assert second["replayed_layers"] == ["lay-1"]
    n_rb_calls_after = sum(1 for cmd, _ in calls["cmds"] if cmd == "show-access-rulebase")
    assert n_rb_calls_after == n_rb_calls  # no new rulebase fetches
    assert second["rulebases"] == first["rulebases"]


def test_changed_revision_refetches(monkeypatch, tmp_path):
    from hst.core import Settings as S

    settings = S(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())
    rev = {"posix": 111}
    transport, calls = make_mock(rulebase_pages=1, rules_per_page=2)

    def h(request):
        resp = transport.handler(request)
        if request.url.path.endswith("show-access-layers"):
            data = resp.json()
            data["access-layers"][0]["last-modify-time"] = dict(rev)
            data["access-layers"][0]["last-modifier"] = "admin"
            return httpx.Response(200, json=data)
        return resp

    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: httpx.MockTransport(h))
    c = CpCollector(_cfg(), settings)
    c.fetch()
    rev["posix"] = 222  # rulebase changed upstream
    out = c.fetch()
    assert out["replayed_layers"] == []
    n_rb = sum(1 for cmd, _ in calls["cmds"] if cmd == "show-access-rulebase")
    assert n_rb == 2  # one per fetch, refetched


def test_no_revision_marker_always_fetches(monkeypatch, tmp_path):
    from hst.core import Settings as S

    settings = S(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())
    transport, calls = make_mock()
    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: transport)
    c = CpCollector(_cfg(), settings)
    c.fetch()
    out = c.fetch()
    assert out["replayed_layers"] == []
    n_rb = sum(1 for cmd, _ in calls["cmds"] if cmd == "show-access-rulebase")
    assert n_rb == 2  # one per fetch, never replayed


def _revisioned(transport, rev):
    """Wrap a make_mock handler so the one layer carries a revision marker."""

    def h(request):
        resp = transport.handler(request)
        if request.url.path.endswith("show-access-layers"):
            data = resp.json()
            data["access-layers"][0]["last-modify-time"] = dict(rev)
            data["access-layers"][0]["last-modifier"] = "admin"
            return httpx.Response(200, json=data)
        return resp

    return h


def test_corrupted_cache_degrades_to_live_fetch(monkeypatch, tmp_path, caplog):
    """A corrupt replay cache falls back to a live fetch."""
    from hst.core import Settings as S
    from hst.core import rawstore

    settings = S(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())
    transport, calls = make_mock(rulebase_pages=1, rules_per_page=2)
    monkeypatch.setattr(
        "hst.collectors.checkpoint._transport",
        lambda config: httpx.MockTransport(_revisioned(transport, {"posix": 111})),
    )
    c = CpCollector(_cfg(), settings)
    c.fetch()  # populate the cache

    cache_dir = settings.raw_dir / "checkpoint" / "replay-cache"
    cache_files = list(cache_dir.glob(f"*{rawstore.SUFFIX}"))
    assert len(cache_files) == 1
    cache_files[0].write_bytes(b"{ not a gzip stream")

    out = c.fetch()

    assert out["replayed_layers"] == []
    n_rb = sum(1 for cmd, _ in calls["cmds"] if cmd == "show-access-rulebase")
    assert n_rb == 2  # second fetch refetched live
    assert "replay cache unreadable" in caplog.text
    assert "lay-1" in caplog.text
    from hst.app.crypto import dek

    assert rawstore.read(cache_files[0], key=dek(settings))["pages"]  # rewritten readable


def test_stale_cache_entries_are_deleted_from_disk(tmp_path, caplog):
    """Deletion observed directly on _cached_pages, where no refetch rewrites the
    file."""
    from hst.core import Settings as S
    from hst.core import rawstore

    settings = S(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())
    c = CpCollector(_cfg(), settings)
    cache_dir = settings.raw_dir / "checkpoint" / "replay-cache"
    cache_dir.mkdir(parents=True)

    corrupt = cache_dir / f"stem-a{rawstore.SUFFIX}"
    corrupt.write_bytes(b"{ not a gzip stream")
    assert c._cached_pages("stem-a", "111|admin") is None
    assert not corrupt.exists()
    assert "replay cache unreadable" in caplog.text

    from hst.app.crypto import dek

    mismatched = rawstore.write(
        settings.raw_dir / "checkpoint",
        "replay-cache",
        "stem-b",
        {"revision": "222|other", "pages": [{"rulebase": []}]},
        key=dek(settings),
    )
    assert c._cached_pages("stem-b", "111|admin") is None
    assert not mismatched.exists()


def test_replay_cache_is_sealed_when_a_secret_key_is_configured(monkeypatch, tmp_path):
    """The cache is sealed with the keyring of the raw store."""
    from hst.app.crypto import dek, generate_key
    from hst.core import Settings as S
    from hst.core import rawstore

    settings = S(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())
    transport, calls = make_mock(rulebase_pages=1, rules_per_page=2)
    monkeypatch.setattr(
        "hst.collectors.checkpoint._transport",
        lambda config: httpx.MockTransport(_revisioned(transport, {"posix": 111})),
    )
    c = CpCollector(_cfg(), settings)
    c.fetch()

    cache_dir = settings.raw_dir / "checkpoint" / "replay-cache"
    cache_files = list(cache_dir.glob(f"*{rawstore.SUFFIX}"))
    assert len(cache_files) == 1
    blob = cache_files[0].read_bytes()
    # sealed, not plaintext: the file is one Fernet token, url-safe base64 of
    # the version byte 0x80 and the ciphertext. A plaintext page holds JSON
    # punctuation, which that alphabet cannot produce, so the quoted rule uid
    # can never appear in it by chance.
    assert re.fullmatch(rb"[A-Za-z0-9_-]+=*", blob)
    assert base64.urlsafe_b64decode(blob)[:1] == b"\x80"
    assert b"rulebase" not in blob and b'"r-0"' not in blob
    stored = rawstore.read(cache_files[0], key=dek(settings))
    # keyed on the published session as well as the layer's own revision
    assert stored["revision"] == "pub-1|111|admin"

    out = c.fetch()
    assert out["replayed_layers"] == ["lay-1"]
    n_rb = sum(1 for cmd, _ in calls["cmds"] if cmd == "show-access-rulebase")
    assert n_rb == 1  # the sealed cache replayed; no second rulebase fetch


def test_a_plaintext_cache_entry_is_deleted_and_refetched(monkeypatch, tmp_path):
    from hst.core import Settings as S

    settings = S(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())
    transport, calls = make_mock(rulebase_pages=1, rules_per_page=2)
    monkeypatch.setattr(
        "hst.collectors.checkpoint._transport",
        lambda config: httpx.MockTransport(_revisioned(transport, {"posix": 111})),
    )
    cache_dir = settings.raw_dir / "checkpoint" / "replay-cache"
    cache_dir.mkdir(parents=True)
    legacy = cache_dir / "cp-cp-mgmt.example-lay-1.json"
    legacy.write_text(json.dumps({"revision": "111|admin", "pages": [{"rulebase": []}]}))

    out = CpCollector(_cfg(), settings).fetch()

    assert out["replayed_layers"] == []
    n_rb = sum(1 for cmd, _ in calls["cmds"] if cmd == "show-access-rulebase")
    assert n_rb == 1  # fetched live despite the matching plaintext entry
    assert not legacy.exists()  # the stale plaintext entry is gone from disk


def _norm_cp():
    from hst.collectors.checkpoint import normalize_checkpoint

    raw = {
        "gateways": [{"uid": "gw-1", "name": "fw1", "type": "simple-gateway", "ipv4-address": "10.9.0.1"}],
        "layers": [{"uid": "lay-1", "name": "Network"}],
        "rulebases": {"lay-1": [CP_RULEBASE_PAGE]},
        "nat": {},
        "replayed_layers": [],
    }
    return normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")


def test_cp_normalize_rules_and_objects():
    from hst.core import uid as uidmod

    batch = _norm_cp()
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    # The registry keys the gateway by its ref and mints the uid from its name,
    # never the CP-native api uid directly (kept as cp_uid).
    fw = nodes["dev:fw1"]
    assert fw.label == "Device" and fw.props["platform"] == "checkpoint"
    assert fw.props["cp_uid"] == cp("gw-1")
    rb = nodes[cp("lay-1")]
    assert rb.label == "FwRulebase" and rb.props["name"] == "Network"
    r1 = nodes[cp("r-1")]
    # Path tracing reads `position` on a FwRule and `ports` on a SvcObject.
    assert (r1.props["position"], r1.props["action"]) == (1, "accept")
    assert ("HAS_RULE", rb.uid, r1.uid) in rels
    assert ("SRC", r1.uid, cp("g-web")) in rels
    assert ("DST", r1.uid, cp("n-be")) in rels
    assert ("SVC", r1.uid, cp("svc-https")) in rels
    assert nodes[cp("n-be")].props["cidr"] == "10.1.2.0/24"
    assert nodes[cp("h-fe")].props["ip"] == "10.1.1.10"
    assert nodes[cp("svc-https")].props["ports"] == "443"
    assert ("MEMBER_OF", cp("h-fe"), cp("g-web")) in rels


def test_cp_host_and_network_objects_get_resolves_to():
    """A host's ip and a network's cidr each carry their address as a
    RESOLVES_TO edge to an IpAddress/Prefix node keyed on the collector's own
    source scope string, beside the display-only ip/cidr prop."""
    from hst.core import uid as uidmod

    batch = _norm_cp()
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    scope = "cp:cp-mgmt.example"
    ip_uid = uidmod.ip(scope, "10.1.1.10")
    assert ("RESOLVES_TO", cp("h-fe"), ip_uid) in rels
    assert nodes[ip_uid].label == "IpAddress"
    assert (nodes[ip_uid].props["ip"], nodes[ip_uid].props["af"]) == ("10.1.1.10", 4)
    pfx_uid = uidmod.prefix(scope, "10.1.2.0/24")
    assert ("RESOLVES_TO", cp("n-be"), pfx_uid) in rels
    assert nodes[pfx_uid].label == "Prefix"
    assert (nodes[pfx_uid].props["cidr"], nodes[pfx_uid].props["af"]) == ("10.1.2.0/24", 4)
    assert nodes[cp("h-fe")].props["ip"] == "10.1.1.10"
    assert nodes[cp("n-be")].props["cidr"] == "10.1.2.0/24"
    assert "opaque" not in nodes[cp("h-fe")].props and "opaque" not in nodes[cp("n-be")].props


def test_cp_v6_objects_get_resolves_to():
    """The v6 counterpart: ip6/cidr6 also carry a RESOLVES_TO edge, to an af=6
    IpAddress/Prefix node, and a dual-stack host gets one edge per family."""
    from hst.collectors.checkpoint import normalize_checkpoint
    from hst.core import uid as uidmod

    page = {
        "rulebase": [],
        "objects-dictionary": [
            {"uid": "h6", "name": "web6", "type": "host", "ipv6-address": "2001:db8::10"},
            {"uid": "n6", "name": "net6", "type": "network", "subnet6": "2001:db8:1::", "mask-length6": 64},
            {
                "uid": "dual",
                "name": "dual",
                "type": "host",
                "ipv4-address": "10.1.1.20",
                "ipv6-address": "2001:db8::20",
            },
        ],
        "total": 0,
        "to": 0,
    }
    raw = {
        "gateways": [],
        "layers": [{"uid": "lay-6", "name": "V6"}],
        "rulebases": {"lay-6": [page]},
        "nat": {},
        "replayed_layers": [],
    }
    batch = normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    scope = "cp:cp-mgmt.example"
    ip6_uid = uidmod.ip(scope, "2001:db8::10")
    assert ("RESOLVES_TO", cp("h6"), ip6_uid) in rels
    assert nodes[ip6_uid].props["af"] == 6
    pfx6_uid = uidmod.prefix(scope, "2001:db8:1::/64")
    assert ("RESOLVES_TO", cp("n6"), pfx6_uid) in rels
    assert nodes[pfx6_uid].props["af"] == 6
    dual_ip4 = uidmod.ip(scope, "10.1.1.20")
    dual_ip6 = uidmod.ip(scope, "2001:db8::20")
    assert ("RESOLVES_TO", cp("dual"), dual_ip4) in rels
    assert ("RESOLVES_TO", cp("dual"), dual_ip6) in rels


@pytest.mark.parametrize(
    "cp_type",
    [
        "access-role",
        "security-zone",
        "dns-domain",
        "updatable-object",
        "dynamic-object",
        "wildcard",
        "group-with-exclusion",
    ],
)
def test_cp_address_less_object_kinds_are_opaque(cp_type):
    """An object kind the engine cannot express as an address set is
    marked opaque with a reason naming the kind."""
    from hst.collectors.checkpoint import normalize_checkpoint
    from hst.core import uid as uidmod

    page = {
        "rulebase": [],
        "objects-dictionary": [{"uid": "obj-x", "name": "x", "type": cp_type}],
        "total": 0,
        "to": 0,
    }
    raw = {
        "gateways": [],
        "layers": [{"uid": "lay-o", "name": "Opaque"}],
        "rulebases": {"lay-o": [page]},
        "nat": {},
        "replayed_layers": [],
    }
    batch = normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")
    nodes = {n.uid: n for n in batch.nodes}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    node = nodes[cp("obj-x")]
    assert node.props["opaque"] is True
    assert node.props["opaque_reason"]
    assert "ip" not in node.props and "cidr" not in node.props and "ranges" not in node.props


def test_cp_unrecognized_object_type_gets_a_generic_opaque_reason():
    """An object type outside every known allow-list (host/network/address-range/
    group/service-*/the named address-less kinds) is opaque."""
    from hst.collectors.checkpoint import normalize_checkpoint
    from hst.core import uid as uidmod

    page = {
        "rulebase": [],
        "objects-dictionary": [{"uid": "obj-mystery", "name": "mystery", "type": "cpmi-mystery-object"}],
        "total": 0,
        "to": 0,
    }
    raw = {
        "gateways": [],
        "layers": [{"uid": "lay-o", "name": "Opaque"}],
        "rulebases": {"lay-o": [page]},
        "nat": {},
        "replayed_layers": [],
    }
    batch = normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")
    nodes = {n.uid: n for n in batch.nodes}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    node = nodes[cp("obj-mystery")]
    assert node.props["opaque"] is True
    assert "cpmi-mystery-object" in node.props["opaque_reason"]


def test_cp_a_modelled_kind_with_no_address_names_the_missing_address():
    from hst.collectors.checkpoint import normalize_checkpoint
    from hst.core import uid as uidmod

    page = {
        "rulebase": [],
        "objects-dictionary": [
            {"uid": "h-bare", "name": "bare-host", "type": "host"},
            {"uid": "n-bare", "name": "bare-net", "type": "network"},
        ],
        "total": 0,
        "to": 0,
    }
    raw = {
        "gateways": [],
        "layers": [{"uid": "lay-b", "name": "Bare"}],
        "rulebases": {"lay-b": [page]},
        "nat": {},
        "replayed_layers": [],
    }
    batch = normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")
    nodes = {n.uid: n for n in batch.nodes}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    for ouid, kind in (("h-bare", "host"), ("n-bare", "network")):
        props = nodes[cp(ouid)].props
        assert props["opaque"] is True
        assert props["opaque_reason"] == f"checkpoint {kind} object carries no address in the payload"


def test_cp_address_range_object_gets_ranges():
    from hst.collectors.checkpoint import normalize_checkpoint
    from hst.core import uid as uidmod

    page = {
        "rulebase": [],
        "objects-dictionary": [
            {
                "uid": "rng-1",
                "name": "dhcp-pool",
                "type": "address-range",
                "ipv4-address-first": "10.5.0.10",
                "ipv4-address-last": "10.5.0.20",
            }
        ],
        "total": 0,
        "to": 0,
    }
    raw = {
        "gateways": [],
        "layers": [{"uid": "lay-r", "name": "Ranges"}],
        "rulebases": {"lay-r": [page]},
        "nat": {},
        "replayed_layers": [],
    }
    batch = normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")
    nodes = {n.uid: n for n in batch.nodes}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    node = nodes[cp("rng-1")]
    assert node.props["ranges"] == ["10.5.0.10-10.5.0.20"]
    assert "opaque" not in node.props


def test_cp_group_carries_the_resolves_to_closure_of_its_member():
    """g-web (group, member h-fe) gets a RESOLVES_TO edge to the SAME
    IpAddress target h-fe resolves to, beside its MEMBER_OF edge."""
    from hst.core import uid as uidmod

    batch = _norm_cp()
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    ip_uid = uidmod.ip("cp:cp-mgmt.example", "10.1.1.10")
    assert ("RESOLVES_TO", cp("g-web"), ip_uid) in rels
    assert ("MEMBER_OF", cp("h-fe"), cp("g-web")) in rels
    nodes = {n.uid: n for n in batch.nodes}
    assert "opaque" not in nodes[cp("g-web")].props


def test_cp_nested_group_closes_over_two_member_of_hops():
    from hst.collectors.checkpoint import normalize_checkpoint
    from hst.core import uid as uidmod

    objects = [
        *CP_OBJECTS,
        {"uid": "g-outer", "name": "outer-grp", "type": "group", "members": ["g-web"]},
    ]
    page = {"rulebase": [], "objects-dictionary": objects, "total": 0, "to": 0}
    raw = {
        "gateways": [],
        "layers": [{"uid": "lay-g", "name": "Groups"}],
        "rulebases": {"lay-g": [page]},
        "nat": {},
        "replayed_layers": [],
    }
    batch = normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    ip_uid = uidmod.ip("cp:cp-mgmt.example", "10.1.1.10")
    assert ("RESOLVES_TO", cp("g-outer"), ip_uid) in rels
    assert "opaque" not in nodes[cp("g-outer")].props


def test_cp_group_with_a_dangling_member_is_opaque_but_keeps_its_partial_closure():
    """A member uid the object dictionary never carried marks the group opaque."""
    from hst.collectors.checkpoint import normalize_checkpoint
    from hst.core import uid as uidmod

    objects = [
        *CP_OBJECTS,
        {"uid": "g-partial", "name": "partial-grp", "type": "group", "members": ["h-fe", "obj-missing"]},
    ]
    page = {"rulebase": [], "objects-dictionary": objects, "total": 0, "to": 0}
    raw = {
        "gateways": [],
        "layers": [{"uid": "lay-g", "name": "Groups"}],
        "rulebases": {"lay-g": [page]},
        "nat": {},
        "replayed_layers": [],
    }
    batch = normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    node = nodes[cp("g-partial")]
    assert node.props["opaque"] is True
    assert node.props["opaque_reason"]
    ip_uid = uidmod.ip("cp:cp-mgmt.example", "10.1.1.10")
    assert ("RESOLVES_TO", cp("g-partial"), ip_uid) in rels  # the resolvable member still narrows


def test_cp_group_membership_cycle_terminates():
    """A membership cycle (A member-of B, B member-of A) must not hang or
    stack-overflow normalize(); the depth/seen-set guard closes it."""
    from hst.collectors.checkpoint import normalize_checkpoint
    from hst.core import uid as uidmod

    objects = [
        *CP_OBJECTS,
        {"uid": "g-a", "name": "grp-a", "type": "group", "members": ["h-fe", "g-b"]},
        {"uid": "g-b", "name": "grp-b", "type": "group", "members": ["g-a"]},
    ]
    page = {"rulebase": [], "objects-dictionary": objects, "total": 0, "to": 0}
    raw = {
        "gateways": [],
        "layers": [{"uid": "lay-g", "name": "Groups"}],
        "rulebases": {"lay-g": [page]},
        "nat": {},
        "replayed_layers": [],
    }
    batch = normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")  # must terminate
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    ip_uid = uidmod.ip("cp:cp-mgmt.example", "10.1.1.10")
    # the cycle reaches the one real leaf address either way; not itself opaque
    assert ("RESOLVES_TO", cp("g-a"), ip_uid) in rels
    assert ("RESOLVES_TO", cp("g-b"), ip_uid) in rels
    assert "opaque" not in nodes[cp("g-a")].props
    assert "opaque" not in nodes[cp("g-b")].props


def _norm_cp_service_groups():
    """One leaf service-tcp (known), a leaf with a relational port, a leaf of
    an unmapped kind, an inner service-group nesting the first two, and an
    outer service-group nesting the inner group plus the unmapped leaf."""
    from hst.collectors.checkpoint import normalize_checkpoint

    objects = [
        *CP_OBJECTS,
        {"uid": "svc-hi", "name": "high-ports", "type": "service-tcp", "port": ">1023"},
        {"uid": "svc-x", "name": "other", "type": "service-other"},
        {
            "uid": "grp-inner",
            "name": "inner-grp",
            "type": "service-group",
            "members": ["svc-https", "svc-hi"],
        },
        {"uid": "grp-outer", "name": "outer-grp", "type": "service-group", "members": ["grp-inner", "svc-x"]},
    ]
    page = {"rulebase": [], "objects-dictionary": objects, "total": 0, "to": 0}
    raw = {
        "gateways": [],
        "layers": [{"uid": "lay-s", "name": "Services"}],
        "rulebases": {"lay-s": [page]},
        "nat": {},
        "replayed_layers": [],
    }
    return normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")


def test_cp_service_group_and_service_other_are_opaque():
    from hst.core import uid as uidmod

    batch = _norm_cp_service_groups()
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    # the two service-group nodes carry no proto/ports of their own
    for guid in ("grp-inner", "grp-outer"):
        node = nodes[cp(guid)]
        assert "proto" not in node.props and "ports" not in node.props
        assert "opaque" not in node.props  # the group itself, not its members
    hi = nodes[cp("svc-hi")].props
    assert hi["proto"] == "tcp"
    assert hi["opaque"] is True and ">1023" in hi["opaque_reason"]
    x = nodes[cp("svc-x")].props
    assert x["opaque"] is True
    assert "service-other" in x["opaque_reason"]
    assert "proto" not in x
    https = nodes[cp("svc-https")].props
    assert https["proto"] == "tcp" and https["ports"] == "443"
    assert "opaque" not in https
    assert ("MEMBER_OF", cp("svc-https"), cp("grp-inner")) in rels
    assert ("MEMBER_OF", cp("svc-hi"), cp("grp-inner")) in rels
    assert ("MEMBER_OF", cp("grp-inner"), cp("grp-outer")) in rels
    assert ("MEMBER_OF", cp("svc-x"), cp("grp-outer")) in rels


def test_cp_negate_flags_are_collected():
    """source-negate/destination-negate/service-negate land on the
    FwRule as booleans."""
    from hst.collectors.checkpoint import normalize_checkpoint
    from hst.core import uid as uidmod

    page = {
        "rulebase": [
            {
                "uid": "r-negate",
                "type": "access-rule",
                "rule-number": 1,
                "name": "negated",
                "enabled": True,
                "action": "act-accept",
                "source": ["g-web"],
                "destination": ["n-be"],
                "service": ["svc-https"],
                "source-negate": True,
                "destination-negate": False,
                # service-negate absent: defaults to False
            },
        ],
        "objects-dictionary": CP_OBJECTS,
        "total": 1,
        "to": 1,
    }
    raw = {
        "gateways": [],
        "layers": [{"uid": "lay-n", "name": "Negate"}],
        "rulebases": {"lay-n": [page]},
        "nat": {},
        "replayed_layers": [],
    }
    batch = normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")
    nodes = {n.uid: n for n in batch.nodes}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    r = nodes[cp("r-negate")].props
    assert (r["src_negate"], r["dst_negate"], r["svc_negate"]) == (True, False, False)


def test_the_management_places_no_gateway_itself():
    """A management server reports no place for its gateways."""
    from hst.collectors.checkpoint import normalize_checkpoint

    raw = {
        "gateways": [
            {"uid": "gw-1", "name": "fw1", "type": "simple-gateway", "ipv4-address": "10.9.0.1"},
            {"uid": "gw-2", "name": "fw2", "type": "simple-gateway", "ipv4-address": "10.9.0.2"},
        ],
        "layers": [],
        "rulebases": {},
        "nat": {},
        "replayed_layers": [],
    }
    batch = normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")
    assert {n.uid for n in batch.nodes if n.label == "Device"}
    assert not [n for n in batch.nodes if n.label == "Site"]
    assert not [r for r in batch.rels if r.rel_type == "LOCATED_IN"]
    assert not [n for n in batch.nodes if n.label == "Device" and n.props.get("reported_location")]


def test_cp_v6_object_addresses_survive_normalize():
    """ipv6-address and subnet6/mask-length6 land as ip6/cidr6; a dual-stack host
    keeps both families, and a v6-only object never claims the v4 keys."""
    from hst.collectors.checkpoint import normalize_checkpoint
    from hst.core import uid as uidmod

    page = {
        "rulebase": [],
        "objects-dictionary": [
            {"uid": "h6", "name": "web6", "type": "host", "ipv6-address": "2001:db8::10"},
            {"uid": "n6", "name": "net6", "type": "network", "subnet6": "2001:db8:1::", "mask-length6": 64},
            {
                "uid": "dual",
                "name": "dual",
                "type": "host",
                "ipv4-address": "10.1.1.20",
                "ipv6-address": "2001:db8::20",
            },
        ],
        "total": 0,
        "to": 0,
    }
    raw = {
        "gateways": [],
        "layers": [{"uid": "lay-6", "name": "V6"}],
        "rulebases": {"lay-6": [page]},
        "nat": {},
        "replayed_layers": [],
    }
    batch = normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")
    nodes = {n.uid: n for n in batch.nodes}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    assert nodes[cp("h6")].props["ip6"] == "2001:db8::10"
    assert "ip" not in nodes[cp("h6")].props
    assert nodes[cp("n6")].props["cidr6"] == "2001:db8:1::/64"
    dual = nodes[cp("dual")].props
    assert (dual["ip"], dual["ip6"]) == ("10.1.1.20", "2001:db8::20")


def test_cp_any_objects_become_props_not_edges():
    from hst.core import uid as uidmod

    batch = _norm_cp()
    nodes = {n.uid: n for n in batch.nodes}
    rels = [r for r in batch.rels if r.start_uid == uidmod.checkpoint("cp-mgmt.example", "", "r-2")]
    assert not [r for r in rels if r.rel_type in ("SRC", "DST", "SVC")]
    r2 = nodes[uidmod.checkpoint("cp-mgmt.example", "", "r-2")]
    assert (r2.props["src_any"], r2.props["dst_any"], r2.props["svc_any"]) == (True, True, True)
    assert r2.props["action"] == "drop"


def test_cp_batch_coherence():
    batch = _norm_cp()
    node_uids = {n.uid for n in batch.nodes}
    dangling = [
        (r.rel_type, r.start_uid, r.end_uid)
        for r in batch.rels
        if r.start_uid not in node_uids or r.end_uid not in node_uids
    ]
    assert not dangling, dangling
    assert batch.source == "checkpoint" and batch.scope == "cp:cp-mgmt.example"
    assert not [n for n in batch.nodes if n.label == "FwRulebase" and n.props.get("kind") == "nat"]


def test_cp_domain_scoped_uids():
    # The Device node's uid is minted from the gateway name.
    from hst.collectors.checkpoint import normalize_checkpoint
    from hst.core import uid as uidmod

    raw = {
        "gateways": [{"uid": "gw-1", "name": "fw1", "type": "simple-gateway"}],
        "layers": [],
        "rulebases": {},
        "nat": {},
        "replayed_layers": [],
    }
    batch = normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="dom-a")
    assert batch.scope == "cp:cp-mgmt.example:dom-a"
    nodes = {n.uid: n for n in batch.nodes}
    fw = nodes["dev:fw1"]
    assert fw.props["cp_uid"] == uidmod.checkpoint("cp-mgmt.example", "dom-a", "gw-1")


# Edge-case rules for the src_any/dst_any/svc_any and action-resolution semantics.
# A second layer/page keeps these independent of CP_RULEBASE_PAGE's pinned assertions.
CP_EDGE_CASE_PAGE = {
    "rulebase": [
        {
            "uid": "r-3",
            "type": "access-rule",
            "rule-number": 1,
            "name": "no-source",
            "enabled": True,
            "action": "act-accept",
            "source": [],
            "destination": ["n-be"],
            "service": ["svc-https"],
        },
        {
            "uid": "r-4",
            "type": "access-rule",
            "rule-number": 2,
            "name": "mixed-source",
            "enabled": True,
            "action": "act-accept",
            "source": ["g-web", "obj-any"],
            "destination": ["n-be"],
            "service": ["svc-https"],
        },
        {
            "uid": "r-5",
            "type": "access-rule",
            "rule-number": 3,
            "name": "mystery-action",
            "enabled": True,
            "action": "act-mystery",
            "source": ["g-web"],
            "destination": ["n-be"],
            "service": ["svc-https"],
        },
    ],
    "objects-dictionary": CP_OBJECTS,
    "total": 3,
    "to": 3,
}


def _norm_cp_edge_cases():
    from hst.collectors.checkpoint import normalize_checkpoint

    raw = {
        "gateways": [],
        "layers": [{"uid": "lay-2", "name": "EdgeCases"}],
        "rulebases": {"lay-2": [CP_EDGE_CASE_PAGE]},
        "nat": {},
        "replayed_layers": [],
    }
    return normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")


def test_cp_empty_source_list_is_not_any():
    """An empty `source` list is "none listed"."""
    from hst.core import uid as uidmod

    batch = _norm_cp_edge_cases()
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    r3 = nodes[cp("r-3")]
    assert r3.props["src_any"] is False
    assert not [r for r in rels if r[0] == "SRC" and r[1] == r3.uid]


def test_cp_mixed_any_and_real_object_source():
    """A field with a concrete object beside an Any entry is not a wildcard."""
    from hst.core import uid as uidmod

    batch = _norm_cp_edge_cases()
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    r4 = nodes[cp("r-4")]
    assert r4.props["src_any"] is False
    assert ("SRC", r4.uid, cp("g-web")) in rels


def test_cp_unresolved_action_uid_falls_back_to_raw_lowercased():
    """An action uid absent from the RulebaseAction dictionary falls back
    to the lowercased raw uid string."""
    from hst.core import uid as uidmod

    batch = _norm_cp_edge_cases()
    nodes = {n.uid: n for n in batch.nodes}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    r5 = nodes[cp("r-5")]
    assert r5.props["action"] == "act-mystery"


def test_cp_nat_rules():
    from hst.collectors.checkpoint import normalize_checkpoint
    from hst.core import uid as uidmod

    nat_page = {
        # A nat-section container has the shape of an access-section.
        "rulebase": [
            {
                "uid": "nsec-1",
                "type": "nat-section",
                "name": "NAT Section",
                "rulebase": [
                    {
                        "uid": "nr-1",
                        "type": "nat-rule",
                        "rule-number": 1,
                        "name": "hide-be",
                        "comments": "hide backend behind fe",
                        "enabled": True,
                        "auto-generated": False,
                        "method": "hide",
                        "original-source": "n-be",
                        "original-destination": "obj-any",
                        "translated-source": "h-fe",
                        "translated-destination": "obj-any",
                    },
                ],
            },
        ],
        "objects-dictionary": CP_OBJECTS,
        "total": 1,
        "to": 1,
    }
    raw = {
        "gateways": [{"uid": "gw-1", "name": "fw1", "type": "simple-gateway"}],
        "layers": [],
        "rulebases": {},
        "nat": {"Standard": [nat_page]},
        "replayed_layers": [],
    }
    batch = normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    nr = nodes[cp("nr-1")]
    assert nr.label == "NatRule" and nr.props["method"] == "hide"
    assert nr.props["name"] == "hide-be"  # name preferred over comments
    assert nr.props["auto_generated"] is False
    # the NAT rulebase is package-keyed and enforced by the gateway, like access layers
    rb = nodes[cp("nat:Standard")]
    assert rb.label == "FwRulebase" and rb.props["kind"] == "nat"
    assert rb.props["vendor"] == "checkpoint"
    assert ("HAS_RULE", cp("nat:Standard"), nr.uid) in rels
    assert ("ENFORCES", "dev:fw1", cp("nat:Standard")) in rels
    assert ("ORIG_SRC", nr.uid, cp("n-be")) in rels
    assert ("XLATE_SRC", nr.uid, cp("h-fe")) in rels
    assert not [r for r in batch.rels if r.rel_type in ("ORIG_DST", "XLATE_DST")]
    # hide rule translating source only: Any in the match destination is a
    # wildcard, Any in the translated destination means "Original, untranslated".
    assert nr.props["dst_any"] is True
    assert nr.props["xlate_dst_original"] is True
    assert "src_any" not in nr.props and "xlate_src_original" not in nr.props
    # all columns resolved: nothing approximate about this rule
    assert "approximate" not in nr.props
    node_uids = {n.uid for n in batch.nodes}
    assert not [r for r in batch.rels if r.start_uid not in node_uids or r.end_uid not in node_uids]


def _norm_cp_nat_detail():
    """One NAT package exercising the precise-NAT columns: service resolution
    (single port, range, Any), auto-generated, Any source, and an object uid
    missing from the dictionary."""
    from hst.collectors.checkpoint import normalize_checkpoint

    objects = [
        *CP_OBJECTS,
        {"uid": "svc-syslog", "name": "syslog-range", "type": "service-udp", "port": "8000-8080"},
        {"uid": "svc-icmp", "name": "ping", "type": "service-icmp"},
    ]
    rules = [
        {
            # static NAT with a port translation: both service columns resolve
            "uid": "nr-svc",
            "type": "nat-rule",
            "rule-number": 1,
            "enabled": True,
            "method": "static",
            "original-source": "h-fe",
            "original-destination": "obj-any",
            "translated-source": "h-fe",
            "translated-destination": "obj-any",
            "original-service": "svc-https",
            "translated-service": "svc-syslog",
        },
        {
            # Any services and Any source; portless service type in xlate
            "uid": "nr-anysvc",
            "type": "nat-rule",
            "rule-number": 2,
            "enabled": True,
            "method": "hide",
            "original-source": "obj-any",
            "original-destination": "n-be",
            "translated-source": "h-fe",
            "translated-destination": "obj-any",
            "original-service": "obj-any",
            "translated-service": "svc-icmp",
        },
        {
            # auto-generated (object-level Automatic NAT), comments but no name
            "uid": "nr-auto",
            "type": "nat-rule",
            "rule-number": 3,
            "enabled": True,
            "auto-generated": True,
            "comments": "Automatic rule for web-fe",
            "method": "static",
            "original-source": "h-fe",
            "original-destination": "obj-any",
            "translated-source": "h-fe",
            "translated-destination": "obj-any",
        },
        {
            # destination uid absent from the dictionary: unknown, not Any
            "uid": "nr-ghost",
            "type": "nat-rule",
            "rule-number": 4,
            "enabled": True,
            "method": "static",
            "original-source": "h-fe",
            "original-destination": "obj-ghost",
            "translated-source": "obj-any",
            "translated-destination": "obj-any",
        },
    ]
    raw = {
        "gateways": [],
        "layers": [],
        "rulebases": {},
        "nat": {"Standard": [{"rulebase": rules, "objects-dictionary": objects, "total": 4, "to": 4}]},
        "replayed_layers": [],
    }
    return normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")


def test_cp_nat_service_columns_resolve_to_ports():
    from hst.core import uid as uidmod

    batch = _norm_cp_nat_detail()
    nodes = {n.uid: n for n in batch.nodes}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    nr = nodes[cp("nr-svc")]
    assert nr.props["orig_service"] == "https"
    assert nr.props["orig_port"] == "443"
    assert nr.props["xlate_service"] == "syslog-range"
    assert nr.props["xlate_port"] == "8000-8080"  # ranges pass through as strings
    assert nr.props["protocol"] == "tcp"  # original service's protocol wins


def test_cp_nat_any_service_and_portless_service_leave_port_props_off():
    from hst.core import uid as uidmod

    batch = _norm_cp_nat_detail()
    nodes = {n.uid: n for n in batch.nodes}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    nr = nodes[cp("nr-anysvc")]
    # Any original service: no orig props at all
    assert "orig_service" not in nr.props and "orig_port" not in nr.props
    # portless service-icmp: name kept, no port/protocol claimed
    assert nr.props["xlate_service"] == "ping"
    assert "xlate_port" not in nr.props and "protocol" not in nr.props
    # Any source is a flag, and the resolved destination keeps its edge
    assert nr.props["src_any"] is True
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert not [r for r in rels if r[0] == "ORIG_SRC" and r[1] == nr.uid]
    assert ("ORIG_DST", nr.uid, cp("n-be")) in rels


def test_cp_nat_auto_generated_and_comments_fallback():
    from hst.core import uid as uidmod

    batch = _norm_cp_nat_detail()
    nodes = {n.uid: n for n in batch.nodes}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    nr = nodes[cp("nr-auto")]
    assert nr.props["auto_generated"] is True
    assert nr.props["name"] == "Automatic rule for web-fe"  # comments fallback


def test_cp_nat_unresolvable_object_marks_rule_approximate():
    """A uid absent from the object dictionary is unknown, not Any: no edge, no
    flag, and approximate=True, which path.py downgrades."""
    from hst.core import uid as uidmod

    batch = _norm_cp_nat_detail()
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    nr = nodes[cp("nr-ghost")]
    assert nr.props["approximate"] is True
    assert "dst_any" not in nr.props
    assert not [r for r in rels if r[0] == "ORIG_DST" and r[1] == nr.uid]
    # resolved rules in the same package stay precise
    assert "approximate" not in nodes[cp("nr-svc")].props


def _nat_page(rule_uid: str, position: int = 1) -> dict:
    return {
        "rulebase": [
            {
                "uid": rule_uid,
                "type": "nat-rule",
                "rule-number": position,
                "enabled": True,
                "method": "hide",
                "original-source": "n-be",
            },
        ],
        "objects-dictionary": CP_OBJECTS,
        "total": 1,
        "to": 1,
    }


def test_cp_nat_packages_get_separate_rulebases():
    """Two policy packages each start their NAT chain at rule 1."""
    from hst.collectors.checkpoint import normalize_checkpoint
    from hst.core import uid as uidmod

    raw = {
        "gateways": [
            {"uid": "gw-1", "name": "fw1", "type": "simple-gateway"},
            {"uid": "gw-2", "name": "fw2", "type": "simple-gateway"},
        ],
        "layers": [],
        "rulebases": {},
        "nat": {"Standard": [_nat_page("nr-std")], "Branch": [_nat_page("nr-br")]},
        "replayed_layers": [],
    }
    batch = normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert nodes[cp("nat:Standard")].props["name"] == "NAT:Standard"
    assert nodes[cp("nat:Branch")].props["name"] == "NAT:Branch"
    assert ("HAS_RULE", cp("nat:Standard"), cp("nr-std")) in rels
    assert ("HAS_RULE", cp("nat:Branch"), cp("nr-br")) in rels
    assert ("HAS_RULE", cp("nat:Standard"), cp("nr-br")) not in rels
    assert nodes[cp("nr-std")].props["position"] == 1
    assert nodes[cp("nr-br")].props["position"] == 1
    # The inferred gateway binding is approximate with more than one gateway.
    enforces = [r for r in batch.rels if r.rel_type == "ENFORCES" and r.end_uid == cp("nat:Standard")]
    assert {r.start_uid for r in enforces} == {"dev:fw1", "dev:fw2"}
    assert all(r.props["approximate"] is True for r in enforces)


def test_cp_nat_as_one_list_reads_as_the_standard_package():
    from hst.collectors.checkpoint import normalize_checkpoint
    from hst.core import uid as uidmod

    raw = {
        "gateways": [],
        "layers": [],
        "rulebases": {},
        "nat": [_nat_page("nr-legacy")],
        "replayed_layers": [],
    }
    batch = normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")
    cp = lambda u: uidmod.checkpoint("cp-mgmt.example", "", u)  # noqa: E731
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert ("HAS_RULE", cp("nat:Standard"), cp("nr-legacy")) in rels


def test_probe_and_fetch_both_release_the_session(monkeypatch):
    transport, calls = make_mock()
    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: transport)
    CpCollector(_cfg(), Settings(_env_file=None)).probe()
    assert calls.get("logout") == 1

    transport2, calls2 = make_mock()
    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: transport2)
    CpCollector(_cfg(), Settings(_env_file=None)).fetch()
    assert calls2.get("logout") == 1


def test_fetch_paginates_flat_show_commands(monkeypatch):
    """show-gateways-and-servers / show-access-layers / show-packages are offset-
    paginated."""
    calls = {"cmds": []}

    def paged(items, offset, key):
        page = items[offset : offset + 1]  # one item per page forces pagination
        return httpx.Response(
            200, json={key: page, "from": offset, "to": offset + len(page), "total": len(items)}
        )

    def handler(request: httpx.Request) -> httpx.Response:
        cmd = request.url.path.removeprefix("/web_api/")
        body = json.loads(request.content or b"{}")
        if cmd == "login":
            return httpx.Response(200, json={"sid": "SID1"})
        calls["cmds"].append((cmd, body))
        if cmd == "logout":
            return httpx.Response(200, json={"message": "OK"})
        offset = body.get("offset", 0)
        if cmd == "show-gateways-and-servers":
            gws = [{"uid": f"gw-{i}", "name": f"fw{i}", "type": "simple-gateway"} for i in range(3)]
            return paged(gws, offset, "objects")
        if cmd == "show-access-layers":
            lays = [{"uid": "lay-1", "name": "Network"}, {"uid": "lay-2", "name": "Edge"}]
            return paged(lays, offset, "access-layers")
        if cmd == "show-packages":
            pkgs = [{"name": "Standard", "uid": "pkg-1"}, {"name": "Branch", "uid": "pkg-2"}]
            return paged(pkgs, offset, "packages")
        if cmd == "show-package":
            return httpx.Response(
                200,
                json={"uid": body["uid"], "access-layers": [{"uid": "lay-1"}]},
            )
        if cmd in ("show-access-rulebase", "show-nat-rulebase"):
            return httpx.Response(200, json={"rulebase": [], "objects-dictionary": [], "total": 0, "to": 0})
        if cmd in _OPTIONAL_READS:
            return _OPTIONAL_READS[cmd]()
        raise AssertionError(f"unexpected cmd {cmd}")

    monkeypatch.setattr(
        "hst.collectors.checkpoint._transport",
        lambda config: httpx.MockTransport(handler),
    )
    raw = CpCollector(_cfg(), Settings(_env_file=None)).fetch()
    assert [g["uid"] for g in raw["gateways"]] == ["gw-0", "gw-1", "gw-2"]
    assert sorted(raw["rulebases"]) == ["lay-1", "lay-2"]
    nat_pkgs = {body["package"] for cmd, body in calls["cmds"] if cmd == "show-nat-rulebase"}
    assert nat_pkgs == {"Standard", "Branch"}


def test_missing_total_fails_loudly(monkeypatch):
    """A reply without `total` aborts the fetch."""
    transport, _ = make_mock()

    def h(request):
        resp = transport.handler(request)
        if request.url.path.endswith("show-access-layers"):
            data = resp.json()
            del data["total"]
            return httpx.Response(200, json=data)
        return resp

    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: httpx.MockTransport(h))
    with pytest.raises(RuntimeError, match="missing 'total'"):
        CpCollector(_cfg(), Settings(_env_file=None)).fetch()


# A session refresh mid-fetch re-logs-in and retries the failed page once.


def _serve_session(cmd: str, body: dict) -> httpx.Response:
    """Minimal happy-path replies for a full fetch: one gateway, one layer, a
    three-page rulebase, one package, empty NAT."""
    offset = body.get("offset", 0)
    if cmd == "logout":
        return httpx.Response(200, json={"message": "OK"})
    if cmd == "show-gateways-and-servers":
        return httpx.Response(
            200, json={"objects": [{"uid": "gw-1", "name": "fw1", "type": "simple-gateway"}], "total": 1}
        )
    if cmd == "show-access-layers":
        return httpx.Response(200, json={"access-layers": [{"uid": "lay-1", "name": "Network"}], "total": 1})
    if cmd == "show-access-rulebase":
        total = 6
        rules = [
            {"uid": f"r-{offset + i}", "rule-number": offset + i + 1, "type": "access-rule"}
            for i in range(2)
            if offset + i < total
        ]
        return httpx.Response(
            200,
            json={"rulebase": rules, "objects-dictionary": [], "total": total, "to": min(offset + 2, total)},
        )
    if cmd == "show-packages":
        return httpx.Response(200, json={"packages": [{"name": "Standard", "uid": "pkg-1"}], "total": 1})
    if cmd == "show-package":
        return httpx.Response(
            200,
            json={"uid": body["uid"], "name": "Standard", "access-layers": [{"uid": "lay-1"}]},
        )
    if cmd == "show-nat-rulebase":
        return httpx.Response(200, json={"rulebase": [], "total": 0, "objects-dictionary": []})
    if cmd in _OPTIONAL_READS:
        return _OPTIONAL_READS[cmd]()
    raise AssertionError(f"unexpected cmd {cmd}")


def test_expired_session_relogs_in_and_retries_the_page(monkeypatch, caplog):
    """A session that lapses mid-pagination (the Web API's own signal: HTTP 400,
    generic_err_wrong_session_id) re-logs-in once and retries the failed page
    with the new sid; the fetch completes with every page."""
    caplog.set_level("INFO")  # the relogin note is informational, below caplog's WARNING default
    state = {"logins": 0, "dead": set()}

    def handler(request: httpx.Request) -> httpx.Response:
        cmd = request.url.path.removeprefix("/web_api/")
        body = json.loads(request.content or b"{}")
        if cmd == "login":
            state["logins"] += 1
            return httpx.Response(200, json={"sid": f"SID{state['logins']}"})
        sid = request.headers.get("X-chkp-sid")
        if cmd == "show-access-rulebase" and body.get("offset", 0) == 2 and sid == "SID1":
            state["dead"].add("SID1")  # the session lapses mid-pagination
        if cmd != "logout" and sid in state["dead"]:
            return httpx.Response(
                400, json={"code": "generic_err_wrong_session_id", "message": f"Wrong session id [{sid}]"}
            )
        return _serve_session(cmd, body)

    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: httpx.MockTransport(handler))
    raw = CpCollector(_cfg(), Settings(_env_file=None)).fetch()
    got = [r["uid"] for p in raw["rulebases"]["lay-1"] for r in p["rulebase"]]
    assert got == [f"r-{i}" for i in range(6)]  # the failed page was retried, none lost
    assert state["logins"] == 2  # exactly one re-login
    assert "renewing the management session" in caplog.text


def test_page_rejected_on_a_fresh_session_is_raised(monkeypatch):
    """A page the management rejects on a fresh session fails the fetch after
    one re-login."""
    state = {"logins": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        cmd = request.url.path.removeprefix("/web_api/")
        if cmd == "login":
            state["logins"] += 1
            return httpx.Response(200, json={"sid": f"SID{state['logins']}"})
        if cmd == "logout":
            return httpx.Response(200, json={"message": "OK"})
        return httpx.Response(403, json={"message": "forbidden"})

    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPStatusError):
        CpCollector(_cfg(), Settings(_env_file=None)).fetch()
    assert state["logins"] == 2


def test_revoked_credential_fails_the_relogin_loud(monkeypatch):
    """A credential revoked mid-fetch must not retry forever: the re-login itself
    is rejected and raises the same loud login failure a fresh probe would."""
    state = {"logins": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        cmd = request.url.path.removeprefix("/web_api/")
        body = json.loads(request.content or b"{}")
        if cmd == "login":
            state["logins"] += 1
            if state["logins"] > 1:
                return httpx.Response(403, json={"message": "credential revoked"})
            return httpx.Response(200, json={"sid": "SID1"})
        if cmd == "show-gateways-and-servers":
            return httpx.Response(401, json={"message": "Wrong session id"})
        return _serve_session(cmd, body)

    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: httpx.MockTransport(handler))
    with pytest.raises(RuntimeError, match="login failed"):
        CpCollector(_cfg(), Settings(_env_file=None)).fetch()
    assert state["logins"] == 2


def test_session_renewed_proactively_before_expiry(monkeypatch):
    """The login reply's session-timeout drives a proactive re-login at two
    thirds of the validity window."""
    clock = {"t": 0.0}
    monkeypatch.setattr("hst.collectors.checkpoint._now", lambda: clock["t"])
    state = {"logins": 0, "cmd_sids": []}

    def handler(request: httpx.Request) -> httpx.Response:
        cmd = request.url.path.removeprefix("/web_api/")
        body = json.loads(request.content or b"{}")
        if cmd == "login":
            state["logins"] += 1
            return httpx.Response(200, json={"sid": f"SID{state['logins']}", "session-timeout": 60})
        if cmd != "logout":
            state["cmd_sids"].append(request.headers.get("X-chkp-sid"))
            clock["t"] += 15.0  # each page costs 15s of a 60s session
        return _serve_session(cmd, body)

    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: httpx.MockTransport(handler))
    raw = CpCollector(_cfg(), Settings(_env_file=None)).fetch()
    got = [r["uid"] for p in raw["rulebases"]["lay-1"] for r in p["rulebase"]]
    assert got == [f"r-{i}" for i in range(6)]
    # renewal at t>=40 of each 60s session: api versions/published session/
    # gateways on SID1, layers/global properties/page-0 on SID2, page-2/page-4/
    # packages on SID3, package details/NAT on SID4
    assert state["logins"] == 4
    assert state["cmd_sids"] == ["SID1"] * 3 + ["SID2"] * 3 + ["SID3"] * 3 + ["SID4"] * 2


def test_layer_uid_cannot_escape_replay_cache_dir(monkeypatch, tmp_path):
    """The layer uid comes from the management server's reply and lands in cache
    filenames; a hostile value must not steer the cache write or the plaintext
    cleanup unlink outside the replay-cache directory."""
    from hst.core import Settings as S

    settings = S(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())
    transport, _ = make_mock()

    def h(request):
        resp = transport.handler(request)
        if request.url.path.endswith("show-access-layers"):
            data = resp.json()
            data["access-layers"][0]["uid"] = "../../../escape"
            data["access-layers"][0]["last-modify-time"] = {"posix": 111}
            data["access-layers"][0]["last-modifier"] = "admin"
            return httpx.Response(200, json=data)
        return resp

    monkeypatch.setattr("hst.collectors.checkpoint._transport", lambda config: httpx.MockTransport(h))
    CpCollector(_cfg(), settings).fetch()

    cache_dir = settings.raw_dir / "checkpoint" / "replay-cache"
    files = list(cache_dir.iterdir())
    assert files, "cache entry expected after a revisioned fetch"
    strays = [p for p in settings.hst_data_dir.rglob("*escape*") if cache_dir not in p.parents]
    assert not strays


def _norm_cp_gateway_types(*, packages: bool = True):
    """Every gateway type the collector keeps, the management and log servers,
    and a cluster with a member list in each of the API's two spellings."""
    from hst.collectors.checkpoint import GATEWAY_TYPES, normalize_checkpoint

    gateways = [
        {"uid": f"gw-{t}", "name": f"fw-{t}", "type": t, "ipv4-address": "10.9.0.1"}
        for t in sorted(GATEWAY_TYPES)
    ]
    gateways += [
        {"uid": "mgmt-1", "name": "smc", "type": "checkpoint-host", "ipv4-address": "10.9.0.100"},
        {"uid": "log-1", "name": "logs", "type": "CpmiLogServer", "ipv4-address": "10.9.0.101"},
        {"uid": "old-1", "name": "untyped"},
        {
            "uid": "cl-1",
            "name": "fw-cluster",
            "type": "CpmiGatewayCluster",
            "cluster-members": [{"uid": "cm-a", "name": "fw-a"}, {"name": "fw-b"}],
        },
        {"uid": "cm-a", "name": "fw-a", "type": "CpmiClusterMember"},
        {"uid": "cm-b", "name": "fw-b", "type": "CpmiClusterMember"},
        {
            "uid": "vsx-1",
            "name": "vsx-cluster",
            "type": "CpmiVsxClusterNetobj",
            "cluster-member-names": ["vsx-a", "vsx-b", "no-such-member"],
        },
        {"uid": "vsx-a", "name": "vsx-a", "type": "CpmiVsxClusterMember"},
        {"uid": "vsx-b", "name": "vsx-b", "type": "CpmiVsxClusterMember"},
        {"uid": "vs-1", "name": "vs1", "type": "CpmiVsClusterNetobj"},
    ]
    raw = {
        "gateways": gateways,
        "layers": [{"uid": "lay-1", "name": "Network"}],
        "rulebases": {"lay-1": [CP_RULEBASE_PAGE]},
        "nat": {},
        "replayed_layers": [],
    }
    if packages:
        raw["packages"] = [{"uid": "pkg-1", "name": "Standard"}]
        raw["package_details"] = {
            "pkg-1": {
                "uid": "pkg-1",
                "name": "Standard",
                "access-layers": [{"uid": "lay-1"}],
                "installation-targets": [{"uid": "vs-1"}],
            }
        }
    return normalize_checkpoint(raw, mgmt="cp-mgmt.example", domain="")


def _device_of(batch, api_uid: str) -> str:
    """The uid of the Device that the gateway object `api_uid` resolved to. The
    registry mints it from the object's name, and the node keeps the api uid
    as `cp_raw_uid`."""
    return next(n.uid for n in batch.nodes if n.label == "Device" and n.props.get("cp_raw_uid") == api_uid)


def test_cp_gateway_type_filter_keeps_every_gateway_type_and_marks_the_servers():
    """Every listed gateway type is a firewall. The management and log servers
    stay Device nodes with role management. An object with no type stays a
    firewall."""
    from hst.collectors.checkpoint import GATEWAY_TYPES
    from hst.core import labels

    batch = _norm_cp_gateway_types()
    devices = {n.uid: n.props for n in batch.nodes if n.label == "Device"}
    ref = lambda u: _device_of(batch, u)  # noqa: E731
    for t in GATEWAY_TYPES:
        assert devices[ref(f"gw-{t}")]["role"] == "firewall", t
        assert devices[ref(f"gw-{t}")]["cp_type"] == t
    assert devices[ref("mgmt-1")]["role"] == "management"
    assert devices[ref("log-1")]["role"] == "management"
    assert devices[ref("old-1")]["role"] == "firewall"
    assert {p["role"] for p in devices.values()} <= labels.DEVICE_ROLES
    firewall_types = {p.get("cp_type") for p in devices.values() if p["role"] == "firewall"}
    assert "checkpoint-host" not in firewall_types


def test_cp_cluster_object_becomes_a_redundancy_group_with_member_of_from_its_members():
    """One RedundancyGroup per cluster object, kind cp-cluster, with MEMBER_OF
    from each member Device the reply names by uid or by name. A name that
    resolves to no object writes no edge. A virtual system is a gateway of
    its own and joins no group."""
    from hst.core import uid as uidmod

    batch = _norm_cp_gateway_types()
    scope = "cp:cp-mgmt.example"
    groups = {n.uid: n.props for n in batch.nodes if n.label == "RedundancyGroup"}
    cluster = uidmod.rgrp("cp-cluster", scope, "fw-cluster")
    vsx = uidmod.rgrp("cp-cluster", scope, "vsx-cluster")
    assert set(groups) == {cluster, vsx}
    assert groups[cluster] == {
        "kind": "cp-cluster",
        "name": "fw-cluster",
        "cp_type": "CpmiGatewayCluster",
        "cp_raw_uid": "cl-1",
    }
    members = {
        (r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "MEMBER_OF" and r.end_uid in groups
    }
    ref = lambda u: _device_of(batch, u)  # noqa: E731
    assert members == {
        (ref("cm-a"), cluster),
        (ref("cm-b"), cluster),
        (ref("vsx-a"), vsx),
        (ref("vsx-b"), vsx),
    }


def test_cp_configured_binding_lands_on_the_virtual_system_device():
    """A VSX package names the virtual system object as its installation
    target, so the configured ENFORCES edge lands on that object's own Device,
    the node the path engine joins a Gaia FirewallInstance to by cp_raw_uid."""
    batch = _norm_cp_gateway_types()
    enforces = [r for r in batch.rels if r.rel_type == "ENFORCES"]
    assert [(r.start_uid, r.props) for r in enforces] == [(_device_of(batch, "vs-1"), {"configured": True})]
    vs = next(n for n in batch.nodes if n.label == "Device" and n.props.get("cp_raw_uid") == "vs-1")
    assert vs.props["role"] == "firewall"


def test_cp_binding_without_package_details_never_names_a_management_server():
    """A raw snapshot without package details binds every firewall
    approximately. The management and log servers are not policy targets and
    get no edge."""
    batch = _norm_cp_gateway_types(packages=False)
    bound = {r.start_uid for r in batch.rels if r.rel_type == "ENFORCES"}
    assert bound
    assert all(r.props == {"approximate": True} for r in batch.rels if r.rel_type == "ENFORCES")
    assert _device_of(batch, "mgmt-1") not in bound
    assert _device_of(batch, "log-1") not in bound
    assert _device_of(batch, "old-1") in bound
    assert _device_of(batch, "vs-1") in bound
