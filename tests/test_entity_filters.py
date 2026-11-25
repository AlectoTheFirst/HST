"""The list filter module (core/filters.py), the address keys it compares
(core/ipenc.py), and the paged read built on them (core/entity_read.py)."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime

import pytest

from hst.core import entity_read, ipenc
from hst.core import filters as F
from hst.core.loader import load
from hst.core.model import Batch

# --- address keys ---------------------------------------------------------------------


def test_graph_keys_sort_in_address_order_within_a_family():
    v4 = [
        "0.0.0.0",  # noqa: S104
        "9.255.255.255",
        "10.0.0.1",
        "10.0.0.10",
        "10.0.1.0",
        "192.168.1.1",
        "255.255.255.255",
    ]
    v6 = ["::", "::1", "2001:db8::1", "2001:db8::10", "fe80::1", "ffff::"]
    for family in (v4, v6):
        keys = [ipenc.graph_key(a) for a in family]
        assert keys == sorted(keys)
        assert [int(ipaddress.ip_address(a)) for a in family] == sorted(
            int(ipaddress.ip_address(a)) for a in family
        )
    # every IPv4 key sorts before every IPv6 key, so a range of one family
    # never takes in an address of the other
    assert max(ipenc.graph_key(a) or "" for a in v4) < min(ipenc.graph_key(a) or "" for a in v6)


def test_graph_key_formats():
    assert ipenc.graph_key("10.0.0.1") == "4:0a000001"
    assert ipenc.graph_key("2001:db8::1") == "6:20010db8000000000000000000000001"
    assert ipenc.graph_key("fe80::1%eth0") == ipenc.graph_key("fe80::1")
    assert ipenc.graph_key("10.0.0.5/24") == "4:0a000005"
    assert ipenc.graph_key("not-an-ip") is None
    assert ipenc.graph_key(None) is None
    assert ipenc.graph_prefix_keys("10.0.0.0/24") == ("4:0a000000", "4:0a0000ff")
    assert ipenc.graph_prefix_keys("10.0.0.7/24") == ("4:0a000000", "4:0a0000ff")
    assert ipenc.graph_prefix_keys("2001:db8::/32") == (
        "6:20010db8000000000000000000000000",
        "6:20010db8ffffffffffffffffffffffff",
    )
    assert ipenc.graph_prefix_keys("bogus") is None


def test_graph_address_props_per_label():
    assert ipenc.graph_address_props("IpAddress", {"ip": "10.0.0.1"}) == {"ip_key": "4:0a000001"}
    assert ipenc.graph_address_props("Endpoint", {"ip": "10.0.0.1"}) == {"ip_key": "4:0a000001"}
    assert ipenc.graph_address_props("Endpoint", {"mac": "aa"}) == {}
    assert ipenc.graph_address_props(("Obj", "Prefix", "L3"), {"cidr": "10.0.0.0/30"}) == {
        "lo_key": "4:0a000000",
        "hi_key": "4:0a000003",
    }
    # a node that carries its keys already keeps them
    assert ipenc.graph_address_props("IpAddress", {"ip": "10.0.0.1", "ip_key": "4:0a000001"}) == {}
    assert ipenc.graph_address_props("Device", {"ip": "10.0.0.1"}) == {}


class _LoaderSession:
    def __init__(self):
        self.rows: dict[str, list[dict]] = {}

    def run(self, query, **params):  # pragma: no cover
        raise AssertionError("autocommit")

    def execute_write(self, work):
        session = self

        class _Tx:
            def run(self, query, **params):
                upsert = "MERGE (n" in query
                if upsert:
                    session.rows.setdefault(query, []).extend(params["rows"])

                class _R:
                    def data(self_inner):
                        if not upsert:
                            return []
                        return [{"uid": r["uid"], "before": {}} for r in params["rows"]]

                return _R()

        return work(_Tx())


def test_the_loader_writes_the_address_keys():
    batch = Batch.model_validate(
        {
            "source": "s1",
            "scope": "unifi:site1",
            "nodes": [
                {"label": "IpAddress", "uid": "ip:a:10.0.0.1", "props": {"ip": "10.0.0.1", "anchor": "a"}},
                {
                    "label": "Prefix",
                    "uid": "pfx:a:10.0.0.0/24",
                    "props": {"cidr": "10.0.0.0/24", "anchor": "a"},
                },
                {"label": "Endpoint", "uid": "ep:x", "props": {"mac": "aa:bb:cc:dd:ee:ff"}},
            ],
        }
    )
    s = _LoaderSession()
    load(s, batch, ts_ms=1_000, collection_ts=1_000)
    written = {r["uid"]: r["props"] for rows in s.rows.values() for r in rows}
    assert written["ip:a:10.0.0.1"]["ip_key"] == "4:0a000001"
    assert (written["pfx:a:10.0.0.0/24"]["lo_key"], written["pfx:a:10.0.0.0/24"]["hi_key"]) == (
        "4:0a000000",
        "4:0a0000ff",
    )
    assert "ip_key" not in written["ep:x"]


def test_a_site_scope_is_compared_by_the_site_uid_not_the_case_sensitive_code():
    """A collector's `FR5` and the stored `fr5` are one graph Site."""
    c = F.compile_filter(F.parse_filter({"site": ["FR5", "dc:1"]}), "device")
    assert c.params["f_site"] == ["site:fr5", "site:dc-1"]
    assert "fs.uid IN $f_site" in c.where and "code IN" not in c.where
    assert F.compile_filter(F.parse_filter({"site": ["FR5"]}), "site").where == "(s.uid IN $f_site)"


def test_a_carried_copy_gains_the_address_keys():
    from hst.core import cycle

    labels, props = cycle._carried_node(
        {
            "labels": ["Obj", "IpAddress", "L3"],
            "props": {"uid": "ip:a", "ip": "10.0.0.1", "collection_ts": 1},
        },
        "not-run",
    )
    assert labels == ("IpAddress", "L3", "Obj")
    assert props["ip_key"] == "4:0a000001"
    assert "collection_ts" not in props


# --- parsing --------------------------------------------------------------------------


def test_parse_normalizes_each_kind():
    f = F.parse_filter(
        {
            "ip": " 10.0.0.1 ",
            "subnet": "10.0.0.7/24",
            "range_start": "2001:db8::1",
            "range_end": "2001:db8::ff",
            "text": "Printer",
            "text_fields": ["vendor", "name", "name"],
            "regex": "sw-[0-9]+",
            "site": ["ber1", " ber1 ", "muc2"],
            "last_seen_after": "2026-01-01T00:00:00Z",
            "last_seen_before": "1767312000000",
        }
    )
    assert f.ip == "10.0.0.1"
    assert f.subnet == "10.0.0.0/24"
    assert f.text_fields == ("name", "vendor")
    assert f.site == ("ber1", "muc2")
    assert f.last_seen_after == datetime(2026, 1, 1, tzinfo=UTC)
    assert f.last_seen_before == datetime(2026, 1, 2, tzinfo=UTC)
    assert f.kinds() == ["ip", "subnet", "text", "regex", "site", "range", "last_seen"]


def test_empty_values_are_no_filter():
    f = F.parse_filter({"ip": None, "text": "", "site": []})
    assert f.kinds() == []
    assert F.compile_filter(f, "endpoint") == F.Compiled("true", {})


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"ip": "10.0.0.256"}, "is not an IP address"),
        ({"subnet": "10.0.0.0/33"}, "is not a prefix"),
        ({"range_start": "10.0.0.1"}, "go together"),
        ({"range_start": "10.0.0.9", "range_end": "10.0.0.1"}, "above range_end"),
        ({"range_start": "10.0.0.1", "range_end": "::1"}, "one address family"),
        ({"text": "x" * (F.TEXT_MAX_LEN + 1)}, "text"),
        ({"text_fields": ["name"]}, "needs text"),
        ({"text": "a", "text_fields": ["serial"]}, "text_fields"),
        ({"regex": "a", "regex_fields": ["mac"]}, "regex_fields"),
        ({"regex_fields": ["name"]}, "needs regex"),
        ({"site": ["x"] * 2 + [str(i) for i in range(F.SCOPE_MAX_ITEMS)]}, "at most"),
        ({"device": ["d" * (F.SCOPE_ITEM_MAX_LEN + 1)]}, "longer than"),
        (
            {"last_seen_after": "2026-02-01T00:00:00Z", "last_seen_before": "2026-01-01T00:00:00Z"},
            "not before",
        ),
        ({"kind": "client"}, "Extra inputs"),
    ],
)
def test_parse_refuses(values, message):
    with pytest.raises(F.FilterError, match=message):
        F.parse_filter(values)


# --- the regex guard ------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    ["sw-.*", "^ap-[0-9]{2}$", r"[a-z]+\.lab", "(?:ab|cd)x", "(ab)*c", "a*?b", r"\d{1,3}", "x|y|z", "[^]a]"],
)
def test_the_regex_guard_accepts(pattern):
    assert F.check_regex(pattern) == pattern


@pytest.mark.parametrize(
    ("pattern", "reason"),
    [
        ("(a+)+", "quantified group"),
        ("(a*)*b", "quantified group"),
        ("(a|aa)+", "quantified group"),
        ("((a)*)*", "quantified group"),
        ("(.*a){3}", "quantified group"),
        (".*.*.*.*x", "unbounded"),
        ("a{1,100}", "repetition bound"),
        ("a{5,2}", "out of order"),
        ("a{2", "malformed"),
        ("(?=x)", "plain and"),
        ("(?<n>x)", "plain and"),
        ("(?i)x", "plain and"),
        (r"(a)\1", r"\\1"),
        (r"\p{L}", r"\\p"),
        (r"\Qa\E", r"\\Q"),
        ("a*+", "possessive"),
        ("[[a]]", "nested character"),
        ("[a&&b]", "nested character"),
        ("*a", "without a target"),
        ("(a", "unbalanced"),
        ("a)", "unbalanced"),
        ("[a", "unterminated"),
        ("a]", "unescaped"),
        ("", "empty"),
        ("a" * (F.REGEX_MAX_LEN + 1), "longer than"),
        ("((((((((a))))))))", "nested deeper"),
    ],
)
def test_the_regex_guard_refuses(pattern, reason):
    with pytest.raises(F.FilterError, match=reason):
        F.check_regex(pattern)


# --- compilation ----------------------------------------------------------------------


def test_each_kind_compiles_to_its_parameters():
    f = F.parse_filter(
        {
            "ip": "10.0.0.1",
            "subnet": "10.0.0.0/24",
            "range_start": "10.0.0.1",
            "range_end": "10.0.0.9",
            "text": "AA-BB",
            "regex": "sw.*",
            "site": ["ber1"],
            "vrf": ["red"],
            "routing_domain": ["corp"],
            "segment": ["bd:vlan:fab0:10"],
            "device": ["swa-01"],
            "port": ["Port 5"],
            "last_seen_after": "2026-01-01T00:00:00Z",
            "last_seen_before": "2026-01-02T00:00:00Z",
        }
    )
    c = F.compile_filter(f, "endpoint")
    assert c.params == {
        "f_ip": "10.0.0.1",
        "f_ip_key": "4:0a000001",
        "f_net_lo": "4:0a000000",
        "f_net_hi": "4:0a0000ff",
        "f_range_lo": "4:0a000001",
        "f_range_hi": "4:0a000009",
        "f_text": "aa-bb",
        "f_text_hex": "aabb",
        "f_regex": "(?i)sw.*",
        "f_regex_max": F.REGEX_MAX_VALUE,
        "f_site": ["site:ber1"],
        "f_vrf": ["red"],
        "f_routing_domain": ["corp"],
        "f_segment": ["bd:vlan:fab0:10"],
        "f_device": ["swa-01"],
        "f_port": ["Port 5"],
        "f_seen_after": 1_767_225_600_000,
        "f_seen_before": 1_767_312_000_000,
    }
    # every parameter the predicate names is bound, and every one bound is named
    import re

    named = set(re.findall(r"\$(f_\w+)", c.where))
    assert named == set(c.params)
    # one attachment subquery carries the site, device and port scopes together
    assert c.where.count("ATTACHED") == 2  # the port text field, the attachment scopes
    assert "=~ $f_regex" in c.where


def test_text_that_is_no_mac_fragment_matches_the_mac_as_text_only():
    c = F.compile_filter(F.parse_filter({"text": "printer"}), "endpoint")
    assert c.params["f_text_hex"] == ""
    c = F.compile_filter(F.parse_filter({"text": "aa:bb", "text_fields": ["mac"]}), "endpoint")
    assert c.params["f_text_hex"] == "aabb"
    assert "e.oui" not in c.where


def test_a_kind_an_entity_lacks_is_refused_not_ignored():
    with pytest.raises(F.FilterError, match=r"site lists do not support the filter.*ip"):
        F.compile_filter(F.parse_filter({"ip": "10.0.0.1"}), "site")
    with pytest.raises(F.FilterError, match="text over: mac"):
        F.compile_filter(F.parse_filter({"text": "a", "text_fields": ["mac"]}), "prefix")


def test_a_prefix_compares_its_bounds():
    c = F.compile_filter(F.parse_filter({"ip": "10.0.0.1", "subnet": "10.0.0.0/8"}), "prefix")
    assert "p.lo_key <= $f_ip_key AND p.hi_key >= $f_ip_key" in c.where
    assert "p.lo_key >= $f_net_lo AND p.hi_key <= $f_net_hi" in c.where


@pytest.mark.parametrize("kind", sorted(F.TARGETS))
def test_every_kind_compiles_what_it_supports(kind):
    target = F.TARGETS[kind]
    values: dict = {}
    if "ip" in target.supports():
        values |= {
            "ip": "10.0.0.1",
            "subnet": "10.0.0.0/24",
            "range_start": "10.0.0.1",
            "range_end": "10.0.0.2",
        }
    if target.text:
        values["text"] = "a"
    if target.regex:
        values["regex"] = "a.*"
    for scope in F.SCOPES:
        if scope in target.supports():
            values[scope] = ["x"]
    if target.last_seen:
        values["last_seen_after"] = "2026-01-01T00:00:00Z"
    c = F.compile_filter(F.parse_filter(values), kind)
    import re

    assert set(re.findall(r"\$(f_\w+)", c.where)) <= set(c.params)
    assert c.where.count("(") == c.where.count(")")
    assert c.where.count("{") == c.where.count("}")


# --- cursors --------------------------------------------------------------------------


def test_a_cursor_round_trips_and_is_tied_to_its_list():
    f = F.parse_filter({"text": "a"})
    cur = F.Cursor(kind="endpoint", run=42, key="printer", uid="ep:1", filter=f.fingerprint())
    text = cur.encode()
    assert "=" not in text
    assert F.decode_cursor(text, kind="endpoint", filter_print=f.fingerprint()) == cur
    with pytest.raises(F.FilterError, match="another list"):
        F.decode_cursor(text, kind="device", filter_print=f.fingerprint())
    other = F.parse_filter({"text": "b"})
    with pytest.raises(F.FilterError, match="another filter"):
        F.decode_cursor(text, kind="endpoint", filter_print=other.fingerprint())


@pytest.mark.parametrize("text", ["", "!!!", "e30", "eyJ2IjoyfQ", "x" * (F.CURSOR_MAX_LEN + 1)])
def test_a_broken_cursor_is_refused(text):
    with pytest.raises(F.FilterError, match="invalid cursor"):
        F.decode_cursor(text, kind="endpoint", filter_print="")


def test_the_fingerprint_ignores_order_and_duplicates():
    a = F.parse_filter({"site": ["b", "a"], "text": "x"})
    b = F.parse_filter({"text": "x", "site": ["a", "b", "a"]})
    assert a.fingerprint() == b.fingerprint()
    assert a.fingerprint() != F.parse_filter({"site": ["a"], "text": "x"}).fingerprint()


def test_after_takes_the_rows_past_the_cursor():
    rows = [
        {"name": "a", "uid": "1"},
        {"name": "b", "uid": "2"},
        {"name": "b", "uid": "3"},
        {"name": "c", "uid": "4"},
    ]
    cur = F.Cursor(kind="k", run=None, key="b", uid="2", filter="")
    assert [r["uid"] for r in F.after(rows, cur)] == ["3", "4"]
    gone = F.Cursor(kind="k", run=None, key="b", uid="25", filter="")
    assert [r["uid"] for r in F.after(rows, gone)] == ["3", "4"]
    assert F.after(rows, None) == rows


# --- the paged read -------------------------------------------------------------------


class _PageSession:
    def __init__(self, page_rows, count=3):
        self.page_rows = page_rows
        self.count = count
        self.calls: list[tuple[str, dict, float | None]] = []

    def run(self, query, **params):
        text = getattr(query, "text", query)
        self.calls.append((text, params, getattr(query, "timeout", None)))
        rows = self.page_rows if "sort_key" in text and "count(" not in text else [{"n": self.count}]

        class _R:
            def data(self_inner):
                return rows

        return _R()


def test_read_page_pins_the_run_and_returns_the_next_cursor():
    f = F.parse_filter({"text": "a"})
    rows = [{"uid": f"ep:{i}", "sort_key": f"n{i}"} for i in range(3)]
    s = _PageSession(rows, count=7)
    page = entity_read.read_page(s, "endpoint", f, snap=42, run=42, cursor=None, limit=2)
    assert page.uids == ["ep:0", "ep:1"]
    assert (page.total_capped, page.total_exact) == (7, True)
    cur = F.decode_cursor(page.next_cursor or "", kind="endpoint", filter_print=f.fingerprint())
    assert (cur.run, cur.key, cur.uid) == (42, "n1", "ep:1")
    (q1, p1, t1), (q2, p2, t2) = s.calls
    assert "e.collection_ts = $snap" in q1 and "e.collection_ts = $snap" in q2
    assert p1["snap"] == p2["snap"] == 42
    assert p1["limit"] == 3 and p2["cap"] == F.COUNT_CAP + 1
    assert t1 == t2 == F.QUERY_TIMEOUT_S
    assert "$c_key" not in q1

    s = _PageSession(rows[2:], count=7)
    page = entity_read.read_page(s, "endpoint", f, snap=42, run=42, cursor=cur, limit=2)
    assert page.uids == ["ep:2"] and page.next_cursor is None
    q, p, _ = s.calls[0]
    assert "(sort_key > $c_key OR (sort_key = $c_key AND e.uid > $c_uid))" in q
    assert (p["c_key"], p["c_uid"]) == ("n1", "ep:1")


def test_the_count_is_capped():
    s = _PageSession([], count=F.COUNT_CAP + 1)
    page = entity_read.read_page(s, "endpoint", F.EntityFilter(), snap=1, run=1, cursor=None, limit=5)
    assert (page.total_capped, page.total_exact) == (F.COUNT_CAP, False)


def test_endpoint_items_fold_the_display_address_and_sort_attachments():
    item = entity_read.endpoint_item(
        {
            "uid": "ep:1",
            "name": "nas",
            "ip": "10.0.0.9",
            "ips": ["10.0.0.5"],
            "attachments": [
                {"device": "b", "port": "1", "ssid": None, "sites": ["z", "a"]},
                {"device": "a", "port": None, "ssid": "corp", "sites": []},
            ],
        }
    )
    assert item["ips"] == ["10.0.0.5", "10.0.0.9"]
    assert [a["device"] for a in item["attachments"]] == ["a", "b"]
    assert item["attachments"][1]["sites"] == ["a", "z"]


def test_the_devices_of_a_site_are_the_devices_of_the_run_each_listed_once():
    query = entity_read.SITE_DEVICES
    assert "d.collection_ts = $snap" in query
    assert "WITH DISTINCT d ORDER BY coalesce(d.hostname, d.uid), d.uid LIMIT $first" in query
