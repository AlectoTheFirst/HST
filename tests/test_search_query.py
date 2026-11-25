"""The typed search (core/search.py) without a database: how a query text is
read, what each mode matches in each graph kind, and the Cypher it sends."""

from __future__ import annotations

import re

import pytest

from hst.core import filters as F
from hst.core import search as S


@pytest.mark.parametrize(
    ("text", "mode"),
    [
        ("10.1.2.7", "ip"),
        (" 2001:db8::5 ", "ip"),
        ("10.1.2.0/24", "prefix"),
        ("10.1.2.7/24", "prefix"),
        ("2001:db8::/32", "prefix"),
        ("10.0.0.5-10.0.0.9", "range"),
        ("10.0.0.5 - 10.0.0.9", "range"),
        ("2001:db8::1-2001:db8::ff", "range"),
        ("aa:bb:cc:dd:ee:ff", "mac"),
        ("AA-BB-CC-DD-EE-FF", "mac"),
        ("aabb.ccdd.eeff", "mac"),
        ("aabbccddeeff", "mac"),
        ("/^edge-[0-9]+$/", "regex"),
        ("core-sw", "text"),
        ("10.1.2", "text"),
        ("edge1 dc2", "text"),
        ("/", "text"),
        ("//", "text"),
    ],
)
def test_the_mode_of_a_query(text, mode):
    assert S.detect(text).mode == mode


def test_the_address_modes_parse_through_the_filter_module():
    assert S.detect("10.1.2.7").filter == F.parse_filter({"ip": "10.1.2.7"})
    assert S.detect("10.1.2.7/24").filter == F.parse_filter({"subnet": "10.1.2.0/24"})
    rng = S.detect("10.0.0.5-10.0.0.9").filter
    assert rng is not None and (rng.range_start, rng.range_end) == ("10.0.0.5", "10.0.0.9")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("10.0.0.9-10.0.0.5", "range_start is above range_end"),
        ("10.0.0.1-2001:db8::1", "one address family"),
        ("/(a+)+/", "regex refused: a quantified group may not hold a quantifier"),
        ("/(?<=a)b/", "regex refused"),
        ("/" + "a" * 129 + "/", "regex refused: longer than 128"),
        ("   ", "empty query"),
    ],
)
def test_a_query_the_filter_module_refuses_is_an_error(text, message):
    with pytest.raises(F.FilterError, match=re.escape(message)):
        S.detect(text)


def test_a_regex_is_checked_by_the_filter_guard_itself(monkeypatch):
    seen: list[str] = []
    real = F.check_regex

    def spy(pattern: str) -> str:
        seen.append(pattern)
        return real(pattern)

    monkeypatch.setattr(F, "check_regex", spy)
    q = S.detect("/edge-.*/")
    assert seen == ["edge-.*"]
    assert q.filter is not None and q.filter.regex == "edge-.*"


def test_a_mac_in_any_notation_is_the_same_mac():
    forms = {
        S.detect(t).mac for t in ("aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff", "AABBCCDDEEFF")
    }
    assert forms == {"aabbccddeeff"}
    q = S.detect("aabb.ccdd.eeff")
    assert {"aabbccddeeff", "aa:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-ff", "AA:BB:CC:DD:EE:FF"} <= set(q.mac_forms)


def test_text_that_names_a_vlan_carries_its_id():
    assert S.detect("vlan 20").vid == 20
    assert S.detect("20").vid == 20
    assert S.detect("edge").vid is None


def test_the_lucene_query_escapes_query_syntax():
    assert S.lucene('core-sw "a" (b)') == "core* AND sw* AND a* AND b*"
    assert S.lucene("10.0.0.1") == "10.0.0.1*"


# --- what each mode searches ----------------------------------------------------------


def _searched(text: str) -> set[str]:
    q = S.detect(text)
    return {k for k in S.GRAPH_KINDS if S.graph_predicate(k, q) is not None}


def test_each_mode_searches_the_kinds_that_hold_what_it_names():
    address = {"device", "interface", "prefix", "ip_address", "endpoint"}
    assert _searched("10.1.2.7") == address
    assert _searched("10.1.2.0/24") == address
    assert _searched("10.1.2.1-10.1.2.9") == address
    assert _searched("aa:bb:cc:dd:ee:ff") == {"device", "interface", "endpoint"}
    assert _searched("/edge.*/") == set(S.GRAPH_KINDS)
    assert _searched("edge") == set(S.GRAPH_KINDS) - {"prefix", "ip_address"}
    assert _searched("10.1.2") == set(S.GRAPH_KINDS)


def test_an_address_matches_through_the_integer_keys():
    q = S.detect("10.1.2.7")
    prefix = S.graph_predicate("prefix", q)
    assert prefix is not None
    assert "p.lo_key <= $f_ip_key AND p.hi_key >= $f_ip_key" in prefix.where
    assert prefix.params["f_ip_key"] == "4:0a010207"
    ip = S.graph_predicate("ip_address", q)
    assert ip is not None and "a.ip_key = $f_ip_key" in ip.where
    iface = S.graph_predicate("interface", q)
    assert (
        iface is not None and "(i)-[fh:HAS_IP]->(fia:IpAddress) WHERE fh._retired_at IS NULL" in iface.where
    )


def test_a_mac_matches_the_mac_property_in_its_common_notations():
    pred = S.graph_predicate("endpoint", S.detect("AABB.CCDD.EEFF"))
    assert pred is not None and pred.where == "e.mac IN $m_macs"
    assert "aa:bb:cc:dd:ee:ff" in pred.params["m_macs"]


def test_text_lists_through_the_full_text_index_or_the_kind_s_own_fields():
    q = S.detect("vlan 20")
    device = S.graph_predicate("device", q)
    assert device is not None and device.fulltext and device.params == {"lucene": "vlan* AND 20*"}
    segment = S.graph_predicate("segment", q)
    assert segment is not None and not segment.fulltext
    assert segment.params == {"t_text": "vlan 20", "t_vid": 20}
    assert "vl.vid = $t_vid" in segment.where


def test_a_uid_query_matches_the_uid_only():
    q = S.Query("dev:edge1", "uid")
    pred = S.graph_predicate("device", q)
    assert pred is not None and pred.where == "d.uid = $u_uid" and pred.params == {"u_uid": "dev:edge1"}


# --- the Cypher -----------------------------------------------------------------------


def _all_queries() -> list[str]:
    out = []
    for text in ("10.1.2.7", "aa:bb:cc:dd:ee:ff", "/edge.*/", "edge", "10.1.2", "vlan 20"):
        q = S.detect(text)
        for kind in S.GRAPH_KINDS:
            pred = S.graph_predicate(kind, q)
            if pred is None:
                continue
            out += [
                S.page_query(kind, pred, seek=False),
                S.page_query(kind, pred, seek=True),
                S.count_query(kind, pred),
            ]
    return out


def test_every_graph_query_pins_its_node_and_every_relationship_to_the_run():
    queries = _all_queries()
    assert queries
    for text in queries:
        var = re.search(r"(?:MATCH \(|YIELD node AS )(\w+)", text)
        assert var is not None, text
        v = var.group(1)
        runless = f"{v}:Meta AND {v}.collection_ts IS NULL"
        pin = f"(({runless}) OR {v}.collection_ts = $snap)\n  AND NOT {v}:Retired"
        assert pin in text, text
        for rel in re.findall(r"-\[(\w+):[A-Z_|]+\]-", text):
            assert f"{rel}._retired_at IS NULL" in text, (rel, text)


def test_a_text_page_uses_the_full_text_index_and_an_address_page_the_label():
    edge = S.graph_predicate("device", S.detect("edge"))
    assert edge is not None
    assert "db.index.fulltext.queryNodes('obj_names', $lucene)" in S.page_query("device", edge, seek=False)
    ip = S.graph_predicate("device", S.detect("10.1.2.7"))
    assert ip is not None
    page = S.page_query("device", ip, seek=True)
    assert page.lstrip().startswith("MATCH (d:Device)")
    assert "(sort_key > $c_key OR (sort_key = $c_key AND d.uid > $c_uid))" in page


def test_a_cursor_belongs_to_one_query():
    a, b = S.detect("10.1.2.7"), S.detect("10.1.2.8")
    cursor = F.Cursor(kind="device", run=7, key="edge1", uid="dev:edge1", filter=a.fingerprint).encode()
    assert F.decode_cursor(cursor, kind="device", filter_print=a.fingerprint).uid == "dev:edge1"
    with pytest.raises(F.FilterError, match="another filter"):
        F.decode_cursor(cursor, kind="device", filter_print=b.fingerprint)
    with pytest.raises(F.FilterError, match="another list"):
        F.decode_cursor(cursor, kind="prefix", filter_print=a.fingerprint)
