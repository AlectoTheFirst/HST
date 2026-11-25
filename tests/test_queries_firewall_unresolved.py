"""The `unresolved` column of the Firewall rules table lists the short note a collector
writes beside each opaque reason, and the reason itself where a collector writes none."""

from hst.queries import QUERIES

CYPHER = next(q for q in QUERIES if q["key"] == "firewall")["cypher"]


def test_each_side_reads_the_short_note_before_the_long_reason():
    for var, side in (("sno", "src"), ("dno", "dst"), ("svc", "service")):
        assert f"coalesce({var}.opaque_note, '{side}: ' + {var}.opaque_reason)" in CYPHER


def test_an_empty_note_lists_nothing():
    # a Cisco ICMP rule is opaque only along the ICMP type its service name shows
    assert CYPHER.count("WHERE x <> '' | toString(x)]") == 3


def test_the_service_column_is_the_service_name():
    assert "collect(DISTINCT svc.name) AS services" in CYPHER
