"""What the router-local read credits when the zone model records a local zone."""

import pytest

import hst.path as _path
from hst.path.addrsets import _rule_intervals
from hst.path.gates import firewall as fw

_BASE = [
    {"rb_uid": "fw:LAN-WAN", "af": 4, "src_zone": "LAN", "dst_zone": "WAN", "dst_unbound": False},
    {"rb_uid": "fw:GUEST-WAN", "af": 4, "src_zone": "GUEST", "dst_zone": "WAN", "dst_unbound": False},
]
_GUEST_LOCAL_V4 = {
    "rb_uid": "fw:GUEST-LOCAL",
    "af": 4,
    "src_zone": "GUEST",
    "dst_zone": "LOCAL",
    "dst_unbound": True,
}


def _ivals(cidr):
    return _rule_intervals([cidr], [], [])


@pytest.fixture
def zone_rows(monkeypatch):
    rows: list[dict] = []

    def read(session, query, **kw):
        return rows if query is fw._DEVICE_ZONE_RULEBASES else []

    def read_one(session, query, **kw):
        if query is fw._ZONE_OF_INTERFACE:
            return {"name": "GUEST"}
        return None

    monkeypatch.setattr(_path, "_read", read)
    monkeypatch.setattr(_path, "_read_one", read_one)
    return rows


def _credited(src, dst):
    considered: list[str] = []
    verdict = fw._firewall_verdict_local(
        None,
        "dev",
        None,
        _ivals(src),
        _ivals(dst),
        22,
        "tcp",
        chain="input",
        in_if="if:eth1.20",
        considered=considered,
    )
    return verdict, set(considered)


def test_the_local_zone_pair_bound_for_the_other_family_stays_uncredited(zone_rows):
    zone_rows[:] = [*_BASE, _GUEST_LOCAL_V4]

    verdict, credited = _credited("2001:db8::5/128", "2001:db8::1/128")

    assert verdict is None
    assert "fw:GUEST-LOCAL" not in credited
    assert credited == {"fw:LAN-WAN", "fw:GUEST-WAN"}


def test_the_local_zone_pair_bound_for_the_flows_family_stays_uncredited(zone_rows):
    zone_rows[:] = [*_BASE, _GUEST_LOCAL_V4]

    verdict, credited = _credited("10.0.2.5/32", "10.0.2.1/32")

    assert verdict is None
    assert credited == {"fw:LAN-WAN", "fw:GUEST-WAN"}


def test_the_forward_path_credits_the_other_family_rule_set(zone_rows):
    zone_rows[:] = [*_BASE, _GUEST_LOCAL_V4]

    uids = fw._other_zone_pair_rulebases(None, "dev", ("GUEST", "LOCAL"), 6)

    assert "fw:GUEST-LOCAL" in uids


def test_no_query_reads_contains_from_an_interface():
    """The collector writes (Zone)-[:CONTAINS]->(Interface)."""
    import re

    text = "\n".join(
        v for k, v in vars(fw).items() if isinstance(v, str) and "CONTAINS" in v and "MATCH" in v
    )
    assert "_retired_at" in text
    out_of_interface = re.findall(r"\([^()]*Interface[^()]*\)\s*-\[[^\]]*CONTAINS[^\]]*\]->", text)
    into_interface_reversed = re.findall(r"<-\[[^\]]*CONTAINS[^\]]*\]-\s*\([^()]*Interface[^()]*\)", text)
    assert out_of_interface == [] and into_interface_reversed == []
    assert "MATCH (dst)-[cc:CONTAINS]->(:Interface)" in fw._DEVICE_ZONE_RULEBASES
