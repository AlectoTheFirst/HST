"""The side-store hits of the typed search (core/search.py `side_rows`,
`side_group`): ARP and MAC table rows for an address or a MAC, the routes for
an address or a prefix, the OSPF LSAs that hold a prefix, each read from the
run the snapshot selects, bounded in rows and time, and shaped as typed hits."""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("pyarrow")
pytest.importorskip("duckdb")

from tests.test_ribsource import _row

from hst.core import filters as F
from hst.core import neighborsource, ribsource, sidestore
from hst.core import search as S
from hst.core.snapshot import Snapshot

OLD, RUN, NEWER = 1000, 2000, 3000
R1, SW1 = "dev:r1", "dev:sw1"
MAC = "aa:bb:cc:00:00:07"
AREA_0 = "0.0.0.0"  # noqa: S104 - an OSPF area id
ANY = "0.0.0.0"  # noqa: S104 - the default prefix


def _arp(ip: str, mac: str, iface: str, device: str = R1, vrf: str = "blue") -> dict[str, Any]:
    return {
        "device_uid": device,
        "vrf": vrf,
        "context_uid": f"vrf:{device}:{vrf}",
        "ip": ip,
        "mac": mac,
        "interface_name": iface,
        "af": 4,
    }


def _mac(mac: str, port: str, vlan: int = 20, device: str = SW1) -> dict[str, Any]:
    return {
        "device_uid": device,
        "vlan": vlan,
        "mac": mac,
        "port_name": port,
        "bridge_domain_uid": f"bd:fab:{vlan}",
    }


def _lsa(lsa_type: str, lsid: str, mask: str | None = None, links: list | None = None) -> dict[str, Any]:
    return {
        "device_uid": R1,
        "context_uid": f"vrf:{R1}:default",
        "process": "1",
        "area": AREA_0,
        "lsa_type": lsa_type,
        "lsid": lsid,
        "adv_router": "10.255.0.1",
        "seq": 1,
        "age": 1,
        "metric": 20 if lsa_type != "router" else None,
        "links": links,
        "attached_routers": None,
        "mask": mask,
        "forwarding_address": None,
        "metric_type": None,
    }


@pytest.fixture
def store(tmp_path):
    # the older run of r1 holds an ARP row the current run no longer has
    sidestore.write_table(
        tmp_path, "arp", "nxos", "r1", f"{OLD}-aaaaaaaa", [_arp("10.1.2.99", "aa:bb:cc:00:00:99", "e9")], OLD
    )
    sidestore.write_table(
        tmp_path,
        "arp",
        "nxos",
        "r1",
        f"{RUN}-bbbbbbbb",
        [_arp("10.1.2.7", "AABB.CC00.0007", "Vlan20"), _arp("10.1.2.8", "aa:bb:cc:00:00:08", "Vlan20")],
        RUN,
    )
    # a run after the snapshot: never read for it
    sidestore.write_table(
        tmp_path,
        "arp",
        "nxos",
        "r1",
        f"{NEWER}-cccccccc",
        [_arp("10.1.2.7", "aa:bb:cc:00:00:77", "e7")],
        NEWER,
    )
    sidestore.write_table(
        tmp_path,
        "mac",
        "nxos",
        "sw1",
        f"{RUN}-dddddddd",
        [_mac("aabbcc000007", "Eth1/7"), _mac("aa:bb:cc:00:00:08", "Eth1/8")],
        RUN,
    )
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "r1",
        f"{RUN}-eeeeeeee",
        [
            _row("0.0.0.0/0", "10.0.0.1", "eth0"),
            _row("10.1.0.0/16", "10.0.0.2", "eth1", "ospf"),
            _row("10.1.2.0/24", "", "Vlan20", "direct"),
        ],
        RUN,
    )
    sidestore.write_table(
        tmp_path,
        "ospf_lsdb",
        "nxos",
        "r1",
        f"{RUN}-ffffffff",
        [
            _lsa(
                "router",
                "10.255.0.1",
                links=[
                    {"link_type": "stub", "link_id": "10.1.2.0", "link_data": "255.255.255.0", "metric": 1},
                    {
                        "link_type": "point-to-point",
                        "link_id": "10.255.0.2",
                        "link_data": "10.0.0.1",
                        "metric": 1,
                    },
                ],
            ),
            _lsa("summary", "10.1.0.0", "255.255.0.0"),
            _lsa("external", ANY, ANY),
            _lsa("network", "10.9.0.1", "255.255.255.0"),
        ],
        RUN,
    )
    return tmp_path


class _Settings:
    manifests_dir = None

    def __init__(self, path):
        self.sidestore_dir = path


def _snapshot(store, cts: int = RUN) -> Snapshot:
    return Snapshot(cts, _Settings(store))


def _rows(store, text: str, kinds=S.SIDE_KINDS) -> S.SideRows:
    return S.side_rows(_snapshot(store), S.detect(text), tuple(kinds))


def test_an_address_finds_its_arp_row_the_mac_table_port_its_route_and_its_lsas(store):
    found = _rows(store, "10.1.2.7")
    assert found.available and found.approximate
    assert [(r["ip"], r["interface_name"], r["run_id"]) for r in found.rows["arp"]] == [
        ("10.1.2.7", "Vlan20", f"{RUN}-bbbbbbbb")
    ]
    # the MAC the ARP row names, written in another notation, is found in the MAC table
    assert [(r["device_uid"], r["port_name"], r["vlan"]) for r in found.rows["mac"]] == [(SW1, "Eth1/7", 20)]
    assert [r["prefix"] for r in found.rows["route"]] == ["10.1.2.0/24"]
    lsas = [(r["lsa_type"], r["prefixlen"]) for r in found.rows["ospf_lsa"]]
    assert lsas == [("router", 24), ("summary", 16), ("external", 0)]


def test_a_mac_finds_its_arp_and_mac_table_rows_in_any_notation(store):
    found = _rows(store, "aabb.cc00.0007", ("arp", "mac"))
    assert [r["ip"] for r in found.rows["arp"]] == ["10.1.2.7"]
    assert [r["port_name"] for r in found.rows["mac"]] == ["Eth1/7"]


def test_a_prefix_finds_the_routes_for_it_and_the_lsas_inside_it(store):
    found = _rows(store, "10.1.0.0/16", ("route", "ospf_lsa", "arp"))
    assert [r["prefix"] for r in found.rows["route"]] == ["10.1.0.0/16"]
    assert sorted((r["lsa_type"], r["prefixlen"]) for r in found.rows["ospf_lsa"]) == [
        ("router", 24),
        ("summary", 16),
    ]
    assert "arp" not in found.rows, "a prefix is not looked up in the ARP tables"


def test_text_and_regex_do_not_read_the_side_store(store):
    for text in ("edge", "/edge.*/"):
        q = S.detect(text)
        assert q.mode in ("text", "regex")
        found = S.side_rows(_snapshot(store), q, S.SIDE_KINDS)
        assert found.rows == {}


def test_the_side_store_reads_the_run_the_snapshot_pins(store):
    old = S.side_rows(_snapshot(store, OLD), S.detect("10.1.2.99"), ("arp",))
    assert [r["mac"] for r in old.rows["arp"]] == ["aa:bb:cc:00:00:99"]
    # the current run no longer holds that row, and the newer run is past the bound
    assert S.side_rows(_snapshot(store), S.detect("10.1.2.99"), ("arp",)).rows["arp"] == []
    pinned = S.side_rows(_snapshot(store), S.detect("10.1.2.7"), ("arp",)).rows["arp"]
    assert [r["interface_name"] for r in pinned] == ["Vlan20"]
    newer = S.side_rows(_snapshot(store, NEWER), S.detect("10.1.2.7"), ("arp",)).rows["arp"]
    assert [r["interface_name"] for r in newer] == ["e7"]


def test_each_lookup_is_capped_in_rows(store, monkeypatch):
    monkeypatch.setattr(S, "SIDE_ROW_CAP", 1)
    found = _rows(store, "10.1.2.7", ("ospf_lsa",))
    assert len(found.rows["ospf_lsa"]) == 1 and found.capped == ["ospf_lsa"]
    group = S.side_group(
        "ospf_lsa",
        found.rows["ospf_lsa"],
        {},
        S.detect("10.1.2.7"),
        run=RUN,
        cursor=None,
        limit=10,
        exact=False,
    )
    assert group.count == 1 and not group.count_exact


def test_a_lookup_past_its_time_limit_answers_nothing_and_says_so(store, monkeypatch):
    class _Interrupted(Exception):
        pass

    _Interrupted.__name__ = "InterruptException"

    def slow(self, *args, **kwargs):
        raise _Interrupted("INTERRUPT Error: Interrupted!")

    monkeypatch.setattr(neighborsource.NeighborSource, "by_ip", slow)
    found = _rows(store, "10.1.2.7", ("arp", "route"))
    assert found.rows["arp"] == [] and found.timed_out == ["arp"]
    assert [r["prefix"] for r in found.rows["route"]] == ["10.1.2.0/24"]


def test_time_limit_interrupts_a_running_statement():
    import duckdb

    con = duckdb.connect()
    try:
        with pytest.raises(duckdb.InterruptException), ribsource.time_limit(con, 0.2):
            con.execute("SELECT count(*) FROM range(100000000000)").fetchall()
        assert con.execute("SELECT 1").fetchall() == [(1,)]
    finally:
        con.close()


def test_side_rows_become_typed_hits_naming_their_source_table(store):
    q = S.detect("10.1.2.7")
    found = S.side_rows(_snapshot(store), q, S.SIDE_KINDS)
    names = {R1: "edge-r1", SW1: "leaf-sw1"}
    arp = S.side_group("arp", found.rows["arp"], names, q, run=RUN, cursor=None, limit=10, exact=True).items[
        0
    ]
    assert arp["source"] == "arp" and arp["uid"] is None and arp["run"] == RUN
    assert arp["source_run"] == f"{RUN}-bbbbbbbb"
    assert arp["name"] == "10.1.2.7"
    assert arp["detail"] == "edge-r1 Vlan20 VRF blue aa:bb:cc:00:00:07"
    assert arp["target"] == {"kind": "device", "uid": R1}
    mac = S.side_group("mac", found.rows["mac"], names, q, run=RUN, cursor=None, limit=10, exact=True).items[
        0
    ]
    assert (mac["source"], mac["name"], mac["detail"]) == (
        "mac",
        "aa:bb:cc:00:00:07",
        "leaf-sw1 Eth1/7 VLAN 20",
    )
    assert mac["fields"]["segment_uid"] == "bd:fab:20"
    route = S.side_group(
        "route", found.rows["route"], names, q, run=RUN, cursor=None, limit=10, exact=True
    ).items[0]
    assert (route["source"], route["name"]) == ("rib", "10.1.2.0/24")
    assert route["detail"] == "edge-r1 VRF default Vlan20 direct"
    lsa = S.side_group(
        "ospf_lsa", found.rows["ospf_lsa"], names, q, run=RUN, cursor=None, limit=10, exact=True
    )
    assert [h["name"] for h in lsa.items] == ["10.1.2.0/24", "10.1.0.0/16", "0.0.0.0/0"]
    assert lsa.items[0]["source"] == "ospf_lsdb"
    assert lsa.items[0]["detail"] == "edge-r1 area 0.0.0.0 router LSA 10.255.0.1 from 10.255.0.1"


def test_side_hits_page_by_cursor(store):
    q = S.detect("10.1.2.7")
    rows = S.side_rows(_snapshot(store), q, ("ospf_lsa",)).rows["ospf_lsa"]
    first = S.side_group("ospf_lsa", rows, {}, q, run=RUN, cursor=None, limit=2, exact=True)
    assert [h["name"] for h in first.items] == ["10.1.2.0/24", "10.1.0.0/16"]
    assert first.count == 3 and first.count_exact and first.next_cursor is not None
    cursor = F.decode_cursor(first.next_cursor, kind="ospf_lsa", filter_print=q.fingerprint)
    assert cursor.run == RUN
    second = S.side_group("ospf_lsa", rows, {}, q, run=RUN, cursor=cursor, limit=2, exact=True)
    assert [h["name"] for h in second.items] == ["0.0.0.0/0"] and second.next_cursor is None


def test_without_a_store_the_side_store_answers_nothing(tmp_path):
    found = S.side_rows(_snapshot(tmp_path / "none"), S.detect("10.1.2.7"), S.SIDE_KINDS)
    assert not found.available
    assert all(rows == [] for rows in found.rows.values())
