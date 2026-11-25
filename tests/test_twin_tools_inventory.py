"""The inventory tools over fake graph sessions: search, get, list and resolve."""

from __future__ import annotations

import pytest
from tests.twin_tools_fakes import FakeGraph, call, context, install

from hst.app.ai.registry import Principal
from hst.twin_tools import inventory

# --- inventory_search ----------------------------------------------------------------------


def _search_rows(params):
    return [
        {"uid": "dev:core1", "label": "Device", "name": "core1", "detail": "router", "matched": "text"},
        {"uid": "dev:core2", "label": "Device", "name": "core2", "detail": "router", "matched": "text"},
    ]


def test_inventory_search_reads_the_selected_run_and_marks_carried_records(monkeypatch):
    graph = install(
        monkeypatch,
        FakeGraph(
            [
                ("obj_names", _search_rows),
                ("coalesce(n.carried, false) AS carried", [{"uid": "dev:core2", "carried": True}]),
            ]
        ),
    )

    failed, envelope = call("inventory_search", {"q": "core", "snapshot": "3000"})

    assert not failed
    items = envelope["result"]["items"]
    assert [(i["uid"], i["match"]) for i in items] == [("dev:core1", "text"), ("dev:core2", "text")]
    assert items[0]["evidence"]["result"]["word"] == "recorded in this run"
    assert (items[0]["evidence"]["result"]["kind"], items[0]["evidence"]["basis"]) == ("record", "observed")
    assert items[1]["evidence"]["basis"] == "configured"
    assert items[1]["evidence"]["result"]["word"] == "carried forward from an earlier run"
    assert envelope["evidence"]["result"]["word"] == "recorded in the snapshot"
    assert envelope["evidence"]["absence"] == "not_recorded"
    assert envelope["page"]["total"] == 2
    # every search query binds the selected run
    assert {params["snap"] for params in graph.reads("obj_names")} == {3000}


def test_inventory_search_with_no_match_establishes_nothing(monkeypatch):
    install(monkeypatch, FakeGraph())

    failed, envelope = call("inventory_search", {"q": "nothing-here"})

    assert not failed
    assert envelope["result"]["items"] == []
    assert envelope["evidence"]["result"]["word"] == "no record matches in the snapshot"
    assert envelope["evidence"]["absence"] == "not_recorded"


def test_inventory_search_refuses_an_unknown_label_before_any_read(monkeypatch):
    graph = install(monkeypatch, FakeGraph())

    failed, error = call("inventory_search", {"q": "core", "label": "NotALabel"})

    assert failed and error["error"]["code"] == "invalid_argument"
    assert error["error"]["field"] == "label"
    assert graph.calls == []


# --- inventory_get: device -----------------------------------------------------------------

_DEVICE_ROW = {
    "uid": "dev:core1",
    "hostname": "core1",
    "role": "router",
    "vendor": "cisco",
    "platform": "iosxe",
    "serial": "FOC1",
    "carried": False,
    "sites": [{"uid": "site:fra1", "code": "FRA1"}],
    "groups": ["rgrp:vpc:lab:1"],
    "interface_count": 12,
    "vrfs": [
        {"uid": "vrf:core1:blue", "name": "blue"},
        {"uid": "vrf:core1:blue", "name": "blue"},
        {"uid": "vrf:core1:default", "name": "default"},
    ],
}


def _device_graph(**kwargs):
    known = kwargs.get("known", {"dev:core1"})
    return FakeGraph(
        [
            (
                "MATCH (d:Device:Obj {uid: $uid, collection_ts: $snap})",
                lambda p: [_DEVICE_ROW] if p["uid"] in known else [],
            ),
            ("toLower(d.hostname) = toLower($name)", kwargs.get("exact", [])),
            ("STARTS WITH toLower($name)", kwargs.get("prefix", [])),
            ("coalesce(n.carried, false) AS carried", kwargs.get("uids", [])),
        ]
    )


def test_inventory_get_reads_a_device_by_hostname(monkeypatch):
    graph = install(monkeypatch, _device_graph(exact=[{"uid": "dev:core1", "hostname": "core1"}]))

    failed, envelope = call("inventory_get", {"kind": "device", "device": "core1"})

    assert not failed
    device = envelope["result"]["device"]
    assert device["uid"] == "dev:core1"
    assert device["site"] == "FRA1" and device["site_uid"] == "site:fra1"
    assert device["redundancy_groups"] == ["rgrp:vpc:lab:1"]
    assert [v["uid"] for v in device["vrfs"]] == ["vrf:core1:blue", "vrf:core1:default"]
    assert device["collection"] is None
    assert device["evidence"]["result"]["word"] == "recorded in this run"
    assert graph.reads("d.serial AS serial")[0]["uid"] == "dev:core1"


def test_inventory_get_takes_a_device_uid_as_given(monkeypatch):
    install(monkeypatch, _device_graph(uids=[{"uid": "dev:core1", "carried": True}]))

    failed, envelope = call("inventory_get", {"kind": "device", "device": "dev:core1"})

    assert not failed and envelope["result"]["device"]["uid"] == "dev:core1"


def test_an_ambiguous_hostname_lists_the_candidates(monkeypatch):
    matches = [{"uid": f"dev:core{i}", "hostname": f"core{i}"} for i in range(1, 4)]
    graph = install(monkeypatch, _device_graph(prefix=matches))

    failed, error = call("inventory_get", {"kind": "device", "device": "core"})

    assert failed and error["error"]["code"] == "ambiguous"
    assert error["error"]["candidates"] == matches
    assert not graph.reads("d.serial AS serial")


def test_an_unknown_device_is_not_found(monkeypatch):
    install(monkeypatch, _device_graph())

    failed, error = call("inventory_get", {"kind": "device", "device": "nowhere"})

    assert failed and error["error"]["code"] == "not_found"


def test_include_collection_needs_runs_manage(monkeypatch):
    graph = install(monkeypatch, _device_graph())

    failed, error = call(
        "inventory_get", {"kind": "device", "device": "dev:core1", "include_collection": True}
    )

    assert failed and error["error"]["code"] == "permission_denied"
    assert error["error"]["field"] == "include_collection"
    assert graph.session_kwargs == []


def test_include_collection_adds_the_collection_state_for_runs_manage(monkeypatch):
    install(monkeypatch, _device_graph(uids=[{"uid": "dev:core1", "carried": False}]))
    seen = []

    async def collection(ctx, graph_uid):
        seen.append(graph_uid)
        return [{"target_id": "t1", "enabled": True}]

    monkeypatch.setattr(inventory, "_collection", collection)

    failed, envelope = call(
        "inventory_get",
        {"kind": "device", "device": "dev:core1", "include_collection": True},
        context(Principal.local(store=True)),
    )

    assert not failed
    assert envelope["result"]["device"]["collection"] == [{"target_id": "t1", "enabled": True}]
    assert seen == ["dev:core1"]


# --- inventory_get: site -------------------------------------------------------------------


def test_inventory_get_reads_one_site_with_its_devices_and_prefixes(monkeypatch):
    members = [{"uid": f"dev:s{i}"} for i in range(3)]
    graph = install(
        monkeypatch,
        FakeGraph(
            [
                (
                    "MATCH (s:Site:Obj {uid: $uid})",
                    [
                        {
                            "uid": "site:fra1",
                            "code": "FRA1",
                            "name": "Frankfurt",
                            "kind": "dc",
                            "carried": False,
                        }
                    ],
                ),
                ("-[l:LOCATED_IN]->(s:Site:Obj {uid: $uid, collection_ts: $snap})", members),
                (
                    "RETURN d.uid AS uid, d.hostname AS hostname",
                    lambda p: [{"uid": u, "hostname": u[4:], "platform": "vyos"} for u in p["uids"]],
                ),
                ("p.kind = 'connected'", [{"cidr": "10.1.0.0/24"}, {"cidr": "10.2.0.0/24"}]),
            ]
        ),
    )

    failed, envelope = call("inventory_get", {"kind": "site", "code": "FRA1", "limit": 2})

    assert not failed
    (site,) = envelope["result"]["sites"]
    assert site["code"] == "FRA1" and site["device_count"] == 3
    assert [d["uid"] for d in site["devices"]] == ["dev:s0", "dev:s1"]
    assert site["devices"][0]["hostname"] == "s0"
    assert site["connected_prefixes"] == ["10.1.0.0/24", "10.2.0.0/24"]
    assert envelope["page"]["truncated"] is True
    # the shared site helpers read the selected run
    assert graph.reads("p.kind = 'connected'")[0] == {"site": "site:fra1", "snap": 4000}
    assert graph.reads("RETURN d.uid AS uid, d.hostname AS hostname")[0]["snap"] == 4000


def test_inventory_get_bounds_a_site_page_by_its_device_rows(monkeypatch):
    members = [{"uid": f"dev:s{i}"} for i in range(3)]
    install(
        monkeypatch,
        FakeGraph(
            [
                (
                    "MATCH (s:Site:Obj {uid: $uid})",
                    [{"uid": "site:fra1", "code": "FRA1", "name": None, "kind": "dc", "carried": False}],
                ),
                ("-[l:LOCATED_IN]->(s:Site:Obj {uid: $uid, collection_ts: $snap})", members),
                (
                    "RETURN d.uid AS uid, d.hostname AS hostname",
                    # two such rows pass the 256 KiB page budget
                    lambda p: [{"uid": u, "hostname": u[4:], "platform": "x" * 200_000} for u in p["uids"]],
                ),
            ]
        ),
    )

    failed, first = call("inventory_get", {"kind": "site", "code": "FRA1"})
    cursor = first["page"]["next_cursor"]
    _, second = call("inventory_get", {"kind": "site", "code": "FRA1", "cursor": cursor})

    assert not failed, first
    (site,) = first["result"]["sites"]
    assert site["device_count"] == 3
    assert [d["uid"] for d in site["devices"]] == ["dev:s0"]
    assert first["page"]["truncated"] is True and cursor is not None
    assert [d["uid"] for d in second["result"]["sites"][0]["devices"]] == ["dev:s1"]


def test_inventory_get_without_a_code_lists_the_sites(monkeypatch):
    rows = [
        {"uid": "site:fra1", "code": "FRA1", "name": None, "kind": "dc", "carried": False, "device_count": 4},
        {
            "uid": "site:ham1",
            "code": "HAM1",
            "name": None,
            "kind": "office",
            "carried": True,
            "device_count": 1,
        },
    ]
    install(monkeypatch, FakeGraph([("MATCH (s:Site:Obj)\n", rows)]))

    failed, envelope = call("inventory_get", {"kind": "site"})

    assert not failed
    assert [s["code"] for s in envelope["result"]["sites"]] == ["FRA1", "HAM1"]
    assert envelope["result"]["sites"][1]["evidence"]["basis"] == "configured"


def test_an_unknown_site_is_not_found(monkeypatch):
    install(monkeypatch, FakeGraph())

    failed, error = call("inventory_get", {"kind": "site", "code": "NOPE"})

    assert failed and error["error"]["code"] == "not_found" and error["error"]["field"] == "code"


# --- inventory_list ------------------------------------------------------------------------


def test_inventory_list_interfaces_of_one_device(monkeypatch):
    rows = [
        {
            "uid": "if:core1:ge0",
            "name": "ge0",
            "kind": "phys",
            "mtu": 1500,
            "oper_status": "up",
            "vrf_uid": "vrf:core1:blue",
            "vrf": "blue",
            "zones": ["zone:fw:inside"],
            "addresses": [{"ip": f"10.0.0.{i}", "prefix": "10.0.0.0/24"} for i in range(60)],
            "carried": False,
        }
    ]
    graph = install(
        monkeypatch,
        FakeGraph(
            [
                ("(i:Interface)-[o:ON]->(d:Device:Obj {uid: $device, collection_ts: $snap})", rows),
                ("MATCH (d:Device:Obj {uid: $uid, collection_ts: $snap})", [{"uid": "dev:core1"}]),
            ]
        ),
    )

    failed, envelope = call("inventory_list", {"kind": "interfaces", "device": "dev:core1", "vrf": "blue"})

    assert not failed
    (item,) = envelope["result"]["items"]
    assert envelope["result"]["device_uid"] == "dev:core1"
    assert len(item["addresses"]) == 50 and item["addresses_truncated"] is True
    params = graph.reads("(i:Interface)-[o:ON]->(d:Device:Obj {uid: $device, collection_ts: $snap})")[0]
    assert params == {"device": "dev:core1", "name": None, "vrf": "blue", "snap": 4000}


def test_inventory_list_zones_with_filters(monkeypatch):
    rows = [
        {
            "uid": "zone:fw:inside",
            "name": "inside",
            "owner_device": "dev:fw",
            "owners": ["dev:fw"],
            "default_action": "drop",
            "default_action_unknown": False,
            "interfaces": ["if:fw:eth1"],
            "rulebases": [{"uid": "rb:fw:main", "side": "from"}],
            "carried": False,
        }
    ]
    graph = install(monkeypatch, FakeGraph([("MATCH (z:Zone:Obj)", rows)]))

    failed, envelope = call("inventory_list", {"kind": "zones", "rulebase": "rb:fw:main"})

    assert not failed
    assert envelope["result"]["items"][0]["rulebases"] == [{"uid": "rb:fw:main", "side": "from"}]
    assert any("local zone" in text for text in envelope["evidence"]["unknowns"])
    assert graph.reads("MATCH (z:Zone:Obj)")[0] == {
        "device": None,
        "interface": None,
        "rulebase": "rb:fw:main",
        "name": None,
        "snap": 4000,
    }


# --- inventory_resolve ---------------------------------------------------------------------


def test_inventory_resolve_context_names_the_ambiguity(monkeypatch):
    rows = [
        {
            "uid": "vrf:a:CORP",
            "name": "CORP",
            "table_id": "CORP",
            "is_global": False,
            "rd": None,
            "domains": [],
            "devices": ["dev:a"],
        },
        {
            "uid": "vrf:b:CORP",
            "name": "CORP",
            "table_id": 7,
            "is_global": False,
            "rd": None,
            "domains": [],
            "devices": ["dev:b"],
        },
    ]
    graph = install(monkeypatch, FakeGraph([("toLower(v.name) = toLower($name)", rows)]))

    failed, envelope = call("inventory_resolve", {"kind": "context", "name": "corp", "snapshot": "3000"})

    assert not failed
    assert [i["uid"] for i in envelope["result"]["items"]] == ["vrf:a:CORP", "vrf:b:CORP"]
    assert envelope["evidence"]["unknowns"] == ["the name matches 2 contexts; choose one by uid"]
    assert graph.reads("toLower(v.name) = toLower($name)")[0] == {
        "name": "corp",
        "domain": None,
        "snap": 3000,
    }


def test_inventory_resolve_address_reports_every_section_with_evidence(monkeypatch):
    nodes = [
        {"uid": f"ip:site{i}:10.0.0.1", "anchor": f"site{i}", "l3dom": f"site{i}", "af": 4} for i in range(11)
    ]
    routes = [
        {
            "kind": "LEARNED_ROUTE",
            "prefix": "10.9.0.0/16",
            "prefix_uid": "pfx:x",
            "protocol": "bgp",
            "metric": 20,
            "interface": "eth0",
            "vrf_uid": "vrf:r1:default",
            "vrf_name": "default",
        }
    ]
    graph = install(
        monkeypatch,
        FakeGraph(
            [
                ("MATCH (n:IpAddress:Obj)", nodes),
                ("LEARNED_ROUTE|STATIC_ROUTE", routes),
                ("coalesce(n.carried, false) AS carried", [{"uid": "vrf:r1:default", "carried": True}]),
            ]
        ),
    )

    failed, envelope = call("inventory_resolve", {"kind": "address", "address": " 10.0.0.1 "})

    assert not failed
    sections = envelope["result"]["sections"]
    assert list(sections) == ["ip_nodes", "endpoints", "interfaces", "bgp_sessions", "next_hop_routes"]
    assert len(sections["ip_nodes"]["rows"]) == 10 and sections["ip_nodes"]["truncated"] is True
    assert sections["endpoints"] == {"rows": [], "truncated": False}
    assert sections["next_hop_routes"]["rows"][0]["evidence"]["basis"] == "configured"
    assert {params["ip"] for params in graph.reads("$ip")} == {"10.0.0.1"}


def test_inventory_resolve_refuses_a_value_that_is_not_an_address(monkeypatch):
    graph = install(monkeypatch, FakeGraph())

    failed, error = call("inventory_resolve", {"kind": "address", "address": "leaf101"})

    assert failed and error["error"]["code"] == "invalid_argument"
    assert graph.session_kwargs == []


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("inventory_get", {"kind": "device", "device": "dev:core1"}),
        ("inventory_list", {"kind": "zones"}),
        ("inventory_resolve", {"kind": "context", "name": "CORP"}),
    ],
)
def test_every_inventory_read_opens_a_read_session(monkeypatch, name, arguments):
    graph = install(monkeypatch, _device_graph(uids=[{"uid": "dev:core1", "carried": False}]))

    call(name, arguments)

    assert graph.session_kwargs and all(kw == {"access_mode": "READ"} for kw in graph.session_kwargs)


def test_the_site_list_counts_only_the_devices_of_the_run_it_reads():
    """The site list counts only the device copies of the selected run."""
    query = inventory._SITES_QUERY
    assert "d.collection_ts = $snap" in query
    assert "d.collection_ts = $snap" in inventory._SITE_MEMBERS_QUERY
