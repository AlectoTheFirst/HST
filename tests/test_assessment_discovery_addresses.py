"""A search of the address kinds ip and network, alone and with the object kinds."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from hst import path
from hst.assessment import discovery


@pytest.fixture
def graph(monkeypatch):
    data = {"objects": [], "addresses": [], "reads": []}

    @contextmanager
    def session(_settings):
        yield object()

    monkeypatch.setattr(discovery.db, "session", session)
    monkeypatch.setattr(discovery.service, "snapshot_reference", lambda settings, value: {"snapshot": value})
    monkeypatch.setattr(discovery.snapshotmod, "resolve", lambda raw, settings, cts: SimpleNamespace(cts=cts))

    def read(session, query, **params):
        data["reads"].append((session.cts, query, params))
        if query == discovery._OBJECTS:
            values = [r for r in data["objects"] if any(label in params["labels"] for label in r["labels"])]
            return values[: params["limit"]]
        if query == discovery._ADDRESS_OBJECTS:
            values = [r for r in data["addresses"] if any(label in params["labels"] for label in r["labels"])]
            if params["uid"]:
                values = [r for r in values if r["uid"] == params["uid"]]
            return values[: params["limit"]]
        if query in (discovery._OWNERS, discovery._DETAILS):
            return []
        raise AssertionError(query)

    monkeypatch.setattr(path, "_read", read)
    return data


def address(uid, label, value):
    return {"uid": uid, "name": value, "labels": ["Obj", label], "address": value}


def test_one_search_finds_devices_interfaces_ip_addresses_and_networks_with_their_kind(graph):
    graph["objects"] = [
        {"uid": "device:edge", "name": "edge-10", "labels": ["Obj", "Device"]},
        {"uid": "interface:edge:eth0", "name": "eth0", "labels": ["Obj", "Interface"]},
    ]
    graph["addresses"] = [
        address("ip:home:10.1.20.11", "IpAddress", "10.1.20.11"),
        address("prefix:home:10.1.20.0/24", "Prefix", "10.1.20.0/24"),
    ]
    found = discovery.search_options(None, "300", "device,interface,ip,network", q="10")
    assert [(item["name"], item["kind"]) for item in found["items"]] == [
        ("10.1.20.0/24", "network"),
        ("10.1.20.11", "ip"),
        ("edge-10", "device"),
        ("eth0", "interface"),
    ]
    assert found["items"][1]["addresses"] == ["10.1.20.11"]
    assert not found["truncated"]
    labels = {query: params["labels"] for _, query, params in graph["reads"] if "labels" in params}
    assert labels == {
        discovery._OBJECTS: ["Device", "Interface"],
        discovery._ADDRESS_OBJECTS: ["IpAddress", "Prefix"],
    }
    assert {read[0] for read in graph["reads"]} == {300}


def test_the_merged_search_is_bound_by_the_limit(graph):
    graph["objects"] = [{"uid": "device:a", "name": "a", "labels": ["Obj", "Device"]}]
    graph["addresses"] = [address("ip:home:10.0.0.1", "IpAddress", "10.0.0.1")]
    found = discovery.search_options(None, "300", "device,ip", limit=1)
    assert [item["uid"] for item in found["items"]] == ["ip:home:10.0.0.1"]
    assert found["truncated"]


def test_an_address_uid_resolves_without_the_object_read(graph):
    graph["addresses"] = [
        address("ip:home:10.0.0.1", "IpAddress", "10.0.0.1"),
        address("ip:home:10.0.0.2", "IpAddress", "10.0.0.2"),
    ]
    found = discovery.search_options(None, "300", "ip", uid="ip:home:10.0.0.2")
    assert [item["uid"] for item in found["items"]] == ["ip:home:10.0.0.2"]
    assert [query for _, query, _ in graph["reads"]] == [discovery._ADDRESS_OBJECTS]


def test_all_kinds_leave_the_address_kinds_out(graph):
    discovery.search_options(None, "300", "all")
    queries = [query for _, query, _ in graph["reads"]]
    assert queries[0] == discovery._OBJECTS
    assert discovery._ADDRESS_OBJECTS not in queries
    assert not {"IpAddress", "Prefix"} & set(graph["reads"][0][2]["labels"])


def test_an_unknown_kind_beside_an_address_kind_is_refused_before_any_read(graph):
    with pytest.raises(ValueError, match="ip, network"):
        discovery.search_options(None, "300", "ip,vip")
    assert graph["reads"] == []
