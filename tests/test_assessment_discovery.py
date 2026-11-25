"""Named choices preserve identity, complete requests and reviewed snapshot scope."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from hst import path
from hst.assessment import discovery
from hst.assessment import evaluation as ev


@pytest.fixture
def graph(monkeypatch):
    data = {"objects": [], "owners": [], "details": [], "reads": []}

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
            if params["uid"]:
                values = [r for r in values if r["uid"] == params["uid"]]
            return values[: params["limit"]]
        if query == discovery._OWNERS:
            return data["owners"]
        if query == discovery._DETAILS:
            return data["details"]
        if query == ev._REQUIREMENT_QUERY:
            return data.get("requirements", [])
        if query == ev._GROUP_QUERY:
            return [g for g in data.get("groups", []) if g["uid"] in params["uids"]]
        raise AssertionError(query)

    monkeypatch.setattr(path, "_read", read)
    return data


def obj(uid, label="Device", name="Frankfurt", **values):
    return {"uid": uid, "name": name, "labels": ["Obj", label], **values}


def test_same_named_devices_remain_distinct_and_every_read_is_pinned(graph):
    graph["objects"] = [obj("router:a"), obj("router:b")]
    graph["owners"] = [
        {"uid": uid, "devices": [{"uid": uid, "name": "Frankfurt", "site": site}]}
        for uid, site in [("router:a", "East"), ("router:b", "West")]
    ]
    found = discovery.search_options(None, "300", "device", q="Frankfurt")
    assert [item["uid"] for item in found["items"]] == ["router:a", "router:b"]
    assert [item["site"] for item in found["items"]] == ["East", "West"]
    assert {read[0] for read in graph["reads"]} == {300}
    assert found["snapshot"] == "300"
    assert not found["truncated"]
    exact = discovery.search_options(None, "200", "device", uid="router:b")
    assert [item["uid"] for item in exact["items"]] == ["router:b"]
    assert graph["reads"][-1][0] == 200


def test_owner_absence_and_shared_ownership_are_explicit(graph):
    graph["objects"] = [obj("rules:shared", "FwRulebase"), obj("rules:unknown", "FwRulebase")]
    graph["owners"] = [
        {
            "uid": "rules:shared",
            "devices": [{"uid": "fw:a", "name": "Firewall A"}, {"uid": "fw:b", "name": "Firewall B"}],
        }
    ]
    shared, absent = discovery.search_options(None, "300", "rulebase")["items"]
    assert shared["selectable"]
    assert "device" not in shared
    assert len(shared["devices"]) == 2
    assert not absent["selectable"]
    assert "owner" in absent["disabled_reason"]


def test_link_endpoints_are_exact_and_unsupported_address_endpoint_disables(graph):
    graph["objects"] = [obj("link:a", "WanLink"), obj("tunnel:b", "Tunnel")]
    graph["details"] = [
        {
            "uid": "link:a",
            "endpoints": [{"uid": "if:a", "labels": ["Interface"]}, {"uid": "if:b", "labels": ["Interface"]}],
        },
        {
            "uid": "tunnel:b",
            "endpoints": [{"uid": "if:c", "labels": ["Interface"]}, {"uid": "ip:d", "labels": ["IpAddress"]}],
        },
    ]
    link, tunnel = discovery.search_options(None, "300", "link,tunnel")["items"]
    assert link["interfaces"] == ["if:a", "if:b"]
    assert link["selectable"]
    assert not tunnel["selectable"]
    assert "all recorded endpoints" in tunnel["disabled_reason"]


def test_domains_show_recorded_members_and_do_not_claim_validated_provenance(graph):
    graph["objects"] = [
        obj(
            "domain:power",
            "FailureDomain",
            source="inventory",
            origin="observed",
            collector="inventory",
            evidence_reference="record.json",
            valid_from_ms=100,
            valid_until_ms=400,
        )
    ]
    graph["details"] = [
        {
            "uid": "domain:power",
            "members": [
                {"uid": "device:a", "name": "Firewall", "labels": ["Device"]},
                {"uid": "domain:rack", "name": "Rack", "labels": ["FailureDomain"]},
            ],
        }
    ]
    item = discovery.search_options(None, "300", "domain")["items"][0]
    assert item["members"] == [
        {"uid": "device:a", "name": "Firewall", "kind": "device"},
        {"uid": "domain:rack", "name": "Rack", "kind": "domain"},
    ]
    assert item["evidence_refs"] == ["record.json"]
    assert item["valid_until_ms"] == 400
    assert item["evidence_status"] == "observed"
    assert item["provenance_validated"] is False


def test_truncated_membership_is_not_selectable(graph):
    graph["objects"] = [obj("domain:large", "FailureDomain", source="inventory")]
    graph["details"] = [
        {"uid": "domain:large", "member_count": 101, "members": [{"uid": "device:a", "labels": ["Device"]}]}
    ]
    result = discovery.search_options(None, "300", "domain")
    assert not result["items"][0]["selectable"]
    assert "partial scope" in result["items"][0]["disabled_reason"]


def test_service_selection_preserves_complete_flow_and_condition(graph):
    graph["objects"] = [obj("service:pay", "ServiceRequirement", name="Payments")]
    graph["requirements"] = [
        {
            "uid": "service:pay",
            "name": "Payments",
            "destination": "Payment processors",
            "roots": ["group:pay"],
            "sources": ["10.0.0.0/24"],
            "proto": "tcp",
            "dport": "443",
            "sport": "1024-65535",
            "success": "session",
            "source_context": "vrf:secure",
            "source_device_uid": "fw:a",
            "identity_uid": None,
            "segment_uid": None,
        }
    ]
    graph["groups"] = [
        {
            "uid": "group:pay",
            "kind": "threshold",
            "n": 1,
            "groups": [],
            "members": [
                {"uid": "backend:a", "address": "192.0.2.1"},
                {"uid": "backend:b", "address": "192.0.2.2"},
            ],
        }
    ]
    item = discovery.search_options(None, "300", "service")["items"][0]
    assert item["selectable"], item
    req = item["definition"]
    assert req["sources"] == ["10.0.0.0/24"]
    assert req["proto"] == "6"
    assert req["port"] == "443"
    assert req["source_port"] == "1024-65535"
    assert req["source_context"] == "vrf:secure"
    assert req["source_device_uid"] == "fw:a"
    assert req["success"] == "session"
    assert req["condition"]["kind"] == "threshold"
    assert req["condition"]["n"] == 1
    assert len(req["condition"]["parts"]) == 2
    assert {m["name"] for m in req["members"]} == {"backend:a", "backend:b"}
    parsed = ev._request_from_body(ev.RequestBody.model_validate(req))
    assert parsed == ev._request_from_requirement(SimpleNamespace(cts=300), "service:pay")


def test_incomplete_service_disabled_without_fabricated_request(graph):
    graph["objects"] = [obj("service:missing", "ServiceRequirement")]
    graph["requirements"] = [{"uid": "service:missing", "roots": []}]
    item = discovery.search_options(None, "300", "service")["items"][0]
    assert not item["selectable"]
    assert "no dependency group" in item["disabled_reason"]
    assert "definition" not in item


def test_suggestions_are_snapshot_matched_and_estate_reads_do_not_select_everything(graph):
    graph["objects"] = [obj("device:a"), obj("device:b"), obj("device:c")]
    deps = [
        {"kind": "graph-object", "uid": "device:a", "snapshot": "300"},
        {"kind": "graph-object", "uid": "device:b", "snapshot": "200"},
        {"kind": "estate", "snapshot": "300"},
    ]
    items = discovery.search_options(None, "300", "device", dependencies=deps)["items"]
    assert [item["suggested"] for item in items] == [True, False, False]
    assert "review relevance" in items[0]["suggestion_reason"]


def test_search_bound_is_explicit(graph):
    graph["objects"] = [obj("device:a"), obj("device:b")]
    result = discovery.search_options(None, "300", "device", limit=1)
    assert result["truncated"]
    assert len(result["items"]) == 1


@pytest.mark.parametrize(
    "args",
    [
        {"snapshot": "latest"},
        {"snapshot": "0"},
        {"snapshot": "-3"},
        {"snapshot": "300", "kind": "Device) RETURN secret"},
        {"snapshot": "300", "limit": 101},
        {"snapshot": "300", "q": "x" * 201},
    ],
)
def test_invalid_scope_rejected_before_any_read(graph, args):
    with pytest.raises(ValueError):
        discovery.search_options(None, **args)
    assert graph["reads"] == []


def test_unpublished_snapshot_refusal_is_not_converted_to_empty_inventory(graph, monkeypatch):
    def absent(settings, value):
        raise ValueError("A published snapshot with an evidence manifest is required.")

    monkeypatch.setattr(discovery.service, "snapshot_reference", absent)
    with pytest.raises(ValueError, match="published snapshot"):
        discovery.search_options(None, "300", "device")
    assert graph["reads"] == []
