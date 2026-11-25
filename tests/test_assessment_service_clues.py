from types import SimpleNamespace

import pytest

from hst import path
from hst.assessment import service_discovery as sd
from hst.assessment import traffic_discovery as td


def candidate(uid, *, destination="192.0.2.8", sources=None, location="Frankfurt", name="Payments"):
    return {
        "uid": uid,
        "name": name,
        "kind": "service",
        "origin": "graph",
        "selectable": True,
        "locations": [location],
        "applications": ["Checkout"],
        "definition": {
            "name": name,
            "destination": "Payment API",
            "sources": sources or ["10.20.0.0/24"],
            "members": [{"name": "api", "addresses": [destination]}],
            "condition": {"kind": "member", "member": "api"},
            "proto": "6",
            "port": "443",
            "source_port": "1024-65535",
            "success": "session",
            "source_context": "vrf:clients",
            "source_device_uid": None,
        },
    }


@pytest.fixture
def reads(monkeypatch):
    values = {"dns": [], "hosts": [], "addresses": [], "saved": [], "calls": []}

    def read(session, query, **params):
        assert session.cts == 300
        values["calls"].append((query, params))
        if query == sd._DNS:
            return values["dns"]
        if query == sd._HOSTS:
            return values["hosts"]
        if query == sd._SAVED_CONTEXTS:
            return values["saved"]
        if query == td._ADDRESSES:
            return [row for row in values["addresses"] if row["uid"] > params["after"]][: params["limit"]]
        raise AssertionError(query)

    monkeypatch.setattr(path, "_read", read)
    return values


def scan(rows, **kwargs):
    def read_page(after, count):
        remaining = [row for row in rows if after is None or row["uid"] > after]
        items = remaining[:count]
        return {
            "items": items,
            "truncated": len(remaining) > count,
            "cursor": items[-1]["uid"] if items else None,
        }

    return sd.scan_services(SimpleNamespace(cts=300), read_page=read_page, **kwargs)


def test_matches_past_first_page_and_preserves_exact_service(reads):
    rows = [candidate(f"service:{i:03}", destination="198.51.100.1") for i in range(155)]
    wanted = candidate("service:155")
    rows.append(wanted)
    result = scan(
        rows, destination="192.0.2.8", client="10.20.0.23", location="Frankfurt", application="Checkout"
    )
    assert result["scanned"] == 156
    assert result["catalog_complete"]
    assert [item["uid"] for item in result["items"]] == ["service:155"]
    assert result["items"][0]["definition"] == wanted["definition"]
    assert len(result["items"][0]["match_reasons"]) == 4


def test_url_host_uses_recorded_dns_explicit_port_only_and_never_fetches(reads):
    reads["dns"] = [{"uid": "dns:checkout", "type": "A", "values": ["192.0.2.8"], "addresses": []}]
    result = scan([candidate("service:a")], destination="https://checkout.example:443/pay?ref=1")
    assert result["items"][0]["uid"] == "service:a"
    assert any("URL paths" in q for q in result["questions"])
    assert result["traffic_options"][0]["uid"] == "dns:checkout"
    assert result["traffic_options"][0]["addresses"] == ["192.0.2.8/32"]
    assert reads["calls"][0][1] == {"hostname": "checkout.example"}
    assert not scan([candidate("service:a")], destination="https://checkout.example:8443")["items"]
    other = candidate("service:b")
    other["definition"]["port"] = "8443"
    assert scan([other], destination="https://checkout.example")["items"]  # No inferred scheme port.


def test_missing_dns_does_not_match_a_similar_service_name(reads):
    result = scan([candidate("service:a", name="missing.example")], destination="https://missing.example")
    assert not result["items"]
    assert not result["traffic_options"]
    assert any("No recorded address evidence" in q for q in result["questions"])


def test_cidr_and_ipv6_clues_use_overlap_without_changing_definition(reads):
    item = candidate("service:ipv6", destination="2001:db8:20::8", sources=["2001:db8:10::/64"])
    result = scan([item], destination="2001:db8:20::/64", client="2001:db8:10::1")
    assert result["items"][0]["definition"] == item["definition"]
    assert not scan([item], destination="2001:db8:21::/64")["items"]


def test_browse_facets_are_complete_before_filtered_page_and_duplicate_names_stay_distinct(reads):
    rows = [candidate("service:a", location="Frankfurt"), candidate("service:b", location="London")]
    result = scan(rows, limit=1)
    assert result["facets"] == {"locations": ["Frankfurt", "London"], "applications": ["Checkout"]}
    assert result["matched_count"] == 2
    assert result["truncated"]
    assert result["catalog_complete"]
    assert scan(rows, location="London")["items"][0]["uid"] == "service:b"


def test_catalog_bound_never_reports_complete_or_definite_absence(reads, monkeypatch):
    monkeypatch.setattr(sd, "MAX_SERVICES", 2)
    rows = [candidate("service:a"), candidate("service:b"), candidate("service:c", destination="203.0.113.8")]
    result = scan(rows, destination="203.0.113.8")
    assert not result["catalog_complete"]
    assert result["truncated"]
    assert result["scanned"] == 2
    assert any("missing match does not establish" in q for q in result["questions"])


def test_time_and_byte_bounds_are_explicit(reads, monkeypatch):
    monkeypatch.setattr(sd, "MAX_BYTES", 1)
    result = scan([candidate("service:a")])
    assert not result["catalog_complete"]
    monkeypatch.setattr(sd, "MAX_BYTES", 1_000_000)
    ticks = iter([0.0, 25.0])
    monkeypatch.setattr(sd.time, "monotonic", lambda: next(ticks))
    result = scan([candidate("service:a")])
    assert not result["catalog_complete"]
    assert result["scanned"] == 0


def test_saved_revisions_share_matcher_and_keep_revision_identity(reads):
    request = candidate("unused")["definition"]
    saved = [
        {"id": "saved:pay", "revision": 7, "title": "My payment service", "definition": {"request": request}}
    ]
    reads["saved"] = [{"uid": "saved:pay", "locations": ["Frankfurt"], "location_count": 1}]
    result = scan([], saved_requirements=saved, destination="192.0.2.8", location="Frankfurt")
    item = result["items"][0]
    assert item["origin"] == "saved"
    assert item["requirement_id"] == "saved:pay"
    assert item["requirement_revision"] == 7
    assert item["definition"]["source_port"] == "1024-65535"
    assert item["definition"]["source_context"] == "vrf:clients"


def test_no_authored_service_offers_explicit_recorded_source_and_dns_choices(reads):
    reads["dns"] = [{"uid": "dns:checkout", "type": "A", "values": ["192.0.2.8"]}]
    reads["addresses"] = [
        {
            "uid": "prefix:frankfurt",
            "name": "Office clients",
            "address": "10.20.0.0/24",
            "contexts": [
                {
                    "device_uid": "router:frankfurt",
                    "device_name": "Frankfurt gateway",
                    "context_uid": "vrf:clients",
                    "context_name": "Client VPN",
                    "site": "Frankfurt",
                }
            ],
        }
    ]
    result = scan([], destination="https://checkout.example", location="Frankfurt")
    assert result["items"] == []
    choices = result["traffic_options"]
    assert {item["role"] for item in choices} == {"client", "destination"}
    clients = next(item for item in choices if item["role"] == "client")
    assert clients["addresses"] == ["10.20.0.0/24"]
    assert clients["context"]["uid"] == "vrf:clients"
    assert "source_device_uid" not in clients  # A gateway is not a device-originated request.
    assert clients["selectable"]


def test_literal_client_scope_is_not_broadened_to_whole_site_prefix(reads):
    reads["addresses"] = [
        {"uid": "prefix:office", "name": "Office", "address": "10.20.0.0/24", "contexts": []}
    ]
    result = scan([], client="10.20.0.23")
    assert result["traffic_options"][0]["addresses"] == ["10.20.0.23/32"]


def test_ambiguous_vrf_address_choice_is_disabled(reads):
    reads["addresses"] = [
        {
            "uid": "prefix:shared",
            "name": "Shared address",
            "address": "10.20.0.0/24",
            "contexts": [
                {"device_uid": "device:a", "device_name": "A", "context_uid": "vrf:a", "context_name": "A"},
                {"device_uid": "device:b", "device_name": "B", "context_uid": "vrf:b", "context_name": "B"},
            ],
        }
    ]
    item = scan([], client="10.20.0.23")["traffic_options"][0]
    assert not item["selectable"]
    assert "multiple recorded forwarding contexts" in item["disabled_reason"]
    assert "context" not in item


@pytest.mark.parametrize(
    "destination", ["https://user:secret@example.com", "https://host:invalid", "https://"]
)
def test_invalid_or_credential_url_is_rejected(reads, destination):
    with pytest.raises(ValueError):
        scan([], destination=destination)
    assert reads["calls"] == []


def test_invalid_client_never_becomes_a_hostname_lookup(reads):
    with pytest.raises(ValueError, match="client IP"):
        scan([], client="my-laptop")
    assert reads["calls"] == []


def test_url_port_must_belong_to_the_matching_destination_member(reads):
    reads["dns"] = [{"uid": "dns:checkout", "type": "A", "values": ["192.0.2.8"]}]
    item = candidate("service:a")
    item["definition"]["members"] = [
        {"name": "first", "addresses": ["192.0.2.8"], "port": "80"},
        {"name": "second", "addresses": ["192.0.2.9"], "port": "443"},
    ]
    assert not scan([item], destination="https://checkout.example:443")["items"]
    assert scan([item], destination="http://checkout.example:80")["items"]


def test_dns_values_must_be_literal_addresses_not_networks(reads):
    reads["dns"] = [{"uid": "dns:bad", "type": "A", "values": ["192.0.2.0/24"]}]
    result = scan([candidate("service:a")], destination="bad.example")
    assert not result["items"]
    assert not result["traffic_options"]
    assert any("No recorded address evidence" in q for q in result["questions"])


def test_saved_definition_is_exact_original_dictionary_for_revision_binding(reads):
    request = candidate("unused")["definition"]
    request["proto"] = "tcp"
    request["sources"] = ["10.20.0.23"]
    request.pop("source_device_uid")
    saved = [{"id": "saved:exact", "revision": 8, "title": "Exact", "definition": {"request": request}}]
    item = scan([], saved_requirements=saved, destination="192.0.2.8")["items"][0]
    assert item["definition"] == request
    assert item["definition"] is not request
    assert item["definition"]["proto"] == "tcp"
    assert item["definition"]["sources"] == ["10.20.0.23"]
    assert "source_device_uid" not in item["definition"]


def test_default_and_named_vrf_are_not_collapsed_to_named_context(reads):
    reads["addresses"] = [
        {
            "uid": "prefix:shared",
            "name": "Shared address",
            "address": "10.20.0.0/24",
            "contexts": [
                {"device_uid": "device:a", "device_name": "A", "context_uid": "vrf:a", "context_name": "A"},
                {"device_uid": "device:b", "device_name": "B", "context_uid": None, "context_name": None},
            ],
        }
    ]
    item = scan([], client="10.20.0.23")["traffic_options"][0]
    assert not item["selectable"]


def test_recorded_address_choices_page_before_matching_and_disclose_bound(reads):
    reads["addresses"] = [
        {"uid": f"address:{i:03}", "name": f"Net {i}", "address": f"10.20.{i}.0/24", "contexts": []}
        for i in range(160)
    ]
    result = td.address_choices(
        SimpleNamespace(cts=300), destinations=[], client=sd.network("10.20.159.4"), location=""
    )
    assert result["items"][0]["uid"] == "address:159"
    assert result["scanned"] == 160
    assert result["complete"]
    capped = td.address_choices(
        SimpleNamespace(cts=300),
        destinations=[],
        client=sd.network("10.20.159.4"),
        location="",
        max_records=100,
    )
    assert not capped["items"]
    assert not capped["complete"]
    assert capped["truncated"]
