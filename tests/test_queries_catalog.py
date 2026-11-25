"""Catalog sanity: unique keys, params wired into the Cypher, scenarios included."""

import re
from pathlib import Path

from hst.queries import QUERIES, catalog


def test_keys_unique():
    entries = catalog()
    keys = [q["key"] for q in entries]
    assert len(keys) == len(set(keys))


def test_params_are_used_in_cypher():
    for q in QUERIES:
        for p in q.get("params", []):
            assert f"${p['name']}" in q["cypher"], f"{q['key']}: ${p['name']} unused"
    # app/tables.run_readonly binds $snap before every catalog query runs.
    for q in QUERIES:
        declared = {p["name"] for p in q.get("params", [])} | {"snap"}
        used = set(re.findall(r"\$(\w+)", q["cypher"]))
        assert used <= declared, f"{q['key']}: undeclared params {used - declared}"


def test_no_query_declares_snap_as_its_own_param():
    for q in QUERIES:
        assert "snap" not in {p["name"] for p in q.get("params", [])}, q["key"]


def test_find_ip_ignores_retired_edges():
    cypher = next(q for q in QUERIES if q["key"] == "find-ip")["cypher"]
    assert re.search(r"\[(\w+):IN\]->\(p:Prefix\) WHERE \1\._retired_at IS NULL", cypher)
    assert re.search(r"\[(\w+):HAS_IP\]->\(ip\) WHERE \1\._retired_at IS NULL", cypher)


def test_find_ip_returns_the_uplink_on_edges():
    cypher = next(q for q in QUERIES if q["key"] == "find-ip")["cypher"]
    assert "AS _uo" in cypher
    assert "AS _ro" in cypher


def test_scenarios_are_included():
    assert any(q["key"] == "scenario-derived-gateway" for q in catalog())


def test_scenarios_carry_real_groups_not_a_flat_bucket():
    entries = catalog()
    assert "scenarios" not in {q["group"] for q in entries}
    by_key = {q["key"]: q for q in entries}
    assert by_key["scenario-derived-gateway"]["group"] == "hygiene"
    assert by_key["scenario-zia-guest-egress"]["group"] == "zscaler"


def test_titles_are_short_enough_for_the_rail():
    for q in catalog():
        assert len(q["title"]) <= 28, f"{q['key']}: title too long for the rail ({q['title']!r})"


def test_scenario_entries_describe_what_they_traverse():
    for q in catalog():
        if q["key"].startswith("scenario-"):
            assert q.get("description"), f"{q['key']}: lost its path chain"


def test_superseded_scenarios_are_not_listed_twice():
    from hst.demo import SCENARIOS

    keys = {q["key"] for q in catalog()}
    assert "scenario-naming-hygiene" not in keys
    assert "scenario-cable-drift" not in keys
    assert {"naming-hygiene", "cable-drift"} <= {s["key"] for s in SCENARIOS}


def test_no_two_entries_share_the_same_cypher():
    seen: dict[str, str] = {}
    for q in catalog():
        body = re.sub(r"\s+", " ", q["cypher"]).strip()
        assert body not in seen, f"{q['key']} duplicates {seen.get(body)}"
        seen[body] = q["key"]


def test_run_readonly_stops_consuming_at_the_row_cap(monkeypatch):
    from contextlib import contextmanager

    from hst.app import tables
    from hst.core import Settings

    class Record:
        def __init__(self, i):
            self.i = i

        def data(self):
            return {"i": self.i}

    class Result:
        def __init__(self):
            self.consumed_rows = 0

        def __iter__(self):
            for i in range(1_000_000):
                self.consumed_rows += 1
                yield Record(i)

        def keys(self):
            return ["i"]

        def consume(self):
            return None

    result = Result()

    class Tx:
        def run(self, query, **params):
            return result

    class Session:
        def execute_read(self, work):
            return work(Tx())

    @contextmanager
    def fake_session(settings, **kwargs):
        yield Session()

    monkeypatch.setattr(tables.dbmod, "session", fake_session)
    out = tables.run_readonly(Settings(_env_file=None), "MATCH (n) RETURN n", {})
    assert len(out["data"]) == tables.MAX_ROWS
    assert out["truncated"] is True
    # run_readonly keeps one row past the cap to know the result overflowed, and
    # stops on the next one
    assert result.consumed_rows <= tables.MAX_ROWS + 2


async def test_mcp_server_builds_and_registers_every_tool():
    import pytest

    pytest.importorskip("mcp")
    from hst.mcp_server import build_server

    server = build_server()
    tools = {t.name: t for t in await server.list_tools()}
    assert set(tools) == {
        "snapshot_list",
        "snapshot_resolve",
        "snapshot_diff",
        "inventory_search",
        "inventory_get",
        "inventory_list",
        "inventory_resolve",
        "routing_routes",
        "routing_bgp",
        "routing_evaluate_policy",
        "routing_predict_routes",
        "policy_evaluate",
        "policy_lookup_nat",
        "lb_lookup_vip",
        "reach_trace",
        "reach_audit_mtu",
        "impact_evaluate_service",
        "impact_assess",
        "change_simulate",
        "change_get_simulation",
        "app_applications",
        "app_find_affected",
        "assessment_read",
        "evidence_get_gaps",
        "query_catalog",
        "query_run_named",
        "query_cypher",
    }
    assert all(t.description for t in tools.values())

    # the local principal with the app store is offered the same tools and the
    # runs.manage tool
    from hst.app.ai.registry import Principal

    with_store = await build_server(Principal.local(store=True)).list_tools()
    assert {t.name for t in with_store} == set(tools) | {"ops_list_collection_runs"}


def test_demo_only_scenarios_are_not_in_the_catalog():
    """A scenario that can only populate from the demo fixture never reaches the
    UI: the catalog lists queries over collected data only."""
    from hst.demo import SCENARIOS

    demo_only = {f"scenario-{sc['key']}" for sc in SCENARIOS if sc.get("fixture_only")}
    assert demo_only, "demo.py marks no scenario fixture_only any more; drop this test"
    keys = {q["key"] for q in catalog()}
    assert not demo_only & keys
    assert not any("fixture_only" in q for q in catalog())


def test_endpoints_ssids_not_collapsed_to_one():
    cypher = next(q for q in QUERIES if q["key"] == "endpoints")["cypher"]
    assert "collect(DISTINCT a.ssid) AS ssids" in cypher
    assert "head(collect(" not in cypher


def test_firewall_rules_surface_ranges_and_opacity():
    cypher = next(q for q in QUERIES if q["key"] == "firewall")["cypher"]
    for column in (
        "collect(DISTINCT sno.ranges) AS src_ranges",
        "collect(DISTINCT dno.ranges) AS dst_ranges",
        "sno.opaque_reason",
        "dno.opaque_reason",
        "svc.opaque_reason",
        "AS unresolved",
    ):
        assert column in cypher, f"firewall query missing {column!r}"
    # the object binds without a RESOLVES_TO target, as in path/gates/firewall.py
    assert "OPTIONAL MATCH (r)-[sr:SRC]->(sno:NetObject) WHERE" in cypher
    assert "OPTIONAL MATCH (sno)-[srt:RESOLVES_TO]->(st)" in cypher
    assert "OPTIONAL MATCH (r)-[dr:DST]->(dno:NetObject) WHERE" in cypher
    assert "OPTIONAL MATCH (dno)-[drt:RESOLVES_TO]->(dt)" in cypher
    assert "(sno:NetObject)-[srt:RESOLVES_TO]" not in cypher
    assert "(dno:NetObject)-[drt:RESOLVES_TO]" not in cypher


def _return_columns(cypher: str) -> list[str]:
    """The column names of the last RETURN of `cypher`, in order."""
    clause = cypher.rsplit("\nRETURN ", 1)[1].split("\nORDER BY", 1)[0]
    items, depth, quoted, start = [], 0, False, 0
    for pos, char in enumerate(clause):
        if char == "'":
            quoted = not quoted
        elif not quoted and char in "([{":
            depth += 1
        elif not quoted and char in ")]}":
            depth -= 1
        elif not quoted and depth == 0 and char == ",":
            items.append(clause[start:pos])
            start = pos + 1
    items.append(clause[start:])
    return [re.split(r"\sAS\s", " ".join(item.split()))[-1] for item in items]


def test_the_firewall_table_names_the_device_the_acl_and_its_binding():
    entry = next(q for q in QUERIES if q["key"] == "firewall")
    cypher = entry["cypher"]
    columns = _return_columns(cypher)
    assert [c for c in columns if not c.startswith("_")] == [
        "device",
        "rulebase",
        "interface",
        "direction",
        "pos",
        "rule",
        "action",
        "src",
        "dst",
        "service",
        "unresolved",
    ]
    # the graph columns the canvas draws, the binding edge included
    assert {"_rb", "_r", "_hr", "_bi", "_pb", "_sr", "_sno", "_srt", "_st"} <= set(columns)
    assert {"_dr", "_dno", "_drt", "_dt", "_sv", "_svc"} <= set(columns)
    assert "ORDER BY device, rulebase, interface, direction, pos" in cypher
    assert "OPTIONAL MATCH (bi:Interface)-[pb:PROTECTED_BY]->(rb)" in cypher
    assert "CASE WHEN pb IS NOT NULL THEN bi.name" in cypher
    assert "CASE WHEN pb IS NOT NULL THEN pb.direction" in cypher
    assert "coalesce(r.in_interface, r.out_interface)" in cypher
    assert "WHEN pb IS NULL AND interface IS NOT NULL AND rb.name ENDS WITH" in cypher
    assert "ELSE rb.name END AS rulebase" in cypher
    # an open side reads any, and a service keeps its protocol
    for flag in ("r.src_any", "r.dst_any", "r.svc_any"):
        assert f"CASE WHEN coalesce({flag}, false) THEN ['any']" in cypher
    assert "collect(DISTINCT svc.name) AS services" in cypher
    assert "svc.ports" not in cypher
    assert "unresolved" in entry["description"]


def test_the_sdwan_paths_name_both_links_and_the_far_device():
    """A tunnel to a hub or a branch ends on the far WAN link's address after NAT."""
    entry = next(q for q in QUERIES if q["key"] == "sdwan-paths")
    cypher = entry["cypher"]
    columns = _return_columns(cypher)
    assert [c for c in columns if not c.startswith("_")] == [
        "edge",
        "wan_link",
        "carrier",
        "interface",
        "local_ip",
        "peer_type",
        "far_device",
        "far_link",
        "far_ip",
        "segments",
        "pair",
    ]
    assert {"_t", "_i", "_d", "_l", "_far", "_te", "_io", "_hl", "_tt", "_seg", "_c"} <= set(columns)
    # the far device through its interface or, after NAT, its WAN link (app/routes/sdwan.py)
    assert "OPTIONAL MATCH (far)<-[fh:HAS_IP]-(fi:Interface)-[:ON]->(fid:Device)" in cypher
    assert "OPTIONAL MATCH (far)<-[flh:HAS_IP]-(fl:WanLink)<-[fhl:HAS_LINK]-(fld:Device)" in cypher
    assert "CASE WHEN far:SdwanGateway THEN far.name ELSE far_edge END AS far_device" in cypher
    assert "t.endpoint AS far_ip" in cypher
    assert "coalesce(far.name, far_edge, t.endpoint)" not in cypher
    # the uid names the WAN link at each end; two links can share one interface
    assert "t.uid CONTAINS ':path:' + d.edge_logical_id + ':' + l.link_logical_id + '~'" in cypher
    assert "t.uid ENDS WITH ':' + x.link_logical_id" in cypher
    # a link with no interface has no ENDPOINT: the edge comes from the uid, by one index seek
    assert "WHERE ud.uid = edge_uid AND ud.collection_ts = $snap AND ud:Device" in cypher
    assert "coalesce(i.name, l.interface) AS interface" in cypher
    # peer_type edge is a branch; a gateway tunnel has no second end
    assert "THEN 'branch'" in cypher
    assert "CASE WHEN t.peer_type = 'gateway' THEN NULL ELSE t.pair END AS pair" in cypher
    assert "direction_observed" not in cypher
    assert "pair" in entry["description"]


def test_the_routing_group_covers_sessions_policies_and_origination():
    """The BGP catalog reads configuration as the devices state it. The observed
    session state and the per-neighbor path tables are side-store tables, not
    graph nodes, so no entry here claims to list advertised or received routes."""
    by_key = {q["key"]: q for q in catalog()}
    routing = {k for k, q in by_key.items() if q["group"] == "routing"}
    assert routing == {
        "bgp-sessions",
        "bgp-peers-by-asn",
        "bgp-per-vrf",
        "bgp-originated",
        "bgp-session-policies",
        "route-maps",
        "prefix-lists",
        "prefix-in-policies",
    }
    assert by_key["policy-unresolved"]["group"] == "hygiene"
    assert by_key["prefix-in-policies"]["params"][0]["name"] == "prefix"
    for key in routing:
        assert "$snap" in by_key[key]["cypher"], key
        assert "Retired" in by_key[key]["cypher"], key


def test_the_sdwan_queries_sit_with_the_cloud_and_wan_scenarios():
    """The VeloCloud graph is a snapshot of what the orchestrator answered: edges,
    WAN links, configured gateway tunnels, segments, steering and the recorded
    discovery gaps. Every SD-WAN entry reads the current snapshot and skips
    retired nodes, and none of them claims a live decision (`ForwardingBoundary`
    stays `candidate_set_complete: false`). No entry reads a quality metric: the
    poll reads no statistics, so latency, jitter, loss and path score are not in
    the graph."""
    by_key = {q["key"]: q for q in catalog()}
    sdwan = {k for k, q in by_key.items() if k.startswith("sdwan-")}
    assert sdwan == {
        "sdwan-edges",
        "sdwan-wan-links",
        "sdwan-carriers",
        "sdwan-paths",
        "sdwan-topology",
        "sdwan-segments",
        "sdwan-link-steering",
        "sdwan-gaps",
    }
    assert all(by_key[k]["group"] == "cloud & wan" for k in sdwan)
    assert "scenario-sdwan-steering" not in by_key
    for key in sdwan:
        assert all(word not in by_key[key]["cypher"] for word in ("latency_ms", "jitter_ms", "loss_pct")), key
    for key in sdwan:
        cypher = by_key[key]["cypher"]
        assert "$snap" in cypher, key
        assert "Retired" in cypher, key
        assert "_retired_at IS NULL" in cypher, key
    # the gap query is what an operator opens after a refused Portal read
    assert "fb.gaps IS NOT NULL" in by_key["sdwan-gaps"]["cypher"]
    assert "capability_gap" in by_key["sdwan-gaps"]["cypher"]


def test_the_zscaler_queries_pick_their_values_from_registered_labels():
    """Every value a Zscaler query asks for is offered from the graph: a required
    param has a picker, and a picker names a label and property the schema has."""
    from hst.core.labels import LABELS

    zscaler = [q for q in QUERIES if q["group"] == "zscaler"]
    assert {"zpa-app-group", "zpa-user-group", "zpa-app-segment", "zpa-connector-group"} <= {
        q["key"] for q in zscaler
    }
    for q in zscaler:
        for p in q.get("params", []):
            assert p.get("picker"), f"{q['key']}: ${p['name']} has no picker"
            assert p["picker"]["label"] in LABELS, f"{q['key']}: unknown label {p['picker']['label']}"
            assert p["picker"]["property"] == "name"
            if p.get("optional"):
                assert f"${p['name']} = ''" in q["cypher"], f"{q['key']}: optional ${p['name']} not skippable"


def test_zpa_pictures_read_applies_to_beside_grants_and_denies():
    from hst.queries import QUERIES

    by_key = {q["key"]: q for q in QUERIES}
    for key in ("zpa-app-group", "zpa-user-group", "zpa-app-segment", "zpa-policy-rules"):
        assert "GRANTS|DENIES|APPLIES_TO" in by_key[key]["cypher"], key


def test_zpa_rule_audit_descriptions_state_what_the_query_checks():
    from hst.queries import QUERIES

    by_key = {q["key"]: q for q in QUERIES}
    for key in ("zpa-groups-without-rules", "zpa-user-group", "zpa-app-group", "zpa-policy-rules"):
        text = by_key[key]["description"].lower()
        for word in ("reach", "nobody", "any identity"):
            assert word not in text, (key, word)


def test_zpa_rule_queries_read_rule_scope():
    from hst.queries import QUERIES

    by_key = {q["key"]: q["cypher"] for q in QUERIES}
    for key in ("zpa-groups-without-rules", "zpa-app-group", "zpa-app-segment"):
        assert "app_scope IN ['any', 'other']" in by_key[key], key
    assert "identity_scope = 'any'" in by_key["zpa-policy-rules"]
    assert "]-(r:ZpaAccessRule)-[f:FOR]->(t)" not in by_key["zpa-user-group"]


def test_zia_location_does_not_present_the_deprecated_ssl_flag():
    from hst.queries import QUERIES

    cypher = {q["key"]: q["cypher"] for q in QUERIES}["zia-location"]
    assert "ssl_scan" not in cypher and "AS profile" in cypher


def test_zia_rule_to_zpa_apps_limits_connector_groups_to_the_gateway():
    from hst.queries import QUERIES

    entry = next(q for q in QUERIES if q["key"] == "zia-forwarding-rules")
    assert "STEERS_VIA" in entry["cypher"] and "zpa_gateway" in entry["cypher"]


def test_zia_location_lists_the_forwarding_rules_that_name_it():
    from hst.queries import QUERIES

    cypher = {q["key"]: q["cypher"] for q in QUERIES}["zia-location"]
    assert "APPLIES_TO" in cypher and "AS forwarding_rules" in cypher


def test_every_zscaler_entry_has_a_section_and_a_short_title():
    from hst.queries import catalog

    entries = [q for q in catalog() if q["group"] == "zscaler"]
    assert entries and all(q.get("section") in ("ZPA", "ZIA") for q in entries)
    assert all(len(q["title"]) <= 28 and not q["title"].startswith(("ZPA ", "ZIA ")) for q in entries)
    sections = [q["section"] for q in entries]
    assert sections == sorted(sections, key=["ZPA", "ZIA"].index)
    groups = list(dict.fromkeys(q["group"] for q in catalog()))
    assert groups.index("zscaler") == groups.index("equinix") - 1


def test_segment_group_sizes_joins_anchored_and_pins_the_rules_to_the_run():
    from hst.queries import QUERIES

    cypher = {q["key"]: q["cypher"] for q in QUERIES}["zpa-app-group"]
    assert "WHERE t = sg OR" not in cypher
    assert "gr.collection_ts = $snap" in cypher
    assert "ORDER BY rules" in cypher and "AS picture_nodes" in cypher


# Relationship types that a listed scenario reads only in an OPTIONAL MATCH.
_OPTIONAL_ONLY = {"scenario-evpn-rt-stitch": {"USES_RT"}}
_REL = re.compile(r"\[\w*:([A-Z_|]+)")


def _written_types() -> set[str]:
    """The upper-case names that the collectors, the reasoner and the other
    writers in src/hst spell as a string or after a colon."""
    root = Path(__file__).resolve().parents[1] / "src" / "hst"
    skip = {"demo.py", "queries.py", "labels.py"}
    found: set[str] = set()
    for path in root.rglob("*.py"):
        if path.name in skip or "app" in path.parts or "twin_tools" in path.parts:
            continue
        found.update(re.findall(r"[\"':]([A-Z][A-Z_]+)\b", path.read_text()))
    return found


def test_a_listed_scenario_reads_only_relationship_types_that_something_writes():
    written = _written_types()
    loose = {}
    for entry in catalog():
        if not entry["key"].startswith("scenario-"):
            continue
        types = {t for m in _REL.findall(entry["cypher"]) for t in m.split("|")}
        missing = types - written - _OPTIONAL_ONLY.get(entry["key"], set())
        if missing:
            loose[entry["key"]] = sorted(missing)
    assert loose == {}


def test_demo_only_scenarios_are_not_listed():
    keys = {q["key"] for q in catalog()}
    for key in ("sdwan-steering", "l3out-contract", "guest-segmentation", "pbr-two-gates", "guest-snat"):
        assert f"scenario-{key}" not in keys, key


def test_vendor_scenarios_sit_in_their_vendor_group_with_a_display_name():
    by_key = {q["key"]: q for q in catalog()}
    assert (by_key["scenario-zia-guest-egress"]["group"], by_key["scenario-zia-guest-egress"]["section"]) == (
        "zscaler",
        "ZIA",
    )
    assert by_key["scenario-equinix-fabric-circuit"]["group"] == "equinix"
    assert by_key["scenario-evpn-rt-stitch"]["group"] == "topology"
    assert by_key["scenario-equinix-hsrp-core"]["group"] == "topology"
    assert all(q["group_title"] for q in by_key.values())
    assert by_key["sdwan-edges"]["group_title"] == "Cloud and WAN"


def test_the_locations_description_states_the_fact_only():
    entry = next(q for q in catalog() if q["key"] == "zia-location-egress")
    assert "no tunnel or no site for a top-level location" in entry["description"]
    assert "`" not in entry["description"] and "location_sites" not in entry["description"]


def test_the_zscaler_group_holds_the_thirteen_merged_entries():
    keys = [q["key"] for q in catalog() if q["group"] == "zscaler" and not q["key"].startswith("scenario-")]
    assert sorted(keys) == sorted(
        [
            "zpa-app-segment",
            "zpa-app-group",
            "zpa-user-group",
            "zpa-connector-group",
            "zpa-connectors",
            "zpa-policy-rules",
            "zpa-segments-at-risk",
            "zpa-groups-without-rules",
            "zia-location",
            "zia-location-group",
            "zia-dc-users",
            "zia-forwarding-rules",
            "zia-location-egress",
        ]
    )
    by_key = {q["key"]: q for q in catalog()}
    optional = {k: [p["name"] for p in by_key[k].get("params", []) if p.get("optional")] for k in keys}
    assert optional["zpa-app-group"] == ["app_group"]
    assert optional["zpa-connectors"] == ["connector_group"]
    assert optional["zia-forwarding-rules"] == ["forwarding_rule"]
    assert optional["zia-location-egress"] == ["location_group"]
    assert "ZpaServiceEdge" in by_key["zpa-connectors"]["cypher"]
    assert "ZpaClientForwardingRule" in by_key["zpa-policy-rules"]["cypher"]
    assert "AS gaps" in by_key["zia-location-egress"]["cypher"]
    assert "AS connector_groups" in by_key["zia-forwarding-rules"]["cypher"]
