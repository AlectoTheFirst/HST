from hst.app import simul_read
from hst.collectors import iosxe, iosxr_bgp, nxos, vyos
from hst.collectors.util import GraphBuilder
from hst.core import uid
from hst.simul.errors import ErrorSink


def test_iosxe_records_network_aggregate_and_redistribution_per_vrf():
    parsed = iosxe.parse_bgp_config(
        """router bgp 65000
 address-family ipv4 vrf BLUE
  network 10.0.0.0 mask 255.255.255.0 route-map EXPORT
  aggregate-address 10.0.0.0 255.255.0.0 summary-only
  redistribute connected route-map CONNECTED
 exit-address-family
"""
    )
    blue = next(process for process in parsed["processes"] if process["vrf"] == "BLUE")
    assert blue["networks"] == [{"prefix": "10.0.0.0/24", "raw": "10.0.0.0", "route_map": "EXPORT"}]
    assert blue["aggregates"] == [
        {"prefix": "10.0.0.0/16", "summary_only": True, "as_set": False, "raw": "10.0.0.0"}
    ]
    assert blue["origin_context_gaps"] == []
    assert blue["redistribute"] == [{"protocol": "connected", "route_map": "CONNECTED"}]


def test_iosxr_records_unfiltered_network_and_redistribution_as_origin_evidence():
    parsed = iosxr_bgp.parse_bgp(
        """router bgp 65000
 network 10.0.0.0/24
 aggregate-address 10.0.0.0/16 summary-only
 redistribute connected
!"""
    )
    assert parsed["networks"] == [{"prefix": "10.0.0.0/24", "policy_name": None}]
    assert parsed["aggregates"] == [{"prefix": "10.0.0.0/16", "summary_only": True, "as_set": False}]
    assert parsed["origin_context_gaps"] == []
    assert parsed["redistribute"] == [{"protocol": "connected", "policy_name": None}]


def test_strict_compiler_records_only_explicit_conditional_intent(monkeypatch):
    process = {
        "uid": "process:1",
        "context_uid": "vrf:1",
        "props": {
            "uid": "process:1",
            "redistribute_protocols": ["connected"],
            "origin_config_recorded": True,
        },
        "platforms": ["iosxe"],
        "vendors": ["cisco"],
    }
    originated = [
        {"process_uid": "process:1", "prefix": "10.0.0.0/24", "proto": "network"},
        {"process_uid": "process:1", "prefix": "10.1.0.0/24", "proto": "connected"},
        {"process_uid": "process:1", "prefix": "10.2.0.0/24", "proto": "static"},
    ]

    def read(_session, query, **_params):
        if "RETURN rp.uid AS uid, properties(rp) AS props" in query:
            return [process]
        if "p.cidr AS prefix, og.proto AS proto" in query:
            return originated
        return []

    monkeypatch.setattr(simul_read.pathmod, "_read", read)
    errors = ErrorSink()
    result = simul_read._read_bgp(None, ["process:1"], "iosxe", errors, infer_origins=False)

    assert result.local_routes == [
        {
            "process_uid": "process:1",
            "prefix": "10.0.0.0/24",
            "origin_mechanism": "network",
            "src_protocol": "network",
            "intent": True,
        }
    ]
    assert errors.errors == []


def test_strict_compiler_marks_a_process_without_recorded_origin_coverage_incomplete(monkeypatch):
    process = {
        "uid": "process:legacy",
        "context_uid": "vrf:1",
        "props": {"uid": "process:legacy"},
        "platforms": ["iosxe"],
        "vendors": ["cisco"],
    }

    def read(_session, query, **_params):
        if "RETURN rp.uid AS uid, properties(rp) AS props" in query:
            return [process]
        return []

    monkeypatch.setattr(simul_read.pathmod, "_read", read)
    errors = ErrorSink()

    simul_read._read_bgp(None, ["process:legacy"], "iosxe", errors, infer_origins=False)

    assert [error.kind for error in errors.errors] == ["origination-not-recorded"]
    assert "coverage was not recorded" in errors.errors[0].detail
    assert errors.errors[0].subject == "process:legacy"


def test_vyos_stages_explicit_network_aggregate_and_redistribution():
    builder = GraphBuilder()
    vrf_uid = "vrf:device-1:default"
    vyos._bgp_stage(
        builder,
        {
            "system-as": "65000",
            "address-family": {
                "ipv4-unicast": {
                    "network": {"10.0.0.0/24": {}},
                    "aggregate-address": {"10.0.0.0/16": {"summary-only": {}}},
                    "redistribute": {"connected": {}},
                }
            },
        },
        "device:1",
        "default",
        vrf_uid,
        "device:1",
        {},
        {},
    )
    batch = builder.batch("vyos", "run")
    process = next(node for node in batch.nodes if node.label == "RoutingProcess")
    assert process.props["redistribute_protocols"] == ["connected"]
    assert process.props["origin_config_recorded"] is True
    assert process.props["origin_afs"] == [4, 6]
    assert process.props["network_import_check"] is False
    origins = {(rel.end_uid, rel.props["proto"]) for rel in batch.rels if rel.rel_type == "ORIGINATES"}
    assert origins == {
        (uid.prefix(vrf_uid, "10.0.0.0/24"), "network"),
        (uid.prefix(vrf_uid, "10.0.0.0/16"), "aggregate"),
    }


def test_nxos_records_dual_stack_named_vrf_origin_configuration():
    processes = nxos.parse_bgp_config(
        """router bgp 65000
  vrf BLUE
    address-family ipv4 unicast
      network 10.0.0.0/24 route-map EXPORT
      aggregate-address 10.0.0.0/8 summary-only
      redistribute direct
    address-family ipv6 unicast
      network 2001:db8::/48
      aggregate-address 2001:db8::/32 advertise-map SELECT
"""
    )
    blue = next(process for process in processes if process["vrf"] == "BLUE")
    assert blue["networks"] == [
        {"prefix": "10.0.0.0/24", "route_map": "EXPORT"},
        {"prefix": "2001:db8::/48", "route_map": None},
    ]
    assert blue["redistribute"] == [{"protocol": "direct", "route_map": None}]
    assert blue["aggregates"][0] == {
        "prefix": "10.0.0.0/8",
        "summary_only": True,
        "as_set": False,
    }
    assert blue["aggregates"][1]["unsupported_options"] == ["advertise-map", "SELECT"]

    batch = nxos.bgp_stage(
        {"bgp": {"processes": processes}},
        dev="device:1",
        existing_vrf_uids=set(),
        source="nxos",
        scope="fixture",
    )
    process = next(
        node
        for node in batch.nodes
        if node.label == "RoutingProcess" and node.uid == uid.routing_process("device:1", "BLUE", "bgp")
    )
    assert process.props["origin_config_recorded"] is True
    assert process.props["origin_afs"] == [4, 6]
    assert process.props["redistribute_protocols"] == ["direct"]
    assert process.props["origin_context_gaps"]


def test_nxos_records_an_aggregate_attribute_map_as_its_own_route_map():
    processes = nxos.parse_bgp_config(
        """router bgp 65014
  vrf WAN
    address-family ipv4 unicast
      aggregate-address 10.8.58.0/27 attribute-map RM_AGG
      aggregate-address 44.198.0.0/15 summary-only attribute-map RM_GHOST
      aggregate-address 10.9.0.0/16 attribute-map RM_AGG suppress-map RM_SUPPRESS
"""
    )
    route_maps = nxos.parse_route_map_config(
        """route-map RM_AGG permit 10
  set as-path prepend 65014 65014
"""
    )
    wan = next(process for process in processes if process["vrf"] == "WAN")
    assert wan["aggregates"] == [
        {"prefix": "10.8.58.0/27", "summary_only": False, "as_set": False, "attribute_map": "RM_AGG"},
        {"prefix": "44.198.0.0/15", "summary_only": True, "as_set": False, "attribute_map": "RM_GHOST"},
        {
            "prefix": "10.9.0.0/16",
            "summary_only": False,
            "as_set": False,
            "attribute_map": "RM_AGG",
            "unsupported_options": ["suppress-map", "RM_SUPPRESS"],
        },
    ]
    assert wan["origin_context_gaps"] == [
        "aggregate-address 10.9.0.0/16 options suppress-map RM_SUPPRESS are not modeled"
    ]

    batch = nxos.bgp_stage(
        {"bgp": {"processes": processes, "route_maps": route_maps}},
        dev="device:1",
        existing_vrf_uids=set(),
        source="nxos",
        scope="fixture",
    )
    vrf_uid = uid.vrf("device:1", "WAN")
    process_uid = uid.routing_process("device:1", "WAN", "bgp")
    originates = {
        rel.end_uid: rel.props
        for rel in batch.rels
        if rel.rel_type == "ORIGINATES" and rel.start_uid == vrf_uid
    }
    assert originates[uid.prefix(vrf_uid, "10.8.58.0/27")]["attribute_map"] == "RM_AGG"
    # the raw name lands on the edge whether or not it resolves
    assert originates[uid.prefix(vrf_uid, "44.198.0.0/15")]["attribute_map"] == "RM_GHOST"
    filters = {
        (rel.end_uid, rel.key["protocol"])
        for rel in batch.rels
        if rel.rel_type == "FILTERED_BY" and rel.start_uid == process_uid
    }
    assert filters == {(uid.route_policy("device:1", "route-map", "RM_AGG"), "aggregate")}


def test_iosxe_records_an_aggregate_attribute_map_and_gaps_the_rest():
    parsed = iosxe.parse_bgp_config(
        """router bgp 65000
 address-family ipv4
  aggregate-address 10.0.0.0 255.0.0.0 attribute-map RM_AGG
  aggregate-address 10.1.0.0 255.255.0.0 as-set advertise-map RM_SELECT
 exit-address-family
"""
    )
    default = parsed["processes"][0]
    assert default["aggregates"] == [
        {
            "prefix": "10.0.0.0/8",
            "summary_only": False,
            "as_set": False,
            "attribute_map": "RM_AGG",
            "raw": "10.0.0.0",
        },
        {
            "prefix": "10.1.0.0/16",
            "summary_only": False,
            "as_set": True,
            "unsupported_options": ["advertise-map", "RM_SELECT"],
            "raw": "10.1.0.0",
        },
    ]
    assert default["origin_context_gaps"] == [
        "aggregate-address 10.1.0.0/16 options advertise-map RM_SELECT are not modeled"
    ]


def test_iosxr_records_an_aggregate_route_policy_as_its_attribute_map():
    parsed = iosxr_bgp.parse_bgp(
        """router bgp 65000
 aggregate-address 10.0.0.0/8 as-set summary-only route-policy RP_AGG
!"""
    )
    assert parsed["aggregates"] == [
        {"prefix": "10.0.0.0/8", "summary_only": True, "as_set": True, "attribute_map": "RP_AGG"}
    ]
    assert parsed["origin_context_gaps"] == []
