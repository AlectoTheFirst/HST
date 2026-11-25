from pathlib import Path

import pytest

from hst.core.fixtures import load_fixture
from hst.core.model import Batch

FIXTURES = Path(__file__).parents[1] / "fixtures"


@pytest.mark.parametrize("name", ["mini-dc.yaml", "mini-enterprise.yaml"])
def test_fixture_loads_and_validates(name):
    batch = load_fixture(FIXTURES / name)
    assert batch.source == "fixture"
    assert len(batch.nodes) > 40
    assert len(batch.rels) > 40


def test_zpa_connector_vm_resolves_to_a_concrete_address():
    batch = load_fixture(FIXTURES / "mini-enterprise.yaml")
    nodes_by_uid = {n.uid: n for n in batch.nodes}
    vnic_uid = "vc:vc01:vm-201/vnic/0"
    assert nodes_by_uid[vnic_uid].label == "Vnic"
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert ("OF", vnic_uid, "vc:vc01:vm-201") in rels
    has_ip = [
        (r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "HAS_IP" and r.start_uid == vnic_uid
    ]
    assert len(has_ip) == 1
    ip_uid = has_ip[0][1]
    assert nodes_by_uid[ip_uid].label == "IpAddress"
    assert nodes_by_uid[ip_uid].props["ip"] == "10.0.12.6"


def test_rel_accepts_list_form():
    batch = Batch.model_validate(
        {
            "source": "t",
            "scope": "t:1",
            "nodes": [{"label": "Site", "uid": "site:x", "props": {}}],
            "rels": [{"type": "LOCATED_IN", "start": ["Device", "dev:x:y"], "end": ["Site", "site:x"]}],
        }
    )
    r = batch.rels[0]
    assert (r.rel_type, r.start_uid, r.end_label) == ("LOCATED_IN", "dev:x:y", "Site")


def test_unregistered_label_rejected():
    batch = Batch.model_validate(
        {
            "source": "t",
            "scope": "t:1",
            "nodes": [{"label": "Switcheroo", "uid": "x:1"}],
        }
    )
    with pytest.raises(ValueError, match="Switcheroo"):
        batch.validate_registry()


def test_unregistered_rel_rejected():
    batch = Batch.model_validate(
        {
            "source": "t",
            "scope": "t:1",
            "rels": [{"type": "FRIENDS_WITH", "start": ["Site", "a"], "end": ["Site", "b"]}],
        }
    )
    with pytest.raises(ValueError, match="FRIENDS_WITH"):
        batch.validate_registry()


# --- BGP/route-policy schema ------------------------------------------------------------


def test_bgp_session_requires_local_and_peer_asn():
    batch = Batch.model_validate(
        {
            "source": "t",
            "scope": "t:1",
            "nodes": [{"label": "BgpSession", "uid": "bgp:x~1.1.1.1:default", "props": {"local_asn": 65000}}],
        }
    )
    with pytest.raises(ValueError, match="peer_asn"):
        batch.validate_registry()


def test_route_policy_requires_kind():
    batch = Batch.model_validate(
        {
            "source": "t",
            "scope": "t:1",
            "nodes": [{"label": "RoutePolicy", "uid": "rtpol:x:route-map:PL_IN", "props": {"name": "PL_IN"}}],
        }
    )
    with pytest.raises(ValueError, match="kind"):
        batch.validate_registry()


def test_route_policy_entry_requires_seq_and_kind():
    batch = Batch.model_validate(
        {
            "source": "t",
            "scope": "t:1",
            "nodes": [{"label": "RoutePolicyEntry", "uid": "rtpol:x:route-map:PL_IN/clause/10", "props": {}}],
        }
    )
    with pytest.raises(ValueError, match=r"seq.*kind|kind.*seq"):
        batch.validate_registry()


def test_prefix_list_entry_requires_filter_fields():
    batch = Batch.model_validate(
        {
            "source": "t",
            "scope": "t:1",
            "nodes": [
                {
                    "label": "PrefixListEntry",
                    "uid": "rtpol:x:prefix-list:PL1/line/10",
                    "props": {"seq": 10, "action": "permit"},
                }
            ],
        }
    )
    with pytest.raises(ValueError, match="min_len"):
        batch.validate_registry()


def test_routing_process_requires_proto():
    batch = Batch.model_validate(
        {
            "source": "t",
            "scope": "t:1",
            "nodes": [{"label": "RoutingProcess", "uid": "rproc:x:default:bgp", "props": {"asn": 65000}}],
        }
    )
    with pytest.raises(ValueError, match="proto"):
        batch.validate_registry()


def test_bgp_schema_batch_validates_end_to_end():
    proc = "rproc:dev:x:default:bgp"
    sess = "bgp:rproc:dev:x:default:bgp~192.0.2.1:default"
    pol = "rtpol:dev:x:route-map:FROM-PEER"
    entry = f"{pol}/clause/10"
    pfx_pol = "rtpol:dev:x:prefix-list:PL1"
    pfx_entry = f"{pfx_pol}/line/10"

    batch = Batch.model_validate(
        {
            "source": "t",
            "scope": "t:1",
            "nodes": [
                {"label": "RoutingProcess", "uid": proc, "props": {"proto": "bgp", "asn": 65000}},
                {
                    "label": "BgpSession",
                    "uid": sess,
                    "props": {
                        "local_asn": 65000,
                        "peer_asn": 65001,
                        "import_policy_name": "FROM-PEER",
                        "import_policy_kind": "route-map",
                    },
                },
                {"label": "RoutePolicy", "uid": pol, "props": {"name": "FROM-PEER", "kind": "route-map"}},
                {
                    "label": "RoutePolicyEntry",
                    "uid": entry,
                    "props": {"seq": 10, "kind": "clause", "action": "permit", "match_prefix_lists": ["PL1"]},
                },
                {"label": "RoutePolicy", "uid": pfx_pol, "props": {"name": "PL1", "kind": "prefix-list"}},
                {
                    "label": "PrefixListEntry",
                    "uid": pfx_entry,
                    "props": {
                        "seq": 10,
                        "action": "permit",
                        "prefix": "10.0.0.0/8",
                        "min_len": 8,
                        "max_len": 8,
                    },
                },
            ],
            "rels": [
                {"type": "HAS", "start": ["RoutingProcess", proc], "end": ["BgpSession", sess]},
                {
                    "type": "FILTERED_BY",
                    "start": ["BgpSession", sess],
                    "end": ["RoutePolicy", pol],
                    "key": {"direction": "in"},
                },
                {"type": "HAS_RULE", "start": ["RoutePolicy", pol], "end": ["RoutePolicyEntry", entry]},
                {
                    "type": "HAS_RULE",
                    "start": ["RoutePolicy", pfx_pol],
                    "end": ["PrefixListEntry", pfx_entry],
                },
                {
                    "type": "REFERENCES",
                    "start": ["RoutePolicyEntry", entry],
                    "end": ["RoutePolicy", pfx_pol],
                    "key": {"kind": "prefix-list"},
                },
            ],
        }
    )
    batch.validate_registry()  # must not raise


def test_dangling_reference_recorded_without_target_node():
    entry = "rtpol:dev:x:route-map:FROM-PEER/clause/10"
    batch = Batch.model_validate(
        {
            "source": "t",
            "scope": "t:1",
            "nodes": [
                {
                    "label": "RoutePolicyEntry",
                    "uid": entry,
                    "props": {
                        "seq": 10,
                        "kind": "clause",
                        "action": "permit",
                        "match_prefix_lists": ["UNDEFINED"],
                    },
                }
            ],
        }
    )
    batch.validate_registry()  # must not raise: no PrefixListEntry/RoutePolicy node required
    node = batch.nodes[0]
    assert node.props["match_prefix_lists"] == ["UNDEFINED"]
