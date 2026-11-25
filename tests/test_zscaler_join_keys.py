"""The keys that the Zscaler joins read are the keys that the collectors write."""

from __future__ import annotations

from tests.test_zia import RAW as ZIA_RAW
from tests.test_zpa import RAW as ZPA_RAW

from hst import reasoner
from hst.collectors.zia import normalize_zia
from hst.collectors.zpa import normalize_zpa


def _nodes(batch, label):
    return [n for n in batch.nodes if n.label == label]


def test_the_zia_rule_names_the_zpa_segment_by_the_id_the_zpa_collector_writes():
    segments = _nodes(normalize_zpa(ZPA_RAW, tenant="acme"), "ZpaAppSegment")
    ids = set()
    for seg in segments:
        assert isinstance(seg.props["zpa_id"], str)
        assert seg.uid.rsplit(":", 1)[1] == seg.props["zpa_id"]
        ids.add(seg.props["zpa_id"])
    rules = {n.uid: n.props for n in _nodes(normalize_zia(ZIA_RAW, tenant="acme"), "ZiaForwardingRule")}
    assert rules["zia:acme:fwdrule:600001"]["zpa_app_segment_ids"] == ["2001"]
    assert "2001" in ids


def test_the_reasoner_join_reads_the_keys_the_collectors_write():
    join = dict(reasoner.RULES)["zia-forwarding-to-zpa-segment"]
    assert "f.zpa_app_segment_ids" in join and "{zpa_id: wanted}" in join
    for rule in _nodes(normalize_zia(ZIA_RAW, tenant="acme"), "ZiaForwardingRule"):
        if rule.props.get("forward_method") == "zpa":
            assert rule.props.get("zpa_app_segment_ids")


def test_the_same_as_rule_reads_the_address_keys_the_collectors_write():
    fetch = reasoner.FETCH_ZSCALER_ADDRESSES
    for key in ("n.private_ip", "n.address", "n.source_ip", "n.uid STARTS WITH 'zia:'"):
        assert key in fetch
    zpa = normalize_zpa(ZPA_RAW, tenant="acme")
    assert all(n.props.get("private_ip") for n in _nodes(zpa, "ZpaAppConnector"))
    assert all(n.props.get("address") for n in _nodes(zpa, "AppServer"))
    for tunnel in _nodes(normalize_zia(ZIA_RAW, tenant="acme"), "Tunnel"):
        assert tunnel.uid.startswith("zia:") and tunnel.props.get("source_ip")
