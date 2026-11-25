"""MTU identity and local route projection in saved assessments."""

from dataclasses import FrozenInstanceError, replace

import pytest
from fastapi import HTTPException
from tests import test_impact_evaluate as base
from tests.app.test_impact_api import REQUEST
from tests.test_mtu_contract import observation

from hst.assessment import evaluation
from hst.impact.evaluate import MtuRequirement, answer


def wire(monkeypatch):
    graph = base.Graph()

    def read(session, query, **params):
        rows = graph.read(query, **params)
        overlay = getattr(session, "overlay", None)
        return rows if overlay is None else overlay(query, params, rows)

    monkeypatch.setattr(base.path, "_read", read)
    monkeypatch.setattr(
        base.path, "_read_one", lambda session, query, **params: graph.read_one(query, **params)
    )
    return graph


def request(size=1500, **fields):
    return replace(base._request(), mtu=MtuRequirement(mode="unfragmented", ip_packet_bytes=size, **fields))


def network(limits):
    original = base._network()
    return replace(
        original,
        interfaces=tuple(
            replace(
                i, mtu_observations_json=(observation(limits[i.uid], subject_uid=i.uid).model_dump_json(),)
            )
            if i.uid in limits
            else i
            for i in original.interfaces
        ),
    )


def test_request_roundtrip_and_deep_immutability():
    body = evaluation.RequestBody(
        **{
            **REQUEST,
            "mtu": {"mode": "packet", "ip_packet_bytes": 1501, "ipv4_df": True, "reply_ip_packet_bytes": 900},
        }
    )
    parsed = evaluation._request_from_body(body)
    assert parsed.mtu.as_request() == body.mtu
    body.mtu.ip_packet_bytes = 999
    assert parsed.mtu.ip_packet_bytes == 1501
    with pytest.raises(FrozenInstanceError):
        parsed.mtu.ip_packet_bytes = 999
    assert evaluation._request_from_body(evaluation.RequestBody(**REQUEST)).mtu is None


def test_af_validation_at_assessment_boundary():
    body = evaluation.RequestBody(**{**REQUEST, "mtu": {"mode": "packet", "ip_packet_bytes": 19}})
    with pytest.raises(HTTPException, match="packet length"):
        evaluation._request_from_body(body)


def test_enabled_missing_projection_never_silently_passes(monkeypatch):
    wire(monkeypatch)
    net = network({})
    legacy = answer(net, base._request())
    assert legacy.lower
    assessed = answer(net, request())
    assert not assessed.lower and assessed.upper
    assert assessed.gaps[-1]["code"] == "MTU_PATH_COVERAGE_INCOMPLETE"
    assert assessed.gaps[-1]["recipe_id"] is None
    inventory = answer(net, replace(request(), mtu=MtuRequirement(mode="inventory")))
    assert inventory.lower == legacy.lower


def test_generous_local_limits_leave_the_assessment_not_established(monkeypatch):
    """The assessment evaluator does not read the trace layer's MTU outcome."""
    wire(monkeypatch)
    net = network({"if:r1-eth1": 9000})
    unfragmented = answer(net, request(1500))
    assert not unfragmented.lower and unfragmented.upper
    assert unfragmented.gaps[-1]["code"] == "MTU_PATH_COVERAGE_INCOMPLETE"
    assert unfragmented.gaps[-1]["recipe_id"] is None
    packet = answer(
        net, replace(request(1500), mtu=MtuRequirement(mode="packet", ip_packet_bytes=1500, ipv4_df=True))
    )
    assert not packet.lower and packet.upper
    assert packet.gaps[-1]["code"] == "MTU_PATH_COVERAGE_INCOMPLETE"


def test_local_known_deficit_and_exact_boundary(monkeypatch):
    wire(monkeypatch)
    net = network({"if:r1-eth1": 1500})
    deficit = answer(net, request(1501))
    assert not deficit.upper
    evidence = [
        s.data["mtu"]
        for m in deficit.members.values()
        for e in m.explanations
        for s in e.steps
        if "mtu" in s.data
    ]
    assert any(item["outcome"] == "fail" and item["known_ceiling_bytes"] == 1500 for item in evidence)
    exact = answer(net, request(1500))
    assert exact.upper and not exact.lower


def test_ipv4_fragmentation_remains_unknown(monkeypatch):
    wire(monkeypatch)
    packet = replace(request(), mtu=MtuRequirement(mode="packet", ip_packet_bytes=1501, ipv4_df=False))
    result = answer(network({"if:r1-eth1": 1500}), packet)
    assert result.upper and not result.lower


def test_an_interface_set_mtu_intent_parses_and_the_mtu_requirement_ends_not_established(monkeypatch):
    """`interface.set_mtu` gives the MTU requirement no evidence to resolve against."""
    from hst.app import fw_overlay_read
    from hst.simul.fw_overlay import Catalog

    wire(monkeypatch)
    monkeypatch.setattr(
        fw_overlay_read,
        "read_catalog",
        lambda session, intents=(): Catalog(
            interfaces={
                "if:eth0": {
                    "uid": "if:eth0",
                    "vendor": "vyos",
                    "platform": "vyos",
                    "parent_interface_uid": None,
                    "parent_uid": None,
                    "configured_tag_depth": None,
                    "port_uid": None,
                    "observations": [],
                }
            }
        ),
    )
    net = network({})
    result = evaluation._evaluate_change(
        object(),
        intents=[{"kind": "interface.set_mtu", "params": {"interface": "if:eth0", "mtu": 9000}}],
        request=request(),
        network=net,
    )
    assert result["intents"] == [
        {"kind": "interface.set_mtu", "params": {"interface": "if:eth0", "mtu": 9000}}
    ]
    assert result["gaps"][-1]["code"] == "MTU_PATH_COVERAGE_INCOMPLETE"
    assert result["not_established"]["after"]["count"] > 0


def test_request_documents_keep_mtu_for_saved_and_discovered_requirements():
    from hst.app.routes import assessments as routes
    from hst.assessment import discovery

    parsed = replace(base._request(), mtu=MtuRequirement(mode="packet", ip_packet_bytes=1501, ipv4_df=True))
    for document in (routes._request_document(parsed), discovery.request_document(parsed)):
        assert document["mtu"] == {
            "mode": "packet",
            "ip_packet_bytes": 1501,
            "ipv4_df": True,
            "reply_ip_packet_bytes": None,
            "traffic_class": None,
        }
        body = evaluation.RequestBody.model_validate(document)
        assert evaluation._request_from_body(body).mtu == parsed.mtu
    plain = routes._request_document(base._request())
    assert "mtu" not in plain
