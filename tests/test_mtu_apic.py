"""APIC MTU configured semantics using only hand-written synthetic fixtures."""

import copy
import json
from pathlib import Path

import httpx
import pytest

from hst.collectors import apic
from hst.collectors.apic import ApicCollector, ApicConfig, normalize_apic
from hst.collectors.base import RAW_OUTCOMES_KEY, raw_sha
from hst.collectors.mtu_apic import MTU_CLASSES, MTU_POLICY_PATH, mtu_sections
from hst.core import uid
from hst.core.config import Settings
from hst.core.mtu import MtuContext, MtuObservation
from hst.core.mtu_read import resolve_constraints

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/mtu/apic/configured.json"


def payload():
    return json.loads(FIXTURE.read_text())


def collector(**extra):
    return ApicCollector(
        ApicConfig(
            url="https://apic.synthetic.invalid",
            fabric="synthetic",
            auth={"username": "synthetic", "password": "synthetic"},
            capture_bgp="none",
            **extra,
        ),
        Settings(_env_file=None),
    )


def observations(batch):
    return [MtuObservation(uid=n.uid, **n.props) for n in batch.nodes if n.label == "MtuObservation"]


def test_baseline_raw_physical_mtu_keeps_unknown_size_basis():
    raw = payload()
    for cls in MTU_CLASSES:
        raw.pop(cls)
    batch = normalize_apic(raw, fabric="synthetic", l3dom="synthetic")
    rows = observations(batch)
    assert len(rows) == 3
    assert all(o.normalized_value is None and o.assertion_kind == "configured" for o in rows)
    assert all(o.metric == "unknown" and "MTU_SEMANTICS_UNKNOWN" in o.gaps for o in rows)
    assert sorted(json.loads(o.raw_value_json) for o in rows) == ["1500", "9000", "9000"]
    assert all("/port/" in o.subject_uid for o in rows)


def test_fabric_default_and_routed_attachment_are_distinct():
    batch = collector().normalize(payload())
    rows = observations(batch)
    defaults = [o for o in rows if o.subject_uid == uid.fabric("synthetic")]
    assert len(defaults) == 2
    assert all(o.normalized_value == 9000 and o.scope == "fabric-l3out-default" for o in defaults)
    direct = [o for o in rows if "lifp-direct" in o.raw_evidence_ref]
    assert {o.metric for o in direct} == {"ipv4_mtu_bytes", "ipv6_mtu_bytes"}
    assert all(o.normalized_value == 1500 and o.direction == "both" for o in direct)
    assert all(o.assertion_kind == "configured" for o in rows)
    assert not any(o.normalized_value is not None and "/port/" in o.subject_uid for o in rows)
    assert batch.sections["mtu:operational"].status == "unsupported"
    batch.validate_registry()
    nodes = {n.uid for n in batch.nodes}
    assert all(r.start_uid in nodes and r.end_uid in nodes for r in batch.rels)


def test_interface_mtu_observation_is_both_directions_and_rx_context_resolves_a_ceiling():
    rows = observations(collector().normalize(payload()))
    direct = [o for o in rows if "lifp-direct" in o.raw_evidence_ref and o.af == 4]
    assert direct and all(o.direction == "both" for o in direct)
    rx = resolve_constraints(direct, MtuContext(af=4, direction="rx"))
    assert rx.constraints and rx.constraints[0].bound_kind == "ceiling"
    assert rx.constraints[0].value_bytes == 1500


def test_inherit_preserves_raw_and_depends_on_matching_policy_family():
    rows = observations(collector().normalize(payload()))
    default_by_af = {o.af: o for o in rows if o.subject_uid == uid.fabric("synthetic")}
    inherited = [o for o in rows if o.resolution_state == "inherited"]
    assert len(inherited) == 4
    for obs in inherited:
        assert json.loads(obs.raw_value_json) == "inherit"
        assert obs.normalized_value == 9000
        assert obs.policy_ref == default_by_af[obs.af].uid
        assert obs.dependency_uids == [obs.policy_ref]


@pytest.mark.parametrize("status", ["unauthorized", "unsupported", "failed", "malformed"])
def test_policy_capture_failure_cannot_inherit_stale_policy_rows(status):
    raw = payload()
    raw[RAW_OUTCOMES_KEY] = {"mtu:l2InstPol": {"status": status, "detail": "synthetic failure"}}
    batch = collector().normalize(raw)
    assert batch.sections["mtu:l2InstPol"].status == status
    rows = observations(batch)
    inherited = [o for o in rows if json.loads(o.raw_value_json) == "inherit"]
    assert len(inherited) == 4
    assert all(o.normalized_value is None and o.gaps == ["MTU_POLICY_UNRESOLVED"] for o in inherited)
    assert not any(o.subject_uid == uid.fabric("synthetic") for o in rows)
    assert len([n for n in batch.nodes if n.label == "Device"]) == 1


def test_floating_and_regular_attachment_binding_and_fragmentation():
    batch = collector().normalize(payload())
    interfaces = [n for n in batch.nodes if n.label == "Interface"]
    assert len(interfaces) == 3
    floating = next(n for n in interfaces if n.props["kind"] == "l3out-floating")
    assert floating.props["attachment_resolved"] is False
    assert all(n.props["ip_fragmentation"] == "unsupported" for n in interfaces)
    assert not any(r.start_uid == floating.uid and r.rel_type == "BOUND_TO" for r in batch.rels)
    assert sum(r.rel_type == "BOUND_TO" for r in batch.rels) == 2


def test_unknown_path_does_not_create_carrier_and_vpc_does_not_invent_single_owner():
    raw = payload()
    attrs = raw["l3extRsPathL3OutAtt"][0]["l3extRsPathL3OutAtt"]["attributes"]
    attrs["tDn"] = "topology/pod-2/paths-101/pathep-[eth1/2]"
    batch = collector().normalize(raw)
    target = uid.aci("synthetic", attrs["dn"])
    assert not any(r.start_uid == target and r.rel_type in {"ON", "BOUND_TO"} for r in batch.rels)
    assert next(n for n in batch.nodes if n.uid == target).props["attachment_resolved"] is False


def test_lag_has_a_port_node_and_explicit_membership_has_unknown_eligibility():
    batch = collector().normalize(payload())
    dev = "dev:synthetic-leaf"  # minted from the fabric node's name
    lag_uid = uid.lag(dev, "po1")
    assert any(n.label == "Port" and n.uid == f"{dev}/port/po1" for n in batch.nodes)
    assert any(n.label == "Lag" and n.uid == lag_uid for n in batch.nodes)
    members = [r for r in batch.rels if r.rel_type == "MEMBER_OF" and r.end_uid == lag_uid]
    assert len(members) == 1
    assert members[0].props["forwarding_eligible"] == "unknown"
    assert members[0].props["basis"] == "configured"


def test_no_policy_default_or_active_member_inference():
    raw = payload()
    raw.pop("l2InstPol")
    raw.pop("pcRsMbrIfs")
    batch = collector().normalize(raw)
    assert not any(r.rel_type == "MEMBER_OF" and r.end_label == "Lag" for r in batch.rels)
    inherited = [o for o in observations(batch) if json.loads(o.raw_value_json) == "inherit"]
    assert all(o.normalized_value is None for o in inherited)
    assert batch.sections["mtu:l2InstPol"].status == "unknown"


def test_optional_capture_reads_documented_paths_and_class_errors_remain_distinct(monkeypatch):
    requests = []
    raw = payload()

    def respond(request):
        requests.append(request.url.path)
        if request.url.path == MTU_POLICY_PATH:
            return httpx.Response(200, json={"imdata": raw["l2InstPol"]})
        cls = request.url.path.rsplit("/", 1)[1].removesuffix(".json")
        if cls == "l3extVirtualLIfP":
            return httpx.Response(
                200,
                json={
                    "imdata": [
                        {"error": {"attributes": {"code": "122", "text": "unknown managed object class"}}}
                    ]
                },
            )
        rows = raw.get(cls, [])
        return httpx.Response(200, json={"imdata": rows, "totalCount": str(len(rows))})

    coll = collector(capture_mtu=True)
    monkeypatch.setattr(coll, "_keep_alive", lambda client: None)
    captured = {}
    with httpx.Client(base_url=coll.config.url, transport=httpx.MockTransport(respond)) as client:
        coll._fetch_mtu(client, captured)
    assert requests == [
        MTU_POLICY_PATH,
        "/api/class/l3extRsPathL3OutAtt.json",
        "/api/class/l3extVirtualLIfP.json",
        "/api/class/pcRsMbrIfs.json",
    ]
    assert captured[RAW_OUTCOMES_KEY]["mtu:l3extVirtualLIfP"]["status"] == "unsupported"
    assert captured[RAW_OUTCOMES_KEY]["mtu:l2InstPol"]["status"] == "ok"


@pytest.mark.parametrize("code,expected", [(403, "unauthorized"), (404, "unsupported"), (500, "failed")])
def test_optional_http_failures_do_not_abort_other_evidence(monkeypatch, code, expected):
    coll = collector(capture_mtu=True)
    monkeypatch.setattr(coll, "_keep_alive", lambda client: None)
    monkeypatch.setattr(coll, "_login", lambda client: None)
    captured = {}
    with httpx.Client(
        base_url=coll.config.url,
        transport=httpx.MockTransport(lambda request: httpx.Response(code, json={"imdata": []})),
    ) as client:
        coll._fetch_mtu(client, captured)
    assert all(o["status"] == expected for o in captured[RAW_OUTCOMES_KEY].values())


def test_optional_page_budget_and_missing_body_are_not_empty(monkeypatch):
    monkeypatch.setattr(apic, "PAGE_SIZE", 1)
    monkeypatch.setattr(apic, "MTU_MAX_PAGES", 1)
    coll = collector(capture_mtu=True)
    monkeypatch.setattr(coll, "_keep_alive", lambda client: None)

    def respond(request):
        if request.url.path == MTU_POLICY_PATH:
            return httpx.Response(200, json={})
        cls = request.url.path.rsplit("/", 1)[1].removesuffix(".json")
        return httpx.Response(
            200, json={"imdata": [{cls: {"attributes": {"dn": "synthetic"}}}], "totalCount": "2"}
        )

    captured = {}
    with httpx.Client(base_url=coll.config.url, transport=httpx.MockTransport(respond)) as client:
        coll._fetch_mtu(client, captured)
    assert captured[RAW_OUTCOMES_KEY]["mtu:l2InstPol"]["status"] == "malformed"
    assert captured[RAW_OUTCOMES_KEY]["mtu:pcRsMbrIfs"]["status"] == "failed"
    assert "budget" in captured[RAW_OUTCOMES_KEY]["mtu:pcRsMbrIfs"]["detail"]


def test_disabled_capture_and_raw_fingerprint():
    coll = collector()
    captured = {}
    coll._fetch_mtu(None, captured)
    assert captured == {}
    raw = payload()
    changed = copy.deepcopy(raw)
    changed["l2InstPol"][0]["l2InstPol"]["attributes"]["fabricMtu"] = "1500"
    assert raw_sha(coll, raw) != raw_sha(coll, changed)
    changed = copy.deepcopy(raw)
    changed[RAW_OUTCOMES_KEY] = {"mtu:l2InstPol": {"status": "unauthorized"}}
    assert raw_sha(coll, raw) != raw_sha(coll, changed)
    assert mtu_sections({})["mtu:l2InstPol"].status == "unknown"
