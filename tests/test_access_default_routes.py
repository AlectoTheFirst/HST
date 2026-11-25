"""Pinned access defaults are evidence, not missing static intent or future supply."""

from dataclasses import replace

import pytest
from tests.test_simul_rib import _rib
from tests.test_vyos import _add_pppoe0, _rib_batch

from hst import path as pathmod
from hst.app import simul_read
from hst.assessment.failure_routing import transform_routing
from hst.impact.evaluate import Interface
from hst.simul import certainty, rib

CTX = "vrf:wan:default"
DEV = "dev:wan"


def _input(origin="pppoe"):
    return rib.RibInput(
        contexts=[{"uid": CTX, "device_uid": DEV, "platform": "vyos", "observed_rib_afs": [4]}],
        access_defaults=[{"context_uid": CTX, "interface": "wan0", "origin": origin}],
        observed_rib={CTX: [_rib("0.0.0.0/0", "192.0.2.1", "static", interface="wan0")]},
        rib_coverage={CTX: "complete"},
    )


@pytest.mark.parametrize("origin", ["pppoe", "dhcp"])
def test_complete_access_default_is_usable_without_a_static_stanza(origin):
    result = rib.compute(_input(origin))
    assert not result.gaps
    assert not result.model_errors
    assert result.validation[0]["status"] == "validated"
    assert [(r["prefix"], r["next_hop"], r["interface"], r["source"]) for r in result.rib] == [
        ("0.0.0.0/0", "192.0.2.1", "wan0", "observed-access-default")
    ]


def test_an_unrelated_configured_static_does_not_hide_the_access_default():
    inp = _input()
    static = {"context_uid": CTX, "prefix": "198.51.100.0/24", "discard": "blackhole"}
    inp.static = [static]
    inp.observed_rib = {
        CTX: [*inp.observed_rib[CTX], _rib("198.51.100.0/24", None, "static", discard="blackhole")]
    }
    result = rib.compute(inp)
    assert not result.gaps
    assert {r["prefix"] for r in result.rib} == {"0.0.0.0/0", "198.51.100.0/24"}


@pytest.mark.parametrize("changed", [False, True])
def test_configured_default_is_not_duplicated_and_cannot_hide_changed_access_supply(changed):
    inp = _input()
    inp.static = [{"context_uid": CTX, "prefix": "0.0.0.0/0", "next_hop": "192.0.2.1", "interface": "wan0"}]
    if changed:
        inp.superseded_contexts = frozenset({CTX})
    result = rib.compute(inp)
    assert [r["source"] for r in result.rib] == ["static"]
    assert any(g["kind"] == certainty.EXTERNAL_RESPONSE for g in result.gaps) == changed


@pytest.mark.parametrize(
    "coverage,afs", [(None, [4]), ("partial", [4]), ("complete", None), ("complete", [6])]
)
def test_incomplete_access_evidence_cannot_prove_the_default(coverage, afs):
    inp = _input()
    inp.rib_coverage = {CTX: coverage}
    inp.contexts = [{**inp.contexts[0], "observed_rib_afs": afs}]
    result = rib.compute(inp)
    assert not result.rib
    assert any("complete pinned IPv4 RIB" in g["detail"] for g in result.gaps)
    assert not result.model_errors


@pytest.mark.parametrize("mutation", ["interface", "prefix", "origin", "context", "discard"])
def test_unrelated_observed_statics_keep_the_missing_configuration_gap(mutation):
    inp = _input()
    route = dict(inp.observed_rib[CTX][0])
    if mutation == "interface":
        route["interface"] = "other0"
    elif mutation == "prefix":
        route.update(prefix="203.0.113.0/24", prefixlen=24)
    elif mutation == "origin":
        inp.access_defaults = [{**inp.access_defaults[0], "origin": "unknown"}]
    elif mutation == "context":
        inp.access_defaults = [{**inp.access_defaults[0], "context_uid": "other-vrf"}]
    else:
        route["discard"] = "blackhole"
    inp.observed_rib = {CTX: [route]}
    result = rib.compute(inp)
    assert any(g["kind"] == "not-collected" for g in result.gaps)


def test_changed_access_supply_is_unknown_and_old_route_is_not_reused():
    result = rib.compute(replace(_input(), superseded_contexts=frozenset({CTX})))
    assert not result.rib
    assert any(g["kind"] == certainty.EXTERNAL_RESPONSE for g in result.gaps)
    assert not result.model_errors


def test_failed_access_interface_does_not_resurrect_from_the_observed_rib():
    iface = Interface(DEV, "if:wan0", "wan0", CTX)
    changed = transform_routing(_input(), [iface], set(), {iface.uid})
    result = rib.compute(changed)
    assert not result.rib
    assert any(g["kind"] == certainty.EXTERNAL_RESPONSE for g in result.gaps)


@pytest.mark.parametrize("option", [None, "no-default-route", "legacy-none"])
def test_pppoe_collector_records_only_enabled_access_default_producers(option):
    def config(cfg):
        _add_pppoe0(cfg)
        node = cfg["interfaces"]["pppoe"]["pppoe0"]
        if option == "legacy-none":
            node["default-route"] = "none"
        elif option:
            node[option] = {}

    batch = _rib_batch(cfg_patch=config)
    iface = next(n for n in batch.nodes if n.label == "Interface" and n.props.get("name") == "pppoe0")
    assert iface.props.get("ipv4_default_origin") == (None if option else "pppoe")
    if not option:
        assert any(r.rel_type == "IN_VRF" and r.start_uid == iface.uid for r in batch.rels)


@pytest.mark.parametrize("disabled", [False, True])
def test_dhcp_subinterface_default_producer_respects_no_default_route(disabled):
    def config(cfg):
        cfg["interfaces"]["ethernet"]["eth0"]["vif"] = {
            "99": {"address": ["dhcp"], "dhcp-options": {"no-default-route": {}} if disabled else {}}
        }

    batch = _rib_batch(cfg_patch=config)
    iface = next(n for n in batch.nodes if n.label == "Interface" and n.props.get("name") == "eth0.99")
    assert iface.props.get("ipv4_default_origin") == (None if disabled else "dhcp")


def test_reader_scopes_access_producers_to_the_unique_device_owner(monkeypatch):
    def read(session, query, **params):
        if query == simul_read._CONTEXTS:
            return [{"uid": CTX, "name": "default", "device_uids": [DEV], "platforms": ["vyos"]}]
        if query == simul_read._ACCESS_DEFAULTS:
            return [
                {"context_uid": CTX, "device_uid": owner, "interface": "wan0", "origin": "pppoe"}
                for owner in (DEV, "other-device")
            ]
        return []

    monkeypatch.setattr(pathmod, "_read", read)
    result = simul_read.read_rib_input(object(), contexts=[CTX])
    assert result.input.access_defaults == [
        {"context_uid": CTX, "device_uid": DEV, "interface": "wan0", "origin": "pppoe"}
    ]
