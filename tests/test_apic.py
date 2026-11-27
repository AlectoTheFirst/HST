"""APIC collector. RAW has the shape of APIC class-query responses:
each entry is {"<cls>": {"attributes": {...}}} as APIC returns inside imdata."""

import json
import pathlib

import httpx
import pytest

from hst.collectors.apic import (
    BGP_CLASSES,
    CLASSES,
    CONTRACT_BYPASS_CLASSES,
    ApicCollector,
    ApicConfig,
    _attrs,
    normalize_apic,
)
from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.core import Settings


def _cfg(**over):
    base = {
        "url": "https://apic.example",
        "auth": {"method": "user_password", "username": "ro", "password": "pw"},
        "fabric": "fab1",
        "site_code": "dc1",
        "l3dom": "dc1",
    }
    base.update(over)
    return ApicConfig(**base)


def _mock_apic(pages: dict[str, list[list[dict]]]):
    """MockTransport: login + per-class paginated responses.

    pages: cls -> list of pages (each a list of MO dicts)."""
    calls = {"login": 0, "gets": []}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/aaaLogin.json":
            calls["login"] += 1
            body = json.loads(request.content)
            assert body["aaaUser"]["attributes"]["name"] == "ro"
            return httpx.Response(200, json={"imdata": [{"aaaLogin": {"attributes": {"token": "tok123"}}}]})
        assert request.url.path.startswith("/api/class/")
        cls = request.url.path.removeprefix("/api/class/").removesuffix(".json")
        page = int(request.url.params.get("page", "0"))
        calls["gets"].append((cls, page))
        assert request.url.params["page-size"] == "1000"
        cls_pages = pages.get(cls, [[]])
        rows = cls_pages[page] if page < len(cls_pages) else []
        return httpx.Response(200, json={"imdata": rows, "totalCount": str(sum(map(len, cls_pages)))})

    return httpx.MockTransport(handler), calls


def test_config_scope_and_secret():
    c = ApicCollector(_cfg(), Settings(_env_file=None))
    assert c.scope == "apic:fab1"
    assert c.config.auth.password.get_secret_value() == "pw"


def test_fetch_logs_in_once_and_paginates(monkeypatch):
    big = [{"fvTenant": {"attributes": {"dn": f"uni/tn-t{i}", "name": f"t{i}"}}} for i in range(1000)]
    tail = [{"fvTenant": {"attributes": {"dn": "uni/tn-last", "name": "last"}}}]
    transport, calls = _mock_apic({"fvTenant": [big, tail]})
    monkeypatch.setattr("hst.collectors.apic._transport", lambda config: transport)
    raw = ApicCollector(_cfg(), Settings(_env_file=None)).fetch()
    assert calls["login"] == 1
    # `capture_bgp` defaults to "all", so the fetch also reads the
    # two BGP observation classes and records their outcomes
    assert set(raw) == {*CLASSES, *CONTRACT_BYPASS_CLASSES, *BGP_CLASSES, RAW_OUTCOMES_KEY}
    assert len(raw["fvTenant"]) == 1001  # both pages, flattened
    assert ("fvTenant", 1) in calls["gets"]  # second page requested
    assert all(len(raw[c]) == 0 for c in CLASSES if c != "fvTenant")
    assert all(len(raw[c]) == 0 for c in BGP_CLASSES)


def test_probe_returns_version(monkeypatch):
    transport, _ = _mock_apic(
        {
            "firmwareCtrlrRunning": [
                [{"firmwareCtrlrRunning": {"attributes": {"version": "6.0(3e)", "dn": "x"}}}]
            ]
        }
    )
    monkeypatch.setattr("hst.collectors.apic._transport", lambda config: transport)
    out = ApicCollector(_cfg(), Settings(_env_file=None)).probe()
    assert "6.0(3e)" in out


def test_login_failure_is_a_clean_error(monkeypatch):
    def handler(request):
        return httpx.Response(401, json={"imdata": [{"error": {"attributes": {"text": "bad credentials"}}}]})

    monkeypatch.setattr("hst.collectors.apic._transport", lambda config: httpx.MockTransport(handler))
    with pytest.raises(RuntimeError, match="login"):
        ApicCollector(_cfg(), Settings(_env_file=None)).probe()


def test_attrs_unwraps():
    assert _attrs({"fvTenant": {"attributes": {"dn": "uni/tn-a"}}}) == {"dn": "uni/tn-a"}


def _mo(cls, **attrs):
    return {cls: {"attributes": attrs}}


RAW = {cls: [] for cls in CLASSES}
RAW["fabricNode"] = [
    _mo(
        "fabricNode",
        dn="topology/pod-1/node-1",
        name="apic1",
        role="controller",
        serial="FCH100AP1C",
        model="APIC-SERVER-M3",
        version="6.0(3e)",
    ),
    _mo(
        "fabricNode",
        dn="topology/pod-1/node-101",
        name="leaf101",
        role="leaf",
        serial="FDO101LEAF",
        model="N9K-C93180YC-FX",
        version="16.0(3e)",
    ),
    _mo(
        "fabricNode",
        dn="topology/pod-1/node-102",
        name="leaf102",
        role="leaf",
        serial="FDO102LEAF",
        model="N9K-C93180YC-FX",
        version="16.0(3e)",
    ),
    _mo(
        "fabricNode",
        dn="topology/pod-1/node-201",
        name="spine201",
        role="spine",
        serial="FDO201SPIN",
        model="N9K-C9336C-FX2",
        version="16.0(3e)",
    ),
]
RAW["topSystem"] = [
    _mo(
        "topSystem",
        dn="topology/pod-1/node-101/sys",
        name="leaf101",
        oobMgmtAddr="10.10.0.101",
        podId="1",
        serial="FDO101LEAF",
    ),
    _mo(
        "topSystem",
        dn="topology/pod-1/node-102/sys",
        name="leaf102",
        oobMgmtAddr="10.10.0.102",
        podId="1",
        serial="FDO102LEAF",
    ),
]
RAW["l1PhysIf"] = [
    _mo("l1PhysIf", dn="topology/pod-1/node-101/sys/phys-[eth1/1]", id="eth1/1", adminSt="up"),
    _mo("l1PhysIf", dn="topology/pod-1/node-101/sys/phys-[eth1/2]", id="eth1/2", adminSt="up"),
    _mo("l1PhysIf", dn="topology/pod-1/node-102/sys/phys-[eth1/1]", id="eth1/1", adminSt="up"),
]
RAW["lldpAdjEp"] = [
    _mo(
        "lldpAdjEp",
        dn="topology/pod-1/node-101/sys/lldp/inst/if-[eth1/2]/adj-1",
        sysName="edge-r1",
        chassisIdV="aa:bb:cc:dd:ee:01",
        portIdV="Gi0/0/0",
    ),
]
RAW["pcAggrIf"] = [
    _mo("pcAggrIf", dn="topology/pod-1/node-101/sys/aggr-[po1]", id="po1"),
]
RAW["cdpAdjEp"] = [
    _mo(
        "cdpAdjEp",
        dn="topology/pod-1/node-101/sys/cdp/inst/if-[eth1/1]/adj-1",
        devId="edge-r9",
        portId="Gi0/0/1",
    ),
]


RAW["fvTenant"] = [_mo("fvTenant", dn="uni/tn-prod", name="prod")]
RAW["fvAp"] = [_mo("fvAp", dn="uni/tn-prod/ap-web", name="web")]
RAW["fvAEPg"] = [
    _mo("fvAEPg", dn="uni/tn-prod/ap-web/epg-fe", name="fe"),
    _mo("fvAEPg", dn="uni/tn-prod/ap-web/epg-be", name="be"),
]
RAW["fvBD"] = [
    _mo("fvBD", dn="uni/tn-prod/BD-web-bd", name="web-bd"),
    _mo("fvBD", dn="uni/tn-prod/BD-orphan-bd", name="orphan-bd"),
]
RAW["fvSubnet"] = [_mo("fvSubnet", dn="uni/tn-prod/BD-web-bd/subnet-[10.1.1.1/24]", ip="10.1.1.1/24")]
RAW["fvCtx"] = [_mo("fvCtx", dn="uni/tn-prod/ctx-prod-vrf", name="prod-vrf", pcEnfPref="Enforced")]
RAW["fvRsCtx"] = [
    _mo("fvRsCtx", dn="uni/tn-prod/BD-web-bd/rsctx", tDn="uni/tn-prod/ctx-prod-vrf"),
    # a BD with no explicit VRF binding, tDn empty
    _mo("fvRsCtx", dn="uni/tn-prod/BD-orphan-bd/rsctx", tDn=""),
]
# The tenant stage derives IN_BD from fvRsBd.
RAW["fvRsBd"] = [
    _mo("fvRsBd", dn="uni/tn-prod/ap-web/epg-fe/rsbd", tDn="uni/tn-prod/BD-web-bd"),
    _mo("fvRsBd", dn="uni/tn-prod/ap-web/epg-be/rsbd", tDn="uni/tn-prod/BD-web-bd"),
]


# OSPF: the L3Out operational classes, on leaf101 in tenant prod's own VRF
# (uni/tn-prod/ctx-prod-vrf). The dn shapes follow apic.py's docs-derived model.
OSPF_AREA_0 = "0.0.0.0"  # noqa: S104 - an OSPF area id
_OSPF_DOM_DN = "topology/pod-1/node-101/sys/ospf/inst-default/dom-prod:prod-vrf"
_OSPF_AREA_DN = f"{_OSPF_DOM_DN}/area-{OSPF_AREA_0}"
_OSPF_IF_DN = f"{_OSPF_AREA_DN}/if-[eth1/1]"
RAW["ospfDom"] = [_mo("ospfDom", dn=_OSPF_DOM_DN, rtrId="10.255.0.1")]
RAW["ospfArea"] = [_mo("ospfArea", dn=_OSPF_AREA_DN, id=OSPF_AREA_0, areaType="regular")]
RAW["ospfIf"] = [_mo("ospfIf", dn=_OSPF_IF_DN, cost="10", nwT="p2p", ctrl="")]
RAW["ospfAdjEp"] = [
    _mo("ospfAdjEp", dn=f"{_OSPF_IF_DN}/adj-10.255.0.2", rtrId="10.255.0.2", addr="10.0.0.2", state="full")
]


def _norm(raw=None):
    from hst.collectors.apic import normalize_apic

    return normalize_apic(raw or RAW, fabric="fab1", l3dom="dc1")


def test_fabric_devices_are_named_by_the_fabric_node_name():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}

    leaf = nodes["dev:leaf101"]
    assert leaf.label == "Device"
    assert leaf.props["hostname"] == "leaf101"
    assert leaf.props["role"] == "leaf"
    assert leaf.props["dn"] == "topology/pod-1/node-101"
    assert leaf.props["mgmt_ip"] == "10.10.0.101"
    assert "dev:apic1" in nodes  # controller too
    fab = [n for n in batch.nodes if n.label == "Fabric"]
    assert len(fab) == 1
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert ("MEMBER_OF", leaf.uid, fab[0].uid) in rels


def test_ports_and_lldp_hints():
    batch = _norm()
    from hst.core import uid as uidmod

    leaf_uid = "dev:leaf101"
    ports = {n.uid: n for n in batch.nodes if n.label == "Port"}
    p12 = ports[f"{leaf_uid}/port/{uidmod.slug('eth1/2')}"]
    assert p12.props["lldp_neighbor_mac"] == "aa:bb:cc:dd:ee:01"
    assert p12.props["lldp_neighbor_name"] == "edge-r1"
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert ("ON", p12.uid, leaf_uid) in rels


def test_lag_port_and_cdp_hints():
    """pcAggrIf -> a Port stamped kind='lag', wired ON its Device like l1PhysIf.
    cdpAdjEp -> cdp_neighbor_name/cdp_neighbor_port land on the existing port,
    as for lldpAdjEp."""
    batch = _norm()
    from hst.core import uid as uidmod

    leaf_uid = "dev:leaf101"
    ports = {n.uid: n for n in batch.nodes if n.label == "Port"}
    lag = ports[f"{leaf_uid}/port/{uidmod.slug('po1')}"]
    assert lag.props["kind"] == "lag"
    assert lag.props["name"] == "po1"
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert ("ON", lag.uid, leaf_uid) in rels
    eth11 = ports[f"{leaf_uid}/port/{uidmod.slug('eth1/1')}"]
    assert eth11.props["cdp_neighbor_name"] == "edge-r9"
    assert eth11.props["cdp_neighbor_port"] == "Gi0/0/1"


def test_tenant_hierarchy_and_vrf():
    batch = _norm()
    from hst.core import uid as uidmod

    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    t = uidmod.aci("fab1", "uni/tn-prod")
    ap = uidmod.aci("fab1", "uni/tn-prod/ap-web")
    fe = uidmod.aci("fab1", "uni/tn-prod/ap-web/epg-fe")
    bd = uidmod.aci("fab1", "uni/tn-prod/BD-web-bd")
    vrf = uidmod.aci("fab1", "uni/tn-prod/ctx-prod-vrf")
    assert nodes[t].label == "Tenant" and nodes[fe].label == "Epg"
    assert ("HAS", t, ap) in rels and ("HAS", ap, fe) in rels
    assert ("IN_VRF", bd, vrf) in rels
    assert ("IN_BD", fe, bd) in rels
    # pcEnfPref is stored lowercased regardless of the fabric's own casing
    assert nodes[vrf].props["pc_enf_pref"] == "enforced"
    pfx = [n for n in batch.nodes if n.label == "Prefix"]
    assert pfx[0].props["cidr"] == "10.1.1.0/24"
    assert pfx[0].props["gateway_ip"] == "10.1.1.1"
    assert pfx[0].props["anchor"] == pfx[0].props["l3dom"]
    assert ("IN", pfx[0].uid, bd) in rels


def test_a_bridge_domain_subnet_is_in_its_bridge_domain_and_never_within_it():
    """Schema v0.31.0: a subnet belongs to its bridge domain by the IN edge an
    Endpoint has to it, the edge the reasoner derives on a classic estate."""
    batch = _norm()
    to_bd = [r for r in batch.rels if r.start_label == "Prefix" and r.end_label == "BridgeDomain"]
    assert to_bd and {r.rel_type for r in to_bd} == {"IN"}


def test_vrf_enforcement_mode_absent_is_absent_not_defaulted():
    """A VRF whose fvCtx row carries no pcEnfPref (an older APIC, or a payload
    that omits it) leaves the property off the node."""
    import copy

    raw = copy.deepcopy(RAW)
    raw["fvCtx"] = raw["fvCtx"] + [
        _mo("fvCtx", dn="uni/tn-prod/ctx-unenforced-vrf", name="unenforced-vrf", pcEnfPref="Unenforced"),
        _mo("fvCtx", dn="uni/tn-prod/ctx-unknown-vrf", name="unknown-vrf"),
    ]
    batch = _norm(raw)
    from hst.core import uid as uidmod

    nodes = {n.uid: n for n in batch.nodes}
    unenforced = nodes[uidmod.aci("fab1", "uni/tn-prod/ctx-unenforced-vrf")]
    unknown = nodes[uidmod.aci("fab1", "uni/tn-prod/ctx-unknown-vrf")]
    assert unenforced.props["pc_enf_pref"] == "unenforced"
    assert "pc_enf_pref" not in unknown.props


def _bypass_of(raw, ctx="uni/tn-prod/ctx-prod-vrf"):
    from hst.core import uid as uidmod

    nodes = {n.uid: n for n in _norm(raw).nodes}
    return nodes[uidmod.aci("fab1", ctx)].props.get("contract_bypass")


def test_contract_bypass_inputs_not_read_are_not_collected():
    """Without the vzAny and ESG classes no VRF states that nothing
    permits its EPG pairs outside their contracts."""
    assert _bypass_of(RAW) == "not-collected"


def test_contract_bypass_flags_vzany_preferred_group_and_esg():
    import copy

    from hst.core.aci_filter import contract_bypass

    raw = copy.deepcopy(RAW)
    for cls in CONTRACT_BYPASS_CLASSES:
        raw[cls] = []
    assert _bypass_of(raw) == ""
    assert contract_bypass(_bypass_of(raw)) is None
    raw["vzAny"] = [_mo("vzAny", dn="uni/tn-prod/ctx-prod-vrf/any", prefGrMemb="disabled")]
    assert _bypass_of(raw) == ""
    raw["vzAny"] = [_mo("vzAny", dn="uni/tn-prod/ctx-prod-vrf/any", prefGrMemb="enabled")]
    raw["vzRsAnyToProv"] = [
        _mo("vzRsAnyToProv", dn="uni/tn-prod/ctx-prod-vrf/any/rsanyToProv-web", tDn="uni/tn-prod/brc-web")
    ]
    raw["fvESg"] = [_mo("fvESg", dn="uni/tn-prod/ap-web/esg-e1", name="e1")]
    raw["fvRsScope"] = [
        _mo("fvRsScope", dn="uni/tn-prod/ap-web/esg-e1/rsscope", tDn="uni/tn-prod/ctx-prod-vrf")
    ]
    assert _bypass_of(raw) == "esg,preferred-group,vzany"
    assert "vzAny" in contract_bypass(_bypass_of(raw))


def test_empty_tdn_never_emits_an_edge():
    """An fvRsCtx row can carry an empty tDn."""
    batch = _norm()
    from hst.core import uid as uidmod

    orphan_bd = uidmod.aci("fab1", "uni/tn-prod/BD-orphan-bd")
    nodes = {n.uid: n for n in batch.nodes}
    assert nodes[orphan_bd].label == "BridgeDomain"
    assert uidmod.aci("fab1", "") not in {r.end_uid for r in batch.rels}
    assert not [r for r in batch.rels if r.end_uid.endswith(":")]


def test_parent_dn_handles_bracketed_rn():
    from hst.collectors.apic import _parent_dn

    assert _parent_dn("uni/tn-prod/ap-web/epg-fe") == "uni/tn-prod/ap-web"
    assert _parent_dn("uni/tn-prod/BD-web-bd/subnet-[10.1.1.1/24]") == "uni/tn-prod/BD-web-bd"
    # nested brackets (rspathAtt wraps a pathep dn that has its own '-[...]')
    assert (
        _parent_dn("uni/tn-prod/ap-web/epg-fe/rspathAtt-[topology/pod-1/paths-101/pathep-[eth1/1]]")
        == "uni/tn-prod/ap-web/epg-fe"
    )


RAW["vzBrCP"] = [_mo("vzBrCP", dn="uni/tn-prod/brc-web-to-be", name="web-to-be")]
RAW["vzSubj"] = [_mo("vzSubj", dn="uni/tn-prod/brc-web-to-be/subj-http", name="http")]
RAW["vzRsSubjFiltAtt"] = [
    _mo(
        "vzRsSubjFiltAtt",
        dn="uni/tn-prod/brc-web-to-be/subj-http/rssubjFiltAtt-http-8080",
        tDn="uni/tn-prod/flt-http-8080",
        action="permit",
    )
]
RAW["vzFilter"] = [_mo("vzFilter", dn="uni/tn-prod/flt-http-8080", name="http-8080")]
RAW["vzEntry"] = [
    _mo(
        "vzEntry",
        dn="uni/tn-prod/flt-http-8080/e-tcp-8080",
        name="tcp-8080",
        prot="tcp",
        dFromPort="8080",
        dToPort="8080",
        etherT="ip",
    )
]
RAW["fvRsProv"] = [
    _mo("fvRsProv", dn="uni/tn-prod/ap-web/epg-be/rsprov-web-to-be", tDn="uni/tn-prod/brc-web-to-be")
]
RAW["fvRsCons"] = [
    _mo("fvRsCons", dn="uni/tn-prod/ap-web/epg-fe/rscons-web-to-be", tDn="uni/tn-prod/brc-web-to-be")
]
RAW["l3extOut"] = [_mo("l3extOut", dn="uni/tn-prod/out-wan", name="wan")]
RAW["l3extInstP"] = [_mo("l3extInstP", dn="uni/tn-prod/out-wan/instP-internet", name="internet")]
RAW["l3extRsEctx"] = [_mo("l3extRsEctx", dn="uni/tn-prod/out-wan/rsectx", tDn="uni/tn-prod/ctx-prod-vrf")]
RAW["l3extSubnet"] = [
    _mo(
        "l3extSubnet",
        dn="uni/tn-prod/out-wan/instP-internet/extsubnet-[198.51.100.0/24]",
        ip="198.51.100.0/24",
        scope="import-security",
    ),
    _mo(
        "l3extSubnet",
        dn="uni/tn-prod/out-wan/instP-internet/extsubnet-[203.0.113.0/24]",
        ip="203.0.113.0/24",
        scope="export-rtctrl",
    ),
]
RAW["fvRsCons"].append(
    _mo(
        "fvRsCons",
        dn="uni/tn-prod/out-wan/instP-internet/rscons-web-to-be",
        tDn="uni/tn-prod/brc-web-to-be",
    )
)
# vzSubj returns subjects of every contract flavor, including out-of-band
# contracts (vzOOBBrCP) that the collector does not fetch.
RAW["vzSubj"].append(_mo("vzSubj", dn="uni/tn-common/oobbrc-default/subj-default", name="default"))
RAW["vzRsSubjFiltAtt"].append(
    _mo(
        "vzRsSubjFiltAtt",
        dn="uni/tn-common/oobbrc-default/subj-default/rssubjFiltAtt-x",
        tDn="uni/tn-prod/flt-http-8080",
    )
)


def test_contract_chain_and_direction():
    batch = _norm()
    from hst.core import uid as uidmod

    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    t = uidmod.aci("fab1", "uni/tn-prod")
    ct = uidmod.aci("fab1", "uni/tn-prod/brc-web-to-be")
    subj = uidmod.aci("fab1", "uni/tn-prod/brc-web-to-be/subj-http")
    flt = uidmod.aci("fab1", "uni/tn-prod/flt-http-8080")
    entry = uidmod.aci("fab1", "uni/tn-prod/flt-http-8080/e-tcp-8080")
    fe = uidmod.aci("fab1", "uni/tn-prod/ap-web/epg-fe")
    be = uidmod.aci("fab1", "uni/tn-prod/ap-web/epg-be")
    assert ("HAS", t, ct) in rels  # Tenant -[:HAS]-> Contract
    assert ("HAS", ct, subj) in rels
    assert ("USES_FILTER", subj, flt) in rels
    uses_filter = next(
        r for r in batch.rels if (r.rel_type, r.start_uid, r.end_uid) == ("USES_FILTER", subj, flt)
    )
    assert uses_filter.props["action"] == "permit"
    assert ("HAS", flt, entry) in rels
    assert ("PROVIDES", be, ct) in rels  # be provides, fe consumes
    assert ("CONSUMES", fe, ct) in rels
    entries = {n.uid: n for n in batch.nodes if n.label == "FilterEntry"}
    assert entries[entry].props["d_from_port"] == "8080"
    # the schema names, which gates/aci.py reads
    assert entries[entry].props["proto"] == "tcp"
    assert "prot" not in entries[entry].props


def test_oob_contract_subjects_are_skipped():
    """A vzSubj subject with no vzBrCP row is dropped with everything under it."""
    batch = _norm()
    from hst.core import uid as uidmod

    oob_subj = uidmod.aci("fab1", "uni/tn-common/oobbrc-default/subj-default")
    assert oob_subj not in {n.uid for n in batch.nodes}
    assert oob_subj not in {r.start_uid for r in batch.rels}
    assert oob_subj not in {r.end_uid for r in batch.rels}


def test_l3out_hierarchy():
    batch = _norm()
    from hst.core import uid as uidmod

    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    out = uidmod.aci("fab1", "uni/tn-prod/out-wan")
    ext = uidmod.aci("fab1", "uni/tn-prod/out-wan/instP-internet")
    t = uidmod.aci("fab1", "uni/tn-prod")
    assert ("PART_OF", out, t) in rels and ("PART_OF", ext, out) in rels


def test_an_external_epg_has_its_vrf_its_security_subnets_and_its_contracts():
    batch = _norm()
    from hst.core import uid as uidmod

    out = uidmod.aci("fab1", "uni/tn-prod/out-wan")
    ext = uidmod.aci("fab1", "uni/tn-prod/out-wan/instP-internet")
    rels = {(r.rel_type, r.start_label, r.start_uid, r.end_label, r.end_uid) for r in batch.rels}
    assert ("IN_VRF", "L3Out", out, "VrfInstance", uidmod.aci("fab1", "uni/tn-prod/ctx-prod-vrf")) in rels
    matched = {end for kind, _label, start, _end_label, end in rels if kind == "MATCHES" and start == ext}
    # the subnet with the scope export-rtctrl classifies no packet
    assert matched == {uidmod.aci("fab1", "uni/tn-prod/out-wan/instP-internet/extsubnet-[198.51.100.0/24]")}
    (prefix,) = [n for n in batch.nodes if n.uid in matched]
    assert (prefix.label, prefix.props["cidr"]) == ("Prefix", "198.51.100.0/24")
    contract = uidmod.aci("fab1", "uni/tn-prod/brc-web-to-be")
    assert ("CONSUMES", "ExtEpg", ext, "Contract", contract) in rels
    assert not [r for r in rels if r[0] == "CONSUMES" and r[1] == "Epg" and r[2] == ext]


RAW["vnsAbsGraph"] = [_mo("vnsAbsGraph", dn="uni/tn-prod/AbsGraph-fw-insert", name="fw-insert")]
RAW["vnsGraphInst"] = [
    _mo(
        "vnsGraphInst",
        dn="uni/tn-prod/GraphInst_C-[uni/tn-prod/brc-web-to-be]-G-[uni/tn-prod/AbsGraph-fw-insert]-S-[uni/tn-prod]",
        ctrctDn="uni/tn-prod/brc-web-to-be",
        graphDn="uni/tn-prod/AbsGraph-fw-insert",
    )
]
RAW["vnsSvcRedirectPol"] = [
    _mo("vnsSvcRedirectPol", dn="uni/tn-prod/svcCont/svcRedirectPol-to-fw", name="to-fw")
]
RAW["vnsRedirectDest"] = [
    _mo(
        "vnsRedirectDest",
        dn="uni/tn-prod/svcCont/svcRedirectPol-to-fw/RedirectDest_ip-[10.1.9.1]",
        ip="10.1.9.1",
        mac="00:50:56:AA:BB:01",
    )
]
RAW["fvCEp"] = [
    _mo("fvCEp", dn="uni/tn-prod/ap-web/epg-fe/cep-00:50:56:11:22:33", mac="00:50:56:11:22:33", name="fe-vm1")
]
RAW["fvIp"] = [
    _mo("fvIp", dn="uni/tn-prod/ap-web/epg-fe/cep-00:50:56:11:22:33/ip-[10.1.1.10]", addr="10.1.1.10"),
    # the same cep with an IPv6 address
    _mo("fvIp", dn="uni/tn-prod/ap-web/epg-fe/cep-00:50:56:11:22:33/ip-[2001:db8::10]", addr="2001:db8::10"),
]
RAW["fvRsPathAtt"] = [
    _mo(
        "fvRsPathAtt",
        dn="uni/tn-prod/ap-web/epg-fe/rspathAtt-[topology/pod-1/paths-101/pathep-[eth1/1]]",
        tDn="topology/pod-1/paths-101/pathep-[eth1/1]",
        encap="vlan-100",
        mode="regular",
    ),
    # vPC: protpaths-<id1>-<id2> binds both leaves via one port-channel pathep.
    _mo(
        "fvRsPathAtt",
        dn="uni/tn-prod/ap-web/epg-be/rspathAtt-[topology/pod-1/protpaths-101-102/pathep-[po-web]]",
        tDn="topology/pod-1/protpaths-101-102/pathep-[po-web]",
        encap="vlan-200",
    ),
    # node-999 is not in fabricNode.
    _mo(
        "fvRsPathAtt",
        dn="uni/tn-prod/ap-web/epg-fe/rspathAtt-[topology/pod-1/paths-999/pathep-[eth9/9]]",
        tDn="topology/pod-1/paths-999/pathep-[eth9/9]",
        encap="vlan-999",
    ),
]
RAW["vzRsSubjGraphAtt"] = [
    _mo(
        "vzRsSubjGraphAtt",
        dn="uni/tn-prod/brc-web-to-be/subj-http/rsSubjGraphAtt",
        tnVnsAbsGraphName="fw-insert",
        tDn="uni/tn-prod/AbsGraph-fw-insert",
    )
]
RAW["fvRsDomAtt"] = [
    _mo(
        "fvRsDomAtt",
        dn="uni/tn-prod/ap-web/epg-fe/rsdomAtt-[uni/vmmp-VMware/dom-dvs1]",
        tDn="uni/vmmp-VMware/dom-dvs1",
    ),
    # physical domain: no DvPortgroup/VMM_BINDING
    _mo("fvRsDomAtt", dn="uni/tn-prod/ap-web/epg-fe/rsdomAtt-[uni/phys-phys1]", tDn="uni/phys-phys1"),
]


def test_pbr_and_service_graph():
    batch = _norm()
    from hst.core import uid as uidmod

    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    subj = uidmod.aci("fab1", "uni/tn-prod/brc-web-to-be/subj-http")
    tmpl = uidmod.aci("fab1", "uni/tn-prod/AbsGraph-fw-insert")
    assert ("APPLIES_GRAPH", subj, tmpl) in rels  # vzRsSubjGraphAtt, not Contract
    # ServiceGraphTemplate.name is what gates/aci.py's _contract_rows reads via
    # sg.name to report the redirect in an indeterminate verdict's reason.
    graph_tmpl = next(n for n in batch.nodes if n.label == "ServiceGraphTemplate")
    assert graph_tmpl.props["name"] == "fw-insert"
    gi = next(n for n in batch.nodes if n.label == "ServiceGraphInstance")
    assert gi.props["ctrct_dn"] == "uni/tn-prod/brc-web-to-be"  # linkage kept as a property
    pol = next(n for n in batch.nodes if n.label == "PbrPolicy")
    dest = next(n for n in batch.nodes if n.label == "PbrDest")
    assert dest.props["ip"] == "10.1.9.1"
    assert ("HAS_DEST", pol.uid, dest.uid) in rels


def test_endpoints_and_bindings():
    batch = _norm()
    from hst.core import uid as uidmod

    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    fe = uidmod.aci("fab1", "uni/tn-prod/ap-web/epg-fe")
    eps = [n for n in batch.nodes if n.label == "Endpoint"]
    # Endpoint.mac is the canonical 12-hex form (collectors/util.py canonical_mac).
    assert eps[0].props["mac"] == "005056112233"
    # Endpoint identity is the mac within its flood domain: the scope is the EPG's
    # bridge domain, resolved through fvRsBd.
    assert eps[0].uid == uidmod.endpoint(uidmod.aci("fab1", "uni/tn-prod/BD-web-bd"), "00:50:56:11:22:33")
    assert eps[0].uid != uidmod.endpoint("dc1", "00:50:56:11:22:33")
    assert ("IN_EPG", eps[0].uid, fe) in rels
    ips = {n.props.get("ip") for n in batch.nodes if n.label == "IpAddress"}
    assert "10.1.1.10" in ips
    # HAS_IP is scoped to the tenant VRF behind the endpoint's EPG (EPG -> BD -> Ctx).
    ip_uid = uidmod.ip("dc1:uni/tn-prod/ctx-prod-vrf", "10.1.1.10")
    assert ("HAS_IP", eps[0].uid, ip_uid) in rels
    ip_nodes = {n.props["ip"]: n for n in batch.nodes if n.label == "IpAddress"}
    assert ip_nodes["10.1.1.10"].props["af"] == 4
    assert ip_nodes["2001:db8::10"].props["af"] == 6
    assert ip_nodes["10.1.1.10"].props["anchor"] == ip_nodes["10.1.1.10"].props["l3dom"]
    leaf101_port = f"dev:leaf101/port/{uidmod.slug('eth1/1')}"
    assert ("STATIC_BINDING", fe, leaf101_port) in rels
    assert ("ON", leaf101_port, "dev:leaf101") in rels
    static_binding = next(
        r for r in batch.rels if (r.rel_type, r.start_uid, r.end_uid) == ("STATIC_BINDING", fe, leaf101_port)
    )
    assert static_binding.props["mode"] == "regular"
    dvpg = [n for n in batch.nodes if n.label == "DvPortgroup"]
    assert dvpg and ("VMM_BINDING", fe, dvpg[0].uid) in rels
    assert len(dvpg) == 1  # the physical-domain fvRsDomAtt row is skipped, not turned
    # into a second DvPortgroup


def test_the_same_mac_in_two_bridge_domains_stays_two_endpoints():
    """Both bridge domains sit in the same tenant VRF."""
    import copy

    from hst.core import uid as uidmod

    mac = "00:50:56:11:22:33"  # the mac of RAW's fvCEp, in BD-web-bd
    raw = copy.deepcopy(RAW)
    raw.setdefault("fvBD", []).append(
        {"fvBD": {"attributes": {"dn": "uni/tn-prod/BD-db-bd", "name": "db-bd"}}}
    )
    raw.setdefault("fvRsCtx", []).append(
        {"fvRsCtx": {"attributes": {"dn": "uni/tn-prod/BD-db-bd/rsctx", "tDn": "uni/tn-prod/ctx-prod-vrf"}}}
    )
    raw.setdefault("fvAEPg", []).append(
        {"fvAEPg": {"attributes": {"dn": "uni/tn-prod/ap-db/epg-db", "name": "db"}}}
    )
    raw.setdefault("fvRsBd", []).append(
        {"fvRsBd": {"attributes": {"dn": "uni/tn-prod/ap-db/epg-db/rsbd", "tDn": "uni/tn-prod/BD-db-bd"}}}
    )
    raw.setdefault("fvCEp", []).append(
        {"fvCEp": {"attributes": {"dn": f"uni/tn-prod/ap-db/epg-db/cep-{mac}", "mac": mac, "name": "db-vm1"}}}
    )

    batch = normalize_apic(raw, fabric="fab1", l3dom="dc1")
    eps = [n for n in batch.nodes if n.label == "Endpoint" and n.props["mac"] == "005056112233"]
    assert len(eps) == 2, "the two bridge domains merged onto one endpoint node"
    assert {n.uid for n in eps} == {
        uidmod.endpoint(uidmod.aci("fab1", "uni/tn-prod/BD-web-bd"), mac),
        uidmod.endpoint(uidmod.aci("fab1", "uni/tn-prod/BD-db-bd"), mac),
    }
    in_epg = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IN_EPG"}
    for ep in eps:
        assert len([pair for pair in in_epg if pair[0] == ep.uid]) == 1


def test_an_endpoint_whose_epg_has_no_bridge_domain_falls_back_to_the_epg(caplog):
    """A fabric that ships no usable fvRsBd for the EPG scopes the endpoint on the
    EPG dn, never on the site."""
    import copy
    import logging

    from hst.core import uid as uidmod

    mac = "00:50:56:99:88:77"
    raw = copy.deepcopy(RAW)
    raw.setdefault("fvAEPg", []).append(
        {"fvAEPg": {"attributes": {"dn": "uni/tn-prod/ap-web/epg-nobd", "name": "nobd"}}}
    )
    raw.setdefault("fvCEp", []).append(
        {
            "fvCEp": {
                "attributes": {"dn": f"uni/tn-prod/ap-web/epg-nobd/cep-{mac}", "mac": mac, "name": "orphan"}
            }
        }
    )

    with caplog.at_level(logging.WARNING):
        batch = normalize_apic(raw, fabric="fab1", l3dom="dc1")
    ep = next(n for n in batch.nodes if n.label == "Endpoint" and n.props["mac"] == "005056998877")
    assert ep.uid == uidmod.endpoint(uidmod.aci("fab1", "uni/tn-prod/ap-web/epg-nobd"), mac)
    assert "no bridge domain resolved for EPG" in caplog.text


def test_an_endpoint_is_in_the_bridge_domain_of_its_epg():
    """An endpoint is IN the flood domain of its EPG, the segment the network map
    and the segment counts join on. An EPG with no usable fvRsBd gives its
    endpoint no bridge domain."""
    import copy

    from hst.core import uid as uidmod

    batch = _norm()
    bd = uidmod.aci("fab1", "uni/tn-prod/BD-web-bd")
    ep = uidmod.endpoint(bd, "00:50:56:11:22:33")
    in_bd = {
        (r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IN" and r.end_label == "BridgeDomain"
    }
    assert (ep, bd) in in_bd

    raw = copy.deepcopy(RAW)
    raw.setdefault("fvAEPg", []).append({"fvAEPg": {"attributes": {"dn": "uni/tn-prod/ap-web/epg-nobd"}}})
    mac = "00:50:56:99:88:77"
    raw.setdefault("fvCEp", []).append(
        {"fvCEp": {"attributes": {"dn": f"uni/tn-prod/ap-web/epg-nobd/cep-{mac}", "mac": mac}}}
    )
    batch = normalize_apic(raw, fabric="fab1", l3dom="dc1")
    orphan = uidmod.endpoint(uidmod.aci("fab1", "uni/tn-prod/ap-web/epg-nobd"), mac)
    assert not [r for r in batch.rels if r.rel_type == "IN" and r.start_uid == orphan]


def test_fvcep_with_unparseable_mac_is_skipped_and_logged(caplog):
    """A row with an unparseable mac is dropped with a logged warning."""
    import copy

    raw = copy.deepcopy(RAW)
    raw["fvCEp"].append(
        {
            "fvCEp": {
                "attributes": {
                    "dn": "uni/tn-prod/ap-web/epg-fe/cep-not-a-mac",
                    "mac": "not-a-mac",
                    "name": "bogus",
                }
            }
        }
    )
    batch = normalize_apic(raw, fabric="fab1", l3dom="dc1")
    assert all(n.props.get("mac") != "not-a-mac" for n in batch.nodes if n.label == "Endpoint")
    assert "apic: skipping fvCEp" in caplog.text


def test_every_device_reports_its_pod_and_places_none_itself():
    """The collector reports the pod each device sits in and places no device
    in a Site. The operator binds the pod to a Site and
    apply_site_assignments writes the edge."""
    batch = _norm()
    devices = [n for n in batch.nodes if n.label == "Device"]
    assert devices  # fixture ships leaf/spine/controller
    assert not [n for n in batch.nodes if n.label == "Site"]
    assert not [r for r in batch.rels if r.rel_type == "LOCATED_IN"]
    assert all(d.props["reported_location"].startswith("fab1/topology/pod-") for d in devices)


def test_vpc_protpaths_binds_both_leaves():
    batch = _norm()
    from hst.core import uid as uidmod

    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    be = uidmod.aci("fab1", "uni/tn-prod/ap-web/epg-be")
    port101 = f"dev:leaf101/port/{uidmod.slug('po-web')}"
    port102 = f"dev:leaf102/port/{uidmod.slug('po-web')}"
    assert ("STATIC_BINDING", be, port101) in rels
    assert ("STATIC_BINDING", be, port102) in rels
    ports = {n.uid for n in batch.nodes if n.label == "Port"}
    assert port101 in ports and port102 in ports
    assert ("ON", port101, "dev:leaf101") in rels
    assert ("ON", port102, "dev:leaf102") in rels


def test_fvrspathatt_skip_counter_logs_to_stderr(caplog):
    """A fvRsPathAtt row whose path references a node-id absent from fabricNode
    is skipped, and the skip count is reported once, to stderr."""
    batch = _norm()
    assert ("apic: skipped 1 fvRsPathAtt rows referencing nodes outside fabricNode") in caplog.text
    ports = {n.uid for n in batch.nodes if n.label == "Port"}
    assert not any(p.endswith("/port/eth9-9") for p in ports)


def test_full_batch_loads_shape():
    """The whole fixture normalizes into one coherent batch: every rel endpoint
    exists as a node in the batch or is a Port on a fixture device."""
    batch = _norm()
    node_uids = {n.uid for n in batch.nodes}
    dangling = [
        (r.rel_type, r.start_uid, r.end_uid)
        for r in batch.rels
        if r.start_uid not in node_uids or r.end_uid not in node_uids
    ]
    assert not dangling, dangling
    assert batch.source == "apic" and batch.scope == "apic:fab1"
    by_label = {}
    for n in batch.nodes:
        by_label[n.label] = by_label.get(n.label, 0) + 1
    assert by_label["Device"] == 4 and by_label["Epg"] == 2
    assert by_label["Contract"] == 1 and by_label["PbrDest"] == 1


# The test reads captures from a directory that `.gitignore` excludes.
# Captures, scrubbed or not, are not committed.
CAPTURE = pathlib.Path(__file__).resolve().parent.parent / "data/raw/apic/first-contact"


@pytest.mark.skipif(not CAPTURE.exists(), reason="no first-contact capture on this machine")
def test_first_contact_capture_replays_clean():
    """The capture normalizes into one batch with no dangling relationship."""
    raw = {p.stem: json.loads(p.read_text()) for p in CAPTURE.glob("*.json")}
    batch = _norm(raw)
    node_uids = {n.uid for n in batch.nodes}
    dangling = [r for r in batch.rels if r.start_uid not in node_uids or r.end_uid not in node_uids]
    assert not dangling
    for n in batch.nodes:
        if n.label == "IpAddress" and ":" in n.props.get("ip", ""):
            assert n.props["af"] == 6


def test_two_tenants_with_the_same_address_do_not_merge():
    """The chain EPG -(fvRsBd)-> BD -(fvRsCtx)-> Ctx keeps the tenants apart."""
    import copy

    raw = copy.deepcopy(RAW)
    # a second tenant, its own VRF/BD/EPG, reusing 10.1.1.10
    raw.setdefault("fvCtx", []).append(
        {"fvCtx": {"attributes": {"dn": "uni/tn-other/ctx-prod-vrf", "name": "prod-vrf"}}}
    )
    raw.setdefault("fvBD", []).append({"fvBD": {"attributes": {"dn": "uni/tn-other/BD-app", "name": "app"}}})
    raw.setdefault("fvRsCtx", []).append(
        {"fvRsCtx": {"attributes": {"dn": "uni/tn-other/BD-app/rsctx", "tDn": "uni/tn-other/ctx-prod-vrf"}}}
    )
    raw.setdefault("fvAEPg", []).append(
        {"fvAEPg": {"attributes": {"dn": "uni/tn-other/ap-a/epg-a", "name": "a"}}}
    )
    raw.setdefault("fvRsBd", []).append(
        {"fvRsBd": {"attributes": {"dn": "uni/tn-other/ap-a/epg-a/rsbd", "tDn": "uni/tn-other/BD-app"}}}
    )
    raw.setdefault("fvCEp", []).append(
        {
            "fvCEp": {
                "attributes": {
                    "dn": "uni/tn-other/ap-a/epg-a/cep-00:50:56:AA:BB:CC",
                    "mac": "00:50:56:AA:BB:CC",
                    "name": "dup",
                }
            }
        }
    )
    raw.setdefault("fvIp", []).append(
        {
            "fvIp": {
                "attributes": {
                    "dn": "uni/tn-other/ap-a/epg-a/cep-00:50:56:AA:BB:CC/ip-[10.1.1.10]",
                    "addr": "10.1.1.10",
                }
            }
        }
    )

    batch = normalize_apic(raw, fabric="fab1", l3dom="dc1")
    same = [n for n in batch.nodes if n.label == "IpAddress" and n.props["ip"] == "10.1.1.10"]
    assert len(same) == 2, "the two tenants merged onto one address node"
    assert len({n.uid for n in same}) == 2
    assert {n.props["l3dom"] for n in same} == {
        "dc1:uni/tn-prod/ctx-prod-vrf",
        "dc1:uni/tn-other/ctx-prod-vrf",
    }


def test_an_incomplete_vrf_chain_falls_back_to_the_l3dom():
    """APIC ships rs objects with an empty tDn (unbound BD, default ctx)."""
    import copy

    raw = copy.deepcopy(RAW)
    raw["fvRsBd"] = [
        {"fvRsBd": {"attributes": {"dn": d["fvRsBd"]["attributes"]["dn"], "tDn": ""}}}
        for d in raw.get("fvRsBd", [])
    ]
    batch = normalize_apic(raw, fabric="fab1", l3dom="dc1")
    ips = [n for n in batch.nodes if n.label == "IpAddress"]
    assert ips and all(n.props["l3dom"] == "dc1" for n in ips)


def test_a_lapsed_token_is_re_logged_in_and_the_page_retried(monkeypatch):
    state = {"logins": 0, "gets": 0, "reject_next": True}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/aaaLogin.json":
            state["logins"] += 1
            return httpx.Response(
                200,
                json={
                    "imdata": [
                        {
                            "aaaLogin": {
                                "attributes": {
                                    "token": f"tok{state['logins']}",
                                    "refreshTimeoutSeconds": "600",
                                }
                            }
                        }
                    ]
                },
            )
        state["gets"] += 1
        if state["reject_next"]:
            state["reject_next"] = False
            return httpx.Response(403, json={"imdata": []})
        return httpx.Response(200, json={"imdata": []})

    monkeypatch.setattr("hst.collectors.apic._transport", lambda config: httpx.MockTransport(handler))
    c = ApicCollector(_cfg(), Settings(_env_file=None))
    client = c._client()
    try:
        rows = c._get_class(client, "fvTenant")
    finally:
        client.close()
    assert rows == []
    assert state["logins"] == 2, "the 403 should have triggered a fresh login"
    assert state["gets"] == 2, "the page should have been retried after re-login"


def test_a_second_rejection_is_raised(monkeypatch):

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/aaaLogin.json":
            return httpx.Response(200, json={"imdata": [{"aaaLogin": {"attributes": {"token": "t"}}}]})
        return httpx.Response(403, json={"imdata": []})

    monkeypatch.setattr("hst.collectors.apic._transport", lambda config: httpx.MockTransport(handler))
    c = ApicCollector(_cfg(), Settings(_env_file=None))
    client = c._client()
    try:
        with pytest.raises(httpx.HTTPStatusError):
            c._get_class(client, "fvTenant")
    finally:
        client.close()


def _mock_apic_with_total(cls: str, rows: list[dict], total_count: int, monkeypatch) -> ApicCollector:
    """A single-page transport reporting an explicit totalCount, independent of
    the rows it returns."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/aaaLogin.json":
            return httpx.Response(200, json={"imdata": [{"aaaLogin": {"attributes": {"token": "tok"}}}]})
        page = int(request.url.params.get("page", "0"))
        body = rows if page == 0 else []
        return httpx.Response(200, json={"imdata": body, "totalCount": str(total_count)})

    monkeypatch.setattr("hst.collectors.apic._transport", lambda config: httpx.MockTransport(handler))
    return ApicCollector(_cfg(), Settings(_env_file=None))


def test_page_short_of_reported_total_raises(monkeypatch):
    """A class query reports totalCount=3 and returns 2 rows."""
    rows = [_mo("fvTenant", dn="uni/tn-a", name="a"), _mo("fvTenant", dn="uni/tn-b", name="b")]
    c = _mock_apic_with_total("fvTenant", rows, total_count=3, monkeypatch=monkeypatch)
    client = c._client()
    try:
        with pytest.raises(RuntimeError, match="fvTenant: page total 3 not covered"):
            c._get_class(client, "fvTenant")
    finally:
        client.close()


def test_page_matching_reported_total_passes(monkeypatch):
    rows = [_mo("fvTenant", dn="uni/tn-a", name="a"), _mo("fvTenant", dn="uni/tn-b", name="b")]
    c = _mock_apic_with_total("fvTenant", rows, total_count=2, monkeypatch=monkeypatch)
    client = c._client()
    try:
        result = c._get_class(client, "fvTenant")
    finally:
        client.close()
    assert len(result) == 2


def test_page_with_no_total_count_keeps_short_page_termination(monkeypatch, caplog):
    """A reply with no totalCount ends at the short page and is logged."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/aaaLogin.json":
            return httpx.Response(200, json={"imdata": [{"aaaLogin": {"attributes": {"token": "tok"}}}]})
        rows = [_mo("fvTenant", dn="uni/tn-a", name="a")] if request.url.params.get("page") == "0" else []
        return httpx.Response(200, json={"imdata": rows})

    monkeypatch.setattr("hst.collectors.apic._transport", lambda config: httpx.MockTransport(handler))
    c = ApicCollector(_cfg(), Settings(_env_file=None))
    client = c._client()
    try:
        result = c._get_class(client, "fvTenant")
    finally:
        client.close()
    assert len(result) == 1
    assert "apic: fvTenant page reply carries no totalCount" in caplog.text


# --- OSPF: the L3Out operational classes --------------------------------------------------


def test_ospf_process_carries_router_id_and_resolves_its_vrf_from_the_dom_name():
    batch = _norm()
    from hst.core import uid as uidmod

    dev = "dev:leaf101"
    rpu = uidmod.routing_process(dev, "prod:prod-vrf", "ospf")
    procs = {
        n.uid: n.props for n in batch.nodes if n.label == "RoutingProcess" and n.props.get("proto") == "ospf"
    }
    assert procs[rpu]["router_id"] == "10.255.0.1"
    in_vrf = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IN_VRF"}
    assert (rpu, uidmod.aci("fab1", "uni/tn-prod/ctx-prod-vrf")) in in_vrf


def test_ospf_area_carries_its_type_and_hangs_off_its_process():
    batch = _norm()
    from hst.core import uid as uidmod

    dev = "dev:leaf101"
    rpu = uidmod.routing_process(dev, "prod:prod-vrf", "ospf")
    au = uidmod.ospf_area(rpu, OSPF_AREA_0)
    areas = {n.uid: n.props for n in batch.nodes if n.label == "OspfArea"}
    assert areas[au]["type"] == "normal"
    has = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "HAS"}
    assert (rpu, au) in has


def test_ospf_interface_mints_an_interface_node_and_lands_in_area():
    batch = _norm()
    from hst.core import uid as uidmod

    dev = "dev:leaf101"
    rpu = uidmod.routing_process(dev, "prod:prod-vrf", "ospf")
    au = uidmod.ospf_area(rpu, OSPF_AREA_0)
    iu = uidmod.interface(dev, "eth1/1")
    ifaces = {n.uid: n.props for n in batch.nodes if n.label == "Interface"}
    assert ifaces[iu]["name"] == "eth1/1"
    on = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ON"}
    assert (iu, dev) in on
    in_area = [r for r in batch.rels if r.rel_type == "IN_AREA" and r.start_uid == iu]
    assert len(in_area) == 1
    assert in_area[0].end_uid == au
    assert (in_area[0].props["cost"], in_area[0].props["network_type"]) == (10, "point-to-point")
    assert in_area[0].props["passive"] is False


def test_ospf_adjacency_endpoints_its_interface_and_carries_the_neighbor():
    batch = _norm()
    from hst.core import uid as uidmod

    dev = "dev:leaf101"
    rpu = uidmod.routing_process(dev, "prod:prod-vrf", "ospf")
    iu = uidmod.interface(dev, "eth1/1")
    adju = uidmod.ospf_adjacency(rpu, iu, "10.255.0.2")
    adjacencies = {n.uid: n.props for n in batch.nodes if n.label == "OspfAdjacency"}
    adj = adjacencies[adju]
    assert adj["state"] == "FULL"
    assert adj["area"] == OSPF_AREA_0
    assert adj["neighbor_router_id"] == "10.255.0.2"
    assert adj["neighbor_ip"] == "10.0.0.2"
    assert adj["local_interface"] == "eth1/1"
    endpoints = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENDPOINT"}
    assert (adju, iu) in endpoints


def test_an_ospf_dom_naming_the_infra_vrf_gets_no_in_vrf_edge():
    """`overlay-1` carries no tenant prefix and does not match the
    "<tenant>:<vrf>" convention `_ospf_ctx_dn` reads."""
    import copy

    raw = copy.deepcopy(RAW)
    raw["ospfDom"] = [
        _mo(
            "ospfDom",
            dn="topology/pod-1/node-101/sys/ospf/inst-default/dom-overlay-1",
            rtrId="10.255.0.9",
        )
    ]
    raw["ospfArea"] = []
    raw["ospfIf"] = []
    raw["ospfAdjEp"] = []
    batch = _norm(raw)
    from hst.core import uid as uidmod

    dev = "dev:leaf101"
    rpu = uidmod.routing_process(dev, "overlay-1", "ospf")
    procs = {n.uid for n in batch.nodes if n.label == "RoutingProcess"}
    assert rpu in procs
    assert not [r for r in batch.rels if r.rel_type == "IN_VRF" and r.start_uid == rpu]


def test_ospf_lsdb_is_declared_not_captured_on_every_run():
    """The class model of this collector has no link-state-database class."""
    c = ApicCollector(_cfg(), Settings(_env_file=None))
    outcomes = c.table_outcomes(RAW)
    assert outcomes["ospf_lsdb"].status == "not-captured"
    assert outcomes["ospf_lsdb"].detail
    assert "ospf_lsdb" in c.SIDE_TABLES


# --- BGP session observations: bgpPeerEntry / bgpPeerAfEntry ------------------------------
#
# The dn nesting (`.../sys/bgp/inst/dom-<tenant>:<ctx>/peer-[<ip>]`, with
# `/af-[<afi>-<safi>]` for the child `bgpPeerAfEntry`) and the `operSt`
# attribute are apic.py's documented shape for these classes, not confirmed
# against a capture.
#
# Reuses the fabric's own leaf101/leaf102 (`FDO101LEAF`/`FDO102LEAF`) and the
# "prod" tenant's "prod-vrf" VRF from the module `RAW` fixture above.
# PEER_A is a complete session on leaf101, in the fabric's own tenant
# VRF; PEER_B is on leaf102 with a `dom-` value carrying no ":" (the fallback
# to the common tenant's default VRF); PEER_C has a peer entry but no
# address-family child; PEER_D's node is not in `fabricNode`.

BGP_PEER_A, BGP_PEER_B, BGP_PEER_C, BGP_PEER_D = "203.0.113.2", "198.51.100.9", "203.0.113.3", "203.0.113.4"

RAW_BGP: dict[str, list] = {
    "bgpPeerEntry": [
        _mo(
            "bgpPeerEntry",
            dn=f"topology/pod-1/node-101/sys/bgp/inst/dom-prod:prod-vrf/peer-[{BGP_PEER_A}]",
            operSt="established",
        ),
        _mo(
            "bgpPeerEntry",
            dn=f"topology/pod-1/node-102/sys/bgp/inst/dom-default/peer-[{BGP_PEER_B}]",
            operSt="down",
        ),
        _mo(
            "bgpPeerEntry",
            dn=f"topology/pod-1/node-101/sys/bgp/inst/dom-prod:prod-vrf/peer-[{BGP_PEER_C}]",
            operSt="established",
        ),
        _mo(
            "bgpPeerEntry",
            dn=f"topology/pod-1/node-999/sys/bgp/inst/dom-prod:prod-vrf/peer-[{BGP_PEER_D}]",
            operSt="established",
        ),
    ],
    "bgpPeerAfEntry": [
        _mo(
            "bgpPeerAfEntry",
            dn=f"topology/pod-1/node-101/sys/bgp/inst/dom-prod:prod-vrf/peer-[{BGP_PEER_A}]/af-[ipv4-ucast]",
        ),
        _mo(
            "bgpPeerAfEntry",
            dn=f"topology/pod-1/node-102/sys/bgp/inst/dom-default/peer-[{BGP_PEER_B}]/af-[ipv4-ucast]",
        ),
        _mo(
            "bgpPeerAfEntry",
            dn=f"topology/pod-1/node-999/sys/bgp/inst/dom-prod:prod-vrf/peer-[{BGP_PEER_D}]/af-[ipv4-ucast]",
        ),
    ],
}


def _bgp_raw(**over):
    raw = {**RAW, **RAW_BGP}
    raw.update(over)
    return raw


def test_bgp_observed_sessions_joins_peer_and_address_family_entries():
    from hst.collectors.apic import bgp_observed_sessions

    sessions = bgp_observed_sessions(_bgp_raw(), "fab1")
    by_peer = {s["peer_ip"]: s for s in sessions}
    assert set(by_peer) == {BGP_PEER_A, BGP_PEER_B}  # PEER_C and PEER_D produce no row
    a = by_peer[BGP_PEER_A]
    assert a["device_uid"] == "dev:leaf101"
    assert a["context_uid"] == "aci:fab1:uni/tn-prod/ctx-prod-vrf"
    assert (a["af"], a["safi"], a["state"]) == (4, "unicast", "established")


def test_a_dom_value_with_no_colon_falls_back_to_the_common_tenant():
    from hst.collectors.apic import bgp_observed_sessions

    sessions = bgp_observed_sessions(_bgp_raw(), "fab1")
    b = next(s for s in sessions if s["peer_ip"] == BGP_PEER_B)
    assert b["device_uid"] == "dev:leaf102"
    assert b["context_uid"] == "aci:fab1:uni/tn-common/ctx-default"
    assert b["state"] == "down"


def test_a_peer_with_no_address_family_entry_produces_no_session_row():
    from hst.collectors.apic import bgp_observed_sessions

    sessions = bgp_observed_sessions(_bgp_raw(), "fab1")
    assert BGP_PEER_C not in {s["peer_ip"] for s in sessions}


def test_a_peer_on_a_node_outside_fabricnode_produces_no_session_row():
    from hst.collectors.apic import bgp_observed_sessions

    sessions = bgp_observed_sessions(_bgp_raw(), "fab1")
    assert BGP_PEER_D not in {s["peer_ip"] for s in sessions}


def test_bgp_side_rows_stamp_the_session_uid_and_leave_routes_empty():
    from hst.collectors.apic import _bgp_session_uid, bgp_side_rows

    tables = bgp_side_rows(_bgp_raw(), "fab1")
    assert tables["bgp_session_routes"] == []
    sessions = {r["peer_ip"]: r for r in tables["bgp_sessions"]}
    a = sessions[BGP_PEER_A]
    expected = _bgp_session_uid(
        {"device_uid": "dev:leaf101", "vrf_name": "prod:prod-vrf", "peer_ip": BGP_PEER_A}
    )
    assert a["session_uid"] == expected
    assert a["established_since_ms"] is None
    assert a["prefixes_received"] is None and a["prefixes_advertised"] is None
    assert a["capabilities"] is None


def test_bgp_table_outcomes_reports_routes_not_captured_regardless_of_capture():
    """The class model has no per-peer path table."""
    from hst.collectors.apic import bgp_table_outcomes

    for capture in ("all", "sessions"):
        outcomes = bgp_table_outcomes(_bgp_raw(), "fab1", capture=capture)
        assert outcomes["bgp_session_routes"].status == "not-captured"
        assert outcomes["bgp_session_routes"].detail
        assert "bgp_sessions" not in outcomes  # the classes answered; the write outcome stands


def test_bgp_table_outcomes_capture_none_states_both_tables_not_captured():
    from hst.collectors.apic import bgp_table_outcomes

    outcomes = bgp_table_outcomes(_bgp_raw(), "fab1", capture="none")
    assert outcomes["bgp_sessions"].status == "not-captured"
    assert outcomes["bgp_session_routes"].status == "not-captured"
    assert "capture_bgp setting is none" in outcomes["bgp_sessions"].detail


def test_bgp_table_outcomes_states_a_failed_class_fetch():
    from hst.collectors.apic import bgp_table_outcomes
    from hst.collectors.base import RAW_OUTCOMES_KEY

    raw = _bgp_raw(**{RAW_OUTCOMES_KEY: {"bgpPeerEntry": {"status": "failed", "detail": "HTTP 500"}}})
    outcomes = bgp_table_outcomes(raw, "fab1", capture="all")
    assert outcomes["bgp_sessions"].status == "failed"
    assert "HTTP 500" in outcomes["bgp_sessions"].detail


def test_every_observed_session_direction_pair_is_captured_or_not_captured_with_a_reason():
    from hst.collectors.apic import bgp_observed_sessions, bgp_table_outcomes
    from hst.core import manifest

    raw = _bgp_raw()
    outcomes = bgp_table_outcomes(raw, "fab1", capture="all")
    directions = manifest.bgp_direction_outcomes(outcomes)
    assert len(directions) == len(bgp_observed_sessions(raw, "fab1")) * 3
    for outcome in directions.values():
        assert outcome.status == "not-captured"
        assert outcome.detail
