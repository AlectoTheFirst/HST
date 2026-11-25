"""Fixed-point scope and strict evidence rules of the integrated RIB reader."""

from typing import Any

from hst import path as pathmod
from hst.app import simul_read


def _install(monkeypatch, read):
    monkeypatch.setattr(pathmod, "_read", lambda session, query, **params: read(query, params))


def test_scope_closes_recursively_over_leaks_next_hop_owners_and_pbr(monkeypatch):
    seen_bindings = []

    def read(query: str, params: dict[str, Any]):
        vrfs = set(params.get("vrfs") or ())
        if "RouteTarget" in query:
            return [
                {"vrf_uid": "a", "kind": "IMPORTS", "rt": "65000:1"},
                {"vrf_uid": "b", "kind": "EXPORTS", "rt": "65000:1"},
                {"vrf_uid": "b", "kind": "IMPORTS", "rt": "65000:2"},
                {"vrf_uid": "e", "kind": "EXPORTS", "rt": "65000:2"},
            ]
        if "toLower(coalesce(rp.proto, '')) = 'bgp'" in query:
            return []
        if "type(r) AS kind" in query:
            rows = []
            if "a" in vrfs:
                rows.append(
                    {
                        "context_uid": "a",
                        "prefix": "0.0.0.0/0",
                        "kind": "STATIC_ROUTE",
                        "next_hop_context_uid": "b",
                        "gateways": [],
                    }
                )
            return rows
        if "target.uid AS target_context_uid" in query and "STATIC_ROUTE" in query:
            return [{"context_uid": "b", "target_context_uid": "c"}] if "b" in vrfs else []
        if "target.uid AS target_context_uid" in query and "PbrPolicy" in query:
            return (
                [
                    {
                        "device_uid": "dev:c",
                        "if_uid": "if:c",
                        "context_uid": "c",
                        "target_context_uid": "d",
                    }
                ]
                if "c" in vrfs
                else []
            )
        if "collect(DISTINCT d.uid) AS device_uids" in query:
            return [
                {
                    "uid": uid,
                    "name": uid,
                    "device_uids": [f"dev:{uid}"],
                    "platforms": ["nxos"],
                    "vendors": [],
                }
                for uid in sorted(vrfs)
            ]
        if "toLower(coalesce(rp.proto, '')) = 'ospf'" in query:
            return []
        if "PbrPolicy" in query and "REDIRECTS_VIA" in query:
            seen_bindings.append(params["dev"])
            return []
        return []

    _install(monkeypatch, read)
    result = simul_read.read_rib_input(object(), contexts=["a"])

    assert [context["uid"] for context in result.input.contexts] == ["a", "b", "c", "d", "e"]
    assert "dev:c" in seen_bindings


def test_integrated_bgp_seeds_only_explicit_origination(monkeypatch):
    def read(query: str, params: dict[str, Any]):
        if "RETURN DISTINCT rp.uid AS uid" in query and "v.uid IN $vrfs" in query:
            return [{"uid": "rp:a"}]
        if "far.uid AS uid" in query:
            return []
        if "collect(DISTINCT d.platform)" in query:
            return [
                {
                    "uid": "rp:a",
                    "props": {"proto": "bgp", "asn": 65001},
                    "context_uid": "a",
                    "platforms": ["nxos"],
                    "vendors": [],
                }
            ]
        if (
            "properties(b) AS props" in query
            or "ip.ip AS ip" in query
            or "collect(properties(e)) AS entries" in query
        ):
            return []
        if "og.proto AS proto" in query:
            return [
                {"process_uid": "rp:a", "prefix": "10.0.0.0/24", "proto": "connected"},
                {"process_uid": "rp:a", "prefix": "203.0.113.0/24", "proto": "aggregate"},
            ]
        if (
            "RouteTarget" in query
            or "target.uid AS target_context_uid" in query
            or "type(r) AS kind" in query
        ):
            return []
        if "collect(DISTINCT d.uid) AS device_uids" in query:
            return [
                {
                    "uid": "a",
                    "name": "default",
                    "device_uids": ["dev:a"],
                    "platforms": ["nxos"],
                    "vendors": [],
                }
            ]
        if "toLower(coalesce(rp.proto, '')) = 'ospf'" in query or "PbrPolicy" in query:
            return []
        return []

    _install(monkeypatch, read)
    result = simul_read.read_rib_input(object(), contexts=["a"])

    assert [route["prefix"] for route in result.input.bgp.local_routes] == ["203.0.113.0/24"]
    assert "origination-not-recorded" in [error["kind"] for error in result.errors.as_dicts()]


def test_bgp_peer_context_expansion_repeats_to_a_fixed_point(monkeypatch):
    def read(query: str, params: dict[str, Any]):
        vrfs = sorted(params.get("vrfs") or ())
        if "RouteTarget" in query or "target.uid AS target_context_uid" in query:
            return []
        if "RETURN DISTINCT rp.uid AS uid" in query and "v.uid IN $vrfs" in query:
            return [{"uid": f"rp:{uid}"} for uid in vrfs]
        if "type(r) AS kind" in query:
            return []
        if "collect(DISTINCT d.uid) AS device_uids" in query:
            return [
                {
                    "uid": uid,
                    "name": "default",
                    "device_uids": [f"dev:{uid}"],
                    "platforms": ["nxos"],
                    "vendors": [],
                }
                for uid in vrfs
            ]
        return []

    def bgp(_session, seeds, platform, errors, *, infer_origins=True):
        contexts = {seed.removeprefix("rp:") for seed in seeds}
        if "a" in contexts:
            contexts.add("b")
        if "b" in contexts:
            contexts.add("c")
        return simul_read.GraphInput(
            processes=[{"uid": f"rp:{uid}", "context_uid": uid} for uid in sorted(contexts)]
        )

    _install(monkeypatch, read)
    monkeypatch.setattr(simul_read, "_read_bgp", bgp)
    result = simul_read.read_rib_input(object(), contexts=["a"])
    assert [context["uid"] for context in result.input.contexts] == ["a", "b", "c"]


def test_shared_context_preserves_all_devices_and_blocks_device_keyed_observations(monkeypatch):
    def read(query: str, params: dict[str, Any]):
        if "collect(DISTINCT d.uid) AS device_uids" in query:
            return [
                {
                    "uid": "fabric",
                    "name": "default",
                    "device_uids": ["dev:b", "dev:a"],
                    "platforms": ["nxos"],
                    "vendors": [],
                }
            ]
        return []

    _install(monkeypatch, read)
    result = simul_read.read_rib_input(object(), contexts=["fabric"])
    context = result.input.contexts[0]

    assert context["device_uids"] == ["dev:a", "dev:b"]
    assert context["device_uid"] is None
    assert result.input.rib_coverage["fabric"] == "ambiguous-device"
    assert result.input.observation_gaps[0]["kind"] == "not-observed"
    assert "context-observation-ambiguous" in [error["kind"] for error in result.errors.as_dicts()]


def test_bgp_observation_requires_exact_address_family_safi_and_policy_stage():
    complete = {"af": 4, "safi": "unicast", "direction": "received", "policy_stage": "pre-import"}
    assert simul_read._bgp_path_supported(complete)
    for changed in (
        {"af": None},
        {"safi": "evpn"},
        {"direction": "received", "policy_stage": "post-import"},
        {"direction": "accepted", "policy_stage": None},
    ):
        assert not simul_read._bgp_path_supported({**complete, **changed})


def test_vyos_13_statics_the_collector_did_not_read_are_an_observation_gap(monkeypatch):
    """A VyOS 1.3 router whose interface routes and per-VRF statics the
    collector does not read records its config section as partial."""
    from types import SimpleNamespace

    def read(query: str, params: dict[str, Any]):
        if "collect(DISTINCT d.uid) AS device_uids" in query:
            return [
                {
                    "uid": "a",
                    "name": "default",
                    "device_uids": ["dev:a"],
                    "platforms": ["vyos"],
                    "vendors": [],
                }
            ]
        if "d.hostname AS host" in query:
            return [{"host": "r1", "source": "lab", "scope": None}]
        return []

    def session(source_type: str, detail: str) -> Any:
        entry = SimpleNamespace(
            device_uids=["dev:a"],
            host="r1",
            source="lab",
            sections={"config": SimpleNamespace(status="partial", detail=detail)},
            tables={},
        )
        manifest = SimpleNamespace(devices=[entry], sources=[SimpleNamespace(name="lab", type=source_type)])
        return SimpleNamespace(snapshot=SimpleNamespace(manifest=manifest))

    _install(monkeypatch, read)
    unread = (
        "VyOS 1.3 configuration not read: protocols bgp <asn>, protocols static interface-route, "
        "protocols vrf"
    )
    result = simul_read.read_rib_input(session("vyos", unread), contexts=["a"])

    errors = [e for e in result.errors.as_dicts() if e["kind"] == "static-config-not-read"]
    assert len(errors) == 1 and errors[0]["subject"] == "a"
    assert "protocols static interface-route, protocols vrf" in errors[0]["detail"]
    assert "bgp" not in errors[0]["detail"]
    gaps = [g for g in result.input.observation_gaps if "protocols vrf" in g["detail"]]
    assert gaps and {g["context_uid"] for g in gaps} == {"a"}

    for other in (
        session("vyos", "VyOS 1.3 configuration not read: protocols bgp <asn>"),
        session("nxos", unread),
    ):
        result = simul_read.read_rib_input(other, contexts=["a"])
        assert "static-config-not-read" not in [e["kind"] for e in result.errors.as_dicts()]
        assert not any("protocols" in g["detail"] for g in result.input.observation_gaps)
