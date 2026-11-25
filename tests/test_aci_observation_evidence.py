"""ACI absence claims require context-specific APIC collection evidence."""

from types import SimpleNamespace

from hst.core.manifest import DeviceEntry, SectionOutcome, SourceEntry
from hst.path.addrsets import _intervals, _ports
from hst.path.gates import aci_symbolic
from hst.path.gates.aci_symbolic import AciTransition
from hst.path.state import FlowRegion


def _region():
    return FlowRegion.from_query(
        _intervals(["10.0.0.1"]),
        _intervals(["10.0.0.2"]),
        frozenset({6}),
        _ports("443"),
    )


def _session(*, sections):
    manifest = SimpleNamespace(
        sources=[SourceEntry(name="apic-prod", type="apic", status="enabled", config_sha256="x")],
        devices=[
            DeviceEntry(
                source="apic-prod",
                host="controller",
                outcome="collected",
                sections=sections,
            )
        ],
    )
    return SimpleNamespace(snapshot=SimpleNamespace(manifest=manifest))


def _install(monkeypatch, *, context_rows, endpoints=(), contracts=()):
    def read(_session, query, **_params):
        if query == aci_symbolic._ACI_CONTEXT:
            return list(context_rows)
        if query == aci_symbolic._ENDPOINTS:
            return list(endpoints)
        if query == aci_symbolic._CONTRACTS:
            return list(contracts)
        raise AssertionError("unexpected query")

    monkeypatch.setattr(aci_symbolic._path, "_read", read)


def test_aci_context_without_endpoint_section_cannot_pass_on_absence(monkeypatch):
    _install(monkeypatch, context_rows=[{"bd_uid": "bd:one", "sources": ["apic-prod"]}])
    effect = AciTransition(_session(sections={}), context_uid="vrf:aci").apply(_region())[0][1]
    assert effect.kind == "indeterminate"
    assert "lacks endpoint observation" in effect.reason


def test_complete_empty_endpoint_observation_proves_absence(monkeypatch):
    _install(monkeypatch, context_rows=[{"bd_uid": "bd:one", "sources": ["apic-prod"]}])
    sections = {
        "endpoint": SectionOutcome(status="empty", row_count=0),
        "policy": SectionOutcome(status="empty", row_count=0),
    }
    effect = AciTransition(_session(sections=sections), context_uid="vrf:aci").apply(_region())[0][1]
    assert effect.kind == "pass"


def test_demonstrably_non_aci_context_preserves_pass(monkeypatch):
    _install(monkeypatch, context_rows=[])
    effect = AciTransition(_session(sections={}), context_uid="vrf:router").apply(_region())[0][1]
    assert effect.kind == "pass"


def test_aci_context_without_source_provenance_is_unknown(monkeypatch):
    _install(monkeypatch, context_rows=[{"bd_uid": "bd:one", "sources": []}])
    effect = AciTransition(_session(sections={}), context_uid="vrf:aci").apply(_region())[0][1]
    assert effect.kind == "indeterminate"
    assert "source provenance" in effect.reason


def test_missing_policy_prevents_empty_endpoint_pass(monkeypatch):
    _install(monkeypatch, context_rows=[{"bd_uid": "bd:one", "sources": ["apic-prod"]}])
    sections = {"endpoint": SectionOutcome(status="empty", row_count=0)}
    effect = AciTransition(_session(sections=sections), context_uid="vrf:aci").apply(_region())[0][1]
    assert effect.kind == "indeterminate"
    assert "lacks policy observation" in effect.reason


def test_apic_vrf_provenance_without_bridge_domain_requires_evidence(monkeypatch):
    _install(
        monkeypatch,
        context_rows=[{"bd_uid": None, "sources": [], "vrf_sources": ["apic-prod"]}],
    )
    effect = AciTransition(_session(sections={}), context_uid="vrf:aci").apply(_region())[0][1]
    assert effect.kind == "indeterminate"
    assert "lacks endpoint observation" in effect.reason


def test_every_apic_source_mapped_to_context_needs_manifest_device_evidence(monkeypatch):
    _install(
        monkeypatch,
        context_rows=[{"bd_uid": "bd:one", "sources": ["apic-prod", "apic-dr"]}],
    )
    session = _session(
        sections={
            "endpoint": SectionOutcome(status="empty", row_count=0),
            "policy": SectionOutcome(status="empty", row_count=0),
        }
    )
    session.snapshot.manifest.sources.append(
        SourceEntry(name="apic-dr", type="apic", status="enabled", config_sha256="y")
    )
    effect = AciTransition(session, context_uid="vrf:aci").apply(_region())[0][1]
    assert effect.kind == "indeterminate"
    assert "apic-dr" in effect.reason
