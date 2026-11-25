import importlib
from types import SimpleNamespace

from hst.path.gates import Stage, _Trail
from hst.path.gates.coverage import degraded_policy_sections

trace = importlib.import_module("hst.path.trace")


def _session(sections, source_type="iosxe", *, outcome="partial", carried=False, effective_run="run-1"):
    entry = SimpleNamespace(
        host="router-1",
        source="edge",
        outcome=outcome,
        carried=carried,
        effective_run=effective_run,
        sections={name: SimpleNamespace(status=status) for name, status in sections.items()},
    )
    manifest = SimpleNamespace(devices=[entry], sources=[SimpleNamespace(name="edge", type=source_type)])
    return SimpleNamespace(snapshot=SimpleNamespace(manifest=manifest))


def _install(monkeypatch):
    monkeypatch.setattr(trace, "aci_contract_verdict", lambda *_args: None)
    monkeypatch.setattr(trace, "unevaluated_gates", lambda *_args: [])
    monkeypatch.setattr(
        "hst.path._read",
        lambda _session, query, **_params: (
            [{"host": "router-1", "source": "edge", "scope": "edge:router-1"}]
            if "RETURN d.hostname AS host" in query
            else []
        ),
    )


def _flow(session):
    trail = _Trail()
    trail.hop("dev:1", "Device", "router-1", stage=Stage.DEVICE)
    legs = [{"verdict": "forwarded", "blocked": False}]
    verdict = trace._flow_gates(
        session, trail, legs, "10.0.0.1 → 10.0.0.2: forwarded", "10.0.0.1", "10.0.0.2", 443, "tcp"
    )
    return trail, legs, verdict


def test_an_unauthorized_interface_config_makes_the_leg_indeterminate(monkeypatch):
    _install(monkeypatch)
    trail, legs, verdict = _flow(_session({"acl": "ok", "interface_config": "unauthorized", "nat": "ok"}))
    assert legs[0]["indeterminate"] is True
    assert "interface_config=unauthorized" in legs[0]["indeterminate_reason"]
    assert "router-1" in legs[0]["indeterminate_reason"]
    assert any("interface_config=unauthorized" in w for w in trail.warnings)
    assert "policy of 1 device(s) not collected completely" in verdict


def test_collected_or_absent_policy_sections_leave_the_leg_alone(monkeypatch):
    _install(monkeypatch)
    _trail, legs, verdict = _flow(
        _session({"acl": "ok", "interface_config": "empty", "nat": "unsupported", "vlan_filter": "ok"})
    )
    assert not legs[0].get("indeterminate")
    assert verdict == "10.0.0.1 → 10.0.0.2: forwarded"


def test_no_manifest_claims_nothing(monkeypatch):
    _install(monkeypatch)
    assert degraded_policy_sections(SimpleNamespace(snapshot=SimpleNamespace(manifest=None)), "dev:1") == []
    assert degraded_policy_sections(object(), "dev:1") == []


def test_a_failed_section_outside_the_policy_contract_is_not_named(monkeypatch):
    _install(monkeypatch)
    session = _session(
        {"arp": "failed", "acl": "ok", "interface_config": "ok", "nat": "malformed", "vlan_filter": "ok"}
    )
    assert degraded_policy_sections(session, "dev:1") == ["nat=malformed"]


# --- the outcomes the trace reads beside the policy sections ----------------------------


def test_a_failed_velocloud_configuration_read_makes_the_leg_indeterminate(monkeypatch):
    """The business policies come from the configuration reads: a refused
    read leaves the edge with no policy, or last run's copy."""
    _install(monkeypatch)
    _trail, legs, _verdict = _flow(_session({"configuration": "failed"}, source_type="velocloud"))
    assert legs[0]["indeterminate"] is True
    assert "configuration=failed" in legs[0]["indeterminate_reason"]


def test_a_device_no_run_ever_collected_makes_the_leg_indeterminate(monkeypatch):
    _install(monkeypatch)
    session = _session({}, outcome="failed", carried=True, effective_run=None)
    _trail, legs, _verdict = _flow(session)
    assert legs[0]["indeterminate"] is True
    assert "device=not collected" in legs[0]["indeterminate_reason"]


def test_a_carried_device_notes_that_its_policy_is_the_last_known_copy(monkeypatch):
    """A device whose source did not run stands on its effective run: the
    gates are that run's, which the trace says without doubting the leg."""
    _install(monkeypatch)
    session = _session(
        {"acl": "ok", "interface_config": "ok", "nat": "ok", "vlan_filter": "ok"},
        outcome="carried",
        carried=True,
    )
    trail, legs, _verdict = _flow(session)
    assert not legs[0].get("indeterminate")
    assert any("policy is the copy from run run-1" in note for note in trail.notes)


def test_a_degraded_policy_section_says_its_objects_carry(monkeypatch):
    _install(monkeypatch)
    _trail, legs, _verdict = _flow(_session({"acl": "failed", "interface_config": "ok", "nat": "ok"}))
    assert "acl carried from the last run that read it" in legs[0]["indeterminate_reason"]


def test_a_partial_unifi_policy_makes_the_leg_indeterminate(monkeypatch):
    """A gateway pair, or zone policies whose zones were not read, leave the
    policy bound to nothing: the section reads partial."""
    _install(monkeypatch)
    _trail, legs, _verdict = _flow(_session({"policy": "partial"}, source_type="unifi"))
    assert legs[0]["indeterminate"] is True
    assert "policy=partial" in legs[0]["indeterminate_reason"]


def _entry(source, sections, *, host="router-1", device_uids=("dev:1",), outcome="partial"):
    return SimpleNamespace(
        host=host,
        source=source,
        outcome=outcome,
        carried=False,
        effective_run="run-1",
        device_uids=device_uids,
        sections={name: SimpleNamespace(status=status) for name, status in sections.items()},
    )


def _multi(entries, sources):
    manifest = SimpleNamespace(
        devices=entries, sources=[SimpleNamespace(name=name, type=kind) for name, kind in sources.items()]
    )
    return SimpleNamespace(snapshot=SimpleNamespace(manifest=manifest))


_IOSXE_REFUSED = {"acl": "ok", "interface_config": "unauthorized", "nat": "ok", "vlan_filter": "ok"}


def test_a_device_an_inventory_source_also_lists_keeps_its_policy_check(monkeypatch):
    _install(monkeypatch)
    session = _multi(
        [_entry("inventory", {"devices": "ok"}, outcome="collected"), _entry("edge", _IOSXE_REFUSED)],
        {"inventory": "nautobot", "edge": "iosxe"},
    )
    trail, legs, verdict = _flow(session)
    assert legs[0]["indeterminate"] is True
    assert "interface_config=unauthorized" in legs[0]["indeterminate_reason"]
    assert any("interface_config=unauthorized" in w for w in trail.warnings)
    assert "not collected completely" in verdict


def test_a_device_two_policy_sources_read_names_each_gap(monkeypatch):
    _install(monkeypatch)
    session = _multi(
        [_entry("fabric", {"policy": "failed"}), _entry("leaf", _IOSXE_REFUSED)],
        {"fabric": "apic", "leaf": "nxos"},
    )
    assert degraded_policy_sections(session, "dev:1") == [
        "fabric: policy=failed",
        "leaf: interface_config=unauthorized",
    ]


def test_an_entry_without_device_uids_beside_mapped_entries_is_read_by_host(monkeypatch):
    _install(monkeypatch)
    session = _multi(
        [
            _entry("other", {"policy": "ok"}, host="other-1", device_uids=("dev:9",)),
            _entry("edge", _IOSXE_REFUSED, device_uids=()),
        ],
        {"other": "unifi", "edge": "iosxe"},
    )
    _trail, legs, _verdict = _flow(session)
    assert legs[0]["indeterminate"] is True
    assert "interface_config=unauthorized" in legs[0]["indeterminate_reason"]


def test_a_contract_section_the_entry_does_not_record_makes_the_leg_indeterminate(monkeypatch):
    _install(monkeypatch)
    trail, legs, _verdict = _flow(_session({"acl": "ok", "nat": "ok", "vlan_filter": "ok"}))
    assert legs[0]["indeterminate"] is True
    assert "interface_config=not recorded" in legs[0]["indeterminate_reason"]
    assert trail.warnings


def test_two_clean_entries_leave_the_leg_alone(monkeypatch):
    _install(monkeypatch)
    clean = dict(_IOSXE_REFUSED, interface_config="ok")
    session = _multi(
        [_entry("inventory", {}, outcome="collected"), _entry("edge", clean, outcome="collected")],
        {"inventory": "nautobot", "edge": "iosxe"},
    )
    _trail, legs, _verdict = _flow(session)
    assert not legs[0].get("indeterminate")
