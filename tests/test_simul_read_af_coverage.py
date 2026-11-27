"""Observed RIB absence is scoped to explicitly captured address families."""

from types import SimpleNamespace

from hst.app.simul_read import _observed_rib_afs, _unread_rib_afs


def _session(*, sections, table="complete", device_uids=("dev:1",)):
    entry = SimpleNamespace(
        device_uids=list(device_uids),
        sections={name: SimpleNamespace(status=status) for name, status in sections.items()},
        tables={"rib": SimpleNamespace(status=table)},
    )
    manifest = SimpleNamespace(devices=[entry])
    return SimpleNamespace(snapshot=SimpleNamespace(manifest=manifest))


def test_cisco_complete_rib_only_proves_ipv4_absence():
    session = _session(sections={})
    assert _observed_rib_afs(session, "dev:1", "iosxe", "complete") == [4]
    assert _observed_rib_afs(session, "dev:1", "nxos", "complete-empty") == [4]
    assert _observed_rib_afs(session, "dev:1", "iosxr", "complete") == [4]


def test_vyos_requires_each_family_command_and_policy_table_commands():
    session = _session(
        sections={
            "routes": "ok",
            "routes_table_100": "empty",
            "routes6": "failed",
            "routes6_table_100": "empty",
        }
    )
    assert _observed_rib_afs(session, "dev:1", "vyos", "complete") == [4]


def test_vyos_dual_stack_complete_empty_is_explicitly_both_families():
    session = _session(
        sections={
            "routes": "empty",
            "routes_table_100": "empty",
            "routes6": "empty",
            "routes6_table_100": "empty",
        }
    )
    assert _observed_rib_afs(session, "dev:1", "vyos", "complete-empty") == [4, 6]


def test_missing_manifest_provenance_or_failed_table_proves_no_family():
    assert _observed_rib_afs(object(), "dev:1", "iosxe", "complete") is None
    assert _observed_rib_afs(_session(sections={}, table="failed"), "dev:1", "iosxe", "failed") == []
    assert _observed_rib_afs(_session(sections={}, device_uids=()), "dev:1", "iosxe", "complete") is None


def test_apic_explicitly_has_no_observed_rib_family_and_unknown_vendor_is_unrecorded():
    session = _session(sections={})
    assert _observed_rib_afs(session, "dev:1", "apic", "complete") == []
    assert _observed_rib_afs(session, "dev:1", "future-os", "complete") is None


def test_a_vyos_family_with_a_recorded_read_that_did_not_complete_is_unread():
    session = _session(
        sections={
            "routes": "ok",
            "routes_table_100": "failed",
            "routes6": "partial",
        }
    )
    assert _unread_rib_afs(session, "dev:1", "vyos") == [4, 6]


def test_a_family_with_no_recorded_read_and_a_device_of_another_platform_are_not_unread():
    session = _session(sections={"routes": "ok"})
    assert _unread_rib_afs(session, "dev:1", "vyos") == []
    assert _unread_rib_afs(_session(sections={"routes6": "failed"}), "dev:1", "iosxe") == []
    assert _unread_rib_afs(object(), "dev:1", "vyos") == []
