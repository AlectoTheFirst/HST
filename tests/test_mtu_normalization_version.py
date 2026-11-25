"""Graph enrichment upgrades must not reuse pre-enrichment collected state."""

from types import SimpleNamespace

from hst.collectors.base import RAW_OUTCOMES_KEY, SourceConfig, raw_sha


def collector(**overrides):
    fields = {
        "config": SourceConfig(),
        "VOLATILE_RAW_KEYS": (),
        "PARSER_VERSION": "1",
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


def test_enabling_mtu_and_upgrading_profiles_invalidate_same_payload():
    raw = {"interfaces": [{"name": "eth0", "mtu": 1500}]}
    before = raw_sha(collector(), raw)
    first = raw_sha(collector(NORMALIZATION_VERSIONS={"mtu": "1"}), raw)
    second = raw_sha(collector(NORMALIZATION_VERSIONS={"mtu": "2"}), raw)
    assert len({before, first, second}) == 3


def test_parser_upgrade_invalidates_an_enabled_graph_enrichment():
    raw = {"interfaces": []}
    a = collector(NORMALIZATION_VERSIONS={"mtu": "1"})
    b = collector(NORMALIZATION_VERSIONS={"mtu": "1"}, PARSER_VERSION="2")
    assert raw_sha(a, raw) != raw_sha(b, raw)


def test_unrelated_collectors_keep_the_unversioned_hash_and_input_is_not_mutated():
    raw = {"interfaces": [{"mtu": 1500}]}
    assert raw_sha(collector(), raw) == raw_sha(collector(NORMALIZATION_VERSIONS={}), raw)
    assert raw == {"interfaces": [{"mtu": 1500}]}


def test_version_order_is_stable_and_never_changes_the_collector_mapping():
    versions = {"mtu": "1", "other": "2"}
    a = collector(NORMALIZATION_VERSIONS=versions)
    b = collector(NORMALIZATION_VERSIONS={"other": "2", "mtu": "1"})
    assert raw_sha(a, {}) == raw_sha(b, {})
    assert versions == {"mtu": "1", "other": "2"}


def test_mtu_capture_failure_differs_from_empty_success_with_same_raw_output():
    c = collector(NORMALIZATION_OUTCOME_KEYS=("interfaces",))
    failed = {"interfaces": "", RAW_OUTCOMES_KEY: {"interfaces": {"status": "unauthorized"}}}
    empty = {"interfaces": "", RAW_OUTCOMES_KEY: {"interfaces": {"status": "ok"}}}
    assert raw_sha(c, failed) != raw_sha(c, empty)
    assert raw_sha(collector(), failed) == raw_sha(collector(), empty)


def test_unrelated_command_outcome_does_not_invalidate_mtu_evidence():
    c = collector(NORMALIZATION_OUTCOME_KEYS=("interfaces",))
    raw = {RAW_OUTCOMES_KEY: {"interfaces": {"status": "ok"}}}
    extra = {RAW_OUTCOMES_KEY: {"interfaces": {"status": "ok"}, "arp": {"status": "failed"}}}
    assert raw_sha(c, raw) == raw_sha(c, extra)


def test_capture_option_participates_even_if_raw_output_is_equal():
    off = collector(config=SimpleNamespace(capture_mtu=False))
    on = collector(config=SimpleNamespace(capture_mtu=True))
    assert raw_sha(off, {}) != raw_sha(on, {})


def test_explicit_semantics_config_invalidates_same_raw():
    a = collector(config=SimpleNamespace(mtu_basis="unknown"), NORMALIZATION_CONFIG_KEYS=("mtu_basis",))
    b = collector(config=SimpleNamespace(mtu_basis="ip_packet"), NORMALIZATION_CONFIG_KEYS=("mtu_basis",))
    assert raw_sha(a, {}) != raw_sha(b, {})
