"""The Gaia source takes its identity from the linked management source's data."""

import pytest
from pydantic import ValidationError

from hst.app import sources as glue
from hst.app.crypto import dek, encrypt_secrets, generate_key
from hst.app.runs_exec import RunEvidence, _record_warnings
from hst.app.store import Source
from hst.collectors import base as coll
from hst.collectors import checkpoint_gateway as gw
from hst.collectors.checkpoint import normalize_checkpoint
from hst.core import Settings, rawstore
from hst.core.identity import MemoryResolver
from hst.core.model import RunManifest

MGMT_RAW = {
    "gateways": [
        {
            "uid": "member-uid",
            "name": "fw-a",
            "type": "CpmiVsxClusterMember",
            "ipv4-address": "192.0.2.10",
            "domain": {"uid": "domain-uid", "name": "SMC User"},
        },
        {"uid": "vs1-uid", "name": "vs-dmz", "type": "CpmiVsClusterNetobj"},
    ]
}
LINK = {"source": "cp-mgmt", "host": "mgmt.example", "domain": "", "scope": "cp:mgmt.example"}


def _settings(tmp_path):
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())


def _config(**overrides):
    payload = {
        "host": "192.0.2.10",
        "auth": {"method": "password", "username": "reader", "password": "secret"},
        "estate": "estate",
        "management_source": "cp-mgmt",
        "observation_uid": "snapshot-a",
        "expert_shell_account": "reader",
    }
    payload.update(overrides)
    return gw.CpGatewayConfig(**payload)


def _mgmt_row(domain=""):
    return Source(
        1,
        "cp-mgmt",
        "checkpoint",
        {"host": "mgmt.example", "domain": domain, "port": 443},
        b"",
        True,
        None,
        None,
    )


def _raw(vsx_stat="   1 | S vs-dmz | dmz_pol | 15Jul2026 | Trust", contexts=None):
    return {
        gw.VERSION_COMMAND: "Product version Check Point Gaia R81.20\nOS build 634\n",
        gw.HOSTNAME_COMMAND: "fw-a\n",
        gw.VSX_STAT_COMMAND: vsx_stat,
        "contexts": contexts if contexts is not None else {"1": {"vsid": 1}},
    }


class FakeSession:
    def execute_write(self, work):
        return work(self)

    def run(self, q, **p):
        class _Result:
            def data(self_inner):
                if "UNWIND $rows" in q and "MERGE (n" in q:
                    return [{"uid": r["uid"], "before": {}, "after": {**r["props"]}} for r in p["rows"]]
                return []

        return _Result()


# --- the config model ------------------------------------------------------------------


def test_management_source_alone_is_a_valid_configuration():
    config = _config()

    assert config.management_source == "cp-mgmt"
    assert config.management_authority_uid == ""
    assert config.appliance_uid == ""
    assert config.vsid_gateway_object_uids == {}
    assert config.management_domain_uid == ""
    assert config.management_host == ""
    assert config.gateway_release == ""
    assert "gateway_object_uid" not in gw.CpGatewayConfig.model_fields


def test_the_form_needs_only_the_estate_the_management_source_and_the_account():
    schema = gw.CpGatewayConfig.model_json_schema()

    assert set(schema["required"]) == {"auth", "estate", "expert_shell_account"}


def test_the_observation_uid_defaults_to_the_source_name_and_then_the_host():
    assert _config(observation_uid="").effective_observation_uid == "192.0.2.10"
    assert _config(observation_uid="", source_name="gaia-a").effective_observation_uid == "gaia-a"
    assert _config().effective_observation_uid == "snapshot-a"
    assert gw.gateway_scope(_config(observation_uid="", source_name="gaia-a")) == (
        "checkpoint-gateway:192.0.2.10:gaia-a"
    )


def test_the_authority_fallback_reads_the_typed_host_and_then_the_source_name():
    assert _config().authority_fallback == "cp:cp-mgmt"
    assert _config(management_host="typed.example", management_domain="dom").authority_fallback == (
        "cp:typed.example:dom"
    )


def test_the_typed_overrides_alone_are_a_valid_configuration():
    config = _config(
        management_source="", management_authority_uid="cp:mgmt.example", appliance_uid="member-uid"
    )

    assert config.management_source == ""


def test_neither_a_management_source_nor_both_overrides_is_refused():
    with pytest.raises(ValidationError, match="management_source is required"):
        _config(management_source="")
    with pytest.raises(ValidationError, match="management_source is required"):
        _config(management_source="", appliance_uid="member-uid")


def test_the_schema_marks_the_management_source_as_a_source_pick():
    field = gw.CpGatewayConfig.model_json_schema()["properties"]["management_source"]

    assert field["format"] == "source"
    assert field["sourceType"] == "checkpoint"
    assert field["title"] == "Management source"
    assert "management_source" not in gw.CpGatewayConfig.model_json_schema().get("required", [])


# --- the platform link -----------------------------------------------------------------


def test_link_sources_writes_the_management_scope_from_the_row():
    payload = {"management_source": "cp-mgmt"}

    linked = gw.CpGatewayCollector.link_sources(payload, {"cp-mgmt": _mgmt_row()})
    assert linked["management_link"] == LINK

    linked = gw.CpGatewayCollector.link_sources(dict(payload), {"cp-mgmt": _mgmt_row(domain="dom")})
    assert linked["management_link"] == {
        "source": "cp-mgmt",
        "host": "mgmt.example",
        "domain": "dom",
        "scope": "cp:mgmt.example:dom",
    }


def test_link_sources_records_a_missing_row_or_a_row_of_another_type_as_a_problem():
    missing = gw.CpGatewayCollector.link_sources({"management_source": "cp-mgmt"}, {})
    assert missing["management_link"]["source"] == "cp-mgmt"
    assert "no source named 'cp-mgmt'" in missing["management_link"]["problem"]

    other = Source(2, "cp-mgmt", "nxos", {"host": "n9k"}, b"", True, None, None)
    wrong = gw.CpGatewayCollector.link_sources({"management_source": "cp-mgmt"}, {"cp-mgmt": other})
    assert "type 'nxos'" in wrong["management_link"]["problem"]

    untouched = gw.CpGatewayCollector.link_sources({"host": "x"}, {"cp-mgmt": _mgmt_row()})
    assert "management_link" not in untouched


def test_build_collector_links_the_named_management_source(tmp_path):
    settings = _settings(tmp_path)
    key = dek(settings)
    config = _config().model_dump(mode="json", exclude={"auth"}) | {
        "auth": {"method": "password", "username": "reader"}
    }
    config.pop("source_name", None)
    row = Source(
        3,
        "gaia-a",
        "checkpoint_gateway",
        config,
        encrypt_secrets(key, {"auth.password": "pw"}),
        True,
        None,
        None,
    )

    linked = glue.build_collector(row, settings, sources={"cp-mgmt": _mgmt_row()})
    assert linked.config.management_link == LINK
    assert linked.scope == "checkpoint-gateway:192.0.2.10:snapshot-a"

    unlinked = glue.build_collector(row, settings)
    assert unlinked.config.management_link == {}


# --- the inventory read from the raw store ---------------------------------------------


def test_the_inventory_is_the_management_sources_newest_stored_payload(tmp_path):
    settings = _settings(tmp_path)
    older = {"gateways": [{"uid": "stale-uid", "name": "fw-a", "type": "CpmiVsxClusterMember"}]}
    rawstore.write(settings.raw_dir, "cp-mgmt", "1000-abcdef", older, key=dek(settings))
    rawstore.write(settings.raw_dir, "cp-mgmt", "2000-abcdef", MGMT_RAW, key=dek(settings))
    collector = gw.CpGatewayCollector(_config(management_link=LINK), settings)

    inventory = collector.management_inventory()

    assert inventory is not None
    assert inventory.scope == "cp:mgmt.example"
    assert inventory.problem == ""
    assert [o.uid for o in inventory.objects] == ["member-uid", "vs1-uid"]
    assert collector.management_inventory() is inventory


def test_a_management_source_never_collected_is_a_problem(tmp_path):
    settings = _settings(tmp_path)
    collector = gw.CpGatewayCollector(_config(management_link=LINK), settings)

    inventory = collector.management_inventory()

    assert inventory is not None
    assert inventory.scope == "cp:mgmt.example"
    assert inventory.objects == ()
    assert "no collected payload yet" in inventory.problem


def test_a_missing_link_and_a_missing_management_source_are_told_apart(tmp_path):
    settings = _settings(tmp_path)

    unlinked = gw.CpGatewayCollector(_config(), settings).management_inventory()
    assert unlinked is not None
    assert "was not linked" in unlinked.problem

    none = gw.CpGatewayCollector(
        _config(management_source="", management_authority_uid="cp:x", appliance_uid="a"), settings
    ).management_inventory()
    assert none is None


# --- normalization under the resolved identity ----------------------------------------


def test_the_gaia_device_and_the_management_device_are_one_node(tmp_path):
    settings = _settings(tmp_path)
    rawstore.write(settings.raw_dir, "cp-mgmt", "1000-abcdef", MGMT_RAW, key=dek(settings))
    collector = gw.CpGatewayCollector(_config(management_link=LINK), settings)
    # one registry, as in one deployment: both sources resolve one ref
    registry = MemoryResolver()
    collector.identity = registry

    batch = collector.normalize(_raw())
    management = normalize_checkpoint(MGMT_RAW, mgmt="mgmt.example", domain="", resolver=registry)

    gaia_device = next(n.uid for n in batch.nodes if n.label == "Device")
    assert gaia_device == registry.resolve_device("ref", "cp:mgmt.example:member-uid", None)
    assert gaia_device in {n.uid for n in management.nodes if n.label == "Device"}
    instance = next(n for n in batch.nodes if n.label == "FirewallInstance")
    assert instance.props["gateway_object_uid"] == "vs1-uid"
    assert instance.props["authority"] == "cp:mgmt.example"
    assert instance.props["domain"] == "domain-uid"
    device_node = next(n for n in batch.nodes if n.label == "Device")
    assert device_node.props["os_version"] == "R81.20"
    assert batch.warnings == []
    assert batch.scope == collector.scope
    assert (
        collector.side_tables(
            _raw(contexts={"1": {"vsid": 1, "routes4": [{"dst": "10.0.0.0/8", "dev": "eth1"}]}})
        )["rib"][0]["device_uid"]
        == gaia_device
    )


def test_an_unmatched_vs_is_written_and_the_batch_carries_the_warning(tmp_path):
    settings = _settings(tmp_path)
    rawstore.write(settings.raw_dir, "cp-mgmt", "1000-abcdef", MGMT_RAW, key=dek(settings))
    collector = gw.CpGatewayCollector(_config(management_link=LINK), settings)
    raw = _raw(
        vsx_stat="   1 | S vs-dmz | p | d | Trust\n   2 | S vs-other | p | d | Trust",
        contexts={"1": {"vsid": 1}, "2": {"vsid": 2}},
    )

    batch = collector.normalize(raw)

    instances = {n.props["gateway_object_uid"] for n in batch.nodes if n.label == "FirewallInstance"}
    assert instances == {"vs1-uid", "vs-other"}
    assert batch.sections["interfaces"].status == "ok"
    assert len(batch.warnings) == 1
    assert "checkpoint_gateway/192.0.2.10" in batch.warnings[0]
    assert "'cp-mgmt'" in batch.warnings[0]
    assert "VS 2 'vs-other'" in batch.warnings[0]
    assert "rib" not in collector.table_outcomes(raw)
    assert collector.table_outcomes(raw)["arp"].status == "partial"


def test_a_management_source_not_yet_collected_warns_and_keys_the_device_by_host(tmp_path):
    settings = _settings(tmp_path)
    collector = gw.CpGatewayCollector(_config(management_link=LINK), settings)

    batch = collector.normalize(_raw())

    device = next(n.uid for n in batch.nodes if n.label == "Device")
    assert device == collector.identity.resolve_device("ref", "cp:mgmt.example:192.0.2.10", None)
    instance = next(n for n in batch.nodes if n.label == "FirewallInstance")
    assert instance.props["gateway_object_uid"] == "vs-dmz"
    assert len(batch.warnings) == 1
    assert "no collected payload yet" in batch.warnings[0]


def test_the_typed_overrides_win_over_the_management_data(tmp_path):
    settings = _settings(tmp_path)
    rawstore.write(settings.raw_dir, "cp-mgmt", "1000-abcdef", MGMT_RAW, key=dek(settings))
    collector = gw.CpGatewayCollector(
        _config(
            management_link=LINK,
            management_authority_uid="cp:typed.example",
            appliance_uid="typed-member",
            vsid_gateway_object_uids={1: "typed-vs1"},
        ),
        settings,
    )

    batch = collector.normalize(_raw())

    assert next(n.uid for n in batch.nodes if n.label == "Device") == collector.identity.resolve_device(
        "ref", "cp:typed.example:typed-member", None
    )
    instance = next(n for n in batch.nodes if n.label == "FirewallInstance")
    assert instance.props["gateway_object_uid"] == "typed-vs1"
    assert instance.props["authority"] == "cp:typed.example"
    assert batch.warnings == []


def test_the_domain_uid_falls_back_to_the_scope_domain_and_then_the_scope(tmp_path):
    settings = _settings(tmp_path)
    no_domain_block = {"gateways": [{"uid": "member-uid", "name": "fw-a", "ipv4-address": "192.0.2.10"}]}
    rawstore.write(settings.raw_dir, "cp-mgmt", "1000-abcdef", no_domain_block, key=dek(settings))

    mds = gw.CpGatewayCollector(
        _config(management_link=LINK | {"domain": "dom", "scope": "cp:mgmt.example:dom"}), settings
    )
    assert mds.gateway_identity(_raw()).domain == "dom"
    assert mds.gateway_identity(_raw()).domain_origin == "scope"

    single = gw.CpGatewayCollector(_config(management_link=LINK), settings)
    assert single.gateway_identity(_raw()).domain == "cp:mgmt.example"
    assert single.gateway_identity(_raw()).domain_origin == "authority"

    typed = gw.CpGatewayCollector(_config(management_link=LINK, management_domain_uid="typed-dom"), settings)
    assert typed.gateway_identity(_raw()).domain == "typed-dom"
    assert typed.gateway_identity(_raw()).domain_origin == "override"


def test_the_release_comes_from_show_version_unless_typed():
    assert gw.gateway_release(_raw(), _config()) == "R81.20"
    assert gw.gateway_release(_raw(), _config(gateway_release="R82")) == "R82"
    assert gw.gateway_release({}, _config()) == ""


def test_the_management_inventory_is_part_of_the_change_hash(tmp_path):
    settings = _settings(tmp_path)
    raw = _raw()
    before = coll.raw_sha(gw.CpGatewayCollector(_config(management_link=LINK), settings), raw)
    rawstore.write(settings.raw_dir, "cp-mgmt", "1000-abcdef", MGMT_RAW, key=dek(settings))
    after = coll.raw_sha(gw.CpGatewayCollector(_config(management_link=LINK), settings), raw)

    assert before != after


# --- the warning channel ---------------------------------------------------------------


def test_the_load_carries_the_batch_warnings_on_its_manifest(tmp_path):
    settings = _settings(tmp_path)
    collector = gw.CpGatewayCollector(_config(management_link=LINK), settings)

    manifest = coll.load_payload(
        collector, FakeSession(), _raw(), collection_ts=1, run_id="1000-abcdef", ts_ms=1000
    )

    assert len(manifest.warnings) == 1
    assert "no collected payload yet" in manifest.warnings[0]


def test_a_loads_warnings_reach_the_run_detail_and_the_run_evidence(tmp_path):
    evidence = RunEvidence(_settings(tmp_path))
    details: list[str] = []
    manifest = RunManifest(
        run_id="r", source="gaia-a", scope="x", warnings=["gaia-a/h: one", "gaia-a/h: two"]
    )

    _record_warnings(evidence, details, manifest)

    assert details == ["warning: gaia-a/h: one", "warning: gaia-a/h: two"]
    assert evidence.warnings == ["gaia-a/h: one", "gaia-a/h: two"]


def test_latest_path_picks_the_newest_run_id_and_ignores_strays(tmp_path):
    settings = _settings(tmp_path)
    assert rawstore.latest_path(settings.raw_dir, "cp-mgmt") is None
    rawstore.write(settings.raw_dir, "cp-mgmt", "3000-abcdef", {}, key=dek(settings))
    rawstore.write(settings.raw_dir, "cp-mgmt", "1000-abcdef", {}, key=dek(settings))
    (settings.raw_dir / "cp-mgmt" / f"notes{rawstore.SUFFIX}").write_bytes(b"")

    newest = rawstore.latest_path(settings.raw_dir, "cp-mgmt")

    assert newest is not None
    assert newest.name == f"3000-abcdef{rawstore.SUFFIX}"
