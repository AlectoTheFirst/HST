"""`hst parse-raw`: an offline parse of a capture, reported section by section.
The payloads are the hand-written NX-OS ones from tests/test_nxos.py, written
out one file per command."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.test_checkpoint import CP_OBJECTS, CP_RULEBASE_PAGE
from tests.test_nxos import CDP_PAYLOAD, HSRP_PAYLOAD, RAW, VPC_PAYLOAD, VRRP_PAYLOAD
from typer.testing import CliRunner

import hst.cli as cli
from hst.app.crypto import dek, generate_key
from hst.collectors import nxos, offline
from hst.collectors.nxos import CMD_VRF, SECTIONS, NxosCollector
from hst.core import rawstore
from hst.core.config import Settings

runner = CliRunner()


def _settings(monkeypatch, tmp_path, **kw) -> Settings:
    settings = Settings(_env_file=None, hst_data_dir=tmp_path / "data", **kw)
    monkeypatch.setattr(cli, "Settings", lambda: settings)
    return settings


@pytest.fixture
def capture(tmp_path) -> Path:
    directory = tmp_path / "nxos-fr2-core-01"
    directory.mkdir()
    for command, text in RAW.items():
        (directory / offline.raw_file_name(command)).write_text(text, encoding="utf-8")
    # RAW answers the first-hop redundancy, vPC and CDP commands with the
    # stand-in of a box without the feature or the neighbors. This capture is
    # a box with all of them, so every section reads ok.
    for command, payload in (
        (nxos.CMD_CDP, CDP_PAYLOAD),
        (nxos.CMD_HSRP, HSRP_PAYLOAD),
        (nxos.CMD_VRRP, VRRP_PAYLOAD),
        (nxos.CMD_VPC, VPC_PAYLOAD),
    ):
        (directory / offline.raw_file_name(command)).write_text(json.dumps(payload), encoding="utf-8")
    # and a VLAN access map, which RAW answers with nothing configured
    (directory / offline.raw_file_name(nxos.CMD_VLAN_FILTER)).write_text(
        "vlan filter GUEST-MAP vlan-list 10\n", encoding="utf-8"
    )
    return directory


# --- file naming ----------------------------------------------------------------------


def test_raw_file_name_drops_the_json_filter_and_slugs_the_rest():
    assert offline.raw_file_name("show vrf | json") == "show-vrf.json"
    assert offline.raw_file_name("show running-config nat") == "show-running-config-nat.txt"
    assert offline.raw_file_name("show ip route vrf *") == "show-ip-route-vrf-star.txt"
    assert (
        offline.raw_file_name("show running-config | include ^ip nat")
        == "show-running-config-include-ip-nat.txt"
    )
    assert (
        offline.raw_file_name("vsenv 1 >/dev/null && ip -j address show")
        == "vsenv-1-dev-null-ip-j-address-show.txt"
    )


def test_every_nxos_command_names_a_distinct_file():
    names = [offline.raw_file_name(c) for c in nxos.COMMANDS]
    assert len(names) == len(set(names))


# --- a full directory capture -----------------------------------------------------------


def test_a_directory_of_the_nxos_payloads_reports_every_section_ok(monkeypatch, tmp_path, capture):
    _settings(monkeypatch, tmp_path)
    r = runner.invoke(cli.app, ["parse-raw", "nxos", str(capture), "--json"])
    assert r.exit_code == 0, r.stdout
    report = json.loads(r.stdout)
    assert report["ok"] is True and report["error"] is None
    for name in SECTIONS:
        assert report["sections"][name]["status"] == "ok", name
    assert report["sections"]["vrfs"]["file"] == "show-vrf.json"
    assert report["labels"]["Device"] == 1
    assert report["labels"]["VrfInstance"] >= 1
    assert report["side_tables"]["rib"] > 0
    assert report["outcomes"]["rib"]["status"] == "complete"
    assert report["missing_files"] == {}
    assert report["unrecognised_files"] == []


def test_the_table_view_prints_one_row_per_section(monkeypatch, tmp_path, capture):
    _settings(monkeypatch, tmp_path)
    r = runner.invoke(cli.app, ["parse-raw", "nxos", str(capture)])
    assert r.exit_code == 0, r.stdout
    for name in ("device", "interfaces", "vrfs", "rib", "ospf"):
        assert name in r.stdout
    assert "nodes: " in r.stdout and "Device 1" in r.stdout


# --- a capture with a required command missing --------------------------------------------


def test_a_missing_required_file_reads_malformed_and_the_rest_is_reported(monkeypatch, tmp_path, capture):
    _settings(monkeypatch, tmp_path)
    (capture / offline.raw_file_name(CMD_VRF)).unlink()
    r = runner.invoke(cli.app, ["parse-raw", "nxos", str(capture), "--json"])
    assert r.exit_code == 1
    report = json.loads(r.stdout)
    assert report["ok"] is False
    vrfs = report["sections"]["vrfs"]
    assert vrfs["status"] == "malformed"
    assert "show-vrf.json" in vrfs["detail"]
    assert report["sections"]["interfaces"]["status"] == "ok"
    assert report["sections"]["rib"]["status"] == "ok"
    assert report["missing_files"] == {CMD_VRF: "show-vrf.json"}
    assert report["labels"]["Device"] == 1


def test_a_missing_optional_file_is_named_and_does_not_hide_the_other_sections(
    monkeypatch, tmp_path, capture
):
    _settings(monkeypatch, tmp_path)
    (capture / offline.raw_file_name(nxos.CMD_LLDP)).unlink()
    (capture / "show-vlan.jsn").write_text("{}", encoding="utf-8")
    r = runner.invoke(cli.app, ["parse-raw", "nxos", str(capture), "--json"])
    report = json.loads(r.stdout)
    assert report["sections"]["neighbors"]["status"] == "failed"
    assert "show-lldp-neighbors-detail.json" in report["sections"]["neighbors"]["detail"]
    assert report["sections"]["interfaces"]["status"] == "ok"
    assert report["unrecognised_files"] == ["show-vlan.jsn"]


def test_a_file_that_is_not_json_is_reported_as_a_parse_error(monkeypatch, tmp_path, capture):
    _settings(monkeypatch, tmp_path)
    (capture / "show-version.json").write_text("% Invalid command\n", encoding="utf-8")
    r = runner.invoke(cli.app, ["parse-raw", "nxos", str(capture), "--json"])
    assert r.exit_code == 1
    report = json.loads(r.stdout)
    assert report["error"] is not None and report["error"].startswith("normalize:")


# --- a raw-store file ---------------------------------------------------------------------


def test_a_raw_store_file_is_decrypted_and_parsed(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path, hst_secret_key=generate_key())
    live = dict(RAW)
    live["_strata_outcomes"] = {cmd: {"status": "ok"} for cmd in RAW}
    path = rawstore.write(
        settings.raw_dir, "nxos-fr2", "1700000000000-abcdef12", live, host="core1", key=dek(settings)
    )
    r = runner.invoke(cli.app, ["parse-raw", "nxos", str(path), "--json"])
    assert r.exit_code == 0, r.stdout
    report = json.loads(r.stdout)
    assert report["sections"]["vrfs"]["status"] == "ok"
    assert report["labels"]["Device"] == 1


def test_a_raw_store_file_without_a_secret_key_fails_closed(monkeypatch, tmp_path):
    _settings(monkeypatch, tmp_path)
    path = tmp_path / "x.json.gz.enc"
    path.write_bytes(b"not a token")
    r = runner.invoke(cli.app, ["parse-raw", "nxos", str(path)])
    assert r.exit_code == 2
    assert "HST_SECRET_KEY" in r.stdout


# --- the command listing and the guards ---------------------------------------------------


def test_commands_lists_the_capture_file_per_command(monkeypatch, tmp_path):
    _settings(monkeypatch, tmp_path)
    r = runner.invoke(cli.app, ["parse-raw", "nxos", "--commands", "--json"])
    assert r.exit_code == 0, r.stdout
    rows = {row["command"]: row for row in json.loads(r.stdout)}
    assert rows[CMD_VRF] == {"command": CMD_VRF, "kind": "required", "file": "show-vrf.json"}
    assert rows[nxos.CMD_LLDP]["kind"] == "optional"
    assert rows[nxos.CMD_BGP_SESSIONS]["kind"] == "optional (capture_bgp)"


def test_an_unknown_collector_and_a_missing_path_are_usage_errors(monkeypatch, tmp_path):
    _settings(monkeypatch, tmp_path)
    assert runner.invoke(cli.app, ["parse-raw", "frobnicate", str(tmp_path)]).exit_code == 2
    assert runner.invoke(cli.app, ["parse-raw", "nxos"]).exit_code == 2
    assert runner.invoke(cli.app, ["parse-raw", "nxos", str(tmp_path / "absent")]).exit_code == 2


def test_a_collector_whose_config_needs_identity_fields_asks_for_config(monkeypatch, tmp_path):
    _settings(monkeypatch, tmp_path)
    r = runner.invoke(cli.app, ["parse-raw", "checkpoint_gateway", str(tmp_path)])
    assert r.exit_code == 2
    assert "--config" in r.stdout


def test_config_builds_the_collector_from_the_stored_shape(monkeypatch, tmp_path, capture):
    _settings(monkeypatch, tmp_path)
    cfg = tmp_path / "nxos.json"
    cfg.write_text(
        json.dumps(
            {
                "host": "core1",
                "auth": {"method": "password", "username": "ro", "password": "pw"},
                "site_code": "fr2",
                "capture_bgp": "none",
            }
        )
    )
    r = runner.invoke(cli.app, ["parse-raw", "nxos", str(capture), "--config", str(cfg), "--json"])
    assert r.exit_code == 0, r.stdout
    report = json.loads(r.stdout)
    assert report["outcomes"]["bgp_session_routes"]["status"] == "not-captured"


# --- a collector without a command loop -----------------------------------------------------


def test_the_checkpoint_directory_is_read_key_by_key(monkeypatch, tmp_path):
    _settings(monkeypatch, tmp_path)
    directory = tmp_path / "cp-mgmt"
    directory.mkdir()
    gateways = [{"uid": "gw-1", "name": "fw1", "type": "simple-gateway", "ipv4-address": "10.9.0.1"}]
    layers = [{"uid": "layer-1", "name": "Network"}]
    (directory / "gateways.json").write_text(json.dumps(gateways))
    (directory / "layers.json").write_text(json.dumps(layers))
    (directory / "rulebases.json").write_text(json.dumps({"layer-1": [CP_RULEBASE_PAGE]}))
    (directory / "packages.json").write_text(json.dumps([]))
    r = runner.invoke(cli.app, ["parse-raw", "checkpoint", str(directory), "--json"])
    report = json.loads(r.stdout)
    assert report["error"] is None, report["error"]
    assert report["sections"]["access"]["status"] == "ok"
    assert report["sections"]["nat"]["status"] == "empty"
    assert report["labels"]["Device"] == 1
    assert report["labels"]["FwRule"] == 2
    assert set(report["missing_files"]) == set(offline.CHECKPOINT_RAW_KEYS) - {
        "gateways",
        "layers",
        "rulebases",
        "packages",
    }
    assert any(o["name"] == "web-fe" for o in CP_OBJECTS)


# --- the report helper on its own ------------------------------------------------------------


def test_parse_report_mirrors_the_manifest_outcomes_without_writing(tmp_path):
    from hst.collectors.auth import SshAgent
    from hst.collectors.nxos import NxosConfig

    collector = NxosCollector(NxosConfig(host="core1", auth=SshAgent(username="ro")), None)
    raw = {**RAW, "_strata_outcomes": {cmd: {"status": "ok"} for cmd in RAW}}
    report = offline.parse_report(collector, raw, path="memory")
    assert report.ok
    assert report.outcomes["rib"].status == "complete"
    assert report.outcomes["rib"].row_count == report.side_tables["rib"]
    assert "ospf_lsdb" in report.outcomes
    assert not list(tmp_path.iterdir())
