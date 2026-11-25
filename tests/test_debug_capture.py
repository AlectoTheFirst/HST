"""Collection debug capture (core/debug_capture.py): records that survive a kill."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import textwrap
import time
import zipfile

import pytest
from tests.test_iosxe import RAW, _collector

from hst.app.crypto import dek, generate_key
from hst.core import Settings, debug_capture, rawstore

RUN_ID = "1790000000000-abcdef12"


@pytest.fixture
def settings(tmp_path):
    return Settings(_env_file=None, hst_secret_key=generate_key(), hst_data_dir=tmp_path)


def _records(settings, source="edge", host="r1", prefix=""):
    raw_path = rawstore.raw_path_of(settings.raw_dir, source, host, RUN_ID)
    records, unreadable = debug_capture.read_records(
        rawstore.sibling(raw_path, prefix + rawstore.DEBUG_SUFFIX), dek(settings)
    )
    assert unreadable == 0
    return records


def _capture(settings, raw=None, **kw):
    return debug_capture.capture(
        settings, source="edge", host="r1", run_id=RUN_ID, collector="iosxe", raw=raw or {}, **kw
    )


def test_nothing_is_recorded_while_the_switch_is_off(settings):
    with _capture(settings) as cap:
        assert cap is None
        with debug_capture.step("normalize") as out:
            assert out == {}
    assert not settings.raw_dir.exists()


def test_the_switch_expires_and_turns_off(settings):
    debug_capture.set_switch(settings, "edge", until_ms=int(time.time() * 1000) + 60_000, by="otto")
    assert debug_capture.enabled(settings, "edge")
    assert debug_capture.switches(settings)["edge"]["by"] == "otto"
    debug_capture.set_switch(settings, "edge", until_ms=int(time.time() * 1000) - 1, by="otto")
    assert not debug_capture.enabled(settings, "edge")
    debug_capture.set_switch(settings, "edge", until_ms=None, by="otto")
    assert debug_capture.switches(settings) == {}


def test_an_iosxe_parse_records_every_template_and_parser_with_its_input(settings):
    debug_capture.set_switch(settings, "edge", until_ms=int(time.time() * 1000) + 60_000, by="otto")
    collector = _collector()
    with _capture(settings, raw=RAW):
        collector.normalize(RAW)
    records = _records(settings)
    begin = records[0]
    assert begin["event"] == "begin" and begin["collector"] == "iosxe"
    assert begin["payload"]["commands"]["show ip route vrf *"]["lines"] > 1
    assert begin["environment"]["textfsm"]
    templates = {r["command"] for r in records if r["event"] == "start" and r["step"] == "textfsm"}
    assert {"show version", "show interfaces", "show ip route vrf *", "show ip arp"} <= templates
    steps = {r["step"] for r in records if r["event"] == "end"}
    assert {"iosxe.parse", "cisco_common.parse_nat_config", "iosxe.parse_bgp_config"} <= steps
    route = next(
        r for r in records if r["event"] == "end" and r.get("step") == "textfsm" and r["records"] > 0
    )
    assert route["ms"] >= 0
    assert records[-1]["event"] == "finish" and records[-1]["status"] == "ok"
    [load] = debug_capture.summarize(records)
    assert load["finished"] and load["open_steps"] == []


def test_a_parser_that_raises_is_recorded_with_its_error(settings):
    @debug_capture.traced
    def parse_broken(text):
        raise ValueError("bad line")

    with pytest.raises(ValueError), _capture(settings, force=True):
        parse_broken("x\ny")
    records = _records(settings)
    end = next(r for r in records if r["event"] == "end")
    assert end["step"].endswith("parse_broken") and "ValueError: bad line" in end["error"]
    assert records[-1] == {**records[-1], "event": "finish", "status": "error"}


def test_the_records_written_before_a_kill_name_the_step_that_was_running(settings):
    key = settings.hst_secret_key
    dek(settings)  # the child unwraps the same data key the parent reads with
    script = textwrap.dedent(
        f"""
        import os, signal
        from hst.core import Settings, debug_capture
        settings = Settings(_env_file=None, hst_secret_key={key!r},
                            hst_data_dir={str(settings.hst_data_dir)!r})
        raw = {{"show ip route vrf *": "a\\nb"}}
        with debug_capture.capture(settings, source="edge", host="r1", run_id={RUN_ID!r},
                                   collector="iosxe", raw=raw, force=True):
            with debug_capture.step("normalize"):
                with debug_capture.step("textfsm", command="show ip route vrf *"):
                    os.kill(os.getpid(), signal.SIGKILL)
        """
    )
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=120)
    assert done.returncode == -9, done.stderr.decode()
    [load] = debug_capture.summarize(_records(settings))
    assert not load["finished"]
    assert [(s["step"], s.get("command")) for s in load["open_steps"]] == [
        ("normalize", None),
        ("textfsm", "show ip route vrf *"),
    ]


def test_a_step_past_the_limit_leaves_a_stack_dump_naming_it(settings):
    settings.hst_debug_stack_after_s = 0.2

    def stuck_in_a_parser():
        time.sleep(0.8)

    with _capture(settings, force=True), debug_capture.step("textfsm", command="show interfaces"):
        stuck_in_a_parser()
    raw_path = rawstore.raw_path_of(settings.raw_dir, "edge", "r1", RUN_ID)
    stack = rawstore.sibling(raw_path, rawstore.DEBUG_STACK_SUFFIX).read_text()
    assert "Timeout" in stack and "stuck_in_a_parser" in stack


def test_a_load_that_ran_fast_leaves_no_stack_file(settings):
    with _capture(settings, force=True), debug_capture.step("normalize"):
        pass
    raw_path = rawstore.raw_path_of(settings.raw_dir, "edge", "r1", RUN_ID)
    assert not rawstore.sibling(raw_path, rawstore.DEBUG_STACK_SUFFIX).exists()


def test_log_records_of_the_loading_thread_are_captured(settings, caplog):
    import logging

    caplog.set_level(logging.INFO)
    with _capture(settings, force=True):
        logging.getLogger("hst.collectors.cli_parse").warning("dropped %d preamble line(s)", 3)
    logs = [r for r in _records(settings) if r["event"] == "log"]
    assert logs == [
        {
            **logs[0],
            "level": "WARNING",
            "logger": "hst.collectors.cli_parse",
            "message": "dropped 3 preamble line(s)",
        }
    ]


def test_redaction_keeps_the_keyword_and_removes_what_follows():
    text = "neighbor 10.0.0.1 password 7 0822455D0A16\nsnmp-server community s3cret RO\n interface Gi1"
    assert debug_capture.redact(text) == (
        "neighbor 10.0.0.1 password <removed>\nsnmp-server community <removed>\n interface Gi1"
    )


def test_the_bundle_holds_records_summary_and_redacted_outputs(settings):
    raw = {
        "show version": "Cisco IOS XE Software",
        "show run | section router bgp": " neighbor 10.0.0.1 password 7 0822455D0A16",
        "_strata_outcomes": {"show version": {"status": "ok"}},
    }
    raw_path = rawstore.write(settings.raw_dir, "edge", RUN_ID, raw, host="r1", key=dek(settings))
    with _capture(settings, raw=raw, force=True), debug_capture.step("normalize"):
        pass
    content = b"".join(
        debug_capture.iter_bundle(settings.raw_dir, dek(settings), [raw_path], raw_mode="redacted")
    )
    bundle = zipfile.ZipFile(io.BytesIO(content))
    prefix = f"captures/edge/r1/{RUN_ID}/"
    names = set(bundle.namelist())
    assert {"environment.json", prefix + "debug.jsonl", prefix + "summary.json"} <= names
    assert prefix + "raw/show-version.txt" in names
    bgp = bundle.read(prefix + "raw/show-run-section-router-bgp.txt").decode()
    assert "0822455D0A16" not in bgp and "password <removed>" in bgp
    summary = json.loads(bundle.read(prefix + "summary.json"))
    assert summary["loads"][0]["finished"] is True
    full = b"".join(debug_capture.iter_bundle(settings.raw_dir, dek(settings), [raw_path], raw_mode="full"))
    assert b"0822455D0A16" in zipfile.ZipFile(io.BytesIO(full)).read(
        prefix + "raw/show-run-section-router-bgp.txt"
    )


UNIFI_SECRETS = (
    "Summer2026corp",
    "isp-pass",
    "Tr0ub4dor",
    "WGPRIV=",
    "deadbeefcafef00d",
    "IAPPVALUE",
    "VWIREVALUE",
)


def test_the_redacted_bundle_removes_unifi_x_secrets_and_the_vyos_snmp_community(settings):
    raw = {
        "wlans": [
            {
                "name": "corp",
                "x_passphrase": "Summer2026corp",
                "x_pppoe_password": "isp-pass",
                "x_ipsec_pre_shared_key": "Tr0ub4dor",
                "x_wireguard_private_key": "WGPRIV=",
                "x_authkey": "deadbeefcafef00d",
                "x_iapp_key": "IAPPVALUE",
                "x_vwirekey": "VWIREVALUE",
                "x_fingerprint": "aa:bb",
            }
        ],
        "config": {"service": {"snmp": {"community": {"S3CRETCOMM": {"authorization": "ro"}}}}},
    }
    raw_path = rawstore.write(settings.raw_dir, "edge", RUN_ID, raw, host="r1", key=dek(settings))
    content = b"".join(
        debug_capture.iter_bundle(settings.raw_dir, dek(settings), [raw_path], raw_mode="redacted")
    )
    bundle = zipfile.ZipFile(io.BytesIO(content))
    text = "".join(bundle.read(n).decode() for n in bundle.namelist() if "/raw/" in n)
    for secret in (*UNIFI_SECRETS, "S3CRETCOMM"):
        assert secret not in text, secret
    assert '"name": "corp"' in text and "aa:bb" in text


def test_the_line_pass_redacts_a_keyword_that_follows_an_underscore():
    assert debug_capture.redact('  "x_authkey": "cafe",') == '  "x_authkey <removed>'
    assert debug_capture.redact("monkey wrench") == "monkey wrench"


def _bundle(settings, raw_path, mode, **kw):
    content = b"".join(
        debug_capture.iter_bundle(settings.raw_dir, dek(settings), [raw_path], raw_mode=mode, **kw)
    )
    zf = zipfile.ZipFile(io.BytesIO(content))
    return {n: zf.read(n).decode() for n in zf.namelist()}


def test_every_entry_of_a_bundle_but_a_full_one_is_redacted(settings, monkeypatch):
    secrets = ("Hunter22xx", "opaque-9931", "StackSecret77", "ParseSecret55", "RunSecret11")
    raw_path = rawstore.write(
        settings.raw_dir, "edge", RUN_ID, {"show version": "System"}, host="r1", key=dek(settings)
    )
    with _capture(settings, force=True) as cap:
        cap.record(
            "log", level="ERROR", logger="x", message="auth failed password=Hunter22xx for opaque-9931"
        )
        cap.record("note", x_passphrase="Hunter22xx")
        with debug_capture.step("login", command="show run"):
            pass
    rawstore.sibling(raw_path, rawstore.DEBUG_STACK_SUFFIX).write_text(
        'File "x.py", line 3\n  raise Error("password=StackSecret77")\nok line\n'
    )
    debug_capture.write_reparse(
        raw_path, {"error": "failed opaque-9931", "x_authkey": "ParseSecret55"}, dek(settings)
    )

    def refuse(path, key):
        raise RuntimeError("cannot read, token=Hunter22xx opaque-9931")

    monkeypatch.setattr(rawstore, "read", refuse)
    kw = {
        "extra": {"run.json": {"detail": "failed with password=RunSecret11", "id": 4}},
        "known": ["opaque-9931"],
    }
    prefix = f"captures/edge/r1/{RUN_ID}/"
    for mode in ("redacted", "none"):
        entries = _bundle(settings, raw_path, mode, **kw)
        joined = "\n".join(entries.values())
        for secret in secrets:
            assert secret not in joined, (mode, secret)
        assert {prefix + "debug.jsonl", prefix + "summary.json", prefix + "stack.txt"} <= set(entries)
        assert {prefix + "reparse.json", "run.json"} <= set(entries)
        assert (prefix + "raw/_error.txt" in entries) == (mode == "redacted")
        assert "ok line" in entries[prefix + "stack.txt"]
        assert json.loads(entries["run.json"])["id"] == 4
        for line in entries[prefix + "debug.jsonl"].splitlines():
            json.loads(line)
    full = "\n".join(_bundle(settings, raw_path, "full", **kw).values())
    for secret in ("Hunter22xx", "StackSecret77", "RunSecret11", "ParseSecret55"):
        assert secret in full, secret


def test_the_outcomes_of_a_redacted_bundle_lose_the_text_a_device_answered(settings):
    raw = {
        "show version": "System",
        "_strata_outcomes": {"show version": {"status": "failed", "detail": "bad password=OutcomeSecret33"}},
    }
    raw_path = rawstore.write(settings.raw_dir, "edge", RUN_ID, raw, host="r1", key=dek(settings))
    entries = _bundle(settings, raw_path, "redacted")
    assert "OutcomeSecret33" not in "\n".join(entries.values())
    assert '"status": "failed"' in entries[f"captures/edge/r1/{RUN_ID}/raw/_outcomes.json"]


def test_a_collector_built_without_settings_is_never_captured():
    with debug_capture.capture(
        None, source="edge", host="r1", run_id=RUN_ID, collector="iosxe", raw={}
    ) as cap:
        assert cap is None
