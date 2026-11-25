"""The debug bundle, streamed (core/debug_capture.py `iter_bundle`).

The bundle is written front to back into pieces handed out as they are
ready, the payload's commands are written a line or a JSON member at a time,
and the records are read a line at a time. The zip holds, entry for entry and
byte for byte, the bundle of the reference builder below, which builds the
whole bundle in memory.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import math
import zipfile
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet, InvalidToken

from hst.app.crypto import dek, generate_key
from hst.core import Settings, debug_capture, rawstore

RUN_ID = "1790000000000-abcdef12"
RUN_ID_2 = "1790000000001-abcdef13"
RUN_ID_3 = "1790000000002-abcdef14"


# --- the reference builder of the bundle ------------------------------------------


def _base_read_records(path: Path, key: str) -> tuple[list[dict[str, Any]], int]:
    fernet = Fernet(key.encode())
    records: list[dict[str, Any]] = []
    unreadable = 0
    try:
        lines = path.read_bytes().splitlines()
    except OSError:
        return records, 0
    for line in lines:
        if not line.strip():
            continue
        try:
            body = json.loads(fernet.decrypt(line))
        except (InvalidToken, ValueError):
            unreadable += 1
            continue
        if isinstance(body, dict):
            records.append(body)
    return records, unreadable


def _base_summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    loads: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    open_steps: list[dict[str, Any]] = []
    for r in records:
        event = r.get("event")
        if event == "begin":
            if current is not None:
                current["open_steps"] = list(open_steps)
            open_steps = []
            env = r.get("environment") or {}
            current = {
                "kind": r.get("kind"),
                "collector": r.get("collector"),
                "begin_ms": r.get("ts_ms"),
                "last_ms": r.get("ts_ms"),
                "finished": False,
                "status": None,
                "error": None,
                "peak_rss_kb": env.get("peak_rss_kb") or env.get("rss_kb"),
                "cgroup_memory_max": env.get("cgroup_memory_max"),
                "oom_kill_at_begin": env.get("oom_kill"),
                "slowest_steps": [],
                "warnings": 0,
                "errors": 0,
            }
            loads.append(current)
            continue
        if current is None:
            continue
        current["last_ms"] = r.get("ts_ms") or current["last_ms"]
        for key in ("rss_kb", "peak_rss_kb"):
            value = r.get(key)
            if isinstance(value, int) and value > (current["peak_rss_kb"] or 0):
                current["peak_rss_kb"] = value
        if event == "start":
            open_steps.append({k: v for k, v in r.items() if k != "event"})
        elif event == "end":
            for i in range(len(open_steps) - 1, -1, -1):
                if open_steps[i].get("step") == r.get("step") and open_steps[i].get("depth") == r.get(
                    "depth"
                ):
                    del open_steps[i]
                    break
            current["slowest_steps"].append(
                {
                    "step": r.get("step"),
                    "ms": r.get("ms"),
                    **({"error": r["error"]} if r.get("error") else {}),
                }
            )
        elif event == "log":
            level = r.get("level")
            if level == "WARNING":
                current["warnings"] += 1
            elif level in ("ERROR", "CRITICAL"):
                current["errors"] += 1
        elif event == "finish":
            current["finished"] = True
            current["status"] = r.get("status")
            current["error"] = r.get("error")
    if current is not None:
        current["open_steps"] = list(open_steps)
    for load in loads:
        load["slowest_steps"] = sorted(load["slowest_steps"], key=lambda s: -(s.get("ms") or 0))[:10]
    return loads


def _base_raw_entries(raw: Any, mode: str) -> dict[str, str]:
    from hst.collectors.offline import raw_file_name

    if not isinstance(raw, dict):
        text = json.dumps(raw, indent=1, default=str)
        return {"payload.json": debug_capture.redact(text) if mode == "redacted" else text}
    out: dict[str, str] = {}
    for key, value in raw.items():
        if key == "_strata_outcomes":
            out["_outcomes.json"] = json.dumps(value, indent=1, default=str)
            continue
        if isinstance(value, str):
            name, text = raw_file_name(str(key)), value
        else:
            name, text = (
                f"{raw_file_name(str(key)).rsplit('.', 1)[0]}.json",
                json.dumps(value, indent=1, default=str),
            )
        out[name] = debug_capture.redact(text) if mode == "redacted" else text
    return out


def _base_add_raw_file(
    bundle: zipfile.ZipFile, raw_path: Path, key: str, *, prefix: str, raw_mode: str
) -> None:
    for kind, record_suffix, stack_suffix in (
        ("", rawstore.DEBUG_SUFFIX, rawstore.DEBUG_STACK_SUFFIX),
        (
            "reparse-",
            rawstore.REPARSE_PREFIX + rawstore.DEBUG_SUFFIX,
            rawstore.REPARSE_PREFIX + rawstore.DEBUG_STACK_SUFFIX,
        ),
    ):
        records_path = rawstore.sibling(raw_path, record_suffix)
        if records_path.is_file():
            records, unreadable = _base_read_records(records_path, key)
            bundle.writestr(
                f"{prefix}{kind}debug.jsonl", "".join(json.dumps(r, default=str) + "\n" for r in records)
            )
            bundle.writestr(
                f"{prefix}{kind}summary.json",
                json.dumps(
                    {"loads": _base_summarize(records), "unreadable_lines": unreadable}, indent=1, default=str
                ),
            )
        stack_path = rawstore.sibling(raw_path, stack_suffix)
        if stack_path.is_file():
            # the stream reads UTF-8, which faulthandler's ASCII always is
            bundle.writestr(
                f"{prefix}{kind}stack.txt", stack_path.read_text(encoding="utf-8", errors="replace")
            )
    result = debug_capture.read_reparse(raw_path, key)
    if result is not None:
        bundle.writestr(f"{prefix}reparse.json", json.dumps(result, indent=1, default=str))
    if raw_mode != "none" and raw_path.is_file():
        try:
            raw = rawstore.read(raw_path, key)
        except Exception as exc:
            bundle.writestr(f"{prefix}raw/_error.txt", debug_capture._describe(exc))
        else:
            for name, text in _base_raw_entries(raw, raw_mode).items():
                bundle.writestr(f"{prefix}raw/{name}", text)


def _base_bundle(
    raw_dir: Path, key: str, raw_paths: list[Path], *, raw_mode: str, extra: dict[str, Any] | None = None
) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("environment.json", json.dumps(debug_capture.environment(), indent=1, default=str))
        for name, value in (extra or {}).items():
            bundle.writestr(name, json.dumps(value, indent=1, default=str))
        root = raw_dir.resolve()
        for raw_path in raw_paths:
            relative = raw_path.resolve().relative_to(root)
            stem = relative.name[: -len(rawstore.SUFFIX)]
            prefix = "captures/" + "/".join((*relative.parent.parts, stem)) + "/"
            _base_add_raw_file(bundle, raw_path, key, prefix=prefix, raw_mode=raw_mode)
    return buffer.getvalue()


# --- the estate --------------------------------------------------------------------


@pytest.fixture
def settings(tmp_path):
    return Settings(_env_file=None, hst_secret_key=generate_key(), hst_data_dir=tmp_path)


def _long_config(lines: int) -> str:
    out = []
    for i in range(lines):
        if i % 7 == 0:
            out.append(f" neighbor 10.0.{i % 250}.1 password 7 0822455D0A{i:06d}")
        elif i % 11 == 0:
            out.append(f"snmp-server community s3cret{i} RO\r")
        elif i % 13 == 0:
            out.append(f" description café → core {i} key")
        else:
            out.append(f" ip route 10.{i % 250}.{i % 199}.0 255.255.255.0 192.0.2.{i % 250}")
    return "\n".join(out) + "\n"


def _nxos_like(rows: int) -> dict[str, Any]:
    return {
        "TABLE_vrf": {
            "ROW_vrf": [
                {
                    "vrf-name-out": "default",
                    "TABLE_prefix": {
                        "ROW_prefix": [
                            {
                                "ipprefix": f"10.{i // 250}.{i % 250}.0/24",
                                "ucast-nhops": 1,
                                "attached": i % 3 == 0,
                                "TABLE_path": {
                                    "ROW_path": [{"ipnexthop": "192.0.2.1", "pref": 20, "metric": 0.5}]
                                },
                                "tag": None,
                                "descr": "key-string abc\nsecond line",
                            }
                            for i in range(rows)
                        ]
                    },
                }
            ]
        },
        "keys": {f"k{i}": [] if i % 2 else {} for i in range(300)},
        "unicode": "é中",
        "floats": [1.5, math.inf, -math.inf],
    }


PAYLOAD: dict[str, Any] = {
    "show version": "Cisco IOS XE Software\r\nVersion 17.9\n",
    "show running-config": _long_config(9000),
    "show ip route vrf *": "",
    "show ip route | json": _nxos_like(700),
    # the same file name as the command above: the entry sits where the first
    # one is and holds this one
    "show ip route  |  json": {"small": [1, 2, 3], "password": "hunter2"},
    "show run | section router bgp": " neighbor 10.0.0.1 password 7 0822455D0A16\n authentication-key x",
    "_strata_outcomes": {"show version": {"status": "ok"}, "show ip route vrf *": {"status": "empty"}},
}


def _records(settings: Settings, raw_path: Path, prefix: str = "") -> None:
    """Two loads of the payload: one that finished, one that did not, plus a
    record before the first begin, an unmatched end, and a line cut short."""
    cap = debug_capture.Capture(
        rawstore.sibling(raw_path, prefix + rawstore.DEBUG_SUFFIX),
        rawstore.sibling(raw_path, prefix + rawstore.DEBUG_STACK_SUFFIX),
        dek(settings),
        stack_after_s=20,
    )
    cap.record("memory", rss_kb=1)
    cap.record("begin", kind="run", collector="iosxe", environment={"rss_kb": 1000, "oom_kill": 0})
    for n in range(14):
        cap.record("start", step=f"step{n}", depth=1, command=f"show {n}", rss_kb=2000 + n)
        cap.record(
            "end",
            step=f"step{n}",
            depth=1,
            ms=float(n % 5),
            rss_kb=2100,
            **({"error": "E"} if n == 3 else {}),
        )
    cap.record("log", level="WARNING", logger="x", message="w é")
    cap.record("log", level="ERROR", logger="x", message="e")
    cap.record("end", step="nowhere", depth=9, ms=1.0)
    cap.record("finish", status="ok", peak_rss_kb=5000)
    cap.record("begin", kind="run", collector="iosxe", environment={"peak_rss_kb": 7})
    cap.record("start", step="iosxe.parse", depth=1)
    cap.record("start", step="textfsm", depth=2, command="show ip route vrf *")
    cap.record("memory", rss_kb=9000, cgroup_current_bytes=1)
    cap.close()
    with rawstore.sibling(raw_path, prefix + rawstore.DEBUG_SUFFIX).open("ab") as handle:
        handle.write(b"gAAAAAB-cut-short\n\n")
    stack = rawstore.sibling(raw_path, prefix + rawstore.DEBUG_STACK_SUFFIX)
    stack.write_bytes(
        b'Timeout (0:00:20)!\r\nThread 0x1 (most recent call first):\n  File "a.py", line 3\xff\n'
    )


def _estate(settings: Settings) -> list[Path]:
    key = dek(settings)
    first = rawstore.write(settings.raw_dir, "edge", RUN_ID, PAYLOAD, host="r1", key=key)
    _records(settings, first)
    _records(settings, first, prefix=rawstore.REPARSE_PREFIX)
    debug_capture.write_reparse(first, {"state": "ok", "report": {"sections": [1, 2]}, "exit_code": 0}, key)
    # a payload that is not an object
    second = rawstore.write(
        settings.raw_dir, "edge", RUN_ID_2, [{"x": i} for i in range(400)], host="r2", key=key
    )
    # a payload that cannot be read
    third = rawstore.write(settings.raw_dir, "core", RUN_ID_3, {"show version": "x"}, key=key)
    third.write_bytes(b"not a token")
    _records(settings, third)
    return [first, second, third]


def _entries(content: bytes) -> list[tuple[str, bytes]]:
    with zipfile.ZipFile(io.BytesIO(content)) as bundle:
        assert bundle.testzip() is None
        return [(info.filename, bundle.read(info)) for info in bundle.infolist()]


@pytest.mark.parametrize("raw_mode", ["redacted", "full", "none"])
def test_the_streamed_bundle_holds_what_the_reference_bundle_holds(settings, raw_mode):
    paths = _estate(settings)
    key = dek(settings)
    extra = {"run.json": {"id": 7, "detail": "orphaned by crash"}}
    streamed = _entries(
        b"".join(debug_capture.iter_bundle(settings.raw_dir, key, paths, raw_mode=raw_mode, extra=extra))
    )
    base = _entries(_base_bundle(settings.raw_dir, key, paths, raw_mode=raw_mode, extra=extra))
    assert [name for name, _ in streamed] == [name for name, _ in base]
    # the environment is read at the moment of the build
    assert (
        json.loads(dict(streamed)["environment.json"]).keys()
        == json.loads(dict(base)["environment.json"]).keys()
    )
    # the text of the error that stopped a payload is redacted like the rest
    error_name = f"captures/core/{RUN_ID_3}/raw/_error.txt"
    held = ("environment.json", error_name)
    assert [e for e in streamed if e[0] not in held] == [e for e in base if e[0] not in held]
    names = dict(streamed)
    if raw_mode == "full":
        assert names[error_name] == dict(base)[error_name]
    if raw_mode == "redacted":
        assert names[error_name].startswith(b"SecretKeyError: ") and b"<removed>" in names[error_name]
    prefix = f"captures/edge/r1/{RUN_ID}/"
    assert json.loads(names[prefix + "summary.json"])["unreadable_lines"] == 1
    if raw_mode == "redacted":
        assert b"0822455D0A" not in names[prefix + "raw/show-run-section-router-bgp.txt"]
        assert b"hunter2" not in names[prefix + "raw/show-ip-route.json"]
    if raw_mode == "none":
        assert not any("/raw/" in name for name in names)


def test_the_bundle_is_handed_out_in_bounded_pieces(settings, monkeypatch):
    """A piece is what the zip holds once a chunk's worth is ready: at most a
    chunk, plus the compressed batch of text that took it past."""
    paths = _estate(settings)
    monkeypatch.setattr(debug_capture, "_BUNDLE_CHUNK", 16 * 1024)
    pieces = list(debug_capture.iter_bundle(settings.raw_dir, dek(settings), paths, raw_mode="full"))
    whole = b"".join(pieces)
    assert len(pieces) >= 3
    assert all(pieces) and max(len(p) for p in pieces) < 16 * 1024 + 2 * debug_capture._TEXT_BATCH
    assert [name for name, _ in _entries(whole)][:2] == [
        "environment.json",
        f"captures/edge/r1/{RUN_ID}/debug.jsonl",
    ]


def test_every_entry_is_dated_with_the_time_of_the_build(settings):
    """An entry written in pieces carries the date and the attributes of one
    written whole, and not the zip format's zero date."""
    paths = _estate(settings)
    content = b"".join(
        debug_capture.iter_bundle(
            settings.raw_dir, dek(settings), paths, raw_mode="full", extra={"run.json": {"id": 7}}
        )
    )
    with zipfile.ZipFile(io.BytesIO(content)) as bundle:
        infos = bundle.infolist()
    names = {info.filename for info in infos}
    prefix = f"captures/edge/r1/{RUN_ID}/"
    assert {"environment.json", "run.json", prefix + "debug.jsonl", prefix + "stack.txt"} <= names
    assert {prefix + "reparse.json", prefix + "raw/show-ip-route.json"} <= names
    [dated] = {info.date_time for info in infos}
    assert dated != (1980, 1, 1, 0, 0, 0)
    assert {(info.compress_type, info.external_attr) for info in infos} == {
        (zipfile.ZIP_DEFLATED, 0o600 << 16)
    }


def test_the_payload_is_let_go_of_as_its_commands_are_written(settings):
    """Each command's output leaves the payload once its entry is written."""
    raw = dict(PAYLOAD)
    sink = debug_capture._Sink()
    with zipfile.ZipFile(sink, "w", zipfile.ZIP_DEFLATED) as bundle:
        pieces = debug_capture._raw_entries(
            bundle, sink, raw, prefix="p/", mode="full", stamp=(2026, 9, 27, 12, 0, 0)
        )
        sizes = []
        for _ in pieces:
            sizes.append(len(raw))
    assert raw == {}
    assert sizes == sorted(sizes, reverse=True)


VALUES: list[Any] = [
    None,
    True,
    3,
    2.5,
    math.nan,
    "line\nbreak é",
    [],
    {},
    (1, 2),
    list(range(300)),
    [[]] * 300,
    {f"k{i}": {"nested": list(range(i % 4)), "s": "a\nb"} for i in range(400)},
    {"outer": [{"inner": list(range(500))}] * 3},
    {i: i for i in range(400)},
    {**{f"k{i}": i for i in range(300)}, 5: "a key that is not a string"},
    [dt.date(2026, 9, 27), Path("/x"), {"when": dt.datetime(2026, 9, 27, 1, 2, 3, tzinfo=dt.UTC)}] * 120,
    _nxos_like(300),
]


@pytest.mark.parametrize("index", range(len(VALUES)))
def test_json_pieces_join_to_the_indented_dump(index):
    value = VALUES[index]
    assert "".join(debug_capture._json_pieces(value)) == json.dumps(value, indent=1, default=str)


def test_a_large_answer_is_encoded_a_member_at_a_time():
    value = _nxos_like(5000)
    pieces = list(debug_capture._json_pieces(value))
    assert "".join(pieces) == json.dumps(value, indent=1, default=str)
    assert max(len(p) for p in pieces) < 16 * 1024


@pytest.mark.parametrize(
    "pieces",
    [
        ["password 1\nsecret", " 2\n", "", "key", "-string 3\n", "no newline password x"],
        ["\n\n", "token abc\r\n", "community"],
        ["", ""],
        ["a" * 70_000 + " psk z\n" + "b" * 10],
    ],
)
def test_redaction_over_pieces_is_redaction_of_the_whole(pieces):
    text = "".join(pieces)
    assert "".join(debug_capture._redacted_pieces(pieces)) == debug_capture.redact(text)
    assert "".join(debug_capture._text_pieces(text, "redacted")) == debug_capture.redact(text)
    assert "".join(debug_capture._text_pieces(text, "full")) == text


def test_the_summary_fed_a_record_at_a_time_is_the_reference_summary(settings):
    raw_path = rawstore.raw_path_of(settings.raw_dir, "edge", "r1", RUN_ID)
    raw_path.parent.mkdir(parents=True)
    _records(settings, raw_path)
    path = rawstore.sibling(raw_path, rawstore.DEBUG_SUFFIX)
    records, unreadable = _base_read_records(path, dek(settings))
    assert debug_capture.read_records(path, dek(settings)) == (records, unreadable) and unreadable == 1
    assert debug_capture.summarize(records) == _base_summarize(records)
    summary = debug_capture.LoadSummary()
    for record in records[:5]:
        summary.add(record)
    # a summary taken part way changes nothing the later records add to
    assert summary.result() == _base_summarize(records[:5])
    for record in records[5:]:
        summary.add(record)
    assert summary.result() == _base_summarize(records)


def test_a_record_file_that_cannot_be_opened_reads_as_no_records(settings):
    reader = debug_capture.RecordReader(settings.raw_dir / "missing.debug.jsonl", dek(settings))
    assert list(reader) == [] and reader.unreadable == 0


def test_a_stack_file_removed_after_the_listing_leaves_a_whole_zip_without_it(settings, monkeypatch):
    paths = _estate(settings)
    stack = rawstore.sibling(paths[0], rawstore.DEBUG_STACK_SUFFIX)
    stack.unlink()
    real = Path.is_file
    # the file was there when it was looked for
    monkeypatch.setattr(Path, "is_file", lambda self: True if self == stack else real(self))

    content = b"".join(debug_capture.iter_bundle(settings.raw_dir, dek(settings), paths, raw_mode="full"))

    names = [name for name, _ in _entries(content)]
    prefix = f"captures/edge/r1/{RUN_ID}/"
    assert prefix + "stack.txt" not in names
    assert prefix + "stack_error.txt" not in names
    assert {prefix + "reparse-stack.txt", prefix + "reparse.json", prefix + "raw/show-ip-route.json"} <= set(
        names
    )


def test_a_stack_file_that_cannot_be_opened_is_named_in_the_bundle(settings, monkeypatch):
    paths = _estate(settings)
    stack = rawstore.sibling(paths[0], rawstore.DEBUG_STACK_SUFFIX)
    real = Path.open

    def refusing(self, *args, **kwargs):
        if self == stack:
            raise PermissionError(13, "Permission denied")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", refusing)

    content = b"".join(debug_capture.iter_bundle(settings.raw_dir, dek(settings), paths, raw_mode="full"))

    entries = dict(_entries(content))
    prefix = f"captures/edge/r1/{RUN_ID}/"
    assert prefix + "stack.txt" not in entries
    assert entries[prefix + "stack_error.txt"] == b"PermissionError: [Errno 13] Permission denied"
    assert prefix + "reparse-stack.txt" in entries
