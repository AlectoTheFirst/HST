"""No configured credential reaches a reader by any output path.

Each vendor payload below is built around distinct credential values and sent
through every path that hands collected data on: the redaction of a parsed
payload, the redacted debug bundle, the HTTP trace body, the interface text,
and the error text stored with a device. The assertion is the same for all of
them: none of the values appears in what came out.
"""

from __future__ import annotations

import asyncio
import copy
import gzip
import io
import json
import zipfile
from typing import Any

import pytest
from cryptography.fernet import Fernet

from hst.app import runs_exec
from hst.collectors import http_trace
from hst.core import debug_capture, rawstore, redaction
from hst.map import interface_text

KEY = Fernet.generate_key().decode()

UNIFI_SECRETS = (
    "Summer2026corp",
    "isp-pass-77",
    "Tr0ub4dor-psk",
    "WGPRIVKEY0123456789=",
    "deadbeefcafef00d",
    "iapp-5521",
)
VYOS_SECRETS = ("snmp-community-9x", "cak-0011223344556677", "psk-peer-secret-31", "bgp-md5-pass-42")
EQUINIX_SECRETS = ("auth-key-EQX-8842",)
RECORD_SECRETS = ("record-value-6603",)


def _unifi() -> dict[str, Any]:
    return {
        "rest/wlanconf": [{"name": "corp", "x_passphrase": UNIFI_SECRETS[0], "security": "wpapsk"}],
        "rest/networkconf": [
            {
                "name": "wan",
                "x_pppoe_password": UNIFI_SECRETS[1],
                "x_ipsec_pre_shared_key": UNIFI_SECRETS[2],
                "x_wireguard_private_key": UNIFI_SECRETS[3],
            }
        ],
        "stat/device": [{"name": "sw1", "x_authkey": UNIFI_SECRETS[4], "x_iapp_key": UNIFI_SECRETS[5]}],
    }


def _vyos() -> dict[str, Any]:
    return {
        "service": {"snmp": {"community": {VYOS_SECRETS[0]: {"authorization": "ro"}}}},
        "interfaces": {"macsec": {"macsec0": {"security": {"mka": {"cak": VYOS_SECRETS[1]}}}}},
        "vpn": {"ipsec": {"authentication": {"psk": {"peer1": {"secret": VYOS_SECRETS[2]}}}}},
        "protocols": {"bgp": {"neighbor": {"10.0.0.1": {"password": VYOS_SECRETS[3]}}}},
    }


def _equinix() -> dict[str, Any]:
    return {
        "connection_pages": [
            {"data": [{"name": "c1", "aSide": {"accessPoint": {"authenticationKey": EQUINIX_SECRETS[0]}}}]}
        ]
    }


def _records() -> dict[str, Any]:
    return {
        "settings": [{"name": "api_password", "value": RECORD_SECRETS[0]}, {"name": "mtu", "value": 1500}]
    }


CORPUS = {
    "unifi": (_unifi, UNIFI_SECRETS),
    "vyos": (_vyos, VYOS_SECRETS),
    "equinix": (_equinix, EQUINIX_SECRETS),
    "records": (_records, RECORD_SECRETS),
}


def _absent(text: str, secrets: tuple[str, ...]) -> None:
    for secret in secrets:
        assert secret not in text, secret


@pytest.mark.parametrize("vendor", CORPUS)
def test_a_redacted_payload_holds_none_of_the_credentials(vendor):
    build, secrets = CORPUS[vendor]
    payload = build()

    out = redaction.redact(copy.deepcopy(payload))
    _absent(json.dumps(out), secrets)
    _absent(json.dumps(redaction.redact_in_place(copy.deepcopy(payload))), secrets)
    assert json.dumps(out) != json.dumps(payload)


def _bundle_text(tmp_path, payload: Any, known: tuple[str, ...] = ()) -> str:
    raw_dir = tmp_path / "raw"
    path = rawstore.write(raw_dir, "src", "1700000000000-abcdef12", payload, host="h1", key=KEY)
    chunks = debug_capture.iter_bundle(raw_dir, KEY, [path], raw_mode="redacted", known=known)
    with zipfile.ZipFile(io.BytesIO(b"".join(chunks))) as bundle:
        return "\n".join(bundle.read(name).decode() for name in bundle.namelist() if "/raw/" in name)


@pytest.mark.parametrize("vendor", CORPUS)
def test_the_redacted_debug_bundle_holds_none_of_the_credentials(vendor, tmp_path):
    build, secrets = CORPUS[vendor]

    text = _bundle_text(tmp_path, build())

    _absent(text, secrets)
    assert "<removed>" in text or "[redacted]" in text


@pytest.mark.parametrize("vendor", CORPUS)
def test_no_entry_of_the_redacted_bundle_holds_a_credential(vendor, tmp_path):
    """The records, the summary, the stack, the re-parse result and the run record carry the payload's
    values too (a parse report, an error that quotes a read), and each is redacted like the payload."""
    build, secrets = CORPUS[vendor]
    raw_dir = tmp_path / "raw"
    run_id = "1700000000000-abcdef12"
    path = rawstore.write(raw_dir, "src", run_id, build(), host="h1", key=KEY)
    cap = debug_capture.Capture(
        rawstore.sibling(path, rawstore.DEBUG_SUFFIX),
        rawstore.sibling(path, rawstore.DEBUG_STACK_SUFFIX),
        KEY,
        stack_after_s=60,
    )
    cap.record("begin", kind="run", collector="x", environment={})
    cap.record("log", level="ERROR", logger="x", message=f"read failed: {json.dumps(build())}")
    cap.record("finish", status="error", error=f"password={secrets[0]}")
    cap.close()
    rawstore.sibling(path, rawstore.DEBUG_STACK_SUFFIX).write_text(f"raise Error('token={secrets[0]}')\n")
    debug_capture.write_reparse(path, {"report": build(), "error": f"key={secrets[0]}"}, KEY)
    extra = {"run.json": {"id": 1, "detail": f"failed: {json.dumps(build())}"}}

    chunks = debug_capture.iter_bundle(raw_dir, KEY, [path], raw_mode="redacted", extra=extra, known=secrets)
    with zipfile.ZipFile(io.BytesIO(b"".join(chunks))) as bundle:
        names = bundle.namelist()
        text = "\n".join(bundle.read(name).decode() for name in names)

    assert {
        "run.json",
        f"captures/src/h1/{run_id}/debug.jsonl",
        f"captures/src/h1/{run_id}/stack.txt",
    } <= set(names)
    assert f"captures/src/h1/{run_id}/reparse.json" in names
    _absent(text, secrets)


def test_the_known_credential_values_are_removed_from_text_the_keys_do_not_reveal(tmp_path):
    """A command's output holds a value no key names; only the values the
    source is configured with can find it, in a bundle and in interface text."""
    secret = "plain-text-5527-zq"
    payload = {"show version": f"System\nlicense {secret} installed\nuptime 3 days", "other": {"a": 1}}

    unredacted = _bundle_text(tmp_path / "a", payload)
    redacted = _bundle_text(tmp_path / "b", payload, known=(secret,))

    assert secret in unredacted
    _absent(redacted, (secret,))
    assert "uptime 3 days" in redacted
    assert secret not in debug_capture.redact(f"x\nlicense {secret}", [secret])


def test_a_multi_line_credential_is_removed_line_by_line(tmp_path):
    # built from parts, so the run-data check (tools/check_no_run_data.py) finds no key marker in the file
    pem = "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END " + "PRIVATE KEY-----"
    payload = {"show crypto": f"key:\n{pem}\nend"}

    text = _bundle_text(tmp_path, payload, known=(pem,))

    assert "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" not in text


@pytest.mark.parametrize("vendor", CORPUS)
def test_a_trace_body_holds_none_of_the_credentials(vendor):
    build, secrets = CORPUS[vendor]
    body = json.dumps(build()).encode()

    plain = http_trace._body(body, "application/json")
    marked = http_trace._body(b"\xef\xbb\xbf" + body, "application/json")
    undeclared = http_trace._body(b"\xef\xbb\xbf  " + body, "")

    for record in (plain, marked, undeclared):
        assert "json" in record
        _absent(json.dumps(record), secrets)


@pytest.mark.parametrize(
    ("body", "kind"),
    [
        (b"password=hunter2-form&user=ada", "text/plain"),
        (b'{"password": "hunter2-form", broken', "application/json"),
        (b"<login><user>ada</user><password>hunter2-form</password></login>", "text/xml"),
        (b"Authorization: Bearer hunter2-form-token-value", "text/plain"),
        (b"GET https://ada:hunter2-form@host/x?api_key=hunter2-form HTTP/1.1", "text/plain"),
    ],
)
def test_a_body_that_is_not_json_is_redacted_as_text(body, kind):
    record = http_trace._body(body, kind)

    assert "hunter2-form" not in json.dumps(record)
    assert "[redacted]" in record["text"]


def test_a_trace_line_loses_the_values_the_source_is_configured_with(tmp_path):
    secret = "configured-secret-3318"
    trace = http_trace.HttpTrace("src", tmp_path, [secret])
    trace.record({"url": f"https://h/{secret}", "response": {"body": {"text": f'say "{secret}"'}}})
    trace._close()

    written = gzip.decompress(trace.spool_path.read_bytes()).decode()
    trace.discard()

    assert secret not in written
    assert "***" in written


def test_interface_text_holds_none_of_the_credentials():
    _absent(interface_text._vyos_text(_vyos()), VYOS_SECRETS)
    resolved = interface_text._resolved(_unifi(), {}, {})
    _absent(json.dumps(resolved), UNIFI_SECRETS)


ERRORS = [
    "HTTPError: 401 for url https://h/api/login?token=err-token-1234&x=1",
    'ConnectError: {"password": "err-pass-4455", "user": "ada"}',
    "AuthError: Authorization: Bearer err-bearer-token-9988",
    "Failed: https://ada:err-url-pass-7766@h/path",
]


@pytest.mark.parametrize("error", ERRORS)
def test_error_text_stored_with_a_device_holds_none_of_the_credentials(error):
    outcome = runs_exec.DeviceOutcome("src", "h1", False, error=error)

    for secret in ("err-token-1234", "err-pass-4455", "err-bearer-token-9988", "err-url-pass-7766"):
        assert secret not in outcome.error


class _Store:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def upsert_device_status(self, source: str, host: str, **fields: Any) -> None:
        self.rows.append({"source": source, "host": host, **fields})


def test_the_error_text_a_status_row_stores_loses_the_sources_credential_values(caplog):
    secret = "opaque-credential-0042"
    store = _Store()
    outcome = runs_exec.DeviceOutcome("src", "h1", False, error=f"ValueError: bad reply from {secret} peer")

    asyncio.run(runs_exec._record_outcomes(store, [outcome], {"password": secret}))  # type: ignore[arg-type]

    assert secret not in store.rows[0]["error"]
    assert secret not in caplog.text
