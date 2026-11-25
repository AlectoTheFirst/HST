"""The shared redaction (core/redaction.py): key rules, text shapes, known values."""

from __future__ import annotations

import json

import pytest
from pydantic import BaseModel, SecretStr
from tests.support.cputime import cpu_time

from hst.core import redaction
from hst.core.redaction import REDACTED, redact, redact_in_place, redact_known, redact_text


@pytest.mark.parametrize(
    "key",
    [
        "authenticationKey",
        "AuthenticationKey",
        "encryptionKey",
        "accessKey",
        "x_passphrase",
        "x_iapp_key",
        "sshPassword",
        "preSharedKey",
        "credentials",
    ],
)
def test_a_vendor_key_name_is_a_credential(key):
    assert redaction.is_secret_key(key)


@pytest.mark.parametrize(
    "key", ["aSide", "keepalive", "x_fingerprint", "x_has_ssh_hostkey", "name", "community"]
)
def test_an_ordinary_key_is_not(key):
    assert not redaction.is_secret_key(key)


def test_a_credential_stored_as_the_key_of_a_dictionary_goes_with_its_container():
    payload = {
        "snmp": {"community": {"snmp-community-9x": {"authorization": "ro"}}},
        "bgp": {"community": "65000:1"},
    }

    out = redact(payload)

    assert "snmp-community-9x" not in json.dumps(out)
    assert out["bgp"] == {"community": "65000:1"}


def test_a_setting_held_as_a_name_and_value_record_is_redacted_by_its_name():
    payload = [{"name": "wan_password", "value": "s3"}, {"name": "mtu", "value": 1500}]

    assert redact(payload) == [{"name": "wan_password", "value": REDACTED}, {"name": "mtu", "value": 1500}]
    assert redact_in_place(json.loads(json.dumps(payload)))[0]["value"] == REDACTED


@pytest.mark.parametrize(
    ("text", "gone"),
    [
        ("password=hunter2&next=1", "hunter2"),
        ('{"api_key": "abc123xyz", "n": 1}', "abc123xyz"),
        ("token: abcdef", "abcdef"),
        ("<secret>hunter2</secret>", "hunter2"),
        ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("sent Bearer abcdefghijklmnop to host", "abcdefghijklmnop"),
        ("https://ada:hunter2@host/x", "hunter2"),
        ("GET /login?user=ada&access_token=abc.def.ghi HTTP/1.1", "abc.def.ghi"),
        ("see https://h/x?y=1 then password: 'two words'", "two words"),
    ],
)
def test_text_loses_the_credentials_of_the_shapes_it_knows(text, gone):
    out = redact_text(text)

    assert gone not in out
    assert REDACTED in out


def test_text_without_a_credential_is_unchanged():
    text = "ConnectError: connection refused by 10.0.0.1:443 after 3 tries (key length 2048)"

    assert redact_text(text) == text
    assert redact_text("plain https://h/x?y=1") == "plain https://h/x?y=1"


def test_redacting_twice_is_the_same_as_once():
    text = 'password=hunter2 Authorization: Bearer abcdefghijklmnop {"token": "tok"}'

    once = redact_text(text)

    assert redact_text(once) == once


def test_a_long_run_of_word_characters_is_read_in_linear_time():
    from tests.support.cputime import cpu_time

    body = "A" * 1_000_000 + " " + "b" * 1_000_000

    with cpu_time() as spent:
        assert redact_text(body) == body
    assert spent.seconds < 5


def test_known_values_are_removed_as_written_and_as_json_writes_them():
    value = 'pa"ss\\word/é'
    text = f"plain {value} and json {json.dumps(value)} and {json.dumps({'k': value})}"

    out = redact_known(text, [value, ""])

    assert value not in out
    assert json.dumps(value)[1:-1] not in out


def test_a_known_value_that_holds_another_goes_whole():
    assert redact_known("a secret-long-value b", ["secret", "secret-long-value"]) == "a *** b"


def test_the_secret_values_of_a_configuration_are_read_at_any_depth():
    class Auth(BaseModel):
        password: SecretStr
        user: str = "ada"

    class Config(BaseModel):
        host: str = "h"
        token: SecretStr = SecretStr("tok-1")
        auth: Auth
        extra: list[Auth] = []

    config = Config(auth=Auth(password=SecretStr("pw-1")), extra=[Auth(password=SecretStr("pw-2"))])

    assert sorted(redaction.secret_values(config)) == ["pw-1", "pw-2", "tok-1"]
    assert redaction.secret_values(None) == []


def test_redact_value_clears_keys_strings_and_known_values_without_touching_the_input():
    value = {
        "id": 4,
        "x_passphrase": "p1",
        "detail": "login failed password=p2 for opaque-1",
        "steps": [{"error": "token=p3"}],
        "opaque-1": "k",
    }

    out = redaction.redact_value(value, ["opaque-1"])

    assert out["id"] == 4 and out["x_passphrase"] == REDACTED
    assert out["detail"] == f"login failed password={REDACTED} for ***"
    assert out["steps"] == [{"error": f"token={REDACTED}"}]
    assert "opaque-1" not in out and out["***"] == "k"
    assert value["x_passphrase"] == "p1" and "p2" in value["detail"]


# device CLI text carries a secret as the token after a keyword, with no
# `=` or `:`.
CLI_SECRETS = [
    " standby 10 authentication S3cr3t-1",
    " standby 1 authentication md5 key-string 7 S3cr3t-2",
    " vrrp 5 authentication text S3cr3t-3",
    "  authentication text S3cr3t-4",
    "snmp-server user admin network-admin auth sha S3cr3t-5 priv S3cr3t-6 localizedkey",
    "snmp-server user u1 grp v3 auth sha S3cr3t-7 priv aes 128 S3cr3t-8",
    "username admin privilege 15 secret 9 S3cr3t-9",
    "enable password 7 S3cr3t-10",
    " key-string 7 S3cr3t-11",
    "crypto isakmp key S3cr3t-12 address 192.0.2.1",
    "tacacs-server key 7 S3cr3t-13",
    "radius-server host 192.0.2.2 key S3cr3t-14",
    " key 7 S3cr3t-15",
    "snmp-server community S3cr3t-16 RO",
    "snmp-server host 192.0.2.3 version 2c S3cr3t-17",
    "set interfaces wireguard wg0 private-key 'S3cr3t-18'",
    "set service snmp community 'S3cr3t-19' authorization ro",
    "set system login user u authentication encrypted-password 'S3cr3t-20'",
    "set protocols bgp 65000 neighbor 192.0.2.4 password 'S3cr3t-21'",
    " pre-shared-key S3cr3t-22",
    "set system login user u authentication plaintext-password S3cr3t-23",
    " ip ospf message-digest-key 1 md5 S3cr3t-24",
    " ip ospf message-digest-key 1 md5 7 S3cr3t-25",
    " message-digest-key 1 md5 encrypted S3cr3t-26",
    " ip ospf authentication-key S3cr3t-27",
    " ip ospf authentication-key 7 S3cr3t-28",
    "ntp authentication-key 1 md5 S3cr3t-29 7",
    " authentication-key 1 md5 encrypted S3cr3t-30",
    " wpa-psk ascii 0 S3cr3t-31",
    " ip nhrp authentication S3cr3t-32",
    "set vpn ipsec site-to-site peer 192.0.2.5 authentication pre-shared-secret 'S3cr3t-33'",
    "set protocols ospf area 0 authentication md5 key-id 1 md5-key S3cr3t-34",
    "set interfaces openvpn vtun0 shared-secret-key S3cr3t-35",
    "radius-server host 192.0.2.6 auth-port 1812 acct-port 1813 timeout 5 retransmit 3 key 7 S3cr3t-36",
]


@pytest.mark.parametrize("line", CLI_SECRETS)
def test_cli_text_loses_the_secret_after_its_keyword(line):
    from hst.core import debug_capture

    assert "S3cr3t" not in redaction.redact_text(line)
    assert "S3cr3t" not in debug_capture.redact(line)


def test_cli_text_keeps_the_lines_that_hold_no_secret():
    for line in (
        "interface Gi0/1 description uplink",
        " standby 10 ip 192.0.2.1",
        "username admin privilege 15 role network-admin",
        "authentication failed for user admin",
        " ip ospf authentication message-digest",
        " ip nhrp authentication",
        "ntp authenticate",
    ):
        assert redaction.redact_text(line) == line


@pytest.mark.parametrize("word", ["tacacs ", "radius-server ", "snmp ", "snmp-server "])
def test_a_line_that_repeats_a_cli_keyword_is_read_in_linear_time(word):
    line = word * (200_000 // len(word))

    with cpu_time() as spent:
        assert redact_text(line) == line
    assert spent.seconds < 10


def test_a_cli_key_past_the_gap_bound_of_its_keyword_is_kept():
    near = "tacacs-server host 192.0.2.7 " + "x" * (redaction._CLI_GAP - 40) + " key S3cr3t-37"
    far = "tacacs-server host 192.0.2.7 " + "x" * (redaction._CLI_GAP + 40) + " key 5ecret-38"

    assert "S3cr3t-37" not in redact_text(near)
    assert redact_text(far) == far
