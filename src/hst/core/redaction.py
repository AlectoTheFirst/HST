"""Redaction of credentials on every path that gives collected data to a reader."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import BaseModel, SecretStr

REDACTED = "[redacted]"
# The replacement for a credential value that the source configuration holds.
KNOWN = "***"

SECRET_KEYS = re.compile(
    r"^(pass(word|wd|phrase)?|pwd|secret|client_secret|token|access_token|refresh_token|"
    r"api[_-]?key|apikey|key|provisioning[_-]?key|sid|session(id)?|jwt|cookie|authorization|cak|ckn)$",
    re.IGNORECASE,
)
# A normalized key that contains one of these words is a credential key. The
# words match compound names such as `adminPassword`, `clientSecret` or
# `preSharedKey`. The short names `sid`, `key`, `pwd` and `jwt` match only a
# whole key, in `SECRET_KEYS`. `aSide` and `keepalive` are not credential keys.
SECRET_WORDS = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "privatekey",
    "privkey",
    "authkey",
    "authenticationkey",
    "encryptionkey",
    "accesskey",
    "apikey",
    "sharedkey",
    "licensekey",
    "psk",
    "vendorconfig",
    "provisioningkey",
    "iappkey",
    "vwirekey",
    "credential",
)
# A UniFi controller holds its credentials in `x_*` fields. Each `x_` key is a
# credential key, except a key that this pattern matches.
_UNIFI_PUBLIC = re.compile(r"^x_(fingerprint|has_.*)$", re.IGNORECASE)
_KEY_SEPARATORS = re.compile(r"[_\-.\s]+")
# The fields that hold the name of a setting in a record of the form `{name: ..., value: ...}`.
_SETTING_NAMES = ("name", "key", "setting", "parameter")


def is_secret_key(key: Any, *, snmp: bool = False) -> bool:
    """Whether `key` is the key of a credential. `snmp` is true for a key below
    a key that contains `snmp`. A `community` key holds the SNMP community
    string there."""
    if not isinstance(key, str):
        return False
    if SECRET_KEYS.match(key) is not None:
        return True
    if key[:2].lower() == "x_" and _UNIFI_PUBLIC.match(key) is None:
        return True
    norm = _KEY_SEPARATORS.sub("", key.lower())
    if any(word in norm for word in SECRET_WORDS):
        return True
    return "communit" in norm and (snmp or "snmp" in norm)


def _setting_secret(record: Mapping[Any, Any], snmp: bool) -> bool:
    """Whether `record` is a setting held as `{name: <credential name>, value: ...}`."""
    return "value" in record and any(is_secret_key(record.get(field), snmp=snmp) for field in _SETTING_NAMES)


def redact(value: Any, *, _snmp: bool = False) -> Any:
    """`value` with every credential-looking key's value replaced, at any depth."""
    if isinstance(value, dict):
        named = _setting_secret(value, _snmp)
        out: dict[Any, Any] = {}
        for k, v in value.items():
            if (named and k == "value") or is_secret_key(k, snmp=_snmp):
                out[k] = REDACTED
            else:
                below = _snmp or (isinstance(k, str) and "snmp" in k.lower())
                out[k] = redact(v, _snmp=below)
        return out
    if isinstance(value, list):
        return [redact(item, _snmp=_snmp) for item in value]
    return value


def redact_in_place(value: Any, *, _snmp: bool = False) -> Any:
    """Replace the value of every credential-looking key of `value` in place,
    at any depth, and return `value`. A caller uses it for a payload that is
    too large to hold twice."""
    if isinstance(value, dict):
        named = _setting_secret(value, _snmp)
        for k, v in value.items():
            if (named and k == "value") or is_secret_key(k, snmp=_snmp):
                value[k] = REDACTED
            else:
                redact_in_place(v, _snmp=_snmp or (isinstance(k, str) and "snmp" in k.lower()))
    elif isinstance(value, list):
        for item in value:
            redact_in_place(item, _snmp=_snmp)
    return value


# --- text ---------------------------------------------------------------------------------

_AUTHORIZATION = re.compile(r"(?i)\b((?:proxy-)?authorization)(\s*[:=]\s*)[^\r\n]*")
_BEARER = re.compile(r"(?i)\b(bearer|basic)(\s+)[A-Za-z0-9._~+/=\-]{8,}")
_URL_PASSWORD = re.compile(r"(?<=://)([^/\s:@]*):[^/\s@]+@")
# `_ASSIGNMENT` matches the name and the separator of `name=value`,
# `name: value` and `"name": "value"`. `_VALUE` matches a quoted string or the
# text up to the next separator. A name starts at the start of a word. The
# regex reads a long run of word characters once.
_ASSIGNMENT = re.compile(r"""(?<![\w.\-])(?P<name>[A-Za-z_][\w.\-]*)(?P<sep>["']?\s*[:=]\s*)""")
_VALUE = re.compile(r"""\[redacted\]|"(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;&"'}\])<>]+""")
_ELEMENT = re.compile(r"<(?P<tag>[A-Za-z_][\w.\-]*)(?P<attrs>[^<>]*)>(?P<body>[^<>]*)</(?P=tag)>")


# In device CLI text (show running-config, VyOS `show configuration commands`,
# an error that quotes a line), a credential is the token after a keyword, with
# no `=` or `:` between them. `_assigned` does not match it. `redact_cli` keeps
# each head below and replaces the one token after it. The heads are the IOS,
# IOS-XE, IOS-XR, NX-OS and VyOS forms that hold a secret. They are HSRP and
# VRRP authentication strings (`standby 10 authentication X`,
# `vrrp 1 authentication text X`, NX-OS `authentication text X` under the
# group), SNMPv3 user keys (`auth sha X`, `priv aes 128 X`, NX-OS
# `... localizedkey`), type 0/5/7/8/9 passwords and secrets, key strings,
# pre-shared keys and secrets, WireGuard and VyOS private keys, OSPF and NTP
# authentication keys (`message-digest-key 1 md5 X`, `authentication-key X`,
# `authentication-key 1 md5 X`, VyOS `md5-key X`), WPA pre-shared keys, NHRP
# authentication strings, TACACS+ and RADIUS server keys, ISAKMP keys and SNMP
# communities.
#
# `_CLI_GAP` is the most characters between `tacacs`, `radius` or `snmp` and the
# `key` or `community` of the same line. The bound keeps the search time linear
# in the length of a line that repeats the first word.
_CLI_GAP = 256
_CLI_HEADS = (
    r"\b(?:standby|vrrp(?:\s+v3)?)\s+\d+(?:\s+address-family\s+\S+)?\s+authentication"
    r"(?:\s+(?:text|md5\s+key-string))?(?:\s+[0-9])?",
    r"^[ \t]*authentication\s+(?:text|md5\s+key-string)(?:\s+[0-9])?",
    r"\bauth\s+(?:md5|sha\S*)",
    r"\bpriv(?:\s+(?:aes(?:[\s-]*(?:128|192|256))?|3des|des\S*))?",
    r"(?<![\w-])(?:password|secret|key-string|pre-shared-key|pre-shared-secret|private-key|"
    r"plaintext-password|encrypted-password|passphrase|psk|md5-key|shared-secret-key)(?:\s+[0-9])?",
    r"(?<![\w-])key\s+[0-9]",
    r"(?<![\w-])message-digest-key\s+\d+\s+md5(?:\s+(?:[0-9]|clear|encrypted))?",
    r"(?<![\w-])authentication-key(?:\s+\d+\s+md5(?:\s+(?:clear|encrypted))?|\s+[0-9])?",
    r"\bwpa-psk\s+(?:ascii|hex)(?:\s+[0-9])?",
    r"\bnhrp\s+authentication",
    rf"\b(?:tacacs|radius)(?:-server)?\b[^\r\n]{{0,{_CLI_GAP}}}?\bkey(?:\s+[0-9])?",
    r"\bisakmp\s+key",
    rf"\bsnmp(?:-server)?\b[^\r\n]{{0,{_CLI_GAP}}}?\bcommunity",
    r"\bsnmp-server\s+host\s+\S+(?:\s+(?:traps|informs))?(?:\s+version\s+(?:1|2c|3\s+(?:auth|noauth|priv)))?",
)
_CLI_SECRET = re.compile(
    r"(?im)(?P<head>" + "|".join(_CLI_HEADS) + r")(?P<sep>[ \t]+)(?P<value>(?!\[redacted\]|<removed>)[^\s]+)"
)


def redact_cli(text: str) -> str:
    """`text` with the token after each CLI credential keyword of `_CLI_HEADS`
    replaced."""
    return _CLI_SECRET.sub(lambda m: f"{m['head']}{m['sep']}{REDACTED}", text)


def _assigned(text: str) -> str:
    """`text` with the value of every `name=value` of a credential name replaced.
    The value of any other name is searched for further names. A URL after
    `https:` is searched for its parameters."""
    out: list[str] = []
    done = 0
    for head in _ASSIGNMENT.finditer(text):
        if head.start() < done or not is_secret_key(head["name"]):
            continue
        value = _VALUE.match(text, head.end())
        if value is None or value[0].strip("\"'") == REDACTED:
            continue
        quote = value[0][:1] if value[0][:1] in "\"'" else ""
        out.append(f"{text[done : head.end()]}{quote}{REDACTED}{quote}")
        done = value.end()
    out.append(text[done:])
    return "".join(out)


def _element(match: re.Match[str]) -> str:
    if not is_secret_key(match["tag"]) or not match["body"].strip():
        return match[0]
    return f"<{match['tag']}{match['attrs']}>{REDACTED}</{match['tag']}>"


def redact_known(text: str, values: Iterable[str], *, marker: str = KNOWN) -> str:
    """`text` with each of `values` replaced by `marker`. A value is replaced in
    its plain form and in its JSON string form. The values are replaced from
    the longest to the shortest. A value that contains another value is
    replaced whole."""
    found = {v for v in values if v}
    for value in sorted(found, key=len, reverse=True):
        for form in dict.fromkeys((value, json.dumps(value)[1:-1])):
            text = text.replace(form, marker)
    return text


def line_forms(values: Iterable[str]) -> list[str]:
    """`values` and each line of at least 8 characters of a multi-line value
    such as a PEM key. A caller that redacts one line at a time uses the
    result."""
    out: list[str] = []
    for value in values:
        out.append(value)
        if "\n" in value:
            out.extend(line.strip() for line in value.splitlines() if len(line.strip()) >= 8)
    return out


def redact_text(text: str, known: Iterable[str] = ()) -> str:
    """`text` with the credentials replaced in an authorization header, a
    bearer or basic token, a URL password, an XML element, a `name=value`
    assignment and a CLI keyword line. The `known` values are replaced last."""
    text = _AUTHORIZATION.sub(lambda m: f"{m[1]}{m[2]}{REDACTED}", text)
    text = _BEARER.sub(lambda m: f"{m[1]}{m[2]}{REDACTED}", text)
    text = _URL_PASSWORD.sub(lambda m: f"{m[1]}:{REDACTED}@", text)
    text = _ELEMENT.sub(_element, text)
    text = _assigned(text)
    text = redact_cli(text)
    return redact_known(text, known)


def _strings(value: Any, known: list[str]) -> Any:
    if isinstance(value, str):
        return redact_text(value, known)
    if isinstance(value, dict):
        return {
            (redact_known(k, known) if isinstance(k, str) else k): _strings(v, known)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_strings(item, known) for item in value]
    return value


def redact_value(value: Any, known: Iterable[str] = ()) -> Any:
    """A redacted copy of `value`. `redact` replaces the values of the
    credential keys. `redact_text` then redacts every string value and replaces
    the `known` values in it. `redact_known` replaces the `known` values in
    every string key. A caller uses it for a record, a summary or a result that
    holds device and collector messages next to its fields."""
    return _strings(redact(value), list(known))


def secret_values(config: Any) -> list[str]:
    """The `SecretStr` values that a configuration holds, at any depth.
    `redact_known` takes them as its `values`."""
    found: list[str] = []
    if isinstance(config, SecretStr):
        value = config.get_secret_value()
        if value:
            found.append(value)
    elif isinstance(config, BaseModel):
        for name in type(config).model_fields:
            found.extend(secret_values(getattr(config, name, None)))
    elif isinstance(config, Mapping):
        for item in config.values():
            found.extend(secret_values(item))
    elif isinstance(config, (list, tuple)):
        for item in config:
            found.extend(secret_values(item))
    return found
