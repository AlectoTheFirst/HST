"""Normalization functions shared by all collectors."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from netutils.constants import BASE_INTERFACES

# Interface-type resolution uses netutils' BASE_INTERFACES, with the keys lowercased.
_ALIAS: dict[str, str] = {}
for _alias, _canonical in BASE_INTERFACES.items():
    _ALIAS[_alias.lower()] = _canonical.lower()
# A canonical name must resolve to itself even when it is not listed as its own alias
# (TwoGigabitEthernet and AppGigabitEthernet are not).
for _canonical in list(_ALIAS.values()):
    _ALIAS.setdefault(_canonical, _canonical)
# "po" resolves to Port-channel.
_ALIAS["po"] = "port-channel"

# The short spelling of each canonical type, as used in uids. A changed entry changes
# every uid built from it.
_SHORT: dict[str, str] = {
    "hundredgigabitethernet": "hu",
    "fortygigabitethernet": "fo",
    "twentyfivegige": "twe",
    # netutils resolves `Fi` to FiftyGigabitEthernet.
    "twogigabitethernet": "tw",
    "fivegigabitethernet": "fiv",
    "fiftygigabitethernet": "fi",
    "tengigabitethernet": "te",
    "gigabitethernet": "gi",
    "fastethernet": "fa",
    "ethernet": "eth",
    "port-channel": "po",
    "loopback": "lo",
    "tunnel": "tu",
    "vlan": "vlan",
    "management": "mgmt",
}

_IFACE_RE = re.compile(r"^\s*([A-Za-z-]+)\s*([0-9].*?)?\s*$")


def _canon_type(word: str) -> str | None:
    """Resolve one interface-type word to its canonical lowercase name."""
    return _ALIAS.get(word.lower())


def canonical_ifname(name: str) -> str:
    """Return the canonical lowercase name of an interface.

    'Eth1/1' gives 'ethernet1/1' and 'Po10' gives 'port-channel10'. A name with
    an unknown type is returned stripped and lowercased.
    """
    m = _IFACE_RE.match(name)
    if not m:
        return name.strip().lower()
    word, rest = m.group(1), m.group(2) or ""
    canonical = _canon_type(word)
    if canonical is None:
        return name.strip().lower()
    return f"{canonical}{rest}"


def short_ifname(name: str) -> str:
    """Return the short spelling of an interface name, as used in uids and UIs.

    'ethernet1/1' gives 'eth1/1'.
    """
    m = _IFACE_RE.match(canonical_ifname(name))
    if not m:
        return name.strip().lower()
    word, rest = m.group(1), m.group(2) or ""
    return f"{_SHORT.get(word, word)}{rest}"


def iface_slug(name: str) -> str:
    """Return the interface segment of a uid. It is the short name with '/' and ':'
    replaced by '-'.

    A '.' stays. `GigabitEthernet0/0.1` and `GigabitEthernet0/0/1` give 2 different segments.
    """
    return short_ifname(name).replace("/", "-").replace(":", "-")


_CAMEL_PART_RE = re.compile(r"[A-Z][a-z0-9]*|[a-z0-9]+")


def _type_initials(word: str) -> str:
    """Return the initials of the parts of a type word.

    'Bundle-Ether' gives 'be' and 'TwentyFiveGigE' gives 'tfge'.
    """
    return "".join(part[0] for part in _CAMEL_PART_RE.findall(word)).lower()


class IfNameResolver:
    """Resolve the interface names that a command prints against the interface table
    of one device.

    `show vrf`, `show ip arp`, route output, LLDP/CDP and FHRP summaries print
    interface names abbreviated (`Vl10`, `Fi1/0/1`, `BE10`, `Mg0/RP0/CPU0/0`). The
    interface table prints them in full. A name resolves to the first of these that
    exists:

    1. the name itself, when the table holds that exact name
    2. the one table name with the same canonical type and the same number
    3. the one table name with the same number whose type word starts with the
       letters of the abbreviation (`Fi` gives `FiveGigabitEthernet`, `Mg` gives
       `MgmtEth`)
    4. the one table name with the same number whose part initials start with the
       abbreviation (`BE` gives `Bundle-Ether`, `TF` gives `TwentyFiveGigE`)

    The number must be the same string, subinterface and slot separators included.
    `Gi0/0.1` does not resolve to `GigabitEthernet0/0/1`. A name without a unique
    match is returned as printed.
    """

    def __init__(self, names: Iterable[str]) -> None:
        self._exact: set[str] = set()
        self._by_number: dict[str, list[tuple[str, str]]] = {}
        for name in names:
            if not name:
                continue
            self._exact.add(name)
            m = _IFACE_RE.match(name)
            if m and m.group(2):
                self._by_number.setdefault(m.group(2).lower(), []).append((name, m.group(1)))
        self._seen: dict[str, str] = {}

    def __call__(self, raw: str | None) -> str | None:
        if not raw:
            return raw
        found = self._seen.get(raw)
        if found is None:
            found = self._seen[raw] = self._resolve(raw)
        return found

    def slug(self, raw: str | None) -> str:
        """`iface_slug` of the resolved name ('' for no name)."""
        resolved = self(raw)
        return iface_slug(resolved) if resolved else ""

    def _resolve(self, raw: str) -> str:
        name = raw.strip()
        if name in self._exact:
            return name
        m = _IFACE_RE.match(name)
        if not m or not m.group(2):
            return name
        word = m.group(1).lower()
        candidates = self._by_number.get(m.group(2).lower(), [])
        canonical = canonical_ifname(name)
        same = [n for n, _ in candidates if canonical_ifname(n) == canonical]
        if same:
            return same[0] if len(same) == 1 else name
        for matches in (
            [n for n, w in candidates if w.lower().startswith(word)],
            [n for n, w in candidates if len(word) > 1 and _type_initials(w).startswith(word)],
        ):
            if matches:
                return matches[0] if len(matches) == 1 else name
        return name


@dataclass(frozen=True)
class Hostname:
    short: str
    fqdn: str | None


def normalize_hostname(name: str) -> Hostname:
    """Lowercase the name and strip the trailing dot. Split it into the short name
    and the fqdn. The fqdn is None for a name without a dot."""
    n = name.strip().lower().rstrip(".")
    if "." in n:
        return Hostname(short=n.split(".", 1)[0], fqdn=n)
    return Hostname(short=n, fqdn=None)
