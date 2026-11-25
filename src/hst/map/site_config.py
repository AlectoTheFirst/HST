"""The operator's site groups and named blocks for the map, and
the country of each site's location.

Postgres holds them as site parameters and the site location. The app writes them here when a run starts,
and the projection reads them when the run publishes. The graph holds only the name and the zone of the
named block of each device. Each run stamps them on its own Device nodes (`site_block`, `site_zone`,
core/cycle.py `apply_site_blocks`).
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hst.core import uid as uidmod

from . import store

# With `internet` the operator states that the device is an internet edge. The map places it as
# `external`, and the tracer reads the stamp of a run (`Device.site_zone`) as the edge of the estate.
ZONES = ("internal", "external", "internet")
logger = logging.getLogger(__name__)

# The country names that the ISO 3166 table of pytz does not hold, or holds in another form (`Britain
# (UK)`, `Korea (South)`, `Turkey`).
COUNTRY_ALIASES = {
    "United Kingdom": "GB",
    "UK": "GB",
    "Great Britain": "GB",
    "England": "GB",
    "Scotland": "GB",
    "Wales": "GB",
    "Northern Ireland": "GB",
    "USA": "US",
    "US": "US",
    "United States of America": "US",
    "Czechia": "CZ",
    "South Korea": "KR",
    "Republic of Korea": "KR",
    "North Korea": "KP",
    "Türkiye": "TR",
    "The Netherlands": "NL",
    "Holland": "NL",
    "Russian Federation": "RU",
    "UAE": "AE",
    "Ivory Coast": "CI",
    "Macedonia": "MK",
    "Eswatini": "SZ",
    "Swaziland": "SZ",
    "Myanmar": "MM",
    "Burma": "MM",
    "Viet Nam": "VN",
    "Cabo Verde": "CV",
    "Vatican": "VA",
    "Holy See": "VA",
    "Democratic Republic of the Congo": "CD",
    "Republic of the Congo": "CG",
}


@dataclass(frozen=True)
class NamedBlock:
    site: str
    name: str
    zone: str | None


@dataclass(frozen=True)
class SiteConfig:
    # Site code to its group path from the top.
    groups: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    # Device uid to its named block.
    blocks: Mapping[str, NamedBlock] = field(default_factory=dict)
    # Site code to the ISO 3166 alpha-2 code of the country its location names.
    countries: Mapping[str, str] = field(default_factory=dict)

    def stored_codes(self) -> dict[str, str]:
        """The site codes of the config, by their Site uid. A graph Site keeps
        the code of its creator (the `FR5` of a collector for the stored `fr5`),
        and a code is case-sensitive. The site of a device is looked up here by
        uid to find its group, block and country."""
        codes = {*self.groups, *self.countries, *(b.site for b in self.blocks.values())}
        return {uidmod.site(code): code for code in sorted(codes)}

    def as_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "groups": {code: list(p) for code, p in sorted(self.groups.items())},
            "blocks": {uid: [b.site, b.name, b.zone] for uid, b in sorted(self.blocks.items())},
        }
        if self.countries:
            out["countries"] = dict(sorted(self.countries.items()))
        return out

    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(self.as_json(), sort_keys=True).encode()).hexdigest()[:16]


def path(sidestore_dir: Path) -> Path:
    return sidestore_dir / store.FAMILY / ".config" / "site_config.json"


def _fold(name: str) -> str:
    """A country name folded for the lookup, with no accents, in lower case, with `&` as `and`, and with
    only letters and digits between single spaces."""
    decomposed = unicodedata.normalize("NFKD", name.replace("&", " and "))
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch)).casefold()
    return " ".join(re.sub(r"[\W_]+", " ", stripped).split())


@functools.cache
def _countries() -> dict[str, str]:
    """The folded country names to their ISO 3166 alpha-2 codes, from the ISO 3166 table of pytz (a
    dependency of neo4j) and `COUNTRY_ALIASES`."""
    try:
        import pytz
    except ImportError:
        logger.warning("[hst.site_config] pytz is not installed: only COUNTRY_ALIASES name a country")
        names: dict[str, str] = {}
    else:
        names = {_fold(name): code.upper() for code, name in pytz.country_names.items()}
    return {**names, **{_fold(alias): code for alias, code in COUNTRY_ALIASES.items()}}


def location_country(location: str | None) -> str | None:
    """The ISO 3166 alpha-2 code of the country in the last comma-separated part of a site location, or
    None. `Example Street 1, Vienna, Austria` gives AT."""
    if not location:
        return None
    return _countries().get(_fold(location.rsplit(",", 1)[-1]))


def from_params(
    sites: Iterable[tuple[str, Mapping[str, Any]]], locations: Mapping[str, str | None] | None = None
) -> SiteConfig:
    """The config of `(site code, site params)` pairs. It holds the `site_group` path and the `blocks` of
    each site, and the country of each site code in `locations` whose location has one."""
    groups: dict[str, tuple[str, ...]] = {}
    blocks: dict[str, NamedBlock] = {}
    for code, params in sites:
        names = tuple(n.strip() for n in str(params.get("site_group") or "").split("/") if n.strip())
        if names:
            groups[code] = names
        for block in params.get("blocks") or []:
            name = str(block.get("name") or "").strip()
            if not name:
                continue
            zone = block.get("zone") if block.get("zone") in ZONES else None
            for uid in block.get("devices") or []:
                blocks.setdefault(str(uid), NamedBlock(code, name, zone))
    countries = {code: c for code, location in (locations or {}).items() if (c := location_country(location))}
    return SiteConfig(groups, blocks, countries)


def write(sidestore_dir: Path, config: SiteConfig) -> None:
    target = path(sidestore_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps(config.as_json(), sort_keys=True))
    tmp.replace(target)


def read(sidestore_dir: Path) -> SiteConfig:
    target = path(sidestore_dir)
    if not target.is_file():
        return SiteConfig()
    data = json.loads(target.read_text())
    return SiteConfig(
        {code: tuple(p) for code, p in data.get("groups", {}).items()},
        {uid: NamedBlock(*b) for uid, b in data.get("blocks", {}).items()},
        dict(data.get("countries", {})),
    )
