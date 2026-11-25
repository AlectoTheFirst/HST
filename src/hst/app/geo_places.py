"""The offline place lookup behind the site address field."""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import logging
import re
import unicodedata
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hst.app.store import GeoPlace

log = logging.getLogger(__name__)

# The app setting that records which file the place table holds:
# {"sha256", "file", "source": "bundled" | "operator"}.
SOURCE_SETTING_KEY = "geo_places_source"

MAX_RESULTS = 20
MIN_QUERY = 2


def name_key(text: str) -> str:
    """Return the place name folded for search.

    The result has no accents, is in lower case and holds only letters and
    digits between single spaces."""
    decomposed = unicodedata.normalize("NFKD", text)
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch)).casefold()
    return " ".join(re.sub(r"[\W_]+", " ", stripped).split())


@dataclass(frozen=True)
class PlaceQuery:
    name: str
    postal: str


def parse_query(text: str) -> PlaceQuery | None:
    """Split the typed text into a place name prefix and a postal code prefix.
    None when neither part is long enough to search on."""
    postal = ""
    words: list[str] = []
    for token in re.split(r"[\s,;]+", text.strip()):
        if not token:
            continue
        if not postal and any(ch.isdigit() for ch in token):
            postal = re.sub(r"[^0-9A-Za-z-]", "", token).upper()
        else:
            words.append(token)
    name = name_key(" ".join(words))
    if len(name) < MIN_QUERY and len(postal) < MIN_QUERY:
        return None
    return PlaceQuery(name=name, postal=postal)


# country code, postal code, place name, admin1 name, admin1 code, admin2 name,
# admin2 code, admin3 name, admin3 code, latitude, longitude, accuracy
_COUNTRY, _POSTAL, _NAME, _ADMIN1, _ADMIN2, _LAT, _LON = 0, 1, 2, 3, 5, 9, 10


def _rows(lines: Iterator[str]) -> Iterator[GeoPlace]:
    for row in csv.reader(lines, delimiter="\t", quoting=csv.QUOTE_NONE):
        if len(row) <= _LON or not row[_LAT] or not row[_LON] or not row[_NAME]:
            continue
        try:
            lat, lon = float(row[_LAT]), float(row[_LON])
        except ValueError:
            continue
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            continue
        yield GeoPlace(
            country_code=row[_COUNTRY],
            postal_code=row[_POSTAL],
            name=row[_NAME],
            admin1=row[_ADMIN1],
            admin2=row[_ADMIN2],
            lat=lat,
            lon=lon,
        )


def read_geonames(path: Path) -> Iterator[GeoPlace]:
    """Read the places of a GeoNames postal code file.

    `path` is the zip as downloaded (allCountries.zip, DE.zip) or the
    tab-separated text inside the zip."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            members = [n for n in archive.namelist() if n.endswith(".txt") and n.lower() != "readme.txt"]
            if not members:
                raise ValueError(f"{path} holds no GeoNames text file")
            for member in members:
                with archive.open(member) as raw:
                    yield from _rows(io.TextIOWrapper(raw, encoding="utf-8", newline=""))
        return
    with path.open(encoding="utf-8", newline="") as text:
        yield from _rows(text)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_record(path: Path, source: str) -> dict[str, str]:
    """The SOURCE_SETTING_KEY value for a table loaded from `path`."""
    return {"sha256": file_sha256(path), "file": path.name, "source": source}


async def load_bundled(store: Any, path: Path) -> int | None:
    """Load the place file of `GEO_PLACES_FILE`, once per file.

    The table is loaded when no file is recorded, or when the recorded file is
    an earlier bundled file. A file an operator loaded with `hst geo-places
    load` is kept. Returns the row count, or None when nothing was loaded.
    """
    if not await asyncio.to_thread(path.is_file):
        log.warning("geo places: %s is not a file; the place table is not loaded", path)
        return None
    record = await asyncio.to_thread(source_record, path, "bundled")
    current = await store.get_setting(SOURCE_SETTING_KEY)
    held = current.value if current else {}
    if held.get("source") == "operator" or held.get("sha256") == record["sha256"]:
        return None
    log.info("geo places: loading %s into the place table", path)
    count = await store.replace_geo_places(read_geonames(path))
    await store.put_setting(SOURCE_SETTING_KEY, record, b"")
    log.info("geo places: loaded %d places from %s", count, path.name)
    return count
