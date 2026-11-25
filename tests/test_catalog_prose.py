"""The query catalog's text follows the product prose rules: no live, reach or
delivery wording, no em dash, no multiplication sign and no decorative glyph."""

from __future__ import annotations

import re

from hst.queries import catalog

WORDS = [
    "live",
    "reach",
    "reaches",
    "reached",
    "reachable",
    "reachability",
    "unreachable",
    "deliver",
    "delivers",
    "delivered",
    "delivery",
    "mate",
    "mates",
]
WORD_RE = re.compile(r"\b(" + "|".join(WORDS) + r")\b", re.IGNORECASE)
# the em dash U+2014, the multiplication sign U+00D7 and U+2600 to U+27BF
GLYPH_RE = re.compile("[" + chr(0x2014) + chr(0xD7) + chr(0x2600) + "-" + chr(0x27BF) + "]")


def _texts(entry):
    yield "title", entry.get("title") or ""
    yield "description", entry.get("description") or ""
    for param in entry.get("params") or []:
        yield f"param {param.get('name')} label", param.get("label") or ""
        yield f"param {param.get('name')} placeholder", param.get("placeholder") or ""


def test_catalog_text_follows_the_prose_rules():
    problems = []
    for entry in catalog():
        for field, text in _texts(entry):
            if WORD_RE.search(text) or GLYPH_RE.search(text):
                problems.append(f"{entry['key']}: {field}: {text}")
    assert not problems, "\n".join(problems)


def test_catalog_columns_follow_the_prose_rules():
    problems = []
    for entry in catalog():
        for alias in re.findall(r"\bAS\s+([A-Za-z_][A-Za-z0-9_]*)", entry.get("cypher") or ""):
            if WORD_RE.search(alias.replace("_", " ")):
                problems.append(f"{entry['key']}: column {alias}")
    assert not problems, "\n".join(problems)


def test_the_equinix_entries_count_circuits():
    by_key = {e["key"]: e for e in catalog()}
    assert by_key["equinix-circuits"]["title"] == "Circuits"
    cypher = by_key["equinix-unbound-ports"]["cypher"]
    assert "AS circuits" in cypher and "live_circuits" not in cypher


def test_the_scan_covers_the_catalog():
    assert len(catalog()) >= 60
