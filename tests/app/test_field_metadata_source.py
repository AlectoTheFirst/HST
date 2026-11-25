from __future__ import annotations

from pathlib import Path

from hst.app.inventory import field_metadata as fm

ROOT = Path(__file__).resolve().parents[2]


def test_field_metadata_has_no_generated_header():
    doc = fm.__doc__ or ""
    assert "GENERATED" not in doc
    assert "Do not edit by hand" not in doc
    assert "field-ownership.json" not in doc
    assert "Classification of every collector configuration field" in doc


def test_the_field_metadata_generator_is_gone():
    assert not (ROOT / "tools" / "gen_field_metadata.py").exists()


def test_the_hand_added_location_sites_row_is_part_of_the_source():
    row = fm.classification_of("zia", "location_sites", None)
    assert row is not None
    assert row.category == "connection"
    assert row.identity_sensitivity == "label"
    assert row.secret is False
