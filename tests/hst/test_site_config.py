"""The site groups and named blocks the map reads from the side store."""

from __future__ import annotations

from pathlib import Path

from hst.map import site_config
from hst.map.site_config import NamedBlock, SiteConfig


def test_the_site_config_holds_the_group_paths_and_the_named_blocks_of_the_sites(tmp_path: Path) -> None:
    config = site_config.from_params(
        [
            (
                "XA2",
                {
                    "site_group": " Area A /Area A1 ",
                    "blocks": [
                        {"name": "External", "zone": "external", "devices": ["dev:swc2"]},
                        {"name": "Core", "zone": "dmz", "devices": ["dev:swc1", "dev:swc2"]},
                    ],
                },
            ),
            ("XA6", {"site_group": None, "blocks": None}),
        ]
    )
    assert config.groups == {"XA2": ("Area A", "Area A1")}
    # A device in two blocks stays in the first; a zone outside internal and external is none.
    assert config.blocks == {
        "dev:swc2": NamedBlock("XA2", "External", "external"),
        "dev:swc1": NamedBlock("XA2", "Core", None),
    }
    assert site_config.read(tmp_path) == SiteConfig()
    site_config.write(tmp_path, config)
    assert site_config.read(tmp_path) == config
    other = site_config.from_params([("XA2", {"site_group": "Area A"})])
    assert other.fingerprint() != config.fingerprint() == site_config.read(tmp_path).fingerprint()


def test_a_block_of_zone_internet_keeps_its_zone_and_changes_the_fingerprint() -> None:
    params = {"blocks": [{"name": "External", "zone": "external", "devices": ["dev:swc2"]}]}
    before = site_config.from_params([("XA2", params)])
    assert before.as_json() == {"groups": {}, "blocks": {"dev:swc2": ["XA2", "External", "external"]}}
    edge = {"name": "Uplink", "zone": "internet", "devices": ["dev:rtr1"]}
    config = site_config.from_params([("XA2", {"blocks": [*params["blocks"], edge]})])
    assert config.blocks["dev:rtr1"] == NamedBlock("XA2", "Uplink", "internet")
    assert config.fingerprint() != before.fingerprint()


def test_the_country_of_a_location_is_its_last_part_as_an_iso_code() -> None:
    assert site_config.location_country("Example Street 1, Vienna, Austria") == "AT"
    assert site_config.location_country("Prague, Czech Republic") == "CZ"
    assert site_config.location_country("Frankfurt am Main, Hessen, Germany") == "DE"
    # Case, accents, spacing and the other common names of a country do not matter.
    assert site_config.location_country("London,  united kingdom ") == "GB"
    assert site_config.location_country("Brno, Czechia") == "CZ"
    assert site_config.location_country("Abidjan, Cote d'Ivoire") == "CI"
    assert site_config.location_country("Istanbul, Türkiye") == "TR"
    # No country name in the last part: no country.
    for location in ("", None, "Vienna", "Example Street 1, Vienna", "Atlantis", "Albany, GA"):
        assert site_config.location_country(location) is None, location


def test_the_site_config_holds_the_country_of_each_site_location(tmp_path: Path) -> None:
    sites = [("XA2", {"site_group": "Area A"}), ("XA6", {}), ("lab", {})]
    locations = {
        "XA2": "Example Street 1, Vienna, Austria",
        "XA6": "Prague, Czech Republic",
        "lab": "Basement",
    }
    config = site_config.from_params(sites, locations=locations)
    assert config.countries == {"XA2": "AT", "XA6": "CZ"}
    assert config.groups == {"XA2": ("Area A",)}
    site_config.write(tmp_path, config)
    assert site_config.read(tmp_path) == config
    # A change of a location's country changes the fingerprint, so the layout is placed again in full; a
    # config whose locations name no country keeps the fingerprint it had without them.
    plain = site_config.from_params(sites)
    moved = site_config.from_params(sites, locations={**locations, "XA6": "Bratislava, Slovakia"})
    assert len({plain.fingerprint(), config.fingerprint(), moved.fingerprint()}) == 3
    assert site_config.from_params(sites, locations={"lab": "Basement"}).fingerprint() == plain.fingerprint()


def test_a_device_site_is_named_by_the_code_the_config_holds_for_its_site_uid() -> None:
    """The graph Site keeps the code of whoever made it (a collector's `FR5`), the config is
    keyed by the stored `fr5`, and a code is case-sensitive."""
    from hst.map.tiers import fold

    config = site_config.from_params(
        [("fr5", {"site_group": "Area A"}), ("xa-2", {})], locations={"xa-2": "Wien, Austria"}
    )
    assert config.stored_codes() == {"site:fr5": "fr5", "site:xa-2": "xa-2"}
    rows = {
        "dev:a": {"label": "a", "site": "FR5"},
        "dev:b": {"label": "b", "site": "XA:2"},
        "dev:c": {"label": "c", "site": "other"},
        "dev:d": {"label": "d", "site": None},
    }

    named = fold.stored_sites(rows, config)

    assert {u: r["site"] for u, r in named.items()} == {
        "dev:a": "fr5",
        "dev:b": "xa-2",
        "dev:c": "other",
        "dev:d": None,
    }
    assert rows["dev:a"]["site"] == "FR5"
    assert fold.stored_sites(rows, SiteConfig()) is rows
