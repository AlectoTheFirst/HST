"""Site groups and named blocks: the rules of hst.app.inventory.site_params.

tests/app/test_inventory_api.py drives the same rules through `PATCH /api/inventory/sites/{id}`.
"""

from __future__ import annotations

import pytest
from pydantic import TypeAdapter, ValidationError

from hst.app.inventory.site_params import SiteBlocks, SiteGroup

GROUP = TypeAdapter(SiteGroup)
BLOCKS = TypeAdapter(SiteBlocks)


def test_a_site_group_path_is_stored_as_names_joined_by_a_spaced_slash():
    assert GROUP.validate_python("  Area A/Area A1 ") == "Area A / Area A1"
    assert GROUP.validate_python("Area A") == "Area A"
    assert GROUP.validate_python("a /b/ c") == "a / b / c"


def test_a_site_group_path_reaches_eight_levels_of_64_characters():
    deepest = "/".join(["n" * 64] * 8)
    assert GROUP.validate_python(deepest) == " / ".join(["n" * 64] * 8)


@pytest.mark.parametrize(
    "path",
    [
        "Area A /",
        "/Area A",
        "Area A //Area A1",
        "Area A / / Area A1",
        "Area A / " + "n" * 65,
        "/".join(["n"] * 9),
    ],
)
def test_a_site_group_path_outside_the_limits_is_refused(path):
    with pytest.raises(ValidationError):
        GROUP.validate_python(path)


@pytest.mark.parametrize("path", [None, "", "   "])
def test_an_empty_site_group_clears_it(path):
    assert GROUP.validate_python(path) is None


def test_a_block_is_stored_with_its_name_stripped_and_every_key():
    blocks = BLOCKS.validate_python(
        [{"name": "  core ", "devices": ["dev:sw1"]}, {"name": "DMZ", "zone": "external"}]
    )
    assert BLOCKS.dump_python(blocks) == [
        {"name": "core", "zone": None, "devices": ["dev:sw1"]},
        {"name": "DMZ", "zone": "external", "devices": []},
    ]


@pytest.mark.parametrize("zone", ["internal", "external", "internet", None])
def test_a_block_zone_is_internal_external_internet_or_none(zone):
    assert BLOCKS.validate_python([{"name": "core", "zone": zone}])[0].zone == zone


@pytest.mark.parametrize("zone", ["", "dmz", "External"])
def test_any_other_block_zone_is_refused(zone):
    with pytest.raises(ValidationError):
        BLOCKS.validate_python([{"name": "core", "zone": zone}])


@pytest.mark.parametrize("name", ["", "   ", "n" * 41])
def test_a_block_name_outside_1_to_40_characters_is_refused(name):
    with pytest.raises(ValidationError):
        BLOCKS.validate_python([{"name": name}])


def test_a_block_name_of_40_characters_is_accepted():
    assert BLOCKS.validate_python([{"name": "n" * 40}])[0].name == "n" * 40


def test_two_blocks_of_one_site_cannot_share_a_name_in_any_case():
    with pytest.raises(ValidationError, match="two blocks are named"):
        BLOCKS.validate_python([{"name": "Core"}, {"name": " core"}])


def test_a_block_cannot_list_a_device_twice():
    with pytest.raises(ValidationError, match="twice"):
        BLOCKS.validate_python([{"name": "core", "devices": ["dev:sw1", "dev:sw1"]}])


def test_a_device_sits_in_at_most_one_block_of_the_site():
    with pytest.raises(ValidationError, match="dev:sw1"):
        BLOCKS.validate_python(
            [
                {"name": "core", "devices": ["dev:sw1"]},
                {"name": "dmz", "devices": ["dev:fw1", "dev:sw1"]},
            ]
        )


@pytest.mark.parametrize("blocks", [None, []])
def test_no_blocks_clears_them(blocks):
    assert BLOCKS.validate_python(blocks) is None
