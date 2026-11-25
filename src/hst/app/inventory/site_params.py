"""The rules of the `site_group` and `blocks` site params."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, Field, field_validator

SITE_GROUP_DEPTH = 8
SITE_GROUP_NAME = 64
BLOCK_NAME = 40


class SiteBlock(BaseModel):
    name: str
    zone: Literal["internal", "external", "internet"] | None = None
    devices: list[str] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        value = value.strip()
        if not 1 <= len(value) <= BLOCK_NAME:
            raise ValueError(f"a block name is 1 to {BLOCK_NAME} characters")
        return value

    @field_validator("devices")
    @classmethod
    def _devices(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("a block lists a device twice")
        return value


def _site_group(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    names = [name.strip() for name in value.split("/")]
    if len(names) > SITE_GROUP_DEPTH:
        raise ValueError(f"a site group is at most {SITE_GROUP_DEPTH} levels deep")
    if not all(1 <= len(name) <= SITE_GROUP_NAME for name in names):
        raise ValueError(f"each name of a site group is 1 to {SITE_GROUP_NAME} characters")
    return " / ".join(names)


def _blocks(value: list[SiteBlock] | None) -> list[SiteBlock] | None:
    if not value:
        return None
    names: set[str] = set()
    owner: dict[str, str] = {}
    for block in value:
        if block.name.casefold() in names:
            raise ValueError(f"two blocks are named {block.name!r}")
        names.add(block.name.casefold())
        for uid in block.devices:
            if uid in owner:
                raise ValueError(f"{uid} is in block {owner[uid]!r} and in block {block.name!r}")
            owner[uid] = block.name
    return value


# An empty value validates to None.
SiteGroup = Annotated[str | None, AfterValidator(_site_group)]
SiteBlocks = Annotated[list[SiteBlock] | None, AfterValidator(_blocks)]
