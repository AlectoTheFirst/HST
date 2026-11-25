"""Header fields and the fixed v1 CUDD variable ordering.

The schema does not import ``dd``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import ClassVar, Literal

Bank = Literal["original", "current", "next"]

BANKS: tuple[Bank, ...] = ("original", "current", "next")


@dataclass(frozen=True, slots=True)
class FieldSpec:
    name: str
    width: int


@dataclass(frozen=True, slots=True)
class HeaderSchema:
    """One address-family header layout with stable field and bit ordering."""

    address_family: Literal[4, 6]
    schema_version: str = "1"
    ordering_version: str = "1"

    _FIXED_FIELDS: ClassVar[tuple[tuple[str, int], ...]] = (
        ("protocol", 8),
        ("source_address", 0),
        ("destination_address", 0),
        ("source_port", 16),
        ("destination_port", 16),
        ("tcp_flags", 8),
        ("icmp_type", 8),
        ("icmp_code", 8),
        ("dscp", 6),
        ("ecn", 2),
        ("fragment_offset", 13),
        ("more_fragments", 1),
    )
    _ALIASES: ClassVar[Mapping[str, str]] = MappingProxyType(
        {
            "proto": "protocol",
            "src": "source_address",
            "src_ip": "source_address",
            "source_ip": "source_address",
            "dst": "destination_address",
            "dst_ip": "destination_address",
            "destination_ip": "destination_address",
            "sport": "source_port",
            "src_port": "source_port",
            "dport": "destination_port",
            "dst_port": "destination_port",
            "flags": "tcp_flags",
            "fragment": "fragment_offset",
            "mf": "more_fragments",
        }
    )

    def __post_init__(self) -> None:
        if type(self.address_family) is not int or self.address_family not in (4, 6):
            raise ValueError("address_family must be 4 or 6")

    @classmethod
    def ipv4(cls) -> HeaderSchema:
        return cls(4)

    @classmethod
    def ipv6(cls) -> HeaderSchema:
        return cls(6)

    @property
    def fields(self) -> tuple[FieldSpec, ...]:
        address_width = 32 if self.address_family == 4 else 128
        return tuple(
            FieldSpec(name, address_width if name in {"source_address", "destination_address"} else width)
            for name, width in self._FIXED_FIELDS
        )

    @property
    def field_names(self) -> tuple[str, ...]:
        return tuple(field.name for field in self.fields)

    @property
    def widths(self) -> Mapping[str, int]:
        return MappingProxyType({field.name: field.width for field in self.fields})

    def canonical_field(self, field: str) -> str:
        canonical = self._ALIASES.get(field, field)
        if canonical not in self.field_names:
            raise KeyError(f"unknown header field: {field}")
        return canonical

    def width(self, field: str) -> int:
        return self.widths[self.canonical_field(field)]

    def variable(self, bank: Bank, field: str, bit: int) -> str:
        if bank not in BANKS:
            raise ValueError(f"unknown header bank: {bank}")
        canonical = self.canonical_field(field)
        width = self.width(canonical)
        if bit < 0 or bit >= width:
            raise IndexError(f"bit {bit} outside {canonical}[0:{width}]")
        prefix = {"original": "o", "current": "c", "next": "n"}[bank]
        return f"{prefix}_{canonical}_{bit}"

    def bits(self, bank: Bank, field: str) -> tuple[str, ...]:
        canonical = self.canonical_field(field)
        return tuple(self.variable(bank, canonical, bit) for bit in range(self.width(canonical)))

    def bank_variables(self, bank: Bank) -> tuple[str, ...]:
        return tuple(variable for field in self.fields for variable in self.bits(bank, field.name))

    @property
    def variables(self) -> tuple[str, ...]:
        """The variables in v1 order. The banks are interleaved per bit, MSB first."""

        return tuple(
            self.variable(bank, field.name, bit)
            for field in self.fields
            for bit in range(field.width)
            for bank in BANKS
        )

    def rename_bank(self, source: Bank, destination: Bank) -> Mapping[str, str]:
        return MappingProxyType(
            {
                self.variable(source, field.name, bit): self.variable(destination, field.name, bit)
                for field in self.fields
                for bit in range(field.width)
            }
        )
