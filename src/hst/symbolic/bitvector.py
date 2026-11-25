"""Boolean formulas for unsigned, most-significant-bit-first bit vectors.

This module is a Python port of `BDDInteger.java` and `ImmutableBDDInteger.java`
of Batfish at commit 2a513d04a14b99d72fe0079f85ad8be3f5b6f4fa. The Batfish
authors license those files under the Apache License 2.0. The port changes them.
`third_party/symbolic/licenses/batfish-2a513d0-Apache-2.0.txt` holds the licence
text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class BitVector:
    bdd: Any
    variables: tuple[str, ...]

    @property
    def width(self) -> int:
        return len(self.variables)

    def _value(self, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("bit-vector values must be integers")
        if value < 0 or value >= 1 << self.width:
            raise ValueError(f"value {value} does not fit in {self.width} bits")
        return value

    def equals(self, value: int) -> Any:
        value = self._value(value)
        result = self.bdd.true
        for offset, variable in enumerate(self.variables):
            bit = 1 << (self.width - offset - 1)
            node = self.bdd.var(variable)
            result &= node if value & bit else ~node
        return result

    def equals_vector(self, other: BitVector) -> Any:
        if self.bdd is not other.bdd or self.width != other.width:
            raise ValueError("bit vectors must have the same manager and width")
        result = self.bdd.true
        for left, right in zip(self.variables, other.variables, strict=True):
            a, b = self.bdd.var(left), self.bdd.var(right)
            result &= (a & b) | (~a & ~b)
        return result

    def at_most(self, value: int) -> Any:
        value = self._value(value)
        less = self.bdd.false
        equal = self.bdd.true
        for offset, variable in enumerate(self.variables):
            bit_set = bool(value & (1 << (self.width - offset - 1)))
            node = self.bdd.var(variable)
            if bit_set:
                less |= equal & ~node
                equal &= node
            else:
                equal &= ~node
        return less | equal

    def at_least(self, value: int) -> Any:
        self._value(value)
        if value == 0:
            return self.bdd.true
        return ~self.at_most(value - 1)

    def between(self, lower: int, upper: int) -> Any:
        self._value(lower)
        self._value(upper)
        if lower > upper:
            raise ValueError("range lower bound exceeds upper bound")
        return self.at_least(lower) & self.at_most(upper)

    def masked_equals(self, value: int, mask: int) -> Any:
        value = self._value(value)
        mask = self._value(mask)
        result = self.bdd.true
        for offset, variable in enumerate(self.variables):
            bit = 1 << (self.width - offset - 1)
            if not mask & bit:
                continue
            node = self.bdd.var(variable)
            result &= node if value & bit else ~node
        return result
