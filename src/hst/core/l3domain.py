from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

# the name every platform's global/unnamed routing table maps onto
DEFAULT_VRF = "default"

Strategy = Literal["auto", "strict"]


@dataclass(frozen=True)
class Vrf:
    device: str
    """Device uid."""

    name: str = DEFAULT_VRF
    """`default` for the global table."""

    rd: str | None = None
    """Route distinguisher, when reported."""

    rts: tuple[str, ...] = ()
    """Import and export route targets, deduplicated and sorted."""

    def normalised(self) -> Vrf:
        return Vrf(self.device, self.name or DEFAULT_VRF, self.rd, tuple(sorted({r for r in self.rts if r})))


@dataclass
class DomainPolicy:
    """How a source resolves VRFs to domains."""

    scope: str
    """The routing scope this source's devices share."""

    strategy: Strategy = "auto"
    """`strict` stops at `device:vrf`."""

    overrides: Mapping[str, str] = field(default_factory=dict)
    """`device:vrf` or `scope:vrf` -> domain name."""


def resolve(vrf: Vrf, policy: DomainPolicy) -> str:
    v = vrf.normalised()

    # An override decides the domain. The key `device:vrf` is read before `scope:vrf`.
    for key in (f"{v.device}:{v.name}", f"{policy.scope}:{v.name}"):
        if key in policy.overrides:
            return policy.overrides[key]

    # The strategy `strict` gives each VRF of each device its own domain.
    if policy.strategy == "strict":
        return f"{v.device}:{v.name}"

    # VRFs with the same route targets share a domain across devices.
    if v.rts:
        return "rt:" + "+".join(v.rts)

    # VRFs with the same name share a domain within a scope. The domain of the
    # global table is the scope.
    if v.name == DEFAULT_VRF:
        return policy.scope
    return f"{policy.scope}:{v.name}"


def display_name(domain: str) -> str:
    if domain.startswith("rt:"):
        return f"route-target {domain[3:]}"
    return domain
