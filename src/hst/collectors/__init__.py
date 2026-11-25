"""Collector plugins. Importing this package registers all built-in collectors."""

from __future__ import annotations

from . import apic as _apic  # noqa: F401  registers itself
from . import checkpoint as _checkpoint  # noqa: F401  registers itself
from . import checkpoint_gateway as _checkpoint_gateway  # noqa: F401  registers itself
from . import equinix as _equinix  # noqa: F401  registers itself
from . import iosxe as _iosxe  # noqa: F401  registers itself
from . import iosxr as _iosxr  # noqa: F401  registers itself
from . import manual as _manual  # noqa: F401  registers itself
from . import nautobot as _nautobot  # noqa: F401  registers itself
from . import ndo as _ndo  # noqa: F401  registers itself
from . import netscaler as _netscaler  # noqa: F401  registers itself
from . import nxos as _nxos  # noqa: F401  registers itself
from . import unifi as _unifi  # noqa: F401  registers itself
from . import velocloud as _velocloud  # noqa: F401  registers itself
from . import vyos as _vyos  # noqa: F401  registers itself
from . import zia as _zia  # noqa: F401  registers itself
from . import zpa as _zpa  # noqa: F401  registers itself
from .base import (
    RAW_OUTCOMES_KEY,
    REGISTRY,
    Collector,
    execute,
    execute_observations,
    fetch_traced,
    load_observations,
    load_payload,
    obs_sha,
    park,
    raw_sha,
    register,
    spill,
)

__all__ = [
    "RAW_OUTCOMES_KEY",
    "REGISTRY",
    "Collector",
    "execute",
    "execute_observations",
    "fetch_traced",
    "load_observations",
    "load_payload",
    "obs_sha",
    "park",
    "raw_sha",
    "register",
    "spill",
]
