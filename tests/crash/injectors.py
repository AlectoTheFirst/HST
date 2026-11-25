"""A fault injector shared by the crash-injection scenarios."""

from __future__ import annotations

import inspect
from typing import Any


class SimulatedCrash(RuntimeError):
    """Raised by a fault-injected seam once its real work is done."""


def crash_after(monkeypatch: Any, module: Any, name: str) -> None:
    """Replace `module.name` with a wrapper that calls the real function, sync
    or async, and then raises `SimulatedCrash`."""
    real = getattr(module, name)

    if inspect.iscoroutinefunction(real):

        async def _boom_async(*args: Any, **kwargs: Any) -> Any:
            await real(*args, **kwargs)
            raise SimulatedCrash(f"simulated crash immediately after {module.__name__}.{name}")

        monkeypatch.setattr(module, name, _boom_async)
        return

    def _boom_sync(*args: Any, **kwargs: Any) -> Any:
        real(*args, **kwargs)
        raise SimulatedCrash(f"simulated crash immediately after {module.__name__}.{name}")

    monkeypatch.setattr(module, name, _boom_sync)
