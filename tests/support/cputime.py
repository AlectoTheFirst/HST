"""The CPU time of a block of a test."""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass


@dataclass
class CpuTime:
    seconds: float = 0.0


@contextmanager
def cpu_time() -> Iterator[CpuTime]:
    """Measure the CPU time that the threads of this process use in the block.

    `seconds` is set when the block ends. The time that the process waits for
    the scheduler, for a sleep or for another process is not in it, so the load
    of the machine does not move a bound on it.
    """
    spent = CpuTime()
    started = time.process_time()
    try:
        yield spent
    finally:
        spent.seconds = time.process_time() - started
