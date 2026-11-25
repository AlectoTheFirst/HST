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
def cpu_time(*, all_threads: bool = False) -> Iterator[CpuTime]:
    """Measure the CPU time that the calling thread uses in the block.

    With `all_threads`, the time is that of all threads of the process. A
    thread that an earlier test left running then adds its time too.

    `seconds` is set when the block ends. The time that the thread waits for
    the scheduler, for a sleep or for another process is not in it, so the load
    of the machine does not move a bound on it.
    """
    clock = time.process_time if all_threads else time.thread_time
    spent = CpuTime()
    started = clock()
    try:
        yield spent
    finally:
        spent.seconds = clock() - started
