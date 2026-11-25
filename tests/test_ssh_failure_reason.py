"""`ssh._failure_reason` finds the first output line in place.

A device can exit non-zero after a whole table on standard output. The
reason is the first 200 characters of the first non-empty line, as
`str.splitlines` finds it, and finding it costs the line, not a list of
every line of the answer.
"""

from __future__ import annotations

import random
import tracemalloc

from hst.collectors import ssh


def _reference(stdout: str) -> str:
    """The reason as a walk over every line gives it."""
    return next((line.strip() for line in stdout.splitlines() if line.strip()), "")[:200]


# Letters, a `%` that no rejection banner follows, the whitespace `str.strip`
# removes, and every line break `str.splitlines` honours.
ALPHABET = [
    *("a", "b", "%", "x" * 150),
    *(" ", "\t", "\u3000"),
    *("\n", "\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"),
]


def test_the_reason_matches_a_walk_over_every_line():
    rng = random.Random(5)
    cases = ["", "   ", "\n\n  \n", "x" * 450, "  lead  \n", "\n  \t first line  \t\n second\n"]
    for _ in range(4000):
        cases.append("".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 12))))
    for stdout in cases:
        assert ssh._failure_reason(stdout, "") == _reference(stdout), repr(stdout)


def test_standard_error_and_a_rejection_banner_come_first():
    assert ssh._failure_reason("table\n", " boom \n") == "boom"
    assert ssh._failure_reason("x\n% Invalid command at '^' marker.\n", "") == (
        "% Invalid command at '^' marker."
    )


def test_a_long_standard_error_is_cut_at_the_reason_bound():
    reason = ssh._failure_reason("", "tacacs " * 100_000)

    assert len(reason) == ssh._STDERR_REASON_MAX
    assert reason.startswith("tacacs tacacs")


def test_a_large_answer_costs_its_first_line_not_a_copy():
    stdout = "\n\n" + "".join(
        f"*> 10.{i // 256 % 256}.{i % 256}.0/24 192.0.2.1 0 65000 {i} i\n" for i in range(200_000)
    )
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        reason = ssh._failure_reason(stdout, "")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert reason == "*> 10.0.0.0/24 192.0.2.1 0 65000 0 i"
    assert peak < 64 * 1024, peak
