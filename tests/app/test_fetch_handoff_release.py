"""A result the loader discards from the plain hand-off an inline cycle or a
refresh passes (`runs_exec._discard_fetched`) is released as the fetch
buffer releases one: nothing else would end its HTTP trace or remove its
spill file."""

from __future__ import annotations

from hst.app import runs_exec


class _Trace:
    discarded = 0

    def discard(self) -> None:
        self.discarded += 1


def test_a_result_discarded_from_a_plain_hand_off_ends_its_trace():
    held = runs_exec._Fetched({"x": 1})
    held.trace = trace = _Trace()  # type: ignore[assignment]
    plain: dict[int, runs_exec._Fetched] = {1: held, 2: runs_exec._Fetched()}

    runs_exec._discard_fetched(plain, 1)
    runs_exec._discard_fetched(plain, 1)
    runs_exec._discard_fetched(plain, 3)

    assert list(plain) == [2]
    assert trace.discarded == 1


def test_a_spilled_result_discarded_from_a_plain_hand_off_loses_its_spill_file(tmp_path, monkeypatch):
    dropped: list[object] = []
    monkeypatch.setattr(runs_exec.rawstore, "drop_spill", dropped.append)
    held = runs_exec._Fetched()
    held.spilled = spill = tmp_path / "unit.spill"  # type: ignore[assignment]

    runs_exec._discard_fetched({7: held}, 7)

    assert dropped == [spill]
