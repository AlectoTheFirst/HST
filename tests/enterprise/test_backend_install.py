"""Native-backend checks that never accept dd.autoref as an enterprise substitute."""

from __future__ import annotations

import gc
import importlib
import os

import pytest


def native_cudd():
    try:
        return importlib.import_module("dd.cudd")
    except ImportError as exc:
        if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
            pytest.fail(f"required native dd.cudd backend is unavailable: {exc}")
        pytest.skip(f"native dd.cudd backend is unavailable: {exc}")


def test_native_cudd_conjunction_quantification_and_rename() -> None:
    cudd = native_cudd()
    manager = cudd.BDD()
    manager.configure(reordering=False)
    assert manager.configure()["reordering"] is False
    manager.declare("source", "destination", "next_source")
    source = manager.var("source")
    destination = manager.var("destination")
    next_source = manager.var("next_source")
    formula = source & destination
    assert manager.exist(["destination"], formula) == source
    assert manager.let({"source": "next_source"}, formula) == (next_source & destination)
    assert manager.support(formula) == {"source", "destination"}
    index, low, high = manager.succ(formula)
    assert index == 0
    assert low == manager.false
    assert high == destination
    del formula, source, destination, next_source, low, high
    gc.collect()
    assert len(manager) == 0


def test_native_cudd_repeated_manager_teardown() -> None:
    cudd = native_cudd()
    for _ in range(5):
        manager = cudd.BDD()
        manager.configure(reordering=False)
        manager.declare("x", "y")
        node = manager.var("x") & manager.var("y")
        del node
        gc.collect()
        assert len(manager) == 0
