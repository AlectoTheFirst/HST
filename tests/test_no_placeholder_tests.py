"""No test is a placeholder."""

from __future__ import annotations

import ast
from pathlib import Path

TESTS = Path(__file__).resolve().parent


def _is_skip_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "skip"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "pytest"
    )


def _is_skip_mark(node: ast.AST) -> bool:
    target = node.func if isinstance(node, ast.Call) else node
    return (
        isinstance(target, ast.Attribute)
        and target.attr == "skip"
        and isinstance(target.value, ast.Attribute)
        and target.value.attr == "mark"
    )


def _placeholders() -> list[str]:
    found = []
    for path in sorted(TESTS.rglob("test_*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not node.name.startswith(
                "test_"
            ):
                continue
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                body = body[1:]
            only_skip = len(body) == 1 and isinstance(body[0], ast.Expr) and _is_skip_call(body[0].value)
            if only_skip or not body or any(_is_skip_mark(d) for d in node.decorator_list):
                found.append(f"{path.relative_to(TESTS.parent)}::{node.name}")
    return found


def test_no_test_is_only_an_unconditional_skip():
    assert _placeholders() == []
