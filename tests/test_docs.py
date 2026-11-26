"""The docs in `docs/` against the code."""

from __future__ import annotations

import ast
import importlib.util
import pkgutil
import re
from functools import cache
from pathlib import Path

import pytest
import typer

ROOT = Path(__file__).resolve().parents[1]
DOCS = sorted((ROOT / "docs").glob("*.md"))
# These 2 docs hold paths of vendor APIs under `/api`.
VENDOR_API_DOCS = {"collectors.md", "device-commands.md"}

SPAN = re.compile(r"`([^`\n]+)`")
PATH = re.compile(r"(?:src/hst|tests|web/src|fixtures|deploy|tools|docs)/[\w./-]+")
TOP_LEVEL = {"README.md", "CONTRIBUTING.md", "CLAUDE.md", "Makefile", "compose.yaml", "compose.worker.yaml"}
SYMBOL = re.compile(r"`(src/hst/[\w/]+\.py)` `([A-Za-z_][\w.]*)(?:\(\))?`")
ROUTE = re.compile(r"(?:(GET|POST|PUT|PATCH|DELETE) )?(/api/[\w/{}.<>-]*)")
DECORATOR = re.compile(r"@\w+\.(get|post|put|patch|delete)\(\s*[\"']([^\"']*)[\"']")
HST_PREFIXES = ("hst ", "uv run hst ", "podman compose exec app hst ")
# These constants hold the keys of a stored payload. No fetch sends their values.
PAYLOAD_KEY_CONSTANTS = {"LEGACY_OSPF_COMMANDS"}


def _lines(doc: Path) -> list[tuple[int, str]]:
    return list(enumerate(doc.read_text().splitlines(), 1))


def _spans(doc: Path) -> list[tuple[int, str]]:
    return [(n, span) for n, line in _lines(doc) for span in SPAN.findall(line)]


@cache
def _defined(path: Path) -> frozenset[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return frozenset(names)


@cache
def _cli() -> dict[tuple[str, ...], frozenset[str] | None]:
    """Each command path of `hst` with its options. The value of a group is None."""
    from hst.cli import app

    out: dict[tuple[str, ...], frozenset[str] | None] = {}

    def walk(command, path: tuple[str, ...]) -> None:
        children = getattr(command, "commands", None)
        opts = {o for p in command.params for o in (*p.opts, *p.secondary_opts)}
        out[path] = None if children else frozenset(opts | {"--help"})
        for name, child in (children or {}).items():
            walk(child, (*path, name))

    walk(typer.main.get_command(app), ())
    return out


def _route_key(path: str) -> str:
    return re.sub(r"\{[^}]*\}|<[^>]*>", "{}", path.rstrip("/."))


@cache
def _routes() -> frozenset[tuple[str, str]]:
    """Each method and path of the API: the OpenAPI schema and the route decorators outside it."""
    from hst.app.main import create_app
    from hst.core.config import Settings

    schema = create_app(Settings(_env_file=None)).openapi()["paths"]
    found = {(method.upper(), _route_key(path)) for path, ops in schema.items() for method in ops}
    for source in (ROOT / "src" / "hst" / "app").rglob("*.py"):
        for method, path in DECORATOR.findall(source.read_text()):
            found.add((method.upper(), _route_key("/api" + path)))
    return frozenset(found)


def test_generated_blocks_match_the_code():
    spec = importlib.util.spec_from_file_location("gen_docs", ROOT / "tools" / "gen_docs.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.stale() == []


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_each_cited_path_exists(doc: Path):
    missing = [
        f"{doc.name}:{n} {span}"
        for n, span in _spans(doc)
        if (PATH.fullmatch(span) or span in TOP_LEVEL) and not (ROOT / span).exists()
    ]
    assert missing == []


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_each_cited_symbol_is_defined_in_its_file(doc: Path):
    missing = []
    for n, line in _lines(doc):
        for path, symbol in SYMBOL.findall(line):
            source = ROOT / path
            if source.exists() and not all(part in _defined(source) for part in symbol.split(".")):
                missing.append(f"{doc.name}:{n} {path} {symbol}")
    assert missing == []


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_each_hst_command_and_option_exists(doc: Path):
    cli = _cli()
    wrong = []
    in_fence = False
    for n, line in _lines(doc):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        for text in [line.strip()] if in_fence else SPAN.findall(line):
            prefix = next((p for p in HST_PREFIXES if text.startswith(p)), None)
            if prefix is None:
                continue
            words = text[len(prefix) :].split()
            path: tuple[str, ...] = ()
            while words and (*path, words[0]) in cli:
                path = (*path, words.pop(0))
            options = cli[path]
            if options is None:
                if words and not words[0].startswith(("-", "<", "[")):
                    wrong.append(f"{doc.name}:{n} `{text}`: no command `{' '.join((*path, words[0]))}`")
                continue
            for word in words:
                option = word.split("=")[0]
                if option.startswith("--") and option not in options:
                    wrong.append(f"{doc.name}:{n} `{text}`: no option `{option}`")
    assert wrong == []


@pytest.mark.parametrize("doc", [d for d in DOCS if d.name not in VENDOR_API_DOCS], ids=lambda p: p.name)
def test_each_api_route_exists(doc: Path):
    routes = _routes()
    paths = {path for _method, path in routes}
    wrong = []
    for n, span in _spans(doc):
        match = ROUTE.fullmatch(span.split("?")[0])
        if match is None:
            continue
        method, path = match.groups()
        key = _route_key(path)
        if key not in paths or (method and (method, key) not in routes):
            wrong.append(f"{doc.name}:{n} {span}")
    assert wrong == []


def _command_constants() -> dict[str, set[str]]:
    """The command strings that a collector module holds in a constant with COMMAND in its
    name or in `SECTIONS`."""
    import hst.collectors as package

    found: dict[str, set[str]] = {}

    def take(value, into: set[str]) -> None:
        if isinstance(value, str):
            if " " in value.strip() or "-" in value:
                into.add(" ".join(value.split()))
        elif hasattr(value, "command"):  # a `Section` is a tuple, and only its command is sent
            take(value.command, into)
        elif isinstance(value, dict):
            for item in value.values():
                take(item, into)
        elif isinstance(value, (tuple, list, set, frozenset)):
            for item in value:
                take(item, into)

    for info in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(f"hst.collectors.{info.name}")
        strings: set[str] = set()
        for name, value in vars(module).items():
            if ("COMMAND" in name.upper() or name == "SECTIONS") and name not in PAYLOAD_KEY_CONSTANTS:
                take(value, strings)
        if strings:
            found[info.name] = strings
    return found


def test_each_command_constant_is_in_the_device_commands_doc():
    doc = ROOT / "docs" / "device-commands.md"
    text = " ".join(doc.read_text().replace("\\|", "|").split())
    missing = sorted(
        f"src/hst/collectors/{module}.py: {command}"
        for module, commands in _command_constants().items()
        for command in commands
        if command not in text
    )
    assert missing == []
