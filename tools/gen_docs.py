"""Write the generated blocks of the docs from the registries of the code.

A block is the text between `<!-- generated: NAME -->` and `<!-- end generated: NAME -->`.
`--check` writes nothing and exits 1 when a block differs from the code.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable
from pathlib import Path

from hst import collectors  # noqa: F401  the import fills REGISTRY
from hst.collectors.base import REGISTRY
from hst.core import db, labels, sidestore
from hst.reasoner import catalog

DOCS = Path(__file__).resolve().parents[1] / "docs"


def _code(values: object) -> str:
    return ", ".join(f"`{v}`" for v in values)  # type: ignore[attr-defined]


def labels_block() -> str:
    rows = ["| Label | Layers | Tier | Gate | Required properties |", "|---|---|---|---|---|"]
    for name, spec in labels.LABELS.items():
        gate = "yes" if spec.gate else "no"
        tier = labels.STRATA_TIERS[labels.TIER_BY_KIND[name]]
        rows.append(f"| `{name}` | {_code(spec.layers)} | {tier} | {gate} | {_code(spec.requires)} |")
    return "\n".join(rows)


def schema_version_block() -> str:
    return f"`src/hst/core/labels.py` `SCHEMA_VERSION` is `{labels.SCHEMA_VERSION}`."


def neo4j_statements_block() -> str:
    return "\n".join(f"- `{' '.join(statement.split())}`" for statement in db.CONSTRAINT_STATEMENTS)


def relationship_types_block() -> str:
    return "\n".join(f"- `{name}`" for name in sorted(labels.RELS))


def vocabularies_block() -> str:
    rows = ["| Name | Values |", "|---|---|"]
    for name in sorted(vars(labels)):
        value = getattr(labels, name)
        if name.isupper() and name != "RELS" and isinstance(value, frozenset):
            rows.append(f"| `{name}` | {_code(sorted(value))} |")
    return "\n".join(rows)


def gate_bindings_block() -> str:
    lines: list[str] = []
    for name, binding in labels.GATE_BINDINGS.items():
        if binding[0] == labels.NOT_DEVICE_BOUND:
            lines.append(f"- `{name}` has no device binding. {binding[1]}")
            continue
        lines.append(f"- `{name}`")
        lines.extend(f"  - `{pattern}`" for pattern in binding)
    return "\n".join(lines)


def sidestore_tables_block() -> str:
    rows = ["| Table | Schema version | Column | Type |", "|---|---|---|---|"]
    for table, schema in sidestore.SCHEMAS.items():
        version = sidestore.SCHEMA_VERSIONS[table]
        rows.extend(f"| `{table}` | {version} | `{field.name}` | `{field.type}` |" for field in schema)
    return "\n".join(rows)


def reasoner_rules_block() -> str:
    return "\n".join(f"{i}. `{name}`" for i, (name, _query) in enumerate(catalog.RULES, 1))


def sources_block() -> str:
    rows = [
        "| Source type | Kind | Class | Module | Side-store tables | Also in the graph |",
        "|---|---|---|---|---|---|",
    ]
    for name in sorted(REGISTRY):
        cls = REGISTRY[name]
        module = "src/" + cls.__module__.replace(".", "/") + ".py"
        tables, mirrored = _code(cls.SIDE_TABLES), _code(cls.GRAPH_MIRRORED_TABLES)
        rows.append(f"| `{name}` | {cls.KIND} | `{cls.__name__}` | `{module}` | {tables} | {mirrored} |")
    return "\n".join(rows)


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in re.split(r"(?<!\\)\|", line.strip().strip("|"))]


def _schema_tables() -> list[tuple[str, list[str], list[list[str]]]]:
    """Each table of a label section of `docs/schema.md`: the label, the header cells and the rows."""
    lines = (DOCS / "schema.md").read_text().split("\n")
    start = lines.index("## Properties and relationships")
    end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith("## "))
    tables: list[tuple[str, list[str], list[list[str]]]] = []
    label = ""
    i = start
    while i < end:
        line = lines[i]
        if line.startswith("#### "):
            label = line[5:].strip()
        elif line.startswith("### "):
            label = ""
        elif label and line.startswith("|") and re.fullmatch(r"\|[-| ]+\|", lines[i + 1].strip()):
            header = _cells(line)
            rows = []
            i += 2
            while i < end and lines[i].startswith("|"):
                rows.append(_cells(lines[i]))
                i += 1
            tables.append((label, header, rows))
            continue
        i += 1
    return tables


def _source_types(cell: str) -> list[str]:
    return [name for name in re.findall(r"`([a-z_]+)`", cell) if name in REGISTRY]


def schema_by_source_type_block() -> str:
    """The rows of the label tables of `docs/schema.md`, ordered by the source type that writes them."""
    per_type: dict[str, dict[str, dict[str, list[tuple[str, str]]]]] = {name: {} for name in sorted(REGISTRY)}
    other: list[tuple[str, str, str, str]] = []
    tables = _schema_tables()
    listed: dict[str, set[str]] = {}
    for label, header, rows in tables:
        writers = listed.setdefault(label, set())
        column = len(header) - 1 if header[-1] == "Written by" else 0 if header[0] == "Source type" else None
        if column is not None:
            writers.update(name for row in rows for name in _source_types(row[column]))
    for label, header, rows in tables:
        if header[0] == "Source type":
            # A table with the value of 1 or more properties for each source type.
            for row in rows:
                for column, name in enumerate(header):
                    if not re.fullmatch(r"`\w+`", name):
                        continue
                    content = f"{row[column]} on {row[1]}" if header[1] == "Rulebase" else row[column]
                    for source_type in _source_types(row[0]):
                        parts = per_type[source_type].setdefault(label, {"props": [], "rels": []})
                        parts["props"].append((name, content))
            continue
        kind = {"Property": "props", "Relationship": "rels"}.get(header[0])
        if kind is None or header[1] not in ("Content", "Properties"):
            continue
        for row in rows:
            first, second = row[0], row[1].replace("](#", "](schema.md#")
            if header[-1] == "Written by":
                names = _source_types(row[2])
                if not names:
                    other.append((label, first, second, row[2]))
            else:
                names = sorted(listed[label])
            for name in names:
                per_type[name].setdefault(label, {"props": [], "rels": []})[kind].append((first, second))
    out: list[str] = []
    for name, by_label in per_type.items():
        out += [f"## `{name}`", ""]
        if not by_label:
            out += ["The collector writes no node and no relationship of a label section.", ""]
        for label, parts in by_label.items():
            out += [f"### {label} of `{name}`", ""]
            if parts["props"]:
                out += ["| Property | Content |", "|---|---|"]
                out += [f"| {first} | {second} |" for first, second in parts["props"]] + [""]
            if parts["rels"]:
                out += ["| Relationship | Properties |", "|---|---|"]
                out += [f"| {first} | {second} |" for first, second in parts["rels"]] + [""]
    out += ["## Loader, reasoner rules and other code", ""]
    out += ["| Label | Property or relationship | Content or properties | Written by |", "|---|---|---|---|"]
    out += [f"| `{label}` | {first} | {second} | {writer} |" for label, first, second, writer in other]
    return "\n".join(out)


# The doc of each block, and the function that writes the block.
BLOCKS: dict[str, tuple[str, Callable[[], str]]] = {
    "schema-version": ("schema.md", schema_version_block),
    "labels": ("schema.md", labels_block),
    "relationship-types": ("schema.md", relationship_types_block),
    "vocabularies": ("schema.md", vocabularies_block),
    "gate-bindings": ("schema.md", gate_bindings_block),
    "neo4j-statements": ("storage.md", neo4j_statements_block),
    "sidestore-tables": ("storage.md", sidestore_tables_block),
    "reasoner-rules": ("conventions.md", reasoner_rules_block),
    "sources": ("collectors.md", sources_block),
    "schema-by-source-type": ("schema-by-source-type.md", schema_by_source_type_block),
}


def render(docs: Path = DOCS) -> dict[Path, str]:
    """The text of each doc with its blocks written again. A doc without its marker is an error."""
    out: dict[Path, str] = {}
    for name, (doc, build) in BLOCKS.items():
        path = docs / doc
        text = out.get(path) or path.read_text()
        start, end = f"<!-- generated: {name} -->", f"<!-- end generated: {name} -->"
        if text.count(start) != 1 or text.count(end) != 1:
            raise SystemExit(f"{doc}: the markers of the block `{name}` must each be there 1 time")
        head, rest = text.split(start)
        _old, tail = rest.split(end)
        out[path] = f"{head}{start}\n{build()}\n{end}{tail}"
    return out


def stale(docs: Path = DOCS) -> list[str]:
    return sorted(path.name for path, text in render(docs).items() if path.read_text() != text)


def main() -> None:
    if "--check" in sys.argv[1:]:
        names = stale()
        if names:
            raise SystemExit(f"generated blocks differ from the code in: {', '.join(names)}. Run {__file__}")
        return
    for path, text in render().items():
        path.write_text(text)


if __name__ == "__main__":
    main()
