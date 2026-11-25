"""Time travel core: the tracer's $snap injection, the ribsource as_of bound,
and the snapshot diff."""

from __future__ import annotations

import functools
import inspect
import pathlib
import re
from typing import Any

import pytest

from hst import path
from hst.core.diff import diff_snapshots
from hst.core.snapshot import Snapshot


def _snap(cts: int | None, settings: Any = None) -> Snapshot:
    """The resolved Snapshot a reader is handed (core/snapshot.py), built
    directly: `resolve` reads the pointer off a graph session, and the tests
    below that only need the run it named have no session to read."""
    return Snapshot(cts, settings)


# --- $snap injection at the _read chokepoint --------------------------------------------


class _CaptureTx:
    def __init__(self, sink: list[dict[str, Any]]) -> None:
        self._sink = sink

    def run(self, query: str, **params: Any):
        self._sink.append({"query": query, "params": params})

        class _Result:
            def data(self) -> list:
                return []

        return _Result()


class _CaptureSession:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def execute_read(self, work, /) -> Any:
        return work(_CaptureTx(self.calls))


def test_read_binds_the_live_sentinel_by_default():
    s = _CaptureSession()
    path._read(s, "MATCH (n) RETURN n", x=1)
    assert s.calls[0]["params"] == {"x": 1, "snap": path.LIVE_SNAP}


def test_cycle_session_carries_its_collection_ts_into_every_read():
    inner = _CaptureSession()
    pinned = path.CycleSession(inner, 1724000000000)
    path._read(pinned, "MATCH (n) RETURN n")
    assert inner.calls[0]["params"] == {"snap": 1724000000000}


def test_pinned_wraps_only_when_a_run_is_known():
    inner = _CaptureSession()
    assert path.pinned(inner, _snap(None)) is inner
    snapshot = _snap(42)
    wrapped = path.pinned(inner, snapshot)
    assert isinstance(wrapped, path.CycleSession) and wrapped.cts == 42
    assert wrapped.snapshot is snapshot


def test_every_tracer_query_carries_the_snap_guard():
    """A query is guarded if it holds one of the tokens of `guard_tokens`."""
    from tests.conftest import snap_guard_corpus_strings

    guard_tokens = ("$snap", "coalesce(", "collection_ts:", "collection_ts =")
    bookkeeping_labels = ("CycleRun", "CollectionRun")

    queries = [s for s in snap_guard_corpus_strings() if "MATCH" in s and "RETURN" in s]
    assert queries, "the source scan found no queries at all, the regex broke"
    missing = [
        q
        for q in queries
        if not any(tok in q for tok in guard_tokens) and not any(label in q for label in bookkeeping_labels)
    ]
    assert not missing, f"cross-run queries without a snapshot guard: {missing}"


# --- the anchor convention, parsed from every Cypher string ------------------------------
#
# Every retained run is a full copy of the graph, and the only node indexes that
# know the run are obj_uid_cts on :Obj(uid, collection_ts) and obj_cts on
# :Obj(collection_ts). A MATCH part that starts from a node the query has not
# bound yet is an anchor, and it must name :Obj and pin collection_ts by
# equality, in the node's map or as a top-level conjunct of the clause's WHERE,
# or the planner scans that label in every kept run. A pin inside an OR is no
# pin. The coalesce form `coalesce(x.collection_ts, $snap) = $snap` cannot use
# either index. An operator-invented :Meta Site carries no
# collection_ts, so a Site anchor is pinned with `(s:Meta OR s.collection_ts =
# $snap)` and found through the site_uid or site_code index. The run
# bookkeeping labels are read by their own uid or listed whole.

_ANCHOR_EXEMPT_LABELS = frozenset({"CycleRun", "CollectionRun", "CyclePointer", "Meta"})
# The labels an operator-invented :Meta node can carry next to them.
_META_LABELS = frozenset({"Site"})

# Queries whose job is every retained run, keyed by module and a fragment of the
# query text, with why. Each entry must still match a query that offends.
_ALL_RUNS: dict[tuple[str, str], str] = {
    ("core/db.py", "MATCH (n:Obj) RETURN count(n)"): "hst check counts the whole database",
    ("core/db.py", "MATCH (n:Obj:Retired) RETURN count(n)"): "hst check counts the whole database",
    ("core/db.py", "MATCH (:Obj)-[r]->(:Obj) RETURN count(r)"): "hst check counts the whole database",
    ("core/cycle.py", "WHERE n.collection_ts IS NULL AND NOT n:Meta"): (
        "migrate-cycle stamps the nodes that carry no run yet"
    ),
    ("core/cycle.py", "r._scope = 'reasoner' AND r.collection_ts IS NULL"): (
        "migrate-cycle removes the reasoner edges written before the run model, once"
    ),
    (
        "core/replay.py",
        "MATCH (n) WITH n LIMIT $batch DETACH DELETE n",
    ): "a rebuild empties its target database",
    ("app/routes/runs.py", "MATCH (n)"): "the graph purge empties the database",
    ("core/cycle.py", "WHERE n.collection_ts < $below"): (
        "retention lists the run keys below a bound, a range seek on obj_cts"
    ),
    ("assessment/archive_sessions.py", "MATCH (n)"): "an archive session empties its scratch database",
    ("bench.py", "HAS_SESSION"): "the benchmark loads and counts a scratch database",
    ("bench.py", "MATCH (n:Device)"): "the benchmark loads and counts a scratch database",
    ("bench.py", "MATCH (n:BgpSession)"): "the benchmark loads and counts a scratch database",
    ("app/routes/explore.py", "coalesce(d.collection_ts, 0) AS ts"): (
        "the hostname index lists every retained copy of a device and keeps the newest"
    ),
}

_FMT = "__F__"
# A node pattern: an opening parenthesis that is no function call's.
_CY_NODE = re.compile(
    r"(?<![\w`])\(\s*(?!DISTINCT\b)([A-Za-z_][A-Za-z_0-9]*)?\s*((?::\s*[A-Za-z_`][A-Za-z_0-9`|&!]*\s*)*)(\{[^{}]*\})?\s*\)",
)
_CY_REL = re.compile(r"\[\s*([A-Za-z_][A-Za-z_0-9]*)")
_CY_CLAUSE = re.compile(r"\b(?:OPTIONAL\s+MATCH|MATCH)\b")
_CY_KEYWORD = re.compile(
    r"\b(OPTIONAL\s+MATCH|MATCH|MERGE|CREATE|WHERE|WITH|RETURN|UNWIND|CALL|SET|DELETE|DETACH|REMOVE"
    r"|FOREACH|UNION|ORDER|LIMIT|SKIP|USING|YIELD)\b"
)
_CY_SUBQUERY = re.compile(r"\b(CALL|EXISTS|COUNT|COLLECT)\s*(\(([^()]*)\))?\s*$")
_CY_BOOL = re.compile(r"\b(AND|OR|XOR)\b")


@functools.cache
def _module_info(
    py: pathlib.Path,
) -> tuple[dict[str, str], dict[str, Any], dict[str, tuple[pathlib.Path, str]]]:
    """One module's string constants, its helper functions whose whole body
    returns an expression, and the names it imports from other hst modules."""
    import ast

    tree = ast.parse(py.read_text())
    root = _hst_root()
    consts: dict[str, str] = {}
    funcs: dict[str, Any] = {}
    imported: dict[str, tuple[pathlib.Path, str]] = {}
    info = (consts, funcs, imported)
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] == "hst":
            base = root.joinpath(*node.module.split(".")[1:])
            target = base.with_suffix(".py") if base.with_suffix(".py").exists() else base / "__init__.py"
            for alias in node.names:
                imported[alias.asname or alias.name] = (target, alias.name)
        elif isinstance(node, ast.FunctionDef):
            body = [
                b for b in node.body if not (isinstance(b, ast.Expr) and isinstance(b.value, ast.Constant))
            ]
            if len(body) == 1 and isinstance(body[0], ast.Return):
                funcs[node.name] = node
    for node in tree.body:
        target_name = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target_name, value_node = node.targets[0].id, node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            target_name, value_node = node.target.id, node.value
        if target_name is not None:
            value = _flat(value_node, py, info)
            if value is not None:
                consts[target_name] = value
    return info


def _hst_root() -> pathlib.Path:
    import hst

    return pathlib.Path(inspect.getsourcefile(hst)).parent


def _helper_text(py: pathlib.Path, name: str, args: list[str]) -> str | None:
    """What a helper of `py` returns for constant string arguments, run on its
    own with the module's string constants and no builtins."""
    import ast
    import copy

    consts, funcs, imported = _module_info(py)
    if name not in funcs:
        if name in imported and imported[name][0].exists():
            return _helper_text(*imported[name], args)
        return None
    defs = []
    for source in funcs.values():  # a helper may call another helper of its module
        fn = copy.deepcopy(source)
        fn.decorator_list = []
        fn.returns = None
        for arg in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs, fn.args.vararg, fn.args.kwarg]:
            if arg is not None:
                arg.annotation = None
        defs.append(fn)
    namespace: dict[str, Any] = {"__builtins__": {}, **consts}
    try:
        # the repository's own source, each helper alone and with no builtins
        exec(compile(ast.fix_missing_locations(ast.Module(defs, [])), str(py), "exec"), namespace)  # noqa: S102
        out = namespace[name](*args)
    except Exception:
        return None
    return out if isinstance(out, str) else None


def _format(template: str, values: dict[str, str]) -> str:
    """`str.format` with every field the call does not give read as `__F__`."""
    out = re.sub(r"\{\{|\}\}|\{([A-Za-z_]*)[^{}]*\}", lambda m: _brace_field(m, values), template)
    return out


def _brace_field(m: re.Match[str], values: dict[str, str]) -> str:
    if m.group(0) == "{{":
        return "{"
    if m.group(0) == "}}":
        return "}"
    return values.get(m.group(1) or "", _FMT)


def _flat(
    node: Any, py: pathlib.Path, info: tuple[dict[str, str], dict[str, Any], dict] | None = None
) -> str | None:
    """The text of a string expression: literals, f-strings (a replacement
    field it cannot read is `__F__`), `+`, module-level string names, the
    module's helper functions called with constant strings, and `.format(...)`
    and `.replace(...)` on any of those."""
    import ast

    consts = (info or _module_info(py))[0]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(str(v.value))
            else:
                text = _flat(v.value, py, info)
                parts.append(_FMT if text is None else text)
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _flat(node.left, py, info), _flat(node.right, py, info)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and info is None:
        if node.keywords or any(isinstance(a, ast.Starred) for a in node.args):
            return None
        # an argument the scan cannot read is passed as `__F__`, as an f-string field is
        args = [_flat(a, py) for a in node.args]
        return _helper_text(py, node.func.id, [_FMT if a is None else a for a in args])
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        base = _flat(node.func.value, py, info)
        if base is None:
            return None
        if node.func.attr == "format":
            values = {k.arg: _flat(k.value, py, info) for k in node.keywords if k.arg}
            return _format(base, {k: v for k, v in values.items() if v is not None})
        if node.func.attr == "replace" and len(node.args) == 2:
            old, new = _flat(node.args[0], py, info), _flat(node.args[1], py, info)
            return base if old is None else base.replace(old, new if new is not None else _FMT)
    return None


def _cypher_strings(py: pathlib.Path) -> list[tuple[int, str]]:
    """Every whole Cypher string a module builds: the largest string expression
    it can be read from, so a fragment spliced into a query is read inside it."""
    import ast

    tree = ast.parse(py.read_text())
    consts = _module_info(py)[0]
    inner: set[int] = set()
    used: set[str] = set()
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if id(node) in inner or isinstance(node, ast.Name):
            continue
        value = _flat(node, py)
        if value is None:
            continue
        for sub in ast.walk(node):
            if sub is not node:
                inner.add(id(sub))
            if isinstance(sub, ast.Name) and sub is not node:
                used.add(sub.id)
        found.append((node.lineno, value))
    fragments = {consts[name] for name in used if name in consts}
    return [
        (line, text)
        for line, text in found
        if text not in fragments
        and re.search(r"\bMATCH\s*(?:[A-Za-z_]\w*\s*=\s*)?\(", text)
        and re.search(r"\b(RETURN|DELETE|SET|MERGE|CREATE|WITH|REMOVE)\b", text)
    ]


def _clause_end(text: str) -> tuple[int, str | None]:
    """Where the clause starting at the head of `text` ends, and the keyword
    that ends it: the first keyword, `{` or `}` outside every bracket."""
    depth = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif depth == 0 and ch in "{}":
            return i, None
        elif depth == 0 and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            m = _CY_KEYWORD.match(text, i)
            # STARTS WITH and ENDS WITH are string operators, not a WITH clause
            if m and not (m.group(1) == "WITH" and re.search(r"\b(?:STARTS|ENDS)\s+$", text[:i])):
                return i, m.group(1)
        i += 1
    return len(text), None


def _split_top(text: str, sep: str = ",") -> list[str]:
    parts, depth, cur = [], 0, []
    for ch in text:
        depth += ch in "([{"
        depth -= ch in ")]}"
        if ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def _conjuncts(where: str) -> list[str]:
    """The top-level AND terms of a WHERE; none when a top-level OR or XOR
    makes the whole clause a disjunction."""
    out, depth, start, i = [], 0, 0, 0
    while i < len(where):
        ch = where[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and (i == 0 or not (where[i - 1].isalnum() or where[i - 1] == "_")):
            m = _CY_BOOL.match(where, i)
            if m:
                if m.group(1) != "AND":
                    return []
                out.append(where[start:i])
                start = i = m.end()
                continue
        i += 1
    out.append(where[start:])
    return [" ".join(c.split()) for c in out]


def _brace_end(text: str, at: int) -> int:
    depth = 0
    for i in range(at, len(text)):
        depth += text[i] == "{"
        depth -= text[i] == "}"
        if depth == 0:
            return i
    return len(text) - 1


def _blocks(text: str) -> list[tuple[int, int, str, set[str] | None]]:
    """The subquery blocks at the top level of `text`, as (start, end, kind,
    imports): `call` for CALL, whose imports are the names in its scope
    clause, and `expr` for EXISTS, COUNT and COLLECT, which see every outer name.
    A brace no such keyword opens is a map and is skipped whole."""
    out: list[tuple[int, int, str, set[str] | None]] = []
    i = 0
    while i < len(text):
        if text[i] == "{":
            end = _brace_end(text, i)
            m = _CY_SUBQUERY.search(text[:i])
            if m and m.group(1) == "CALL" and (m.group(3) or "").strip() != "*":
                out.append(
                    (i, end + 1, "call", {v.strip() for v in (m.group(3) or "").split(",") if v.strip()})
                )
            elif m:
                out.append((i, end + 1, "expr", None))
            i = end + 1
            continue
        i += 1
    return out


def _returned(body: str) -> set[str]:
    """The names a CALL subquery returns to the query around it."""
    names: set[str] = set()
    for m in re.finditer(r"\bRETURN\b", body):
        tail = body[m.end() :]
        tail = tail[: _clause_end(tail)[0]]
        for item in _split_top(tail):
            alias = re.search(r"\bAS\s+([A-Za-z_][A-Za-z_0-9]*)\s*$", item)
            bare = re.fullmatch(r"\s*(?:DISTINCT\s+)?([A-Za-z_][A-Za-z_0-9]*)\s*", item)
            if alias or bare:
                names.add((alias or bare).group(1))  # type: ignore[union-attr]
    return names


def _pinned(var: str | None, labels: set[str], props: str, where: str) -> bool:
    if re.search(r"\bcollection_ts\s*:\s*\$", props):
        return True
    if not var:
        return False
    for term in _conjuncts(where):
        if re.fullmatch(rf"{var}\.collection_ts\s*(?:=|IN)\s*\$\w+", term):
            return True
        if labels & _META_LABELS and re.fullmatch(
            rf"\(\s*{var}:Meta\s+OR\s+{var}\.collection_ts\s*=\s*\$\w+\s*\)", term
        ):
            return True
    return False


def _scope(text: str, bound: set[str], problems: list[str]) -> None:
    """Check every anchor of one query scope, then of each subquery in it."""
    blocks = _blocks(text)
    masked = list(text)
    for start, end, _, _ in blocks:
        masked[start:end] = " " * (end - start)
    flat = "".join(masked)
    cuts = [(m.start(), m.end()) for m in re.finditer(r"\bUNION(?:\s+ALL)?\b", flat)]
    edges = [0] + [e for _, e in cuts], [s for s, _ in cuts] + [len(flat)]
    for lo, hi in zip(*edges, strict=True):
        branch = set(bound) | {_FMT}
        _branch(text, flat, lo, hi, branch, blocks, problems)
        for start, end, kind, imports in blocks:
            if lo <= start < hi:
                inner = set(imports) if kind == "call" and imports is not None else set(branch)
                _scope(text[start + 1 : end - 1], inner, problems)


def _branch(
    text: str,
    flat: str,
    lo: int,
    hi: int,
    bound: set[str],
    blocks: list[tuple[int, int, str, set[str] | None]],
    problems: list[str],
) -> None:
    def bind(lo_at: int, hi_at: int) -> None:
        before = flat[lo_at:hi_at]
        bound.update(n.group(1) for n in _CY_NODE.finditer(before) if n.group(1))
        bound.update(_CY_REL.findall(before))
        bound.update(re.findall(r"\bAS\s+([A-Za-z_][A-Za-z_0-9]*)", before))
        for names in re.findall(r"\b(?:WITH|YIELD|CALL\s*\()\s*([A-Za-z_0-9, ]+)", before):
            bound.update(v.strip() for v in names.split(","))
        for b_start, b_end, kind, _ in blocks:
            if kind == "call" and lo_at <= b_start < hi_at:
                bound.update(_returned(text[b_start + 1 : b_end - 1]))

    start = lo
    for clause in _CY_CLAUSE.finditer(flat, lo, hi):
        bind(start, clause.start())
        start = clause.start()
        rest = flat[clause.end() : hi]
        at, keyword = _clause_end(rest)
        pattern = rest[:at]
        where = ""
        tail = rest[at:]
        while keyword == "USING":  # a planner hint sits between the pattern and its WHERE
            skip, keyword = _clause_end(tail[len("USING") :])
            tail = tail[len("USING") + skip :]
        if keyword == "WHERE":
            tail = tail[len("WHERE") :]
            where = tail[: _clause_end(tail)[0]]
        for part in _split_top(pattern):
            # a top-level `x:Obj` in the WHERE is planned as a pattern label, so it
            # counts the same for the index the anchor seeks
            nodes = [
                (
                    n.group(1),
                    set(re.findall(r"[A-Za-z_][A-Za-z_0-9]*", n.group(2) or ""))
                    | (
                        {"Obj"}
                        if n.group(1)
                        and re.search(rf"(?:^|\bAND)\s*{re.escape(n.group(1))}:Obj\b", where.strip())
                        else set()
                    ),
                    n.group(3) or "",
                )
                for n in _CY_NODE.finditer(part)
            ]
            names = {v for v, _, _ in nodes if v} | set(_CY_REL.findall(part))
            if not nodes or names & bound:
                bound |= names
                continue
            bound |= names
            if any(
                ("Obj" in labels and _pinned(v, labels, props, where)) or labels & _ANCHOR_EXEMPT_LABELS
                for v, labels, props in nodes
            ):
                continue
            if not any(labels for _, labels, _ in nodes):
                kind = "starts from an unlabelled node"
            elif not any("Obj" in labels for _, labels, _ in nodes):
                kind = "anchors without :Obj"
            else:
                kind = "anchors on :Obj without an equality pin on collection_ts"
            problems.append(f"{kind}: {' '.join(part.split())[:120]}")
    # what the clauses after the last MATCH bind, for the subqueries among them
    bind(start, hi)


def anchor_problems(query: str) -> list[str]:
    """What breaks the anchor convention in one Cypher string.

    A coalesce run guard anywhere; a node matched by uid with no label; and a
    MATCH part none of whose variables an earlier clause bound (an anchor) with
    no node that both names :Obj and pins collection_ts by equality, unless the
    part names a run bookkeeping label. Each UNION branch is a scope of its own,
    a CALL subquery sees only the names it imports, and an EXISTS, COUNT or
    COLLECT subquery sees the names around it.
    """
    text = re.sub(r"//[^\n]*|/\*.*?\*/", "", query, flags=re.S)
    text = re.sub(r"'(?:[^'\\]|\\.)*'", "''", text)
    problems: list[str] = []
    if re.search(r"coalesce\(\s*[A-Za-z_0-9]+\.collection_ts\s*,", text):
        problems.append("pins the run with coalesce")
    for node in _CY_NODE.finditer(text):
        if not (node.group(2) or "").strip() and re.search(r"\buid\s*:", node.group(3) or ""):
            problems.append(f"matches a uid on an unlabelled node: {node.group(0)}")
    _scope(text, set(), problems)
    return problems


def _anchor_census() -> list[tuple[str, str, list[str]]]:
    root = _hst_root()
    out = []
    for py in sorted(root.rglob("*.py")):
        rel = py.relative_to(root).as_posix()
        for _line, text in _cypher_strings(py):
            problems = anchor_problems(text)
            if problems:
                out.append((rel, text, problems))
    return out


def _listed(rel: str, text: str, entries) -> tuple[str, str] | None:
    return next(((f, frag) for f, frag in entries if f == rel and frag in text), None)


def test_every_cypher_anchor_seeks_a_run_index():
    """Parse every Cypher string in hst and fail on an anchor that is
    unlabelled, lacks :Obj, does not pin collection_ts by equality, or pins
    with coalesce."""
    import hst.core.cycle as cyclemod

    assert _cypher_strings(pathlib.Path(inspect.getsourcefile(cyclemod))), "the AST scan found no Cypher"
    census = _anchor_census()
    used: set[tuple[str, str]] = set()
    offenders = []
    for rel, text, problems in census:
        key = _listed(rel, text, _ALL_RUNS)
        if key is not None:
            used.add(key)
            continue
        offenders.append(f"{rel}: {problems} in\n{text.strip()[:400]}")
    assert not offenders, "anchors that scan every retained run:\n\n" + "\n\n".join(offenders)
    stale = set(_ALL_RUNS) - used
    assert not stale, f"listed queries that no longer offend, delete them from the list: {sorted(stale)}"


# --- the nodes a query finds by property, not only the first anchor -----------------------
#
# A node found by the value of one of its properties (`(ip:IpAddress {ip: $ip})`,
# `(:Interface {uid: $in_if})` inside an EXISTS, a Device by uid in a pattern
# comprehension) is a copy per retained run unless the query pins it. A node
# reached from a pinned one through an edge is in the run, so it needs no pin
# of its own. The check reads every scope of the query, subqueries and pattern
# comprehensions too, which the anchor check above does not.

_CY_LOOKUP = re.compile(r"(?:^|,)\s*(?!collection_ts\b)[A-Za-z_]\w*\s*:\s*(?:\$|[A-Za-z_])")


def _top_level_pins(flat: str, lo: int, hi: int) -> tuple[set[str], set[str]]:
    """The variables a clause of `flat[lo:hi]` pins with a top-level
    `x.collection_ts = $p` conjunct of its WHERE, and those it leaves to an
    operator's site that no run has copied yet (`x:Meta OR ...`), a node every
    run shares."""
    pinned: set[str] = set()
    shared: set[str] = set()
    for clause in _CY_CLAUSE.finditer(flat, lo, hi):
        rest = flat[clause.end() : hi]
        at, keyword = _clause_end(rest)
        tail = rest[at:]
        while keyword == "USING":
            skip, keyword = _clause_end(tail[len("USING") :])
            tail = tail[len("USING") + skip :]
        if keyword != "WHERE":
            continue
        tail = tail[len("WHERE") :]
        for term in _conjuncts(tail[: _clause_end(tail)[0]]):
            if m := re.fullmatch(r"(\w+)\.collection_ts\s*(?:=|IN)\s*\$\w+", term):
                pinned.add(m.group(1))
            elif m := re.fullmatch(r"\(\s*(\w+):Meta\s+OR\s+\1\.collection_ts\s*=\s*\$\w+\s*\)", term):
                shared.add(m.group(1))
    return pinned, shared


def _comprehension_pin(flat: str, var: str, at: int) -> bool:
    """Whether the innermost `[...]` around `at` pins `var` in a WHERE of its own."""
    depth = 0
    for i in range(at - 1, -1, -1):
        if flat[i] == "]":
            depth += 1
        elif flat[i] == "[":
            if depth == 0:
                inner = flat[i : flat.find("]", at)]
                return re.search(rf"\b{var}\.collection_ts\s*=\s*\$\w+", inner) is not None
            depth -= 1
    return False


_CY_LINK = re.compile(r"\s*<?-+(?:\[[^\]]*\])?-*>?\s*")


def _chains(flat: str, lo: int, hi: int) -> list[list[tuple[str | None, set[str], str, int]]]:
    """The node patterns of `flat[lo:hi]` as (variable, labels, property map,
    position), grouped into the paths they are written as: nodes with nothing but
    a relationship between them. A path is in one run when any node of it is."""
    chains: list[list[tuple[str | None, set[str], str, int]]] = []
    last_end = -1
    for node in _CY_NODE.finditer(flat, lo, hi):
        entry = (
            node.group(1),
            set(re.findall(r"\w+", node.group(2) or "")),
            node.group(3) or "",
            node.start(),
        )
        if (
            chains
            and _CY_LINK.fullmatch(flat[last_end : node.start()])
            and flat[last_end : node.start()].strip()
        ):
            chains[-1].append(entry)
        else:
            chains.append([entry])
        last_end = node.end()
    return chains


def _join_scope(
    text: str, inherited: set[str], shared_in: set[str], problems: list[str], before: str = ""
) -> None:
    blocks = _blocks(text)
    masked = list(text)
    for start, end, _, _ in blocks:
        masked[start:end] = " " * (end - start)
    flat = "".join(masked)
    cuts = [(m.start(), m.end()) for m in re.finditer(r"\bUNION(?:\s+ALL)?\b", flat)]
    edges = [0] + [e for _, e in cuts], [s for s, _ in cuts] + [len(flat)]
    for lo, hi in zip(*edges, strict=True):
        chains = _chains(flat, lo, hi)
        pins, meta = _top_level_pins(flat, lo, hi)
        in_run = inherited | pins
        shared = shared_in | (meta - in_run)
        for chain in chains:
            for var, _, props, at in chain:
                if var and (re.search(r"\bcollection_ts\s*:", props) or _comprehension_pin(flat, var, at)):
                    in_run.add(var)
        grown = True
        while grown:
            grown = False
            for chain in chains:
                names = {v for v, _, _, _ in chain if v}
                if len(chain) > 1 and names & in_run and not names <= in_run:
                    in_run |= names
                    grown = True
        for chain in chains:
            names = {v for v, _, _, _ in chain if v}
            # a node an earlier clause bound is that clause's to pin, unless it is
            # a node every run shares
            seen = before + flat[lo : chain[0][3]]
            anchored = len(chain) > 1 and any(
                v in in_run or (v not in shared and re.search(rf"\b{v}\b", seen)) for v in names
            )
            for var, labels, props, at in chain:
                if not labels or labels & _ANCHOR_EXEMPT_LABELS or anchored:
                    continue
                if var in in_run or var in shared or re.search(r"\bcollection_ts\s*:", props):
                    continue
                if _CY_LOOKUP.search(props[1:-1]):
                    shown = " ".join(flat[at : flat.find(")", at) + 1].split())
                    problems.append(f"finds a node by property without a run pin: {shown}")
        for start, end, kind, imports in blocks:
            if lo <= start < hi:
                names = set(imports or ())
                _join_scope(
                    text[start + 1 : end - 1],
                    in_run if kind == "expr" else names & in_run,
                    shared if kind == "expr" else names & shared,
                    problems,
                    before + flat[lo:start],
                )


def join_problems(query: str) -> list[str]:
    """The nodes one Cypher string finds by a property value and leaves unpinned
    to the run, in any scope of the query."""
    text = re.sub(r"//[^\n]*|/\*.*?\*/", "", query, flags=re.S)
    text = re.sub(r"'(?:[^'\\]|\\.)*'", "''", text)
    problems: list[str] = []
    _join_scope(text, set(), set(), problems)
    return problems


# Queries that find a node by property in every retained run on purpose, by
# module and a fragment of the query text, with why. Each entry must still offend.
_JOINS_ALL_RUNS: dict[tuple[str, str], str] = {}


def test_every_node_found_by_property_is_pinned_to_the_run():
    census = []
    root = _hst_root()
    for py in sorted(root.rglob("*.py")):
        rel = py.relative_to(root).as_posix()
        for _line, text in _cypher_strings(py):
            if problems := join_problems(text):
                census.append((rel, text, problems))
    used: set[tuple[str, str]] = set()
    offenders = []
    for rel, text, problems in census:
        key = _listed(rel, text, _JOINS_ALL_RUNS)
        if key is not None:
            used.add(key)
            continue
        offenders.append(f"{rel}: {problems} in\n{text.strip()[:400]}")
    assert not offenders, "nodes found by property that read every retained run:\n\n" + "\n\n".join(offenders)
    stale = set(_JOINS_ALL_RUNS) - used
    assert not stale, f"listed queries that no longer offend, delete them from the list: {sorted(stale)}"


@pytest.mark.parametrize(
    ("query", "count"),
    [
        (
            "MATCH (d:Device:Obj {uid: $d, collection_ts: $snap}) "
            "WHERE NOT EXISTS { MATCH (i:Interface {uid: $i}) } RETURN d",
            1,
        ),
        (
            "MATCH (d:Device:Obj {uid: $d, collection_ts: $snap}) "
            "WHERE NOT EXISTS { MATCH (i:Interface {uid: $i}) WHERE i.collection_ts = $snap } RETURN d",
            0,
        ),
        (
            "MATCH (d:Device:Obj {uid: $d, collection_ts: $snap}) "
            "RETURN head([(x:Device {uid: $d})-[:ENFORCES]->(r) | x.name]) AS n",
            1,
        ),
        (
            "MATCH (d:Device:Obj {uid: $d, collection_ts: $snap}) "
            "RETURN head([(x:Device {uid: $d, collection_ts: $snap})-[:ENFORCES]->(r) | x.name]) AS n",
            0,
        ),
        ("MATCH (s:Obj {collection_ts: $snap}) MATCH (p:IpAddress {ip: s.peer_ip}) RETURN p", 1),
        (
            "MATCH (s:Obj {collection_ts: $snap})-[:ENDPOINT]->"
            "(p:IpAddress:Obj {collection_ts: $snap, ip: s.peer_ip}) RETURN p",
            0,
        ),
        ("MATCH (a:Obj {uid: $a, collection_ts: $snap})-[:ON]->(d:Device) RETURN d", 0),
        ("MATCH (c:CycleRun {uid: $uid}) RETURN c", 0),
        # a node only a site that no run has copied yet joins to is not in that site's run
        (
            "MATCH (s:Site:Obj) WHERE (s:Meta OR s.collection_ts = $snap) "
            "MATCH (s)<-[:LOCATED_IN]-(d:Device {uid: $d}) RETURN d",
            1,
        ),
        # a node a subquery's pattern joins to one the query has bound is in that one's run
        (
            "MATCH (d:Device:Obj {uid: $d, collection_ts: $snap}) CALL (d) { MATCH (d)-[:ON]-(i:Interface) "
            "WHERE NOT EXISTS { MATCH (i)-[:IN_VRF]->(:VrfInstance {uid: $vrf}) } RETURN i } RETURN i",
            0,
        ),
    ],
)
def test_the_join_guard_flags_a_node_found_by_property_anywhere_in_the_query(query, count):
    assert len(join_problems(query)) == count, join_problems(query)


def test_the_scan_reads_a_pin_a_helper_builds():
    """A run pin spliced in through a helper (explore.py `_pinned`, netobjects
    `_alive`) is read in the query text, not left as an unknown field."""
    import hst.app.routes.explore as explore

    texts = [text for _, text in _cypher_strings(pathlib.Path(inspect.getsourcefile(explore)))]
    assert any("MATCH (d:Device:Obj) WHERE d.collection_ts = $snap AND NOT d:Retired" in t for t in texts), (
        texts
    )
    uid_seek = (
        "CALL { MATCH (n:Obj {uid: $uid, collection_ts: $snap}) "
        "USING INDEX n:Obj(uid, collection_ts) RETURN n UNION"
    )
    assert any(uid_seek in t for t in texts), texts


@pytest.mark.parametrize(
    ("query", "kind"),
    [
        ("MATCH (d:Device {uid: $u}) WHERE coalesce(d.collection_ts, $snap) = $snap RETURN d", "coalesce"),
        ("MATCH (d:Device {uid: $u}) WHERE d.collection_ts = $snap RETURN d", "without :Obj"),
        ("MATCH (a {uid: $a}) RETURN a", "unlabelled node"),
        ("MATCH (n) WHERE n.collection_ts = $cts RETURN n", "unlabelled node"),
        ("MATCH (d:Device:Obj {uid: $u}) RETURN d", "without an equality pin"),
        # a pin inside a disjunction lets the planner use no index
        (
            "MATCH (n:Obj) WHERE n.collection_ts = $snap OR n.collection_ts IS NULL RETURN n",
            "without an equality pin",
        ),
        # the second branch of a union is a query of its own
        (
            "MATCH (a:Device:Obj {uid: $u, collection_ts: $snap}) RETURN a.uid AS u "
            "UNION MATCH (a:Device {uid: $u}) RETURN a.uid AS u",
            "without :Obj",
        ),
        # an EXISTS subquery that starts from a node of its own
        (
            "MATCH (d:Device:Obj {uid: $u, collection_ts: $snap}) "
            "WHERE EXISTS { MATCH (z:Zone {uid: $z}) } RETURN d",
            "without :Obj",
        ),
        # only a label that can be an operator :Meta node takes the Meta form
        (
            "MATCH (d:Device:Obj) WHERE (d:Meta OR d.collection_ts = $snap) RETURN d",
            "without an equality pin",
        ),
    ],
)
def test_the_anchor_parser_names_each_broken_form(query, kind):
    assert any(kind in p for p in anchor_problems(query)), anchor_problems(query)


@pytest.mark.parametrize(
    "query",
    [
        "MATCH (d:Device:Obj {uid: $u, collection_ts: $snap}) RETURN d",
        "MATCH (n:Obj {collection_ts: $snap}) WHERE n._scope = $s RETURN n",
        "MATCH (d:Device:Obj) WHERE d.uid IN $uids AND d.collection_ts = $snap RETURN d",
        "MATCH (s:Site:Obj) WHERE s.code IN $site AND (s:Meta OR s.collection_ts = $snap) RETURN s",
        "UNWIND $devs AS du MATCH (d:Device:Obj {uid: du, collection_ts: $snap})<-[o:ON]-(p:Port) RETURN p",
        "MATCH (c:CycleRun {uid: $uid}) RETURN c",
        "MATCH (a:Obj {uid: $a, collection_ts: $snap}) MATCH (a)-[:ON]->(d:Device) RETURN d",
        # each branch of a union inside CALL (d) imports d
        "MATCH (d:Device:Obj {uid: $u, collection_ts: $snap}) "
        "CALL (d) { MATCH (x:Zone)-[:OWNED_BY]->(d) RETURN x "
        "UNION MATCH (x:VrfInstance)-[:OWNED_BY]->(d) RETURN x } "
        "MATCH (x)-[:ON]->(y) RETURN y",
        "MATCH (d:Obj) USING INDEX d:Obj(uid, collection_ts) WHERE d.uid IN $uids AND d.collection_ts = $cts "
        "AND d:Device RETURN d",
    ],
)
def test_the_anchor_parser_accepts_the_indexed_forms(query):
    assert anchor_problems(query) == []


# --- one snapshot resolved per request --------------------------------------------------


class _PointerSession:
    """A graph session whose pointer read answers a different run every time,
    the way a real one does when a cycle publishes mid-request. Also records
    the uid of every meta read, which is how `run_status` names its run."""

    def __init__(self, runs: list[int]) -> None:
        self._runs = list(runs)
        self.uids: list[str] = []

    def run(self, query: str, **params: Any):
        rows: list[dict] = []
        if "CyclePointer" in query:
            rows = [{"current": self._runs.pop(0)}]
        else:
            self.uids.append(params["uid"])

        class _R:
            def data(self) -> list:
                return rows

        return _R()


def test_a_request_resolves_one_snapshot_for_graph_and_side_store(tmp_path):
    """One request, one resolution: a run published after the snapshot was
    resolved cannot reach any reader of that answer.

    The pointer here answers 1000 the first time it is read and 2000 after, so
    a reader resolving it on its own would bind the newer run. The graph pin,
    the side-store bound and the run the answer carries all name 1000, and the
    pointer is read exactly once.
    """

    class _Settings:
        sidestore_dir = tmp_path
        manifests_dir = None

    from hst.core import cycle as cyclemod
    from hst.core import ribsource
    from hst.core import snapshot as snapshotmod

    session = _PointerSession([1000, 2000])
    snapshot = snapshotmod.resolve(session, _Settings())

    pinned = path.pinned(session, snapshot)
    rib = ribsource.for_snapshot(snapshot)
    cyclemod.run_status(session, snapshot)

    assert snapshot.cts == 1000
    assert pinned.cts == 1000
    assert rib._as_of_ms == 1000
    assert session.uids == ["cycle:1000"]
    assert cyclemod.current_ts_or_none(session) == 2000


def test_the_side_store_reads_the_snapshots_manifest(monkeypatch, tmp_path):
    """The RIB evidence is decided from the manifest the snapshot already read."""
    from hst.core import manifest as manifestmod
    from hst.core import ribsource
    from hst.core import snapshot as snapshotmod

    class _Record:
        snapshot_key = 1000
        parent = None
        devices: list = []
        files: list = []

    class _Settings:
        manifests_dir = tmp_path / "manifests"
        hst_data_dir = tmp_path
        sidestore_dir = tmp_path / "sidestore"

    reads: list[int] = []

    def counting_read(settings: Any, key: int) -> Any:
        reads.append(key)
        return _Record()

    monkeypatch.setattr(manifestmod, "read", counting_read)

    snapshot = snapshotmod.resolve(_PointerSession([1000]), _Settings())
    rib = ribsource.for_snapshot(snapshot)

    assert reads == [1000]
    assert rib.approximate is False
    assert snapshot.approximate is False


def test_an_unpinned_snapshot_reads_no_manifest_and_is_approximate(tmp_path):
    """No pointer yet: the snapshot names no run, so there is no manifest to
    read and every reader works from file age."""
    from hst.core import ribsource
    from hst.core import snapshot as snapshotmod

    class _Settings:
        manifests_dir = tmp_path / "manifests"
        hst_data_dir = tmp_path
        sidestore_dir = tmp_path / "sidestore"

    snapshot = snapshotmod.resolve(_PointerSession([]), _Settings())
    assert snapshot.cts is None
    assert snapshot.manifest is None
    assert snapshot.approximate is True
    assert snapshot.snapshot_id is None
    assert snapshot.completeness() == {}
    assert ribsource.for_snapshot(snapshot).approximate is True


def test_the_snapshot_exposes_per_device_completeness_from_the_manifest(monkeypatch, tmp_path):
    """What each device's collection produced travels with the snapshot.

    A reader that has the snapshot can say which devices the run collected,
    which were carried, and what each section and side-store table of a
    device produced, without opening the manifest itself.
    """
    from hst.core import manifest as manifestmod
    from hst.core import snapshot as snapshotmod
    from hst.core.model import SectionOutcome, TableOutcome

    entries = [
        manifestmod.DeviceEntry(
            source="edge",
            host="r1",
            outcome="partial",
            effective_run="1700000000000-aaaaaaaa",
            sections={"arp": SectionOutcome(status="failed", detail="timeout")},
            tables={"rib": TableOutcome(status="complete", path="rib/edge/r1/x.parquet")},
        ),
        manifestmod.DeviceEntry(source="edge", host="r2", outcome="carried", carried=True),
    ]

    class _Record:
        snapshot_key = 1000
        parent = None
        devices = entries
        files: list = []

    class _Settings:
        manifests_dir = tmp_path / "manifests"
        hst_data_dir = tmp_path
        sidestore_dir = tmp_path / "sidestore"

    monkeypatch.setattr(manifestmod, "read", lambda settings, key: _Record())

    snapshot = snapshotmod.resolve(_PointerSession([1000]), _Settings())
    completeness = snapshot.completeness()
    assert sorted(completeness) == ["edge/r1", "edge/r2"]

    r1 = completeness["edge/r1"]
    assert r1.outcome == "partial"
    assert r1.effective_run == "1700000000000-aaaaaaaa"
    assert r1.carried is False
    assert r1.sections == {"arp": "failed"}
    assert r1.tables == {"rib": "complete"}

    r2 = snapshot.device_completeness("edge", "r2")
    assert r2 is not None and r2.outcome == "carried" and r2.carried is True
    assert r2.sections == {} and r2.tables == {}
    assert snapshot.device_completeness("edge", "r3") is None


# --- RibSource as_of bound --------------------------------------------------------------


def _rib_row(prefix: str, next_hop: str) -> dict:
    from hst.core import ipenc

    lo, hi, prefixlen, af = ipenc.prefix_bounds(prefix)
    return {
        "device_uid": "dev:r1",
        "vrf": "default",
        "prefix": prefix,
        "next_hop": next_hop,
        "interface": "eth0",
        "protocol": "static",
        "metric": 1,
        "af": af,
        "prefixlen": prefixlen,
        "lo": lo,
        "hi": hi,
    }


@pytest.fixture
def bounded_store(tmp_path):
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    from hst.core import sidestore

    sidestore.write_table(
        tmp_path, "rib", "vyos", "", "1700000000000-aa11bb22", [_rib_row("0.0.0.0/0", "10.0.0.1")], 1000
    )
    sidestore.write_table(
        tmp_path, "rib", "vyos", "", "1700000001000-cc33dd44", [_rib_row("0.0.0.0/0", "10.0.0.2")], 2000
    )
    return tmp_path


def test_unbounded_lookup_reads_the_newest_run(bounded_store):
    from hst.core.ribsource import RibSource

    out = RibSource(bounded_store).lpm("dev:r1", None, "8.8.8.8", legacy_vrf="default")
    assert {r["next_hop"] for r in out} == {"10.0.0.2"}


def test_as_of_bound_selects_the_newest_run_at_or_before_it(bounded_store):
    from hst.core.ribsource import RibSource

    out = RibSource(bounded_store, as_of_ms=1500).lpm("dev:r1", None, "8.8.8.8", legacy_vrf="default")
    assert {r["next_hop"] for r in out} == {"10.0.0.1"}


def test_as_of_bound_before_every_run_returns_nothing(bounded_store):
    from hst.core.ribsource import RibSource

    assert RibSource(bounded_store, as_of_ms=500).lpm("dev:r1", None, "8.8.8.8", legacy_vrf="default") == []


# --- snapshot diff ----------------------------------------------------------------------


class _DiffTx:
    def __init__(self, data: dict[str, dict[str, list[dict]]]) -> None:
        self._data = data

    def run(self, query: str, **params: Any):
        kind = "rels" if "type(r)" in query else "nodes"
        rows = self._data[kind].get(params["snap"], [])

        class _Result:
            def data(self) -> list:
                return rows

        return _Result()


class _DiffSession:
    def __init__(self, data: dict[str, dict[str, list[dict]]]) -> None:
        self._data = data

    def execute_read(self, work, /) -> Any:
        return work(_DiffTx(self._data))


def _node(uid: str, label: str, name: str, **props: Any) -> dict:
    return {
        "uid": uid,
        "labels": ["Obj", label, "Phys"],
        "props": {"name": name, "_last_seen": 1, **props},
    }


def test_diff_reports_added_removed_and_changed_and_ignores_bookkeeping():
    data = {
        "nodes": {
            "100": [
                _node("dev:a", "Device", "a", role="router"),
                _node("dev:b", "Device", "b"),
            ],
            "200": [
                # _last_seen differs run to run and must not count as a change
                {
                    **_node("dev:a", "Device", "a", role="firewall"),
                    "props": {"name": "a", "role": "firewall", "_last_seen": 2},
                },
                _node("dev:c", "Device", "c"),
            ],
        },
        "rels": {
            "100": [{"t": "ON", "start": "if:x", "end": "dev:a", "props": {"_last_seen": 1}}],
            "200": [{"t": "ON", "start": "if:y", "end": "dev:a", "props": {"_last_seen": 2}}],
        },
    }
    out = diff_snapshots(_DiffSession(data), "100", "200")
    assert out["counts"]["nodes"] == {"added": 1, "removed": 1, "changed": 1}
    assert out["nodes"]["added"][0]["uid"] == "dev:c"
    assert out["nodes"]["removed"][0]["uid"] == "dev:b"
    assert out["nodes"]["changed"][0] == {
        "uid": "dev:a",
        "label": "Device",
        "name": "a",
        "changes": {"role": ["router", "firewall"]},
    }
    assert out["counts"]["rels"] == {"added": 1, "removed": 1, "changed": 0}
    assert not out["truncated"]


def test_the_diff_lists_a_removal_and_reads_a_carried_object_as_unchanged():
    """The two absences a device-scoped carry produces, seen from the diff.

    `dev:a` was collected in both runs and stopped reporting its interface, so
    the interface is not in the second run and the diff lists it as removed.
    `dev:b` belongs to a device that failed, so the second run holds it carried
    and stamped with why and when it was last seen; that stamp is not a
    change to the object."""
    carried = {
        **_node("dev:b", "Device", "b"),
        "props": {"name": "b", "_last_seen": 2, "carried_reason": "failed", "last_seen_ts": 1},
    }
    data = {
        "nodes": {
            "100": [_node("dev:a", "Device", "a"), _node("dev:b", "Device", "b")],
            "200": [_node("dev:a", "Device", "a"), carried],
        },
        "rels": {
            "100": [{"t": "ON", "start": "if:a1", "end": "dev:a", "props": {"_last_seen": 1}}],
            "200": [],
        },
    }
    out = diff_snapshots(_DiffSession(data), "100", "200")

    assert out["counts"]["nodes"] == {"added": 0, "removed": 0, "changed": 0}
    assert out["counts"]["rels"] == {"added": 0, "removed": 1, "changed": 0}
    assert out["rels"]["removed"][0]["start"] == "if:a1"


def test_diff_reports_the_assertion_conflicts_standing_at_each_snapshot():
    """The diff reports the conflicts standing at each side."""
    # The source rows are named for the fabric and the fleet, not for the
    # collectors that read them: authority is the collector type in the head of
    # each assertion, and the row name carries none of it.
    contested = {
        **_node("dev:a", "Device", "a", role="router"),
        "props": {
            "name": "a",
            "role": "router",
            "platform": "nxos",
            "_sources": ["fab1", "dc1-leaves"],
            "_assert.role": ['apic/fab1="leaf"', 'nxos/dc1-leaves="router"'],
            "_assert.platform": ['apic/fab1="nxos"', 'nxos/dc1-leaves="nxos"'],
        },
    }
    data = {
        "nodes": {
            "100": [_node("dev:a", "Device", "a", role="router", platform="nxos")],
            "200": [contested],
        },
        "rels": {"100": [], "200": []},
    }
    out = diff_snapshots(_DiffSession(data), "100", "200")

    assert out["conflicts"]["counts"] == {"a": 0, "b": 1}
    assert out["conflicts"]["a"] == []
    assert out["conflicts"]["b"] == [
        {
            "uid": "dev:a",
            "label": "Device",
            "name": "a",
            "field": "role",
            "assertions": [
                {"collector": "apic", "source": "fab1", "value": "leaf"},
                {"collector": "nxos", "source": "dc1-leaves", "value": "router"},
            ],
            "effective": "router",
        }
    ]
    # a field both sources asserted the same value for is not a conflict, and
    # the assertion properties never mark the node changed
    assert out["counts"]["nodes"]["changed"] == 0
    assert not out["truncated"]


def test_diff_of_identical_snapshots_is_empty():
    rows = [_node("dev:a", "Device", "a")]
    data = {"nodes": {"100": rows, "200": rows}, "rels": {"100": [], "200": []}}
    out = diff_snapshots(_DiffSession(data), "100", "200")
    assert out["counts"] == {
        "nodes": {"added": 0, "removed": 0, "changed": 0},
        "rels": {"added": 0, "removed": 0, "changed": 0},
    }


# --- run status on pinned answers -----------------------------------------------------------------


class _RunStatusSession:
    """The autocommit `run` over a scripted CycleRun row, as `current_ts` uses."""

    def __init__(self, rows):
        self._rows = rows
        self.queries = []

    def run(self, query, **params):
        self.queries.append((query, params))
        rows = self._rows

        class _R:
            def data(_self):
                return rows

        return _R()


def test_run_status_reads_the_cycle_meta_node():
    from hst.core import cycle as cyclemod

    session = _RunStatusSession(
        [
            {
                "cts": 2000,
                "created": "2026-09-01T00:00:00+00:00",
                "degraded": True,
                "sources_carried": ["vyos-gw", "apic-1"],
                "sources_failed": None,
                "sources_partial": ["nxos-fleet"],
                "sources_cancelled": ["iosxe-core"],
            }
        ]
    )
    status = cyclemod.run_status(session, _snap(2000))
    assert status == {
        "snapshot": "2000",
        "created": "2026-09-01T00:00:00+00:00",
        "degraded": True,
        "sources_carried": ["apic-1", "vyos-gw"],
        "sources_failed": [],
        "sources_partial": ["nxos-fleet"],
        "sources_cancelled": ["iosxe-core"],
        "freshness": {"devices": [], "truncated": False, "approximate": True},
    }
    assert session.queries[0][1] == {"uid": "cycle:2000"}


def test_run_status_is_none_without_a_pin_or_a_meta_node():
    from hst.core import cycle as cyclemod

    assert cyclemod.run_status(_RunStatusSession([]), None) is None
    assert cyclemod.run_status(_RunStatusSession([]), _snap(None)) is None
    assert cyclemod.run_status(_RunStatusSession([]), _snap(2000)) is None


class _PropsSession:
    """Captures what `write_cycle_meta` writes, with no database behind it."""

    def __init__(self) -> None:
        self.props: dict = {}

    def run(self, _query, **params):
        self.props = params.get("props", {})

        class _Result:
            def single(self_inner):
                return None

            def consume(self_inner):
                return None

            def data(self_inner):
                return []

            def __iter__(self_inner):
                return iter(())

        return _Result()

    def execute_write(self, fn, *args, **kwargs):
        return fn(self, *args, **kwargs)


def test_a_snapshot_names_the_sources_an_operator_stopped():
    """A cancelled source has a list of its own on the snapshot."""
    from hst.core import cycle as cyclemod

    session = _PropsSession()
    cyclemod.write_cycle_meta(
        session,
        3000,
        statuses={
            "vyos-gw": "fresh",
            "apic-1": "carried",
            "nxos-fleet": "partial",
            "iosxe-core": "cancelled",
            "unifi": "failed",
        },
        carried_from=2000,
        nodes=1,
        rels=0,
        degraded=True,
    )
    assert session.props["sources_cancelled"] == ["iosxe-core"]
    # and it is in no other list, so nothing double-counts it
    assert session.props["sources_carried"] == ["apic-1"]
    assert session.props["sources_fresh"] == ["vyos-gw"]
    assert session.props["sources_partial"] == ["nxos-fleet"]
    assert session.props["sources_failed"] == ["unifi"]
