"""Query results in the UI table shape, and the guard on operator-supplied Cypher."""

from __future__ import annotations

import difflib
import json
import logging
import re
import unicodedata
from collections.abc import Iterable, Iterator
from typing import Any

from neo4j import unit_of_work

from hst.core import Settings
from hst.core import db as dbmod
from hst.core import snapshot as snapshotmod
from hst.core.labels import LABELS, RELS, RESERVED_LABELS

log = logging.getLogger(__name__)

MAX_ROWS = 500
NEO4J_TIMEOUT_S = 15.0
# The size limit on the text of one query, on POST /api/cypher and on query_cypher
# on MCP and in the agent.
MAX_QUERY_BYTES = 64 * 1024
# MAX_RESULT_BYTES bounds the cumulative serialized size of the result as rows
# stream in.
MAX_RESULT_BYTES = 4 * 1024 * 1024

# Procedures an operator may call.
ALLOWED_PROCEDURES = frozenset(
    {
        "db.index.fulltext.querynodes",  # queries.py `search`
        "db.index.fulltext.queryrelationships",
        "db.labels",
        "db.relationshiptypes",
        "db.propertykeys",
        "db.schema.visualization",
        "db.schema.nodetyperepresentation",
        "db.schema.reltyperepresentation",
    }
)

# Neo4j replaces unicode escapes anywhere in the query text before it lexes the
# query, for the pre-parser and both parsers. An escape is a backslash, one or
# more `u` and 4 hex digits. A backslash after an odd number of backslashes
# starts no escape. The pattern matches a backslash pair first, and
# `_decode_unicode_escapes` keeps the pair. Neo4j reads `\u0053HOW TRANSACTIONS`
# as SHOW TRANSACTIONS. Every text check runs on the decoded text.
_UNICODE_ESCAPE = re.compile(r"\\\\|\\u+([0-9a-fA-F]{4})")


def _decode_unicode_escapes(query: str) -> str:
    """`query` with each unicode escape replaced by its character, as Neo4j reads it."""

    def _replace(match: re.Match[str]) -> str:
        digits = match.group(1)
        return match.group() if digits is None else chr(int(digits, 16))

    return _UNICODE_ESCAPE.sub(_replace, query)


# The tokenizer runs once, ahead of every other check. The named alternatives
# below are tried in order, and the first match wins. A line comment ends at a line feed or a carriage
# return, the two characters that end it in the Neo4j lexers. A number is a
# hexadecimal (`0x1F`), octal (`0o17`), decimal (`.5`, `1.5e-3`) or integer
# (`1_000`, `1e5`) literal of Cypher 5. A word starts with a `\w` character
# that is no decimal digit.
_TOKEN = re.compile(
    r"(?P<string>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
    r"|(?P<backtick>`[^`]*`)"
    r"|(?P<block_comment>/\*.*?\*/)"
    r"|(?P<line_comment>//[^\r\n]*)"
    r"|(?P<word>[^\W\d]\w*)"
    r"|(?P<number>0[xX][\dA-Fa-f_]+|0[oO][0-7_]+"
    r"|(?:\d[\d_]*)?\.\d[\d_]*(?:[eE][+-]?\d[\d_]*)?|\d[\d_]*(?:[eE][+-]?\d[\d_]*)?)"
    r"|(?P<other>.)",
    re.DOTALL,
)
_WORD_CHAR = re.compile(r"\w")


def _tokenize(query: str, literal: str = " ") -> tuple[str, list[str]]:
    """Split `query` into code text and the string literals it contains.

    Code text is `query` with every string literal replaced by `literal` and
    every block comment and line comment replaced by one space. A number
    that a letter, a digit or `_` follows gets one space after it. In
    `LIMIT 1LOAD CSV` and `LIMIT 0x1FLOAD CSV` the code text holds
    `LIMIT 1 LOAD CSV` and `LIMIT 0x1F LOAD CSV`. In a word, each character
    that is no identifier character (`²`, `½`) is a space, and the word is
    tokenized again. A backtick-quoted identifier and every other character
    stay in place.

    The second value holds the string literals with their quotes, in order.
    `_URL` is checked against the string literals.
    """
    code_parts: list[str] = []
    strings: list[str] = []
    for match in _TOKEN.finditer(query):
        if match.lastgroup == "string":
            strings.append(match.group())
            code_parts.append(literal)
        elif match.lastgroup in ("block_comment", "line_comment"):
            code_parts.append(" ")
        elif match.lastgroup == "number" and _WORD_CHAR.match(query, match.end()):
            code_parts.append(match.group() + " ")
        elif match.lastgroup == "word" and not match.group().isidentifier():
            name = "".join(c if ("_" + c).isidentifier() else " " for c in match.group())
            code_parts.append(_tokenize(name)[0] if name != match.group() else match.group())
        else:
            code_parts.append(match.group())
    return "".join(code_parts), strings


# The character class includes the backtick for escaped identifiers such as ``CALL `dbms`.components()``.
# The lookahead matches a backtick directly after CALL, as in ``CALL`db`.checkpoint()``.
_CALL = re.compile(r"\bCALL(?:\s+|(?=`))([A-Za-z_`][\w.`]*)", re.IGNORECASE)
_LOAD_CSV = re.compile(r"\bLOAD\s+CSV\b", re.IGNORECASE)
# SHOW and TERMINATE open Neo4j administration commands (SHOW TRANSACTIONS,
# TERMINATE TRANSACTIONS, SHOW USERS). A query whose first clause is either
# keyword is rejected. Cypher accepts a prefix ahead of that clause, and `_admin_command`
# skips it in two steps. `_PREPARSER_PREFIX` skips pre-parser options
# (`CYPHER 5`, `CYPHER runtime=slotted`), `EXPLAIN` and `PROFILE`. The Neo4j
# pre-parser lexes a version number as its own token and needs no whitespace
# after it. `CYPHER 5SHOW` is version 5 followed by SHOW. The version
# alternative of the pattern ends without whitespace. The pattern has nothing
# after the repeated group, and the first greedy match succeeds without
# backtracking. `_use_clause_ends` then skips one USE clause in every form of
# the Cypher 5 grammar rule `USE GRAPH? graphReference`.
_PREPARSER_PREFIX = re.compile(
    r"\s*(?:(?:CYPHER|EXPLAIN|PROFILE|\w+\s*=\s*[\w.]+)\s+|\d[\d.]*\s*)*",
    re.IGNORECASE,
)
_USE_KEYWORD = re.compile(r"USE\b", re.IGNORECASE)
_GRAPH_KEYWORD = re.compile(r"\s*GRAPH\b", re.IGNORECASE)
# One name of a graph reference. A backtick name may hold doubled backticks. An
# unescaped name runs to the next whitespace, dot, parenthesis or backtick. The
# scan runs on text with unicode escapes decoded. An escaped space (`\u0020`)
# ends a name, as it does in Neo4j.
_NAME = r"(?:`(?:[^`]|``)*`|[^\s.()`]+)"
_FIRST_NAME = re.compile(r"\s*" + _NAME)
_NEXT_NAME = re.compile(r"\s*\.\s*" + _NAME)
_OPEN_PAREN = re.compile(r"\s*\(")
_PAREN = re.compile(r"`[^`]*`|[()]")
_ADMIN_KEYWORD = re.compile(r"\s*(SHOW|TERMINATE)\b", re.IGNORECASE)
# The scan for a USE clause in any position. The alternatives ahead of `word`
# consume a backtick name, a parameter, a number with its dot, and a property
# key or a label with its dot or colon.
_USE_SCAN = re.compile(r"`[^`]*`|\$\w+|\d+\.|[.:]\s*[^\W\d]\w*|(?P<word>[^\W\d]\w*)")
_GRAPH_REFERENCE = re.compile(r"\s*(?:[^\W\d]|`|\()")


def _paren_group_end(code: str, pos: int) -> int | None:
    """The end of the parenthesis group whose `(` ends just before `pos`.

    Parentheses nest to any depth. A parenthesis inside a backtick name does
    not count. The result is None when the group does not close.
    """
    depth = 1
    for token in _PAREN.finditer(code, pos):
        if token.group() == "(":
            depth += 1
        elif token.group() == ")":
            depth -= 1
            if depth == 0:
                return token.end()
    return None


def _graph_reference_end(code: str, pos: int) -> int | None:
    """The end of the graph reference that starts at `pos`, or None.

    A graph reference is a graph reference in parentheses, a function call such
    as `graph.byName(...)`, or a dotted name such as `neo4j` or `` `a`.`b` ``.
    """
    opening = _OPEN_PAREN.match(code, pos)
    if opening:
        return _paren_group_end(code, opening.end())
    name = _FIRST_NAME.match(code, pos)
    if not name:
        return None
    end = name.end()
    while dotted := _NEXT_NAME.match(code, end):
        end = dotted.end()
    arguments = _OPEN_PAREN.match(code, end)
    if arguments:
        return _paren_group_end(code, arguments.end())
    return end


def _use_clause_ends(code: str, pos: int) -> list[int]:
    """The start of the first clause for each reading of the code at `pos`.

    Without a USE clause at `pos` the result is `[pos]`. `USE graph SHOW ...`
    has 2 readings, with GRAPH as the keyword or as the database name. A USE
    clause followed by the word GRAPH returns both ends.
    """
    use = _USE_KEYWORD.match(code, pos)
    if not use:
        return [pos]
    starts = [use.end()]
    graph = _GRAPH_KEYWORD.match(code, use.end())
    if graph:
        starts.append(graph.end())
    return [end for start in starts if (end := _graph_reference_end(code, start)) is not None]


def _admin_command(code: str) -> str | None:
    """SHOW or TERMINATE when either keyword opens the first clause of `code`, else None."""
    prefix = _PREPARSER_PREFIX.match(code)
    start = prefix.end() if prefix else 0
    for clause in _use_clause_ends(code, start):
        keyword = _ADMIN_KEYWORD.match(code, clause)
        if keyword:
            return keyword.group(1).upper()
    return None


def _use_clause(code: str) -> bool:
    """Whether `code` holds the word USE ahead of a name, a backtick name or a
    parenthesis, the 3 starts of a graph reference."""
    return any(
        (match.group("word") or "").upper() == "USE" and _GRAPH_REFERENCE.match(code, match.end())
        for match in _USE_SCAN.finditer(code)
    )


_URL = re.compile(r"""['"]\s*(?:file|https?|ftp|jar)\s*:""", re.IGNORECASE)
# A reference to the extension namespaces apoc, gds, dbms, genai and vector is
# rejected, in call position or inline, with or without backtick escaping. The
# optional backtick between name and dot matches the `` `apoc`.`load` `` spelling.
_LIBRARY_NAMESPACE = re.compile(r"\b(?:apoc|gds|dbms|genai|vector)`?\s*\.", re.IGNORECASE)
_NAMESPACES = "apoc, gds, dbms, genai and vector"

# The identifier check requires that every `:Label` and `[:REL_TYPE]` token in
# the query text is a label or a relationship type of core.labels. The check
# matches text patterns. It does not validate property names or relationship
# direction.
_STRING_LITERAL = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"", re.DOTALL)
_BRACKETED = re.compile(r"\[([^\[\]]*)\]")
_COLON_TOKEN = re.compile(r":\s*([A-Za-z_][A-Za-z0-9_]*)")
# The type of a relationship pattern follows the optional variable name, as in
# `[r:REL_TYPE ...]` or `[:REL_TYPE]`. The pattern matches at the start of the
# bracket only.
_REL_HEAD = re.compile(
    r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s*([A-Za-z_][A-Za-z0-9_]*)"
    r"|^\s*:\s*([A-Za-z_][A-Za-z0-9_]*)"
)
_KNOWN_LABELS = LABELS.keys() | RESERVED_LABELS


# A `{` opens a subquery or an existential block after CALL, EXISTS, COUNT or
# COLLECT, or when its content starts with a clause. Each other `{` opens a map
# literal. `_blank_map_keys` blanks the keys of a map only. The patterns inside
# a block keep their labels.
_BLOCK_BEFORE = re.compile(r"\b(?:CALL|EXISTS|COUNT|COLLECT)$", re.IGNORECASE)
# A clause keyword ahead of a colon is the first key of a map.
_BLOCK_AFTER = re.compile(
    r"\s*(?:MATCH|OPTIONAL|WITH|UNWIND|RETURN|CALL|WHERE|USE|UNION|CREATE|MERGE|FOREACH|FINISH)\b(?!\s*:)",
    re.IGNORECASE,
)
_MAP_KEY = re.compile(r"\s*(?:[A-Za-z_][A-Za-z0-9_]*|`[^`]*`)\s*:")


def _opens_block(text: str, i: int) -> bool:
    """Whether the `{` at `i` opens a subquery or an existential block."""
    end = i
    while end and text[end - 1].isspace():
        end -= 1
    # 8 characters hold the longest keyword and the character ahead of it.
    return bool(_BLOCK_BEFORE.search(text[max(0, end - 8) : end]) or _BLOCK_AFTER.match(text, i + 1))


def _blank_map_keys(text: str) -> str:
    """`text` with the colon after each key of a map literal blanked.

    In `{rel: type(r), uid: x.uid}` or `(n:Device {hostname: x})` the colons
    separate keys from values, and a value that is a function or a variable
    (`type`, `x`) is no label for `_COLON_TOKEN`. A key starts a map or follows
    a comma at the nesting level of the map.
    """
    out = list(text)
    maps: list[bool] = []

    def blank_key(at: int) -> None:
        found = _MAP_KEY.match(text, at)
        if found:
            out[found.end() - 1] = " "

    for i, ch in enumerate(text):
        if ch == "{":
            is_map = not _opens_block(text, i)
            maps.append(is_map)
            if is_map:
                blank_key(i + 1)
        elif ch == "}":
            if maps:
                maps.pop()
        elif ch == "," and maps and maps[-1]:
            blank_key(i + 1)
    return "".join(out)


def _identifier_tokens(query: str) -> tuple[set[str], set[str]]:
    """The `:Label` tokens and the relationship-type tokens of the query text.

    String literals are blanked first. A colon inside a string literal (a
    hostname, a routing-domain name) is no label reference. The type of a
    bracketed relationship pattern (`[r:REL_TYPE ...]`, `[:REL_TYPE]`) goes to
    the relationship types. Every other `:Word` token is a label.
    """
    text = _blank_map_keys(_STRING_LITERAL.sub(lambda m: " " * len(m.group(0)), query))
    rel_types: set[str] = set()

    def _take_rel_type(match: re.Match[str]) -> str:
        content = match.group(1)
        found = _REL_HEAD.match(content)
        if found:
            rel_types.add(found.group(1) or found.group(2))
        return "[" + " " * len(content) + "]"

    label_text = _BRACKETED.sub(_take_rel_type, text)
    labels = {tok.group(1) for tok in _COLON_TOKEN.finditer(label_text)}
    return labels, rel_types


class QueryRejected(ValueError):
    """The query asked for something read-only mode does not prevent."""


class ResultTooLarge(ValueError):
    """The result set exceeded MAX_RESULT_BYTES before it reached the row cap."""


def audit_outcome(exc: BaseException) -> str:
    """The `cypher_events.outcome` token for a call that ended in this exception."""
    if isinstance(exc, QueryRejected):
        return "rejected"
    if isinstance(exc, ResultTooLarge):
        return "result_too_large"
    return "error"


def result_size(table: dict[str, Any]) -> tuple[int, int]:
    """Rows returned, and the serialized size of what the caller receives."""
    return len(table.get("data", ())), len(json.dumps(table, default=str).encode())


def _plain_space(code: str) -> str:
    """`code` with every separator, format and control character as a space.

    The regex whitespace class does not match U+180E or other format characters, and the
    openCypher grammar counts some of them as whitespace. Tab and newline
    stay as they are."""
    return "".join(
        " " if c not in "\t\n\r" and unicodedata.category(c) in ("Zs", "Zl", "Zp", "Cf", "Cc") else c
        for c in code
    )


def check_readonly(query: str) -> None:
    """Reject read-mode primitives that reach outside the graph.

    `LOAD CSV WITH HEADERS FROM 'http://host/a.csv' AS r RETURN r` is a legal read
    query that execute_read runs.

    Unicode escapes (`\\u0053`) are decoded first, as Neo4j decodes them
    before it lexes the query. Every check runs on the decoded text.

    A query whose first clause is `SHOW` or `TERMINATE` is an administration
    command and is rejected. Pre-parser options, `EXPLAIN`, `PROFILE` and a
    `USE` clause ahead of that clause do not change the verdict. A version
    number can run into the next word, as in `CYPHER 5SHOW`. The USE clause
    can take the GRAPH keyword and a name, a function call or a parenthesized
    reference, with parentheses nested to any depth.

    A `USE` clause is rejected at the start of the query, of a UNION part and
    of a subquery.

    The decoded query is tokenized once, left to right, into string literals,
    backtick identifiers, block comments, line comments, words, numbers and
    other characters (see `_tokenize`). A keyword directly after a number,
    as in `LIMIT 1LOAD CSV`, is a keyword in the code text. A `/*` or `//`
    inside a string literal starts no comment. The URL scheme check runs on
    the string literals. `LOAD CSV`, `CALL`, the library-namespace check and
    the identifier check run on the code text.

    The function also rejects a `:Label` or `[:REL_TYPE]` token that is not
    registered in core.labels (LABELS, RELS). This check validates identifier
    names only.
    """
    code, strings = _tokenize(_decode_unicode_escapes(query))
    code = _plain_space(code)
    command = _admin_command(code)
    if command:
        raise QueryRejected(f"{command} commands are not permitted")
    if _use_clause(code):
        raise QueryRejected("USE clauses are not permitted")
    if _LOAD_CSV.search(code):
        raise QueryRejected("LOAD CSV is not permitted")
    if any(_URL.search(literal) for literal in strings):
        raise QueryRejected(URL_LITERAL_REFUSAL)
    for name in _CALL.findall(code):
        if name.lower() not in ALLOWED_PROCEDURES:
            raise QueryRejected(
                f"procedure {name!r} is not permitted; allowed: {', '.join(sorted(ALLOWED_PROCEDURES))}"
            )
    if _LIBRARY_NAMESPACE.search(code):
        # The guard assumes a Neo4j with at most the stock apoc and gds extensions.
        raise QueryRejected(f"functions in the {_NAMESPACES} namespaces are not permitted")
    labels, rel_types = _identifier_tokens(code)
    unknown_labels = sorted(labels - _KNOWN_LABELS)
    unknown_rels = sorted(rel_types - RELS)
    if unknown_labels or unknown_rels:
        raise QueryRejected(_unknown_identifier_message(unknown_labels, unknown_rels))


# A string literal that starts with a URL scheme is refused.
URL_LITERAL_REFUSAL = (
    "file:, http:, https:, ftp: and jar: URLs are not permitted in a string literal. "
    "Pass the value as a parameter, for example WHERE n.url = $url with params "
    '{"url": "https://portal.example.com"}, or match a part of it, for example '
    "WHERE n.url CONTAINS 'portal.example.com'"
)

# The graph holds a domain as a property. The refusal of an unknown label that
# matches `_NAME_GUESS` ends with `NAME_PROPERTIES_HINT`.
_NAME_GUESS = re.compile(r"domain|fqdn|url|dns|host", re.IGNORECASE)
NAME_PROPERTIES_HINT = (
    "A domain or a host name is a property, not a label: ZpaAppSegment.domains (a list), "
    "NetObject.values where NetObject.kind = 'fqdn', Device.hostname and Device.hostname_fqdn, "
    "and DnsRecord.fqdn. The graph holds no URL nodes; match the host part of a URL against these"
)


def _unknown_identifier_message(labels: list[str], rel_types: list[str]) -> str:
    """The refusal of an unregistered identifier, with the registered names
    nearest to each one."""
    parts = []
    for name, known in [(n, _KNOWN_LABELS) for n in labels] + [(r, RELS) for r in rel_types]:
        near = difflib.get_close_matches(name, sorted(known), n=3, cutoff=0.6)
        parts.append(f"{name} (did you mean {', '.join(near)}?)" if near else name)
    message = f"unknown identifier: {', '.join(parts)}"
    if any(_NAME_GUESS.search(name) for name in labels):
        message += f". {NAME_PROPERTIES_HINT}"
    return message


# A lexeme of code text for the pinning rule is a string literal as `''`, a
# backtick name, a parameter, a word, a number or one other character.
_LEXEME = re.compile(r"''|`[^`]*`|\$(?:`[^`]*`|\w+)|[^\W\d]\w*|\d\w*|\S")
_WORD = re.compile(r"[^\W\d]\w*")
_SNAP = ("$snap", "$`snap`")
_CLAUSES = frozenset(
    {
        "MATCH",
        "OPTIONAL",
        "WITH",
        "UNWIND",
        "RETURN",
        "CALL",
        "UNION",
        "USE",
        "CREATE",
        "MERGE",
        "DELETE",
        "DETACH",
        "SET",
        "REMOVE",
        "FOREACH",
        "LOAD",
        "FINISH",
        "INSERT",
    }
)
# The words that an operand follows. A clause keyword after one of them is a
# variable with the name of a keyword.
_BEFORE_OPERAND = frozenset(
    {
        "AND",
        "OR",
        "XOR",
        "NOT",
        "IN",
        "IS",
        "CONTAINS",
        "STARTS",
        "ENDS",
        "WHERE",
        "CASE",
        "WHEN",
        "THEN",
        "ELSE",
        "AS",
        "BY",
        "ON",
        "OF",
        "FROM",
        "DISTINCT",
        "YIELD",
        "SKIP",
        "LIMIT",
        "OFFSET",
        "USING",
    }
    | (_CLAUSES - {"UNION", "OPTIONAL", "DETACH", "FINISH"})
)
_WORD_OPERATORS = ("AND", "OR", "XOR", "IS", "IN", "CONTAINS", "STARTS", "ENDS")
_STAR_OWNERS = ("WITH", "RETURN", "YIELD", "DISTINCT")
_ITEMS_END = ("ORDER", "SKIP", "LIMIT", "OFFSET", "WHERE")
_BLOCK_WORDS = ("EXISTS", "COUNT", "COLLECT")
_PATH_FUNCTIONS = ("SHORTESTPATH", "ALLSHORTESTPATHS")
# The fields of db.index.fulltext.queryNodes and queryRelationships that hold
# a node or a relationship.
_ENTITY_FIELDS = ("node", "relationship")
_MAX_NESTING = 32


class _Unpinned(Exception):
    """A part of the query can return nodes or relationships of every run."""


class _Pinning:
    """The pinning rule on the code text of one query.

    A pinning predicate is `x.collection_ts = $snap`, `$snap = x.collection_ts`,
    `coalesce(x.collection_ts, $snap) = $snap` or
    `(x:Meta OR x.collection_ts = $snap)` as an AND term of a WHERE, or
    `{collection_ts: $snap}` in the pattern of a node or a relationship.

    A comma-separated part of a pattern is pinned when a pinning predicate
    binds one of its variables, or when it holds a variable of `scope` or of
    a pinned part of the same pattern. `scope` holds the variables of the
    pinned patterns of the earlier clauses, the variables that a procedure
    yields, and the names that a WITH, an UNWIND or the RETURN of a subquery
    gives to them and to the expressions that read them.

    A clause keyword in the place of an operand makes the query not pinned.
    """

    def __init__(self, code: str) -> None:
        self.lex: list[str] = _LEXEME.findall(code)
        # The keyword of each word that is no property key and no label, else "".
        self.key: list[str] = []
        self.close: dict[int, int] = {}
        self.found = False
        # The indexes of the MATCH keywords that `_clauses` has read as a clause.
        self.walked: set[int] = set()
        for i, lexeme in enumerate(self.lex):
            before = self.lex[i - 1] if i else ""
            after_dot = before == "." and i > 1 and not self.lex[i - 2][0].isdigit()
            named = _WORD.fullmatch(lexeme) and before != ":" and not after_dot
            self.key.append(lexeme.upper() if named else "")

    def pinned(self) -> bool:
        if not self._groups():
            return False
        try:
            self._query(0, len(self.lex), set(), 0)
        except _Unpinned:
            return False
        return self.found and all(i in self.walked for i, key in enumerate(self.key) if key == "MATCH")

    def _groups(self) -> bool:
        """Fill `close` with the end of each bracket group and of each CASE
        expression. False when a group does not close.

        A CASE opens a group when an operand or WHEN follows it. The group
        holds a WHEN and no clause keyword outside its brackets."""
        closers = {"(": ")", "[": "]", "{": "}"}
        stack: list[int] = []
        for i, lexeme in enumerate(self.lex):
            if lexeme in closers or (self.key[i] == "CASE" and self._operand_at(i + 1)):
                stack.append(i)
            elif self.key[i] == "END" and stack and self.key[stack[-1]] == "CASE":
                start = stack.pop()
                self.close[start] = i
                inner = [j for j in self._top(start + 1, i) if not self._string_test_with(j)]
                keys = {self.key[j] for j in inner}
                if "WHEN" not in keys or not _CLAUSES.isdisjoint(keys):
                    return False
            elif lexeme in closers.values():
                if not stack or closers.get(self.lex[stack[-1]]) != lexeme:
                    return False
                self.close[stack.pop()] = i
        return not stack

    def _string_test_with(self, i: int) -> bool:
        """Whether the lexeme at `i` is the WITH of STARTS WITH or ENDS WITH."""
        return self.key[i] == "WITH" and i > 0 and self.key[i - 1] in ("STARTS", "ENDS")

    def _operand_at(self, i: int) -> bool:
        """Whether the lexeme at `i` can start an operand."""
        if i >= len(self.lex):
            return False
        lexeme = self.lex[i]
        if _WORD.fullmatch(lexeme):
            return self.key[i] not in _WORD_OPERATORS
        return lexeme in ("(", "[", "{", "-", "+", "''") or lexeme[0] in "`$" or lexeme[0].isdigit()

    def _name(self, i: int) -> str | None:
        lexeme = self.lex[i]
        if lexeme[0] == "`":
            return lexeme[1:-1]
        return lexeme if _WORD.fullmatch(lexeme) else None

    def _top(self, lo: int, hi: int) -> Iterator[int]:
        """The indexes in [lo, hi) outside every bracket group that opens in it."""
        i = lo
        while i < hi:
            yield i
            i = self.close.get(i, i) + 1

    def _find(self, lo: int, hi: int, keys: tuple[str, ...]) -> int:
        return next((i for i in self._top(lo, hi) if self.key[i] in keys), hi)

    def _split(self, lo: int, hi: int) -> Iterator[tuple[int, int]]:
        """The comma-separated ranges of [lo, hi)."""
        start = lo
        for i in self._top(lo, hi):
            if self.lex[i] == ",":
                yield start, i
                start = i + 1
        yield start, hi

    def _starts_clause(self, i: int, lo: int) -> bool:
        """Whether the clause keyword at `i` follows a complete expression."""
        if i == lo:
            return True
        before = self.lex[i - 1]
        if before == "*":
            return i - 1 > lo and (self.key[i - 2] in _STAR_OWNERS or self.lex[i - 2] == ",")
        if _WORD.fullmatch(before):
            key = self.key[i - 1]
            after_union = key == "DISTINCT" and i - 1 > lo and self.key[i - 2] == "UNION"
            return key not in _BEFORE_OPERAND or after_union
        return before in (")", "]", "}", "''") or before[0] in "`$" or before[0].isdigit()

    def _clauses(self, lo: int, hi: int) -> list[tuple[str, int, int]]:
        """The clauses of [lo, hi), each as its keyword, the index after the
        keyword and its end. The first entry holds the lexemes ahead of the
        first keyword under the keyword "".

        Raises `_Unpinned` for a clause keyword in the place of an operand,
        except the WITH of STARTS WITH and ENDS WITH."""
        starts: list[tuple[str, int, int]] = []
        for i in self._top(lo, hi):
            key = self.key[i]
            if key not in _CLAUSES or (starts and i < starts[-1][2]):
                continue
            if self._string_test_with(i):
                continue
            if not self._starts_clause(i, lo):
                raise _Unpinned
            if key == "OPTIONAL" and i + 1 < hi and self.key[i + 1] in ("MATCH", "CALL"):
                starts.append((self.key[i + 1], i, i + 2))
            else:
                starts.append((key, i, i + 1))
        clauses = [("", lo, starts[0][1] if starts else hi)]
        for n, (key, _, body) in enumerate(starts):
            if key == "MATCH":
                self.walked.add(body - 1)
            clauses.append((key, body, starts[n + 1][1] if n + 1 < len(starts) else hi))
        return clauses

    def _query(self, lo: int, hi: int, imported: set[str], depth: int, bare: bool = False) -> set[str]:
        """Walk the clauses of [lo, hi) with the bound variables `imported`.

        Returns the variables that every RETURN of the query holds. `bare`
        reads the lexemes ahead of the first clause as a pattern with a WHERE,
        the short form of EXISTS and COUNT."""
        if depth > _MAX_NESTING:
            raise _Unpinned
        scope = set(imported)
        # The yielded nodes and relationships that the next WITH must pin.
        pending: set[str] = set()
        returned: set[str] | None = None
        for key, a, b in self._clauses(lo, hi):
            if pending and key != "WITH":
                raise _Unpinned
            if key == "MATCH" or (key == "" and bare and a < b):
                where = self._find(a, b, ("WHERE",))
                pins = self._pins(where + 1, b) if where < b else set()
                scope = self._pattern(a, self._find(a, where, ("USING",)), pins, scope)
                self._nested(a, b, scope, depth)
            elif key == "RETURN":
                self._nested(a, b, scope, depth)
                names = self._names(a, self._find(a, b, _ITEMS_END), scope)
                returned = names if returned is None else returned & names
            elif key == "WITH":
                end = self._find(a, b, _ITEMS_END)
                where = self._find(a, b, ("WHERE",))
                self._nested(a, end, scope, depth)
                pins = self._pins(where + 1, b) if where < b else set()
                for name in pending:
                    kept = self._names(a, end, {name}, aliases=False)
                    if not kept or not kept <= pins:
                        raise _Unpinned
                pending.clear()
                scope = self._names(a, end, scope)
                self._nested(end, b, scope, depth)
            elif key == "UNION":
                scope = set(imported)
            elif key == "CALL":
                self._call(a, b, scope, pending, depth)
            else:
                self._nested(a, b, scope, depth)
                if key == "UNWIND" and (alias := self._alias(a, b, scope)) is not None:
                    scope.add(alias)
        if pending:
            raise _Unpinned
        return returned or set()

    def _call(self, a: int, b: int, scope: set[str], pending: set[str], depth: int) -> None:
        """Walk a CALL clause. A subquery adds the variables it returns to
        `scope`. A procedure adds the variables it yields. A node or a
        relationship that a full-text procedure yields goes to `pending`,
        unless the WHERE of the YIELD pins it."""
        block = a if a < b and self.lex[a] == "{" else None
        inner: set[str] = set()
        if block is not None:
            # A subquery reads the outer variables that its first WITH imports.
            if self.key[block + 1] == "WITH":
                inner = set(scope)
        elif a < b and self.lex[a] == "(" and self.close[a] + 1 < b and self.lex[self.close[a] + 1] == "{":
            block = self.close[a] + 1
            listed = self.lex[a + 1 : self.close[a]]
            inner = set(scope) if "*" in listed else {n for n in scope if n in listed or f"`{n}`" in listed}
        if block is not None:
            scope |= self._query(block + 1, self.close[block], inner, depth + 1)
            self._nested(self.close[block] + 1, b, scope, depth)
            return
        self._nested(a, b, scope, depth)
        paren = next((i for i in self._top(a, b) if self.lex[i] == "("), b)
        fulltext = "".join(self.lex[a:paren]).replace("`", "").lower().startswith("db.index.fulltext.")
        yields = self._find(a, b, ("YIELD",))
        if yields == b:
            if fulltext:
                raise _Unpinned
            return
        where = self._find(yields, b, ("WHERE",))
        pins = self._pins(where + 1, b) if where < b else set()
        for start, end in self._split(yields + 1, where):
            field, name = self._item(start, end)
            if field is None or name is None:
                raise _Unpinned
            scope.add(name)
            if fulltext and field in _ENTITY_FIELDS and name not in pins:
                pending.add(name)

    def _item(self, lo: int, hi: int) -> tuple[str | None, str | None]:
        """The source and the name of the projection item `x` or `x AS y` in
        [lo, hi). Both are None for another item."""
        if hi - lo == 1:
            return self._name(lo), self._name(lo)
        if hi - lo == 3 and self.key[lo + 1] == "AS":
            return self._name(lo), self._name(lo + 2)
        return None, None

    def _names(self, lo: int, hi: int, scope: set[str], aliases: bool = True) -> set[str]:
        """The names that the projection items in [lo, hi) give to the
        variables in `scope`. With `aliases`, also the name after `AS` of each
        expression that reads a variable in `scope`."""
        if lo < hi and self.key[lo] == "DISTINCT":
            lo += 1
        names: set[str] = set()
        for start, end in self._split(lo, hi):
            source, name = self._item(start, end)
            if end - start == 1 and self.lex[start] == "*":
                names |= scope
            elif source in scope and name is not None:
                names.add(name)
            elif aliases and (alias := self._alias(start, end, scope)) is not None:
                names.add(alias)
        return names

    def _alias(self, lo: int, hi: int, scope: set[str]) -> str | None:
        """The name after `AS` when [lo, hi) is an expression that reads a
        variable in `scope`, then `AS` and a name."""
        if hi - lo < 3 or self.key[hi - 2] != "AS":
            return None
        reads = any(
            self._name(i) in scope and (i == 0 or self.lex[i - 1] not in (".", ":"))
            for i in range(lo, hi - 2)
        )
        return self._name(hi - 1) if reads else None

    def _pattern(self, lo: int, hi: int, pins: set[str], scope: set[str]) -> set[str]:
        """`scope` with the variables of the pattern in [lo, hi). Raises
        `_Unpinned` for a part of the pattern that is not pinned."""
        parts = [self._part(start, end, pins) for start, end in self._split(lo, hi)]
        holders: dict[str, list[int]] = {}
        for n, (names, _) in enumerate(parts):
            for name in names:
                holders.setdefault(name, []).append(n)
        bound = set(scope)
        queue = [n for n, (names, own) in enumerate(parts) if own or names & pins or names & scope]
        pinned: set[int] = set()
        while queue:
            n = queue.pop()
            if n in pinned:
                continue
            pinned.add(n)
            for name in parts[n][0] - bound:
                bound.add(name)
                queue.extend(holders[name])
        if len(pinned) < len(parts):
            raise _Unpinned
        return bound

    def _part(self, lo: int, hi: int, pins: set[str]) -> tuple[set[str], bool]:
        """The variables of one comma-separated part of a pattern, and whether a
        property map of the part pins it. The WHERE of a node or a relationship
        of the part adds to `pins`."""
        names: set[str] = set()
        own = False
        nodes = 0
        if hi - lo > 2 and self.lex[lo + 1] == "=" and (path := self._name(lo)) is not None:
            names.add(path)
        i = lo
        while i < hi:
            end = self.close.get(i)
            if end is None or (self.lex[i] == "(" and self.lex[i + 1] == "("):
                i += 1
                continue
            if self.lex[i] in ("(", "["):
                nodes += 1 if self.lex[i] == "(" else 0
                name, pin = self._element(i + 1, end, pins)
                if name is not None:
                    names.add(name)
                own = own or pin
            i = end + 1
        if not nodes:
            raise _Unpinned
        return names, own

    def _element(self, lo: int, hi: int, pins: set[str]) -> tuple[str | None, bool]:
        """The variable of the node or relationship pattern in [lo, hi), and
        whether its property map holds `collection_ts: $snap`."""
        name = None
        if lo < hi and (
            lo + 1 == hi or self.lex[lo + 1] in (":", "{", "*") or self.key[lo + 1] in ("WHERE", "IS")
        ):
            name = self._name(lo)
        own = False
        for i in self._top(lo, hi):
            if self.lex[i] == "{":
                for start, end in self._split(i + 1, self.close[i]):
                    if (
                        end - start == 3
                        and self._name(start) == "collection_ts"
                        and self.lex[start + 1] == ":"
                        and self.lex[start + 2] in _SNAP
                    ):
                        own = self.found = True
            elif self.key[i] == "WHERE":
                pins |= self._pins(i + 1, hi)
                break
        return name, own

    def _pins(self, lo: int, hi: int, depth: int = 0) -> set[str]:
        """The variables that the predicate in [lo, hi) pins."""
        while hi - lo > 1 and self.lex[lo] == "(" and self.close[lo] == hi - 1:
            lo, hi = lo + 1, hi - 1
        top = list(self._top(lo, hi))
        keys = [self.key[i] for i in top]
        loose_case = any(self.key[i] == "CASE" and i not in self.close for i in top)
        if depth > _MAX_NESTING or loose_case or "XOR" in keys:
            return set()
        pins: set[str] = set()
        if "OR" in keys:
            cut = top[keys.index("OR")]
            for meta, run in (((lo, cut), (cut + 1, hi)), ((cut + 1, hi), (lo, cut))):
                name = self._equals_snap(*run)
                is_meta = meta[1] - meta[0] == 3 and self.lex[meta[0] + 1 : meta[1]] == [":", "Meta"]
                if keys.count("OR") == 1 and name is not None and is_meta and self._name(meta[0]) == name:
                    pins.add(name)
        elif "AND" in keys:
            start = lo
            for cut in [*(i for i in top if self.key[i] == "AND"), hi]:
                pins |= self._pins(start, cut, depth + 1)
                start = cut + 1
        elif (name := self._equals_snap(lo, hi)) is not None:
            pins.add(name)
        if pins:
            self.found = True
        return pins

    def _equals_snap(self, lo: int, hi: int) -> str | None:
        """The variable `x` when [lo, hi) is `x.collection_ts = $snap`,
        `$snap = x.collection_ts` or `coalesce(x.collection_ts, $snap) = $snap`."""
        lex = self.lex

        def run_of(i: int) -> str | None:
            return self._name(i) if lex[i + 1] == "." and self._name(i + 2) == "collection_ts" else None

        if hi - lo == 5 and lex[lo + 3] == "=" and lex[lo + 4] in _SNAP:
            return run_of(lo)
        if hi - lo == 5 and lex[lo] in _SNAP and lex[lo + 1] == "=":
            return run_of(lo + 2)
        if (
            hi - lo == 10
            and self.key[lo] == "COALESCE"
            and [lex[lo + 1], lex[lo + 5], lex[lo + 7], lex[lo + 8]] == ["(", ",", ")", "="]
            and lex[lo + 6] in _SNAP
            and lex[lo + 9] in _SNAP
        ):
            return run_of(lo + 2)
        return None

    def _nested(self, lo: int, hi: int, scope: set[str], depth: int) -> None:
        """Walk the subquery blocks, the pattern comprehensions and the
        shortest path functions in [lo, hi)."""
        if depth > _MAX_NESTING:
            raise _Unpinned
        i = lo
        while i < hi:
            end = self.close.get(i)
            if end is None:
                i += 1
            elif self.lex[i] == "{" and self._is_block(i, end):
                self._query(i + 1, end, scope, depth + 1, bare=True)
                i = end + 1
            elif self.lex[i] == "[" and (bar := self._comprehension_bar(i, end)) is not None:
                where = self._find(i + 1, bar, ("WHERE",))
                pins = self._pins(where + 1, bar) if where < bar else set()
                self._nested(i + 1, end, self._pattern(i + 1, where, pins, scope), depth + 1)
                i = end + 1
            elif self.lex[i] in ("(", "[") and (local := self._iterators(i + 1, end)):
                self._nested(i + 1, end, scope | local, depth + 1)
                i = end + 1
            else:
                if self.lex[i] == "(" and i and self.key[i - 1] in _PATH_FUNCTIONS:
                    self._pattern(i + 1, end, set(), scope)
                i += 1

    def _iterators(self, lo: int, hi: int) -> set[str]:
        """The variables that the list comprehension, the quantifier or the
        reduce in [lo, hi) binds with IN."""
        return {
            name
            for i in self._top(lo, hi)
            if i + 1 < hi
            and self.key[i + 1] == "IN"
            and self.lex[i - 1] not in (".", ":")
            and (name := self._name(i)) is not None
        }

    def _is_block(self, i: int, end: int) -> bool:
        """Whether the `{` at `i` opens a subquery."""
        if i and self.key[i - 1] in _BLOCK_WORDS:
            return True
        return i + 2 < end and self.key[i + 1] in _CLAUSES and self.lex[i + 2] != ":"

    def _comprehension_bar(self, i: int, end: int) -> int | None:
        """The index of the `|` when the `[` at `i` opens a pattern comprehension."""
        first = i + 1
        if first + 2 < end and self.lex[first + 1] == "=" and self._name(first) is not None:
            first += 2
        if first >= end or self.lex[first] != "(":
            return None
        return next((j for j in self._top(i + 1, end) if self.lex[j] == "|"), None)


# The Latest label refusal of query_cypher on MCP and in the agent, applied
# before check_readonly. core/cycle.py does not write the Latest label.
LATEST_TOKEN = re.compile(r":\s*Latest\b")
LATEST_REFUSAL = (
    "the old Latest label is not read here any more. Drop that label "
    "from the pattern and pin the anchor with x.collection_ts = $snap on an "
    ":Obj node instead, for example MATCH (d:Device:Obj) WHERE d.collection_ts = $snap. "
    "An unguarded MATCH reads every retained run."
)

UNPINNED_QUERY = (
    "a pattern of the query is not pinned to $snap, so the query reads every retained run. Pin one node "
    "in each connected pattern component with x.collection_ts = $snap on an :Obj node, "
    "as an AND term of the WHERE of its MATCH, "
    "for example MATCH (d:Device:Obj) WHERE d.collection_ts = $snap RETURN d. "
    "An operator-invented Site carries no run: pin a Site with (s:Meta OR s.collection_ts = $snap)"
)


def is_pinned(query: str) -> bool:
    """Whether every pattern of `query` reads the one run that `$snap` holds.

    The query is pinned when it holds a pinning predicate and each of these
    holds a pinned variable (`_Pinning`): every comma-separated part of every
    MATCH and OPTIONAL MATCH pattern, of every pattern in an EXISTS, COUNT or
    COLLECT block and of every pattern comprehension, and the node or the
    relationship that a full-text procedure yields. Unicode escapes are decoded
    first, as in `check_readonly`.
    """
    code, _ = _tokenize(_decode_unicode_escapes(query), "''")
    return _Pinning(_plain_space(code)).pinned()


def check_pinned(query: str, mode: str = "refuse") -> str | None:
    """Apply the pinning rule to model-authored Cypher.

    `$snap` is bound to one run before a query executes. A query that
    `is_pinned` refuses reads every retained run. `query_cypher` on MCP and in
    the agent calls this before `run_readonly`. The query catalog, the explore
    routes and POST /api/cypher do not.

    `mode` is the `HST_AI_CYPHER_PINNING` setting. `refuse` raises
    `QueryRejected` with the guard form. `warn` logs a warning and returns the
    same guidance for the caller to attach to the result. A pinned query
    returns None.
    """
    if is_pinned(query):
        return None
    if mode == "warn":
        log.warning("model-authored cypher holds an unpinned pattern and reads every retained run")
        return UNPINNED_QUERY
    raise QueryRejected(UNPINNED_QUERY)


# Past this cap, the graph of the node-link view is reported as partial.
MAX_GRAPH_NODES = 300
MAX_GRAPH_RELS = 600


def _ordered_labels(labels: Any) -> list[str]:
    """Sort a node's labels with its primary label first.

    The primary label is the one label not in `RESERVED_LABELS` (the domain
    label a collector registers, e.g. `Prefix`, `Device`). The rest (`Obj`,
    the layer labels, `Gate`) follow in sorted order. A meta node with no
    primary label (every label reserved) keeps plain sorted order.
    """
    rest = sorted(labels)
    primary = [label for label in rest if label not in RESERVED_LABELS]
    if len(primary) != 1:
        return rest
    rest.remove(primary[0])
    return [primary[0], *rest]


class _GraphCollector:
    """Nodes and relationships reached by a result, deduplicated by element id.

    The payload comes from the graph types of the driver.
    """

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.rels: dict[str, dict[str, Any]] = {}
        self.truncated = False
        # Serialized size of everything collected so far. The caller charges it
        # against MAX_RESULT_BYTES with the rows.
        self.total_bytes = 0
        # The ids of the payload nodes that the record in progress touched, in
        # order of first contact. It is None outside `add_record`. `_row_seen`
        # holds the same ids as a set. A node that the record reaches 2 times
        # is listed 1 time.
        self._row: list[str] | None = None
        self._row_seen: set[str] = set()

    def add_record(self, values: Iterable[Any]) -> list[str]:
        """Collect the values of one record and return the ids of the payload
        nodes that it touched. The table and the canvas select by these ids.

        One walk collects the payload and the ids. A node that the cap dropped
        is not in `nodes` and is not listed.
        """
        self._row, self._row_seen = [], set()
        for value in values:
            self.add(value)
        touched, self._row = self._row, None
        return touched

    def _touch(self, element_id: str) -> None:
        # The row lists only the ids that `nodes` holds.
        if self._row is None or element_id in self._row_seen or element_id not in self.nodes:
            return
        self._row_seen.add(element_id)
        self._row.append(element_id)

    def add(self, value: Any) -> None:
        from neo4j.graph import Node, Path, Relationship

        if isinstance(value, Node):
            self._node(value)
        elif isinstance(value, Relationship):
            self._rel(value)
        elif isinstance(value, Path):
            for node in value.nodes:
                self._node(node)
            for rel in value.relationships:
                self._rel(rel)
        elif isinstance(value, (list, tuple)):
            for item in value:
                self.add(item)
        elif isinstance(value, dict):
            for item in value.values():
                self.add(item)

    def _node(self, node: Any) -> None:
        if node.element_id in self.nodes:
            # An earlier row collected the node. This row also touched it.
            self._touch(node.element_id)
            return
        if len(self.nodes) >= MAX_GRAPH_NODES:
            self.truncated = True
            return
        payload = {
            "id": node.element_id,
            "labels": _ordered_labels(node.labels),
            "properties": dict(node),
        }
        self.nodes[node.element_id] = payload
        self.total_bytes += len(json.dumps(payload, default=str))
        self._touch(node.element_id)

    def _rel(self, rel: Any) -> None:
        if rel.element_id in self.rels:
            # The payload holds both ends of a collected relationship. This row
            # also touched them.
            self._touch(rel.start_node.element_id)
            self._touch(rel.end_node.element_id)
            return
        if len(self.rels) >= MAX_GRAPH_RELS:
            self.truncated = True
            # The relationship is dropped and adds no end node. An end that the
            # payload holds is a node that this row touched.
            self._touch(rel.start_node.element_id)
            self._touch(rel.end_node.element_id)
            return
        # A relationship is kept only when the payload holds both of its end nodes.
        self._node(rel.start_node)
        self._node(rel.end_node)
        if rel.start_node.element_id not in self.nodes or rel.end_node.element_id not in self.nodes:
            self.truncated = True
            return
        payload = {
            "id": rel.element_id,
            "type": rel.type,
            "start": rel.start_node.element_id,
            "end": rel.end_node.element_id,
            "properties": dict(rel),
        }
        self.rels[rel.element_id] = payload
        self.total_bytes += len(json.dumps(payload, default=str))

    def payload(self) -> dict[str, Any]:
        graph = {
            "nodes": list(self.nodes.values()),
            "relationships": list(self.rels.values()),
            "truncated": self.truncated,
        }
        return json.loads(json.dumps(graph, default=str))


def rows_to_table(
    keys: list[str],
    records: list[dict[str, Any]],
    truncated: bool = False,
    nodes: list[list[str]] | None = None,
) -> dict[str, Any]:
    """Named columns and row arrays, JSON-round-tripped with a str() fallback.

    `nodes` holds one id list per record. It becomes the `nodes` of each row,
    the payload nodes that the record touched. Without it a row has `row` only."""
    truncated = truncated or len(records) > MAX_ROWS
    rows: list[dict[str, Any]] = [{"row": [r.get(k) for k in keys]} for r in records[:MAX_ROWS]]
    if nodes is not None:
        for row, ids in zip(rows, nodes[:MAX_ROWS], strict=True):
            row["nodes"] = ids
    rows = json.loads(json.dumps(rows, default=str))
    return {"columns": keys, "data": rows, "truncated": truncated}


def run_readonly(
    settings: Settings,
    query: str,
    params: dict[str, Any],
    trusted: bool = False,
    graph: bool = False,
) -> dict[str, Any]:
    """Run a read query. `trusted=True` skips the guard, for the canned catalog only.

    Operator-supplied Cypher goes through check_readonly first.

    `graph=True` adds the nodes and relationships that the result touched,
    for the node-link view. Each row then also has `nodes`, the element ids of
    the payload nodes that the record touched, in order of first contact.
    Hidden columns, paths and relationship ends count.

    A column whose name starts with `_` is graph-only. Its values go to the
    graph payload and stay out of the table. The catalog queries use such a
    column to return a scalar table and its entities in one query.

    An explicit `snap` in `params` wins. Otherwise the function resolves the
    pointer once per call and binds it as `snap` (the live sentinel when no
    cycle has run).
    """
    if not trusted:
        check_readonly(query)

    @unit_of_work(timeout=NEO4J_TIMEOUT_S)
    def work(
        tx: Any,
    ) -> tuple[list[str], list[dict[str, Any]], list[list[str]], bool, _GraphCollector | None]:
        # Transaction.run reads its kwargs as query parameters too. The user dict goes in `parameters`.
        result = tx.run(query, parameters=params)
        records: list[dict[str, Any]] = []
        # One id list per record, parallel to `records`. The list is empty without the graph.
        row_nodes: list[list[str]] = []
        overflow = False
        total_bytes = 0
        collector = _GraphCollector() if graph else None
        for record in result:
            if len(records) > MAX_ROWS:
                overflow = True
                break
            if collector is not None:
                # The collector reads `record.values()`. `record.data()` returns a
                # node as a property dict without labels and relationships.
                touched = collector.add_record(record.values())
                row_nodes.append(touched)
                # The id list is part of the row and counts toward MAX_RESULT_BYTES.
                total_bytes += len(json.dumps(touched))
            data = record.data()
            # `_`-prefixed columns are graph-only and reach neither the table nor the size count.
            for hidden in [k for k in data if k.startswith("_")]:
                del data[hidden]
            total_bytes += len(json.dumps(data, default=str))
            # The graph payload is in the response body with the rows and counts
            # toward MAX_RESULT_BYTES.
            graph_bytes = collector.total_bytes if collector is not None else 0
            if total_bytes + graph_bytes > MAX_RESULT_BYTES:
                raise ResultTooLarge(
                    f"result exceeded {MAX_RESULT_BYTES // (1024 * 1024)} MB; "
                    "return fewer properties or aggregate the rows"
                )
            records.append(data)
        keys = list(result.keys())
        result.consume()
        return keys, records, row_nodes, overflow, collector

    # READ access covers the autocommit pointer read as well as the managed read.
    with dbmod.session(settings, access_mode="READ") as s:
        if "snap" not in params:
            cts = snapshotmod.resolve(s, settings).cts
            params = {**params, "snap": snapshotmod.snap_param(cts)}
        keys, records, row_nodes, overflow, collector = s.execute_read(work)
    table = rows_to_table(
        [k for k in keys if not k.startswith("_")],
        records,
        truncated=overflow,
        nodes=row_nodes if collector is not None else None,
    )
    if collector is not None:
        table["graph"] = collector.payload()
    return table
