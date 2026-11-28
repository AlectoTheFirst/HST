"""The guard on operator-supplied Cypher.

`execute_read` rejects write *operations*. It says nothing about read-mode primitives
that reach outside the graph, and Neo4j Community runs every query as the built-in
admin. `LOAD CSV WITH HEADERS FROM 'http://…'` is a legal read query.
"""

from __future__ import annotations

import pytest
from tests.support.cputime import cpu_time

from hst.app.tables import (
    ALLOWED_PROCEDURES,
    MAX_ROWS,
    UNPINNED_QUERY,
    QueryRejected,
    _decode_unicode_escapes,
    check_pinned,
    check_readonly,
    is_pinned,
    rows_to_table,
)

ALLOWED = [
    "MATCH (n:Device) RETURN n LIMIT 10",
    "MATCH (d:Device)-[:LOCATED_IN]->(s:Site) RETURN d.hostname, s.code",
    "CALL db.index.fulltext.queryNodes('obj_names', $q) YIELD node RETURN node",
    "CALL db.labels()",
    "call DB.LABELS()",  # case-insensitive
    "MATCH (n) WHERE n.url = 'ftpserver' RETURN n",  # not a scheme
    "MATCH (n) WHERE n.name = 'http_proxy' RETURN n",  # not a scheme
    # The tokenizer reads a string literal's own `/*` and `*/` as string text.
    "MATCH (n) WHERE n.a = '/* not a comment */' RETURN n",
    # Likewise `LOAD CSV` spelled out inside a string is data, not the clause.
    "MATCH (n) WHERE n.a = 'LOAD CSV FROM here' RETURN n",
]

REJECTED = [
    "LOAD CSV WITH HEADERS FROM 'http://attacker.example/x' AS r RETURN r",
    "load csv from 'file:///etc/passwd' as r return r",
    "LOAD  CSV FROM 'https://169.254.169.254/latest/meta-data/' AS r RETURN r",
    "CALL dbms.components() YIELD name RETURN name",
    "CALL apoc.load.json('http://attacker.example/x') YIELD value RETURN value",
    "CALL dbms.security.listUsers()",
    "MATCH (n) RETURN 'file:///etc/passwd'",
    "CALL db.awaitIndexes()",  # real, but not needed here
    # Every spelling of an escaped identifier is rejected, including a permitted procedure.
    "CALL `dbms`.components()",
    "CALL `dbms.components`()",
    "CALL `db.labels`()",
    "call `apoc`.`load`.`json`('http://attacker.example/x')",
    # genai.vector.encode is an inline function whose config map carries a caller-set `endpoint`. The
    # endpoint arrives as a parameter here, past the URL-literal check.
    "RETURN genai.vector.encode($text, 'OpenAI', $conf) AS v",
    "RETURN `genai`.`vector`.`encode`($text, 'OpenAI', $conf) AS v",
    "RETURN `genai.vector.encode`($text, 'OpenAI', $conf) AS v",
    "CALL genai.vector.encodeBatch($rows, 'OpenAI', $conf) YIELD vector RETURN vector",
    "WITH vector.similarity.cosine($a, $b) AS s RETURN s",
    "RETURN `vector`.`similarity`.`euclidean`($a, $b) AS s",
    # A `/*` in one string literal and a `*/` in a later one hide no LOAD CSV clause.
    "MATCH (n) WHERE n.a = '/*' LOAD CSV FROM $url AS row RETURN n.b = '*/'",
    # A `//` inside a string is not a line comment; the forbidden CALL on the
    # following line stays visible to the guard.
    "MATCH (n) WHERE n.a = '//' \nCALL dbms.components()",
    # A backtick-quoted identifier's own `/*` is literal identifier text, not
    # a comment opener.
    "CALL `x/*`() CALL dbms.components() /* end */",
    # Cypher needs no whitespace between CALL and a backtick name.
    "CALL`db`.checkpoint()",
    "CALL`tx`.setMetaData({})",
    "MATCH (n) CALL`db.stats.retrieve`('QUERIES') YIELD data RETURN data",
    # Format and separator characters that Python's \s does not match.
    "LOAD\u180eCSV FROM $url AS r RETURN r",
    "LOAD\\u180ECSV FROM $url AS r RETURN r",
    "CALL\u180edbms.components()",
    "SHOW\u2028TRANSACTIONS",
]


@pytest.mark.parametrize("query", ALLOWED)
def test_permitted(query):
    check_readonly(query)


@pytest.mark.parametrize("query", REJECTED)
def test_rejected(query):
    with pytest.raises(QueryRejected):
        check_readonly(query)


def test_a_comment_cannot_smuggle_the_primitive_past_the_check():
    """Comments are stripped before the check."""
    with pytest.raises(QueryRejected):
        check_readonly("CALL /* sneaky */ dbms.components()")
    check_readonly("// LOAD CSV FROM 'http://x' would be rejected\nMATCH (n) RETURN n")
    check_readonly("/* CALL dbms.components() */ MATCH (n) RETURN n")


def test_the_catalog_query_that_needs_a_procedure_is_allowed():
    from hst.queries import QUERIES

    search = next(q for q in QUERIES if q["key"] == "search")
    assert "queryNodes" in search["cypher"]
    check_readonly(search["cypher"])


def test_the_audit_contexts_query_passes_the_guard():
    """`hst audit contexts` runs trusted, hardcoded Cypher (not a catalog entry,
    so not covered by the loop below); it passes the guard unaided."""
    from hst.queries import AUDIT_INTERFACES_MISSING_CONTEXT

    check_readonly(AUDIT_INTERFACES_MISSING_CONTEXT)


def test_the_resolve_context_query_passes_the_guard():
    """`hst context find` and the MCP `resolve_context` tool run trusted,
    hardcoded Cypher (not a catalog entry, so not covered by the loop below);
    it passes the guard unaided."""
    from hst.queries import RESOLVE_CONTEXT_QUERY

    check_readonly(RESOLVE_CONTEXT_QUERY)


def test_every_catalog_query_passes_the_guard_unaided():
    from hst.queries import QUERIES

    for q in QUERIES:
        check_readonly(q["cypher"])


def test_inline_library_functions_are_rejected_without_a_call_clause():
    """Library functions are legal in expression position, where the CALL
    allowlist never looks."""
    for query in (
        "RETURN apoc.load.jsonParams($url, {}, null) AS v",
        "WITH gds.version() AS v RETURN v",
        "RETURN dbms.components() AS v",
        "RETURN `apoc`.`load`.`jsonParams`($url, {}, null) AS v",
        "RETURN `apoc.load.jsonParams`($url, {}, null) AS v",
        "RETURN genai.vector.encode($text, 'OpenAI', $conf) AS v",
        "RETURN vector.similarity.cosine($a, $b) AS s",
    ):
        with pytest.raises(QueryRejected, match="namespaces"):
            check_readonly(query)


def test_allowed_procedures_are_lowercase():
    """The check lowercases before comparing; an uppercase entry would never match."""
    assert all(p == p.lower() for p in ALLOWED_PROCEDURES)


def test_truncation_is_reported_when_iteration_stopped_early():
    table = rows_to_table(["x"], [{"x": 1}], truncated=True)
    assert table["truncated"] is True
    assert len(table["data"]) == 1

    table = rows_to_table(["x"], [{"x": i} for i in range(MAX_ROWS + 5)])
    assert table["truncated"] is True
    assert len(table["data"]) == MAX_ROWS


@pytest.mark.parametrize(
    ("query", "keyword"),
    [
        ("SHOW TRANSACTIONS", "SHOW"),
        ("show procedures yield name RETURN name", "SHOW"),
        ("  /* admin */ SHOW USERS", "SHOW"),
        ("TERMINATE TRANSACTIONS 'neo4j-transaction-42'", "TERMINATE"),
        ("// stop it\nterminate transactions $ids", "TERMINATE"),
        ("USE neo4j SHOW TRANSACTIONS", "SHOW"),
        ("USE neo4j TERMINATE TRANSACTIONS 'neo4j-transaction-1'", "TERMINATE"),
        ("CYPHER 5 SHOW TRANSACTIONS", "SHOW"),
        ("CYPHER runtime=slotted planner = cost SHOW TRANSACTIONS", "SHOW"),
        ("EXPLAIN USE `neo4j` SHOW TRANSACTIONS", "SHOW"),
        ("PROFILE use graph.byName($db) show transactions", "SHOW"),
        ("USE GRAPH neo4j SHOW TRANSACTIONS", "SHOW"),
        ("USE (neo4j) SHOW TRANSACTIONS", "SHOW"),
        ("USE graph.byName(toLower('NEO4J')) SHOW TRANSACTIONS", "SHOW"),
        ("USE GRAPH ((graph.byName(toLower(trim(' neo4j '))))) SHOW TRANSACTIONS", "SHOW"),
        ("USE graph SHOW TRANSACTIONS", "SHOW"),
        ("USE `neo``4j`.`a(b` SHOW TRANSACTIONS", "SHOW"),
        ("CYPHER 5 USE GRAPH neo4j TERMINATE TRANSACTIONS 'neo4j-transaction-1'", "TERMINATE"),
        (
            "USE neo4j SHOW TRANSACTIONS YIELD transactionId, currentQuery "
            "WHERE $snap IS NOT NULL RETURN transactionId, currentQuery",
            "SHOW",
        ),
        ("CYPHER 5SHOW TRANSACTIONS", "SHOW"),
        ("CYPHER 5TERMINATE TRANSACTIONS 'neo4j-transaction-1'", "TERMINATE"),
        ("CYPHER 5USE neo4j SHOW TRANSACTIONS", "SHOW"),
        ("\\u0053HOW TRANSACTIONS", "SHOW"),
        ("\\uuu0053HOW TRANSACTIONS", "SHOW"),
        ("USE neo4j\\u0020SHOW TRANSACTIONS", "SHOW"),
        ("USE neo4j \\u0054ERMINATE TRANSACTIONS 'neo4j-transaction-1'", "TERMINATE"),
        ("// c\rSHOW TRANSACTIONS", "SHOW"),
        ("// c\rTERMINATE TRANSACTIONS 'neo4j-transaction-1'", "TERMINATE"),
        ("USE neo4j // c\rSHOW TRANSACTIONS", "SHOW"),
        ("CYPHER 5 // c\r\nSHOW TRANSACTIONS", "SHOW"),
    ],
)
def test_administration_commands_are_rejected(query, keyword):
    """The guard rejects a query whose first clause is SHOW or TERMINATE.
    Pre-parser options, EXPLAIN, PROFILE and a USE clause ahead of it are skipped,
    including the GRAPH keyword, parenthesized references and nested function calls.
    A version number may run straight into the keyword. Unicode escapes are decoded
    first, as Neo4j decodes them before it lexes the query. A line comment ends at a
    carriage return as well as at a line feed."""
    with pytest.raises(QueryRejected, match=f"{keyword} commands are not permitted"):
        check_readonly(query)


def test_an_escaped_snap_in_a_pinning_predicate_pins_the_query():
    assert check_pinned("MATCH (d:Device) WHERE d.collection_ts = $\\u0073nap RETURN d") is None


def test_an_admin_command_that_holds_snap_is_refused_by_both_checks():
    query = "\\u0053HOW TRANSACTIONS YIELD transactionId WHERE $\\u0073nap IS NOT NULL RETURN transactionId"
    with pytest.raises(QueryRejected, match="not pinned to \\$snap"):
        check_pinned(query)
    with pytest.raises(QueryRejected, match="SHOW commands are not permitted"):
        check_readonly(query)


def test_an_escaped_backslash_starts_no_unicode_escape():
    """A backslash that follows an odd number of backslashes is itself escaped."""
    assert _decode_unicode_escapes("a\\\\u0041") == "a\\\\u0041"
    assert _decode_unicode_escapes("a\\\\\\u0041") == "a\\\\A"
    assert _decode_unicode_escapes("\\uu0041\\u00") == "A\\u00"


def test_an_escape_inside_a_string_literal_passes():
    check_readonly("MATCH (n:Device) WHERE n.hostname = 'r\\u00e9seau-01' RETURN n")


def test_show_and_terminate_elsewhere_in_a_query_pass():
    check_readonly("MATCH (n:Device) RETURN n.show AS show, 'TERMINATE' AS terminate")


def test_a_read_query_behind_a_prefix_passes():
    """Pre-parser options ahead of an ordinary read leave it a read."""
    check_readonly("CYPHER runtime=slotted MATCH (n:Device) RETURN n.show AS show")
    check_readonly("EXPLAIN MATCH (n:Device) RETURN n")


@pytest.mark.parametrize(
    "query",
    [
        "USE system MATCH (n) RETURN n",
        "USE neo4j MATCH (n:Device) RETURN n",
        "use `system` MATCH (n) RETURN n",
        "USE`system` MATCH (n) RETURN n",
        "USE GRAPH (neo4j) MATCH (n:Device) RETURN n",
        "USE graph.byName(toLower('SYSTEM')) MATCH (n) RETURN n",
        "CYPHER 5 USE system MATCH (n) RETURN n",
        "CYPHER 5USE system MATCH (n) RETURN n",
        "EXPLAIN USE system MATCH (n) RETURN n",
        "MATCH (n:Device) RETURN n UNION USE system MATCH (n) RETURN n",
        "CALL { USE system MATCH (n) RETURN n } RETURN n",
        "CALL () { USE system MATCH (n) RETURN n } RETURN n",
        "U\\u0053E system MATCH (n) RETURN n",
        "USE/* c */system MATCH (n) RETURN n",
        "USE\u180esystem MATCH (n) RETURN n",
        "USE\nsystem\nMATCH (n) RETURN n",
    ],
)
def test_a_use_clause_is_rejected_in_any_position(query):
    with pytest.raises(QueryRejected, match=r"^USE clauses are not permitted$"):
        check_readonly(query)


@pytest.mark.parametrize(
    "query",
    [
        "MATCH (n:Device) WHERE n.use = 'x' RETURN n.use AS v",
        "MATCH (n:Device) RETURN n {.use, .name}",
        "MATCH (n:Device) RETURN 'USE system' AS v",
        "MATCH (n:Device) RETURN n.hostname AS `use`",
        "MATCH (n:Device) WHERE n.name = $use RETURN n",
        "MATCH (use:Device) RETURN use.hostname, use",
        "MATCH (n:Device) RETURN {use: n.hostname} AS m // USE system",
        "MATCH (n:Device) WHERE n.reuse IS NULL RETURN n.user",
    ],
)
def test_the_word_use_outside_a_use_clause_passes(query):
    check_readonly(query)


@pytest.mark.parametrize(
    ("query", "refusal"),
    [
        ("WITH 1 AS a LIMIT 1LOAD CSV FROM $u AS r RETURN r", "LOAD CSV"),
        ("WITH 1 AS a LIMIT 0x1FLOAD CSV FROM $u AS r RETURN r", "LOAD CSV"),
        ("WITH 1 AS a LIMIT 0o7LOAD CSV FROM $u AS r RETURN r", "LOAD CSV"),
        ("WITH 1.5LOAD CSV FROM $u AS r RETURN r", "LOAD CSV"),
        ("WITH 1e5LOAD CSV FROM $u AS r RETURN r", "LOAD CSV"),
        ("WITH 1_000LOAD CSV FROM $u AS r RETURN r", "LOAD CSV"),
        ("WITH 1 AS a LIMIT 1CALL db.stats.retrieve('QUERIES') YIELD data RETURN data", "procedure"),
        ("WITH 1 AS a LIMIT 1CALL db.ping() YIELD success RETURN success", "procedure"),
        ("WITH 1 AS a LIMIT 0o7CALL db.ping() YIELD success RETURN success", "procedure"),
        ("WITH 1 AS a LIMIT 1CALL`db`.checkpoint()", "procedure"),
        ("WITH 1 AS a LIMIT 1\\u0043ALL db.ping() YIELD success RETURN success", "procedure"),
        ("WITH 1 AS a LIMIT 1USE system MATCH (n) RETURN n", "USE"),
        ("CYPHER 5SHOW TRANSACTIONS", "SHOW"),
        ("CYPHER 5TERMINATE TRANSACTIONS 'neo4j-transaction-1'", "TERMINATE"),
        ("RETURN 1apoc.text.join(['a'], 'b') AS v", "namespaces"),
        ("RETURN 1gds.version() AS v", "namespaces"),
        ("RETURN 1dbms.components() AS v", "namespaces"),
        ("RETURN 1genai.vector.encode($text, 'OpenAI', $conf) AS v", "namespaces"),
        ("RETURN 1vector.similarity.cosine($a, $b) AS v", "namespaces"),
        ("WITH 1 AS a LIMIT 1²LOAD CSV FROM $u AS r RETURN r", "LOAD CSV"),
        ("WITH 1 AS a LIMIT ½CALL db.ping() YIELD success RETURN success", "procedure"),
        ("WITH 1 AS a LIMIT x²5CALL db.ping() YIELD success RETURN success", "procedure"),
    ],
)
def test_a_keyword_right_after_a_number_is_refused(query, refusal):
    with pytest.raises(QueryRejected, match=refusal):
        check_readonly(query)


@pytest.mark.parametrize(
    "query",
    [
        "MATCH (n:Device) WHERE n.x = 0x1F OR n.y = 1e5 OR n.z = 1_000 OR n.w = .5 RETURN n",
        "MATCH p = (a:Device)-[:CONNECTED_TO*1..3]-(b) RETURN p",
        "MATCH (d1call:Device) RETURN d1call.hostname AS h2load",
        "MATCH (n:Device) RETURN n.x1 AS x1, [1, 2][0] AS y",
        "MATCH (n:Device) RETURN n.hostname AS réseau1",
    ],
)
def test_a_number_beside_a_name_passes(query):
    check_readonly(query)


PINNED = [
    "MATCH (d:Device:Obj) WHERE d.collection_ts = $snap RETURN d",
    "MATCH (d:Device) WHERE $snap = d.collection_ts AND d.hostname STARTS WITH 'core' RETURN d",
    "MATCH (d:Device) WHERE coalesce(d.collection_ts, $snap) = $snap RETURN d.hostname AS n",
    "MATCH (d:Device {collection_ts: $snap}) RETURN d",
    "MATCH (d:Device WHERE d.collection_ts = $snap) RETURN d",
    "MATCH (d:Device)-[r:CONNECTED_TO {collection_ts: $snap}]-(e) RETURN d, e",
    "MATCH (s:Site) WHERE (s:Meta OR s.collection_ts = $snap) RETURN s",
    "MATCH (d:Device) WHERE d.`collection_ts` = $`snap` RETURN d",
    "MATCH (d:Device)\nWHERE d.collection_ts=$snap\n  AND (d.role = 'x' OR d.role = 'y')\nRETURN d LIMIT 5",
    # a later pattern holds a variable that an earlier clause has bound
    "MATCH (d:Device) WHERE d.collection_ts = $snap OPTIONAL MATCH (d)-[:ON]->(i) RETURN d, i",
    "MATCH (d:Device) WHERE d.collection_ts = $snap WITH d AS e MATCH (e)-[:ON]->(i) RETURN i",
    "MATCH (d:Device) WHERE d.collection_ts = $snap WITH collect(d) AS ds UNWIND ds AS x "
    "MATCH (x)-[:ON]->(i) RETURN i",
    "MATCH (d:Device {collection_ts: $snap}) OPTIONAL MATCH (d)-[:ON]-(i) WITH coalesce(i, d) AS x "
    "MATCH (x)-[:ON]-(y) RETURN y",
    "UNWIND $uids AS wanted MATCH (n:Obj {uid: wanted, collection_ts: $snap}) RETURN n",
    # each comma-separated part and each UNION part holds its own predicate
    "MATCH (d:Device), (s:Site) WHERE d.collection_ts = $snap AND (s:Meta OR s.collection_ts = $snap) "
    "RETURN d, s",
    "MATCH (d:Device) WHERE d.collection_ts = $snap RETURN d UNION "
    "MATCH (d:Site) WHERE d.collection_ts = $snap RETURN d",
    "MATCH (d:Device), (d)-[:LOCATED_IN]->(s:Site) WHERE d.collection_ts = $snap RETURN s",
    # subqueries, pattern comprehensions and the full-text procedure
    "CALL { MATCH (d:Device) WHERE d.collection_ts = $snap RETURN d } MATCH (d)-[:ON]->(i) RETURN i",
    "MATCH (d:Device) WHERE d.collection_ts = $snap CALL { WITH d MATCH (d)-[:ON]->(i) RETURN i } RETURN i",
    "MATCH (d:Device) WHERE d.collection_ts = $snap CALL (d) { MATCH (d)-[:ON]->(i) RETURN i } RETURN i",
    "MATCH (d:Device) WHERE d.collection_ts = $snap AND EXISTS { (d)-[:ON]->(:Interface) } RETURN d",
    "MATCH (d:Device) WHERE d.collection_ts = $snap RETURN d, [(d)-[:ON]->(i) | i.name] AS names",
    "MATCH p = (a:Device)-[:CONNECTED_TO*1..3]-(b) WHERE a.collection_ts = $snap "
    "RETURN [n IN nodes(p) | head([(n)-[:LOCATED_IN]->(s:Site) | s.code])] AS sites",
    "MATCH p = shortestPath((a:Device)-[*..5]-(b:Device)) WHERE a.collection_ts = $snap RETURN p",
    "CALL db.index.fulltext.queryNodes('obj_names', $q) YIELD node, score "
    "WITH node AS n, score WHERE n.collection_ts = $snap RETURN n",
    # a CASE and a comment beside the predicate
    "MATCH (d:Device) WHERE CASE WHEN d.x IS NULL THEN true ELSE d.x = 1 END AND d.collection_ts = $snap "
    "RETURN d",
    "MATCH (d:Device) WHERE d.collection_ts = $snap "
    "RETURN CASE WHEN d.a OR d.b THEN 'x' ELSE d.name END AS v",
    "MATCH (d:Device) WHERE (d.collection_ts = $snap) AND d.role = 'x' // OR true\nRETURN d",
    "MATCH (d:Device) WHERE " + "(true AND " * 5 + "d.collection_ts = $snap" + ")" * 5 + " RETURN d",
    "CYPHER runtime=slotted MATCH (d:Device) WHERE d.collection_ts = $snap RETURN d",
]

NOT_PINNED = [
    # no $snap, and $snap outside a pinning predicate
    "MATCH (d:Device) RETURN d",
    "MATCH (d:Device) WHERE $snap IS NOT NULL RETURN d",
    "MATCH (d:Device) RETURN d, $snap AS run",
    "RETURN $snap",
    "MATCH (d:Device) WHERE d.hostname = $snap RETURN d",
    "MATCH (d:Device) WHERE d.collection_ts = $snapshot RETURN d",
    "MATCH (d:Device) WHERE d.name = 'x.collection_ts = $snap' RETURN d",
    "MATCH (d:Device) /* WHERE d.collection_ts = $snap */ RETURN d",
    "MATCH (d:Device {name: {collection_ts: $snap}}) RETURN d",
    # the predicate is no AND term of the WHERE
    "MATCH (d:Device) WHERE d.collection_ts = $snap OR true RETURN d",
    "MATCH (d:Device)\nWHERE d.collection_ts = $snap\n  OR d.role = 'x'\nRETURN d",
    "MATCH (d:Device) WHERE (d.collection_ts = $snap OR d.role = 'x') RETURN d",
    "MATCH (d:Device) WHERE true OR (d.collection_ts = $snap AND true) RETURN d",
    "MATCH (d:Device) WHERE d.collection_ts = $snap XOR true RETURN d",
    "MATCH (d:Device) WHERE NOT d.collection_ts = $snap RETURN d",
    "MATCH (d:Device) WHERE NOT (d.collection_ts = $snap) RETURN d",
    "MATCH (d:Device) WHERE all(x IN [1] WHERE d.collection_ts = $snap) OR true RETURN d",
    "MATCH (d:Device) WHERE CASE WHEN true THEN true ELSE d.collection_ts = $snap END RETURN d",
    "MATCH (d:Device) WHERE CASE WHEN true THEN true AND d.collection_ts = $snap AND true ELSE true END "
    "RETURN d",
    "MATCH (d:Device WHERE d.collection_ts = $snap OR true) RETURN d",
    # another comparison than the equality with $snap
    "MATCH (d:Device) WHERE d.collection_ts <> $snap RETURN d",
    "MATCH (d:Device) WHERE d.collection_ts <= $snap RETURN d",
    "MATCH (d:Device) WHERE d.collection_ts = $snap + 1 RETURN d",
    "MATCH (d:Device) WHERE d.collection_ts = $snap.x RETURN d",
    "MATCH (d:Device) WHERE 1 = d.collection_ts = $snap RETURN d",
    "MATCH (d:Device) WHERE d.collection_ts = $snap = false RETURN d",
    "MATCH (d:Device) WHERE d.collection_ts = $snap IS NULL RETURN d",
    "MATCH (d:Device) WHERE (d:Device OR d.collection_ts = $snap) RETURN d",
    "MATCH (d:Device) WHERE (d:Meta OR e.collection_ts = $snap) RETURN d",
    "MATCH (d:Device) WHERE coalesce(d.other, $snap) = $snap RETURN d",
    # one pattern is pinned and another is not
    "MATCH (d:Device), (s:Site) WHERE d.collection_ts = $snap RETURN d, s",
    "MATCH (d:Device) WHERE d.collection_ts = $snap MATCH (e:Device) RETURN e",
    "MATCH (d:Device) WHERE d.collection_ts = $snap RETURN d UNION MATCH (d:Device) RETURN d",
    "MATCH (d:Device) WHERE d.collection_ts = $snap RETURN d UNION ALL MATCH (d:Device) RETURN d",
    "MATCH (d:Device) WHERE d.collection_ts = $snap WITH count(d) AS n MATCH (d:Device) RETURN d, n",
    "MATCH (d:Device) WHERE d.collection_ts = $snap WITH d AS e MATCH (d:Device) RETURN d",
    "MATCH (d:Device) WHERE d.collection_ts = $snap RETURN COLLECT { MATCH (e:Device) RETURN e } AS every",
    "MATCH (d:Device) WHERE d.collection_ts = $snap RETURN [(e:Device)-[:ON]->(i) | i] AS every",
    "MATCH (d:Device) WHERE d.collection_ts = $snap AND EXISTS { MATCH (e:Device) WHERE e.role = d.role } "
    "RETURN d",
    "MATCH (d:Device) WHERE d.collection_ts = $snap RETURN shortestPath((a:Device)-[*]-(b:Device))",
    "MATCH (d:Device) WHERE d.collection_ts = $snap CALL { MATCH (d)-[:ON]->(i) RETURN i } RETURN i",
    "MATCH (d:Device) WHERE d.collection_ts = $snap CALL (d) { MATCH (e:Device) RETURN e } RETURN e",
    "CALL { MATCH (d:Device) RETURN d } WITH d WHERE d.collection_ts = $snap RETURN d",
    "CALL db.index.fulltext.queryNodes('obj_names', $q) YIELD node WHERE $snap IS NOT NULL RETURN node",
    "CALL db.index.fulltext.queryNodes('obj_names', $q) YIELD node "
    "MATCH (d:Device {collection_ts: $snap}) RETURN node, d",
    # the variable of the pattern holds no node of a pinned pattern
    "WITH null AS d MATCH (d:Device), (s:Site {collection_ts: $snap}) RETURN d",
    "UNWIND $rows AS row MATCH (row) MATCH (s:Site {collection_ts: $snap}) RETURN row",
    # a variable with the name of a keyword
    "WITH false AS set MATCH (d:Device) WHERE d.collection_ts = $snap AND set OR true RETURN d",
    "WITH 'x' AS set MATCH (d:Device) WHERE d.collection_ts = $snap AND d.name = set "
    "WITH count(*) AS c MATCH (d:Device) RETURN d",
    "WITH 1 AS case MATCH (d:Device) WHERE d.collection_ts = $snap AND d.x = case "
    "WITH count(*) AS end MATCH (d:Device) RETURN d",
    "WITH true AS case MATCH (d:Device) WHERE d.collection_ts = $snap AND case OR true RETURN d AS end",
    "MATCH (d:Device) WHERE d.collection_ts = $snap AND d:Device|SET WITH count(*) AS c "
    "MATCH (d:Device) RETURN d",
    # text that the walk cannot read
    "MATCH (d:Device) WHERE d.collection_ts = $snap RETURN d; MATCH (e:Device) RETURN e",
    "MATCH (d:Device) WHERE d.collection_ts = $snap RETURN d " + "(" * 2000,
    # the predicate is an AND term 40 parentheses deep, and the walk reads 32
    "MATCH (d:Device) WHERE " + "(true AND " * 40 + "d.collection_ts = $snap" + ")" * 40 + " RETURN d",
    "SHOW TRANSACTIONS YIELD transactionId WHERE $snap IS NOT NULL RETURN transactionId",
]


@pytest.mark.parametrize("query", PINNED)
def test_a_query_with_every_pattern_pinned_is_pinned(query):
    assert is_pinned(query)
    assert check_pinned(query) is None
    assert check_pinned(query, "warn") is None


@pytest.mark.parametrize("query", NOT_PINNED)
def test_a_query_with_an_unpinned_pattern_gets_the_refusal_or_the_note(query):
    assert not is_pinned(query)
    with pytest.raises(QueryRejected) as refusal:
        check_pinned(query)
    assert str(refusal.value) == UNPINNED_QUERY
    assert check_pinned(query, "warn") == UNPINNED_QUERY


@pytest.mark.parametrize(
    "query",
    [
        "MATCH (d:Device:Obj) WHERE d.collection_ts = $snap WITH d LIMIT 1MATCH (x:Device) RETURN x",
        "MATCH (d:Device:Obj) WHERE d.collection_ts = $snap WITH d LIMIT 0x1FMATCH (x:Device) RETURN x",
        "MATCH (d:Device:Obj) WHERE d.collection_ts = $snap WITH d LIMIT 1OPTIONAL MATCH (x:Device) RETURN x",
        "MATCH (d:Device:Obj) WHERE d.collection_ts = $snap RETURN d LIMIT 1UNION MATCH (d:Device) RETURN d",
    ],
)
def test_an_unpinned_clause_right_after_a_number_is_not_pinned(query):
    assert not is_pinned(query)
    with pytest.raises(QueryRejected, match="not pinned to \\$snap"):
        check_pinned(query)


@pytest.mark.parametrize(
    ("query", "refusal"),
    [
        (
            "MATCH (d:Device:Obj) WHERE d.collection_ts = $snap WITH d LIMIT 1LOAD CSV FROM $u AS r "
            "RETURN r, d",
            "LOAD CSV",
        ),
        (
            "MATCH (d:Device:Obj) WHERE d.collection_ts = $snap WITH d LIMIT 1CALL db.ping() YIELD success "
            "RETURN success, d",
            "procedure",
        ),
    ],
)
def test_a_pinned_query_with_a_keyword_right_after_a_number_is_refused(query, refusal):
    assert is_pinned(query)
    with pytest.raises(QueryRejected, match=refusal):
        check_readonly(query)


def test_every_catalog_query_that_holds_snap_is_pinned():
    from hst.queries import AUDIT_INTERFACES_MISSING_CONTEXT, QUERIES, RESOLVE_CONTEXT_QUERY

    # `freshness` reads the CollectionRun nodes of every run and holds no $snap.
    assert [q["key"] for q in QUERIES if not is_pinned(q["cypher"])] == ["freshness"]
    assert "$snap" not in next(q["cypher"] for q in QUERIES if q["key"] == "freshness")
    assert is_pinned(AUDIT_INTERFACES_MISSING_CONTEXT)
    assert is_pinned(RESOLVE_CONTEXT_QUERY)


def test_a_map_key_with_the_name_of_a_clause_keyword_is_no_label():
    check_readonly("MATCH (n:Device) RETURN {with: n.hostname, match: n.role} AS m")


def test_a_query_of_9000_maps_passes_the_guard_within_5_seconds():
    with cpu_time() as spent:
        check_readonly("MATCH (n:Device) RETURN " + ", ".join(["{a: 1}"] * 9000))
    assert spent.seconds < 5


def test_a_query_of_64_kib_is_checked_within_5_seconds():
    # each part of the pattern holds a variable of the part after it
    chain = ", ".join(f"(d{i})-[:CONNECTED_TO]->(d{i + 1})" for i in reversed(range(2500)))
    with cpu_time() as spent:
        assert is_pinned(f"MATCH {chain} WHERE d0.collection_ts = $snap RETURN d0")
        assert is_pinned("MATCH (d:Device) WHERE d.collection_ts = $snap RETURN " + "[" * 30000 + "]" * 30000)
        assert is_pinned(
            "MATCH (d:Device) WHERE d.collection_ts = $snap " + "AND (d.x = 1) " * 4000 + "RETURN d"
        )
    assert spent.seconds < 5
