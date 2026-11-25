"""The words of a result, defined once.

An engine answers with the three values of the model: `holds`,
`does-not-hold` and `not-established`. These words do not name the tested
statement. The statement differs by tool. A rule permits the flow, a device
forwards it, a connection condition holds, or an object exists. This module
maps the three values onto the words of each statement. The model gives 2
more answers for an item that is decided in parts. `split` means that the
alternatives decide a part differently and the mode decides the whole.
`partly` means that a rule set permits one part and blocks another.

The `Result` model allows `true`, `false`, `split` and `partly` only when the
engine decided the whole item from collected data. An `open` answer has at
least 1 `Missing` entry. A tool that cannot name a data subject uses one of
`FIXED_REASONS`.

`typescript()` renders the table for the web. `tests/test_result_words.py`
asserts that `web/src/results/words.ts` equals it. `python -m hst.results.words`
regenerates that file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Kind = Literal["result", "record", "declared"]
Statement = Literal[
    "rule-permits",  # the rule set permits the flow
    "rule-first-match",  # this rule is the first match of the packets
    "hop-forwards",  # the device forwards the flow at this hop
    "trace-forwards",  # the flow is forwarded on all candidate paths
    "condition-holds",  # the connection condition holds
    "route-policy-accepts",  # the route policy accepts the route
    "nat-rule-matches",  # the NAT rule matches the flow
    "connection-resolves",  # the application connection resolves to addresses
    "object-exists",  # the object exists in side B
]
Answer = Literal["true", "false", "open", "split", "partly", "not-applicable", "default", "added", "changed"]
Quantifier = Literal["some", "every"]
Condition = Literal["forward", "round-trip", "session"]
EngineValue = Literal["holds", "does-not-hold", "not-established"]

# The answer of each engine value. The caller states `split` and `partly` from
# the parts it decided.
ANSWER_OF_VALUE: dict[str, Answer] = {
    "holds": "true",
    "does-not-hold": "false",
    "not-established": "open",
}

# The words of each statement. `{cause}` is the gate or route that decided,
# as the engine names it ("rule 10 of LAN-WAN on core1"). `{device}` is the
# device at which a trace or a split is decided.
WORDS: dict[str, dict[str, str]] = {
    "rule-permits": {
        "true": "permitted",
        "false": "blocked by {cause}",
        "open": "not decided",
        "partly": "partly permitted",
        "not-applicable": "not applicable",
    },
    "rule-first-match": {
        "true": "first match",
        "open": "not decided",
    },
    "hop-forwards": {
        "true": "forwarded",
        "false": "{cause}",
        "open": "not decided",
    },
    "trace-forwards": {
        "true": "forwarded, all candidate paths",
        "false": "blocked at {device}",
        "open": "not decided at {device}",
        "split": "split by path at {device}",
    },
    "condition-holds": {
        "true": "passes",
        "false": "fails",
        "open": "not decided",
        "split": "split by path at {device}",
    },
    "route-policy-accepts": {
        "true": "accepted",
        "false": "rejected",
        "open": "not decided",
        "default": "platform default",
    },
    "nat-rule-matches": {
        "true": "matches",
        "open": "not decided",
    },
    "connection-resolves": {
        "true": "resolved",
        "open": "unresolved",
    },
    "object-exists": {
        "true": "present",
        "false": "removed",
        "open": "not decided",
        "added": "added",
        "changed": "changed",
    },
}

# The forms of the `false` word of a hop, by the cause that the trace records.
HOP_FALSE_FORMS: tuple[str, ...] = (
    "blocked by {rule}",
    "no route",
    "discarded by route {route}",
    "blocked at VIP {vip}",
)

QUANTIFIER_WORDS: dict[str, str] = {
    "some": "counts as passing if one path or member works",
    "every": "counts as passing only if every path and member works",
}

CONDITION_WORDS: dict[str, str] = {
    "forward": "the forward flow",
    "round-trip": "the forward flow and its reply",
    "session": "the session: the forward flow, its reply and the state policy",
}

# The engine's mode names and their quantifier.
QUANTIFIER_OF_MODE: dict[str, Quantifier] = {"possible": "some", "guaranteed": "every"}

# Reasons an answer is open when no data subject can be named. Every other
# open answer names a device, a table, a rule or an interface.
FIXED_REASONS: dict[str, str] = {
    "translated-split": "the walk cannot follow the flow through the translation on this device",
    "capacity-not-modelled": "the capacity condition is declared, not calculated",
    "evaluation-budget": "the calculation stopped at its deadline before this part",
    "owner-not-collected": "the relationship has no owning device in the snapshot",
}

# The words that a result never holds. The set has the terms of the engine and
# the words that claim more than a snapshot can show.
FORBIDDEN_WORDS: frozenset[str] = frozenset(
    {
        "proven",
        "possible",
        "holds",
        "does-not-hold",
        "not-established",
        "indeterminate",
        "mixed",
        "reached",
        "reachable",
        "reachability",
        "delivered",
        "leg",
    }
)

# The completeness words of a record.
RECORD_WORDS: dict[str, str] = {
    "recorded": "recorded in the snapshot",
    "observed": "recorded in this run",
    "carried": "carried forward from an earlier run",
    "complete": "recorded from a complete table",
    "incomplete": "recorded from an incomplete table",
    "configured": "configured; not observed in operation",
    "computed": "computed from configuration; not observed",
    "validated": "computed and confirmed by the observed table",
    "history-dependent": "computed; the arrival order decided the selection",
    "mismatch": "computed; the observed table disagrees",
    "unsettled": "computed; the calculation did not settle",
    "state-not-captured": "configured; the session state was not captured",
    "kind-not-evaluated": "recorded; of a kind the engine does not evaluate",
    "stored": "stored record",
    "declared": "declared by a person",
    # The 2 words below answer a whole call that lists items.
    "empty": "no record matches in the snapshot",
    "per-item": "each item states its own result",
}


class Missing(BaseModel):
    """One reason that keeps an answer open. It holds a reason code, the
    subject when there is one, and the sentence of the engine."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1, max_length=120)
    subject: str | None = Field(default=None, max_length=500)
    detail: str | None = Field(default=None, max_length=1000)


class Result(BaseModel):
    """The answer of one item in the words of the statement that it tests.

    `kind` is `result` for a computed result, `record` for an observed record
    and `declared` for a declared record. Only a `result` has a statement and
    an answer. `word` is the rendered answer. `quantifier` and `condition` are
    the strictness and the condition of the question where the statement has
    them. `missing` holds the reasons when the answer is `open`."""

    model_config = ConfigDict(extra="forbid")

    kind: Kind = "result"
    statement: Statement | None = None
    answer: Answer | None = None
    word: str = Field(min_length=1, max_length=500)
    quantifier: Quantifier | None = None
    condition: Condition | None = None
    missing: list[Missing] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def _consistent(self) -> Result:
        if self.kind != "result":
            if self.statement is not None or self.answer is not None:
                raise ValueError(f"a {self.kind} has no statement and no answer")
            return self
        if self.statement is None or self.answer is None:
            raise ValueError("a result names its statement and its answer")
        if self.answer not in WORDS[self.statement]:
            raise ValueError(f"{self.answer!r} is not an answer of {self.statement}")
        if (self.answer == "open") != bool(self.missing):
            raise ValueError("an open answer names what is missing; a decided answer names nothing")
        lowered = self.word.lower()
        for word in FORBIDDEN_WORDS:
            if _contains_word(lowered, word):
                raise ValueError(f"the word {word!r} is not a result word")
        return self


def _contains_word(text: str, word: str) -> bool:
    import re

    return re.search(rf"(?<![\w-]){re.escape(word)}(?![\w-])", text) is not None


def word(statement: Statement, answer: Answer, *, cause: str | None = None, device: str | None = None) -> str:
    """The rendered word of one answer. The function fills `{cause}` and
    `{device}` from the arguments. Without `device`, the word drops
    " at {device}". Without `cause`, the word has a fallback cause."""
    if answer not in WORDS[statement]:
        raise ValueError(f"{answer!r} is not an answer of {statement}")
    template = WORDS[statement][answer]
    if "{cause}" in template:
        fallback = "blocked" if statement == "hop-forwards" else "a rule"
        template = template.replace("{cause}", cause or fallback)
    if "{device}" in template:
        template = template.replace(" at {device}", f" at {device}" if device else "")
    return template


def from_engine(
    statement: Statement,
    value: str,
    *,
    cause: str | None = None,
    device: str | None = None,
    quantifier: Quantifier | None = None,
    condition: Condition | None = None,
    missing: list[Missing] | tuple[Missing, ...] = (),
) -> Result:
    """A `Result` from one of the three values of the engine. `value` is
    `holds`, `does-not-hold` or `not-established`. A caller states `split`
    and `partly` through `decided`."""
    if value not in ANSWER_OF_VALUE:
        raise ValueError(f"{value!r} is not an engine value")
    answer = ANSWER_OF_VALUE[value]
    return Result(
        statement=statement,
        answer=answer,
        word=word(statement, answer, cause=cause, device=device),
        quantifier=quantifier,
        condition=condition,
        missing=list(missing),
    )


def decided(
    statement: Statement,
    answer: Answer,
    *,
    cause: str | None = None,
    device: str | None = None,
    quantifier: Quantifier | None = None,
    condition: Condition | None = None,
) -> Result:
    """A decided `Result` that the caller states. `answer` is any answer
    except `open`."""
    if answer == "open":
        raise ValueError("an open answer comes from `from_engine` with its missing entries")
    return Result(
        statement=statement,
        answer=answer,
        word=word(statement, answer, cause=cause, device=device),
        quantifier=quantifier,
        condition=condition,
    )


def record(completeness: str, *, missing: list[Missing] | tuple[Missing, ...] = ()) -> Result:
    """The `Result` of a record. It has no answer. Its word is the
    completeness word, and `missing` holds what keeps the record incomplete."""
    kind: Kind = "declared" if completeness == "declared" else "record"
    return Result(kind=kind, word=RECORD_WORDS[completeness], missing=list(missing))


def lines(result: Result, *, subject: str, run: str | None = None) -> list[str]:
    """The lines that every surface writes for a result. The first line holds
    the subject and the answer. A "Tested" line follows when the result has a
    condition or a quantifier. The last line names the missing data of an open
    answer, or the run of the data. A record gives 1 line."""
    first = f"{subject}: {result.word}."
    if result.kind != "result":
        return [first]
    tested = []
    if result.condition:
        tested.append(CONDITION_WORDS[result.condition])
    if result.quantifier:
        tested.append(QUANTIFIER_WORDS[result.quantifier])
    out = [first]
    if tested:
        out.append("Tested: " + ", ".join(tested) + ".")
    if result.answer == "open":
        reasons = []
        for item in result.missing:
            text = item.detail or FIXED_REASONS.get(item.code, item.code)
            reasons.append(f"{item.subject}: {text}" if item.subject else text)
        out.append("Not decided: " + "; ".join(reasons) + ".")
    else:
        out.append(f"All data on the path is in run {run}." if run else "All data on the path was collected.")
    return out


# The explanation of one firewall rule has at most 3 lines and an optional
# "Not decided" line. Line 1 states what the rule does and on which exits.
# Line 2 states the policy route and the tunnel that the rule stands behind.
# Line 3 states the exits that the rule does not cover. `policy_evaluate`
# writes the lines in `summary.lines`. The leak guard writes the coverage
# lines of each record.

RULE_VERBS: dict[str, str] = {
    "accept": "permits",
    "permit": "permits",
    "allow": "permits",
    "drop": "drops",
    "deny": "drops",
    "reject": "rejects",
    "block": "drops",
}

# Address lists longer than this are written as a count.
MAX_LISTED_ADDRESSES = 4


def _join(items: list[str], last: str = "and") -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + f" {last} " + items[-1]


def _hosts(addresses: list[str]) -> tuple[str, str, bool]:
    """The nouns for a source list. The result holds the subject of line 2,
    the subject of line 3, and whether the subject is singular."""
    single = all("/" not in a for a in addresses)
    if single and len(addresses) == 1:
        return "This host", "the host", True
    if single and len(addresses) <= MAX_LISTED_ADDRESSES:
        return f"These {len(addresses)} hosts", "the hosts", False
    return "These sources", "the sources", False


def _addresses(addresses: list[str] | str, noun: str) -> str:
    if addresses == "any" or not addresses:
        return f"any {noun}"
    if len(addresses) > MAX_LISTED_ADDRESSES:
        return f"{len(addresses)} {noun} networks"
    return _join(list(addresses))


def rule_label(rulebase: str | None, position: object, device: str | None = None) -> str:
    """The name of a rule in the form "LAN-WAN rule 10 on core1"."""
    label = f"{rulebase} rule {position}" if rulebase else f"rule {position}"
    return f"{label} on {device}" if device else label


def rule_does_line(
    *,
    rulebase: str | None,
    position: object,
    device: str | None,
    action: str | None,
    hosts: list[str] | str,
    host_objects: list[str],
    destinations: list[str] | str,
    exits: list[str],
) -> str:
    """Line 1 of a rule explanation. It states what the rule does to which
    traffic, and on which exits."""
    verb = RULE_VERBS.get(str(action or "").lower(), "matches")
    text = f"{rule_label(rulebase, position, device)} {verb} traffic from {_addresses(hosts, 'source')}"
    if host_objects:
        text += f" (group{'s' if len(host_objects) > 1 else ''} {_join(host_objects)})"
    if destinations != "any" and destinations:
        text += f" to {_addresses(destinations, 'destination')}"
    if exits:
        text += f" when it leaves through {_join(exits, 'or')}"
    return text + "."


def rule_role_line(
    *, position: object, hosts: list[str] | str, tunnels: list[str], policy_routes: list[str]
) -> str:
    """Line 2 of a rule explanation. It names the policy routes that send the
    sources of the rule into a tunnel first. The rule applies when that
    routing does not."""
    if hosts == "any":
        subject, singular = "This traffic", True
    else:
        subject, _, singular = _hosts(list(hosts))
    verb = "is" if singular else "are"
    return (
        f"{subject} {verb} normally policy-routed into {_join(tunnels)} by {_join(policy_routes)}. "
        f"Rule {position} applies when that routing does not."
    )


def not_covered_line(exits: list[str], hosts: list[str] | str) -> str:
    """Line 3 of a rule explanation. It names the exits of the rulebase that
    the rule does not cover."""
    if hosts == "any":
        subject, singular = "the traffic", True
    else:
        _, subject, singular = _hosts(list(hosts))
    gets = "gets" if singular else "get"
    them = "it" if len(exits) == 1 else "them"
    return (
        f"It does not cover {_join(exits, 'or')}, so without the policy routes {subject} still {gets} "
        f"out through {them}."
    )


def covered_line(exits: list[str], hosts: list[str] | str, position: object) -> str:
    """The line of a leak guard record whose exits the rule covers."""
    if hosts == "any":
        subject, singular = "the traffic", True
    else:
        _, subject, singular = _hosts(list(hosts))
    leaves = "leaves" if singular else "leave"
    them = "it" if singular else "them"
    return (
        f"Without the policy routes {subject} {leaves} through {_join(exits, 'or')}, where rule {position} "
        f"blocks {them}."
    )


def decided_first_line(rule: str, exits: list[str]) -> str:
    """The line for the exits where an earlier rule of the rulebase decides
    the traffic first."""
    return f"{rule[:1].upper()}{rule[1:]} decides this traffic first on {_join(exits, 'and')}."


def not_decided_line(missing: list[Missing]) -> str:
    """The "Not decided" line of a rule explanation, in the form that `lines`
    writes."""
    reasons: list[str] = []
    for item in missing:
        text = item.detail or FIXED_REASONS.get(item.code, item.code)
        text = f"{item.subject}: {text}" if item.subject else text
        if text not in reasons:
            reasons.append(text)
    return "Not decided: " + "; ".join(reasons) + "."


def typescript() -> str:
    """The table for the web, as a TypeScript module."""
    table = {
        "words": WORDS,
        "quantifier": QUANTIFIER_WORDS,
        "condition": CONDITION_WORDS,
        "quantifierOfMode": QUANTIFIER_OF_MODE,
        "fixedReasons": FIXED_REASONS,
        "record": RECORD_WORDS,
        "forbidden": sorted(FORBIDDEN_WORDS),
    }
    body = json.dumps(table, indent=2, ensure_ascii=False)
    return (
        "// Generated by `python -m hst.results.words` from src/hst/results/words.py.\n"
        "// Do not edit: tests/test_result_words.py asserts that this file equals the source.\n\n"
        f"export const RESULT_WORDS = {body} as const;\n\n"
        "export type ResultStatement = keyof typeof RESULT_WORDS.words;\n"
        'export type ResultAnswer = "true" | "false" | "open" | "split" | "partly" | "not-applicable" | '
        '"default" | "added" | "changed";\n'
        "export type ResultQuantifier = keyof typeof RESULT_WORDS.quantifier;\n"
        "export type ResultCondition = keyof typeof RESULT_WORDS.condition;\n\n"
        "/** The rendered word of one answer: `{cause}` and `{device}` filled in, or left out. */\n"
        "export function resultWord(statement: ResultStatement, answer: ResultAnswer, "
        "cause?: string | null, device?: string | null): string {\n"
        "  const table: Record<string, string> = RESULT_WORDS.words[statement];\n"
        "  let template = table[answer] ?? answer;\n"
        '  if (template.includes("{cause}")) template = template.replace("{cause}", cause ?? '
        '(statement === "hop-forwards" ? "blocked" : "a rule"));\n'
        '  if (template.includes("{device}")) {\n'
        '    template = template.replace(" at {device}", device ? ` at ${device}` : "");\n'
        "  }\n"
        "  return template;\n"
        "}\n"
    )


WEB_FILE = Path(__file__).resolve().parents[3] / "web" / "src" / "results" / "words.ts"


def main(argv: list[str] | None = None) -> int:
    target = Path(argv[0]) if argv else WEB_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(typescript())
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
