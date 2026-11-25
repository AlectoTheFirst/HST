"""The Business Application generator.

A generation turns a description into one application definition at one
pinned snapshot. The model runs a bounded tool loop over the tools of
`generator_registry`. They are 4 catalogue tools and the tools of
`generator_tools`. Each tool is bound to the run of the generation, and one
generation reads one snapshot. The model returns one YAML document.

`postprocess` decides every reference that reaches the YAML. It applies these
rules to the document of the model:

- An inventory uid that no lookup step returned becomes an `unresolved`
  placeholder. A literal address that neither the description nor a step
  names becomes an `unresolved` placeholder. A value that a step only repeats
  from its own arguments, such as the search text, counts as not returned.
- Every inventory reference is resolved again at the snapshot. No object, a
  kind mismatch or no address in the requested context gives an `unresolved`
  placeholder. More than one object gives an `ambiguous` placeholder.
- A device reference whose graph role is a firewall or a router
  (`TRANSIT_ROLES`) becomes an `unresolved` placeholder.
- An `ip` reference whose address is recorded as more than one IpAddress node
  becomes an `ambiguous` placeholder that lists the nodes.
- A `dns` reference becomes the `ip` reference of the IpAddress node that its
  record resolves to, when a VIP lookup or an address in the description
  names the same node.
- A reference that the model chose among several objects of its kind that one
  search step returned stays `resolved` with selection `model-choice`. The
  report lists the other objects as alternatives.
- Any placeholder makes the document schema version 2 and `draft`.

An edit starts from a saved revision. The model receives the change and the
canonical export of that revision (`edit_question`), and `postprocess` takes
the revision as `base`. These rules apply to an edit:

- The document keeps the application id of the base revision.
- A uid or an address that the base revision writes counts as returned by a
  lookup.
- A member that the model left in the same group as the base revision writes
  it is kept as written. A kept member has no report row unless it is a
  placeholder. The row of a kept placeholder lets the draft workspace bind
  it. Validation at the snapshot reports the resolution of every kept member.

`report` assembles the generation report from the post-processed draft and
its validation result. `generation_record` builds the `application-generation`
record. The record holds the arguments of each step with the digest of its
result, the output YAML, the report, the validation result and the parse
errors. The step arguments in the report and in the record leave out
`snapshot`. The record names the run that every call read. The `ai_steps`
rows of the turn keep the arguments that the model sent.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import ValidationError

from hst.app.ai import prompt as prompt_mod
from hst.app.ai.registry import AGENT_MODEL_CHARS, Principal, Surface, ToolRegistry, ToolSpec
from hst.applications.models import BusinessApplicationDefinition, InventoryReference
from hst.applications.resolution import LABEL_KIND, InventoryCandidate
from hst.applications.yaml_format import (
    ApplicationFormatError,
    canonical_yaml,
    definition_digest,
    parse_application_source,
)

if TYPE_CHECKING:
    from hst.app.agent.tools import ToolCall

GENERATOR_SURFACES: frozenset[Surface] = frozenset({"service_generator"})
# The catalogue tools the generator offers, in the order it offers them.
CATALOGUE_TOOLS = ("inventory_search", "inventory_resolve", "app_applications", "lb_lookup_vip")
# The tools whose items are candidates for a phrase of the description.
SEARCH_TOOLS = frozenset({"inventory_search", "search_objects"})
# The most objects that one report lists as found and not written.
MAX_RELATED = 50
MAX_CANDIDATES = 20
NOT_RETURNED = "not returned by any lookup"
# The device roles of a firewall or a router (core.labels.DEVICE_ROLES).
# `postprocess` turns a member device with one of these roles into a placeholder.
TRANSIT_ROLES = frozenset({"firewall", "gateway", "router", "sdwan-hub", "sdwan-edge"})

SYSTEM = """\
Write a Business Application definition from the description. Return only one \
YAML document, optionally inside one ```yaml fence, with no other text.

The document has these fields: schema_version: 2, kind: BusinessApplication, id \
(lower case letters, digits and hyphens, starting with a letter), name, \
description, owner, environment, state: draft, services, groups and connections.
- A group has id, name and members. A member has id, name and exactly one of: \
inventory {kind, uid, role}, address (a host address or a prefix) or placeholder \
{text, expected_kind, status, candidates, note}.
- inventory.kind is one of device, interface, ip, network, dns, \
service_requirement, vrf, identity or segment. inventory.role is source, \
destination, component or shared.
- A connection has id, name, source and destination (group ids), success \
(forward, round-trip or session) and destination_condition {kind: member, \
member: <a member id of the destination group>}, or {kind: or, parts: [...]} \
over several members. protocol and destination_ports are optional. Write them \
only when the description names a protocol, a port or a service that sets one. \
Otherwise leave both out: the connection then allows any protocol and port. \
Never write a port that the description does not give.
- A service has id, name, connection_ids and component_roles [{group_id, role}], \
where role is client, endpoint, dependency or component. A connection belongs to \
at most one service.

Look up every object with the tools before you write it. Every inventory uid \
you write must appear in a tool result. When no lookup returns an object, write \
a placeholder with status unresolved, the phrase from the description as text, \
the uids you saw as candidates and a short note. When a lookup returns several \
objects and the description does not decide between them, choose one; the \
server lists the others for review.

How to look up what the description names:
- A hostname or FQDN: resolve_hostname, then inventory_resolve with kind address \
for its answer.
- A server, VM or endpoint: search_objects with kind vm, endpoint or device, then \
object_addresses on the uid found. Write the ip uid.
- A load balancer VIP or virtual service: search_objects with kind vip, or \
lb_lookup_vip for an address, then object_addresses for the VIP address and the \
pool members. Write the ip uid of the VIP.
- A site or an office population: search_objects with kind site, then kind \
network by name. Write the network uid.
- A prefix or subnet: search_objects with kind network, or inventory_resolve \
with kind address for a literal. Write the network uid.
- A VRF or routing context: inventory_resolve with kind context. Set \
source_context.vrf or destination_context.vrf only when every member of the \
group is in that VRF.
- A security zone: search_objects with kind zone. It is evidence only; do not \
write it.
- The addresses that use a tunnel, a VPN or a policy route, such as "the IPs \
configured to use the tunnel": search_objects with kind tunnel, interface, vrf \
or pbr_policy, then policy_route_sources on the uid found. Each rule it returns \
lists the sources that rule sends to the target. Write every source of every \
rule as a member of the source group: a source with a uid as inventory kind ip \
(network for a Prefix) with that uid, and a source without a uid, a network of \
a range, as a literal address. Name the earlier rules that send part of the \
traffic elsewhere, such as local destinations, in the group description. When \
the description names no destination, the destination group holds the \
destinations of the rule as literal addresses.
- An address group or an address object of a rule: search_objects with kind \
net_object, then object_addresses on the uid. Write its items and the networks \
of its ranges as for policy_route_sources.
- An existing application: app_applications with mode list.

When a hostname and a VIP or an address name the same IpAddress, write the ip \
uid. Never write a firewall or a router on the path, or a graph business \
service, as a member. Write host addresses without a mask. Put notes in \
placeholder.note, never in YAML comments. A note states what the lookups \
returned; never write that the snapshot does not show something a tool result \
shows. Every lookup reads the snapshot the generation is pinned to."""

EDIT_SYSTEM = """\
This request edits a saved Business Application. The message holds the change \
to make and the saved revision as YAML. Return the whole definition with the \
change applied. Keep the application id. Keep every service, group, member and \
connection that the change does not touch as the saved revision writes it, with \
the same ids. Look up every object the change adds before you write it."""


def system_prompt(
    principal: Principal, tools: Iterable[prompt_mod.OfferedTool], *, edit: bool = False
) -> prompt_mod.AssembledPrompt:
    """Return the system text of a generation. It is the structured base of
    the `service_generator` surface without site instructions, then `SYSTEM`,
    then `EDIT_SYSTEM` for an edit. `static_hash` is the SHA-256 of the whole
    text."""
    base = prompt_mod.assemble("service_generator", prompt_mod.SiteInstructions(), tools, principal)
    system = f"{base.system}\n\n{SYSTEM}"
    if edit:
        system = f"{system}\n\n{EDIT_SYSTEM}"
    return prompt_mod.AssembledPrompt(
        system=system, context_block="", static_hash=hashlib.sha256(system.encode()).hexdigest()
    )


_BACKTICKS = re.compile(r"`+")


def edit_question(change: str, export: str, *, application_id: str, revision: int) -> str:
    """Return the message of an edit. It holds the change, then the canonical
    export of the base revision in a fence longer than any backtick run of the
    export."""
    fence = "`" * max(3, max((len(run) for run in _BACKTICKS.findall(export)), default=0) + 1)
    return (
        f"Change: {change}\n\n"
        f"Saved revision {revision} of application {application_id}:\n"
        f"{fence}yaml\n{export.rstrip()}\n{fence}"
    )


# --- the tool list -------------------------------------------------------------------------


def _takes_snapshot(schema: Mapping[str, Any]) -> bool:
    properties = schema.get("properties")
    return isinstance(properties, Mapping) and "snapshot" in properties


def _without_snapshot(value: Any) -> Any:
    """A copy of a JSON Schema with the `snapshot` property removed from every
    object schema in it, and from every `required` list."""
    if isinstance(value, list):
        return [_without_snapshot(item) for item in value]
    if not isinstance(value, dict):
        return value
    out: dict[str, Any] = {}
    for key, item in value.items():
        if key == "properties" and isinstance(item, dict):
            out[key] = {name: _without_snapshot(prop) for name, prop in item.items() if name != "snapshot"}
        elif key == "required" and isinstance(item, list):
            out[key] = [name for name in item if name != "snapshot"]
        else:
            out[key] = _without_snapshot(item)
    return out


def bind_snapshot(spec: ToolSpec, snapshot_id: str) -> ToolSpec:
    """Return `spec` as the generator offers it.

    The spec is offered on the `service_generator` surface, and the model copy
    of its result is bounded at `AGENT_MODEL_CHARS`. The published schema of a
    tool with a `snapshot` argument has no `snapshot` property. Every call of
    that tool runs with `snapshot` set to `snapshot_id`.
    """
    limits = replace(spec.limits, max_model_chars=min(spec.limits.max_model_chars, AGENT_MODEL_CHARS))
    schema = spec.input_schema()
    if not _takes_snapshot(schema):
        return replace(spec, surfaces=GENERATOR_SURFACES, limits=limits)
    body = spec.run

    def run(ctx: Any, arguments: dict[str, Any]) -> Any:
        return body(ctx, {**arguments, "snapshot": snapshot_id})

    run.__name__ = run.__qualname__ = spec.name
    return replace(
        spec, run=run, surfaces=GENERATOR_SURFACES, limits=limits, wire_schema=_without_snapshot(schema)
    )


def generator_specs() -> list[ToolSpec]:
    """The catalogue tools of `CATALOGUE_TOOLS`, then the generator's own tools."""
    from hst.app.agent.tools import agent_registry
    from hst.applications import generator_tools

    catalogue = agent_registry()
    specs = []
    for name in CATALOGUE_TOOLS:
        spec = catalogue.get(name)
        if spec is None:
            raise LookupError(f"the tool catalogue has no {name}")
        specs.append(spec)
    return [*specs, *generator_tools.specs()]


def generator_registry(snapshot_id: str, specs: Iterable[ToolSpec] | None = None) -> ToolRegistry:
    """Return the tools of one generation, each bound to the run of
    `snapshot_id` (`bind_snapshot`). `specs` defaults to `generator_specs()`."""
    registry = ToolRegistry()
    for spec in generator_specs() if specs is None else specs:
        registry.register(bind_snapshot(spec, snapshot_id))
    return registry


# --- steps and what they found -------------------------------------------------------------


@dataclass(frozen=True)
class Step:
    """One tool call of a generation. It holds the arguments that the model
    sent without `snapshot`, and the unframed result or error text."""

    tool: str
    arguments: dict[str, Any]
    result: str
    is_error: bool


def steps_of(calls: Iterable[ToolCall]) -> list[Step]:
    """Return the steps of the tool calls of a turn, with each result unframed.

    The arguments of a step leave out `snapshot`. Every tool of a generation
    reads the run of the generation (`bind_snapshot`)."""
    from hst.app.agent.tools import unframe

    return [
        Step(
            tool=call.name,
            arguments=(
                {key: value for key, value in call.arguments.items() if key != "snapshot"}
                if isinstance(call.arguments, Mapping)
                else {}
            ),
            result=call.ui_result if call.ui_result is not None else unframe(call.result),
            is_error=call.is_error,
        )
        for call in calls
    ]


_IPV4 = r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?![\d/])(?!\.\d)"
_IPV6 = r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4})?(?::(?:[0-9A-Fa-f]{1,4})?){2,7}(?:/\d{1,3})?(?![0-9A-Fa-f:/])"
_ADDRESS = re.compile(f"{_IPV4}|{_IPV6}")
_TOKEN_SPLIT = re.compile(r"[\s\"',\[\]{}()<>]+")


def addresses_in(text: str) -> set[str]:
    """The IP addresses and prefixes written in `text`, in normalized form. A
    prefix written with a host address, such as 10.0.10.5/24, also gives the
    host address."""
    found: set[str] = set()
    for match in _ADDRESS.finditer(text):
        value = match.group(0)
        try:
            if "/" in value:
                found.add(str(ipaddress.ip_network(value, strict=False)))
                found.add(str(ipaddress.ip_interface(value).ip))
            else:
                found.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    return found


def _normalized(address: str) -> str | None:
    try:
        return str(
            ipaddress.ip_network(address, strict=False) if "/" in address else ipaddress.ip_address(address)
        )
    except ValueError:
        return None


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _objects(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _objects(item)
    elif isinstance(value, list):
        for item in value:
            yield from _objects(item)


def _search_items(body: Any) -> list[dict[str, Any]]:
    """Return the items of a search result, from `result.items` of an envelope or from `items`."""
    if not isinstance(body, dict):
        return []
    holder = body.get("result") if isinstance(body.get("result"), dict) else body
    items = holder.get("items") if isinstance(holder, dict) else None
    if not isinstance(items, list):
        return []
    return [
        {"uid": item["uid"], "label": item.get("label"), "name": item.get("name")}
        for item in items
        if isinstance(item, dict) and isinstance(item.get("uid"), str)
    ]


def _is_edge(value: Any) -> bool:
    return isinstance(value, dict) and all(isinstance(value.get(key), str) for key in ("from", "rel", "to"))


def _without_echo(body: Any, arguments: Mapping[str, Any]) -> Any:
    """`body` without the top-level result fields that repeat one of the call's
    string arguments, such as the `q` of `search_objects`, the `query` of
    `inventory_search` or the `address` of `inventory_resolve`. The fields of
    an envelope's `result` count as top-level. Items, rows and records keep
    every value."""
    asked = {value.strip() for value in _strings(dict(arguments))}

    def kept(holder: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in holder.items()
            if not (isinstance(value, str) and value.strip() in asked)
        }

    if not isinstance(body, dict):
        return body
    out = kept(body)
    if isinstance(out.get("result"), dict):
        out["result"] = kept(out["result"])
    return out


@dataclass
class Lookups:
    """What the steps of one generation returned.

    `strings` holds, per step, every string of its result except the
    top-level fields that repeat the arguments of the call (`_without_echo`).
    `addresses` holds, per step, every address written in those strings. An
    error step has an empty set in both lists. `chains` maps a uid to the
    edges that a chain lookup reported for it. `found` holds the items of each
    search step. `vip_uids` and `vip_addresses` are the VIP nodes and
    addresses that a VIP lookup returned. `known_uids` and `known_addresses`
    are the uids and addresses that the base revision of an edit writes.
    """

    steps: Sequence[Step]
    description_addresses: set[str]
    strings: list[set[str]] = field(default_factory=list)
    addresses: list[set[str]] = field(default_factory=list)
    chains: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    found: list[tuple[int, list[dict[str, Any]]]] = field(default_factory=list)
    vip_uids: set[str] = field(default_factory=set)
    vip_addresses: set[str] = field(default_factory=set)
    known_uids: set[str] = field(default_factory=set)
    known_addresses: set[str] = field(default_factory=set)

    @classmethod
    def of(
        cls, steps: Sequence[Step], description: str, base: BusinessApplicationDefinition | None = None
    ) -> Lookups:
        lookups = cls(steps=steps, description_addresses=addresses_in(description))
        if base is not None:
            for group in base.groups:
                for member in group.members:
                    if member.inventory is not None:
                        lookups.known_uids.add(member.inventory.uid)
                    if member.placeholder is not None:
                        lookups.known_uids.update(member.placeholder.candidates)
                    if member.address is not None:
                        lookups.known_addresses |= addresses_in(member.address)
        for index, step in enumerate(steps):
            strings: set[str] = set()
            addresses: set[str] = set()
            if not step.is_error:
                try:
                    body: Any = json.loads(step.result)
                except ValueError:
                    body = None
                    strings = {token for token in _TOKEN_SPLIT.split(step.result) if token}
                else:
                    strings = set(_strings(_without_echo(body, step.arguments)))
                    lookups._read_body(step, index, body)
                for text in strings:
                    addresses |= addresses_in(text)
            lookups.strings.append(strings)
            lookups.addresses.append(addresses)
        return lookups

    def _read_body(self, step: Step, index: int, body: Any) -> None:
        for node in _objects(body):
            uid, chain = node.get("uid"), node.get("chain")
            if isinstance(uid, str) and isinstance(chain, list):
                edges = self.chains.setdefault(uid, [])
                for edge in chain:
                    if _is_edge(edge) and edge not in edges:
                        edges.append({key: edge[key] for key in ("from", "rel", "to")})
                if step.tool == "object_addresses" and node.get("role") == "vip":
                    self.vip_uids.add(uid)
                    if isinstance(node.get("address"), str):
                        self.vip_addresses |= addresses_in(node["address"])
            if step.tool == "lb_lookup_vip":
                for key in ("vip", "vips"):
                    for text in _strings(node.get(key)):
                        self.vip_addresses |= addresses_in(text)
        if step.tool in SEARCH_TOOLS:
            self.found.append((index, _search_items(body)))

    def seen(self, uid: str) -> bool:
        """Whether a non-error step returned `uid`, or the base revision writes it."""
        return uid in self.known_uids or any(uid in strings for strings in self.strings)

    def address_seen(self, address: str) -> bool:
        """Whether the description, the base revision or a non-error step
        names `address`."""
        return (
            address in self.description_addresses
            or address in self.known_addresses
            or any(address in found for found in self.addresses)
        )

    def chain(self, uid: str) -> list[dict[str, str]]:
        return list(self.chains.get(uid, []))

    def origins(self, uid: str) -> set[str]:
        """`uid` and every node on a chain a lookup reported for it."""
        return {uid} | {node for edge in self.chains.get(uid, []) for node in (edge["from"], edge["to"])}

    def alternatives(self, uid: str, kind: str) -> list[str]:
        """Return the other objects of each search step that returned `uid` or
        a node on its chain. The search must label that node as an object of
        `kind`. An alternative has the same label as that node. A node of
        another kind on the chain, such as the virtual service of a pool
        member, gives no alternatives."""
        origins = self.origins(uid)
        out: list[str] = []
        for _index, items in self.found:
            labels = {item["uid"]: item.get("label") for item in items}
            for origin in origins & labels.keys():
                if LABEL_KIND.get(str(labels[origin])) != kind:
                    continue
                out += [
                    item["uid"]
                    for item in items
                    if item["uid"] not in origins and item.get("label") == labels[origin]
                ]
        return list(dict.fromkeys(out))

    def evidence(self, uids: Iterable[str] = (), addresses: Iterable[str] = ()) -> list[dict[str, Any]]:
        """The steps whose result names one of `uids` or `addresses`, numbered from 1."""
        wanted_uids, wanted_addresses = set(uids), set(addresses)
        return [
            {"step": index + 1, "tool": step.tool, "arguments": step.arguments}
            for index, step in enumerate(self.steps)
            if self.strings[index] & wanted_uids or self.addresses[index] & wanted_addresses
        ]


# --- post-processing -----------------------------------------------------------------------


class SnapshotFacts(Protocol):
    """The post-processor's reads of the generation's run
    (`generator_tools.GraphFacts`)."""

    def resolve(self, reference: InventoryReference) -> list[InventoryCandidate]: ...
    def ip_nodes(self, address: str) -> list[str]: ...
    def dns_answers(self, uid: str) -> list[tuple[str, str]]: ...
    def device_role(self, uid: str) -> str | None: ...


@dataclass
class Draft:
    """A post-processed generation.

    `yaml` is the canonical YAML of `definition`, or the text of the model
    when the text did not parse or validate. `errors` holds the parse and
    schema errors with their line and column. `references` holds one entry per
    checked group member in document order. A member that an edit kept has no
    entry unless it is a placeholder. `related` holds the objects that searches
    returned, that the definition does not name and that matter to the request
    (`_related`), each with the reason. `related_omitted` counts the other
    objects that searches returned and that the definition does not name.
    """

    yaml: str
    definition: BusinessApplicationDefinition | None
    errors: list[dict[str, Any]] = field(default_factory=list)
    references: list[dict[str, Any]] = field(default_factory=list)
    related: list[dict[str, Any]] = field(default_factory=list)
    related_omitted: int = 0


_FENCE = re.compile(r"```[ \t]*(?:ya?ml)?[ \t]*\n(.*?)```", re.DOTALL | re.IGNORECASE)


def extract_yaml(answer: str) -> str:
    """Return the YAML document of a model answer. It is the body of the
    first fenced block, or the whole answer when the answer has no fence."""
    fenced = _FENCE.search(answer)
    return (fenced.group(1) if fenced else answer).strip() + "\n"


def _reference(
    path: str,
    phrase: str,
    status: str,
    selection: str,
    *,
    kind: str | None = None,
    uid: str | None = None,
    bindings: Sequence[Mapping[str, Any]] = (),
    alternatives: Sequence[str] = (),
    chain: Sequence[Mapping[str, str]] = (),
    evidence: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    return {
        "path": path,
        "phrase": phrase,
        "status": status,
        "selection": selection,
        "kind": kind,
        "uid": uid,
        "bindings": [dict(binding) for binding in bindings],
        "alternatives": list(alternatives),
        "chain": [dict(edge) for edge in chain],
        "evidence": [dict(item) for item in evidence],
        "issues": [],
    }


def _to_placeholder(
    member: dict[str, Any],
    *,
    text: str,
    expected_kind: str | None,
    status: str,
    candidates: Sequence[str],
    note: str,
) -> list[str]:
    """Replace the member's address or inventory reference with a placeholder
    and return its candidates."""
    for key in ("address", "inventory", "context"):
        member.pop(key, None)
    kept = list(dict.fromkeys(candidates))[:MAX_CANDIDATES]
    member["placeholder"] = {
        "text": text[:500],
        "expected_kind": expected_kind,
        "status": status,
        "candidates": kept,
        "note": note[:1000],
    }
    return kept


def _confirmed_answer(dns_uid: str, lookups: Lookups, facts: SnapshotFacts) -> str | None:
    """Return the one IpAddress node that the record `dns_uid` resolves to
    and that a VIP lookup or an address in the description also names.
    Returns None when no node or more than one node qualifies."""
    confirmed = {
        uid
        for uid, address in facts.dns_answers(dns_uid)
        if uid in lookups.vip_uids
        or _normalized(address) in lookups.vip_addresses | lookups.description_addresses
    }
    return next(iter(confirmed)) if len(confirmed) == 1 else None


def _inventory_member(
    member: dict[str, Any], path: str, lookups: Lookups, facts: SnapshotFacts, identity: str
) -> dict[str, Any]:
    reference = dict(member["inventory"])
    written = str(reference["uid"])
    phrase = str(member.get("name") or written)
    if not lookups.seen(written):
        _to_placeholder(
            member,
            text=phrase,
            expected_kind=reference["kind"],
            status="unresolved",
            candidates=[],
            note=NOT_RETURNED,
        )
        return _reference(path, phrase, "unresolved", "none")
    if reference["kind"] == "dns":
        answer = _confirmed_answer(written, lookups, facts)
        if answer is not None:
            reference = {**reference, "kind": "ip", "uid": answer}
            member["inventory"] = reference
    uid = str(reference["uid"])
    kind = str(reference["kind"])
    origins = lookups.origins(uid) | {written}
    evidence = lookups.evidence(uids=origins)
    candidates = facts.resolve(InventoryReference.model_validate(reference))
    bindings = []
    problem: tuple[str, list[str], str] | None = None
    if not candidates:
        problem = ("unresolved", [], f"{uid} was not found at snapshot {identity}")
    elif len(candidates) > 1:
        problem = ("ambiguous", [c.uid for c in candidates], f"{uid} resolved to {len(candidates)} objects")
    else:
        candidate = candidates[0]
        bindings = [b for b in candidate.addresses if reference.get("context") in (None, b.context)]
        role = facts.device_role(candidate.uid) if kind == "device" and candidate.kind == "device" else None
        if candidate.kind != kind:
            problem = ("unresolved", [candidate.uid], f"expected {kind}, found {candidate.kind}")
        elif role in TRANSIT_ROLES:
            problem = ("unresolved", [], f"{uid} is a {role}, and a firewall or a router is never a member")
        elif not bindings:
            problem = (
                "unresolved",
                [candidate.uid],
                "the referenced object has no address in the requested context",
            )
        elif kind == "ip":
            nodes = list(dict.fromkeys(facts.ip_nodes(bindings[0].address)))
            if len(nodes) > 1:
                problem = (
                    "ambiguous",
                    nodes,
                    f"address {bindings[0].address} is recorded as {len(nodes)} IpAddress nodes",
                )
    if problem is not None:
        status, observed, note = problem
        kept = _to_placeholder(
            member, text=phrase, expected_kind=kind, status=status, candidates=observed, note=note
        )
        return _reference(
            path, phrase, status, "none", alternatives=kept, chain=lookups.chain(uid), evidence=evidence
        )
    alternatives = lookups.alternatives(uid, kind)
    return _reference(
        path,
        phrase,
        "resolved",
        "model-choice" if alternatives else "exact",
        kind=kind,
        uid=uid,
        bindings=[{"address": b.address, "context": b.context} for b in bindings],
        alternatives=alternatives,
        chain=lookups.chain(uid),
        evidence=evidence,
    )


def _member_reference(
    member: dict[str, Any], path: str, lookups: Lookups, facts: SnapshotFacts, identity: str
) -> dict[str, Any]:
    placeholder = member.get("placeholder")
    if isinstance(placeholder, dict):
        kept = [uid for uid in placeholder.get("candidates") or [] if lookups.seen(uid)]
        placeholder["candidates"] = kept
        return _reference(
            path,
            str(placeholder["text"]),
            str(placeholder.get("status") or "unresolved"),
            "none",
            alternatives=kept,
            evidence=lookups.evidence(uids=set(kept)),
        )
    address = member.get("address")
    if isinstance(address, str):
        phrase = str(member.get("name") or address)
        if lookups.address_seen(address):
            return _reference(
                path,
                phrase,
                "resolved",
                "exact",
                bindings=[{"address": address, "context": member.get("context")}],
                evidence=lookups.evidence(addresses={address}),
            )
        _to_placeholder(
            member,
            text=phrase,
            expected_kind="network" if "/" in address else "ip",
            status="unresolved",
            candidates=[],
            note=NOT_RETURNED,
        )
        return _reference(path, phrase, "unresolved", "none")
    return _inventory_member(member, path, lookups, facts, identity)


_WORD = re.compile(r"[0-9a-z]+")


def _name_phrase(name: Any, description_words: set[str]) -> str | None:
    """Return the words of `name` of 3 or more characters that are not
    numbers, when the name has at least one such word and the description
    holds every one of them. Returns None otherwise."""
    if not isinstance(name, str):
        return None
    words = [word for word in _WORD.findall(name.casefold()) if len(word) >= 3 and not word.isdigit()]
    if words and all(word in description_words for word in words):
        return " ".join(dict.fromkeys(words))
    return None


def _related(
    lookups: Lookups,
    references: Sequence[Mapping[str, Any]],
    written: Iterable[str] = (),
    description: str = "",
) -> tuple[list[dict[str, Any]], int]:
    """Return the related objects and the count of the objects that are not listed.

    The function considers each object that a search step returned and that
    no reference names, uses on a chain or lists as an alternative. It skips
    `written`, the uids of the members that an edit kept. It lists an object
    with a reason only when the object matters to the request:

    - A lookup step that is not a search, such as `object_addresses` or
      `policy_route_sources`, started from the object and returned a written
      member or a placeholder candidate.
    - Such a step returned the object beside a written member or a
      placeholder candidate.
    - The description holds every word of its name (`_name_phrase`).

    The list holds at most `MAX_RELATED` objects."""
    named: set[str] = set(written)
    members: set[str] = set(written)
    candidates: set[str] = set()
    addresses: set[str] = set(lookups.known_addresses)
    for ref in references:
        named.update(ref["alternatives"])
        if ref["uid"] is not None:
            named |= lookups.origins(ref["uid"])
            members.add(ref["uid"])
        elif ref["status"] == "resolved":
            addresses |= {
                value for binding in ref["bindings"] if (value := _normalized(str(binding["address"])))
            }
        else:
            candidates.update(ref["alternatives"])
    used: list[tuple[int, str, set[str]]] = []
    for index, step in enumerate(lookups.steps):
        if step.is_error or step.tool in SEARCH_TOOLS:
            continue
        strings = lookups.strings[index]
        if strings & members or lookups.addresses[index] & addresses:
            used.append((index, "a written member", set(_strings(step.arguments))))
        elif strings & candidates:
            used.append((index, "a placeholder candidate", set(_strings(step.arguments))))
    description_words = set(_WORD.findall(description.casefold()))

    def reason(uid: str, name: Any) -> str | None:
        for index, what, subjects in used:
            if uid in subjects:
                return f"{lookups.steps[index].tool} at step {index + 1} started from it and returned {what}"
        for index, what, _subjects in used:
            if uid in lookups.strings[index]:
                return f"{lookups.steps[index].tool} at step {index + 1} returned it with {what}"
        phrase = _name_phrase(name, description_words)
        return f"the description names {phrase}" if phrase else None

    related: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    for index, items in lookups.found:
        step = lookups.steps[index]
        for item in items:
            if item["uid"] in named or item["uid"] in seen:
                continue
            seen.add(item["uid"])
            why = reason(item["uid"], item.get("name"))
            if why is None:
                continue
            related[item["uid"]] = {
                "uid": item["uid"],
                "label": item.get("label"),
                "name": item.get("name"),
                "relation": f"returned by {step.tool} at step {index + 1}",
                "reason": why,
            }
    listed = list(related.values())[:MAX_RELATED]
    return listed, len(seen) - len(listed)


def postprocess(
    answer: str,
    *,
    description: str,
    steps: Sequence[Step],
    facts: SnapshotFacts,
    snapshot: Mapping[str, Any],
    base: BusinessApplicationDefinition | None = None,
) -> Draft:
    """Decide every reference of the document of the model by the rules of
    the module docstring. `base` is the saved revision that an edit starts
    from. A document that does not parse or validate returns as the text of
    the model with its errors."""
    text = extract_yaml(answer)
    try:
        parsed = parse_application_source(text)
    except ApplicationFormatError as exc:
        return Draft(yaml=text, definition=None, errors=[error.as_dict() for error in exc.errors])
    lookups = Lookups.of(steps, description, base)
    identity = str(snapshot.get("snapshot") or "")
    document = copy.deepcopy(parsed.document.model_dump(mode="json", exclude_none=True))
    kept: dict[tuple[str, str], dict[str, Any]] = {}
    if base is not None:
        document["id"] = base.id
        saved = base.model_dump(mode="json", exclude_none=True)
        kept = {
            (group["id"], member["id"]): member
            for group in saved.get("groups", [])
            for member in group.get("members", [])
        }
    references = []
    written: set[str] = set()
    for group in document.get("groups", []):
        for member in group.get("members", []):
            if kept.get((group["id"], member["id"])) == member:
                if "inventory" in member:
                    written.add(member["inventory"]["uid"])
                # A kept placeholder gets a report row. The draft workspace binds it from that row.
                if "placeholder" not in member:
                    continue
            path = f"groups.{group['id']}.members.{member['id']}"
            references.append(_member_reference(member, path, lookups, facts, identity))
    if any("placeholder" in member for group in document.get("groups", []) for member in group["members"]):
        document["schema_version"] = 2
        document["state"] = "draft"
    try:
        definition = BusinessApplicationDefinition.model_validate(document)
    except ValidationError as exc:
        errors = [
            {
                "path": ".".join(str(part) for part in error["loc"]) or "$",
                "message": error["msg"],
                "line": None,
                "column": None,
            }
            for error in exc.errors(include_url=False)
        ]
        return Draft(yaml=text, definition=None, errors=errors)
    related, omitted = _related(lookups, references, written, description)
    return Draft(
        yaml=canonical_yaml(definition),
        definition=definition,
        references=references,
        related=related,
        related_omitted=omitted,
    )


# --- the report and the record -------------------------------------------------------------


def report(
    draft: Draft, *, generation_id: str, snapshot: Mapping[str, Any], validation: Mapping[str, Any] | None
) -> dict[str, Any]:
    """Return the generation report without the validation result. The
    generation result holds the validation result beside the report.

    Each reference gains the resolution issues of its path. `blocking` lists
    the members that keep the ready state unavailable. They are every
    placeholder and every member with a resolution issue.
    """
    resolution = (validation or {}).get("resolution") or {}
    issues: dict[str, list[dict[str, Any]]] = {}
    for issue in resolution.get("issues") or []:
        issues.setdefault(str(issue.get("path")), []).append(dict(issue))
    references = [{**ref, "issues": issues.get(ref["path"], [])} for ref in draft.references]
    blocking = [ref["path"] for ref in references if ref["status"] != "resolved" or ref["issues"]]
    return {
        "generation_id": generation_id,
        "snapshot": dict(snapshot),
        "definition_digest": definition_digest(draft.definition) if draft.definition is not None else None,
        "references": references,
        "related": draft.related,
        "related_omitted": draft.related_omitted,
        "blocking": list(dict.fromkeys(blocking)),
    }


def generation_record(
    *,
    generation_id: str,
    created_by: int,
    created_at: datetime,
    snapshot: Mapping[str, Any],
    source: Mapping[str, Any],
    description: str,
    provider: str | None,
    model: str | None,
    system_prompt_sha256: str,
    steps: Sequence[Step],
    draft: Draft,
    report: Mapping[str, Any],
    validation: Mapping[str, Any] | None,
    validation_digest: str | None,
) -> dict[str, Any]:
    """Return the `application-generation` record of one generation. A step
    keeps its arguments and the SHA-256 of its result text. The `ai_steps`
    rows of the turn hold the result text."""
    return {
        "id": generation_id,
        "schema_version": 1,
        "created_by": created_by,
        "created_at": created_at.isoformat(),
        "snapshot": dict(snapshot),
        "source": dict(source),
        "description": description,
        "provider": provider,
        "model": model,
        "system_prompt_sha256": system_prompt_sha256,
        "steps": [
            {
                "tool": step.tool,
                "arguments": step.arguments,
                "result_sha256": hashlib.sha256(step.result.encode()).hexdigest(),
                "is_error": step.is_error,
            }
            for step in steps
        ],
        "yaml": draft.yaml,
        "definition_digest": report.get("definition_digest"),
        "errors": draft.errors,
        "report": dict(report),
        "validation": dict(validation) if validation is not None else None,
        "validation_digest": validation_digest,
    }
