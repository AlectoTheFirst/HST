"""IOS-XR BGP and RPL config parsing for `router bgp`, `prefix-set` and
`route-policy`.

Scope:

  - `parse_bgp` returns one entry of `processes` for `router bgp` and one for
    each `vrf NAME` sub-block. The default VRF is the first entry. A
    neighbor-group, af-group or session-group declared globally is an
    inheritance source inside a VRF block.
  - Only the RPL `prefix-set ... end-set` is captured. `ip prefix-list` and
    `ipv6 prefix-list` are not captured.
  - IPv6 prefix-sets, IPv6 prefix-lists and IPv6 BGP neighbors are out of
    scope.
  - A guard is parsed as a full boolean expression with `and`, `or`, `not` and
    parentheses. The atoms are `destination in NAME|(inline)`,
    `as-path in NAME|(inline)`, `as-path length|neighbor-is|originates-from|
    passes-through`, `community matches-any|matches-every NAME|(inline)`,
    comparisons of `med`, `local-preference` and `tag`, `origin is` and
    `apply NAME`. A plain `and`-chain that the flat match_* fields express
    exactly is stored in these fields. Any other guard is stored whole as
    `match_expr`. Every other boolean form (next-hop, route-type, rd,
    rib-has-route, validation-state) is an `unsupported` atom and is listed
    in `match_unsupported`. The engine evaluates a guard with such an atom as
    false and reports it.
  - A branch body can hold a nested `if`, which is parsed recursively.
  - `community-set` and `as-path-set` are captured as community-list and
    as-path-list RoutePolicy nodes. `extcommunity-set`, `large-community-set`
    and RPL parameters are not captured. A guard or a set line that uses one
    of them is unsupported.

Each branch of an `if ... elseif ... else ... endif` statement gets a
synthetic seq and a RoutePolicyEntry. The `continues` and `continue_seq`
properties chain the branches, and a failed guard leads to the next branch.
Each branch except the last has `continues=True` and `continue_seq` set to the
seq of the next branch. The last branch ends the chain. An explicit `else` has
no guard. A branch whose body holds a nested `if`, or a `set`, `delete` or
`prepend` line after an `apply`, has only its guard. The entries of its body
follow it in configured order with `parent_seq` set to the seq of the branch.
"""

from __future__ import annotations

import itertools
import json
import re
from typing import Any

from .util import parse_aggregate_options, parse_cluster_id, parse_maximum_paths

# --- router bgp -----------------------------------------------------------------------

_RE_ROUTER_BGP = re.compile(r"^router bgp (\d+)$")
_RE_ROUTER_ID = re.compile(r"^bgp router-id (\S+)$")
_RE_CLUSTER_ID = re.compile(r"^bgp cluster-id (\S+)$")
_RE_MED_ALWAYS = re.compile(r"^bgp bestpath med always$")
_RE_NEIGHBOR_GROUP_HDR = re.compile(r"^neighbor-group (\S+)$")
_RE_AF_GROUP_HDR = re.compile(r"^af-group (\S+) address-family ipv4 unicast$")
_RE_SESSION_GROUP_HDR = re.compile(r"^session-group (\S+)$")
_RE_NEIGHBOR_HDR = re.compile(r"^neighbor (\S+)$")
_RE_REDISTRIBUTE_HDR = re.compile(r"^redistribute (\S+)\b(.*)$")
_RE_NETWORK_HDR = re.compile(r"^network (\S+)\b(.*)$")
_RE_AGGREGATE_HDR = re.compile(r"^aggregate-address (\S+)(?:\s+(.*))?$")
_RE_VRF_HDR = re.compile(r"^vrf (\S+)$")
_RE_ORIGIN_STATEMENT = re.compile(r"^(?:redistribute|network|aggregate-address) ")

_RE_REMOTE_AS = re.compile(r"^remote-as (\d+)$")
_RE_USE_NEIGHBOR_GROUP = re.compile(r"^use neighbor-group (\S+)$")
_RE_USE_AF_GROUP = re.compile(r"^use af-group (\S+)$")
_RE_USE_SESSION_GROUP = re.compile(r"^use session-group (\S+)$")
_RE_ADDRESS_FAMILY = re.compile(r"^address-family ipv4 unicast\b")
# Matches any address family header. Group 1 is the family (`ipv4 unicast`,
# `ipv6 unicast`, ...).
_RE_ANY_ADDRESS_FAMILY = re.compile(r"^address-family (\S+ \S+)")
_RE_ROUTE_POLICY_DIR = re.compile(r"^route-policy (\S+) (in|out)$")
# The cluster id of a neighbor. It replaces the `bgp cluster-id` of the process.
_RE_NEIGHBOR_CLUSTER_ID = re.compile(r"^cluster-id (\S+)$")


def _parse_group_body(lines: list[str]) -> dict[str, Any]:
    """Return the fields that a neighbor-group, af-group, session-group or
    neighbor block sets. `resolve_bgp_sessions` inherits a field that is None."""
    fields: dict[str, Any] = {
        "remote_as": None,
        "use_neighbor_group": None,
        "use_af_group": None,
        "use_session_group": None,
        "afi_activated": False,
        "import_policy": None,
        "export_policy": None,
        "shutdown": None,
        "route_reflector_client": None,
        "cluster_id": None,
    }
    # The address family of the current line. XR prints the lines of a block
    # before its `address-family` sub-blocks. A line after an `address-family`
    # header belongs to that family. The value is None before the first
    # header. The body of an af-group is ipv4 unicast.
    family: str | None = None
    for line in lines:
        if m := _RE_ANY_ADDRESS_FAMILY.match(line):
            family = m[1]
        if line in ("route-reflector-client", "route-reflector-client inheritance-disable"):
            # Only the setting of the IPv4 unicast family applies to the session.
            if family in (None, "ipv4 unicast"):
                fields["route_reflector_client"] = line == "route-reflector-client"
        elif m := _RE_REMOTE_AS.match(line):
            fields["remote_as"] = int(m[1])
        elif m := _RE_NEIGHBOR_CLUSTER_ID.match(line):
            fields["cluster_id"] = parse_cluster_id(m[1])
        elif m := _RE_USE_NEIGHBOR_GROUP.match(line):
            fields["use_neighbor_group"] = m[1]
        elif m := _RE_USE_AF_GROUP.match(line):
            fields["use_af_group"] = m[1]
        elif m := _RE_USE_SESSION_GROUP.match(line):
            fields["use_session_group"] = m[1]
        elif _RE_ADDRESS_FAMILY.match(line):
            fields["afi_activated"] = True
        elif m := _RE_ROUTE_POLICY_DIR.match(line):
            name, direction = m[1], m[2]
            if direction == "in":
                fields["import_policy"] = name
            else:
                fields["export_policy"] = name
        elif line == "next-hop-self":
            fields["next_hop_self"] = "ebgp"
        elif line == "shutdown":
            fields["shutdown"] = True
        elif line == "no shutdown":
            fields["shutdown"] = False
    return fields


def _parse_bgp_single(text: str) -> dict[str, Any] | None:
    """Parse one `router bgp <asn>` process (module docstring, scope). Return
    None when the capture holds no `router bgp` line.

    The indentation sets the block boundaries. A line at 1 space of indent
    under `router bgp N` has one of 3 roles. It opens a named block
    (`neighbor-group`, `af-group`, `session-group`, `neighbor`). It opens an
    `address-family` block of the process, whose `redistribute`, `network` and
    `aggregate-address` lines at 2 spaces of indent are the origins of the
    process. It is a statement of the process (`bgp router-id`, or an origin
    statement at that level). Every other line at 2 or more spaces of indent
    belongs to the open named block at any nesting depth. The
    `address-family ipv4 unicast` sub-block of a neighbor is such a line."""
    asn: int | None = None
    router_id: str | None = None
    cluster_id: str | None = None
    always_compare_med = False
    multipath_relax = False
    # The `maximum-paths` values of the process address-family blocks, keyed by `<type>_v<family>`.
    maximum_paths: dict[str, int] = {}
    default_originate_afs: list[int] = []
    neighbor_groups: dict[str, dict] = {}
    af_groups: dict[str, dict] = {}
    session_groups: dict[str, dict] = {}
    neighbors: list[dict] = []
    redistribute: list[dict] = []
    networks: list[dict[str, Any]] = []
    aggregates: list[dict[str, Any]] = []
    origin_context_gaps: list[str] = []

    current_kind: str | None = None
    current_name: str | None = None
    current_body: list[str] = []
    # The family of the open process `address-family` block at 1 space of indent.
    process_family: str | None = None

    def origin_statement(stripped: str) -> None:
        """A process `redistribute`, `network` or `aggregate-address` line."""
        if m := _RE_REDISTRIBUTE_HDR.match(stripped):
            proto, rest = m[1], m[2]
            pm = re.search(r"route-policy (\S+)", rest)
            redistribute.append({"protocol": proto, "policy_name": pm[1] if pm else None})
        elif m := _RE_NETWORK_HDR.match(stripped):
            pm = re.search(r"route-policy (\S+)", m[2])
            networks.append({"prefix": m[1], "policy_name": pm[1] if pm else None})
        elif m := _RE_AGGREGATE_HDR.match(stripped):
            # `route-policy NAME` is the attribute policy of the aggregate.
            recorded, gap = parse_aggregate_options(m[1], (m[2] or "").split(), policy_keyword="route-policy")
            if gap:
                origin_context_gaps.append(gap)
            aggregates.append(recorded)

    def flush() -> None:
        nonlocal current_kind, current_name, current_body
        if current_kind is not None:
            fields = _parse_group_body(current_body)
            if current_kind == "neighbor-group":
                neighbor_groups[current_name] = fields
            elif current_kind == "af-group":
                fields["afi_activated"] = True  # An af-group is an address family.
                af_groups[current_name] = fields
            elif current_kind == "session-group":
                session_groups[current_name] = fields
            elif current_kind == "neighbor":
                neighbors.append({"addr": current_name, **fields})
        current_kind, current_name, current_body = None, None, []

    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped == "!":
            continue
        indent = len(raw) - len(raw.lstrip(" "))

        if indent == 0:
            flush()
            if m := _RE_ROUTER_BGP.match(stripped):
                asn = int(m[1])
            continue

        if indent == 1:
            flush()
            process_family = None
            if m := _RE_ANY_ADDRESS_FAMILY.match(stripped):
                process_family = m[1]
            elif stripped == "default-information originate":
                default_originate_afs.append(4)
            elif m := _RE_NEIGHBOR_GROUP_HDR.match(stripped):
                current_kind, current_name = "neighbor-group", m[1]
            elif m := _RE_AF_GROUP_HDR.match(stripped):
                current_kind, current_name = "af-group", m[1]
            elif m := _RE_SESSION_GROUP_HDR.match(stripped):
                current_kind, current_name = "session-group", m[1]
            elif m := _RE_NEIGHBOR_HDR.match(stripped):
                current_kind, current_name = "neighbor", m[1]
            elif m := _RE_ROUTER_ID.match(stripped):
                router_id = m[1]
            elif m := _RE_CLUSTER_ID.match(stripped):
                cluster_id = parse_cluster_id(m[1])
            elif _RE_MED_ALWAYS.match(stripped):
                always_compare_med = True
            elif stripped == "bgp bestpath as-path multipath-relax":
                multipath_relax = True
            else:
                origin_statement(stripped)
            continue

        # IOS-XR takes `network`, `redistribute` and `aggregate-address` in
        # the address-family block of the process, one indent below the
        # header. This module reads the IPv4 unicast family. The same statement
        # in IPv6 unicast is recorded as a gap in `origin_context_gaps`.
        if process_family is not None:
            if (
                indent == 2
                and process_family in ("ipv4 unicast", "ipv6 unicast")
                and (parsed_paths := parse_maximum_paths(stripped))
            ):
                for kind, count in parsed_paths:
                    maximum_paths[f"{kind}_v{4 if process_family == 'ipv4 unicast' else 6}"] = count
            elif indent == 2 and stripped == "default-information originate":
                if process_family in ("ipv4 unicast", "ipv6 unicast"):
                    default_originate_afs.append(4 if process_family == "ipv4 unicast" else 6)
            elif indent == 2 and process_family == "ipv4 unicast":
                origin_statement(stripped)
            elif indent == 2 and process_family == "ipv6 unicast" and _RE_ORIGIN_STATEMENT.match(stripped):
                origin_context_gaps.append(f"address-family ipv6 unicast {stripped!r} is not recorded")
            continue

        # A line at 2 or more spaces of indent belongs to the open named block.
        if current_kind is not None:
            current_body.append(stripped)
    flush()

    if asn is None:
        return None
    return {
        "asn": asn,
        "router_id": router_id,
        "cluster_id": cluster_id,
        **({"always_compare_med": True} if always_compare_med else {}),
        **({"maximum_paths": maximum_paths} if maximum_paths else {}),
        **({"multipath_relax": True} if multipath_relax else {}),
        **(
            {"default_information_originate_afs": sorted(set(default_originate_afs))}
            if default_originate_afs
            else {}
        ),
        "neighbor_groups": neighbor_groups,
        "af_groups": af_groups,
        "session_groups": session_groups,
        "neighbors": neighbors,
        "redistribute": redistribute,
        "networks": networks,
        "aggregates": aggregates,
        "origin_context_gaps": origin_context_gaps,
    }


def parse_bgp(text: str) -> dict[str, Any] | None:
    """Parse the default process and each IOS-XR ``vrf NAME`` sub-process.

    The top-level keys hold the default process.
    """
    lines = text.splitlines()
    base_lines: list[str] = []
    vrf_blocks: dict[str, list[str]] = {}
    active_vrf: str | None = None
    for raw in lines:
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if indent == 1 and (match := _RE_VRF_HDR.match(stripped)):
            active_vrf = match[1]
            vrf_blocks.setdefault(active_vrf, [])
            continue
        if active_vrf is not None:
            if indent <= 1 and stripped:
                active_vrf = None
            else:
                vrf_blocks[active_vrf].append(raw.removeprefix(" "))
                continue
        base_lines.append(raw)

    default = _parse_bgp_single("\n".join(base_lines))
    if default is None:
        return None
    processes = [{**default, "vrf": "", "af": 4}]
    header = f"router bgp {default['asn']}"
    for vrf_name, body in vrf_blocks.items():
        scoped = _parse_bgp_single("\n".join([header, *body]))
        if scoped is None:
            continue
        scoped["router_id"] = scoped.get("router_id") or default.get("router_id")
        # The VRFs share the process statement `bgp cluster-id`.
        scoped["cluster_id"] = scoped.get("cluster_id") or default.get("cluster_id")
        # Groups declared globally are valid inheritance sources in VRF blocks.
        for key in ("neighbor_groups", "af_groups", "session_groups"):
            scoped[key] = {**default.get(key, {}), **scoped.get(key, {})}
        processes.append({**scoped, "vrf": vrf_name, "af": 4})
    return {**default, "processes": processes}


def resolve_bgp_sessions(bgp: dict[str, Any]) -> list[dict[str, Any]]:
    """Apply the inheritance chain to each neighbor. The result has the shape
    that `cisco_common.bgp_stage` emits as `BgpSession` nodes. Each field takes
    the first value in this order: the neighbor, its neighbor-group, the
    af-group, the session-group. The af-group is the af-group of the
    neighbor-group, or else of the neighbor. The session-group is the
    session-group of the neighbor, or else of the neighbor-group."""
    sessions: list[dict[str, Any]] = []
    for nb in bgp["neighbors"]:
        ng = bgp["neighbor_groups"].get(nb["use_neighbor_group"]) if nb["use_neighbor_group"] else None
        afg_name = (ng or {}).get("use_af_group") or nb["use_af_group"]
        afg = bgp["af_groups"].get(afg_name) if afg_name else None
        sg_name = nb["use_session_group"] or (ng or {}).get("use_session_group")
        sg = bgp["session_groups"].get(sg_name) if sg_name else None
        chain = (nb, ng, afg, sg)

        def resolve(key: str, _chain: tuple = chain) -> Any:
            for src in _chain:
                if src is not None and src.get(key) is not None:
                    return src[key]
            return None

        import_policy = resolve("import_policy")
        export_policy = resolve("export_policy")
        gaps = [
            f"undefined {kind} {name}"
            for kind, name, fields in (
                ("neighbor-group", nb["use_neighbor_group"], ng),
                ("af-group", afg_name, afg),
                ("session-group", sg_name, sg),
            )
            if name and fields is None
        ]
        sessions.append(
            {
                "peer_ip": nb["addr"],
                "peer_asn": resolve("remote_as"),
                "local_asn": bgp["asn"],
                "afi_safi": ["ipv4-unicast"] if any((s or {}).get("afi_activated") for s in chain) else [],
                "import_policy_name": import_policy,
                "import_policy_kind": "rpl" if import_policy else None,
                "export_policy_name": export_policy,
                "export_policy_kind": "rpl" if export_policy else None,
                "state": "shutdown" if resolve("shutdown") else None,
                "route_reflector_client": resolve("route_reflector_client"),
                **({"cluster_id": resolve("cluster_id")} if resolve("cluster_id") else {}),
                **({"next_hop_self": resolve("next_hop_self")} if resolve("next_hop_self") else {}),
                **({"inheritance_gaps": gaps} if gaps else {}),
            }
        )
    return sessions


# --- prefix-set -------------------------------------------------------------------------

_RE_PREFIX_SET_HDR = re.compile(r"^prefix-set (\S+)$")
_RE_PREFIX_SET_LINE = re.compile(
    r"^(?P<prefix>\S+/\d+)(?:\s+ge\s+(?P<ge>\d+))?(?:\s+le\s+(?P<le>\d+))?(?:\s+eq\s+(?P<eq>\d+))?$"
)


def _resolve_length_range(plen: int, ge: int | None, le: int | None, eq: int | None) -> tuple[int, int]:
    """The default length range of a standalone prefix-set entry.
    Without ge, le or eq the range is [L,L], with `ge` alone
    [ge,32], with `le` alone [L,le], with both [ge,le], and with `eq` [eq,eq]."""
    if eq is not None:
        return eq, eq
    if ge is not None and le is not None:
        return ge, le
    if ge is not None:
        return ge, 32
    if le is not None:
        return plen, le
    return plen, plen


def parse_prefix_lists(text: str) -> list[dict[str, Any]]:
    """The vendor-neutral `{"name", "kind", "entries"}` shape of
    `prefix-set NAME ... end-set` blocks. `seq` is synthetic and 1-based."""
    policies: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] | None = None
    seq = 0
    for raw in text.splitlines():
        stripped = raw.strip().rstrip(",")
        if not stripped or stripped == "!":
            continue
        if m := _RE_PREFIX_SET_HDR.match(stripped):
            entries = []
            policies.append({"name": m[1], "kind": "prefix-list", "entries": entries})
            seq = 0
            continue
        if stripped == "end-set":
            entries = None
            continue
        if entries is None:
            continue
        m = _RE_PREFIX_SET_LINE.match(stripped)
        if not m:
            continue
        prefix = m["prefix"]
        try:
            plen = int(prefix.rsplit("/", 1)[1])
        except (IndexError, ValueError):
            continue
        ge = int(m["ge"]) if m["ge"] else None
        le = int(m["le"]) if m["le"] else None
        eq = int(m["eq"]) if m["eq"] else None
        min_len, max_len = _resolve_length_range(plen, ge, le, eq)
        seq += 1
        entries.append(
            {
                "seq": seq,
                "action": "permit",
                "prefix": prefix,
                "ge": ge,
                "le": le,
                "eq": eq,
                "min_len": min_len,
                "max_len": max_len,
            }
        )
    return policies


# --- community-set / as-path-set ---------------------------------------------------------

_RE_COMMUNITY_SET_HDR = re.compile(r"^community-set (\S+)$")
_RE_AS_PATH_SET_HDR = re.compile(r"^as-path-set (\S+)$")
_RE_COMMUNITY_LITERAL = re.compile(r"^\d+:\d+$")
_RE_COMMUNITY_WILDCARD = re.compile(r"^(?:\d+|\*|\[\d+\.\.\d+\]):(?:\d+|\*|\[\d+\.\.\d+\])$")
_WELL_KNOWN_COMMUNITIES = {"internet", "no-export", "no-advertise", "local-as", "no-export-subconfed"}
_RE_REGEX_ELEMENT = re.compile(r"^ios-regex\s+(['\"])(.*)\1$")
_RE_AS_PATH_RUN = re.compile(r"^(neighbor-is|originates-from|passes-through)\s+(['\"])(.*)\2$")
_RE_AS_PATH_LENGTH = re.compile(r"^length\s+(eq|ge|le|is)\s+(\d+)$")


def _split_elements(text: str) -> list[str]:
    """Return the comma-separated elements of a set body or an inline
    `( ... )` set. A comma inside quotes or brackets does not split."""
    body = text.strip()
    if body.startswith("(") and body.endswith(")"):
        body = body[1:-1]
    out: list[str] = []
    depth, quote, start = 0, "", 0
    for i, c in enumerate(body):
        if quote:
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c in "[(":
            depth += 1
        elif c in "])":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(body[start:i].strip())
            start = i + 1
    out.append(body[start:].strip())
    return [e for e in out if e and not e.startswith("#")]


def community_element(text: str) -> tuple[str, str]:
    """Return one community-set element as `(match_type, value)`
    (simul/matchlist.py). A literal `ASN:NN` or a well-known name is
    `standard`. A pattern with `*` or a `[lo..hi]` range is `wildcard`.
    `ios-regex '...'` is `ios-regex`. Any other form (`dfa-regex`,
    `private-as`, a parameter) is `unsupported`."""
    element = text.strip()
    if _RE_COMMUNITY_LITERAL.match(element) or element.lower() in _WELL_KNOWN_COMMUNITIES:
        return "standard", element
    if _RE_COMMUNITY_WILDCARD.match(element):
        return "wildcard", element
    if m := _RE_REGEX_ELEMENT.match(element):
        return "ios-regex", m[2]
    return "unsupported", element


def as_path_element(text: str) -> tuple[str, str]:
    """Return one as-path-set element as `(match_type, value)`. The supported
    forms are `ios-regex '...'`,
    `neighbor-is|originates-from|passes-through '<asn> ...'` and
    `length eq|ge|le|is N`. Any other form (`dfa-regex`, `unique-length`,
    `is-local`, a range inside a run) is `unsupported`."""
    element = text.strip()
    if m := _RE_REGEX_ELEMENT.match(element):
        return "ios-regex", m[2]
    if (m := _RE_AS_PATH_RUN.match(element)) and all(t.isdigit() for t in m[3].split()):
        return m[1], m[3]
    if m := _RE_AS_PATH_LENGTH.match(element):
        return "length", f"{m[1]} {m[2]}"
    return "unsupported", element


def _parse_sets(text: str, header: re.Pattern[str], element: Any, kind: str) -> list[dict[str, Any]]:
    sets: list[dict[str, Any]] = []
    name: str | None = None
    body: list[str] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped == "!":
            continue
        if m := header.match(stripped):
            name, body = m[1], []
            continue
        if stripped == "end-set":
            if name is not None:
                elements = _split_elements(" ".join(body))
                entries = []
                for seq, e in enumerate(elements, start=1):
                    match_type, value = element(e)
                    entries.append({"seq": seq, "action": "permit", "match_type": match_type, "value": value})
                sets.append({"name": name, "kind": kind, "entries": entries})
            name = None
            continue
        if name is not None:
            body.append(stripped)
    return sets


_RE_NAMES_A_SET = re.compile(
    r"\b(?:community matches-(?:any|every)|as-path in|delete community in|set community)\s+[^\s(]"
)


def names_a_set(route_policy_text: str) -> bool:
    """Return whether a route-policy references a community-set or an
    as-path-set by name. The fetch in `iosxr.py` reads the sets in that case."""
    return _RE_NAMES_A_SET.search(route_policy_text) is not None


def parse_community_sets(text: str) -> list[dict[str, Any]]:
    """Parse `community-set NAME ... end-set` blocks into `{"name", "kind":
    "community-list", "entries"}`. Each element is a `permit` entry
    (simul/matchlist.py)."""
    return _parse_sets(text, _RE_COMMUNITY_SET_HDR, community_element, "community-list")


def parse_as_path_sets(text: str) -> list[dict[str, Any]]:
    """Parse `as-path-set NAME ... end-set` blocks into `{"name", "kind":
    "as-path-list", "entries"}`. Each element is a `permit` entry
    (simul/matchlist.py)."""
    return _parse_sets(text, _RE_AS_PATH_SET_HDR, as_path_element, "as-path-list")


# --- route-policy (RPL) ------------------------------------------------------------------

_RE_ROUTE_POLICY_HDR = re.compile(r"^route-policy (\S+)$")
_RE_IF = re.compile(r"^if (.+) then$")
_RE_ELSEIF = re.compile(r"^elseif (.+) then$")
_RE_ELSE = re.compile(r"^else$")
_RE_ENDIF = re.compile(r"^endif$")

_RE_SET_LOCAL_PREF = re.compile(r"^set local-preference (\d+)$")
_RE_SET_MED = re.compile(r"^set med (\d+)$")
_RE_SET_ORIGIN = re.compile(r"^set origin (igp|egp|incomplete)$")
_RE_SET_TAG = re.compile(r"^set tag (\d+)$")
_RE_SET_WEIGHT = re.compile(r"^set weight (\d+)$")
_RE_SET_NEXT_HOP = re.compile(r"^set next-hop (\d+\.\d+\.\d+\.\d+)$")
_RE_PREPEND = re.compile(r"^prepend as-path (\d+)(?: (\d+))?$")
_RE_APPLY = re.compile(r"^apply ([^\s(]+)$")
_RE_SET_COMMUNITY = re.compile(r"^set community (\(.*\)|[^\s(]+)(?: (additive))?$")
_RE_DELETE_COMMUNITY_IN = re.compile(r"^delete community in ([^\s(]+)$")

# The words that precede an inline `( ... )` set in a guard. Any other `(`
# opens a group.
_SET_OPENERS = {"in", "matches-any", "matches-every"}
_COMPARE_OPS = {"eq", "ge", "le", "is"}
_COMPARE_ATTRIBUTES = {"med": "med", "local-preference": "local_pref", "tag": "tag"}


def _parse_block(lines: list[str], i: int) -> tuple[list[dict[str, Any]], int]:
    """Return the items up to the `elseif`, `else` or `endif` that closes this
    level, or up to the end. An `if` is parsed recursively."""
    items: list[dict[str, Any]] = []
    n = len(lines)
    while i < n:
        line = lines[i]
        if _RE_ELSEIF.match(line) or _RE_ELSE.match(line) or _RE_ENDIF.match(line):
            return items, i
        if m := _RE_IF.match(line):
            body, i = _parse_block(lines, i + 1)
            branches = [{"guard": m[1], "body": body}]
            while i < n:
                if m2 := _RE_ELSEIF.match(lines[i]):
                    body, i = _parse_block(lines, i + 1)
                    branches.append({"guard": m2[1], "body": body})
                elif _RE_ELSE.match(lines[i]):
                    body, i = _parse_block(lines, i + 1)
                    branches.append({"guard": None, "body": body})
                else:  # endif
                    i += 1
                    break
            items.append({"type": "if", "branches": branches})
            continue
        items.append({"type": "line", "text": line})
        i += 1
    return items, i


def _tokenize_body(lines: list[str]) -> list[dict[str, Any]]:
    """Return the items of a route-policy body. `if`, `elseif`, `else` and
    `endif` are self-delimiting RPL keywords, and the indentation is not read.
    A stray closing keyword at the top level is kept as statement text.
    `_make_entry` reports it as unsupported."""
    items: list[dict[str, Any]] = []
    i = 0
    while i < len(lines):
        block, i = _parse_block(lines, i)
        items.extend(block)
        if i < len(lines):
            items.append({"type": "line", "text": lines[i]})
            i += 1
    return items


# --- guard expressions


def _guard_tokens(text: str) -> list[str]:
    """Return the tokens of a guard. A token is a word, a quoted string, a
    grouping parenthesis, or an inline set `( ... )` after `in`, `matches-any`
    or `matches-every`."""
    tokens: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c in "'\"":
            j = text.find(c, i + 1)
            j = n - 1 if j < 0 else j
            tokens.append(text[i : j + 1])
            i = j + 1
        elif c == "(" and tokens and tokens[-1] in _SET_OPENERS:
            depth, j = 0, i
            while j < n:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            tokens.append(text[i : j + 1])
            i = j + 1
        elif c in "()":
            tokens.append(c)
            i += 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in "()'\"":
                j += 1
            tokens.append(text[i:j])
            i = j
    return tokens


def _atom(words: list[str]) -> dict[str, Any]:
    """One boolean atom as a `match_expr` node
    (simul/compile.py), or `{"unsupported": text}`."""
    text = " ".join(words)
    w = words
    inline = len(w) == 3 and w[2].startswith("(")
    if len(w) == 3 and w[:2] == ["destination", "in"]:
        return {"prefixes": _split_elements(w[2])} if inline else {"prefix_list": w[2]}
    if len(w) == 3 and w[:2] == ["as-path", "in"]:
        if inline:
            return {"as_path": [list(as_path_element(e)) for e in _split_elements(w[2])]}
        return {"as_path_list": w[2]}
    if len(w) == 4 and w[:2] == ["as-path", "length"] and w[2] in _COMPARE_OPS and w[3].isdigit():
        return {"compare": "as_path_length", "op": w[2], "value": int(w[3])}
    if len(w) == 3 and w[0] == "as-path" and w[1] in {"neighbor-is", "originates-from", "passes-through"}:
        match_type, value = as_path_element(f"{w[1]} {w[2]}")
        return {"as_path": [[match_type, value]]}
    if len(w) == 3 and w[0] == "community" and w[1] in {"matches-any", "matches-every"}:
        every = w[1] == "matches-every"
        if inline:
            return {
                "communities": [list(community_element(e)) for e in _split_elements(w[2])],
                "every": every,
            }
        return {"community_list": w[2], "every": every}
    if len(w) == 3 and w[0] in _COMPARE_ATTRIBUTES and w[1] in _COMPARE_OPS and w[2].isdigit():
        return {"compare": _COMPARE_ATTRIBUTES[w[0]], "op": w[1], "value": int(w[2])}
    if len(w) == 3 and w[:2] == ["origin", "is"] and w[2] in {"igp", "egp", "incomplete"}:
        return {"origin": w[2]}
    if len(w) == 2 and w[0] == "apply":
        return {"call": w[1]}
    return {"unsupported": text}


class _GuardParser:
    """`or` binds loosest, then `and`, then `not`. Parentheses group."""

    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def expression(self) -> dict[str, Any]:
        parts = [self.conjunction()]
        while self.peek() == "or":
            self.take()
            parts.append(self.conjunction())
        return parts[0] if len(parts) == 1 else {"or": parts}

    def conjunction(self) -> dict[str, Any]:
        parts = [self.negation()]
        while self.peek() == "and":
            self.take()
            parts.append(self.negation())
        return parts[0] if len(parts) == 1 else {"and": parts}

    def negation(self) -> dict[str, Any]:
        if self.peek() == "not":
            self.take()
            return {"not": self.negation()}
        if self.peek() == "(":
            self.take()
            inner = self.expression()
            if self.peek() != ")":
                raise ValueError("unbalanced parenthesis")
            self.take()
            return inner
        words: list[str] = []
        while self.peek() not in (None, "and", "or", ")", "("):
            words.append(self.take())
        if not words:
            raise ValueError("empty atom")
        return _atom(words)


def guard_expression(guard: str) -> dict[str, Any]:
    """Return an RPL guard as a `match_expr` tree (simul/compile.py). The tree
    has `and` and `or` lists, `not`, and the atoms of `_atom`. A guard that
    does not parse is one `unsupported` atom with the whole text."""
    parser = _GuardParser(_guard_tokens(guard))
    try:
        node = parser.expression()
    except (ValueError, IndexError):
        return {"unsupported": guard.strip()}
    if parser.peek() is not None:
        return {"unsupported": guard.strip()}
    return node


def _atoms(node: dict[str, Any]) -> list[dict[str, Any]]:
    if "and" in node or "or" in node:
        return [a for child in node.get("and") or node.get("or") or () for a in _atoms(child)]
    if "not" in node:
        return _atoms(node["not"])
    return [node]


def _flat_fields(node: dict[str, Any]) -> dict[str, Any] | None:
    """Return the guard as plain `match_*` fields, or None when the fields
    cannot express the guard. The fields express a top-level `and`-chain of
    named prefix sets, AS-path sets, community sets with matches-any, and
    `med` and `tag` equality, with each kind at most once. The flat fields OR
    the names of one kind, and RPL ANDs them."""
    conjuncts = node.get("and", [node])
    fields: dict[str, Any] = {}
    for atom in conjuncts:
        if "prefix_list" in atom and "match_prefix_lists" not in fields:
            fields["match_prefix_lists"] = [atom["prefix_list"]]
        elif "as_path_list" in atom and "match_as_path_lists" not in fields:
            fields["match_as_path_lists"] = [atom["as_path_list"]]
        elif "community_list" in atom and not atom.get("every") and "match_community_lists" not in fields:
            fields["match_community_lists"] = [atom["community_list"]]
        elif atom.get("compare") == "med" and atom["op"] in {"eq", "is"} and "match_metric" not in fields:
            fields["match_metric"] = atom["value"]
        elif atom.get("compare") == "tag" and atom["op"] in {"eq", "is"} and "match_tags" not in fields:
            fields["match_tags"] = [atom["value"]]
        else:
            return None
    return fields


def _guard_fields(guard: str) -> dict[str, Any]:
    """Return a branch guard as RoutePolicyEntry fields.

    A plain `and`-chain that the flat `match_*` fields express exactly is
    stored in these fields. Any other guard (`or`, `not`, parentheses, an
    inline set, `matches-every`, a comparison other than equality, a repeated
    kind) is stored whole as `match_expr` (JSON). For such a guard, the flat
    fields list each set and each policy that the guard references
    (`match_policies`). An atom that the engine cannot evaluate is listed in
    `match_unsupported`. The engine evaluates the whole guard as false and
    reports it."""
    node = guard_expression(guard)
    flat = _flat_fields(node)
    if flat is not None:
        return flat
    fields: dict[str, Any] = {"match_expr": json.dumps(node, sort_keys=True, separators=(",", ":"))}
    for atom in _atoms(node):
        if "prefix_list" in atom:
            fields.setdefault("match_prefix_lists", []).append(atom["prefix_list"])
        elif "as_path_list" in atom:
            fields.setdefault("match_as_path_lists", []).append(atom["as_path_list"])
        elif "community_list" in atom:
            fields.setdefault("match_community_lists", []).append(atom["community_list"])
        elif "call" in atom:
            fields.setdefault("match_policies", []).append(atom["call"])
        elif "unsupported" in atom:
            fields.setdefault("match_unsupported", []).append(atom["unsupported"])
    return fields


# --- statements


def _literal_communities(elements: list[tuple[str, str]]) -> list[str] | None:
    if elements and all(t == "standard" and v.lower() != "internet" for t, v in elements):
        return [v for _t, v in elements]
    return None


def _make_entry(
    seq: int, stmt_lines: list[str], community_sets: dict[str, list[dict[str, Any]]] | None = None
) -> dict[str, Any]:
    """Return the fields of one RoutePolicyEntry from a run of simple
    (non-`if`) RPL statement lines.

    Every `set` clause with a schema field is stored in that field.
    `apply NAME` is `calls_policy`. `drop` and `done` are a terminal `action`
    (deny and permit), and no later line of the run is read. `pass` and a
    comment line set `passes`. Batfish converts a comment line with the
    implicit pass of a set clause. `set community` with a literal list, or
    with the name of a community-set of literals, is stored in
    `set_communities`. `delete community in NAME` is stored in
    `set_comm_list_delete`. Each other line (a set form with no field,
    `unsuppress-route`, a stray keyword) is kept verbatim in
    `set_unsupported`, and the engine reports it. A kept `set`, `delete` or
    `prepend` line sets `passes`."""
    community_sets = community_sets or {}
    entry: dict[str, Any] = {"seq": seq, "kind": "statement"}

    def unsupported(line: str) -> None:
        entry.setdefault("set_unsupported", []).append(line)
        if line.startswith(("set ", "delete ", "prepend ")):
            entry["passes"] = True

    for line in stmt_lines:
        if "action" in entry:
            break
        if line.startswith("#"):
            entry["passes"] = True
        elif m := _RE_SET_LOCAL_PREF.match(line):
            entry["set_local_pref"] = int(m[1])
        elif m := _RE_SET_MED.match(line):
            entry["set_metric"] = int(m[1])
        elif m := _RE_SET_ORIGIN.match(line):
            entry["set_origin"] = m[1]
        elif m := _RE_SET_TAG.match(line):
            entry["set_tag"] = int(m[1])
        elif m := _RE_SET_WEIGHT.match(line):
            entry["set_weight"] = int(m[1])
        elif m := _RE_SET_NEXT_HOP.match(line):
            entry["set_next_hop"] = m[1]
        elif m := _RE_PREPEND.match(line):
            count = int(m[2]) if m[2] else 1
            entry.setdefault("set_as_path_prepend", []).extend([int(m[1])] * count)
        elif m := _RE_APPLY.match(line):
            entry["calls_policy"] = m[1]
        elif m := _RE_SET_COMMUNITY.match(line):
            if m[1].startswith("("):
                values = _literal_communities([community_element(e) for e in _split_elements(m[1])])
            else:
                members = community_sets.get(m[1])
                values = (
                    _literal_communities([(e["match_type"], e["value"]) for e in members])
                    if members is not None
                    else None
                )
            if values is None:
                unsupported(line)
            else:
                entry["set_communities"] = values
                entry["set_communities_additive"] = m[2] == "additive"
        elif m := _RE_DELETE_COMMUNITY_IN.match(line):
            entry["set_comm_list_delete"] = m[1]
        elif line == "drop":
            entry["action"] = "deny"
        elif line == "done":
            entry["action"] = "permit"
        elif line == "pass":
            entry["passes"] = True
        else:
            unsupported(line)
    return entry


_SET_LINE_PREFIXES = ("set ", "delete ", "prepend ")


def _runs(lines: list[str]) -> list[list[str]]:
    """Split the statement lines after an `apply` that a set line follows. One
    entry runs its sets before its `apply`. The split puts the later set line
    in the next entry, after the applied policy, as configured."""
    runs: list[list[str]] = [[]]
    for i, line in enumerate(lines):
        runs[-1].append(line)
        if _RE_APPLY.match(line) and any(later.startswith(_SET_LINE_PREFIXES) for later in lines[i + 1 :]):
            runs.append([])
    return [r for r in runs if r]


def _flatten_route_policy(
    lines: list[str], community_sets: dict[str, list[dict[str, Any]]] | None = None
) -> list[dict[str, Any]]:
    """The ordered `RoutePolicyEntry` field-dicts of one `route-policy NAME ...
    end-policy` body, with a synthetic 1-based `seq` in configured order."""
    entries: list[dict[str, Any]] = []
    seq = 0

    def add(entry: dict[str, Any], parent: int | None) -> dict[str, Any]:
        if parent is not None:
            entry["parent_seq"] = parent
        entries.append(entry)
        return entry

    def emit(items: list[dict[str, Any]], parent: int | None) -> None:
        nonlocal seq
        pending: list[str] = []

        def flush() -> None:
            nonlocal seq
            for run in _runs(pending):
                seq += 1
                add(_make_entry(seq, run, community_sets), parent)
            pending.clear()

        for item in items:
            if item["type"] == "line":
                pending.append(item["text"])
                continue
            flush()
            branch_entries: list[dict[str, Any]] = []
            for br in item["branches"]:
                body = br["body"]
                texts = [b["text"] for b in body if b["type"] == "line"]
                inline = len(texts) == len(body) and len(_runs(texts)) <= 1
                seq += 1
                entry = (
                    _make_entry(seq, texts, community_sets) if inline else {"seq": seq, "kind": "statement"}
                )
                if br["guard"] is not None:
                    entry.update(_guard_fields(br["guard"]))
                branch_entries.append(add(entry, parent))
                if not inline:
                    emit(body, entry["seq"])
            for current, following in itertools.pairwise(branch_entries):
                current["continues"] = True
                current["continue_seq"] = following["seq"]
        flush()

    emit(_tokenize_body(lines), None)
    return entries


def parse_route_policies(
    text: str, community_sets: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """Parse `route-policy NAME ... end-policy` blocks into the vendor-neutral
    `{"name", "kind": "rpl", "entries"}` shape. With `community_sets`
    (`parse_community_sets`), `set community NAME` resolves to the literal
    members of the set."""
    members = {s["name"]: s["entries"] for s in community_sets or ()}
    policies: list[dict[str, Any]] = []
    current_name: str | None = None
    body: list[str] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped == "!":
            continue
        if m := _RE_ROUTE_POLICY_HDR.match(stripped):
            current_name, body = m[1], []
            continue
        if stripped == "end-policy":
            if current_name is not None:
                policies.append(
                    {"name": current_name, "kind": "rpl", "entries": _flatten_route_policy(body, members)}
                )
            current_name = None
            continue
        if current_name is not None:
            body.append(stripped)
    return policies


# --- entry point ---------------------------------------------------------------------


def parse(
    bgp: dict[str, Any] | None,
    prefix_set_text: str,
    route_policy_text: str,
    community_set_text: str = "",
    as_path_set_text: str = "",
) -> dict[str, Any]:
    """Build the shape that `cisco_common.bgp_stage` reads, from the result of
    `parse_bgp` for the `router bgp` extract and from the other extract texts.
    `xr_route_policies` and `xr_prefix_lists` are always present and can be
    empty. `xr_community_lists` and `xr_as_path_lists` are present only when a
    set exists. `xr_bgp`, `xr_bgp_sessions`, `xr_bgp_redistribute` and
    `xr_bgp_processes` are present only when the device has a `router bgp`
    process."""
    community_sets = parse_community_sets(community_set_text)
    as_path_sets = parse_as_path_sets(as_path_set_text)
    out: dict[str, Any] = {
        "xr_route_policies": parse_route_policies(route_policy_text, community_sets),
        "xr_prefix_lists": parse_prefix_lists(prefix_set_text),
    }
    if community_sets:
        out["xr_community_lists"] = community_sets
    if as_path_sets:
        out["xr_as_path_lists"] = as_path_sets
    if bgp is not None:
        out["xr_bgp"] = {"asn": bgp["asn"], "router_id": bgp["router_id"]}
        out["xr_bgp_sessions"] = resolve_bgp_sessions(bgp)
        out["xr_bgp_redistribute"] = [r for r in bgp["redistribute"] if r["policy_name"]]
        out["xr_bgp_processes"] = [
            {
                "vrf": process.get("vrf") or "",
                "af": process.get("af", 4),
                "asn": process["asn"],
                "router_id": process.get("router_id"),
                **({"cluster_id": process["cluster_id"]} if process.get("cluster_id") else {}),
                **({"always_compare_med": True} if process.get("always_compare_med") else {}),
                **({"maximum_paths": process["maximum_paths"]} if process.get("maximum_paths") else {}),
                **({"multipath_relax": True} if process.get("multipath_relax") else {}),
                **(
                    {"default_information_originate_afs": process["default_information_originate_afs"]}
                    if process.get("default_information_originate_afs")
                    else {}
                ),
                "sessions": resolve_bgp_sessions(process),
                "redistribute": process["redistribute"],
                "networks": process["networks"],
                "aggregates": process["aggregates"],
                "origin_context_gaps": process["origin_context_gaps"],
            }
            for process in bgp["processes"]
        ]
    return out
