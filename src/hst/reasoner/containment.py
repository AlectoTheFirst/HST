"""The address-containment rule."""

from __future__ import annotations

import ipaddress
from typing import Any

# A candidate is an address that a live Endpoint, Interface or Device
# (manual.py) holds via HAS_IP. A mention row (an address in a policy object)
# has no holder and is no candidate. Targets are connected prefixes only.
#
# All 3 reads start from the nodes of the run through the obj_cts index
# (`:Obj {collection_ts: $cts}`).
CONTAINMENT_ADDRESSES = """
MATCH (h)-[r:HAS_IP]->(ia:IpAddress:Obj {collection_ts: $cts})
WHERE r._retired_at IS NULL AND NOT h:Retired AND NOT ia:Retired
RETURN DISTINCT ia.uid AS uid, ia.ip AS ip, ia.l3dom AS l3dom, ia.anchor AS anchor
"""

CONTAINMENT_PREFIXES = """
MATCH (p:Prefix:Obj {collection_ts: $cts})
WHERE p.kind = 'connected' AND NOT p:Retired
RETURN DISTINCT p.uid AS uid, p.cidr AS cidr, p.l3dom AS l3dom, p.anchor AS anchor
"""

# The prefixes that serve a bridge domain, via the gateway interface of the
# domain. The query reads the GATEWAY_FOR edges that the gateway rules
# committed before this read.
CONTAINMENT_BD_MAP = """
MATCH (s:BridgeDomain:Obj {collection_ts: $cts})<-[rz:REALIZES]-(v:VlanInstance)<-[bt:BOUND_TO]-(i:Interface)
      -[g:GATEWAY_FOR]->(p:Prefix)
WHERE NOT s:Retired AND NOT v:Retired AND NOT i:Retired AND NOT p:Retired
  AND rz._retired_at IS NULL AND bt._retired_at IS NULL
RETURN DISTINCT s.uid AS bd, p.uid AS pfx
"""

# The NOT EXISTS skips pairs a collector (or a carry) already asserted.
CONTAINMENT_WRITE = """
UNWIND $pairs AS pair
MATCH (ia:IpAddress:Obj {uid: pair.ip, collection_ts: $cts})
WHERE NOT ia:Retired
MATCH (p:Prefix:Obj {uid: pair.pfx, collection_ts: $cts})
WHERE NOT p:Retired
  AND NOT EXISTS { MATCH (ia)-[e:IN]->(p) WHERE e._retired_at IS NULL }
MERGE (ia)-[c:IN {source: 'reasoner'}]->(p)
SET c.derived = true, c.rule = 'address-containment',
    c._scope = 'reasoner', c.collection_ts = $cts, c.collected_at = $ts
RETURN count(*) AS n
"""


def containment_pairs(
    addresses: list[dict[str, Any]],
    prefixes: list[dict[str, Any]],
    bd_serving: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """The (address uid, prefix uid) pairs of the address-containment rule.

    The function is pure. The inputs are plain dicts in the row shapes of
    `CONTAINMENT_ADDRESSES`, `CONTAINMENT_PREFIXES` and `CONTAINMENT_BD_MAP`.
    The result is the sorted pairs without duplicates. The anchor of an
    address selects the join.

    - A `bd:` anchor joins the prefixes that serve that bridge domain. When
      no gateway chain gives a prefix for the domain (a UniFi SVI has no
      BOUND_TO edge), it joins the containing prefixes of the same l3dom.
    - A `vrf:` anchor joins the prefixes with the same anchor only.
    - A scope-string anchor (unsegmented addressing) joins by l3dom.

    The result has one pair per containing prefix instance. N gateways that
    serve one subnet in one routing domain give N edges, and readers use
    DISTINCT. A malformed ip or cidr is skipped without an error.

    Prefixes are indexed by (version, prefix length) and network. Each
    address is looked up once per prefix length in the index.
    """
    served: dict[str, set[str]] = {}
    for row in bd_serving:
        served.setdefault(row["bd"], set()).add(row["pfx"])
    by_len: dict[tuple[int, int], dict[Any, list[dict[str, Any]]]] = {}
    for pfx in prefixes:
        try:
            net = ipaddress.ip_network(pfx["cidr"])
        except (TypeError, ValueError):
            continue
        by_len.setdefault((net.version, net.prefixlen), {}).setdefault(net, []).append(pfx)
    lengths = {v: sorted(n for ver, n in by_len if ver == v) for v in (4, 6)}
    pairs: set[tuple[str, str]] = set()
    for a in addresses:
        try:
            addr = ipaddress.ip_address(a["ip"])
        except (TypeError, ValueError):
            continue
        containing = [
            pfx
            for n in lengths[addr.version]
            for pfx in by_len[(addr.version, n)].get(ipaddress.ip_network((addr, n), strict=False), ())
        ]
        anchor = a.get("anchor") or ""
        if anchor.startswith("vrf:"):
            chosen = [pfx for pfx in containing if pfx.get("anchor") == anchor]
        elif anchor.startswith("bd:"):
            in_bd = served.get(anchor, set())
            chosen = [pfx for pfx in containing if pfx["uid"] in in_bd]
            if not chosen:
                chosen = [pfx for pfx in containing if pfx.get("l3dom") == a.get("l3dom")]
        else:
            chosen = [pfx for pfx in containing if pfx.get("l3dom") == a.get("l3dom")]
        pairs.update((a["uid"], pfx["uid"]) for pfx in chosen)
    return [{"ip": ip_uid, "pfx": pfx_uid} for ip_uid, pfx_uid in sorted(pairs)]
