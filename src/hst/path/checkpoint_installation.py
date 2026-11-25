"""Observed VS policy bindings outrank management installation targets."""

from typing import Any

import hst.path as path

QUERY = """
MATCH (i:Interface:Obj {uid:$in_if, collection_ts: $snap})-[c:IN_CONTEXT]->(fi:FirewallInstance)
      -[e:ENFORCES]->(rb:FwRulebase)
MATCH (i)-[iv:IN_VRF]->(vrf:VrfInstance)
WHERE NOT i:Retired AND NOT fi:Retired AND NOT rb:Retired AND NOT vrf:Retired
 AND c._retired_at IS NULL AND e._retired_at IS NULL AND iv._retired_at IS NULL
 AND i:Obj AND i.collection_ts=$snap AND rb.collection_ts = $snap
 AND e.context_uid=vrf.uid AND coalesce(rb.kind,'access')=$kind
 AND coalesce(rb.chain,'forward')=$chain
 AND (e.ingress_interface_uid='*' OR e.ingress_interface_uid=$in_if)
 AND (e.egress_interface_uid='*' OR e.egress_interface_uid=$out_if)
 AND e.address_family=$af
RETURN rb.uid AS rb_uid, rb.name AS rb_name, rb.vendor AS vendor, rb.af AS af,
 rb.default_action AS default_action, rb.default_action_unknown AS default_action_unknown,
 rb.global_state_policy AS global_state_policy, rb.state_policy_basis AS state_policy_basis,
 rb.established_default_unknown AS established_default_unknown,
 rb.match_context AS match_context, rb.chain AS chain,
 fi.gateway_object_uid AS owner_raw_uid,
 NOT coalesce((e.installed=true AND e.coverage IN ['complete','complete-empty']
      AND rb.configured_revision IS NOT NULL
      AND e.installed_revision=rb.configured_revision),false) AS approximate
ORDER BY rb_name
"""


def candidates(session: Any, ingress: str, egress: str | None, af: int, chain: str):
    return path._read(session, QUERY, in_if=ingress, out_if=egress, af=af, chain=chain, kind="access")
