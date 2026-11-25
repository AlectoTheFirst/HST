"""Constants every reasoner module shares."""

from __future__ import annotations

from hst.core.labels import DEVICE_ROLES

# A statement deletes at most `$limit` reasoner edges of one run.
CLEAR = (
    "MATCH (n:Obj {collection_ts: $cts})-[r]->() "
    "WHERE r._scope = 'reasoner' AND r.collection_ts = $cts "
    "WITH r LIMIT $limit DELETE r RETURN count(*) AS n"
)
# `infra` is the reasoner's own marker.
CLEAR_PROPS = (
    "CALL { MATCH (ep:Endpoint:Obj) WHERE ep.infra IS NOT NULL "
    "AND ep.collection_ts = $cts REMOVE ep.infra } "
    "CALL { MATCH (fp:FabricPort:Obj) WHERE fp.binding_issue IS NOT NULL "
    "AND fp.collection_ts = $cts REMOVE fp.binding_issue, fp.binding_ports }"
)

# Device.role values that terminate a connected prefix.
GATEWAY_ROLES = ["router", "gateway", "sdwan-hub", "sdwan-edge"]
if not set(GATEWAY_ROLES) <= DEVICE_ROLES:
    raise RuntimeError("GATEWAY_ROLES must be a subset of core.labels.DEVICE_ROLES")

# CONNECTED_TO sources that state a cable before cable-from-last-connection runs.
STATED_CABLE_SOURCES = ["unifi", "unifi-uplink", "unifi-lldp"]

# Equinix circuit states (`VirtualCircuit.state`). A Fabric connection that
# carries traffic is ACTIVE. A Network Edge device link group that carries
# traffic is PROVISIONED. A circuit in one of these 2 states gives a cable and
# a stretch observation. A circuit in another state or without a state gives
# neither.
ACTIVE_CIRCUIT_STATES = ["ACTIVE", "PROVISIONED"]
# The states of a circuit that does not carry traffic again. The route and the
# catalog count and list such a circuit as ended.
ENDED_CIRCUIT_STATES = ["DEPROVISIONED", "DELETED", "CANCELLED"]
