"""Neo4j driver helpers, constraints, and indexes."""

from __future__ import annotations

import atexit
import contextlib
import ipaddress
import logging
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from urllib.parse import SplitResult, urlsplit

from neo4j import Driver, GraphDatabase, Session, TrustCustomCAs

from .config import Settings

log = logging.getLogger(__name__)

# `hst init-db` applies these statements idempotently.
CONSTRAINT_STATEMENTS: list[str] = [
    "CREATE CONSTRAINT obj_uid_cts IF NOT EXISTS FOR (n:Obj) REQUIRE (n.uid, n.collection_ts) IS UNIQUE",
    "CREATE INDEX obj_cts IF NOT EXISTS FOR (n:Obj) ON (n.collection_ts)",
    "CREATE INDEX device_serial IF NOT EXISTS FOR (n:Device) ON (n.serial)",
    "CREATE INDEX device_hostname_fqdn IF NOT EXISTS FOR (n:Device) ON (n.hostname_fqdn)",
    "CREATE INDEX ipaddress_ip IF NOT EXISTS FOR (n:IpAddress) ON (n.ip)",
    "CREATE INDEX prefix_cidr IF NOT EXISTS FOR (n:Prefix) ON (n.cidr)",
    "CREATE INDEX endpoint_mac IF NOT EXISTS FOR (n:Endpoint) ON (n.mac)",
    "CREATE INDEX fwrule_rule_uid IF NOT EXISTS FOR (n:FwRule) ON (n.rule_uid)",
    "CREATE INDEX interface_name IF NOT EXISTS FOR (n:Interface) ON (n.name)",
    "CREATE INDEX interface_edge_device_uid IF NOT EXISTS FOR (n:Interface) ON (n.edge_device_uid)",
    "CREATE INDEX dnsrecord_fqdn IF NOT EXISTS FOR (n:DnsRecord) ON (n.fqdn)",
    # Neither name is unique.
    "CREATE INDEX vrfinstance_name IF NOT EXISTS FOR (n:VrfInstance) ON (n.name)",
    "CREATE INDEX routingdomain_name IF NOT EXISTS FOR (n:RoutingDomain) ON (n.name)",
    "CREATE INDEX zpaappsegment_zpa_id IF NOT EXISTS FOR (n:ZpaAppSegment) ON (n.zpa_id)",
    "CREATE INDEX zpaappsegment_name IF NOT EXISTS FOR (n:ZpaAppSegment) ON (n.name)",
    "CREATE INDEX zpasegmentgroup_name IF NOT EXISTS FOR (n:ZpaSegmentGroup) ON (n.name)",
    "CREATE INDEX zpasegmentgroup_zpa_id IF NOT EXISTS FOR (n:ZpaSegmentGroup) ON (n.zpa_id)",
    "CREATE INDEX identitygroup_name IF NOT EXISTS FOR (n:IdentityGroup) ON (n.name)",
    "CREATE INDEX zialocation_name IF NOT EXISTS FOR (n:ZiaLocation) ON (n.name)",
    "CREATE INDEX tunnel_source_ip IF NOT EXISTS FOR (n:Tunnel) ON (n.source_ip)",
    # The range indexes answer the `>=` and `<=` comparisons on the fixed-width address keys.
    "CREATE INDEX ipaddress_ip_key IF NOT EXISTS FOR (n:IpAddress) ON (n.ip_key)",
    "CREATE INDEX endpoint_ip_key IF NOT EXISTS FOR (n:Endpoint) ON (n.ip_key)",
    "CREATE INDEX prefix_lo_key IF NOT EXISTS FOR (n:Prefix) ON (n.lo_key)",
    "CREATE INDEX connected_to_source_cts IF NOT EXISTS "
    "FOR ()-[r:CONNECTED_TO]-() ON (r.source, r.collection_ts)",
    "CREATE INDEX bridged_to_source_cts IF NOT EXISTS "
    "FOR ()-[r:BRIDGED_TO]-() ON (r.source, r.collection_ts)",
    "CREATE FULLTEXT INDEX obj_names IF NOT EXISTS FOR (n:Obj) ON EACH [n.name, n.description, n.hostname]",
    "CREATE INDEX device_cts IF NOT EXISTS FOR (n:Device) ON (n.collection_ts)",
    "CREATE INDEX interface_cts IF NOT EXISTS FOR (n:Interface) ON (n.collection_ts)",
    "CREATE INDEX port_cts IF NOT EXISTS FOR (n:Port) ON (n.collection_ts)",
    "CREATE INDEX ipaddress_cts IF NOT EXISTS FOR (n:IpAddress) ON (n.collection_ts)",
    "CREATE INDEX prefix_cts IF NOT EXISTS FOR (n:Prefix) ON (n.collection_ts)",
    "CREATE INDEX vrfinstance_cts IF NOT EXISTS FOR (n:VrfInstance) ON (n.collection_ts)",
    "CREATE INDEX endpoint_cts IF NOT EXISTS FOR (n:Endpoint) ON (n.collection_ts)",
    "CREATE INDEX bridgedomain_cts IF NOT EXISTS FOR (n:BridgeDomain) ON (n.collection_ts)",
    "CREATE INDEX interface_uid IF NOT EXISTS FOR (n:Interface) ON (n.uid)",
    "CREATE INDEX device_uid IF NOT EXISTS FOR (n:Device) ON (n.uid)",
    "CREATE INDEX vrfinstance_uid IF NOT EXISTS FOR (n:VrfInstance) ON (n.uid)",
    "CREATE INDEX prefix_uid IF NOT EXISTS FOR (n:Prefix) ON (n.uid)",
    "CREATE INDEX fwrulebase_uid IF NOT EXISTS FOR (n:FwRulebase) ON (n.uid)",
    "CREATE INDEX ipaddress_uid IF NOT EXISTS FOR (n:IpAddress) ON (n.uid)",
    "CREATE INDEX netobject_uid IF NOT EXISTS FOR (n:NetObject) ON (n.uid)",
    "CREATE INDEX pbrpolicy_uid IF NOT EXISTS FOR (n:PbrPolicy) ON (n.uid)",
    "CREATE INDEX tunnel_uid IF NOT EXISTS FOR (n:Tunnel) ON (n.uid)",
    "CREATE INDEX gate_uid IF NOT EXISTS FOR (n:Gate) ON (n.uid)",
    "CREATE INDEX zpaappsegment_uid IF NOT EXISTS FOR (n:ZpaAppSegment) ON (n.uid)",
    "CREATE INDEX virtualservice_uid IF NOT EXISTS FOR (n:VirtualService) ON (n.uid)",
    # A graph can hold a duplicate uid of these labels.
    "CREATE INDEX meta_uid IF NOT EXISTS FOR (n:Meta) ON (n.uid)",
    "CREATE INDEX site_uid IF NOT EXISTS FOR (n:Site) ON (n.uid)",
    "CREATE INDEX site_code IF NOT EXISTS FOR (n:Site) ON (n.code)",
    "CREATE INDEX cyclerun_uid IF NOT EXISTS FOR (n:CycleRun) ON (n.uid)",
    "CREATE INDEX collectionrun_uid IF NOT EXISTS FOR (n:CollectionRun) ON (n.uid)",
    # The MAC joins of the reasoner (reasoner/catalog.py cable-from-endpoint-mac
    # and cable-from-last-connection) and the hostname lookups of the query
    # catalog use these 2 indexes.
    "CREATE INDEX interface_mac_cts IF NOT EXISTS FOR (n:Interface) ON (n.mac, n.collection_ts)",
    "CREATE INDEX device_hostname IF NOT EXISTS FOR (n:Device) ON (n.hostname)",
    # The trace's gateway read (path/session.py GATEWAYS) starts from the run's
    # GATEWAY_FOR edges.
    "CREATE INDEX gateway_for_cts IF NOT EXISTS FOR ()-[r:GATEWAY_FOR]-() ON (r.collection_ts)",
]


_DRIVERS: dict[tuple[str, str, str], Driver] = {}
_LOCK = threading.Lock()


def get_driver(settings: Settings) -> Driver:
    """The driver is thread-safe."""
    key = (settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)
    driver = _DRIVERS.get(key)
    if driver is None:
        with _LOCK:
            driver = _DRIVERS.get(key)
            if driver is None:
                driver = GraphDatabase.driver(
                    settings.neo4j_uri,
                    auth=(settings.neo4j_user, settings.neo4j_password),
                    # _retired_at and :Retired exist only after the first retirement.
                    notifications_min_severity="OFF",
                    **_tls_kwargs(settings.neo4j_uri, settings.neo4j_tls_ca_file),
                )
                _DRIVERS[key] = driver
    return driver


_SECURE_SCHEMES = {"bolt+s", "bolt+ssc", "neo4j+s", "neo4j+ssc"}
_PLAIN_SCHEMES = {"bolt", "neo4j"}


def _tls_kwargs(uri: str, ca_file: str) -> dict[str, Any]:
    parts = _split(uri)
    scheme = parts.scheme.lower() if parts else ""

    if ca_file:
        if scheme in _SECURE_SCHEMES:
            raise ValueError(
                f"neo4j_uri uses the {scheme!r} scheme, which carries its own TLS, and "
                "neo4j_tls_ca_file is set. Use a bolt:// or neo4j:// URI with "
                f"neo4j_tls_ca_file, or keep {scheme!r} and leave neo4j_tls_ca_file empty."
            )
        return {"encrypted": True, "trusted_certificates": TrustCustomCAs(ca_file)}

    if scheme in _PLAIN_SCHEMES:
        host = parts.hostname if parts else None
        if host and not _is_loopback_host(host):
            log.warning(
                "neo4j_uri (%s) is unencrypted and %r is not loopback: the bolt "
                "password and all query traffic cross the network in cleartext. Set "
                "neo4j_tls_ca_file or use a +s/+ssc scheme.",
                scheme,
                host,
            )
    return {}


def _is_loopback_host(host: str) -> bool:
    """A resolution failure returns False."""
    host = host.strip("[]")
    with contextlib.suppress(ValueError):
        return ipaddress.ip_address(host).is_loopback
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    return all(ipaddress.ip_address(info[4][0]).is_loopback for info in infos)


def close_drivers() -> None:
    with _LOCK:
        while _DRIVERS:
            _, driver = _DRIVERS.popitem()
            with contextlib.suppress(Exception):
                driver.close()


def close_driver(settings: Settings) -> None:
    """Close the cached driver of `settings` and remove it from the cache."""
    key = (settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)
    with _LOCK:
        driver = _DRIVERS.pop(key, None)
    if driver is not None:
        with contextlib.suppress(Exception):
            driver.close()


atexit.register(close_drivers)


@contextmanager
def session(settings: Settings, access_mode: str | None = None) -> Iterator[Session]:
    # `access_mode` is "READ" or "WRITE".
    kwargs: dict[str, Any] = {"database": settings.neo4j_database}
    if access_mode is not None:
        kwargs["default_access_mode"] = access_mode
    with get_driver(settings).session(**kwargs) as s:
        yield s


def init_db(s: Session) -> list[str]:
    applied = []
    # IF NOT EXISTS keeps an existing definition.
    stale = s.run(
        "SHOW FULLTEXT INDEXES YIELD name, properties "
        "WHERE name = 'obj_names' AND NOT 'hostname' IN properties "
        "RETURN name"
    ).data()
    if stale:
        s.run("DROP INDEX obj_names").consume()
        applied.append("DROP INDEX obj_names (definition without hostname)")
    # obj_uid is dropped before the composite constraint is created.
    for name, kind, plural in (
        ("obj_uid", "CONSTRAINT", "CONSTRAINTS"),
        ("obj_scope_seen", "INDEX", "INDEXES"),
    ):
        found = s.run(f"SHOW {plural} YIELD name WHERE name = $name RETURN name", name=name).data()
        if found:
            s.run(f"DROP {kind} {name}").consume()
            applied.append(f"DROP {kind} {name} (pre-cycle-model, superseded)")
    for stmt in CONSTRAINT_STATEMENTS:
        s.run(stmt).consume()
        applied.append(stmt.split(" IF NOT EXISTS")[0])
    return applied


def check(s: Session) -> dict[str, Any]:
    def count(query: str) -> int:
        # A bare aggregate returns exactly one row. single() has the type
        # Record | None.
        row = s.run(query).single()
        return int(row["c"]) if row else 0

    nodes = count("MATCH (n:Obj) RETURN count(n) AS c")
    retired = count("MATCH (n:Obj:Retired) RETURN count(n) AS c")
    rels = count("MATCH (:Obj)-[r]->(:Obj) RETURN count(r) AS c")
    constraints = [r["name"] for r in s.run("SHOW CONSTRAINTS YIELD name RETURN name")]
    return {"nodes": nodes, "nodes_retired": retired, "rels": rels, "constraints": constraints}


def same_endpoint(a: str, b: str) -> bool:
    """True when two bolt URIs have the same port and their hosts are equal or resolve to
    a common address. Every loopback address and the unspecified address count as one address."""
    first, second = _endpoint(a), _endpoint(b)
    if first is None or second is None or first[1] != second[1]:
        return False
    if first[0] == second[0]:
        return True
    return bool(_addresses(first[0]) & _addresses(second[0]))


def resolves(uri: str) -> bool:
    """True when the host of a bolt URI resolves to an address."""
    endpoint = _endpoint(uri)
    return endpoint is not None and bool(_addresses(endpoint[0]))


_LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]"}


def _split(uri: str) -> SplitResult | None:
    """Return `urlsplit` of the URI, or `None` when it cannot be parsed. A URI without a scheme gets `bolt://`."""
    try:
        return urlsplit(uri if "://" in uri else f"bolt://{uri}")
    except ValueError:
        return None


def _endpoint(uri: str) -> tuple[str, int] | None:
    parts = _split(uri)
    if parts is None:
        return None
    try:
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port or 7687
    except ValueError:
        return None
    if not host:
        return None
    return ("localhost" if host in _LOOPBACK else host, port)


def _resolve(host: str) -> list[str]:
    """The addresses `host` resolves to. A resolution failure returns an empty list."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return []
    return [str(info[4][0]) for info in infos]


def _addresses(host: str) -> frozenset[str]:
    """The addresses of `host` in one spelling per address. An IPv4-mapped IPv6 address is
    its IPv4 address. A loopback or unspecified address is `loopback`."""
    found: set[str] = set()
    for text in _resolve(host):
        try:
            parsed = ipaddress.ip_address(text.partition("%")[0])
        except ValueError:
            continue
        mapped = parsed.ipv4_mapped if isinstance(parsed, ipaddress.IPv6Address) else None
        address = mapped or parsed
        found.add("loopback" if address.is_loopback or address.is_unspecified else str(address))
    return frozenset(found)
