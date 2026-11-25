/**
 * The kinds of edge between two sites (GET /api/sites/graph,
 * app/routes/site_graph.py), their order and their words, and one boundary
 * pair as text. The network map's estate level and its site panel read these.
 */

import type { SiteEdgeKind, SitePair } from "../api/types";

export const KIND_ORDER: readonly SiteEdgeKind[] = ["cable", "circuit", "tunnel", "l3", "bgp"];

export const KIND_LABEL: Record<SiteEdgeKind, string> = {
  cable: "cables",
  circuit: "fabric circuits",
  tunnel: "tunnels",
  l3: "shared prefixes",
  bgp: "BGP sessions",
};

/** One boundary pair as the panel prints it: the two ends and a note. */
export function describePair(kind: SiteEdgeKind, p: SitePair): { a: string; b: string; note: string } {
  const s = (v: unknown) => (v === null || v === undefined ? "" : String(v));
  switch (kind) {
    case "cable":
      return {
        a: `${s(p.a_name)} ${s(p.a_port)}`.trim(),
        b: `${s(p.b_name)} ${s(p.b_port)}`.trim(),
        note: s(p.source),
      };
    case "circuit":
      return {
        a: [s(p.a_fabric_port), s(p.a_name) && `${s(p.a_name)} ${s(p.a_port)}`].filter(Boolean).join(", "),
        b: [s(p.b_fabric_port), s(p.b_name) && `${s(p.b_name)} ${s(p.b_port)}`].filter(Boolean).join(", "),
        note: [s(p.name), s(p.state), p.bandwidth_mbps != null ? `${s(p.bandwidth_mbps)} Mb/s` : ""]
          .filter(Boolean)
          .join(", "),
      };
    case "tunnel":
      return {
        a: `${s(p.a_name)} ${s(p.a_end)}`.trim(),
        b: `${s(p.b_name)} ${s(p.b_end)}`.trim(),
        note: [s(p.encap), s(p.link_kind) && `over ${s(p.link_kind)}`, s(p.state)].filter(Boolean).join(", "),
      };
    case "l3":
      return {
        a: `${s(p.a_name)} ${s(p.a_iface)} ${s(p.a_ip)}`.trim(),
        b: `${s(p.b_name)} ${s(p.b_iface)} ${s(p.b_ip)}`.trim(),
        note: [s(p.cidr), s(p.domain) || `VRF ${s(p.vrf)}`].join(", "),
      };
    case "bgp":
      return {
        a: `${s(p.a_name)} ${s(p.a_ip)} AS${s(p.a_asn)}`.trim(),
        b: `${s(p.b_name)} ${s(p.b_ip)} AS${s(p.b_asn)}`.trim(),
        note: [s(p.kind), s(p.state)].filter(Boolean).join(", "),
      };
  }
}
