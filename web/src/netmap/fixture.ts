import type { SiteGraphEdge, SiteGraphPayload, SiteGraphSite } from "../api/types";

export function site(
  code: string,
  lat: number | null,
  lon: number | null,
  extra: Partial<SiteGraphSite> = {},
): SiteGraphSite {
  return { code, name: code, lat, lon, devices: 1, exits: [], ...extra };
}

export function edge(a: string, b: string, kind: SiteGraphEdge["kind"], count = 1): SiteGraphEdge {
  return { a, b, kind, count, pairs: [] };
}

// two hubs in Frankfurt, an Equinix hall beside them, a DC in Amsterdam, and
// branches around Berlin and Munich
export const SITES: SiteGraphSite[] = [
  site("fra-hub1", 50.11, 8.68, { tiers: { "sdwan-hub": 2 } }),
  site("fra-hub2", 50.12, 8.7, { tiers: { "sdwan-hub": 2 } }),
  site("FR2", 50.1, 8.72, { kind: "colo" }),
  site("ams-dc", 52.37, 4.9, { tiers: { spine: 2, leaf: 4 } }),
  site("ber-b1", 52.52, 13.4, { tiers: { "sdwan-edge": 1 } }),
  site("ber-b2", 52.5, 13.42, { tiers: { "sdwan-edge": 1 } }),
  site("muc-b1", 48.14, 11.58, { tiers: { "sdwan-edge": 1 } }),
  site("nowhere", null, null),
];

export const PAYLOAD: SiteGraphPayload = {
  sites: SITES,
  edges: [
    edge("ber-b1", "fra-hub1", "tunnel", 2),
    edge("ber-b2", "fra-hub1", "tunnel", 2),
    edge("ber-b1", "ber-b2", "tunnel"),
    edge("FR2", "fra-hub1", "cable", 4),
    edge("ams-dc", "fra-hub2", "bgp", 3),
    edge("muc-b1", "ber-b1", "tunnel"),
  ],
  unplaced: [],
};
