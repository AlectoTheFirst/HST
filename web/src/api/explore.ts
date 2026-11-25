/**
 * Client for /api/explore: graph search, node browsing, schema and statistics
 * (app/routes/explore.py). Every route reads the current snapshot and is open
 * to any role with graph.read.
 */

import { api } from "./client";
import type { ResultGraph } from "./types";
import type { SearchAnswer, SearchParams } from "../search/types";

export interface SearchHit {
  uid: string;
  label: string | null;
  name: string;
  detail: string;
  /** Which strategy found the node: its exact uid, an IP address or prefix, or the name index. */
  matched: "uid" | "address" | "text";
}

export interface SearchResult {
  query: string;
  items: SearchHit[];
  total: number;
  labels: { label: string; count: number }[];
}

export interface ExploreNode {
  id: string;
  uid: string;
  label: string | null;
  labels: string[];
  name: string;
  properties: Record<string, unknown>;
  bookkeeping: Record<string, unknown>;
}

export interface NeighborGroup {
  type: string;
  direction: "out" | "in";
  label: string | null;
  count: number;
}

export interface NodeResult {
  snapshot: unknown;
  node: ExploreNode;
  neighbors: NeighborGroup[];
}

export interface NeighborPage {
  total: number;
  offset: number;
  limit: number;
  items: { uid: string; label: string | null; name: string }[];
  graph?: ResultGraph;
}

export interface CountRow {
  value: string;
  count: number;
  /** An identity group whose name is its group id: no name was collected. */
  id_only?: boolean;
}

export interface GraphStats {
  snapshot: unknown;
  total_nodes: number;
  labels: { label: string; count: number; layers: string[]; doc: string }[];
  layers: { layer: string; count: number }[];
  devices: { total: number; by_vendor: CountRow[]; by_platform: CountRow[]; by_role: CountRow[] };
}

export interface LabelDetail {
  label: string;
  layers: string[];
  doc: string;
  count: number;
  sampled: boolean;
  properties: { name: string; share: number }[];
  relationships: { type: string; direction: "out" | "in"; other: string | null; count: number }[];
  examples: { uid: string; name: string }[];
  cypher: string;
}

export interface RouteRow {
  vrf: string | null;
  context_uid: string | null;
  prefix: string;
  next_hop: string | null;
  next_hop_context_uid: string | null;
  interface: string | null;
  protocol: string | null;
  discard: string | null;
  metric: number | null;
  prefixlen: number | null;
  af: number | null;
  /** With an address filter: the row is at the longest prefix that covers the
   *  address in its own routing table, whatever the other filters keep. */
  longest?: boolean;
}

export interface RoutePage {
  /** False when the side store is not installed or holds no route table. */
  available: boolean;
  /** True when the files were chosen by age, because no manifest governs the snapshot. */
  approximate: boolean;
  /** The outcome the snapshot recorded for the device's route table. */
  coverage: string | null;
  /** The collection time of the snapshot the page was read from; null before the first run. */
  snapshot: number | null;
  device_uid: string;
  context_uid: string | null;
  run_id: string | null;
  total: number;
  offset: number;
  limit: number;
  protocols: { protocol: string; count: number }[];
  items: RouteRow[];
}

/** One route of GET /api/explore/route-search: a device's route for the
 *  searched address or prefix. `device` is the hostname, else the uid. */
export interface RouteSearchRow {
  device_uid: string;
  device: string;
  vrf: string | null;
  context_uid: string | null;
  prefix: string;
  next_hop: string | null;
  interface: string | null;
  protocol: string | null;
  metric: number | null;
}

export interface RouteSearchResult {
  query: string;
  total: number;
  items: RouteSearchRow[];
}

function query(params: Record<string, string | number | undefined>): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== "") q.set(key, String(value));
  const text = q.toString();
  return text ? `?${text}` : "";
}

export const exploreApi = {
  stats: () => api<GraphStats>("/explore/stats"),
  label: (label: string) => api<LabelDetail>(`/explore/labels/${encodeURIComponent(label)}`),
  search: (q: string, label?: string, limit = 25) => api<SearchResult>(`/explore/search${query({ q, label, limit })}`),
  /** The typed search (search/types.ts): the hits grouped by kind, a page per
   *  kind. With a cursor, the next page of the one kind asked. */
  find: (params: SearchParams) => {
    const q = new URLSearchParams({ q: params.q, typed: "true" });
    for (const kind of params.kinds ?? []) q.append("kind", kind);
    if (params.cursor) q.set("cursor", params.cursor);
    if (params.limit !== undefined) q.set("limit", String(params.limit));
    if (params.snapshot !== undefined) q.set("snapshot", String(params.snapshot));
    return api<SearchAnswer>(`/explore/search?${q.toString()}`);
  },
  node: (uid: string) => api<NodeResult>(`/explore/node${query({ uid })}`),
  neighbors: (params: { uid: string; type: string; direction: "out" | "in"; label?: string; offset?: number; limit?: number }) =>
    api<NeighborPage>(`/explore/neighbors${query(params)}`),
  routes: (params: { uid: string; address?: string; prefix?: string; protocol?: string; offset?: number; limit?: number }) =>
    api<RoutePage>(`/explore/routes${query(params)}`),
  routeSearch: (q: string, limit = 100) => api<RouteSearchResult>(`/explore/route-search${query({ q, limit })}`),
  values: (label: string, property: string, q: string, limit = 20) =>
    api<{ items: CountRow[] }>(`/explore/values${query({ label, property, q, limit })}`),
};
