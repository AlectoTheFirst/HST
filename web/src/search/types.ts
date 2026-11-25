/**
 * The typed answer of GET /api/explore/search?typed=true: the hits of one
 * query grouped by kind, a page per kind, each kind paged on with its own
 * cursor.
 */

/** The kinds the search groups its hits by, in the server's fixed order. */
export const KINDS = [
  "device",
  "interface",
  "site",
  "prefix",
  "ip_address",
  "endpoint",
  "vrf",
  "segment",
  "application",
  "arp",
  "mac",
  "route",
  "ospf_lsa",
] as const;

export type Kind = (typeof KINDS)[number];

/** The kinds a hit opens as: a graph object. */
export type TargetKind = "device" | "interface" | "site" | "prefix" | "ip_address" | "endpoint" | "vrf" | "segment" | "application";

export type MatchMode = "uid" | "ip" | "prefix" | "range" | "mac" | "regex" | "text";

/** Where a hit was read: the graph, a side-store table, or (`local`) the
 *  page's own data, for a group the page adds itself. */
export type HitSource = "graph" | "arp" | "mac" | "rib" | "ospf_lsdb" | "local";

export interface SearchHit {
  /** One of KINDS; a legacy answer's unknown label, or a page's own kind for a local hit. */
  kind: Kind | (string & {});
  /** Unique within the kind. */
  key: string;
  /** The graph uid for a graph kind; null for a side-store row. */
  uid: string | null;
  name: string;
  detail: string;
  source: HitSource;
  matched: MatchMode | "address";
  run: number | null;
  source_run: string | null;
  /** What opening the hit opens: the hit itself for a graph kind, the device
   *  (or the segment) of a side-store row. */
  target: { kind: TargetKind | (string & {}); uid: string } | null;
  fields: Record<string, string | number | null>;
}

export interface KindCount {
  kind: Kind;
  count: number;
  count_exact: boolean;
}

export interface HitPage {
  items: SearchHit[];
  next_cursor: string | null;
}

/** The legacy hit: every answer carries these. */
export interface LegacyHit {
  uid: string;
  label: string | null;
  name: string;
  detail: string;
  matched: string;
}

export interface SearchAnswer {
  query: string;
  items: LegacyHit[];
  total: number;
  labels: { label: string; count: number }[];
  /** The typed fields: absent from an older server's answer. */
  mode?: MatchMode;
  snapshot?: number | null;
  kinds?: KindCount[];
  groups?: Partial<Record<Kind, HitPage>>;
  side_store?: {
    available: boolean;
    approximate: boolean;
    /** Side kinds whose lookup returned the row limit. */
    capped?: Kind[];
    /** Side kinds whose lookup stopped at the time limit. */
    timed_out?: Kind[];
  };
}

export interface SearchParams {
  q: string;
  kinds?: readonly Kind[];
  cursor?: string;
  limit?: number;
  snapshot?: number;
}
