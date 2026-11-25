import { ApiError, api } from "../../api/client";
import type { Row, TableName } from "../render/types";

export interface Columnar {
  columns: string[];
  rows: unknown[][];
}

export interface Counts {
  added: number;
  removed: number;
  changed: number;
}

export interface TimelineRun {
  key: number;
  kind: string | null;
  parent: number | null;
  published_ts: number | null;
  state: string | null;
  tiers_ready: boolean;
  counts: Counts;
  replan_recommended: boolean;
}

export interface Timeline {
  current: number | null;
  runs: TimelineRun[];
}

export type Op = "add" | "remove" | "set";

export interface DeltaRow {
  uid: string;
  op: Op;
  before: Row | null;
  after: Row | null;
}

export interface Tunnel {
  uid: string;
  encap: string | null;
  other: string | null;
}

export interface Tier3 {
  uid: string;
  snapshot: number;
  state: "warm" | "cold";
  categories: Record<string, Row[]>;
  contexts: Row[];
  tunnels?: Tunnel[];
  rows?: Row[];
}

export interface InterfaceFacts {
  uid: string;
  snapshot: number;
  label: string | null;
  device_uid: string | null;
  name: string | null;
  interface: Row | null;
  interfaces?: string[];
  port: Row | null;
  contexts: string[];
  addresses: string[];
  lags: string[];
}

export interface InterfaceText {
  uid: string;
  command: string;
  fetched_ts: number | null;
  text: string;
}

/** GET /api/hst/device-text: the device's version, routing, ACL and NAT sections, redacted. */
export interface DeviceText {
  uid: string;
  snapshot: number;
  fetched_ts: number | null;
  sections: Array<{ key: string; title: string; parts: Array<{ command: string; text: string }> }>;
}

/** The HST routes the map reads. Tests pass their own. */
export interface SegmentClient {
  uid: string;
  name: string | null;
  ip: string[];
  mac: string | null;
  port: string | null;
  last_seen_ts: number | null;
}

export interface Segment {
  uid: string;
  device_uid: string;
  snapshot: number;
  state: "warm" | "cold";
  prefix: string | null;
  vid: number | null;
  name: string | null;
  clients: SegmentClient[];
}

export interface Source {
  timeline(): Promise<Timeline>;
  tier(name: TableName, snapshot: number, tile?: string): Promise<Row[]>;
  delta(name: TableName, snapshot: number, tile?: string): Promise<DeltaRow[]>;
  layout(snapshot: number, tile?: string): Promise<Row[]>;
  layoutDelta(snapshot: number, tile?: string): Promise<Row[]>;
  device(uid: string, snapshot: number): Promise<Tier3>;
  segment(uid: string, snapshot: number): Promise<Segment>;
  interface(uid: string, snapshot: number): Promise<InterfaceFacts>;
  interfaceText(uid: string, snapshot: number): Promise<InterfaceText>;
}

export function decode(c: Columnar): Row[] {
  return c.rows.map((values) => {
    const row: Row = {};
    c.columns.forEach((name, i) => {
      row[name] = values[i];
    });
    return row;
  });
}

function query(params: Record<string, string | number | undefined>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined) q.set(k, String(v));
  return q.toString();
}

async function tileRows<T>(tile: string | undefined, load: () => Promise<T[]>): Promise<T[]> {
  try {
    return await load();
  } catch (err) {
    if (tile !== undefined && err instanceof ApiError && err.status === 404) return [];
    throw err;
  }
}

export const http: Source = {
  timeline: () => api<Timeline>("/hst/timeline"),
  tier: (name, snapshot, tile) =>
    tileRows(tile, async () => decode(await api<Columnar>(`/hst/tier?${query({ name, snapshot, tile })}`))),
  delta: (name, snapshot, tile) =>
    tileRows(tile, async () => (await api<{ rows: DeltaRow[] }>(`/hst/delta?${query({ name, snapshot, tile })}`)).rows),
  layout: (snapshot, tile) =>
    tileRows(tile, async () => decode(await api<Columnar>(`/hst/layout?${query({ snapshot, tile })}`))),
  layoutDelta: (snapshot, tile) =>
    tileRows(tile, async () => decode(await api<Columnar>(`/hst/layout-delta?${query({ snapshot, tile })}`))),
  device: (uid, snapshot) => api<Tier3>(`/hst/device?${query({ uid, snapshot })}`),
  segment: (uid, snapshot) => api<Segment>(`/hst/segment?${query({ uid, snapshot })}`),
  interface: (uid, snapshot) => api<InterfaceFacts>(`/hst/interface?${query({ uid, snapshot })}`),
  interfaceText: (uid, snapshot) => api<InterfaceText>(`/hst/interface-text?${query({ uid, snapshot })}`),
};
