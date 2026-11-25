import type { ResultValue } from "../results/text";
/**
 * The application flow overlay: the response of
 * GET /api/business-applications/{id}/flows (hst/applications/flows.py),
 * shared by the Network Map (netmap/flows.ts, FlowPanel.tsx) and the 3D twin
 * (hst/flows/place.ts).
 *
 * A path is the device sequence of stored evaluation evidence. Its hops are
 * devices an evaluated packet crossed, never application components.
 */

import { api } from "../api/client";

/** The map's key for a path or connection answer, and the keys of `counts`:
 *  the connection condition passes, fails or is not decided (`open`). */
export type PathAnswer = "passes" | "fails" | "open";
/** An evaluated connection carries its answer in `result`; the others carry none. */
export type FlowState = "evaluated" | "unresolved" | "not-evaluated";
/** What a list or a drawing shows for a connection: the answer of an evaluated one, else its state. */
export type ShownState = PathAnswer | "unresolved" | "not-evaluated";
/** How a map draws one segment: a path that is not decided is `decided` up
 *  to the device of its first unknown step and `open` after it. */
export type SegmentState = "passes" | "fails" | "decided" | "open";
export type Phase = "forward" | "reply";

export interface FlowStep {
  device_uid: string | null;
  stage: string;
  kind: string;
  detail: string;
  unknown: string[];
  phase: Phase;
  gate: boolean;
}

export interface FlowSegment {
  from: string;
  to: string;
  phase: Phase;
  state: SegmentState;
}

export interface FlowPath {
  id: string;
  /** the path's answer to the statement that the connection condition holds */
  result: ResultValue;
  /** evaluated parts that took this path to this answer */
  count: number;
  /** destination members the parts belong to */
  members: string[];
  /** device uids in walk order; `phases[i]` is the phase of `devices[i]` */
  devices: string[];
  phases: Phase[];
  segments: FlowSegment[];
  steps: FlowStep[];
  /** a failing path: the deciding step and its device, where the stop marker goes */
  stop_index: number | null;
  stop_device: string | null;
  /** a path that is not decided: the first step with an unknown and its device */
  unknown_index: number | null;
  unknown_device: string | null;
  missing: string[];
}

export interface FlowEndpoint {
  member: string;
  inventory_uid: string | null;
  /** the devices that hold the member's inventory object at the run */
  devices: string[];
  addresses: string[];
}

export interface FlowEvaluation {
  session_id: string;
  run_id: string;
  execution: "queued" | "running" | "completed" | "failed" | "cancelled";
  snapshot: string;
  revision: number | null;
  finished_at: string | null;
  stale: { snapshot: boolean; revision: boolean };
}

export interface FlowConnection {
  id: string;
  name: string;
  /** the answer of an evaluated connection; null for an unresolved or not evaluated one */
  result: ResultValue | null;
  service_id: string | null;
  source: string;
  destination: string;
  protocol: string | null;
  destination_ports: Array<number | string> | null;
  success: "forward" | "round-trip" | "session";
  readiness: "ready" | "unresolved";
  state: FlowState;
  issues: Array<{ code: string; path: string; detail: string }>;
  endpoints: { source: FlowEndpoint[]; destination: FlowEndpoint[] };
  evaluation: FlowEvaluation | null;
  paths: FlowPath[];
  /** distinct paths past the cap */
  more_paths: number;
  counts: Record<PathAnswer, number>;
  missing: string[];
  evidence_truncated: boolean;
}

export interface FlowsResponse {
  application: { id: string; revision: number; digest: string; name: string };
  snapshot: { snapshot: string; manifest_sha256: string; estate: string };
  resolution_digest: string;
  connections: FlowConnection[];
  /** the runs and revisions the shown evaluations come from */
  evaluated: { snapshots: string[]; revisions: number[] };
  /** some shown evaluation is from another run or revision than the map's */
  stale: { snapshot: boolean; revision: boolean };
  max_paths: number;
}

/** What a map shows: one application, and the connections toggled on. */
export interface FlowSelection {
  application: string;
  connections: string[];
}

export function flowsPath(application: string, snapshot: string | number, revision?: number): string {
  const query = new URLSearchParams({ snapshot: String(snapshot) });
  if (revision) query.set("revision", String(revision));
  return `/business-applications/${encodeURIComponent(application)}/flows?${query}`;
}

export function fetchFlows(application: string, snapshot: string | number, revision?: number): Promise<FlowsResponse> {
  return api<FlowsResponse>(flowsPath(application, snapshot, revision));
}

/** The connections a selection shows, in response order. */
export function selectedConnections(flows: FlowsResponse | undefined, selection: FlowSelection | null): FlowConnection[] {
  if (!flows || !selection || selection.application !== flows.application.id) return [];
  const on = new Set(selection.connections);
  return flows.connections.filter((c) => on.has(c.id));
}

/** The banner text when a shown evaluation is not from the map's run or the
 *  application's revision; null when every shown evaluation matches. */
export function staleBanner(flows: FlowsResponse, shown: FlowConnection[]): string | null {
  const parts: string[] = [];
  const runs = new Set<string>();
  const revisions = new Set<number>();
  for (const c of shown) {
    if (!c.evaluation) continue;
    if (c.evaluation.stale.snapshot) runs.add(c.evaluation.snapshot);
    if (c.evaluation.stale.revision && c.evaluation.revision !== null) revisions.add(c.evaluation.revision);
  }
  if (runs.size) parts.push(`run ${[...runs].sort().join(", ")}, not run ${flows.snapshot.snapshot}`);
  if (revisions.size) parts.push(`revision ${[...revisions].sort((a, b) => a - b).join(", ")}, not revision ${flows.application.revision}`);
  return parts.length ? `Evaluation of ${parts.join(" and of ")}` : null;
}

/** The map's key for a condition answer: "true" passes, "false" fails, anything else is not decided. */
export function outcomeOf(result: ResultValue | null | undefined): PathAnswer {
  return result?.answer === "true" ? "passes" : result?.answer === "false" ? "fails" : "open";
}

/** The shown state of a connection: the answer of an evaluated one, else its state. */
export function shownState(c: FlowConnection): ShownState {
  return c.state === "evaluated" ? outcomeOf(c.result) : c.state;
}

export const STATE_TEXT: Record<ShownState, string> = {
  passes: "Passes",
  fails: "Fails",
  open: "Not decided",
  unresolved: "Unresolved",
  "not-evaluated": "Not evaluated",
};
