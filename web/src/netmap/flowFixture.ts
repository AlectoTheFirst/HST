/** Flow overlay fixtures for the netmap tests (flows.test.ts, FlowPanel.test.tsx). */

import type { FlowConnection, FlowPath, FlowsResponse, PathAnswer } from "../applications/flows";
import type { ResultValue } from "../results/text";

const ANSWER: Record<PathAnswer, "true" | "false" | "open"> = { passes: "true", fails: "false", open: "open" };
const WORD: Record<PathAnswer, string> = { passes: "passes", fails: "fails", open: "not decided" };

/** The server's condition result for a path or connection the map keys as `outcome`. */
export function conditionResult(outcome: PathAnswer, missing: string[] = []): ResultValue {
  return {
    kind: "result",
    statement: "condition-holds",
    answer: ANSWER[outcome],
    word: WORD[outcome],
    quantifier: null,
    condition: "forward",
    missing: outcome === "open" ? (missing.length ? missing : ["the evaluation of this part is open"]).map((detail) => ({ code: "not-decided", subject: null, detail })) : [],
  };
}

/** A path; `answer` picks its result and the state of its segments. */
export function path(over: Partial<FlowPath> & Pick<FlowPath, "devices"> & { answer?: PathAnswer }): FlowPath {
  const { answer = "passes", ...rest } = over;
  const devices = rest.devices;
  return {
    id: devices.join("-") + answer,
    result: conditionResult(answer, rest.missing),
    count: 1,
    members: ["db"],
    phases: devices.map(() => "forward"),
    segments: devices.slice(1).map((to, i) => ({ from: devices[i], to, phase: "forward", state: answer })),
    steps: devices.map((d) => ({ device_uid: d, stage: "route", kind: "via", detail: "", unknown: [], phase: "forward", gate: false })),
    stop_index: null,
    stop_device: null,
    unknown_index: null,
    unknown_device: null,
    missing: [],
    ...rest,
  };
}

/** A connection; `answer` makes it an evaluated one with that result. */
export function connection(over: Partial<FlowConnection> & Pick<FlowConnection, "id"> & { answer?: PathAnswer }): FlowConnection {
  const { answer, ...rest } = over;
  const evaluated = answer !== undefined || rest.state === undefined || rest.state === "evaluated";
  return {
    name: rest.id,
    result: evaluated ? conditionResult(answer ?? "passes", rest.missing) : null,
    service_id: "front",
    source: "clients",
    destination: "servers",
    protocol: "tcp",
    destination_ports: [443],
    success: "forward",
    readiness: "ready",
    state: evaluated ? "evaluated" : rest.state!,
    issues: [],
    endpoints: { source: [], destination: [] },
    evaluation: null,
    paths: [],
    more_paths: 0,
    counts: { passes: 0, fails: 0, open: 0 },
    missing: [],
    evidence_truncated: false,
    ...rest,
  };
}

export function response(connections: FlowConnection[], over: Partial<FlowsResponse> = {}): FlowsResponse {
  return {
    application: { id: "shop", revision: 3, digest: "d", name: "Shop" },
    snapshot: { snapshot: "7", manifest_sha256: "m", estate: "test" },
    resolution_digest: "r",
    connections,
    evaluated: { snapshots: [], revisions: [] },
    stale: { snapshot: false, revision: false },
    max_paths: 50,
    ...over,
  };
}
