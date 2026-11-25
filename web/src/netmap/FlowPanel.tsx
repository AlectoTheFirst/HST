/**
 * The Flows panel of a site diagram: pick a Business Application, toggle its
 * connections one by one or by service, and read the hops of each stored
 * path. Nothing is toggled when an application is picked, and the panel reads
 * stored evaluations only (GET /api/business-applications/{id}/flows). A
 * connection with no evaluation at the drawing's run offers the Analysis run
 * of the Coverage section, for at most EVALUATE_CAP connections, to a user
 * who holds changes.write.
 */

import { ResultLines } from "../results/ResultLines";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api/client";
import { useCurrentUser } from "../auth";
import { analyzeReadyConnections } from "../applications/analysis";
import { fetchFlows, outcomeOf, shownState, STATE_TEXT, staleBanner, type FlowConnection, type FlowPath, type FlowSelection, type FlowsResponse } from "../applications/flows";
import type { ApplicationRevision, ResolvedApplication } from "../applications/types";

/** The most connections one Evaluate press submits. */
export const EVALUATE_CAP = 20;
/** How often the panel reads the flows again while an evaluation is queued or running. */
const PENDING_POLL_MS = 5000;

const pending = (c: FlowConnection) => c.evaluation?.execution === "queued" || c.evaluation?.execution === "running";

/** The stored flows of the selected application at the drawing's run. */
export function useApplicationFlows(selection: FlowSelection | null, snapshot: number | null) {
  const application = selection?.application ?? "";
  return useQuery<FlowsResponse>({
    queryKey: ["application-flows", application, String(snapshot)],
    queryFn: () => fetchFlows(application, snapshot!),
    enabled: application !== "" && snapshot !== null,
    refetchInterval: (query) => (query.state.data?.connections.some(pending) ? PENDING_POLL_MS : false),
  });
}

/** A saved view's flow selection, or null for anything that is not one. */
export function flowSelectionOf(value: unknown): FlowSelection | null {
  if (typeof value !== "object" || value === null) return null;
  const { application, connections } = value as Record<string, unknown>;
  if (typeof application !== "string" || !application) return null;
  return { application, connections: Array.isArray(connections) ? connections.filter((c): c is string => typeof c === "string") : [] };
}

function plural(n: number, one: string, many: string) {
  return `${n} ${n === 1 ? one : many}`;
}

function Hops({ path, label, nameOf, drawn }: { path: FlowPath; label: string; nameOf: (id: string) => string; drawn: ReadonlySet<string> }) {
  // the steps of each hop, in walk order: a hop is a run of steps on one device in one phase
  const hops: { device: string; phase: string; steps: FlowPath["steps"] }[] = [];
  for (const step of path.steps) {
    if (step.device_uid === null) continue;
    const last = hops[hops.length - 1];
    if (last && last.device === step.device_uid && last.phase === step.phase) last.steps.push(step);
    else hops.push({ device: step.device_uid, phase: step.phase, steps: [step] });
  }
  // the stop is on the last hop of its device, the first unknown on the first
  const outcome = outcomeOf(path.result);
  let stopHop = -1;
  hops.forEach((h, i) => {
    if (outcome === "fails" && h.device === path.stop_device) stopHop = i;
  });
  const unknownHop = outcome === "open" ? hops.findIndex((h) => h.device === path.unknown_device) : -1;
  return (
    <ol className="nm-flow-hops" aria-label={label}>
      {hops.map((hop, i) => (
        <li key={`${hop.device}:${hop.phase}:${i}`}>
          {nameOf(hop.device)}
          {hop.phase === "reply" ? ", response" : ""}
          {!drawn.has(hop.device) ? ", not in this drawing" : ""}
          {i === stopHop ? ", stops here" : ""}
          {i === unknownHop ? ", first unknown step" : ""}
          {hop.steps.some((s) => s.gate || s.unknown.length > 0) && (
            <ul>
              {hop.steps
                .filter((s) => s.gate || s.unknown.length > 0)
                .map((s, j) => (
                  <li key={j}>
                    {s.stage} {s.kind}
                    {s.detail ? `: ${s.detail}` : ""}
                    {s.unknown.length > 0 ? ` (unknown: ${s.unknown.join(", ")})` : ""}
                  </li>
                ))}
            </ul>
          )}
        </li>
      ))}
    </ol>
  );
}

function ConnectionDetail({ c, nameOf, drawn }: { c: FlowConnection; nameOf: (id: string) => string; drawn: ReadonlySet<string> }) {
  if (c.state === "unresolved")
    return (
      <ul className="nm-flow-notes">
        {c.issues.map((i) => (
          <li key={`${i.code}:${i.path}`}>
            {i.path}: {i.detail}
          </li>
        ))}
      </ul>
    );
  if (c.state === "not-evaluated")
    return <p className="nm-flow-notes">{pending(c) ? `Evaluation ${c.evaluation!.execution}` : "No stored evaluation"}</p>;
  return (
    <>
      <p className="nm-flow-notes">
        {plural(c.paths.length + c.more_paths, "path", "paths")}
        {c.counts.fails ? `, ${c.counts.fails} failing` : ""}
        {c.counts.open ? `, ${c.counts.open} not decided` : ""}
        {c.more_paths > 0 ? `, first ${c.paths.length} listed` : ""}
        {c.evidence_truncated ? ", stored evidence incomplete" : ""}
      </p>
      {shownState(c) === "open" && c.missing.length > 0 && <p className="nm-flow-notes">Missing evidence: {c.missing.join(", ")}</p>}
      {c.paths.map((p, i) => (
        <details key={p.id} className="nm-flow-path">
          <summary>
            Path {i + 1}: {p.result.word}, {plural(p.count, "part", "parts")}
            {p.members.length ? ` to ${p.members.join(", ")}` : ""}
          </summary>
          <Hops path={p} label={`Hops of path ${i + 1} of ${c.name}`} nameOf={nameOf} drawn={drawn} />
          <ResultLines className="nm-flow-notes" subject={`Path ${i + 1}`} result={p.result} />
        </details>
      ))}
    </>
  );
}

export default function FlowPanel({
  snapshot,
  selection,
  onSelection,
  flows,
  nameOf,
  drawn,
  note,
  onClose,
}: {
  /** the run of the drawing; null when the drawing names none */
  snapshot: number | null;
  selection: FlowSelection | null;
  onSelection: (selection: FlowSelection | null) => void;
  flows: ReturnType<typeof useApplicationFlows>;
  nameOf: (id: string) => string;
  /** the devices of the drawing */
  drawn: ReadonlySet<string>;
  /** what the flow paint lit, and what it could not draw */
  note: string;
  onClose: () => void;
}) {
  const user = useCurrentUser();
  const canEvaluate = !!user?.permissions.includes("changes.write");
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<string | null>(null);
  const [evaluating, setEvaluating] = useState(false);
  const catalog = useQuery({
    queryKey: ["business-applications"],
    queryFn: () => api<{ applications: ApplicationRevision[] }>("/business-applications"),
    staleTime: 60_000,
  });
  const record = catalog.data?.applications.find((a) => a.id === selection?.application);
  const data = flows.data && selection && flows.data.application.id === selection.application ? flows.data : undefined;
  const connections = data?.connections ?? [];
  const on = new Set(selection?.connections ?? []);
  const shown = connections.filter((c) => on.has(c.id));
  const banner = data && shown.length ? staleBanner(data, shown) : null;

  const toggle = (ids: string[], value: boolean) => {
    if (!selection) return;
    const next = new Set(on);
    for (const id of ids) {
      if (value) next.add(id);
      else next.delete(id);
    }
    onSelection({ ...selection, connections: connections.map((c) => c.id).filter((id) => next.has(id)) });
  };
  const services = record?.definition.services ?? [];
  const inService = new Set(services.flatMap((s) => s.connection_ids));
  const groups = [
    ...services.map((s) => ({ id: s.id, name: `Service ${s.name}`, items: connections.filter((c) => s.connection_ids.includes(c.id)) })),
    { id: "", name: "Not in a service", items: connections.filter((c) => !inService.has(c.id)) },
  ].filter((g) => g.items.length > 0);

  // the Analysis run of Coverage, for the shown connections with no evaluation at this run
  const waiting = shown.filter((c) => c.state === "not-evaluated" && c.readiness === "ready" && c.service_id && !pending(c));
  const submitted = waiting.slice(0, EVALUATE_CAP);
  const evaluate = async () => {
    if (!data || submitted.length === 0 || snapshot === null) return;
    setEvaluating(true);
    setStatus(null);
    try {
      const ids = submitted.map((c) => c.id);
      const resolution = await api<ResolvedApplication>(`/business-applications/${encodeURIComponent(data.application.id)}/resolve`, {
        method: "POST",
        body: { snapshot: String(snapshot), revision: data.application.revision, connection_ids: ids },
      });
      const names = new Map(connections.map((c) => [c.id, c.name] as const));
      const session = await analyzeReadyConnections(data.application, resolution, names, ids);
      const queued = ids.length - session.omitted.length;
      setStatus(session.omitted.length
        ? `Evaluation of ${plural(queued, "connection", "connections")} queued at run ${snapshot}, not submitted: ${session.omitted.map((id) => names.get(id) ?? id).join(", ")} (${session.reason ?? "admission limit"})`
        : `Evaluation of ${plural(ids.length, "connection", "connections")} queued at run ${snapshot}`);
      void queryClient.invalidateQueries({ queryKey: ["analysis-sessions"] });
      await queryClient.invalidateQueries({ queryKey: ["application-flows", data.application.id, String(snapshot)] });
    } catch (err) {
      setStatus(err instanceof Error ? err.message : String(err));
    } finally {
      setEvaluating(false);
    }
  };

  return (
    <aside className="nm-panel nm-flowpanel" aria-label="Application flows">
      <header>
        Flows
        <button type="button" onClick={onClose} aria-label="Close flows">Close</button>
      </header>
      <div className="nm-flowbody">
        {catalog.isPending && <p role="status">Loading the applications</p>}
        {catalog.error && <p role="alert">Applications not loaded</p>}
        {catalog.data && (
          <label>
            Application{" "}
            <select
              aria-label="Application"
              value={selection?.application ?? ""}
              onChange={(e) => onSelection(e.target.value ? { application: e.target.value, connections: [] } : null)}
            >
              <option value="">None</option>
              {catalog.data.applications.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </label>
        )}
        {catalog.data?.applications.length === 0 && <p>No applications</p>}
        {selection && snapshot !== null && flows.isPending && <p role="status">Loading the stored flows at run {snapshot}</p>}
        {selection && flows.error && <p role="alert">{flows.error.message}</p>}
        {banner && (
          <p className="banner warn" role="note">
            {banner}
          </p>
        )}
        {note && shown.length > 0 && <p className="nm-layernote">{note}</p>}
        {data && connections.length === 0 && <p>No connections</p>}
        {groups.map((g) => {
          const ids = g.items.map((c) => c.id);
          return (
            <fieldset key={g.id || "none"} className="nm-flow-group">
              <legend>
                <label>
                  <input type="checkbox" checked={ids.every((id) => on.has(id))} onChange={(e) => toggle(ids, e.target.checked)} />
                  {g.name}
                </label>
              </legend>
              <ul>
                {g.items.map((c) => (
                  <li key={c.id}>
                    <label>
                      <input type="checkbox" checked={on.has(c.id)} onChange={(e) => toggle([c.id], e.target.checked)} />
                      {c.name}
                    </label>{" "}
                    <span className={`nm-flow-state nm-flow-${shownState(c)}`}>{STATE_TEXT[shownState(c)]}</span>
                    {on.has(c.id) && <ConnectionDetail c={c} nameOf={nameOf} drawn={drawn} />}
                    {on.has(c.id) && c.state === "not-evaluated" && c.readiness === "ready" && !c.service_id && (
                      <p className="nm-flow-notes">No service</p>
                    )}
                  </li>
                ))}
              </ul>
            </fieldset>
          );
        })}
        {waiting.length > 0 && canEvaluate && (
          <>
            <button type="button" disabled={evaluating} onClick={() => void evaluate()}>
              Evaluate {plural(submitted.length, "connection", "connections")} at run {snapshot}
            </button>
          </>
        )}
        {status && <p role="status">{status}</p>}
      </div>
    </aside>
  );
}
