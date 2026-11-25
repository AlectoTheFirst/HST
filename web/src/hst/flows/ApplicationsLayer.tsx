import { useState } from "react";
import { api } from "../../api/client";
import { shownState, STATE_TEXT, staleBanner, type FlowConnection, type FlowsResponse } from "../../applications/flows";
import type { ApplicationRevision } from "../../applications/types";

/** The application and the connections the twin shows, at the revision picked. */
export interface TwinFlowSelection {
  application: string;
  revision: number;
  connections: string[];
}

export type CatalogLoader = () => Promise<{ applications: ApplicationRevision[] }>;

const loadCatalog: CatalogLoader = () => api<{ applications: ApplicationRevision[] }>("/business-applications");

interface Props {
  run: number | null;
  selection: TwinFlowSelection | null;
  onSelection(selection: TwinFlowSelection | null): void;
  flows: FlowsResponse | null;
  loading: boolean;
  error: string | null;
  /** Per connection id, the devices of its paths and endpoints the drawing does not hold. */
  offMap: ReadonlyMap<string, number>;
  catalog?: CatalogLoader;
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** What the list says about one connection: its state and what the map cannot show of it. */
function notes(c: FlowConnection, offMap: number, run: number | null): string[] {
  const out: string[] = [];
  if (c.state === "unresolved") {
    out.push(...c.issues.map((i) => `${i.path}: ${i.detail}`));
  } else if (c.state === "not-evaluated") {
    const execution = c.evaluation?.execution;
    const at = run !== null ? `run ${run}` : "this run";
    out.push(execution === "queued" || execution === "running" ? `Evaluation ${execution}` : `No stored evaluation at ${at}`);
  } else {
    const parts = [plural(c.paths.length + c.more_paths, "path", "paths")];
    if (c.counts.fails) parts.push(`${c.counts.fails} failing`);
    if (c.counts.open) parts.push(`${c.counts.open} not decided`);
    out.push(parts.join(", "));
    if (c.more_paths > 0) out.push(`${plural(c.more_paths, "path", "paths")} not drawn`);
    if (shownState(c) === "open" && c.missing.length) out.push(`Missing evidence: ${c.missing.join(", ")}`);
    if (c.evidence_truncated) out.push("Stored evidence incomplete");
  }
  if (offMap > 0) out.push(`${plural(offMap, "device", "devices")} not in the drawing`);
  return out;
}

/**
 * The Applications section of the layers menu.
 */
export default function ApplicationsLayer({ run, selection, onSelection, flows, loading, error, offMap, catalog = loadCatalog }: Props) {
  const [apps, setApps] = useState<ApplicationRevision[] | null>(null);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [requested, setRequested] = useState(false);

  const open = () => {
    if (requested) return;
    setRequested(true);
    catalog().then(
      (body) => setApps(body.applications),
      (e: unknown) => setCatalogError(e instanceof Error ? e.message : String(e)),
    );
  };

  const record = apps?.find((a) => a.id === selection?.application);
  const on = new Set(selection?.connections ?? []);
  const connections = flows && selection && flows.application.id === selection.application ? flows.connections : [];
  const shown = connections.filter((c) => on.has(c.id));
  const banner = flows && shown.length ? staleBanner(flows, shown) : null;
  const set = (ids: string[]) => selection && onSelection({ ...selection, connections: connections.map((c) => c.id).filter((id) => ids.includes(id)) });
  const toggle = (ids: string[], value: boolean) => {
    const next = new Set(on);
    for (const id of ids) {
      if (value) next.add(id);
      else next.delete(id);
    }
    set([...next]);
  };
  const services = record?.definition.services ?? [];
  const inService = new Set(services.flatMap((s) => s.connection_ids));
  const groups: { id: string; name: string; items: FlowConnection[] }[] = [
    ...services.map((s) => ({ id: s.id, name: `Service ${s.name}`, items: connections.filter((c) => s.connection_ids.includes(c.id)) })),
    { id: "", name: "Not in a service", items: connections.filter((c) => !inService.has(c.id)) },
  ].filter((g) => g.items.length > 0);

  return (
    <details className="hst-apps" onToggle={(e) => e.currentTarget.open && open()}>
      <summary>Applications</summary>
      <div className="hst-apps-panel">
        {requested && apps === null && !catalogError && <p role="status">Loading the applications</p>}
        {catalogError && <p role="alert">{catalogError}</p>}
        {apps && (
          <label>
            Application{" "}
            <select
              aria-label="Application"
              value={selection?.application ?? ""}
              onChange={(e) => {
                const picked = apps.find((a) => a.id === e.target.value);
                onSelection(picked ? { application: picked.id, revision: picked.revision, connections: [] } : null);
              }}
            >
              <option value="">None</option>
              {apps.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </label>
        )}
        {apps && apps.length === 0 && <p>No applications</p>}
        {selection && loading && <p role="status">Loading the stored flows at run {run}</p>}
        {selection && error && <p role="alert">{error}</p>}
        {banner && <p className="hst-apps-banner" role="note">{banner}</p>}
        {selection && flows && connections.length === 0 && <p>No connections</p>}
        {groups.map((g) => {
          const ids = g.items.map((c) => c.id);
          const all = ids.every((id) => on.has(id));
          return (
            <fieldset key={g.id || "none"} className="hst-apps-group">
              <legend>
                <label>
                  <input type="checkbox" checked={all} onChange={(e) => toggle(ids, e.target.checked)} />
                  {g.name}
                </label>
              </legend>
              <ul>
                {g.items.map((c) => (
                  <li key={c.id}>
                    <label>
                      <input type="checkbox" checked={on.has(c.id)} onChange={(e) => toggle([c.id], e.target.checked)} />
                      {c.name}
                    </label>
                    <span className={`hst-apps-state hst-apps-${shownState(c)}`}>{STATE_TEXT[shownState(c)]}</span>
                    {on.has(c.id) && (
                      <ul className="hst-apps-notes">
                        {notes(c, offMap.get(c.id) ?? 0, run).map((text) => (
                          <li key={text}>{text}</li>
                        ))}
                      </ul>
                    )}
                  </li>
                ))}
              </ul>
            </fieldset>
          );
        })}
      </div>
    </details>
  );
}
