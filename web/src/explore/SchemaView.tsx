import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ApiError } from "../api/client";
import { exploreApi, type CountRow } from "../api/explore";

const TOP = 8;

function message(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed";
}

function snapshotText(snapshot: unknown): string {
  return typeof snapshot === "number" ? new Date(snapshot).toLocaleString() : "No published snapshot";
}

/** The first rows, and the rest folded into one "Other" row. */
function topRows(rows: CountRow[]): CountRow[] {
  if (rows.length <= TOP) return rows;
  const rest = rows.slice(TOP - 1).reduce((sum, r) => sum + r.count, 0);
  return [...rows.slice(0, TOP - 1), { value: "Other", count: rest }];
}

function Bars({ title, rows, onPick }: { title: string; rows: CountRow[]; onPick?: (value: string) => void }) {
  const max = Math.max(1, ...rows.map((r) => r.count));
  return (
    <section className="editorcard xs-bars" aria-label={title}>
      <h3 className="eyebrow">{title}</h3>
      {rows.length === 0 && <p className="hint">None</p>}
      <ul className="xs-barlist">
        {rows.map((row) => {
          const content = <>
            <span className="xs-barlabel">{row.value}</span>
            <span className="xs-bartrack" aria-hidden="true"><span className="xs-bar" style={{ width: `${(row.count / max) * 100}%` }} /></span>
            <span className="xs-barvalue">{row.count.toLocaleString()}</span>
          </>;
          return (
            <li key={row.value} title={row.value}>
              {onPick && row.value !== "Other"
                ? <button type="button" className="xs-barrow" onClick={() => onPick(row.value)}>{content}</button>
                : <span className="xs-barrow">{content}</span>}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

export function SchemaView({ onOpenNode, onOpenCypher }: {
  onOpenNode: (uid: string) => void;
  /** Set for an operator only: hands a starter query to the Cypher editor. */
  onOpenCypher?: (cypher: string) => void;
}) {
  const stats = useQuery({ queryKey: ["explore", "stats"], queryFn: exploreApi.stats, staleTime: 60_000 });
  const [filter, setFilter] = useState("");
  const [label, setLabel] = useState<string | null>(null);
  if (stats.isPending) return <p className="hint" role="status">Loading</p>;
  if (stats.isError) return <div className="banner err"><div className="sub">{message(stats.error)}</div></div>;
  const s = stats.data;
  const labels = s.labels.filter((l) => l.label.toLowerCase().includes(filter.trim().toLowerCase()));
  const maxLabel = Math.max(1, ...s.labels.map((l) => l.count));
  return (
    <div className="xs">
      <div className="xs-tiles">
        <div className="xs-tile"><span className="xs-tilelabel">Nodes</span><span className="xs-tilevalue">{s.total_nodes.toLocaleString()}</span></div>
        <div className="xs-tile"><span className="xs-tilelabel">Node types</span><span className="xs-tilevalue">{s.labels.length.toLocaleString()}</span></div>
        <div className="xs-tile"><span className="xs-tilelabel">Devices</span><span className="xs-tilevalue">{s.devices.total.toLocaleString()}</span></div>
        <div className="xs-tile"><span className="xs-tilelabel">Snapshot</span><span className="xs-tilevalue small">{snapshotText(s.snapshot)}</span></div>
      </div>

      <div className="xs-grid">
        <Bars title="Nodes by layer" rows={s.layers.map((l) => ({ value: l.layer, count: l.count }))} />
        <Bars title="Devices by vendor" rows={topRows(s.devices.by_vendor)} />
        <Bars title="Devices by platform" rows={topRows(s.devices.by_platform)} />
        <Bars title="Devices by role" rows={topRows(s.devices.by_role)} />
      </div>

      <div className="xb-columns">
        <section className="editorcard xs-labels" aria-label="Node types">
          <div className="bar">
            <h3 className="eyebrow">Node types</h3>
            <label className="xb-field">
              <span className="xs-sr">Filter</span>
              <input type="search" className="xb-input" placeholder="Filter" value={filter} onChange={(e) => setFilter(e.target.value)} />
            </label>
          </div>
          <ul className="xs-barlist">
            {labels.map((l) => (
              <li key={l.label} title={l.label}>
                <button type="button" className={"xs-barrow" + (label === l.label ? " on" : "")} aria-pressed={label === l.label} onClick={() => setLabel(l.label)}>
                  <span className="xs-barlabel">{l.label}<span className="xs-layers">{l.layers.join(", ")}</span></span>
                  <span className="xs-bartrack" aria-hidden="true"><span className="xs-bar" style={{ width: `${(l.count / maxLabel) * 100}%` }} /></span>
                  <span className="xs-barvalue">{l.count.toLocaleString()}</span>
                </button>
              </li>
            ))}
          </ul>
          {labels.length === 0 && <p className="hint">No matching node types</p>}
        </section>
        {label && <LabelPanel key={label} label={label} onOpenNode={onOpenNode} onOpenCypher={onOpenCypher} onClose={() => setLabel(null)} />}
      </div>
    </div>
  );
}

function LabelPanel({ label, onOpenNode, onOpenCypher, onClose }: {
  label: string; onOpenNode: (uid: string) => void; onOpenCypher?: (cypher: string) => void; onClose: () => void;
}) {
  const detail = useQuery({ queryKey: ["explore", "label", label], queryFn: () => exploreApi.label(label), staleTime: 60_000 });
  const d = detail.data;
  return (
    <section className="editorcard xb-node" aria-label={`Node type ${label}`}>
      <div className="bar">
        <span className="eyebrow">Node type</span>
        <button type="button" className="secondary" onClick={onClose}>Close</button>
      </div>
      <div className="xb-nodehead">
        <h2 className="xb-title">{label}</h2>
        {d?.doc && <p className="hint">{d.doc}</p>}
      </div>
      {detail.isPending && <p className="hint" role="status">Loading</p>}
      {detail.isError && <div className="banner err"><div className="sub">{message(detail.error)}</div></div>}
      {d && <>
        {d.sampled && <p className="hint">Sampled</p>}
        <h3 className="eyebrow">Properties</h3>
        <ul className="xs-barlist">
          {d.properties.map((p) => (
            <li key={p.name} title={p.name}>
              <span className="xs-barrow">
                <span className="xs-barlabel mono">{p.name}</span>
                <span className="xs-bartrack" aria-hidden="true"><span className="xs-bar" style={{ width: `${p.share * 100}%` }} /></span>
                <span className="xs-barvalue">{Math.round(p.share * 100)}%</span>
              </span>
            </li>
          ))}
        </ul>
        <h3 className="eyebrow">Relationships</h3>
        {d.relationships.length === 0 && <p className="hint">No relationships</p>}
        <ul className="xb-list">
          {d.relationships.map((r) => (
            <li key={`${r.type}-${r.direction}-${r.other}`} className="xs-rel">
              {r.direction === "out"
                ? <span>{label} <b>{r.type}</b> {r.other ?? "node"}</span>
                : <span>{r.other ?? "node"} <b>{r.type}</b> {label}</span>}
              <span className="xb-count">{r.count.toLocaleString()}</span>
            </li>
          ))}
        </ul>
        <h3 className="eyebrow">Examples</h3>
        <ul className="xb-neighbors">
          {d.examples.map((e) => (
            <li key={e.uid}><button type="button" className="xb-neighbor" title={e.uid} onClick={() => onOpenNode(e.uid)}>{e.name}</button></li>
          ))}
        </ul>
        <details className="xb-bookkeeping">
          <summary>Starter Cypher</summary>
          <pre className="rawpre">{d.cypher}</pre>
          {onOpenCypher && <button type="button" className="secondary" onClick={() => onOpenCypher(d.cypher)}>Open in the Cypher editor</button>}
        </details>
      </>}
    </section>
  );
}
