import { DeviceName, useNamer } from "../shell/deviceNames";
import { useWorkspace } from "../workspace/WorkspaceContext";
import { emptyRequirement } from "../assessments/types";
/** The "What changed" pane shows the added, removed and changed nodes and rels between 2 snapshots (GET /api/diff). */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import type {
  DiffNode,
  DiffNodeChanged,
  DiffRel,
  DiffRelChanged,
  DiffResponse,
  SnapshotList,
} from "../api/types";
import { SnapshotPicker } from "../flowdesk/SnapshotPicker";
import { useAiContext, useAiPaneId } from "../ai/context";
import { changeRows, defaultPair, formatValue, isEmptyDiff } from "./diffmodel";
import "../diagram/netmap.css";
import "./diff.css";

function ChangesCell({ changes }: { changes: Record<string, [unknown, unknown]> }) {
  const rows = changeRows(changes);
  return (
    <details>
      <summary>
        {rows.length} propert{rows.length === 1 ? "y" : "ies"} changed
      </summary>
      <div className="diff-changes">
        {rows.map((c) => (
          <div className="diff-change-row" key={c.key}>
            <span className="diff-change-key">{c.key}</span>
            <span className="diff-change-vals">
              {formatValue(c.before)} to {formatValue(c.after)}
            </span>
          </div>
        ))}
      </div>
    </details>
  );
}

function NodeTable({ rows }: { rows: DiffNode[] | DiffNodeChanged[] }) {
  const name = useNamer();
  if (rows.length === 0) return null;
  const changed = "changes" in rows[0];
  return (
    <div className="diff-tablewrap">
      <table>
        <thead>
          <tr>
            <th>UID</th>
            <th>Label</th>
            <th>Name</th>
            {changed && <th></th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((n) => (
            <tr key={n.uid}>
              <td>{n.uid}</td>
              <td>{n.label}</td>
              <td>{n.name || (name(n.uid) !== n.uid ? name(n.uid) : "")}</td>
              {"changes" in n && (
                <td>
                  <ChangesCell changes={n.changes} />
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RelTable({ rows }: { rows: DiffRel[] | DiffRelChanged[] }) {
  if (rows.length === 0) return null;
  const changed = "changes" in rows[0];
  return (
    <div className="diff-tablewrap">
      <table>
        <thead>
          <tr>
            <th>Type</th>
            <th>Start</th>
            <th>End</th>
            {changed && <th></th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={`${r.type}:${r.start}:${r.end}:${i}`}>
              <td>{r.type}</td>
              <td><DeviceName uid={r.start} /></td>
              <td><DeviceName uid={r.end} /></td>
              {"changes" in r && (
                <td>
                  <ChangesCell changes={r.changes} />
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function StatusSection({
  heading,
  tone,
  nodes,
  rels,
}: {
  heading: string;
  tone: "ok" | "bad" | "warn";
  nodes: DiffNode[] | DiffNodeChanged[];
  rels: DiffRel[] | DiffRelChanged[];
}) {
  if (nodes.length === 0 && rels.length === 0) return null;
  return (
    <section className="diff-group">
      <div className="diff-groupheadrow">
        <h3 className={"diff-grouphead " + tone}>{heading}</h3>
      </div>
      <NodeTable rows={nodes} />
      <RelTable rows={rels} />
    </section>
  );
}

function DiffResult({ data }: { data: DiffResponse }) {
  return (
    <>
      <div className="diff-summary">
        <span className="diff-chip ok">{data.counts.nodes.added} nodes added</span>
        <span className="diff-chip bad">{data.counts.nodes.removed} nodes removed</span>
        <span className="diff-chip warn">{data.counts.nodes.changed} nodes changed</span>
        <span className="diff-chip ok">{data.counts.rels.added} rels added</span>
        <span className="diff-chip bad">{data.counts.rels.removed} rels removed</span>
        <span className="diff-chip warn">{data.counts.rels.changed} rels changed</span>
      </div>
      {data.truncated && (
        <div className="diff-truncated">
          first 500 entries per list
        </div>
      )}
      {isEmptyDiff(data.counts) ? (
        <div className="diff-empty">no differences</div>
      ) : (
        <div className="diff-groups">
          <StatusSection
            heading="Added"
            tone="ok"
            nodes={data.nodes.added}
            rels={data.rels.added}
          />
          <StatusSection
            heading="Removed"
            tone="bad"
            nodes={data.nodes.removed}
            rels={data.rels.removed}
          />
          <StatusSection
            heading="Changed"
            tone="warn"
            nodes={data.nodes.changed}
            rels={data.rels.changed}
          />
        </div>
      )}
    </>
  );
}

export default function DiffPage() {
  const workspace = useWorkspace();
  const snapshots = useQuery({
    queryKey: ["snapshots"],
    queryFn: () => api<SnapshotList>("/snapshots"),
  });

  const [aOverride, setAOverride] = useState("");
  const [bOverride, setBOverride] = useState("");
  const pair = defaultPair(snapshots.data?.snapshots ?? []);
  const a = aOverride || pair?.a || "";
  const b = bOverride || pair?.b || "";
  useAiContext(
    useAiPaneId(),
    a && b
      ? { snapshot: { id: b, compare_id: a, origin: aOverride || bOverride ? "pinned" : "page-default" } }
      : null,
  );

  const diff = useQuery({
    queryKey: ["diff", a, b],
    queryFn: () => api<DiffResponse>(`/diff?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`),
    enabled: !!a && !!b,
  });

  return (
    <div className="diff-page">
      <div className="diff-toolbar">
        <SnapshotPicker value={a} onChange={setAOverride} label="A" />
        <span className="diff-arrow">to</span>
        <SnapshotPicker value={b} onChange={setBOverride} label="B" />
        {workspace && a && b && a !== b && <button type="button" onClick={() => workspace.openAssessments(undefined, undefined, { title: `Regression ${a} to ${b}`, kind: "regression", analysis: { before_snapshot: a, snapshot: b }, definition: { request: emptyRequirement(), intents: [], snapshot: b, mode: "possible", freshness_s: 86400 } })}>Explain this regression</button>}
      </div>
      {!a || !b ? (
        <div className="diff-empty">no snapshot pair</div>
      ) : diff.isLoading ? (
        <div className="diff-empty">loading the diff</div>
      ) : diff.isError ? (
        <div className="diff-empty">
          diff failed to load:{" "}
          {diff.error instanceof ApiError ? diff.error.message : "diff failed"}
        </div>
      ) : diff.data ? (
        <DiffResult data={diff.data} />
      ) : null}
    </div>
  );
}
