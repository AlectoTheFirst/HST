import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api/client";
import type { ResultGraph } from "../api/types";
import { PinnedSnapshotPicker } from "../assessments/PinnedSnapshotPicker";
import GraphView from "../explore/GraphView";
import type { ApplicationRevision, ResolutionIssue } from "./types";

/** GET /api/business-applications/{id}/graph: the revision joined to its
 *  resolved inventory at a pinned run (hst/applications/inventory_graph.py). */
export interface ApplicationGraph extends ResultGraph {
  application: { id: string; revision: number; digest: string; name: string };
  snapshot: { snapshot: string; manifest_sha256: string; estate: string };
  resolution_digest: string;
  issues: ResolutionIssue[];
  library_query: { key: string; params: { uids: string } };
}

/** The view draws the application with the inventory objects that its members resolve to at a pinned snapshot. */
export default function ApplicationInventory({ record }: { record: ApplicationRevision }) {
  const [snapshot, setSnapshot] = useState("");
  const graph = useQuery({
    queryKey: ["business-application-graph", record.id, record.revision, snapshot],
    queryFn: () => api<ApplicationGraph>(`/business-applications/${encodeURIComponent(record.id)}/graph?snapshot=${encodeURIComponent(snapshot)}&revision=${record.revision}`),
    enabled: snapshot !== "",
  });
  return (
    <section aria-label="Inventory graph">
      <h3>Expand to inventory</h3>
      <PinnedSnapshotPicker label="Inventory snapshot" value={snapshot} onChange={setSnapshot} />
      {graph.isLoading && <p role="status">Resolving the inventory</p>}
      {graph.isError && <p role="alert">{graph.error instanceof Error ? graph.error.message : "The inventory could not be resolved"}</p>}
      {graph.data && (
        <>
          {graph.data.issues.length > 0 && (
            <ul aria-label="Resolution issues">
              {graph.data.issues.map((issue) => (
                <li key={`${issue.code}:${issue.path}`}>
                  {issue.path}: {issue.detail}
                </li>
              ))}
            </ul>
          )}
          {graph.data.truncated && <p>Partial graph</p>}
          <GraphView graph={graph.data} />
          {graph.data.library_query.params.uids && (
            <p>
              Explore library query <code>{graph.data.library_query.key}</code>, uids <code>{graph.data.library_query.params.uids}</code>
            </p>
          )}
        </>
      )}
    </section>
  );
}
