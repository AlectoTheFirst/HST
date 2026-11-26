import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { changedAreas } from "./ApplicationEditor";
import type { ApplicationRevision, RevisionOrigin } from "./types";

const ORIGIN_SOURCES: Record<RevisionOrigin["source"], string> = {
  import: "Imported from YAML",
  editor: "Saved in the visual editor",
  api: "Saved through the API",
  trace: "Added from a trace",
  generator: "Saved from a generated draft",
};

export function describeOrigin(origin: RevisionOrigin | null | undefined): string {
  if (!origin) return "Origin not recorded";
  const source = ORIGIN_SOURCES[origin.source] ?? `Saved from ${origin.source}`;
  const validation = origin.validation;
  if (!validation) return `${source}, not validated`;
  const blocking = validation.blocking_count;
  const state =
    blocking === 0
      ? "nothing blocked the ready state"
      : `${blocking} ${blocking === 1 ? "path blocked" : "paths blocked"} the ready state`;
  return `${source}, validated at snapshot ${validation.snapshot.snapshot}, ${state}`;
}

export function useRevisionHistory(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ["business-application-history", id],
    queryFn: () =>
      api<{ revisions: ApplicationRevision[] }>(
        `/business-applications/${encodeURIComponent(id!)}/history`,
      ),
    enabled: !!id && enabled,
  });
}

/** The revisions of an application with compare and export. */
export function ApplicationRevisions({
  record,
  onExport,
}: {
  record: ApplicationRevision;
  onExport: (revision: number) => void;
}) {
  const history = useRevisionHistory(record.id);
  const [comparison, setComparison] = useState<ApplicationRevision | null>(null);
  return (
    <section>
      <h3>Revisions</h3>
      {history.isLoading && <p role="status">Loading revision history</p>}
      {history.data?.revisions.map((item) => (
        <article className="application-row" key={item.revision}>
          <div>
            <strong>Revision {item.revision}</strong>
            <span>{new Date(item.created_at).toLocaleString()}</span>
          </div>
          <p>{describeOrigin(item.origin)}</p>
          <code>{item.digest}</code>
          <button type="button" onClick={() => setComparison(item)}>
            Compare with current
          </button>
          <button type="button" onClick={() => onExport(item.revision)}>
            Export revision {item.revision}
          </button>
        </article>
      ))}
      {comparison && (
        <section className="application-edit-card" aria-label="Revision differences">
          <h4>
            Revision {comparison.revision} compared with revision {record.revision}
          </h4>
          <p>
            {changedAreas(comparison.definition, record.definition).join(", ") ||
              "No definition changes"}
          </p>
          <details>
            <summary>Inspect definitions</summary>
            <h5>Revision {comparison.revision}</h5>
            <pre>{JSON.stringify(comparison.definition, null, 2)}</pre>
            <h5>Revision {record.revision}</h5>
            <pre>{JSON.stringify(record.definition, null, 2)}</pre>
          </details>
          <button type="button" onClick={() => setComparison(null)}>
            Close comparison
          </button>
        </section>
      )}
    </section>
  );
}
