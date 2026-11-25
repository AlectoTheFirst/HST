/**
 * The Analysis run of an application's ready connections: the action of the
 * Coverage section, shared with the flow panel of the Network Map.
 */

import { api } from "../api/client";
import type { AnalysisSessionRecord, ConnectionAnalysisInput } from "../analysis/contracts";
import type { ResolvedApplication } from "./types";

export interface AnalyzedApplication {
  id: string;
  revision: number;
  digest: string;
  name: string;
}

/** The queued session, and the connections engine admission left out with
 *  its reason (`results.admission` of the session). */
export interface AnalyzedSession {
  id: string;
  omitted: string[];
  reason?: string;
}

/** Save a connection session of the ready connections of `resolution` that
 *  an explicit service holds, queue its runs, and return the session. The
 *  other selections are recorded in the review and not submitted.
 *  `names` gives a connection's display name by id. */
export async function analyzeReadyConnections(
  application: AnalyzedApplication,
  resolution: ResolvedApplication,
  names: ReadonlyMap<string, string>,
  selectedConnections: string[],
): Promise<AnalyzedSession> {
  const runnable = resolution.connections.filter(
    (item) => item.readiness === "ready" && item.request && item.service_id,
  );
  const input: ConnectionAnalysisInput = {
    kind: "connection",
    snapshot: resolution.snapshot,
    changes: [],
    mode: "possible",
    connections: runnable.map((item) => ({
      id: item.id,
      name: names.get(item.id) ?? item.id,
      source: {
        kind: "application_connection",
        reference: {
          application: {
            id: application.id,
            revision: application.revision,
            digest: application.digest,
          },
          service_id: item.service_id ?? "",
          connection_id: item.id,
        },
        request: item.request!,
        resolved_scope_digest: resolution.digest,
      },
    })),
  };
  const unresolved = resolution.connections
    .filter((item) => item.readiness !== "ready" || !item.service_id)
    .map((item) => ({
      id: item.id,
      issues: item.service_id
        ? item.issues
        : [
            ...item.issues,
            { code: "service-association-required", message: "No explicit service" },
          ],
    }));
  const created = await api<AnalysisSessionRecord>("/analysis-sessions", {
    method: "POST",
    body: {
      title: `${application.name} analysis`,
      input,
      review: { selected_connection_ids: selectedConnections, unresolved },
    },
  });
  const queued = await api<AnalysisSessionRecord>(
    `/analysis-sessions/${encodeURIComponent(created.id)}/runs`,
    {
      method: "POST",
      body: {
        session_revision: created.revision,
        input_digest: created.input_digest,
        analysis: { kind: "evaluate" },
      },
    },
  );
  const admission = queued?.results?.admission as
    { omitted?: string[]; reason?: string } | undefined;
  return { id: created.id, omitted: admission?.omitted ?? [], reason: admission?.reason };
}
