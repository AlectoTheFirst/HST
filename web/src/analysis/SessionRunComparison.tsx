import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { EvidenceValue } from "../assessments/AnalysisResult";
import type { AnalysisRun } from "../assessments/types";
import type { ResultValue } from "../results/text";
import type { AnalysisRunSummary, AnalysisSessionRecord } from "./contracts";

/** GET /api/analysis-sessions/{id}/runs/{run_id}. `run` is the saved run.
 *  `summary` is the entry of the stored session definition. */
export interface SessionRun {
  summary: AnalysisRunSummary;
  run: Omit<AnalysisRun, "result"> & {
    input_digest?: string;
    snapshot_refs?: Array<{ snapshot?: string | number | null }>;
    result: { result?: ResultValue | null } | null;
  };
}

function snapshots(run: SessionRun["run"]): string {
  const ids = (run.snapshot_refs ?? [])
    .map((ref) => ref.snapshot)
    .filter((id) => id != null)
    .map(String);
  return ids.length ? ids.join(", ") : "not recorded";
}

/** The rows of the comparison table, as label and value, from the saved run. */
export function comparedFields(session: AnalysisSessionRecord, value: SessionRun): Array<[string, string]> {
  return [
    ["Session", session.title],
    ["Run", value.run.id],
    ["Item", value.summary.item_id],
    ["Snapshot", snapshots(value.run)],
    ["Input digest", value.run.input_digest ?? "not recorded"],
    ["Engine version", value.run.engine_version ?? "not recorded"],
    ["Created", value.run.created_at],
    ["Execution", value.run.state],
    ["Result", value.run.result?.result?.word ?? "no result"],
  ];
}

function useSessionRun(sessionId: string, runId: string) {
  return useQuery({
    queryKey: ["analysis-session-run", sessionId, runId],
    queryFn: () =>
      api<SessionRun>(
        `/analysis-sessions/${encodeURIComponent(sessionId)}/runs/${encodeURIComponent(runId)}`,
      ),
    enabled: !!sessionId && !!runId,
  });
}

interface Side {
  session: string;
  run: string;
}

export function SessionRunComparison({
  sessionId,
  sessions,
}: {
  sessionId: string;
  sessions: AnalysisSessionRecord[];
}) {
  const [left, setLeft] = useState<Side>({ session: sessionId, run: "" });
  const [right, setRight] = useState<Side>({ session: sessionId, run: "" });
  const a = useSessionRun(left.session, left.run);
  const b = useSessionRun(right.session, right.run);
  const byId = new Map(sessions.map((session) => [session.id, session]));
  if (!sessions.some((session) => session.definition.runs.length > 0)) return null;
  const sides = [
    { label: "A", side: left, select: setLeft, query: a },
    { label: "B", side: right, select: setRight, query: b },
  ];
  const rows = sides.map(({ side, query }) => {
    const session = byId.get(side.session);
    return session && query.data ? comparedFields(session, query.data) : null;
  });
  return (
    <section aria-label="Compare runs">
      <h3>Compare runs</h3>
      <div className="assessment-fields">
        {sides.map(({ label, side, select }) => (
          <fieldset key={label}>
            <legend>Run {label}</legend>
            <label className="assessment-field">
              <span>Session {label}</span>
              <select
                value={side.session}
                onChange={(e) => select({ session: e.target.value, run: "" })}
              >
                {sessions.map((session) => (
                  <option key={session.id} value={session.id}>
                    {session.title} / revision {session.revision}
                  </option>
                ))}
              </select>
            </label>
            <label className="assessment-field">
              <span>Run {label}</span>
              <select
                value={side.run}
                onChange={(e) => select({ session: side.session, run: e.target.value })}
              >
                <option value="">Choose a run</option>
                {(byId.get(side.session)?.definition.runs ?? []).map((run) => (
                  <option key={run.id} value={run.id}>
                    {run.item_id} / {run.id}
                  </option>
                ))}
              </select>
            </label>
          </fieldset>
        ))}
      </div>
      {sides.map(
        ({ label, query }) =>
          query.isError && (
            <p role="alert" key={label}>
              Run {label} not loaded
            </p>
          ),
      )}
      {rows[0] && rows[1] && (
        <>
          <table className="analysis-run-comparison">
            <thead>
              <tr>
                <th scope="col">Field</th>
                <th scope="col">Run A</th>
                <th scope="col">Run B</th>
                <th scope="col">Comparison</th>
              </tr>
            </thead>
            <tbody>
              {rows[0].map(([label, valueA], index) => {
                const valueB = rows[1]![index][1];
                return (
                  <tr key={label}>
                    <th scope="row">{label}</th>
                    <td>{valueA}</td>
                    <td>{valueB}</td>
                    <td>{valueA === valueB ? "same" : "different"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <div className="assessment-fields">
            {sides.map(({ label, query }) => (
              <section key={label} aria-label={`Saved result of run ${label}`}>
                <h4>Saved result of run {label}</h4>
                <EvidenceValue value={query.data!.run.result} />
              </section>
            ))}
          </div>
        </>
      )}
    </section>
  );
}
