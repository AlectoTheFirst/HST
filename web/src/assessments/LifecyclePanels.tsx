import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { EvidenceValue, record } from "./AnalysisResult";
import { Field } from "./RequirementComposer";
import type { AnalysisRun, Assessment } from "./types";

export function CollectionFollowup({
  assessment,
  onNavigate,
}: {
  assessment: Assessment;
  onNavigate: (id?: string, run?: string) => void;
}) {
  const actions = assessment.definition.collection_actions ?? [];
  return actions.length ? (
    <section>
      <h3>Collection and reevaluation</h3>
      {actions.map((action, i) => (
        <details key={String(action.request_id ?? i)}>
          <summary>
            {String(action.source)} / {String(action.host || "controller")}:{" "}
            {String(action.state).replaceAll("_", " ")}
          </summary>
          <p>{String(action.reason ?? "Waiting for collection and committed publication")}</p>
          {typeof action.gap_closed === "boolean" && (
            <p>
              {action.gap_closed ? "Requested evidence gap closed" : "Requested evidence gap open"}
            </p>
          )}
          <div className="assessment-actions">
            {typeof action.run_id === "string" && (
              <button
                type="button"
                onClick={() => onNavigate(assessment.id, action.run_id as string)}
              >
                Open run before collection
              </button>
            )}
            {typeof action.reevaluation_run_id === "string" && (
              <button
                type="button"
                onClick={() => onNavigate(assessment.id, action.reevaluation_run_id as string)}
              >
                Open run after collection at snapshot {String(action.published_snapshot)}
              </button>
            )}
          </div>
          <EvidenceValue value={action} />
        </details>
      ))}
    </section>
  ) : null;
}

export function RunComparison({ runs }: { runs: AnalysisRun[] }) {
  const [left, setLeft] = useState("");
  const [right, setRight] = useState("");
  const a = useQuery({
    queryKey: ["analysis-job", left],
    queryFn: () => api<AnalysisRun>(`/analysis-jobs/${encodeURIComponent(left)}`),
    enabled: !!left,
  });
  const b = useQuery({
    queryKey: ["analysis-job", right],
    queryFn: () => api<AnalysisRun>(`/analysis-jobs/${encodeURIComponent(right)}`),
    enabled: !!right,
  });
  return (
    <details>
      <summary>Compare saved results</summary>
      <div className="assessment-fields">
        {[
          [left, setLeft, a, "A"],
          [right, setRight, b, "B"],
        ].map(([selected, select, query, label]) => {
          const result = query as typeof a;
          return (
            <section key={String(label)}>
              <label className="assessment-field">
                <span>Saved run {String(label)}</span>
                <select
                  value={selected as string}
                  onChange={(e) => (select as (v: string) => void)(e.target.value)}
                >
                  <option value="">Choose a run</option>
                  {runs.map((run) => (
                    <option key={run.id} value={run.id}>
                      {run.kind} / {run.state} / {run.created_at}
                    </option>
                  ))}
                </select>
              </label>
              {result.isLoading && <p role="status">Loading saved result</p>}
              {result.isError && <p role="alert">Could not load the selected result</p>}
              {result.data && (
                <>
                  <h4>
                    {result.data.kind.charAt(0).toUpperCase()}
                    {result.data.kind.slice(1)} / {result.data.state}
                  </h4>
                  <p>
                    Run {result.data.id}, revision{" "}
                    {result.data.assessment_revision ?? "not recorded"}
                  </p>
                  <EvidenceValue
                    value={{ inputs: result.data.inputs, result: result.data.result }}
                  />
                </>
              )}
            </section>
          );
        })}
      </div>
    </details>
  );
}

export function RetentionPanel({
  assessment,
  runId,
  canAdminister,
}: {
  assessment: Assessment;
  runId?: string;
  canAdminister: boolean;
}) {
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const retention = useQuery({
    queryKey: ["assessment-retention", assessment.id],
    queryFn: () =>
      api<Record<string, unknown>>(`/assessments/${encodeURIComponent(assessment.id)}/retention`),
  });
  const replay = useQuery({
    queryKey: ["assessment-replay", assessment.id, runId],
    queryFn: () =>
      api<Record<string, unknown>>(
        `/assessments/${encodeURIComponent(assessment.id)}/runs/${encodeURIComponent(runId!)}/replay-status`,
      ),
    enabled: !!runId,
  });
  async function update(release: boolean) {
    setBusy(true);
    setError("");
    try {
      await api(`/assessments/${encodeURIComponent(assessment.id)}/retention`, {
        method: "PUT",
        body: {
          reason,
          release,
          retain_until: !release && until ? new Date(until).toISOString() : null,
        },
      });
      await retention.refetch();
      await replay.refetch();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section>
      <h3>Evidence retention and replay</h3>
      {retention.isLoading && <p role="status">Loading retention policy</p>}
      {(retention.isError || replay.isError) && (
        <p role="alert">Could not check evidence availability</p>
      )}
      {retention.data && <EvidenceValue value={retention.data} />}
      {replay.data && <EvidenceValue value={replay.data} />}
      {canAdminister && (
        <fieldset disabled={busy}>
          <legend>Retention policy</legend>
          <Field label="Retention policy reason" value={reason} onChange={setReason} required />
          <Field label="Retain until" type="datetime-local" value={until} onChange={setUntil} />
          <div className="assessment-actions">
            <button type="button" disabled={!reason.trim()} onClick={() => update(false)}>
              Retain evidence
            </button>
            <button type="button" disabled={!reason.trim()} onClick={() => update(true)}>
              Release retention
            </button>
          </div>
        </fieldset>
      )}
      {error && <p role="alert">{error}</p>}
    </section>
  );
}

export function proposalSummary(value: unknown): string {
  const proposal = record(value);
  return `Saved proposal ${String(proposal.id)}, revision ${String(proposal.revision)}`;
}
