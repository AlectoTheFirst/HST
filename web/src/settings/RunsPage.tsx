/**
 * Runs: the source list with the trigger buttons that POST /api/runs
 * (runs.py), and the run history from GET /api/runs.
 *
 * With RUN_EXECUTION=queue the trigger answers with a queued `collect.run`
 * job.
 *
 * On a demo instance (GET /api/runs `demo`), an admin also gets the demo estate
 * load (`DemoEstateCard`), which starts a `demo` run through the same POST.
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import type { DebugOverview, HttpTraces, Job, JobHistory, QueuedRun, Run, RunHistory } from "../api/types";
import { atLeast, useAuth } from "../auth";
import { CollectionDebug, capturesOfRun, runBundleHref } from "./CollectionDebug";
import { CollectionProgressView } from "./CollectionProgress";

const POLL_MS = 5000;

/** A whole run, or one source of a cycle. */
type CancelTarget = { id: number; source?: string };

function hasRunning(data: RunHistory | undefined): boolean {
  return !!data?.runs.some((r) => r.status === "running");
}

function hasPending(data: JobHistory | undefined): boolean {
  return !!data?.jobs.some((j) => j.state === "running" || j.state === "queued");
}

/** The runs queued through POST /api/runs that have not finished: each job
 *  waits for a worker, or runs while the run it started is in flight. */
function pendingRuns(data: RunHistory | undefined): Job[] {
  return data?.pending_runs ?? [];
}

function fmtTime(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : "";
}

function fmtDuration(seconds: number | null): string {
  if (seconds === null) return "";
  return seconds < 1 ? `${Math.round(seconds * 1000)} ms` : `${seconds.toFixed(1)} s`;
}

function fmtSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function traceHref(t: { run_id: string; source: string; host: string }): string {
  const params = new URLSearchParams({ source: t.source, host: t.host });
  return `/api/runs/http-traces/${encodeURIComponent(t.run_id)}?${params.toString()}`;
}

function fmtAttempt(job: Job): string {
  if (job.attempt === 0) return "";
  return job.max_attempts > 1 ? `${job.attempt} of ${job.max_attempts}` : String(job.attempt);
}

/** The run source of the demo estate load (app/demo_estate.py). */
const DEMO_SOURCE = "demo";

/**
 * The demo estate load, on a demo instance only (GET /api/runs `demo`): the bundled
 * synthetic estate as a `demo` run, which publishes estate versions 1, 2 and 3 as three
 * runs, creates the demo sites that do not exist and imports the five business
 * applications.
 */
function DemoEstateCard({ data }: { data: RunHistory }) {
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const load = useMutation<Run | QueuedRun, ApiError>({
    mutationFn: () => api<Run | QueuedRun>("/runs", { method: "POST", body: { source: DEMO_SOURCE } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["runs"] });
      queryClient.invalidateQueries({ queryKey: ["jobs"] });
    },
  });
  const last = data.runs.find((r) => r.source === DEMO_SOURCE);
  const running = last?.status === "running";
  const queued = pendingRuns(data).some((j) => j.source === DEMO_SOURCE);

  async function handleLoad() {
    if (
      !window.confirm(
        "Publish the demo estate as 3 runs and make the last run the current run",
      )
    )
      return;
    setError(null);
    try {
      await load.mutateAsync();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Demo estate load not started");
    }
  }

  return (
    <div className="editorcard">
      <div className="bar">
        <span className="eyebrow">Demo estate</span>
      </div>
      <div className="runs-trigger-row">
        <button
          className="primary"
          type="button"
          disabled={running || queued || load.isPending}
          onClick={handleLoad}
        >
          {running ? "Loading" : queued ? "Queued" : load.isPending ? "Starting" : "Load demo estate"}
        </button>
      </div>
      {last && (
        <div className="banner" role="status">
          <div className="sub">
            Last demo load: <span className={`run-status run-status-${last.status}`}>{last.status}</span>
            {last.finished_at ? `, finished ${fmtTime(last.finished_at)}` : `, started ${fmtTime(last.started_at)}`}
            {last.detail && <div className="dim">{last.detail}</div>}
          </div>
        </div>
      )}
      {error && (
        <div className="banner err" role="alert">
          <div className="sub">{error}</div>
        </div>
      )}
    </div>
  );
}

export default function RunsPage() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const [triggerError, setTriggerError] = useState<{ source: string; message: string } | null>(null);
  const [purgeNote, setPurgeNote] = useState<string | null>(null);

  const runsQuery = useQuery<RunHistory, ApiError>({
    queryKey: ["runs"],
    queryFn: () => api<RunHistory>("/runs"),
    refetchInterval: (query) =>
      hasRunning(query.state.data) || pendingRuns(query.state.data).length > 0 ? POLL_MS : false,
  });

  const jobsQuery = useQuery<JobHistory, ApiError>({
    queryKey: ["jobs"],
    queryFn: () => api<JobHistory>("/jobs"),
    refetchInterval: (query) => (hasPending(query.state.data) ? POLL_MS : false),
  });

  // A trace exists only for a source that HST_HTTP_TRACE names.
  const tracesQuery = useQuery<HttpTraces, ApiError>({
    queryKey: ["http-traces"],
    queryFn: () => api<HttpTraces>("/runs/http-traces"),
    refetchInterval: (query) => (hasRunning(runsQuery.data) && query.state.data?.enabled ? POLL_MS : false),
  });

  const debugQuery = useQuery<DebugOverview, ApiError>({
    queryKey: ["debug-capture"],
    queryFn: () => api<DebugOverview>("/debug-capture"),
    refetchInterval: (query) =>
      hasRunning(runsQuery.data) && query.state.data?.sources.some((s) => s.until_ms !== null) ? POLL_MS : false,
  });

  const triggerMutation = useMutation<Run | QueuedRun, ApiError, string>({
    mutationFn: (source) => api<Run | QueuedRun>("/runs", { method: "POST", body: { source } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["runs"] });
      queryClient.invalidateQueries({ queryKey: ["jobs"] });
    },
  });

  const runningSources = new Set((runsQuery.data?.runs ?? []).filter((r) => r.status === "running").map((r) => r.source));
  const queuedSources = new Set(pendingRuns(runsQuery.data).map((j) => j.source));

  async function handleTrigger(source: string) {
    setTriggerError(null);
    try {
      await triggerMutation.mutateAsync(source);
    } catch (err) {
      setTriggerError({ source, message: err instanceof ApiError ? err.message : "Trigger failed" });
    }
  }

  const cancelMutation = useMutation<{ id: number; status: string }, ApiError, CancelTarget>({
    mutationFn: ({ id, source }) =>
      api<{ id: number; status: string }>(`/runs/${id}/cancel`, {
        method: "POST",
        body: source ? { source } : {},
      }),
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ["runs"] });
    },
  });

  function isTarget(target: CancelTarget): boolean {
    const v = cancelMutation.variables;
    return !!v && v.id === target.id && v.source === target.source;
  }

  function cancelling(target: CancelTarget): boolean {
    return cancelMutation.isPending && isTarget(target);
  }

  const purgeMutation = useMutation<{ deleted_nodes: number }, ApiError>({
    mutationFn: () => api<{ deleted_nodes: number }>("/graph/purge", { method: "POST" }),
    onSuccess: (data) => {
      setPurgeNote(`${data.deleted_nodes} nodes deleted`);
      queryClient.invalidateQueries({ queryKey: ["runs"] });
    },
    onError: (err) => setPurgeNote(err instanceof ApiError ? err.message : "Purge failed"),
  });

  function handlePurge() {
    if (
      !window.confirm(
        "Delete every node and relationship of the graph in Neo4j",
      )
    )
      return;
    setPurgeNote(null);
    purgeMutation.mutate();
  }

  const runs = runsQuery.data?.runs ?? [];
  const jobs = jobsQuery.data?.jobs ?? [];

  return (
    <div className="ops-page">
      <div className="editorcard">
        <div className="bar">
          <span className="eyebrow">Sources</span>
        </div>
        <div className="runs-triggers">
          {(runsQuery.data?.sources ?? []).map((source) => {
            const running = runningSources.has(source);
            const queued = queuedSources.has(source);
            const pendingThis = triggerMutation.isPending && triggerMutation.variables === source;
            return (
              <div className="runs-trigger-row" key={source}>
                <span className="runs-source-name">{source}</span>
                <button
                  className="primary"
                  type="button"
                  aria-label={`Trigger ${source}`}
                  disabled={running || queued || pendingThis}
                  onClick={() => handleTrigger(source)}
                >
                  {running ? "Running" : queued ? "Queued" : pendingThis ? "Starting" : "Trigger"}
                </button>
              </div>
            );
          })}
          {runsQuery.isSuccess && (runsQuery.data?.sources ?? []).length === 0 && (
            <div className="hint">No enabled sources</div>
          )}
        </div>
        {triggerError && (
          <div className="banner err" role="alert">
            <div className="sub">
              {triggerError.source}: {triggerError.message}
            </div>
          </div>
        )}
      </div>

      {user && atLeast(user.role, "admin") && runsQuery.data?.demo && <DemoEstateCard data={runsQuery.data} />}

      {user && atLeast(user.role, "admin") && (
        <div className="editorcard">
          <div className="bar">
            <span className="eyebrow">Danger zone</span>
          </div>
          <div className="runs-trigger-row">
            <button
              className="linkish sf-danger"
              type="button"
              disabled={purgeMutation.isPending}
              onClick={handlePurge}
            >
              {purgeMutation.isPending ? "Purging" : "Purge graph"}
            </button>
          </div>
          {purgeNote && (
            <div className={"banner" + (purgeMutation.isError ? " err" : "")} role="status">
              <div className="sub">{purgeNote}</div>
            </div>
          )}
        </div>
      )}

      <div className="results">
        <div className="eyebrow">History</div>
        {runsQuery.isLoading && <div className="hint">Loading</div>}
        {runsQuery.isError && <div className="hint">{runsQuery.error.message}</div>}
        {runsQuery.isSuccess && runs.length === 0 && <div className="tableempty">No runs</div>}
        {runs.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Status</th>
                <th>Started</th>
                <th>Finished</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id}>
                  <td>{r.source}</td>
                  <td className={`run-status run-status-${r.status}`}>{r.status}</td>
                  <td>{fmtTime(r.started_at)}</td>
                  <td>{fmtTime(r.finished_at)}</td>
                  <td className="dim">
                    {r.detail}
                    {r.status === "running" &&
                      r.progress?.map((p) => (
                        <div className="runs-source-progress" key={p.source}>
                          <CollectionProgressView progress={p} />
                          {(r.progress?.length ?? 0) > 1 && (
                            <button
                              type="button"
                              className="runs-cancel"
                              aria-label={`Cancel ${p.source} in run ${r.id}`}
                              disabled={cancelling({ id: r.id, source: p.source })}
                              onClick={() => cancelMutation.mutate({ id: r.id, source: p.source })}
                            >
                              {cancelling({ id: r.id, source: p.source })
                                ? "Stopping"
                                : `Cancel ${p.source}`}
                            </button>
                          )}
                        </div>
                      ))}
                    {r.status === "running" && (
                      <button
                        type="button"
                        className="runs-cancel"
                        aria-label={`Cancel run ${r.id}`}
                        disabled={cancelling({ id: r.id })}
                        onClick={() => cancelMutation.mutate({ id: r.id })}
                      >
                        {cancelling({ id: r.id }) ? "Stopping" : "Cancel"}
                      </button>
                    )}
                    {cancelMutation.isError && cancelMutation.variables?.id === r.id && (
                      <span className="hint">{cancelMutation.error.message}</span>
                    )}
                    {capturesOfRun(r, debugQuery.data).length > 0 && (
                      <div>
                        <a href={runBundleHref(r.id)} download>
                          Debug bundle
                        </a>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="results">
        <div className="eyebrow">Maintenance</div>
        {jobsQuery.isLoading && <div className="hint">Loading</div>}
        {jobsQuery.isError && <div className="hint">{jobsQuery.error.message}</div>}
        {jobsQuery.isSuccess && jobs.length === 0 && (
          <div className="tableempty">No maintenance jobs</div>
        )}
        {jobs.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Job</th>
                <th>State</th>
                <th>Attempt</th>
                <th>Started</th>
                <th>Finished</th>
                <th>Took</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((j) => (
                <tr key={j.id}>
                  <td className="runs-source-name">{j.kind}</td>
                  <td className={`run-status run-status-${j.state}`}>{j.state}</td>
                  <td>{fmtAttempt(j)}</td>
                  <td>{fmtTime(j.started_at)}</td>
                  <td>{fmtTime(j.finished_at)}</td>
                  <td>{fmtDuration(j.duration_s)}</td>
                  <td className="dim">{j.detail}{j.state === "running" && j.progress?.map(p => <CollectionProgressView key={p.source} progress={p} />)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {debugQuery.isSuccess && (
        <CollectionDebug
          overview={debugQuery.data}
          unredacted={!!user?.permissions.includes("sources.write")}
        />
      )}

      {tracesQuery.isSuccess && (tracesQuery.data.enabled || tracesQuery.data.traces.length > 0) && (
        <div className="results">
          <div className="eyebrow">HTTP traces</div>
          <div className="hint">
            {tracesQuery.data.enabled
              ? `Tracing on: ${tracesQuery.data.enabled === "*" ? "all sources" : tracesQuery.data.enabled}`
              : "Tracing off"}
          </div>
          {tracesQuery.data.traces.length === 0 && <div className="tableempty">No traces</div>}
          {tracesQuery.data.traces.length > 0 && (
            <table>
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Host</th>
                  <th>Fetched</th>
                  <th>Size</th>
                  <th>File</th>
                </tr>
              </thead>
              <tbody>
                {tracesQuery.data.traces.map((t) => (
                  <tr key={`${t.source}/${t.host}/${t.run_id}`}>
                    <td>{t.source}</td>
                    <td className="dim">{t.host}</td>
                    <td>{fmtTime(new Date(t.fetch_ts_ms).toISOString())}</td>
                    <td>{fmtSize(t.size)}</td>
                    <td>
                      <a href={traceHref(t)} download={`${t.run_id}.http.jsonl`}>
                        {t.run_id}.http.jsonl
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
