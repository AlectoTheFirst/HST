/**
 * Collection debug on the Runs page (routes/debug_capture.py): the capture
 * switch per source, the captures on disk, and per source its newest stored
 * payloads with a re-parse in isolation.
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import type { DebugCapture, DebugOverview, DebugPayloads, Run } from "../api/types";

const REPARSE_POLL_MS = 2000;

const UNREDACTED_CONFIRM =
  "Download the unredacted bundle with the device output and the credentials";

function fmtMs(ms: number | null | undefined): string {
  return ms ? new Date(ms).toLocaleString() : "";
}

function fmtKib(kib: number | null | undefined): string {
  if (!kib) return "";
  return kib < 1024 ? `${kib} KiB` : `${(kib / 1024).toFixed(0)} MiB`;
}

function fmtBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

export function payloadBundleHref(
  p: { source: string; host: string; run_id: string },
  raw: "redacted" | "full" = "redacted",
): string {
  const params = new URLSearchParams({ source: p.source, host: p.host, run_id: p.run_id, raw });
  return `/api/debug-capture/bundle?${params.toString()}`;
}

export function runBundleHref(id: number, raw: "redacted" | "full" = "redacted"): string {
  return `/api/runs/${id}/debug-bundle?raw=${raw}`;
}

/** The captures a run's bundle holds: begun between the run's start and its
 *  finish, of the run's own source, or of any source for a run that is not
 *  one source's (a cycle). The same rule the bundle endpoint applies. */
export function capturesOfRun(run: Run, overview: DebugOverview | undefined): DebugCapture[] {
  if (!overview) return [];
  const started = Date.parse(run.started_at);
  const finished = run.finished_at ? Date.parse(run.finished_at) : Date.now();
  const single = overview.sources.some((s) => s.name === run.source);
  return overview.captures.filter(
    (c) =>
      c.begin_ms !== null &&
      c.begin_ms >= started &&
      c.begin_ms <= finished &&
      (!single || c.source_name === run.source),
  );
}

function downloadUnredacted(href: string) {
  if (window.confirm(UNREDACTED_CONFIRM)) window.location.assign(href);
}

function captureResult(c: DebugCapture): string {
  if (!c.finished) return "No finish record";
  return c.status === "ok" ? "ok" : `error: ${c.error ?? ""}`;
}

function runningStep(c: DebugCapture): string {
  if (c.finished || c.open_steps.length === 0) return "";
  const s = c.open_steps[c.open_steps.length - 1];
  return s.command ? `${s.step} (${s.command})` : s.step;
}

function Payloads({ source, unredacted }: { source: string; unredacted: boolean }) {
  const queryClient = useQueryClient();
  const query = useQuery<DebugPayloads, ApiError>({
    queryKey: ["debug-payloads", source],
    queryFn: () => api<DebugPayloads>(`/debug-capture/payloads?source=${encodeURIComponent(source)}`),
    refetchInterval: (q) =>
      q.state.data?.payloads.some((p) => p.reparse?.state === "running") ? REPARSE_POLL_MS : false,
  });
  const reparse = useMutation<unknown, ApiError, { host: string; run_id: string }>({
    mutationFn: ({ host, run_id }) =>
      api("/debug-capture/reparse", { method: "POST", body: { source, host, run_id } }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["debug-payloads", source] }),
  });

  if (query.isLoading) return <div className="hint">Loading</div>;
  if (query.isError) return <div className="hint">{query.error.message}</div>;
  const payloads = query.data?.payloads ?? [];
  if (payloads.length === 0) return <div className="tableempty">No stored payload</div>;
  return (
    <>
      <table>
        <thead>
          <tr>
            <th>Host</th>
            <th>Fetched</th>
            <th>Size</th>
            <th>Re-parse</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {payloads.map((p) => {
            const running = p.reparse?.state === "running";
            return (
              <tr key={p.id}>
                <td className="dim">{p.host}</td>
                <td>{fmtMs(p.fetch_ts_ms)}</td>
                <td>{fmtBytes(p.size)}</td>
                <td className="dim">
                  {p.reparse ? p.reparse.state : "Not run"}
                  {p.reparse?.error ? `: ${p.reparse.error}` : ""}
                  {p.reparse?.peak_rss_kb ? `, peak ${fmtKib(p.reparse.peak_rss_kb)}` : ""}
                </td>
                <td>
                  <button
                    type="button"
                    className="linkish"
                    aria-label={`Parse ${p.host || p.source} ${p.run_id} again in isolation`}
                    disabled={running}
                    onClick={() => reparse.mutate({ host: p.host, run_id: p.run_id })}
                  >
                    {running ? "Parsing" : "Parse again in isolation"}
                  </button>{" "}
                  <a href={payloadBundleHref(p)} download>
                    Bundle
                  </a>
                  {unredacted && (
                    <>
                      {" "}
                      <button
                        type="button"
                        className="linkish"
                        onClick={() => downloadUnredacted(payloadBundleHref(p, "full"))}
                      >
                        Unredacted
                      </button>
                    </>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {reparse.isError && <div className="hint">{reparse.error.message}</div>}
    </>
  );
}

export function CollectionDebug({
  overview,
  unredacted = false,
}: {
  overview: DebugOverview;
  unredacted?: boolean;
}) {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState<string | null>(null);
  const toggle = useMutation<unknown, ApiError, { name: string; enabled: boolean }>({
    mutationFn: ({ name, enabled }) =>
      api(`/debug-capture/sources/${encodeURIComponent(name)}`, { method: "PUT", body: { enabled } }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["debug-capture"] }),
  });

  return (
    <div className="results">
      <div className="eyebrow">Collection debug</div>
      <table>
        <thead>
          <tr>
            <th>Source</th>
            <th>Type</th>
            <th>Capture</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {overview.sources.map((s) => {
            const on = s.until_ms !== null;
            return [
              <tr key={s.name}>
                <td className="runs-source-name">{s.name}</td>
                <td className="dim">{s.type}</td>
                <td>{on ? `On until ${fmtMs(s.until_ms)}${s.by ? `, by ${s.by}` : ""}` : "Off"}</td>
                <td>
                  <button
                    type="button"
                    className="linkish"
                    aria-label={`${on ? "Turn off" : "Turn on"} debug capture for ${s.name}`}
                    disabled={toggle.isPending && toggle.variables?.name === s.name}
                    onClick={() => toggle.mutate({ name: s.name, enabled: !on })}
                  >
                    {on ? "Turn off" : "Turn on"}
                  </button>{" "}
                  <button
                    type="button"
                    className="linkish"
                    aria-expanded={open === s.name}
                    onClick={() => setOpen(open === s.name ? null : s.name)}
                  >
                    {open === s.name ? "Hide payloads" : "Payloads"}
                  </button>
                </td>
              </tr>,
              open === s.name && (
                <tr key={`${s.name}-payloads`}>
                  <td colSpan={4}>
                    <Payloads source={s.name} unredacted={unredacted} />
                  </td>
                </tr>
              ),
            ];
          })}
        </tbody>
      </table>
      {toggle.isError && <div className="hint">{toggle.error.message}</div>}
      {overview.captures.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Source</th>
              <th>Host</th>
              <th>Began</th>
              <th>Result</th>
              <th>Running step</th>
              <th>Peak memory</th>
              <th>Download</th>
            </tr>
          </thead>
          <tbody>
            {overview.captures.map((c) => (
              <tr key={c.id}>
                <td>{c.source_name}</td>
                <td className="dim">{c.host}</td>
                <td>{fmtMs(c.begin_ms)}</td>
                <td className={c.finished && c.status === "ok" ? "" : "run-status-error"}>
                  {captureResult(c)}
                  {c.has_stack ? ", stack dump" : ""}
                </td>
                <td className="dim">{runningStep(c)}</td>
                <td>{fmtKib(c.peak_rss_kb)}</td>
                <td>
                  <a href={payloadBundleHref(c)} download>
                    Bundle
                  </a>
                  {unredacted && (
                    <>
                      {" "}
                      <button
                        type="button"
                        className="linkish"
                        onClick={() => downloadUnredacted(payloadBundleHref(c, "full"))}
                      >
                        Unredacted
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
