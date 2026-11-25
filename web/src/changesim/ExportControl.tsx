/** The backend (POST /api/changesim/export) runs the simulation again at the depth chosen here. */

import { useState } from "react";
import { ApiError, apiDownload } from "../api/client";
import { formatSnapshotDate } from "../flowdesk/SnapshotPicker";
import type { SimulatePolicyChangeResult, SimulatedFlowSpec } from "./assessImpact";
import "./changesim.css";

/** The engine's depth bounds (src/hst/app/fw_overlay_read.py). */
const MIN_DEPTH = 1;
const MAX_DEPTH = 8;

/** A result whose flows the tool derived sends no flows. */
function flowsToSend(policy: SimulatePolicyChangeResult): SimulatedFlowSpec[] | undefined {
  if (policy.flows_derived) return undefined;
  const specs = (policy.flows ?? [])
    .map((entry) => entry.flow ?? {})
    .filter((flow): flow is SimulatedFlowSpec => Boolean(flow.src && flow.dst))
    .map((flow) => {
      const port = flow.port == null || flow.port === "" ? undefined : Number(flow.port);
      return {
        src: flow.src,
        dst: flow.dst,
        ...(port != null && Number.isFinite(port) ? { port } : {}),
        ...(flow.proto ? { proto: flow.proto } : {}),
        ...(flow.mtu ? { mtu: flow.mtu } : {}),
      };
    });
  return specs.length ? specs : undefined;
}

function parseSites(raw: string): string[] {
  return raw
    .split(",")
    .map((site) => site.trim())
    .filter(Boolean);
}

/** The object URL is revoked after the click is dispatched. */
function save(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function snapshotText(id: string | null): string {
  return id ? formatSnapshotDate(Number(id)) : "no recorded run";
}

export function ExportControl({ policy }: { policy: SimulatePolicyChangeResult }) {
  // The depth is clamped once, in submit().
  const [depth, setDepth] = useState(String(MIN_DEPTH));
  const [sites, setSites] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ranAt, setRanAt] = useState<string | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (pending) return;
    setPending(true);
    setError(null);
    try {
      const named = parseSites(sites);
      const chosen = Math.min(MAX_DEPTH, Math.max(MIN_DEPTH, Math.round(Number(depth) || MIN_DEPTH)));
      const { blob, filename, headers } = await apiDownload("/changesim/export", {
        method: "POST",
        body: {
          intents: policy.intents ?? [],
          flows: flowsToSend(policy),
          depth: chosen,
          ...(named.length ? { sites: named } : {}),
        },
        fallbackFilename: "hst-change-simulation.zip",
      });
      save(blob, filename);
      setRanAt(headers.get("X-HST-Snapshot") || "");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "export could not be generated");
    } finally {
      setPending(false);
    }
  }

  const shown = policy.snapshot ?? "";
  const differs = ranAt !== null && ranAt !== shown;

  return (
    // noValidate: the clamp in submit() decides the depth.
    <form className="chgsim-export" onSubmit={submit} noValidate>
      <div className="chgsim-exportfields">
        <label className="chgsim-exportfield">
          <span>Depth</span>
          <input
            type="number"
            min={MIN_DEPTH}
            max={MAX_DEPTH}
            value={depth}
            disabled={pending}
            onChange={(e) => setDepth(e.target.value)}
          />
        </label>
        <label className="chgsim-exportfield">
          <span>Sites</span>
          <input
            type="text"
            placeholder="all sites"
            value={sites}
            disabled={pending}
            onChange={(e) => setSites(e.target.value)}
          />
        </label>
        <button type="submit" disabled={pending}>
          {pending ? "Generating" : "Download full detail"}
        </button>
      </div>
      {differs && (
        <p className="chgsim-truncated">
          {`Export run ${snapshotText(ranAt || null)}`}
        </p>
      )}
      {error && <p className="chgsim-truncated">{error}</p>}
    </form>
  );
}
