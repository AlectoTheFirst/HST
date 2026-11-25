/**
 * The devices of one source.
 */

import { DeviceName } from "../shell/deviceNames";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import type {
  SourceDevice,
  SourceDeviceIn,
  SourceDeviceStatus,
  SourceDevicesResponse,
  SourceTestResult,
  GroupEffectiveResponse,
} from "../api/types";

function StatusLine({ status }: { status: SourceDeviceStatus | null | undefined }) {
  if (!status || !status.last_attempt_at) {
    return <span className="hint">never collected</span>;
  }
  const failing = status.consecutive_failures > 0;
  const when = failing ? status.last_attempt_at : (status.last_success_at ?? status.last_attempt_at);
  const timings = [
    status.fetch_ms !== null ? `fetch ${status.fetch_ms}ms` : null,
    status.load_ms !== null ? `load ${status.load_ms}ms` : null,
  ].filter(Boolean);
  return (
    <>
      <span className={"badge " + (failing ? "warn" : "ok")} title={failing ? status.last_error : undefined}>
        {failing ? `${status.consecutive_failures} consecutive failures` : "collecting"}
      </span>
      <span className="hint">
        {(failing ? "last attempt " : "last success ") + new Date(when).toLocaleString()}
        {timings.length > 0 ? `, ${timings.join(", ")}` : ""}
      </span>
      {failing && status.last_error && <span className="hint">{status.last_error}</span>}
    </>
  );
}

interface DraftDevice {
  host: string;
  port: string; // "" = follow the group
  enabled: boolean;
}

function toDraft(d: SourceDevice): DraftDevice {
  return {
    host: d.host,
    port: d.port === null ? "" : String(d.port),
    enabled: d.enabled,
  };
}

function toRequest(drafts: DraftDevice[]): SourceDeviceIn[] {
  return drafts.map((d) => ({
    host: d.host.trim(),
    port: d.port.trim() === "" ? null : Number(d.port),
    enabled: d.enabled,
  }));
}

/** First problem that makes the draft unsendable, or null. */
function draftError(drafts: DraftDevice[]): string | null {
  const seen = new Set<string>();
  for (const d of drafts) {
    const host = d.host.trim();
    if (!host) return "Missing host";
    if (seen.has(host)) return `Duplicate host ${host}`;
    seen.add(host);
    if (d.port.trim() !== "" && !/^\d+$/.test(d.port.trim())) return `${host}: port not a number`;
  }
  return null;
}

export function DevicesPanel({
  sourceName,
  canManage,
  fleetCapable = true,
}: {
  sourceName: string;
  canManage: boolean;
  fleetCapable?: boolean;
}) {
  const queryClient = useQueryClient();
  const [drafts, setDrafts] = useState<DraftDevice[] | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [probeResults, setProbeResults] = useState<Record<string, SourceTestResult>>({});
  const [probing, setProbing] = useState<ReadonlySet<string>>(() => new Set());
  const [pasting, setPasting] = useState(false);
  const [pasteText, setPasteText] = useState("");
  const deviceQueryKey = ["source-devices", sourceName];

  const devicesQuery = useQuery<SourceDevicesResponse, ApiError>({
    queryKey: deviceQueryKey,
    queryFn: () => api<SourceDevicesResponse>(`/sources/${encodeURIComponent(sourceName)}/devices`),
    enabled: fleetCapable,
  });
  const effectiveQuery = useQuery<GroupEffectiveResponse, ApiError>({
    queryKey: ["group-effective", sourceName],
    queryFn: () => api<GroupEffectiveResponse>(`/sources/${encodeURIComponent(sourceName)}/effective`),
    enabled: !fleetCapable,
  });

  const server = devicesQuery.data?.devices ?? [];
  const rows = drafts ?? server.map(toDraft);
  const dirty = drafts !== null;
  const statusByHost = new Map(server.map((d) => [d.host, d.status]));

  const saveMutation = useMutation<SourceDevicesResponse, ApiError, SourceDeviceIn[]>({
    mutationFn: (devices) =>
      api<SourceDevicesResponse>(`/sources/${encodeURIComponent(sourceName)}/devices`, { method: "PUT", body: { devices } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: deviceQueryKey });
      setDrafts(null);
      setSaveError(null);
    },
    onError: (err) => setSaveError(err.message),
  });

  const probeMutation = useMutation<SourceTestResult, ApiError, string>({
    mutationFn: (host) =>
      api<SourceTestResult>(`/sources/${encodeURIComponent(sourceName)}/devices/${encodeURIComponent(host)}/test`, { method: "POST" }),
  });

  function edit(index: number, patch: Partial<DraftDevice>) {
    const next = rows.map((r, i) => (i === index ? { ...r, ...patch } : r));
    setDrafts(next);
    setSaveError(null);
  }

  function remove(index: number) {
    setDrafts(rows.filter((_, i) => i !== index));
    setSaveError(null);
  }

  function addRow() {
    setDrafts([...rows, { host: "", port: "", enabled: true }]);
    setSaveError(null);
  }

  function addPasted() {
    const added: DraftDevice[] = [];
    for (const raw of pasteText.split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      const [host, port = ""] = line.split(",").map((s) => s.trim());
      added.push({ host, port, enabled: true });
    }
    if (added.length) setDrafts([...rows, ...added]);
    setPasteText("");
    setPasting(false);
  }

  function save() {
    const problem = draftError(rows);
    if (problem) {
      setSaveError(problem);
      return;
    }
    saveMutation.mutate(toRequest(rows));
  }

  async function probe(host: string) {
    setProbing((prev) => new Set(prev).add(host));
    try {
      const result = await probeMutation.mutateAsync(host);
      setProbeResults((r) => ({ ...r, [host]: result }));
    } catch (err) {
      const detail = err instanceof ApiError ? err.message : "Probe failed";
      setProbeResults((r) => ({ ...r, [host]: { ok: false, detail } }));
    } finally {
      setProbing((prev) => {
        const next = new Set(prev);
        next.delete(host);
        return next;
      });
    }
  }

  if (!fleetCapable && effectiveQuery.isLoading) return <div className="hint">Loading discovered devices</div>;
  if (!fleetCapable && effectiveQuery.isError) return <div className="hint">{effectiveQuery.error.message}</div>;
  if (!fleetCapable) return (
    <div className="editorcard devices-panel">
      <div className="bar"><span className="eyebrow">Discovered devices</span></div>
      {(effectiveQuery.data?.devices ?? []).length === 0 && <div className="tableempty">No discovered devices</div>}
      {(effectiveQuery.data?.devices ?? []).map((device) => (
        <div className="device-row" key={`${device.host}:${device.device_uids.join(",")}`}>
          <span className="source-name">
            {device.device_uids.length
              ? device.device_uids.map((uid, i) => <span key={uid}>{i > 0 && ", "}<DeviceName uid={uid} /></span>)
              : device.host}
          </span>
          <span className="hint">Site {device.site ?? "unassigned"}, routing scope {device.values.routing_scope ?? "default"} ({device.origins.routing_scope}), L2 fabric {device.values.l2fabric ?? "default"} ({device.origins.l2fabric})</span>
        </div>
      ))}
    </div>
  );
  if (devicesQuery.isLoading) return <div className="hint">Loading devices</div>;
  if (devicesQuery.isError) return <div className="hint">{devicesQuery.error.message}</div>;

  return (
    <div className="editorcard devices-panel">
      <div className="bar">
        <span className="eyebrow">Devices</span>
      </div>

      {rows.length === 0 && !canManage && <div className="tableempty">No devices</div>}

      {rows.map((row, index) => {
        const result = probeResults[row.host];
        const effective = effectiveQuery.data?.devices.find((d) => d.host === row.host);
        return (
          <div className="device-row" key={index}>
            <span className="param sf-field">
              <label htmlFor={`dev-host-${sourceName}-${index}`}>Host</label>
              <input
                id={`dev-host-${sourceName}-${index}`}
                value={row.host}
                disabled={!canManage}
                onChange={(e) => edit(index, { host: e.target.value })}
              />
            </span>
            <span className="param sf-field">
              <label htmlFor={`dev-port-${sourceName}-${index}`}>Port</label>
              <input
                id={`dev-port-${sourceName}-${index}`}
                value={row.port}
                placeholder="group"
                inputMode="numeric"
                disabled={!canManage}
                onChange={(e) => edit(index, { port: e.target.value })}
              />
            </span>
            <span className="param sf-field">
              <label htmlFor={`dev-on-${sourceName}-${index}`}>Enabled</label>
              <input
                id={`dev-on-${sourceName}-${index}`}
                type="checkbox"
                checked={row.enabled}
                disabled={!canManage}
                onChange={(e) => edit(index, { enabled: e.target.checked })}
              />
            </span>
            <div className="device-row-status">
              <StatusLine status={statusByHost.get(row.host)} />
              {effective && (
                <span className="hint">
                  Effective site {effective.site ?? "unassigned"}, routing scope {effective.values.routing_scope ?? "default"} ({effective.origins.routing_scope}), L2 fabric {effective.values.l2fabric ?? "default"} ({effective.origins.l2fabric})
                </span>
              )}
            </div>
            <div className="source-actions">
              <button
                type="button"
                className="linkish"
                aria-label={`Probe ${row.host}`}
                onClick={() => probe(row.host)}
                disabled={dirty || probing.has(row.host) || !row.host}
              >
                {probing.has(row.host) ? "Probing" : "Probe"}
              </button>
              {canManage && (
                <button
                  type="button"
                  className="linkish sf-danger"
                  aria-label={`Remove ${row.host || "device"}`}
                  onClick={() => remove(index)}
                >
                  Remove
                </button>
              )}
            </div>
            {result && (
              <div className={"banner " + (result.ok ? "ok" : "bad")}>
                <div className="sub">{result.detail || (result.ok ? "ok" : "failed")}</div>
              </div>
            )}
          </div>
        );
      })}

      {saveError && (
        <div className="banner err" role="alert">
          <div className="sub">{saveError}</div>
        </div>
      )}

      {canManage && pasting && (
        <div className="param sf-field">
          <label htmlFor={`dev-paste-${sourceName}`}>Hosts</label>
          <textarea
            id={`dev-paste-${sourceName}`}
            value={pasteText}
            rows={5}
            onChange={(e) => setPasteText(e.target.value)}
          />
          <div className="source-actions">
            <button type="button" className="linkish" onClick={addPasted}>
              Add hosts
            </button>
            <button type="button" className="linkish" onClick={() => setPasting(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {canManage && (
        <div className="source-actions card-actions">
          <button type="button" className="linkish" onClick={addRow}>
            Add device
          </button>
          {!pasting && (
            <button type="button" className="linkish" onClick={() => setPasting(true)}>
              Paste hosts
            </button>
          )}
          <button
            type="button"
            className="primary"
            onClick={save}
            disabled={!dirty || saveMutation.isPending}
          >
            {saveMutation.isPending ? "Saving" : "Save devices"}
          </button>
        </div>
      )}
    </div>
  );
}
