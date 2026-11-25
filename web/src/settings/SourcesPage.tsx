/**
 * The Sources page lists the sources from GET /api/sources.
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import { atLeast, useAuth } from "../auth";
import type {
  Source,
  SourceCreateRequest,
  SourceKind,
  SourcePatchRequest,
  SourceTestResult,
  SourceType,
  SourceTypeSchema,
  SourceTypesResponse,
  SourcesResponse,
} from "../api/types";
import { SaveWarnings } from "../inventory/ui/SaveWarnings";
import { DevicesPanel } from "./DevicesPanel";
import { SchemaForm } from "./SchemaForm";

function errorMessage(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.message : fallback;
}

function AddSourceForm({
  types,
  sources,
  onCreate,
  onCancel,
  pending,
  error,
  noun,
}: {
  types: SourceType[];
  /** Every configured source, for a config field that names one. */
  sources: Source[];
  onCreate: (body: SourceCreateRequest) => void;
  onCancel: () => void;
  pending: boolean;
  error: string | null;
  noun: string;
}) {
  const [name, setName] = useState("");
  const [type, setType] = useState("");
  const schema = types.find((t) => t.type === type)?.schema;

  if (!types.length) {
    return (
      <div className="editorcard">
        <div className="bar">
          <span className="eyebrow">Add {noun}</span>
          <button type="button" className="linkish" onClick={onCancel}>
            Cancel
          </button>
        </div>
        <p className="hint">No {noun} types</p>
      </div>
    );
  }

  return (
    <div className="editorcard">
      <div className="bar">
        <span className="eyebrow">Add {noun}</span>
        <button type="button" className="linkish" onClick={onCancel}>
          Cancel
        </button>
      </div>
      <div className="param sf-field">
        <label htmlFor="new-source-name">Name</label>
        {/* The name becomes the source's `scope`. */}
        <input
          id="new-source-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          // The `v` RegExp flag of `pattern` needs the escaped hyphen.
          pattern="[a-z0-9\-]{2,32}"
          aria-describedby="new-source-name-hint"
          required
        />
        <p id="new-source-name-hint" className="sf-hint">
          2 to 32 lowercase letters, digits and hyphens
        </p>
      </div>
      <div className="param sf-field">
        <label htmlFor="new-source-type">Type</label>
        <select id="new-source-type" value={type} onChange={(e) => setType(e.target.value)}>
          <option value="">Choose a type</option>
          {types.map((t) => (
            <option key={t.type} value={t.type}>
              {t.type}
            </option>
          ))}
        </select>
      </div>
      {schema && (
        <SchemaForm
          schema={schema}
          mode="create"
          submitLabel="Create"
          pending={pending}
          error={error}
          sources={sources}
          onSubmit={(config) => onCreate({ name, type, config })}
        />
      )}
    </div>
  );
}

function SourceRow({
  source,
  schema,
  canManage,
  editing,
  showingDevices,
  onToggleDevices,
  onToggleEdit,
  onSaveConfig,
  savePending,
  saveError,
  onToggleEnabled,
  togglePending,
  onDelete,
  deletePending,
  onProbe,
  rowError,
  probeResult,
  probePending,
  sources,
}: {
  source: Source;
  schema: SourceTypeSchema | undefined;
  canManage: boolean;
  /** Every configured source, for a config field that names one. */
  sources: Source[];
  editing: boolean;
  showingDevices: boolean;
  onToggleDevices: () => void;
  onToggleEdit: () => void;
  onSaveConfig: (config: Record<string, unknown>) => void;
  savePending: boolean;
  saveError: string | null;
  onToggleEnabled: () => void;
  togglePending: boolean;
  onDelete: () => void;
  deletePending: boolean;
  onProbe: () => void;
  rowError: string | null;
  probeResult: SourceTestResult | undefined;
  probePending: boolean;
}) {
  const fleetCapable = source.kind === "group";
  return (
    <div className="source-row">
      <div className="source-row-head">
        <span className="source-name">{source.name}</span>
        <span className="source-type">{source.type}</span>
        {typeof source.config.interval_s === "number" && source.config.interval_s > 0 && (
          <span className="badge ok">polls every {source.config.interval_s}s</span>
        )}
        <span className={"badge " + (source.enabled ? "ok" : "warn")}>
          {source.enabled ? "enabled" : "disabled"}
        </span>
        {Object.entries(source.secrets).map(([field, isSet]) => (
          <span className={"badge " + (isSet ? "ok" : "warn")} key={field}>
            {field}: {isSet ? "set" : "not set"}
          </span>
        ))}
        <span className="source-updated hint">{source.updated_at ? `updated ${source.updated_at}` : ""}</span>
        <div className="source-actions">
          {schema && (
            <button
              type="button"
              className="linkish"
              aria-label={`Devices of ${source.name}`}
              onClick={onToggleDevices}
            >
              {showingDevices
                ? "Close devices"
                : fleetCapable
                  ? "Collection targets"
                  : "Discovered devices"}
            </button>
          )}
          {canManage && (
            <button type="button" className="linkish" aria-label={`Edit ${source.name}`} onClick={onToggleEdit}>
              {editing ? "Close" : "Edit"}
            </button>
          )}
          {canManage && (
            <button
              type="button"
              className="linkish"
              aria-label={`${source.enabled ? "Disable" : "Enable"} ${source.name}`}
              onClick={onToggleEnabled}
              disabled={togglePending}
            >
              {togglePending ? "Working" : source.enabled ? "Disable" : "Enable"}
            </button>
          )}
          <button
            type="button"
            className="linkish"
            aria-label={`Probe ${source.name}`}
            onClick={onProbe}
            disabled={probePending}
          >
            {probePending ? "Probing" : "Probe"}
          </button>
          {canManage && (
            <button
              type="button"
              className="linkish sf-danger"
              aria-label={`Delete ${source.name}`}
              onClick={onDelete}
              disabled={deletePending}
            >
              {deletePending ? "Deleting" : "Delete"}
            </button>
          )}
        </div>
      </div>
      {rowError && (
        <div className="banner err" role="alert">
          <div className="sub">{rowError}</div>
        </div>
      )}
      {probeResult && (
        <div className={"banner " + (probeResult.ok ? "ok" : "bad")}>
          <div className="sub">{probeResult.detail || (probeResult.ok ? "ok" : "failed")}</div>
        </div>
      )}
      {canManage && editing && schema && (
        <SchemaForm
          schema={schema}
          config={source.config}
          mode="edit"
          submitLabel="Save"
          pending={savePending}
          error={saveError}
          sources={sources}
          onSubmit={onSaveConfig}
          onSubmitConnection={onSaveConfig}
          onSubmitCollection={onSaveConfig}
        />
      )}
      {showingDevices && (
        <DevicesPanel
          sourceName={source.name}
          canManage={canManage}
          fleetCapable={fleetCapable}
        />
      )}
    </div>
  );
}

/** The source list. `kind` picks which half of it a page shows and what a row
 * is called; without it every source is listed. */
export default function SourcesPage({ kind }: { kind?: SourceKind } = {}) {
  const { user } = useAuth();
  const noun = kind === "group" ? "group" : kind === "orchestrator" ? "orchestrator" : "source";
  const title = kind === "group" ? "Groups" : kind === "orchestrator" ? "Orchestrators" : "Sources";
  const canManage = !!user && atLeast(user.role, "admin");
  const queryClient = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [editingName, setEditingName] = useState<string | null>(null);
  const [devicesName, setDevicesName] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [rowError, setRowError] = useState<{ name: string; message: string } | null>(null);
  const [saveWarnings, setSaveWarnings] = useState<{ name: string; warnings: string[] } | null>(null);
  const showWarnings = (saved: Source) => setSaveWarnings(saved.warnings?.length ? { name: saved.name, warnings: saved.warnings } : null);
  const [probeResults, setProbeResults] = useState<Record<string, SourceTestResult>>({});
  const [probing, setProbing] = useState<ReadonlySet<string>>(() => new Set());

  const typesQuery = useQuery<SourceTypesResponse, ApiError>({
    queryKey: ["source-types"],
    queryFn: () => api<SourceTypesResponse>("/source-types"),
  });
  const sourcesQuery = useQuery<SourcesResponse, ApiError>({
    queryKey: ["sources"],
    queryFn: () => api<SourcesResponse>("/sources"),
  });

  const createMutation = useMutation<Source, ApiError, SourceCreateRequest>({
    mutationFn: (body) => api<Source>("/sources", { method: "POST", body }),
    onSuccess: (saved) => {
      queryClient.invalidateQueries({ queryKey: ["sources"] });
      setAdding(false);
      setCreateError(null);
      showWarnings(saved);
    },
    onError: (err) => setCreateError(err.message),
  });

  const saveConfigMutation = useMutation<Source, ApiError, { name: string; config: Record<string, unknown> }>({
    mutationFn: ({ name, config }) =>
      api<Source>(`/sources/${encodeURIComponent(name)}`, { method: "PATCH", body: { config } }),
    onSuccess: (saved) => {
      queryClient.invalidateQueries({ queryKey: ["sources"] });
      setEditingName(null);
      setSaveError(null);
      showWarnings(saved);
    },
    onError: (err) => setSaveError(err.message),
  });

  const toggleMutation = useMutation<Source, ApiError, { name: string; body: SourcePatchRequest }>({
    mutationFn: ({ name, body }) => api<Source>(`/sources/${encodeURIComponent(name)}`, { method: "PATCH", body }),
    onSuccess: (saved) => {
      queryClient.invalidateQueries({ queryKey: ["sources"] });
      setRowError(null);
      showWarnings(saved);
    },
  });

  const deleteMutation = useMutation<{ ok: boolean }, ApiError, string>({
    mutationFn: (name) => api(`/sources/${encodeURIComponent(name)}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sources"] });
      setRowError(null);
    },
  });

  const probeMutation = useMutation<SourceTestResult, ApiError, string>({
    mutationFn: (name) => api<SourceTestResult>(`/sources/${encodeURIComponent(name)}/test`, { method: "POST" }),
  });

  async function handleDelete(name: string) {
    if (!window.confirm(`Delete source ${name}`)) return;
    try {
      await deleteMutation.mutateAsync(name);
    } catch (err) {
      setRowError({ name, message: errorMessage(err, "Delete failed") });
    }
  }

  async function handleToggleEnabled(name: string, enabled: boolean) {
    try {
      await toggleMutation.mutateAsync({ name, body: { enabled } });
    } catch (err) {
      setRowError({ name, message: errorMessage(err, "Update failed") });
    }
  }

  function handleToggleEdit(name: string) {
    setSaveError(null);
    setEditingName((current) => (current === name ? null : name));
  }

  async function handleProbe(name: string) {
    setProbing((prev) => new Set(prev).add(name));
    try {
      const result = await probeMutation.mutateAsync(name);
      setProbeResults((r) => ({ ...r, [name]: result }));
    } catch (err) {
      setProbeResults((r) => ({ ...r, [name]: { ok: false, detail: errorMessage(err, "Probe failed") } }));
    } finally {
      setProbing((prev) => {
        const next = new Set(prev);
        next.delete(name);
        return next;
      });
    }
  }

  const types = typesQuery.data?.types ?? [];
  const addableTypes = kind ? types.filter((t) => t.kind === kind) : types;
  // A config field that names another source reads the unfiltered list.
  const allSources = sourcesQuery.data?.sources ?? [];
  const sources = allSources.filter((s) => !kind || s.kind === kind);

  return (
    <div className="ops-page">
      <div className="bar">
        <span className="eyebrow">{title}</span>
        {canManage && !adding && (
          <button type="button" className="primary" onClick={() => setAdding(true)}>
            Add {noun}
          </button>
        )}
      </div>

      {saveWarnings && (
        <SaveWarnings subject={saveWarnings.name} warnings={saveWarnings.warnings} onDismiss={() => setSaveWarnings(null)} />
      )}

      {sourcesQuery.isLoading && <div className="hint">Loading</div>}
      {sourcesQuery.isError && <div className="hint">{sourcesQuery.error.message}</div>}
      {sourcesQuery.isSuccess && sources.length === 0 && !adding && (
        <div className="tableempty">No {noun}s</div>
      )}

      {canManage && adding && (
        <AddSourceForm
          types={addableTypes}
          sources={allSources}
          pending={createMutation.isPending}
          error={createError}
          noun={noun}
          onCancel={() => {
            setAdding(false);
            setCreateError(null);
          }}
          onCreate={(body) => createMutation.mutate(body)}
        />
      )}

      <div className="source-list">
        {sources.map((source) => (
          <SourceRow
            key={source.name}
            source={source}
            sources={allSources}
            schema={types.find((t) => t.type === source.type)?.schema}
            canManage={canManage}
            editing={editingName === source.name}
            showingDevices={devicesName === source.name}
            onToggleDevices={() =>
              setDevicesName((current) => (current === source.name ? null : source.name))
            }
            onToggleEdit={() => handleToggleEdit(source.name)}
            onSaveConfig={(config) => saveConfigMutation.mutate({ name: source.name, config })}
            savePending={saveConfigMutation.isPending && saveConfigMutation.variables?.name === source.name}
            saveError={editingName === source.name ? saveError : null}
            onToggleEnabled={() => handleToggleEnabled(source.name, !source.enabled)}
            togglePending={toggleMutation.isPending && toggleMutation.variables?.name === source.name}
            onDelete={() => handleDelete(source.name)}
            deletePending={deleteMutation.isPending && deleteMutation.variables === source.name}
            onProbe={() => handleProbe(source.name)}
            rowError={rowError?.name === source.name ? rowError.message : null}
            probeResult={probeResults[source.name]}
            probePending={probing.has(source.name)}
          />
        ))}
      </div>
    </div>
  );
}
