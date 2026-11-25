/**
 * The retention limits of the deployment.
 */

import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import { atLeast, useAuth } from "../auth";
import type { RetentionPatch, RetentionSettings } from "../api/types";

function errorMessage(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.message : fallback;
}

type FieldName = keyof RetentionPatch;
type Draft = Record<FieldName, string>;

/** The fields, in the order the page states them. `min` mirrors the
 *  server's bounds (routes/retention.py). */
const FIELDS: readonly { name: FieldName; label: string; min: number }[] = [
  { name: "cycle_keep_runs", label: "Graph history", min: 1 },
  { name: "cycle_keep_device_runs", label: "Device and refresh runs", min: 0 },
  { name: "login_event_retention_days", label: "Sign-in records", min: 0 },
  { name: "cypher_event_retention_days", label: "Cypher records", min: 0 },
  { name: "job_history_retention_days", label: "Maintenance job records", min: 0 },
  { name: "ai_conversation_retention_days", label: "AI conversations", min: 0 },
  { name: "ai_step_result_days", label: "AI tool results", min: 0 },
  { name: "ai_event_retention_days", label: "AI events", min: 0 },
];

function toDraft(settings: RetentionSettings): Draft {
  return {
    cycle_keep_runs: String(settings.cycle_keep_runs),
    cycle_keep_device_runs: String(settings.cycle_keep_device_runs),
    login_event_retention_days: String(settings.login_event_retention_days),
    cypher_event_retention_days: String(settings.cypher_event_retention_days),
    job_history_retention_days: String(settings.job_history_retention_days),
    ai_conversation_retention_days: String(settings.ai_conversation_retention_days),
    ai_step_result_days: String(settings.ai_step_result_days),
    ai_event_retention_days: String(settings.ai_event_retention_days),
  };
}

export default function LifecyclePage() {
  const { user: me } = useAuth();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<Draft | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  const settings = useQuery<RetentionSettings, ApiError>({
    queryKey: ["retention"],
    queryFn: () => api<RetentionSettings>("/settings/retention"),
  });

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (settings.data && !draft) setDraft(toDraft(settings.data));
  }, [settings.data, draft]);

  const save = useMutation<RetentionSettings, ApiError, RetentionPatch>({
    mutationFn: (body) => api<RetentionSettings>("/settings/retention", { method: "PATCH", body }),
    onSuccess: (saved) => {
      queryClient.setQueryData(["retention"], saved);
      setDraft(toDraft(saved));
      setSaveError(null);
    },
    onError: (err) => setSaveError(errorMessage(err, "Save failed")),
  });

  if (!me || !atLeast(me.role, "admin")) return null;

  if (settings.isLoading) {
    return (
      <div className="ops-page">
        <span className="hint">Loading</span>
      </div>
    );
  }
  if (settings.isError) {
    return (
      <div className="ops-page">
        <div className="banner err" role="alert">
          <div className="sub">{errorMessage(settings.error, "Retention settings not loaded")}</div>
        </div>
      </div>
    );
  }
  if (!draft) return null;

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!draft) return;
    const body: RetentionPatch = {};
    for (const field of FIELDS) {
      const value = Number(draft[field.name]);
      if (!Number.isInteger(value) || value < field.min) {
        setSaveError(`${field.label}: whole number of ${field.min} or more`);
        return;
      }
      body[field.name] = value;
    }
    save.mutate(body);
  }

  const savedAt = settings.data?.updated_at ?? null;

  return (
    <div className="ops-page">
      <div className="bar">
        <span className="eyebrow">Lifecycle</span>
        <span className="hint">{savedAt ? `saved ${savedAt}` : "environment defaults"}</span>
      </div>

      <form className="editorcard" onSubmit={handleSubmit} aria-label="Retention settings">
        {FIELDS.map((field) => (
          <div className="param sf-field" key={field.name}>
            <label htmlFor={`retention-${field.name}`}>{field.label}</label>
            <input
              id={`retention-${field.name}`}
              type="number"
              min={field.min}
              step={1}
              required
              value={draft[field.name]}
              onChange={(e) =>
                setDraft((d) => (d ? { ...d, [field.name]: e.target.value } : d))
              }
            />
          </div>
        ))}

        <div className="bar">
          <button className="primary" type="submit" disabled={save.isPending}>
            {save.isPending ? "Saving" : "Save"}
          </button>
        </div>

        {saveError && (
          <div className="banner err" role="alert">
            <div className="sub">{saveError}</div>
          </div>
        )}
      </form>
    </div>
  );
}
