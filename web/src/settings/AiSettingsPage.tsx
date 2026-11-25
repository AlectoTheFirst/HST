/**
 * Ask-AI agent configuration. Admin only.
 *
 * The provider list and each provider's credential fields come from
 * GET /api/settings/ai/providers.
 *
 * A blank credential field keeps the stored credential. A save or a test that
 * selects another endpoint or a weaker TLS check needs each stored credential
 * again. A stored credential that the auth mode of the typed credentials does
 * not use is sent as null.
 *
 * The prompt is assembled from fixed layers on the server. The form edits only
 * the site instructions and shows the fixed layers read-only. A prompt in
 * `replace` mode is sent in place of the fixed layers, and the form warns
 * while that mode is active.
 */

import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import type { AiEvents, AiProviders, AiSettings, AiTestResult } from "../api/types";

/** The options that select the host of the provider calls, as in `_endpoint`
 *  of app/routes/ai.py. */
const ENDPOINT_OPTIONS = ["base_url", "aws_region"];

/** The auth mode that uses each Bedrock credential, as in `bedrock_auth_mode`
 *  of app/agent/registry.py. */
const AUTH_MODE: Record<string, string> = {
  aws_bedrock_api_key: "api_key",
  aws_access_key_id: "keys",
  aws_secret_access_key: "keys",
  aws_session_token: "keys",
};

function isOn(value: string | undefined): boolean {
  return ["1", "true", "yes", "on"].includes((value ?? "").trim().toLowerCase());
}

/** Whether `options` select another endpoint or a weaker TLS check than
 *  `saved`. The server then refuses to keep a stored credential
 *  (`_require_own_credentials` of app/routes/ai.py). */
function needsOwnCredentials(
  options: Record<string, string>,
  saved: Record<string, string>,
): boolean {
  if (ENDPOINT_OPTIONS.some((name) => (options[name] ?? "") !== (saved[name] ?? ""))) return true;
  if (isOn(options.tls_skip_verify) && !isOn(saved.tls_skip_verify)) return true;
  const bundle = (options.tls_ca_bundle ?? "").trim();
  return bundle !== "" && bundle !== (saved.tls_ca_bundle ?? "").trim();
}

function fmtTokens(tokensIn: number | null, tokensOut: number | null): string {
  if (tokensIn === null && tokensOut === null) return "";
  return `${tokensIn ?? 0} in, ${tokensOut ?? 0} out`;
}

function fmtUser(username: string | null, userId: number | null): string {
  if (username) return username;
  return userId === null ? "none" : `user ${userId}`;
}

/** The AI audit trail: tokens per user per UTC day over the last 30 days, and
 *  the newest events. Events carry metadata only; the server sends no
 *  question, answer, argument or result text. */
function AiEventsPanel() {
  const events = useQuery({
    queryKey: ["ai-events"],
    queryFn: () => api<AiEvents>("/settings/ai/events"),
  });

  if (events.isLoading) return <div className="hint">Loading</div>;
  if (events.isError) {
    return (
      <div className="hint">
        {events.error instanceof ApiError ? events.error.message : "AI events not loaded"}
      </div>
    );
  }
  if (!events.data) return null;
  const { daily_tokens: daily, events: rows } = events.data;

  return (
    <>
      <div className="results">
        <div className="eyebrow">Tokens per day</div>
        {daily.length === 0 ? (
          <div className="tableempty">No token counts in the last 30 days</div>
        ) : (
          <table aria-label="Tokens per day">
            <thead>
              <tr>
                <th>Day</th>
                <th>User</th>
                <th>Tokens in</th>
                <th>Tokens out</th>
              </tr>
            </thead>
            <tbody>
              {daily.map((d) => (
                <tr key={`${d.day}-${d.user_id ?? "none"}`}>
                  <td>{d.day}</td>
                  <td>{fmtUser(d.username, d.user_id)}</td>
                  <td>{d.tokens_in}</td>
                  <td>{d.tokens_out}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="results">
        <div className="eyebrow">AI events</div>
        {rows.length === 0 ? (
          <div className="tableempty">No AI events</div>
        ) : (
          <table aria-label="AI events">
            <thead>
              <tr>
                <th>Time</th>
                <th>User</th>
                <th>Origin</th>
                <th>Event</th>
                <th>Tool</th>
                <th>Model</th>
                <th>Outcome</th>
                <th>Latency</th>
                <th>Tokens</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.id}>
                  <td>{new Date(e.at).toLocaleString()}</td>
                  <td>{fmtUser(e.username, e.user_id)}</td>
                  <td>{e.origin}</td>
                  <td>{e.event}</td>
                  <td>{e.tool ?? ""}</td>
                  <td>{e.model_served ?? e.model_requested ?? ""}</td>
                  <td>{e.error_class ? `${e.outcome} (${e.error_class})` : e.outcome}</td>
                  <td>{e.latency_ms === null ? "" : `${e.latency_ms} ms`}</td>
                  <td>{fmtTokens(e.tokens_in, e.tokens_out)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

export default function AiSettingsPage() {
  const queryClient = useQueryClient();

  const providers = useQuery({
    queryKey: ["ai-providers"],
    queryFn: () => api<AiProviders>("/settings/ai/providers"),
  });
  const settings = useQuery({
    queryKey: ["ai-settings"],
    queryFn: () => api<AiSettings>("/settings/ai"),
  });

  const [form, setForm] = useState<AiSettings | null>(null);
  const [credentials, setCredentials] = useState<Record<string, string>>({});

  function setOption(name: string, value: string) {
    test.reset();
    setForm((f) => (f ? { ...f, options: { ...(f.options ?? {}), [name]: value } } : f));
  }

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (settings.data && !form) setForm(settings.data);
  }, [settings.data, form]);

  const save = useMutation({
    mutationFn: (body: AiSettings & { credentials?: Record<string, string | null> }) =>
      api<AiSettings>("/settings/ai", { method: "PUT", body }),
    onSuccess: (saved) => {
      queryClient.setQueryData(["ai-settings"], saved);
      setForm(saved);
      setCredentials({});
      queryClient.invalidateQueries({ queryKey: ["health"] });
    },
  });

  // The probe body overrides the stored settings for this one request.
  const test = useMutation({
    mutationFn: (body: {
      provider: string;
      model: string;
      effort: string;
      options: Record<string, string>;
      secrets?: Record<string, string | null>;
    }) => api<AiTestResult>("/settings/ai/test", { method: "POST", body }),
  });

  if (settings.isLoading || providers.isLoading) {
    return <div className="ops-page"><span className="hint">Loading</span></div>;
  }
  const loadError = settings.error ?? providers.error;
  if (loadError) {
    return (
      <div className="ops-page">
        <div className="banner err">
          <div className="sub">
            {loadError instanceof ApiError ? loadError.message : "AI settings not loaded"}
          </div>
        </div>
      </div>
    );
  }
  if (!form) return null;

  const chosen = providers.data?.providers.find((p) => p.id === form.provider);
  const ownProvider = form.provider === settings.data?.provider;
  const onFile = settings.data?.stored_credentials ?? [];
  const ownCredentials =
    !ownProvider || needsOwnCredentials(form.options ?? {}, settings.data?.options ?? {});
  const isTyped = (name: string) => (credentials[name] ?? "").trim() !== "";
  const typedModes = new Set(
    (chosen?.credentials ?? []).filter((f) => isTyped(f.name)).map((f) => AUTH_MODE[f.name] ?? ""),
  );

  /** What a save does with the stored value of a blank credential field.
   *  "removed" sends null. "required" blocks the save. */
  function blankState(name: string): "none" | "stored" | "required" | "removed" {
    if (!onFile.includes(name)) return "none";
    if (!ownProvider) return "removed";
    if (typedModes.size > 0 && !typedModes.has(AUTH_MODE[name] ?? "")) return "removed";
    return ownCredentials ? "required" : "stored";
  }

  /** The `credentials` of a save and the `secrets` of a test. */
  function credentialValues(): Record<string, string | null> {
    const values: Record<string, string | null> = {};
    for (const field of chosen?.credentials ?? []) {
      if (isTyped(field.name)) values[field.name] = credentials[field.name];
      else if (blankState(field.name) === "removed") values[field.name] = null;
    }
    return values;
  }

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const values = credentialValues();
    save.mutate({
      ...form!,
      options: form!.options ?? {},
      ...(Object.keys(values).length ? { credentials: values } : {}),
    });
  }

  return (
    <div className="ops-page">
      <div className="bar">
        <span className="eyebrow">AI agent</span>
        <span className="hint">
          {form.enabled && form.configured ? "enabled" : "not configured"}
        </span>
      </div>

      <form className="editorcard" onSubmit={handleSubmit} aria-label="AI agent settings">
        <label className="sf-field">
          <label>
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
            />
            &nbsp;Enable the AI agent
          </label>
        </label>

        <div className="param">
          <label htmlFor="ai-provider">Provider</label>
          <select
            id="ai-provider"
            value={form.provider}
            onChange={(e) => {
              const next = providers.data?.providers.find((p) => p.id === e.target.value);
              if (!next) return;
              const saved = settings.data?.provider === next.id ? settings.data : undefined;
              setForm({
                ...form,
                provider: next.id,
                model: saved?.model ?? next.models[0] ?? "",
                options: saved?.options ?? {},
                effort: saved?.effort ?? "high",
                configured: saved?.configured ?? false,
                // api_key is shared by Anthropic and OpenRouter; a stored key
                // for one must not be advertised as a key for the other.
                stored_credentials: saved?.stored_credentials ?? [],
              });
              setCredentials({}); // credentials are per-provider; never carry them over
              test.reset();
              save.reset();
            }}
          >
            {providers.data?.providers.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
        </div>

        {/* A checkbox stores "true" or nothing. */}
        {chosen?.options?.map((field) =>
          field.kind === "checkbox" ? (
            <label className="sf-field" key={field.name}>
              <label>
                <input
                  id={`ai-opt-${field.name}`}
                  type="checkbox"
                  checked={form.options?.[field.name] === "true"}
                  onChange={(e) => setOption(field.name, e.target.checked ? "true" : "")}
                />
                &nbsp;{field.label}
              </label>
            </label>
          ) : field.kind === "textarea" ? (
            <div className="param" key={field.name}>
              <label htmlFor={`ai-opt-${field.name}`}>{field.label}</label>
              <textarea
                id={`ai-opt-${field.name}`}
                rows={6}
                spellCheck={false}
                placeholder={field.placeholder ?? ""}
                value={form.options?.[field.name] ?? ""}
                onChange={(e) => setOption(field.name, e.target.value)}
              />
            </div>
          ) : (
            <div className="param" key={field.name}>
              <label htmlFor={`ai-opt-${field.name}`}>
                {field.label}
              </label>
              <input
                id={`ai-opt-${field.name}`}
                spellCheck={false}
                required={field.required}
                pattern={field.required ? ".*\\S.*" : undefined}
                aria-describedby={field.help ? `ai-opt-${field.name}-help` : undefined}
                placeholder={field.placeholder ?? ""}
                value={form.options?.[field.name] ?? ""}
                onChange={(e) => setOption(field.name, e.target.value)}
                onBlur={(e) => {
                  if (field.required) setOption(field.name, e.target.value.trim());
                }}
              />
              {field.help && (
                <span className="hint" id={`ai-opt-${field.name}-help`}>{field.help}</span>
              )}
            </div>
          ),
        )}

        {chosen?.credentials.map((field) => {
          const state = !ownProvider
            ? "none"
            : isTyped(field.name) && onFile.includes(field.name)
              ? "stored"
              : blankState(field.name);
          return (
            <div className="param" key={field.name}>
              <label htmlFor={`ai-cred-${field.name}`}>
                {field.label}
                {state === "stored" && <span className="hint">&nbsp;stored</span>}
                {state === "required" && <span className="hint">&nbsp;re-entry required</span>}
                {state === "removed" && <span className="hint">&nbsp;removed on save</span>}
              </label>
              <input
                id={`ai-cred-${field.name}`}
                type={field.secret ? "password" : "text"}
                autoComplete="off"
                spellCheck={false}
                required={(!ownProvider && field.required) || state === "required"}
                placeholder={state === "stored" ? "stored value" : (field.placeholder ?? "")}
                value={credentials[field.name] ?? ""}
                onChange={(e) => {
                  test.reset();
                  setCredentials((c) => ({ ...c, [field.name]: e.target.value }));
                }}
              />
            </div>
          );
        })}

        <div className="param">
          <label htmlFor="ai-model">Model</label>
          <input
            id="ai-model"
            spellCheck={false}
            required
            list="ai-model-suggestions"
            value={form.model}
            onChange={(e) => {
              test.reset();
              setForm({ ...form, model: e.target.value });
            }}
          />
          <datalist id="ai-model-suggestions">
            {chosen?.models.map((m) => (
              <option key={m} value={m} />
            ))}
          </datalist>
        </div>

        {chosen?.supports_effort && (
          <div className="param">
            <label htmlFor="ai-effort">Effort</label>
            <select
              id="ai-effort"
              value={form.effort}
              onChange={(e) => {
                test.reset();
                setForm({ ...form, effort: e.target.value });
              }}
            >
              {["low", "medium", "high"].map((e) => (
                <option key={e} value={e}>
                  {e}
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="sf-field">
          <label htmlFor="ai-system">Site instructions</label>
          {form.prompt_mode === "replace" && (
            <div className="banner warn" role="alert">
              <div className="sub">
                Fixed prompt layers not sent in replace mode
              </div>
              <button
                type="button"
                className="linkish"
                onClick={() => setForm({ ...form, prompt_mode: "append" })}
              >
                Append to the fixed layers
              </button>
            </div>
          )}
          <textarea
            id="ai-system"
            className="ai-system"
            rows={6}
            spellCheck={false}
            value={form.system_prompt}
            onChange={(e) => setForm({ ...form, system_prompt: e.target.value })}
          />
        </div>

        <details className="sf-field">
          <summary>Fixed prompt layers</summary>
          {providers.data?.prompt_layers.map((layer) => (
            <div key={layer.id}>
              <span className="eyebrow">{layer.label}</span>
              <pre className="ai-layer">{layer.text}</pre>
            </div>
          ))}
        </details>

        <div className="source-actions">
          <button className="primary" type="submit" disabled={save.isPending}>
            {save.isPending ? "Saving" : "Save"}
          </button>
          <button
            type="button"
            className="linkish"
            disabled={test.isPending}
            onClick={(e) => {
              if (!e.currentTarget.form?.reportValidity()) return;
              const values = credentialValues();
              test.mutate({
                provider: form.provider,
                model: form.model,
                effort: form.effort,
                options: form.options ?? {},
                ...(Object.keys(values).length ? { secrets: values } : {}),
              });
            }}
          >
            {test.isPending ? "Testing" : "Test connection"}
          </button>
        </div>

        {save.isError && (
          <div className="banner err">
            <div className="sub">
              {save.error instanceof ApiError ? save.error.message : "Save failed"}
            </div>
          </div>
        )}
        {test.isError && (
          <div className="banner err">
            <div className="sub">
              {test.error instanceof ApiError ? test.error.message : "Connection test failed"}
            </div>
          </div>
        )}
        {test.data && (
          <div className={"banner " + (test.data.ok ? "ok" : "bad")}>
            <div className="sub">
              {test.data.ok
                ? `Reached ${test.data.provider}, ${test.data.model}`
                : (test.data.error ?? "Provider rejected the request")}
            </div>
          </div>
        )}
      </form>

      <AiEventsPanel />
    </div>
  );
}
