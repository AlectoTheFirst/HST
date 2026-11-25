/**
 * Settings, Authentication (permission `settings.auth`): the local-login
 * toggle, identity-provider CRUD and per-provider group-to-role mappings.
 */

import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import { atLeast, useAuth } from "../auth";
import type {
  AuthProvider,
  AuthProviderCreateRequest,
  AuthProviderPatchRequest,
  AuthProviderTestResult,
  AuthSettings,
  DefaultRole,
  GroupMapping,
  GroupMappingRequest,
  ProviderKind,
  Role,
} from "../api/types";

const ROLES: Role[] = ["viewer", "operator", "admin"];
const DEFAULT_ROLES: DefaultRole[] = ["viewer", "operator", "admin", "none"];

function errorMessage(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.message : fallback;
}

function asString(config: Record<string, unknown> | undefined, key: string, fallback = ""): string {
  const v = config?.[key];
  return typeof v === "string" ? v : fallback;
}

function asBool(config: Record<string, unknown> | undefined, key: string): boolean {
  return config?.[key] === true;
}

function providerPath(name: string): string {
  return `/settings/auth/providers/${encodeURIComponent(name)}`;
}

// --- TLS trust, shared by both provider kinds ----------------------------------

interface TlsValues {
  tls_skip_verify: boolean;
  tls_ca_bundle: string;
}

function tlsInitial(config: Record<string, unknown> | undefined): TlsValues {
  return {
    tls_skip_verify: asBool(config, "tls_skip_verify"),
    tls_ca_bundle: asString(config, "tls_ca_bundle"),
  };
}

// The server verifies with the server-wide CA bundle when both keys are absent.
function tlsConfig(values: TlsValues): Record<string, unknown> {
  return {
    ...(values.tls_skip_verify ? { tls_skip_verify: true } : {}),
    ...(values.tls_ca_bundle.trim() ? { tls_ca_bundle: values.tls_ca_bundle.trim() } : {}),
  };
}

/** A TLS-intercepting proxy's CA, or a verification skip, for this provider's
 *  outbound calls only. Overrides the server-wide TLS_VERIFY / TLS_CA_BUNDLE. */
function TlsFields<T extends TlsValues>({
  idPrefix,
  values,
  setValues,
}: {
  idPrefix: string;
  values: T;
  setValues: (update: (v: T) => T) => void;
}) {
  return (
    <>
      <label className="sf-field">
        <label>
          <input
            id={`${idPrefix}-tls-skip-verify`}
            type="checkbox"
            checked={values.tls_skip_verify}
            onChange={(e) => setValues((v) => ({ ...v, tls_skip_verify: e.target.checked }))}
          />
          &nbsp;Skip TLS certificate verification
        </label>
      </label>
      <div className="param sf-field">
        <label htmlFor={`${idPrefix}-tls-ca-bundle`}>CA certificate</label>
        <textarea
          id={`${idPrefix}-tls-ca-bundle`}
          rows={6}
          spellCheck={false}
          placeholder="-----BEGIN CERTIFICATE-----"
          value={values.tls_ca_bundle}
          onChange={(e) => setValues((v) => ({ ...v, tls_ca_bundle: e.target.value }))}
        />
      </div>
    </>
  );
}

// --- OIDC form ---------------------------------------------------------------

interface OidcValues extends TlsValues {
  issuer: string;
  client_id: string;
  groups_claim: string;
  default_role: DefaultRole;
  label: string;
  secret: string;
}

function oidcInitial(config: Record<string, unknown> | undefined): OidcValues {
  return {
    issuer: asString(config, "issuer"),
    client_id: asString(config, "client_id"),
    groups_claim: asString(config, "groups_claim", "groups"),
    default_role: (asString(config, "default_role", "viewer") as DefaultRole) || "viewer",
    label: asString(config, "label"),
    secret: "",
    ...tlsInitial(config),
  };
}

function OidcForm({
  idPrefix,
  initial,
  hasSecret,
  mode,
  redirectUri,
  pending,
  error,
  onSubmit,
  onCancel,
}: {
  idPrefix: string;
  initial: Record<string, unknown> | undefined;
  hasSecret: boolean;
  mode: "create" | "edit";
  /** `redirect_uri` of the provider, in edit mode. */
  redirectUri?: string | null;
  pending: boolean;
  error: string | null;
  onSubmit: (body: { config: Record<string, unknown>; secret?: string }) => void;
  onCancel?: () => void;
}) {
  const [values, setValues] = useState<OidcValues>(() => oidcInitial(initial));

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const config: Record<string, unknown> = {
      issuer: values.issuer,
      client_id: values.client_id,
      groups_claim: values.groups_claim || "groups",
      default_role: values.default_role,
      ...(values.label.trim() ? { label: values.label.trim() } : {}),
      ...tlsConfig(values),
    };
    onSubmit({ config, ...(values.secret.trim() ? { secret: values.secret } : {}) });
  }

  return (
    <form
      className="editorcard"
      onSubmit={handleSubmit}
      aria-label={mode === "create" ? "Add OIDC provider" : "Edit OIDC provider"}
    >
      <div className="param sf-field">
        <label htmlFor={`${idPrefix}-issuer`}>Issuer</label>
        <input
          id={`${idPrefix}-issuer`}
          type="url"
          required
          value={values.issuer}
          onChange={(e) => setValues((v) => ({ ...v, issuer: e.target.value }))}
        />
      </div>
      <div className="param sf-field">
        <label htmlFor={`${idPrefix}-client-id`}>Client ID</label>
        <input
          id={`${idPrefix}-client-id`}
          required
          value={values.client_id}
          onChange={(e) => setValues((v) => ({ ...v, client_id: e.target.value }))}
        />
      </div>
      <div className="param sf-field">
        <label htmlFor={`${idPrefix}-secret`}>
          Client secret
          {hasSecret && <span className="hint">&nbsp;stored</span>}
        </label>
        <input
          id={`${idPrefix}-secret`}
          type="password"
          autoComplete="off"
          spellCheck={false}
          value={values.secret}
          onChange={(e) => setValues((v) => ({ ...v, secret: e.target.value }))}
        />
      </div>
      <div className="param sf-field">
        <label htmlFor={`${idPrefix}-groups-claim`}>Groups claim</label>
        <input
          id={`${idPrefix}-groups-claim`}
          value={values.groups_claim}
          onChange={(e) => setValues((v) => ({ ...v, groups_claim: e.target.value }))}
        />
      </div>
      <div className="param sf-field">
        <label htmlFor={`${idPrefix}-default-role`}>Default role</label>
        <select
          id={`${idPrefix}-default-role`}
          value={values.default_role}
          onChange={(e) => setValues((v) => ({ ...v, default_role: e.target.value as DefaultRole }))}
        >
          {DEFAULT_ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
      </div>
      <div className="param sf-field">
        <label htmlFor={`${idPrefix}-label`}>Label</label>
        <input
          id={`${idPrefix}-label`}
          value={values.label}
          onChange={(e) => setValues((v) => ({ ...v, label: e.target.value }))}
        />
      </div>
      <TlsFields idPrefix={idPrefix} values={values} setValues={setValues} />
      {mode === "edit" && (
        <div className="auth-saml-endpoints">
          <div className="param">
            <span className="param-label">Redirect URI</span>
            {redirectUri ? <code>{redirectUri}</code> : <span className="hint">HST_PUBLIC_URL not set</span>}
          </div>
        </div>
      )}
      {error && (
        <div className="banner err" role="alert">
          <div className="sub">{error}</div>
        </div>
      )}
      <div className="bar">
        <button className="primary" type="submit" disabled={pending}>
          {pending ? "Saving" : mode === "create" ? "Create" : "Save"}
        </button>
        {onCancel && (
          <button type="button" className="linkish" onClick={onCancel}>
            Cancel
          </button>
        )}
      </div>
    </form>
  );
}

// --- SAML form -----------------------------------------------------------------

interface SamlValues extends TlsValues {
  idp_metadata_url: string;
  idp_metadata_xml: string;
  username_attr: string;
  groups_attr: string;
  default_role: DefaultRole;
  label: string;
}

function samlInitial(config: Record<string, unknown> | undefined): SamlValues {
  return {
    idp_metadata_url: asString(config, "idp_metadata_url"),
    idp_metadata_xml: asString(config, "idp_metadata_xml"),
    username_attr: asString(config, "username_attr"),
    groups_attr: asString(config, "groups_attr"),
    default_role: (asString(config, "default_role", "viewer") as DefaultRole) || "viewer",
    label: asString(config, "label"),
    ...tlsInitial(config),
  };
}

function SamlForm({
  idPrefix,
  initial,
  mode,
  spEntityId,
  spAcsUrl,
  pending,
  error,
  onSubmit,
  onCancel,
}: {
  idPrefix: string;
  initial: Record<string, unknown> | undefined;
  mode: "create" | "edit";
  /** `sp_entity_id` of the provider, in edit mode. */
  spEntityId?: string | null;
  /** `sp_acs_url` of the provider, in edit mode. */
  spAcsUrl?: string | null;
  pending: boolean;
  error: string | null;
  onSubmit: (body: { config: Record<string, unknown> }) => void;
  onCancel?: () => void;
}) {
  const [values, setValues] = useState<SamlValues>(() => samlInitial(initial));
  const [validationError, setValidationError] = useState<string | null>(null);

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!values.idp_metadata_url.trim() && !values.idp_metadata_xml.trim()) {
      setValidationError("No IdP metadata URL or XML");
      return;
    }
    setValidationError(null);
    const config: Record<string, unknown> = {
      ...(values.idp_metadata_url.trim() ? { idp_metadata_url: values.idp_metadata_url.trim() } : {}),
      ...(values.idp_metadata_xml.trim() ? { idp_metadata_xml: values.idp_metadata_xml.trim() } : {}),
      username_attr: values.username_attr,
      groups_attr: values.groups_attr,
      default_role: values.default_role,
      ...(values.label.trim() ? { label: values.label.trim() } : {}),
      ...tlsConfig(values),
    };
    onSubmit({ config });
  }

  return (
    <form
      className="editorcard"
      onSubmit={handleSubmit}
      aria-label={mode === "create" ? "Add SAML provider" : "Edit SAML provider"}
    >
      <div className="param sf-field">
        <label htmlFor={`${idPrefix}-metadata-url`}>IdP metadata URL</label>
        <input
          id={`${idPrefix}-metadata-url`}
          type="url"
          value={values.idp_metadata_url}
          onChange={(e) => setValues((v) => ({ ...v, idp_metadata_url: e.target.value }))}
        />
      </div>
      <div className="param sf-field">
        <label htmlFor={`${idPrefix}-metadata-xml`}>IdP metadata XML</label>
        <textarea
          id={`${idPrefix}-metadata-xml`}
          rows={6}
          spellCheck={false}
          value={values.idp_metadata_xml}
          onChange={(e) => setValues((v) => ({ ...v, idp_metadata_xml: e.target.value }))}
        />
      </div>
      <div className="param sf-field">
        <label htmlFor={`${idPrefix}-username-attr`}>Username attribute</label>
        <input
          id={`${idPrefix}-username-attr`}
          value={values.username_attr}
          onChange={(e) => setValues((v) => ({ ...v, username_attr: e.target.value }))}
        />
      </div>
      <div className="param sf-field">
        <label htmlFor={`${idPrefix}-groups-attr`}>Groups attribute</label>
        <input
          id={`${idPrefix}-groups-attr`}
          value={values.groups_attr}
          onChange={(e) => setValues((v) => ({ ...v, groups_attr: e.target.value }))}
        />
      </div>
      <div className="param sf-field">
        <label htmlFor={`${idPrefix}-default-role`}>Default role</label>
        <select
          id={`${idPrefix}-default-role`}
          value={values.default_role}
          onChange={(e) => setValues((v) => ({ ...v, default_role: e.target.value as DefaultRole }))}
        >
          {DEFAULT_ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
      </div>
      <div className="param sf-field">
        <label htmlFor={`${idPrefix}-label`}>Label</label>
        <input
          id={`${idPrefix}-label`}
          value={values.label}
          onChange={(e) => setValues((v) => ({ ...v, label: e.target.value }))}
        />
      </div>
      <TlsFields idPrefix={idPrefix} values={values} setValues={setValues} />
      {mode === "edit" && (
        <div className="auth-saml-endpoints">
          <div className="eyebrow">SP endpoints</div>
          {spEntityId && spAcsUrl ? (
            <>
              <div className="param">
                <span className="param-label">Entity ID and metadata URL</span>
                <code>{spEntityId}</code>
              </div>
              <div className="param">
                <span className="param-label">ACS URL</span>
                <code>{spAcsUrl}</code>
              </div>
            </>
          ) : (
            <span className="hint">HST_PUBLIC_URL not set</span>
          )}
        </div>
      )}
      {(validationError || error) && (
        <div className="banner err" role="alert">
          <div className="sub">{validationError || error}</div>
        </div>
      )}
      <div className="bar">
        <button className="primary" type="submit" disabled={pending}>
          {pending ? "Saving" : mode === "create" ? "Create" : "Save"}
        </button>
        {onCancel && (
          <button type="button" className="linkish" onClick={onCancel}>
            Cancel
          </button>
        )}
      </div>
    </form>
  );
}

// --- Add provider --------------------------------------------------------------

function AddProviderForm({
  onCreate,
  onCancel,
  pending,
  error,
}: {
  onCreate: (body: AuthProviderCreateRequest) => void;
  onCancel: () => void;
  pending: boolean;
  error: string | null;
}) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<ProviderKind>("oidc");

  return (
    <div className="editorcard">
      <div className="bar">
        <span className="eyebrow">Add provider</span>
        <button type="button" className="linkish" onClick={onCancel}>
          Cancel
        </button>
      </div>
      <div className="param sf-field">
        <label htmlFor="new-provider-name">Name</label>
        <input id="new-provider-name" value={name} onChange={(e) => setName(e.target.value)} required />
      </div>
      <div className="param sf-field">
        <label htmlFor="new-provider-kind">Kind</label>
        <select id="new-provider-kind" value={kind} onChange={(e) => setKind(e.target.value as ProviderKind)}>
          <option value="oidc">OIDC</option>
          <option value="saml">SAML</option>
        </select>
      </div>
      {kind === "oidc" ? (
        <OidcForm
          idPrefix="new-provider"
          initial={undefined}
          hasSecret={false}
          mode="create"
          pending={pending}
          error={error}
          onSubmit={(body) => onCreate({ name, kind, ...body })}
        />
      ) : (
        <SamlForm
          idPrefix="new-provider"
          initial={undefined}
          mode="create"
          pending={pending}
          error={error}
          onSubmit={(body) => onCreate({ name, kind, ...body })}
        />
      )}
    </div>
  );
}

// --- Group mappings --------------------------------------------------------------

function GroupMappingsPanel({ providerName }: { providerName: string }) {
  const queryClient = useQueryClient();
  const [groupName, setGroupName] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [error, setError] = useState<string | null>(null);

  const mappingsQuery = useQuery<GroupMapping[], ApiError>({
    queryKey: ["auth-provider-mappings", providerName],
    queryFn: () => api<GroupMapping[]>(`${providerPath(providerName)}/mappings`),
  });

  const upsertMutation = useMutation<GroupMapping, ApiError, GroupMappingRequest>({
    mutationFn: (body) =>
      api<GroupMapping>(`${providerPath(providerName)}/mappings`, { method: "POST", body }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["auth-provider-mappings", providerName] });
      setGroupName("");
      setError(null);
    },
    onError: (err) => setError(errorMessage(err, "Mapping not added")),
  });

  const deleteMutation = useMutation<void, ApiError, string>({
    mutationFn: (group) =>
      api<void>(`${providerPath(providerName)}/mappings/${encodeURIComponent(group)}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["auth-provider-mappings", providerName] });
      setError(null);
    },
    onError: (err) => setError(errorMessage(err, "Mapping not removed")),
  });

  function handleAdd(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!groupName.trim()) return;
    upsertMutation.mutate({ group_name: groupName.trim(), role });
  }

  const mappings = mappingsQuery.data ?? [];

  return (
    <div className="auth-mappings">
      <div className="eyebrow">Group mappings</div>
      {mappingsQuery.isLoading && <div className="hint">Loading</div>}
      {mappingsQuery.isSuccess && mappings.length === 0 && (
        <div className="tableempty">No group mappings</div>
      )}
      {mappings.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Group</th>
              <th>Role</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {mappings.map((m) => (
              <tr key={m.group_name}>
                <td>{m.group_name}</td>
                <td>{m.role}</td>
                <td>
                  <button
                    type="button"
                    className="linkish sf-danger"
                    aria-label={`Remove mapping ${m.group_name}`}
                    onClick={() => deleteMutation.mutate(m.group_name)}
                    disabled={deleteMutation.isPending && deleteMutation.variables === m.group_name}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <form className="auth-mapping-add" onSubmit={handleAdd} aria-label={`Add mapping for ${providerName}`}>
        <input
          aria-label="Group name"
          placeholder="Group name"
          value={groupName}
          onChange={(e) => setGroupName(e.target.value)}
        />
        <select aria-label="Mapped role" value={role} onChange={(e) => setRole(e.target.value as Role)}>
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <button type="submit" className="linkish" disabled={upsertMutation.isPending}>
          {upsertMutation.isPending ? "Adding" : "Add"}
        </button>
      </form>
      {error && (
        <div className="banner err" role="alert">
          <div className="sub">{error}</div>
        </div>
      )}
    </div>
  );
}

// --- Provider row --------------------------------------------------------------

function ProviderRow({
  provider,
  editing,
  onToggleEdit,
  onSaveConfig,
  savePending,
  saveError,
  onToggleEnabled,
  togglePending,
  onDelete,
  deletePending,
  onTest,
  testPending,
  testResult,
  rowError,
}: {
  provider: AuthProvider;
  editing: boolean;
  onToggleEdit: () => void;
  onSaveConfig: (body: { config: Record<string, unknown>; secret?: string }) => void;
  savePending: boolean;
  saveError: string | null;
  onToggleEnabled: () => void;
  togglePending: boolean;
  onDelete: () => void;
  deletePending: boolean;
  onTest: () => void;
  testPending: boolean;
  testResult: AuthProviderTestResult | undefined;
  rowError: string | null;
}) {
  return (
    <div className="source-row">
      <div className="source-row-head">
        <span className="source-name">{provider.name}</span>
        <span className="source-type">{provider.kind}</span>
        <span className={"badge " + (provider.enabled ? "ok" : "warn")}>
          {provider.enabled ? "enabled" : "disabled"}
        </span>
        {provider.kind === "oidc" && (
          <span className={"badge " + (provider.has_secret ? "ok" : "warn")}>
            {provider.has_secret ? "client secret set" : "no client secret"}
          </span>
        )}
        <div className="source-actions">
          <button type="button" className="linkish" aria-label={`Edit ${provider.name}`} onClick={onToggleEdit}>
            {editing ? "Close" : "Edit"}
          </button>
          <button
            type="button"
            className="linkish"
            aria-label={`${provider.enabled ? "Disable" : "Enable"} ${provider.name}`}
            onClick={onToggleEnabled}
            disabled={togglePending}
          >
            {togglePending ? "Working" : provider.enabled ? "Disable" : "Enable"}
          </button>
          <button
            type="button"
            className="linkish"
            aria-label={`Test ${provider.name}`}
            onClick={onTest}
            disabled={testPending}
          >
            {testPending ? "Testing" : "Test"}
          </button>
          <button
            type="button"
            className="linkish sf-danger"
            aria-label={`Delete ${provider.name}`}
            onClick={onDelete}
            disabled={deletePending}
          >
            {deletePending ? "Deleting" : "Delete"}
          </button>
        </div>
      </div>
      {rowError && (
        <div className="banner err" role="alert">
          <div className="sub">{rowError}</div>
        </div>
      )}
      {testResult && (
        <div className={"banner " + (testResult.ok ? "ok" : "bad")}>
          <div className="sub">{testResult.detail || (testResult.ok ? "ok" : "failed")}</div>
        </div>
      )}
      {editing &&
        (provider.kind === "oidc" ? (
          <OidcForm
            idPrefix={`provider-${provider.name}`}
            initial={provider.config}
            hasSecret={provider.has_secret}
            redirectUri={provider.redirect_uri}
            mode="edit"
            pending={savePending}
            error={saveError}
            onSubmit={onSaveConfig}
          />
        ) : (
          <SamlForm
            idPrefix={`provider-${provider.name}`}
            initial={provider.config}
            spEntityId={provider.sp_entity_id}
            spAcsUrl={provider.sp_acs_url}
            mode="edit"
            pending={savePending}
            error={saveError}
            onSubmit={onSaveConfig}
          />
        ))}
      <GroupMappingsPanel providerName={provider.name} />
    </div>
  );
}

// --- Page ------------------------------------------------------------------

export default function AuthSettingsPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [editingName, setEditingName] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [rowError, setRowError] = useState<{ name: string; message: string } | null>(null);
  const [testResults, setTestResults] = useState<Record<string, AuthProviderTestResult>>({});
  const [testing, setTesting] = useState<ReadonlySet<string>>(() => new Set());
  const [localLoginError, setLocalLoginError] = useState<string | null>(null);

  const settingsQuery = useQuery<AuthSettings, ApiError>({
    queryKey: ["auth-settings"],
    queryFn: () => api<AuthSettings>("/settings/auth"),
  });
  const providersQuery = useQuery<AuthProvider[], ApiError>({
    queryKey: ["auth-providers-admin"],
    queryFn: () => api<AuthProvider[]>("/settings/auth/providers"),
  });

  const toggleLocalLoginMutation = useMutation<AuthSettings, ApiError, boolean>({
    mutationFn: (local_login_enabled) =>
      api<AuthSettings>("/settings/auth", { method: "PUT", body: { local_login_enabled } }),
    onSuccess: (data) => {
      queryClient.setQueryData(["auth-settings"], data);
      setLocalLoginError(null);
    },
  });

  const createMutation = useMutation<AuthProvider, ApiError, AuthProviderCreateRequest>({
    mutationFn: (body) => api<AuthProvider>("/settings/auth/providers", { method: "POST", body }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["auth-providers-admin"] });
      setAdding(false);
      setCreateError(null);
    },
    onError: (err) => setCreateError(err.message),
  });

  const saveConfigMutation = useMutation<
    AuthProvider,
    ApiError,
    { name: string; body: { config: Record<string, unknown>; secret?: string } }
  >({
    mutationFn: ({ name, body }) =>
      api<AuthProvider>(providerPath(name), { method: "PATCH", body }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["auth-providers-admin"] });
      setEditingName(null);
      setSaveError(null);
    },
    onError: (err) => setSaveError(err.message),
  });

  const toggleMutation = useMutation<AuthProvider, ApiError, { name: string; enabled: boolean }>({
    mutationFn: ({ name, enabled }): Promise<AuthProvider> =>
      api<AuthProvider>(providerPath(name), {
        method: "PATCH",
        body: { enabled } satisfies AuthProviderPatchRequest,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["auth-providers-admin"] });
      setRowError(null);
    },
  });

  const deleteMutation = useMutation<void, ApiError, string>({
    mutationFn: (name) => api<void>(providerPath(name), { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["auth-providers-admin"] });
      setRowError(null);
    },
  });

  const testMutation = useMutation<AuthProviderTestResult, ApiError, string>({
    mutationFn: (name) => api<AuthProviderTestResult>(`${providerPath(name)}/test`, { method: "POST" }),
  });

  if (!user || !atLeast(user.role, "admin")) return null;

  async function handleToggleLocalLogin(enabled: boolean) {
    try {
      await toggleLocalLoginMutation.mutateAsync(enabled);
    } catch (err) {
      setLocalLoginError(errorMessage(err, "Update failed"));
    }
  }

  async function handleDelete(name: string) {
    if (!window.confirm(`Delete provider ${name}`)) return;
    try {
      await deleteMutation.mutateAsync(name);
    } catch (err) {
      setRowError({ name, message: errorMessage(err, "Delete failed") });
    }
  }

  async function handleToggleEnabled(name: string, enabled: boolean) {
    try {
      await toggleMutation.mutateAsync({ name, enabled });
    } catch (err) {
      setRowError({ name, message: errorMessage(err, "Update failed") });
    }
  }

  async function handleTest(name: string) {
    setTesting((prev) => new Set(prev).add(name));
    try {
      const result = await testMutation.mutateAsync(name);
      setTestResults((r) => ({ ...r, [name]: result }));
    } catch (err) {
      setTestResults((r) => ({ ...r, [name]: { ok: false, detail: errorMessage(err, "Test failed") } }));
    } finally {
      setTesting((prev) => {
        const next = new Set(prev);
        next.delete(name);
        return next;
      });
    }
  }

  function handleToggleEdit(name: string) {
    setSaveError(null);
    setEditingName((current) => (current === name ? null : name));
  }

  const providers = providersQuery.data ?? [];
  const localLoginEnabled = settingsQuery.data?.local_login_enabled ?? true;

  return (
    <div className="ops-page">
      <div className="editorcard">
        <div className="bar">
          <span className="eyebrow">Local login</span>
        </div>
        <label className="sf-field">
          <label>
            <input
              type="checkbox"
              checked={localLoginEnabled}
              disabled={toggleLocalLoginMutation.isPending || settingsQuery.isLoading}
              onChange={(e) => handleToggleLocalLogin(e.target.checked)}
            />
            &nbsp;Allow signing in with a local username and password
          </label>
        </label>
        {localLoginError && (
          <div className="banner err" role="alert">
            <div className="sub">{localLoginError}</div>
          </div>
        )}
      </div>

      <div className="bar">
        <span className="eyebrow">Identity providers</span>
        {!adding && (
          <button type="button" className="primary" onClick={() => setAdding(true)}>
            Add provider
          </button>
        )}
      </div>

      {providersQuery.isLoading && <div className="hint">Loading</div>}
      {providersQuery.isError && <div className="hint">{providersQuery.error.message}</div>}
      {providersQuery.isSuccess && providers.length === 0 && !adding && (
        <div className="tableempty">No identity providers</div>
      )}

      {adding && (
        <AddProviderForm
          pending={createMutation.isPending}
          error={createError}
          onCancel={() => {
            setAdding(false);
            setCreateError(null);
          }}
          onCreate={(body) => createMutation.mutate(body)}
        />
      )}

      <div className="source-list">
        {providers.map((p) => (
          <ProviderRow
            key={p.name}
            provider={p}
            editing={editingName === p.name}
            onToggleEdit={() => handleToggleEdit(p.name)}
            onSaveConfig={(body) => saveConfigMutation.mutate({ name: p.name, body })}
            savePending={saveConfigMutation.isPending && saveConfigMutation.variables?.name === p.name}
            saveError={editingName === p.name ? saveError : null}
            onToggleEnabled={() => handleToggleEnabled(p.name, !p.enabled)}
            togglePending={toggleMutation.isPending && toggleMutation.variables?.name === p.name}
            onDelete={() => handleDelete(p.name)}
            deletePending={deleteMutation.isPending && deleteMutation.variables === p.name}
            onTest={() => handleTest(p.name)}
            testPending={testing.has(p.name)}
            testResult={testResults[p.name]}
            rowError={rowError?.name === p.name ? rowError.message : null}
          />
        ))}
      </div>
    </div>
  );
}
