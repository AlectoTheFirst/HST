/**
 * Access tokens: the personal access tokens of the MCP HTTP transport.
 *
 * Every user manages their own tokens (GET, POST /api/access-tokens and
 * DELETE /api/access-tokens/{id}). A token is created with a name, a scope
 * and an expiry. The scope defaults to read and cannot change after creation:
 * the list shows it and no control edits it.
 *
 * The token text arrives once, in the answer to the create request.
 *
 * A user who holds `settings.ai` also gets the switch that enables the
 * transport at /api/mcp (PUT /api/settings/mcp). Everyone else sees whether
 * it is enabled.
 */

import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import { useAuth } from "../auth";
import type {
  AccessToken,
  AccessTokenCreate,
  AccessTokenCreated,
  AccessTokenList,
  McpSettings,
  TokenScope,
} from "../api/types";

const SCOPES: readonly TokenScope[] = ["read", "read-write"];
const QUERY_KEY = ["access-tokens"];

function errorMessage(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.message : fallback;
}

/** An ISO instant from the server as "YYYY-MM-DD HH:MM UTC". */
function utc(iso: string): string {
  return `${iso.slice(0, 16).replace("T", " ")} UTC`;
}

function CreateTokenForm({
  onCreate,
  pending,
  error,
}: {
  onCreate: (body: AccessTokenCreate) => void;
  pending: boolean;
  error: string | null;
}) {
  const [name, setName] = useState("");
  const [scope, setScope] = useState<TokenScope>("read");
  const [days, setDays] = useState("90");

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    onCreate({ name, scope, expires_in_days: Number(days) });
  }

  return (
    <form className="editorcard" onSubmit={handleSubmit} aria-label="Create token">
      <div className="bar">
        <span className="eyebrow">New token</span>
      </div>
      <div className="param sf-field">
        <label htmlFor="new-token-name">Name</label>
        <input
          id="new-token-name"
          value={name}
          maxLength={100}
          required
          onChange={(e) => setName(e.target.value)}
        />
      </div>
      <div className="param sf-field">
        <label htmlFor="new-token-scope">Scope</label>
        <select
          id="new-token-scope"
          value={scope}
          onChange={(e) => setScope(e.target.value as TokenScope)}
        >
          {SCOPES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>
      <div className="param sf-field">
        <label htmlFor="new-token-days">Days until expiry</label>
        <input
          id="new-token-days"
          type="number"
          min={1}
          max={90}
          step={1}
          required
          value={days}
          onChange={(e) => setDays(e.target.value)}
        />
      </div>
      {error && (
        <div className="banner err" role="alert">
          <div className="sub">{error}</div>
        </div>
      )}
      <div className="bar">
        <button className="primary" type="submit" disabled={pending}>
          {pending ? "Creating" : "Create token"}
        </button>
      </div>
    </form>
  );
}

function TokenTable({
  tokens,
  onRevoke,
  revoking,
}: {
  tokens: AccessToken[];
  onRevoke: (token: AccessToken) => void;
  revoking: number | null;
}) {
  if (tokens.length === 0) return <div className="tableempty">No tokens</div>;
  return (
    <table aria-label="Access tokens">
      <thead>
        <tr>
          <th>Name</th>
          <th>Scope</th>
          <th>Created</th>
          <th>Expires</th>
          <th>Last used</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {tokens.map((token) => (
          <tr key={token.id}>
            <td>{token.name}</td>
            <td>{token.scope}</td>
            <td>{utc(token.created_at)}</td>
            <td>{token.expired ? `expired ${utc(token.expires_at)}` : utc(token.expires_at)}</td>
            <td>{token.last_used_at ? utc(token.last_used_at) : "never"}</td>
            <td>
              <button
                type="button"
                className="linkish"
                aria-label={`Revoke ${token.name}`}
                disabled={revoking === token.id}
                onClick={() => onRevoke(token)}
              >
                {revoking === token.id ? "Revoking" : "Revoke"}
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function AccessTokensPage() {
  const { user: me } = useAuth();
  const queryClient = useQueryClient();
  const [created, setCreated] = useState<AccessTokenCreated | null>(null);
  const [createError, setCreateError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const list = useQuery<AccessTokenList, ApiError>({
    queryKey: QUERY_KEY,
    queryFn: () => api<AccessTokenList>("/access-tokens"),
  });

  const create = useMutation<AccessTokenCreated, ApiError, AccessTokenCreate>({
    mutationFn: (body) => api<AccessTokenCreated>("/access-tokens", { method: "POST", body }),
    onSuccess: (token) => {
      setCreated(token);
      setCreateError(null);
      void queryClient.invalidateQueries({ queryKey: QUERY_KEY });
    },
    onError: (err) => setCreateError(errorMessage(err, "Token not created")),
  });

  const revoke = useMutation<void, ApiError, AccessToken>({
    mutationFn: (token) => api<void>(`/access-tokens/${token.id}`, { method: "DELETE" }),
    onSuccess: () => {
      setActionError(null);
      void queryClient.invalidateQueries({ queryKey: QUERY_KEY });
    },
    onError: (err) => setActionError(errorMessage(err, "Token not revoked")),
  });

  const toggle = useMutation<McpSettings, ApiError, boolean>({
    mutationFn: (enabled) =>
      api<McpSettings>("/settings/mcp", { method: "PUT", body: { mcp_http_enabled: enabled } }),
    onSuccess: () => {
      setActionError(null);
      void queryClient.invalidateQueries({ queryKey: QUERY_KEY });
    },
    onError: (err) => setActionError(errorMessage(err, "Setting not saved")),
  });

  if (!me) return null;
  const canSwitch = me.permissions.includes("settings.ai");

  return (
    <div className="ops-page">
      <div className="bar">
        <span className="eyebrow">Access tokens</span>
      </div>

      {list.isLoading && <span className="hint">Loading</span>}
      {list.isError && (
        <div className="banner err" role="alert">
          <div className="sub">{errorMessage(list.error, "Tokens not loaded")}</div>
        </div>
      )}

      {list.data &&
        (canSwitch ? (
          <label className="checkline">
            <input
              type="checkbox"
              checked={list.data.mcp_http_enabled}
              disabled={toggle.isPending}
              onChange={(e) => toggle.mutate(e.target.checked)}
            />
            &nbsp;Enable the MCP HTTP transport at /api/mcp
          </label>
        ) : (
          <p className="hint">
            {list.data.mcp_http_enabled
              ? "MCP HTTP transport enabled"
              : "MCP HTTP transport disabled"}
          </p>
        ))}

      {actionError && (
        <div className="banner err" role="alert">
          <div className="sub">{actionError}</div>
        </div>
      )}

      {created && (
        <div className="banner ok" role="status" aria-label="New token">
          <div className="sub">
            Token {created.name} ({created.scope}) created, text shown once
          </div>
          <code>{created.token}</code>
          <button type="button" className="linkish" onClick={() => setCreated(null)}>
            Done
          </button>
        </div>
      )}

      <CreateTokenForm
        onCreate={(body) => create.mutate(body)}
        pending={create.isPending}
        error={createError}
      />

      {list.data && (
        <TokenTable
          tokens={list.data.tokens}
          onRevoke={(token) => revoke.mutate(token)}
          revoking={revoke.isPending && revoke.variables ? revoke.variables.id : null}
        />
      )}
    </div>
  );
}
