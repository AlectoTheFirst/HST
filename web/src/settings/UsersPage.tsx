/**
 * The Users page manages the accounts through /api/users (users.py).
 */

import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import { atLeast, useAuth } from "../auth";
import type {
  RevokedSessions,
  Role,
  User,
  UserCreateRequest,
  UserPatchRequest,
  UsersResponse,
} from "../api/types";

const ROLES: Role[] = ["viewer", "operator", "admin"];

function errorMessage(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.message : fallback;
}

function CreateUserForm({
  onCreate,
  pending,
  error,
}: {
  onCreate: (body: UserCreateRequest) => void;
  pending: boolean;
  error: string | null;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("viewer");

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    onCreate({ username, password, role });
  }

  return (
    <form className="editorcard" onSubmit={handleSubmit} aria-label="Create user">
      <div className="bar">
        <span className="eyebrow">Add user</span>
      </div>
      <div className="param sf-field">
        <label htmlFor="new-user-username">Username</label>
        <input
          id="new-user-username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />
      </div>
      <div className="param sf-field">
        <label htmlFor="new-user-password">Password</label>
        <input
          id="new-user-password"
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          minLength={12}
          required
        />
      </div>
      <div className="param sf-field">
        <label htmlFor="new-user-role">Role</label>
        <select id="new-user-role" value={role} onChange={(e) => setRole(e.target.value as Role)}>
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
      </div>
      {error && (
        <div className="banner err">
          <div className="sub">{error}</div>
        </div>
      )}
      <div className="bar">
        <button className="primary" type="submit" disabled={pending}>
          {pending ? "Creating" : "Create"}
        </button>
      </div>
    </form>
  );
}

function ResetPasswordForm({
  user,
  onSubmit,
  pending,
  error,
}: {
  user: User;
  onSubmit: (password: string) => void;
  pending: boolean;
  error: string | null;
}) {
  const [newPassword, setNewPassword] = useState("");

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    onSubmit(newPassword);
  }

  return (
    <form className="editorcard" onSubmit={handleSubmit} aria-label={`Reset password for ${user.username}`}>
      <div className="param sf-field">
        <label htmlFor={`reset-${user.id}`}>New password</label>
        <input
          id={`reset-${user.id}`}
          type="password"
          autoComplete="new-password"
          minLength={12}
          required
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
        />
      </div>
      {error && (
        <div className="banner err" role="alert">
          <div className="sub">{error}</div>
        </div>
      )}
      <div className="bar">
        <button className="primary" type="submit" disabled={pending}>
          {pending ? "Saving" : "Set password"}
        </button>
      </div>
    </form>
  );
}

function UserRow({
  user,
  self,
  onRoleChange,
  onClearOverride,
  onToggleDisabled,
  togglePending,
  resetting,
  onToggleReset,
  onResetPassword,
  resetPending,
  resetError,
  rowError,
  onRevokeSessions,
  revokePending,
  rowNote,
}: {
  user: User;
  self: boolean;
  onRoleChange: (role: Role) => void;
  onClearOverride: () => void;
  onToggleDisabled: () => void;
  togglePending: boolean;
  resetting: boolean;
  onToggleReset: () => void;
  onResetPassword: (password: string) => void;
  resetPending: boolean;
  resetError: string | null;
  rowError: string | null;
  onRevokeSessions: () => void;
  revokePending: boolean;
  rowNote: string | null;
}) {
  const identityLabel = user.identities.length > 0 ? user.identities.join(", ") : "local";
  const mapped = user.identities.length > 0 && user.role_source === "mapped";
  const overridden = user.identities.length > 0 && user.role_source === "local";

  return (
    <div className="source-row">
      <div className="source-row-head">
        <span className="source-name">
          {user.username}
          {self && " (you)"}
        </span>
        <span className="source-type">{identityLabel}</span>
        {mapped ? (
          <>
            <span className="hint">mapped: {user.role}</span>
            <select
              aria-label={`Override role for ${user.username}`}
              value=""
              disabled={togglePending}
              onChange={(e) => {
                if (e.target.value) onRoleChange(e.target.value as Role);
              }}
            >
              <option value="">Override</option>
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </>
        ) : (
          <select
            aria-label={`Role for ${user.username}`}
            value={user.role}
            disabled={togglePending}
            onChange={(e) => onRoleChange(e.target.value as Role)}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        )}
        {overridden && (
          <button
            type="button"
            className="linkish"
            aria-label={`Clear role override for ${user.username}`}
            onClick={onClearOverride}
            disabled={togglePending}
          >
            Clear override
          </button>
        )}
        <span className={"badge " + (user.disabled ? "warn" : "ok")}>
          {user.disabled ? "disabled" : "enabled"}
        </span>
        <div className="source-actions">
          <button
            type="button"
            className="linkish"
            aria-label={`${user.disabled ? "Enable" : "Disable"} ${user.username}`}
            onClick={onToggleDisabled}
            disabled={togglePending}
          >
            {togglePending ? "Working" : user.disabled ? "Enable" : "Disable"}
          </button>
          {user.has_password && (
            <button
              type="button"
              className="linkish"
              aria-label={`Reset password ${user.username}`}
              onClick={onToggleReset}
            >
              {resetting ? "Close" : "Reset password"}
            </button>
          )}
          <button
            type="button"
            className="linkish"
            aria-label={`Sign out all sessions for ${user.username}`}
            onClick={onRevokeSessions}
            disabled={revokePending}
          >
            {revokePending ? "Signing out" : "Sign out everywhere"}
          </button>
        </div>
      </div>
      {rowError && (
        <div className="banner err" role="alert">
          <div className="sub">{rowError}</div>
        </div>
      )}
      {rowNote && (
        <div className="banner ok" role="status">
          <div className="sub">{rowNote}</div>
        </div>
      )}
      {resetting && user.has_password && (
        <ResetPasswordForm user={user} onSubmit={onResetPassword} pending={resetPending} error={resetError} />
      )}
    </div>
  );
}

export default function UsersPage() {
  const { user: me } = useAuth();
  const queryClient = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [rowError, setRowError] = useState<{ id: number; message: string } | null>(null);
  const [resettingId, setResettingId] = useState<number | null>(null);
  const [resetError, setResetError] = useState<string | null>(null);
  const [rowNote, setRowNote] = useState<{ id: number; message: string } | null>(null);

  const usersQuery = useQuery<UsersResponse, ApiError>({
    queryKey: ["users"],
    queryFn: () => api<UsersResponse>("/users"),
  });

  const createMutation = useMutation<User, ApiError, UserCreateRequest>({
    mutationFn: (body) => api<User>("/users", { method: "POST", body }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
      setAdding(false);
      setCreateError(null);
    },
    onError: (err) => setCreateError(err.message),
  });

  const toggleMutation = useMutation<User, ApiError, { id: number; body: UserPatchRequest }>({
    mutationFn: ({ id, body }) => api<User>(`/users/${id}`, { method: "PATCH", body }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
      setRowError(null);
    },
  });

  const resetMutation = useMutation<User, ApiError, { id: number; password: string }>({
    mutationFn: ({ id, password }) => api<User>(`/users/${id}`, { method: "PATCH", body: { password } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
      setResettingId(null);
      setResetError(null);
    },
    onError: (err) => setResetError(err.message),
  });

  const revokeMutation = useMutation<RevokedSessions, ApiError, number>({
    mutationFn: (id) => api<RevokedSessions>(`/users/${id}/sessions`, { method: "DELETE" }),
  });

  if (!me || !atLeast(me.role, "admin")) return null;

  async function handleToggle(id: number, body: UserPatchRequest) {
    try {
      await toggleMutation.mutateAsync({ id, body });
    } catch (err) {
      setRowError({ id, message: errorMessage(err, "Update failed") });
    }
  }

  async function handleRevokeSessions(user: User) {
    if (
      !window.confirm(
        `Sign out every session and revoke every access token of ${user.username}`,
      )
    )
      return;
    setRowError(null);
    setRowNote(null);
    try {
      const { revoked, revoked_tokens: tokens = 0 } =
        await revokeMutation.mutateAsync(user.id);
      const sessions =
        revoked === 1 ? "1 session signed out" : `${revoked} sessions signed out`;
      const revokedTokens =
        tokens === 1 ? "1 access token revoked" : `${tokens} access tokens revoked`;
      setRowNote({
        id: user.id,
        message: tokens === 0 ? sessions : `${sessions}, ${revokedTokens}`,
      });
    } catch (err) {
      setRowError({ id: user.id, message: errorMessage(err, "Sign-out failed") });
    }
  }

  function handleToggleReset(id: number) {
    setResetError(null);
    setResettingId((current) => (current === id ? null : id));
  }

  const users = usersQuery.data?.users ?? [];

  return (
    <div className="ops-page">
      <div className="bar">
        <span className="eyebrow">Users</span>
        {!adding && (
          <button type="button" className="primary" onClick={() => setAdding(true)}>
            Add user
          </button>
        )}
      </div>

      {usersQuery.isLoading && <div className="hint">Loading</div>}
      {usersQuery.isError && <div className="hint">{usersQuery.error.message}</div>}

      {adding && (
        <CreateUserForm
          pending={createMutation.isPending}
          error={createError}
          onCreate={(body) => createMutation.mutate(body)}
        />
      )}

      <div className="source-list">
        {users.map((u) => (
          <UserRow
            key={u.id}
            user={u}
            self={me.username === u.username}
            togglePending={toggleMutation.isPending && toggleMutation.variables?.id === u.id}
            rowError={rowError?.id === u.id ? rowError.message : null}
            onRoleChange={(role) => handleToggle(u.id, { role })}
            onClearOverride={() => handleToggle(u.id, { role_source: "mapped" })}
            onToggleDisabled={() => handleToggle(u.id, { disabled: !u.disabled })}
            resetting={resettingId === u.id}
            onToggleReset={() => handleToggleReset(u.id)}
            onResetPassword={(password) => resetMutation.mutate({ id: u.id, password })}
            resetPending={resetMutation.isPending && resetMutation.variables?.id === u.id}
            resetError={resettingId === u.id ? resetError : null}
            onRevokeSessions={() => handleRevokeSessions(u)}
            revokePending={revokeMutation.isPending && revokeMutation.variables === u.id}
            rowNote={rowNote?.id === u.id ? rowNote.message : null}
          />
        ))}
      </div>
    </div>
  );
}
