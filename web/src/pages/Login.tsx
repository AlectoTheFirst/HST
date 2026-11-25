/**
 * Login: local username/password (POST /api/login) and the provider buttons
 * from GET /api/auth/providers, a public endpoint that needs no session.
 */

import { useState, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import { ThemeToggle } from "../shell/ThemeToggle";
import type { AuthProvidersResponse, LoginRequest, Me } from "../api/types";
import { claimUserStorage } from "../userStorage";

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchParams] = useSearchParams();
  const ssoFailed = searchParams.get("error") === "sso";

  const providersQuery = useQuery<AuthProvidersResponse, ApiError>({
    queryKey: ["auth-providers"],
    queryFn: () => api<AuthProvidersResponse>("/auth/providers"),
    retry: false,
  });
  const providers = providersQuery.data?.providers ?? [];
  const localLoginEnabled = providersQuery.data?.local_login_enabled ?? true;

  const mutation = useMutation<Me, ApiError, LoginRequest>({
    mutationFn: (body) =>
      // The login call opts out of the global 401 hook.
      api<Me>("/login", { method: "POST", body, skipUnauthorizedHook: true }),
    onSuccess: async (me) => {
      claimUserStorage(me.username);
      queryClient.setQueryData(["me"], me);
      await queryClient.invalidateQueries({ queryKey: ["me"] });
      navigate("/");
    },
  });

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    mutation.mutate({ username, password });
  }

  function handleProviderLogin(name: string) {
    // eslint-disable-next-line react-hooks/immutability
    window.location.href = `/api/auth/${encodeURIComponent(name)}/login`;
  }

  return (
    <div className="login-shell">
      <div className="login-card">
        <div className="login-brand">
          <b>HST</b>
          <span>Flow Desk</span>
        </div>

        {ssoFailed && (
          <p role="alert" className="login-error">
            Single sign-on failed
          </p>
        )}

        {providers.length > 0 && (
          <div className="login-providers">
            {providers.map((p) => (
              <button
                key={p.name}
                type="button"
                className="login-provider"
                onClick={() => handleProviderLogin(p.name)}
              >
                Continue with {p.label}
              </button>
            ))}
          </div>
        )}

        {localLoginEnabled && (
          <form className="login-local" onSubmit={handleSubmit}>
            <label className="login-field">
              <span>Username</span>
              <input
                name="username"
                autoComplete="username"
                // eslint-disable-next-line jsx-a11y/no-autofocus
                autoFocus
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </label>

            <label className="login-field">
              <span>Password</span>
              <input
                name="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </label>

            {mutation.isError && (
              <p role="alert" className="login-error">
                {mutation.error instanceof ApiError ? mutation.error.message : "Login failed"}
              </p>
            )}

            <button className="primary login-submit" type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Signing in" : "Sign in"}
            </button>
          </form>
        )}
      </div>

      <div className="login-theme">
        <ThemeToggle />
      </div>
    </div>
  );
}
