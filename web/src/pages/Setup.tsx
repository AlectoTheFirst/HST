/**
 * First-run setup: the first screen of a deployment with no accounts, in the login shell's
 * markup and styles.
 */

import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import { ThemeToggle } from "../shell/ThemeToggle";
import type { Me, SetupRequest } from "../api/types";
import { claimUserStorage } from "../userStorage";

export default function Setup({ minPasswordLength }: { minPasswordLength: number }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // The password match is checked only here.
  const mismatch = confirm.length > 0 && password !== confirm;
  const tooShort = password.length > 0 && password.length < minPasswordLength;

  const mutation = useMutation<Me, ApiError, SetupRequest>({
    mutationFn: (body) =>
      // Opts out of the global 401 hook.
      api<Me>("/setup", { method: "POST", body, skipUnauthorizedHook: true }),
    onSuccess: async (me) => {
      claimUserStorage(me.username);
      queryClient.setQueryData(["me"], me);
      await queryClient.invalidateQueries({ queryKey: ["setup"] });
      await queryClient.invalidateQueries({ queryKey: ["me"] });
      navigate("/");
    },
  });

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (mismatch || tooShort) return;
    mutation.mutate({ username, password });
  }

  return (
    <div className="login-shell">
      <form className="login-card" onSubmit={handleSubmit}>
        <div className="login-brand">
          <b>HST</b>
          <span>Setup</span>
        </div>

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
            autoComplete="new-password"
            minLength={minPasswordLength}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            aria-describedby="setup-pw-hint"
          />
        </label>
        <p id="setup-pw-hint" className="login-hint">
          At least {minPasswordLength} characters
        </p>

        <label className="login-field">
          <span>Confirm password</span>
          <input
            name="confirm"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
          />
        </label>

        {(mismatch || tooShort || mutation.isError) && (
          <p role="alert" className="login-error">
            {mismatch
              ? "Passwords do not match"
              : tooShort
                ? `Password shorter than ${minPasswordLength} characters`
                : mutation.error instanceof ApiError
                  ? mutation.error.message
                  : "Setup failed"}
          </p>
        )}

        <button
          className="primary login-submit"
          type="submit"
          disabled={mutation.isPending || mismatch || tooShort}
        >
          {mutation.isPending ? "Creating" : "Create administrator"}
        </button>
      </form>

      <div className="login-theme">
        <ThemeToggle />
      </div>
    </div>
  );
}
