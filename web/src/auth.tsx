/** The session user and the route guard of the role-gated pages. */

import { createContext, useContext, useEffect, useMemo, type ReactNode } from "react";
import { Navigate, useNavigate } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, setOnUnauthorized } from "./api/client";
import type { Me, Role } from "./api/types";
import { Forbidden } from "./shell/Forbidden";
import { claimUserStorage, clearUserStorage } from "./userStorage";

const ROLE_ORDER: readonly Role[] = ["viewer", "operator", "admin"];

/** Whether `role` is at least `min` in the order viewer < operator < admin. */
export function atLeast(role: Role, min: Role): boolean {
  return ROLE_ORDER.indexOf(role) >= ROLE_ORDER.indexOf(min);
}

export interface AuthState {
  user: Me | null;
  loading: boolean;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

async function fetchMe(): Promise<Me | null> {
  try {
    const me = await api<Me>("/me");
    claimUserStorage(me.username);
    return me;
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) return null;
    throw err;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery<Me | null>({
    queryKey: ["me"],
    queryFn: fetchMe,
    retry: false,
  });

  // A 401 on any request drops the cached session and the stored data of the
  // user, and navigates to /login.
  useEffect(() => {
    setOnUnauthorized(() => {
      // The cache must keep the ["setup"] query.
      queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== "setup" });
      // A mutation holds its variables: a password, or a created token.
      queryClient.getMutationCache().clear();
      queryClient.setQueryData(["me"], null);
      clearUserStorage();
      navigate("/login");
    });
    return () => setOnUnauthorized(null);
  }, [navigate, queryClient]);

  const value = useMemo<AuthState>(
    () => ({ user: data ?? null, loading: isLoading }),
    [data, isLoading],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}

/** The signed-in user, or null outside an AuthProvider. For components that
 *  also render where no provider sits, such as the AI result cards. */
export function useCurrentUser(): Me | null {
  return useContext(AuthContext)?.user ?? null;
}

export function RequireRole({
  min,
  children,
}: {
  min: Role;
  children: ReactNode;
}) {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;
  if (!atLeast(user.role, min)) {
    return <Forbidden />;
  }
  return <>{children}</>;
}
