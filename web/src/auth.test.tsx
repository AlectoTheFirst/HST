import { afterEach, describe, it, expect } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { atLeast, AuthProvider } from "./auth";
import { api, ApiError } from "./api/client";
import { THEME_KEY } from "./shell/theme";
import { mockApi } from "./test/fetchMock";
import { ME_VIEWER } from "./test/fixtures";
import { USER_KEYS } from "./userStorage";
import type { Role } from "./api/types";

describe("atLeast: viewer < operator < admin", () => {
  const cases: [Role, Role, boolean][] = [
    ["viewer", "viewer", true],
    ["viewer", "operator", false],
    ["viewer", "admin", false],
    ["operator", "viewer", true],
    ["operator", "operator", true],
    ["operator", "admin", false],
    ["admin", "viewer", true],
    ["admin", "operator", true],
    ["admin", "admin", true],
  ];

  it.each(cases)("atLeast(%s, %s) === %s", (role, min, expected) => {
    expect(atLeast(role, min)).toBe(expected);
  });
});

/** A signed-in session whose next request answers 401. */
async function renderExpiringSession(): Promise<QueryClient> {
  // /me answers once for the initial load, then 401 like an expired session
  let meCalls = 0;
  mockApi({
    "GET /api/me": () => {
      meCalls += 1;
      return meCalls === 1 ? { status: 200, body: ME_VIEWER } : { status: 401 };
    },
    "GET /api/queries": () => ({ status: 401 }),
  });

  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <AuthProvider>
          <Routes>
            <Route path="/" element={<div>workspace</div>} />
            <Route path="/login" element={<div>login page</div>} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await waitFor(() => expect(queryClient.getQueryData(["me"])).toEqual(ME_VIEWER));
  return queryClient;
}

describe("AuthProvider session expiry", () => {
  afterEach(() => {
    window.sessionStorage.clear();
  });

  it("clears the query cache on a 401 as logout does", async () => {
    const queryClient = await renderExpiringSession();

    // account-scoped data cached during the session must not survive expiry
    queryClient.setQueryData(["queries"], { queries: [{ id: 1 }] });

    // any request coming back 401 stands in for the session expiring
    await expect(api("/queries")).rejects.toBeInstanceOf(ApiError);

    expect(queryClient.getQueryData(["queries"])).toBeUndefined();
    await waitFor(() => expect(queryClient.getQueryData(["me"])).toBeNull());
    expect(await screen.findByText("login page")).toBeInTheDocument();
  });

  it("drops the mutations and their variables on a 401", async () => {
    const queryClient = await renderExpiringSession();
    const mutation = queryClient
      .getMutationCache()
      .build(queryClient, { mutationFn: async (variables: { password: string }) => variables.password.length });
    await mutation.execute({ password: "correct horse battery" });
    expect(queryClient.getMutationCache().getAll()).toHaveLength(1);

    await expect(api("/queries")).rejects.toBeInstanceOf(ApiError);

    expect(queryClient.getMutationCache().getAll()).toEqual([]);
  });

  it("removes the stored data of the user on a 401 and keeps a display preference", async () => {
    await renderExpiringSession();
    const userKeys = [...USER_KEYS, `hst.inventory.draft:${ME_VIEWER.username}:site:create`];
    const storages = [window.localStorage, window.sessionStorage];
    for (const storage of storages) {
      for (const key of userKeys) storage.setItem(key, "1");
    }
    window.localStorage.setItem(THEME_KEY, "dark");

    await expect(api("/queries")).rejects.toBeInstanceOf(ApiError);

    for (const storage of storages) {
      expect(userKeys.filter((key) => storage.getItem(key) !== null)).toEqual([]);
    }
    expect(window.localStorage.getItem(THEME_KEY)).toBe("dark");
    expect(await screen.findByText("login page")).toBeInTheDocument();
  });
});
