import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Routes, Route } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import Login from "./Login";
import { mockApi, type MockHandler } from "../test/fetchMock";
import { AUTH_PROVIDERS_PUBLIC } from "../test/fixtures";
import type { AuthProvidersResponse } from "../api/types";

const NO_PROVIDERS: AuthProvidersResponse = { providers: [], local_login_enabled: true };

function renderLogin(initialEntries: string[] = ["/login"]) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={initialEntries}>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<p>Flow Desk home</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function mockRoutes(extra: Record<string, MockHandler> = {}) {
  mockApi({
    "GET /api/auth/providers": () => ({ status: 200, body: NO_PROVIDERS }),
    ...extra,
  });
}

describe("Login page: local form", () => {
  it("renders, submits credentials, and navigates to / on success", async () => {
    let receivedBody: unknown;
    mockRoutes({
      "POST /api/login": (req) => {
        receivedBody = req.body;
        return { status: 200, body: { username: "viewer1", role: "viewer" } };
      },
    });
    const user = userEvent.setup();
    renderLogin();

    expect(await screen.findByRole("button", { name: /sign in/i })).toBeInTheDocument();

    await user.type(screen.getByLabelText(/username/i), "viewer1");
    await user.type(screen.getByLabelText(/password/i), "hunter2");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByText("Flow Desk home")).toBeInTheDocument();
    expect(receivedBody).toEqual({ username: "viewer1", password: "hunter2" });
  });

  it("shows the server's error message on a failed login", async () => {
    mockRoutes({
      "POST /api/login": () => ({ status: 401, body: { error: "invalid credentials" } }),
    });
    const user = userEvent.setup();
    renderLogin();

    await user.type(await screen.findByLabelText(/username/i), "nobody");
    await user.type(screen.getByLabelText(/password/i), "wrong");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("invalid credentials");
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });
});

describe("Login page: SSO providers", () => {
  it("renders a button per enabled provider, above the local form", async () => {
    mockRoutes({ "GET /api/auth/providers": () => ({ status: 200, body: AUTH_PROVIDERS_PUBLIC }) });
    renderLogin();

    expect(await screen.findByRole("button", { name: "Continue with Okta" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });

  it("navigates to the provider's login endpoint", async () => {
    mockRoutes({ "GET /api/auth/providers": () => ({ status: 200, body: AUTH_PROVIDERS_PUBLIC }) });
    const user = userEvent.setup();
    renderLogin();

    const original = window.location;
    // jsdom throws "Not implemented: navigation" on an assignment to the real object
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...original, href: original.href },
    });

    await user.click(await screen.findByRole("button", { name: "Continue with Okta" }));
    expect(window.location.href).toBe("/api/auth/okta/login");

    Object.defineProperty(window, "location", { configurable: true, value: original });
  });

  it("encodes the provider name in the path of the login endpoint", async () => {
    mockRoutes({
      "GET /api/auth/providers": () => ({
        status: 200,
        body: { providers: [{ name: "corp/sso?x", kind: "oidc", label: "Corp" }], local_login_enabled: true },
      }),
    });
    const user = userEvent.setup();
    renderLogin();

    const original = window.location;
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...original, href: original.href },
    });

    await user.click(await screen.findByRole("button", { name: "Continue with Corp" }));
    expect(window.location.href).toBe("/api/auth/corp%2Fsso%3Fx/login");

    Object.defineProperty(window, "location", { configurable: true, value: original });
  });

  it("hides the local form when local login is disabled", async () => {
    mockRoutes({
      "GET /api/auth/providers": () => ({
        status: 200,
        body: { ...AUTH_PROVIDERS_PUBLIC, local_login_enabled: false },
      }),
    });
    renderLogin();

    expect(await screen.findByRole("button", { name: "Continue with Okta" })).toBeInTheDocument();
    expect(screen.queryByLabelText(/username/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /sign in/i })).not.toBeInTheDocument();
  });

  it("shows the SSO failure banner when the URL carries ?error=sso", async () => {
    mockRoutes();
    renderLogin(["/login?error=sso"]);

    expect(await screen.findByRole("alert")).toHaveTextContent("Single sign-on failed");
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });
});
