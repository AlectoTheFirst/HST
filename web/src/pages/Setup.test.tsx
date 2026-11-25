import { describe, it, expect, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "../App";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_ADMIN } from "../test/fixtures";

const GOOD = "a-long-enough-admin-pw";

function renderApp(entries: string[] = ["/"]) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={entries}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  document.body.innerHTML = "";
});

describe("first-run setup", () => {
  it("shows the setup form when the deployment has no accounts", async () => {
    mockApi({
      "GET /api/setup": () => ({ status: 200, body: { required: true, min_password_length: 12 } }),
      "GET /api/me": () => ({ status: 401, body: { error: "not authenticated" } }),
    });
    renderApp();

    expect(await screen.findByRole("button", { name: /create administrator/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^sign in$/i })).not.toBeInTheDocument();
  });

  it("shows the setup form on every route", async () => {
    mockApi({
      "GET /api/setup": () => ({ status: 200, body: { required: true, min_password_length: 12 } }),
      "GET /api/me": () => ({ status: 401, body: { error: "not authenticated" } }),
    });
    renderApp(["/settings/users"]);

    expect(await screen.findByRole("button", { name: /create administrator/i })).toBeInTheDocument();
  });

  it("never shows setup once the deployment has accounts", async () => {
    mockApi({
      "GET /api/setup": () => ({ status: 200, body: { required: false, min_password_length: 12 } }),
      "GET /api/me": () => ({ status: 401, body: { error: "not authenticated" } }),
    });
    renderApp();

    expect(await screen.findByRole("button", { name: /^sign in$/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /create administrator/i })).not.toBeInTheDocument();
  });

  it("submits the new administrator", async () => {
    const posted: unknown[] = [];
    let done = false;
    mockApi({
      "GET /api/setup": () => ({
        status: 200,
        body: { required: !done, min_password_length: 12 },
      }),
      "POST /api/setup": (req) => {
        posted.push(req.body);
        done = true;
        return { status: 201, body: ME_ADMIN };
      },
      "GET /api/me": () => ({ status: done ? 200 : 401, body: done ? ME_ADMIN : { error: "no" } }),
      "GET /api/health": () => ({ status: 200, body: { path: true, neo4j: true, postgres: true } }),
    });
    renderApp();

    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/^username$/i), "ada");
    await user.type(screen.getByLabelText(/^password$/i), GOOD);
    await user.type(screen.getByLabelText(/confirm password/i), GOOD);
    await user.click(screen.getByRole("button", { name: /create administrator/i }));

    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0]).toEqual({ username: "ada", password: GOOD });
  });

  it("refuses to submit when the two passwords differ", async () => {
    let posted = 0;
    mockApi({
      "GET /api/setup": () => ({ status: 200, body: { required: true, min_password_length: 12 } }),
      "POST /api/setup": () => {
        posted += 1;
        return { status: 201, body: ME_ADMIN };
      },
      "GET /api/me": () => ({ status: 401, body: { error: "no" } }),
    });
    renderApp();

    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/^username$/i), "ada");
    await user.type(screen.getByLabelText(/^password$/i), GOOD);
    await user.type(screen.getByLabelText(/confirm password/i), `${GOOD}-typo`);

    expect(await screen.findByRole("alert")).toHaveTextContent(/do not match/i);
    expect(screen.getByRole("button", { name: /create administrator/i })).toBeDisabled();
    expect(posted).toBe(0);
  });

  it("refuses a password shorter than the server's minimum", async () => {
    mockApi({
      "GET /api/setup": () => ({ status: 200, body: { required: true, min_password_length: 12 } }),
      "GET /api/me": () => ({ status: 401, body: { error: "no" } }),
    });
    renderApp();

    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/^password$/i), "short");

    expect(await screen.findByRole("alert")).toHaveTextContent(/shorter than 12 characters/i);
    expect(screen.getByRole("button", { name: /create administrator/i })).toBeDisabled();
  });

  it("shows the server's rejection", async () => {
    mockApi({
      "GET /api/setup": () => ({ status: 200, body: { required: true, min_password_length: 12 } }),
      "POST /api/setup": () => ({ status: 409, body: { error: "setup has already been completed" } }),
      "GET /api/me": () => ({ status: 401, body: { error: "no" } }),
    });
    renderApp();

    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/^username$/i), "ada");
    await user.type(screen.getByLabelText(/^password$/i), GOOD);
    await user.type(screen.getByLabelText(/confirm password/i), GOOD);
    await user.click(screen.getByRole("button", { name: /create administrator/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/already been completed/i);
  });
});
