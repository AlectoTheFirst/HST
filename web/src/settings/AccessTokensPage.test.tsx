import { describe, it, expect } from "vitest";
import { render, screen, within, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import AccessTokensPage from "./AccessTokensPage";
import { AuthProvider } from "../auth";
import { mockApi, type MockHandler } from "../test/fetchMock";
import { ME_ADMIN, ME_VIEWER } from "../test/fixtures";
import type { AccessToken, AccessTokenCreate, Me } from "../api/types";

const LAPTOP: AccessToken = {
  id: 1,
  name: "laptop",
  scope: "read",
  created_at: "2026-09-01T08:00:00+00:00",
  expires_at: "2026-11-30T08:00:00+00:00",
  last_used_at: null,
  expired: false,
};

const CI: AccessToken = {
  id: 2,
  name: "ci",
  scope: "read-write",
  created_at: "2026-09-02T08:00:00+00:00",
  expires_at: "2026-12-01T08:00:00+00:00",
  last_used_at: "2026-09-03T10:30:00+00:00",
  expired: false,
};

function renderPage(
  me: Me,
  tokens: AccessToken[],
  extra: Record<string, MockHandler> = {},
  enabled = false,
) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: me }),
    "GET /api/access-tokens": () => ({ status: 200, body: { tokens, mcp_http_enabled: enabled } }),
    ...extra,
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AuthProvider>
          <AccessTokensPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function created(body: AccessTokenCreate, id = 3) {
  return {
    status: 201,
    body: {
      id,
      name: body.name,
      scope: body.scope ?? "read",
      created_at: "2026-09-28T12:00:00+00:00",
      expires_at: "2026-12-27T12:00:00+00:00",
      last_used_at: null,
      expired: false,
      token: "shown-once-text",
    },
  };
}

describe("AccessTokensPage: the scope", () => {
  it("defaults the scope to read and sends it with the new token", async () => {
    const user = userEvent.setup();
    let posted: AccessTokenCreate | null = null;
    renderPage(ME_VIEWER, [], {
      "POST /api/access-tokens": (req) => {
        posted = req.body as AccessTokenCreate;
        return created(posted);
      },
    });

    const scope = await screen.findByLabelText("Scope");
    expect(scope).toHaveValue("read");
    await user.type(screen.getByLabelText("Name"), "laptop");
    await user.click(screen.getByRole("button", { name: "Create token" }));

    await waitFor(() => expect(posted).toEqual({ name: "laptop", scope: "read", expires_in_days: 90 }));
    const shown = await screen.findByRole("status", { name: "New token" });
    expect(shown).toHaveTextContent("shown-once-text");
    expect(shown).toHaveTextContent("(read)");
  });

  it("sends the scope chosen at creation", async () => {
    const user = userEvent.setup();
    let posted: AccessTokenCreate | null = null;
    renderPage(ME_VIEWER, [], {
      "POST /api/access-tokens": (req) => {
        posted = req.body as AccessTokenCreate;
        return created(posted);
      },
    });

    await user.type(await screen.findByLabelText("Name"), "ci");
    await user.selectOptions(screen.getByLabelText("Scope"), "read-write");
    await user.click(screen.getByRole("button", { name: "Create token" }));

    await waitFor(() => expect(posted?.scope).toBe("read-write"));
  });

  it("shows the scope of each token in the list and offers no control to change it", async () => {
    renderPage(ME_VIEWER, [CI, LAPTOP]);

    const table = await screen.findByRole("table", { name: "Access tokens" });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows.map((row) => within(row).getAllByRole("cell")[1].textContent)).toEqual([
      "read-write",
      "read",
    ]);
    expect(within(table).queryByRole("combobox")).not.toBeInTheDocument();
    // the create form's select is the only scope control on the page
    expect(screen.getAllByRole("combobox")).toHaveLength(1);
  });
});

describe("AccessTokensPage: the list", () => {
  it("revokes a token by id", async () => {
    const user = userEvent.setup();
    const revoked: string[] = [];
    renderPage(ME_VIEWER, [LAPTOP], {
      "DELETE /api/access-tokens/1": (req) => {
        revoked.push(req.path);
        return { status: 204 };
      },
    });

    await user.click(await screen.findByRole("button", { name: "Revoke laptop" }));

    await waitFor(() => expect(revoked).toEqual(["/api/access-tokens/1"]));
  });

  it("states that a token was never used", async () => {
    renderPage(ME_VIEWER, [LAPTOP]);

    const table = await screen.findByRole("table", { name: "Access tokens" });
    expect(within(table).getByText("never")).toBeInTheDocument();
  });
});

describe("AccessTokensPage: the transport switch", () => {
  it("is offered to a user who holds settings.ai and saves the choice", async () => {
    const user = userEvent.setup();
    let saved: unknown = null;
    renderPage(ME_ADMIN, [], {
      "PUT /api/settings/mcp": (req) => {
        saved = req.body;
        return { status: 200, body: { mcp_http_enabled: true } };
      },
    });

    await user.click(await screen.findByRole("checkbox", { name: /Enable the MCP HTTP transport/ }));

    await waitFor(() => expect(saved).toEqual({ mcp_http_enabled: true }));
  });

  it("is not offered to a viewer, who sees the state only", async () => {
    renderPage(ME_VIEWER, [], {}, true);

    expect(await screen.findByText("MCP HTTP transport enabled")).toBeInTheDocument();
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  });
});
