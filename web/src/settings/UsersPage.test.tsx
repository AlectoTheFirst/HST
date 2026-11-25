import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import UsersPage from "./UsersPage";
import { AuthProvider } from "../auth";
import { mockApi, type MockHandler } from "../test/fetchMock";
import {
  ME_ADMIN,
  ME_OPERATOR,
  ME_VIEWER,
  USER_ADMIN_ROW,
  USER_MAPPED_ROW,
  USER_OVERRIDDEN_ROW,
  USER_VIEWER_ROW,
  USERS_RESPONSE,
} from "../test/fixtures";
import type { Me } from "../api/types";

function renderUsers(me: Me, extraRoutes: Record<string, MockHandler> = {}) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: me }),
    "GET /api/users": () => ({ status: 200, body: USERS_RESPONSE }),
    ...extraRoutes,
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AuthProvider>
          <UsersPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("UsersPage: hides itself below admin", () => {
  it("renders nothing for a viewer", async () => {
    renderUsers(ME_VIEWER);
    await waitFor(() => expect(screen.queryByText(/loading/i)).not.toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /add user/i })).not.toBeInTheDocument();
    expect(screen.queryByText(USER_ADMIN_ROW.username)).not.toBeInTheDocument();
  });

  it("renders nothing for an operator", async () => {
    renderUsers(ME_OPERATOR);
    await waitFor(() => expect(screen.queryByText(/loading/i)).not.toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /add user/i })).not.toBeInTheDocument();
  });

  it("renders the user list for an admin", async () => {
    renderUsers(ME_ADMIN);
    expect(await screen.findByRole("button", { name: /add user/i })).toBeInTheDocument();
    expect(screen.getByText(USER_ADMIN_ROW.username, { exact: false })).toBeInTheDocument();
  });
});

describe("UsersPage: self-lockout surfaced verbatim", () => {
  it("shows the server's exact 400 message when an admin demotes themselves", async () => {
    const user = userEvent.setup();
    renderUsers(ME_ADMIN, {
      "PATCH /api/users/1": () => ({
        status: 400,
        body: { error: "you cannot disable or demote yourself" },
      }),
    });

    const roleSelect = await screen.findByLabelText(`Role for ${USER_ADMIN_ROW.username}`);
    await user.selectOptions(roleSelect, "viewer");

    expect(await screen.findByRole("alert")).toHaveTextContent("you cannot disable or demote yourself");
  });
});

describe("UsersPage: create user", () => {
  it("posts the create body and refreshes the list on success", async () => {
    const user = userEvent.setup();
    let posted: unknown = null;
    renderUsers(ME_ADMIN, {
      "POST /api/users": (req) => {
        posted = req.body;
        return {
          status: 201,
          body: { id: 3, username: "newop", role: "operator", disabled: false, created_at: "2026-07-23T00:00:00+00:00" },
        };
      },
    });

    await user.click(await screen.findByRole("button", { name: /add user/i }));
    await user.type(screen.getByLabelText("Username"), "newop");
    await user.type(screen.getByLabelText("Password"), "hunter2hunter2");
    await user.selectOptions(screen.getByLabelText("Role"), "operator");
    await user.click(screen.getByRole("button", { name: "Create" }));

    expect(posted).toEqual({ username: "newop", password: "hunter2hunter2", role: "operator" });
  });

  it("surfaces a 409 for a duplicate username", async () => {
    const user = userEvent.setup();
    renderUsers(ME_ADMIN, {
      "POST /api/users": () => ({ status: 409, body: { error: "username already exists" } }),
    });

    await user.click(await screen.findByRole("button", { name: /add user/i }));
    await user.type(screen.getByLabelText("Username"), "admin1");
    await user.type(screen.getByLabelText("Password"), "hunter2hunter2");
    await user.click(screen.getByRole("button", { name: "Create" }));

    expect(await screen.findByText("username already exists")).toBeInTheDocument();
  });
});

describe("UsersPage: password reset", () => {
  it("closes the form and clears it on success", async () => {
    const user = userEvent.setup();
    renderUsers(ME_ADMIN, {
      [`PATCH /api/users/${USER_VIEWER_ROW.id}`]: () => ({ status: 200, body: USER_VIEWER_ROW }),
    });

    await user.click(await screen.findByRole("button", { name: `Reset password ${USER_VIEWER_ROW.username}` }));
    const input = await screen.findByLabelText("New password");
    await user.type(input, "brandnewpass");
    await user.click(screen.getByRole("button", { name: "Set password" }));

    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Set password" })).not.toBeInTheDocument(),
    );
  });

  it("keeps the form open with the server's error and the typed password on a 400", async () => {
    const user = userEvent.setup();
    renderUsers(ME_ADMIN, {
      [`PATCH /api/users/${USER_VIEWER_ROW.id}`]: () => ({
        status: 400,
        body: { error: "password must be at least 8 characters" },
      }),
    });

    await user.click(await screen.findByRole("button", { name: `Reset password ${USER_VIEWER_ROW.username}` }));
    const input = (await screen.findByLabelText("New password")) as HTMLInputElement;
    await user.type(input, "shortish");
    await user.click(screen.getByRole("button", { name: "Set password" }));

    expect(await screen.findByText("password must be at least 8 characters")).toBeInTheDocument();
    expect(screen.getByLabelText("New password")).toHaveValue("shortish");
  });
});

describe("UsersPage: password reset hidden without a local password", () => {
  it("does not offer password reset for an SSO-provisioned account", async () => {
    renderUsers(ME_ADMIN, {
      "GET /api/users": () => ({ status: 200, body: { users: [USER_MAPPED_ROW] } }),
    });

    await screen.findByText(USER_MAPPED_ROW.username, { exact: false });
    expect(
      screen.queryByRole("button", { name: `Reset password ${USER_MAPPED_ROW.username}` }),
    ).not.toBeInTheDocument();
  });
});

describe("UsersPage: identity column and role origin", () => {
  it("shows 'local' for a local account and the provider name for an SSO one", async () => {
    renderUsers(ME_ADMIN, {
      "GET /api/users": () => ({ status: 200, body: { users: [USER_ADMIN_ROW, USER_MAPPED_ROW] } }),
    });

    await screen.findByText(USER_ADMIN_ROW.username, { exact: false });
    expect(screen.getByText("local")).toBeInTheDocument();
    expect(screen.getByText("okta")).toBeInTheDocument();
  });

  it("shows 'mapped: <role>' with an override control for a mapped row", async () => {
    renderUsers(ME_ADMIN, {
      "GET /api/users": () => ({ status: 200, body: { users: [USER_MAPPED_ROW] } }),
    });

    expect(await screen.findByText(`mapped: ${USER_MAPPED_ROW.role}`)).toBeInTheDocument();
    expect(
      screen.getByLabelText(`Override role for ${USER_MAPPED_ROW.username}`),
    ).toBeInTheDocument();
    // no plain role select for a mapped row
    expect(screen.queryByLabelText(`Role for ${USER_MAPPED_ROW.username}`)).not.toBeInTheDocument();
  });

  it("overriding a mapped role sends the same role PATCH a local row uses", async () => {
    const user = userEvent.setup();
    let patched: unknown = null;
    renderUsers(ME_ADMIN, {
      "GET /api/users": () => ({ status: 200, body: { users: [USER_MAPPED_ROW] } }),
      [`PATCH /api/users/${USER_MAPPED_ROW.id}`]: (req) => {
        patched = req.body;
        return { status: 200, body: { ...USER_MAPPED_ROW, role: "admin", role_source: "local" } };
      },
    });

    const select = await screen.findByLabelText(`Override role for ${USER_MAPPED_ROW.username}`);
    await user.selectOptions(select, "admin");

    expect(patched).toEqual({ role: "admin" });
  });

  it("clearing an override sends {role_source: 'mapped'}", async () => {
    const user = userEvent.setup();
    let patched: unknown = null;
    renderUsers(ME_ADMIN, {
      "GET /api/users": () => ({ status: 200, body: { users: [USER_OVERRIDDEN_ROW] } }),
      [`PATCH /api/users/${USER_OVERRIDDEN_ROW.id}`]: (req) => {
        patched = req.body;
        return { status: 200, body: { ...USER_OVERRIDDEN_ROW, role_source: "mapped" } };
      },
    });

    await user.click(
      await screen.findByRole("button", { name: `Clear role override for ${USER_OVERRIDDEN_ROW.username}` }),
    );

    expect(patched).toEqual({ role_source: "mapped" });
  });

  it("a local account has neither a mapped label nor a clear-override control", async () => {
    renderUsers(ME_ADMIN, {
      "GET /api/users": () => ({ status: 200, body: { users: [USER_ADMIN_ROW] } }),
    });

    await screen.findByLabelText(`Role for ${USER_ADMIN_ROW.username}`);
    expect(screen.queryByText(/^mapped:/)).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: `Clear role override for ${USER_ADMIN_ROW.username}` }),
    ).not.toBeInTheDocument();
  });
});

describe("UsersPage: sign out everywhere", () => {
  it("does nothing when the confirm is declined", async () => {
    const user = userEvent.setup();
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    let called = false;
    renderUsers(ME_ADMIN, {
      [`DELETE /api/users/${USER_VIEWER_ROW.id}/sessions`]: () => {
        called = true;
        return { status: 200, body: { revoked: 2 } };
      },
    });

    await user.click(
      await screen.findByRole("button", { name: `Sign out all sessions for ${USER_VIEWER_ROW.username}` }),
    );

    expect(confirmSpy).toHaveBeenCalled();
    expect(called).toBe(false);
    confirmSpy.mockRestore();
  });

  it("reports how many sessions the server ended", async () => {
    const user = userEvent.setup();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderUsers(ME_ADMIN, {
      [`DELETE /api/users/${USER_VIEWER_ROW.id}/sessions`]: () => ({
        status: 200,
        body: { revoked: 3 },
      }),
    });

    await user.click(
      await screen.findByRole("button", { name: `Sign out all sessions for ${USER_VIEWER_ROW.username}` }),
    );

    expect(await screen.findByRole("status")).toHaveTextContent("3 sessions signed out");
    vi.restoreAllMocks();
  });

  it("reports 0 sessions when the account had none", async () => {
    const user = userEvent.setup();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderUsers(ME_ADMIN, {
      [`DELETE /api/users/${USER_VIEWER_ROW.id}/sessions`]: () => ({
        status: 200,
        body: { revoked: 0 },
      }),
    });

    await user.click(
      await screen.findByRole("button", { name: `Sign out all sessions for ${USER_VIEWER_ROW.username}` }),
    );

    expect(await screen.findByRole("status")).toHaveTextContent("0 sessions signed out");
    vi.restoreAllMocks();
  });

  it("surfaces a 404 for an account deleted since the list loaded", async () => {
    const user = userEvent.setup();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderUsers(ME_ADMIN, {
      [`DELETE /api/users/${USER_VIEWER_ROW.id}/sessions`]: () => ({
        status: 404,
        body: { error: `no user ${USER_VIEWER_ROW.id}` },
      }),
    });

    await user.click(
      await screen.findByRole("button", { name: `Sign out all sessions for ${USER_VIEWER_ROW.username}` }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(`no user ${USER_VIEWER_ROW.id}`);
    vi.restoreAllMocks();
  });
});
