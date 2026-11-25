import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import AuthSettingsPage from "./AuthSettingsPage";
import { AuthProvider } from "../auth";
import { mockApi, type MockHandler } from "../test/fetchMock";
import {
  AUTH_PROVIDER_OIDC,
  AUTH_PROVIDER_SAML,
  AUTH_PROVIDERS_ADMIN,
  AUTH_SETTINGS,
  GROUP_MAPPINGS_OKTA,
  ME_ADMIN,
  ME_OPERATOR,
} from "../test/fixtures";
import type { AuthProvider as AuthProviderRow, Me } from "../api/types";

function renderPage(me: Me = ME_ADMIN, extraRoutes: Record<string, MockHandler> = {}) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: me }),
    "GET /api/settings/auth": () => ({ status: 200, body: AUTH_SETTINGS }),
    "GET /api/settings/auth/providers": () => ({ status: 200, body: AUTH_PROVIDERS_ADMIN }),
    "GET /api/settings/auth/providers/okta/mappings": () => ({ status: 200, body: GROUP_MAPPINGS_OKTA }),
    "GET /api/settings/auth/providers/adfs/mappings": () => ({ status: 200, body: [] }),
    ...extraRoutes,
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AuthProvider>
          <AuthSettingsPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("AuthSettingsPage: hides itself below admin", () => {
  it("renders nothing for an operator", async () => {
    renderPage(ME_OPERATOR);
    await waitFor(() => expect(screen.queryByText(/loading/i)).not.toBeInTheDocument());
    expect(screen.queryByText("Identity providers")).not.toBeInTheDocument();
  });
});

describe("AuthSettingsPage: provider list", () => {
  it("lists providers with kind and enabled state", async () => {
    renderPage();

    expect(await screen.findByText(AUTH_PROVIDER_OIDC.name)).toBeInTheDocument();
    expect(screen.getByText("oidc")).toBeInTheDocument();
    expect(screen.getByText(AUTH_PROVIDER_SAML.name)).toBeInTheDocument();
    expect(screen.getByText("saml")).toBeInTheDocument();
    expect(screen.getByText("enabled")).toBeInTheDocument();
    expect(screen.getByText("disabled")).toBeInTheDocument();
  });
});

describe("AuthSettingsPage: URLs of HST for the identity provider", () => {
  async function openEdit(provider: AuthProviderRow) {
    const user = userEvent.setup();
    renderPage(ME_ADMIN, {
      "GET /api/settings/auth/providers": () => ({ status: 200, body: [provider] }),
    });
    await user.click(await screen.findByRole("button", { name: `Edit ${provider.name}` }));
  }

  it("shows the 2 SP URLs of a SAML provider", async () => {
    await openEdit(AUTH_PROVIDER_SAML);

    expect(screen.getByText("Entity ID and metadata URL").nextElementSibling?.textContent).toBe(
      AUTH_PROVIDER_SAML.sp_entity_id,
    );
    expect(screen.getByText("ACS URL").nextElementSibling?.textContent).toBe(AUTH_PROVIDER_SAML.sp_acs_url);
    expect(screen.queryByText("Metadata URL")).not.toBeInTheDocument();
    expect(screen.queryByText("Redirect URI")).not.toBeInTheDocument();
    expect(screen.queryByText("HST_PUBLIC_URL not set")).not.toBeInTheDocument();
  });

  it("shows the state label when the SP URLs are null", async () => {
    await openEdit({ ...AUTH_PROVIDER_SAML, sp_entity_id: null, sp_acs_url: null });

    expect(screen.getByText("HST_PUBLIC_URL not set")).toBeInTheDocument();
    expect(screen.queryByText("Entity ID and metadata URL")).not.toBeInTheDocument();
    expect(screen.queryByText("ACS URL")).not.toBeInTheDocument();
  });

  it("shows the redirect URI of an OIDC provider", async () => {
    await openEdit(AUTH_PROVIDER_OIDC);

    expect(screen.getByText("Redirect URI").nextElementSibling?.textContent).toBe(AUTH_PROVIDER_OIDC.redirect_uri);
    expect(screen.queryByText("HST_PUBLIC_URL not set")).not.toBeInTheDocument();
  });

  it("shows the state label when the redirect URI is null", async () => {
    await openEdit({ ...AUTH_PROVIDER_OIDC, redirect_uri: null });

    expect(screen.getByText("Redirect URI").nextElementSibling?.textContent).toBe("HST_PUBLIC_URL not set");
  });
});

describe("AuthSettingsPage: create provider", () => {
  it("posts the OIDC create body, including the secret", async () => {
    const user = userEvent.setup();
    let posted: unknown = null;
    renderPage(ME_ADMIN, {
      "POST /api/settings/auth/providers": (req) => {
        posted = req.body;
        return { status: 201, body: { ...AUTH_PROVIDER_OIDC, name: "new-okta" } };
      },
    });

    await user.click(await screen.findByRole("button", { name: "Add provider" }));
    await user.type(screen.getByLabelText("Name"), "new-okta");
    // kind defaults to oidc
    await user.type(screen.getByLabelText("Issuer"), "https://new.okta.com");
    await user.type(screen.getByLabelText("Client ID"), "client-abc");
    await user.type(screen.getByLabelText("Client secret"), "s3cr3t");
    await user.click(screen.getByRole("button", { name: "Create" }));

    expect(posted).toEqual({
      name: "new-okta",
      kind: "oidc",
      config: {
        issuer: "https://new.okta.com",
        client_id: "client-abc",
        groups_claim: "groups",
        default_role: "viewer",
      },
      secret: "s3cr3t",
    });
  });
});

describe("AuthSettingsPage: secret stays write-only", () => {
  it("omits the secret key from the PATCH when left blank on edit", async () => {
    const user = userEvent.setup();
    let patched: unknown = null;
    renderPage(ME_ADMIN, {
      "PATCH /api/settings/auth/providers/okta": (req) => {
        patched = req.body;
        return { status: 200, body: AUTH_PROVIDER_OIDC };
      },
    });

    await user.click(await screen.findByRole("button", { name: `Edit ${AUTH_PROVIDER_OIDC.name}` }));
    const claim = screen.getByLabelText("Groups claim");
    await user.clear(claim);
    await user.type(claim, "roles");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(patched).toEqual({
      config: {
        issuer: AUTH_PROVIDER_OIDC.config.issuer,
        client_id: AUTH_PROVIDER_OIDC.config.client_id,
        groups_claim: "roles",
        default_role: AUTH_PROVIDER_OIDC.config.default_role,
        label: AUTH_PROVIDER_OIDC.config.label,
      },
    });
    expect(patched).not.toHaveProperty("secret");
  });

  it("shows that a secret is stored without ever showing its value", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: `Edit ${AUTH_PROVIDER_OIDC.name}` }));
    expect(screen.getByText(/stored/)).toBeInTheDocument();
    const field = screen.getByLabelText("Client secret", { exact: false }) as HTMLInputElement;
    expect(field.value).toBe("");
  });
});

describe("AuthSettingsPage: group mappings", () => {
  it("lists existing mappings and posts a new one", async () => {
    const user = userEvent.setup();
    let posted: unknown = null;
    renderPage(ME_ADMIN, {
      "POST /api/settings/auth/providers/okta/mappings": (req) => {
        posted = req.body;
        return { status: 201, body: { group_name: "eng", role: "operator" } };
      },
    });

    await screen.findByText(AUTH_PROVIDER_OIDC.name);
    expect(await screen.findByText(GROUP_MAPPINGS_OKTA[0].group_name)).toBeInTheDocument();

    const addForm = screen.getByRole("form", { name: `Add mapping for ${AUTH_PROVIDER_OIDC.name}` });
    await user.type(within(addForm).getByLabelText("Group name"), "eng");
    await user.selectOptions(within(addForm).getByLabelText("Mapped role"), "operator");
    await user.click(within(addForm).getByRole("button", { name: "Add" }));

    expect(posted).toEqual({ group_name: "eng", role: "operator" });
  });

  it("deletes a mapping", async () => {
    const user = userEvent.setup();
    let deletedPath = "";
    renderPage(ME_ADMIN, {
      "DELETE /api/settings/auth/providers/okta/mappings/network-admins": (req) => {
        deletedPath = req.path;
        return { status: 204 };
      },
    });

    await user.click(
      await screen.findByRole("button", { name: `Remove mapping ${GROUP_MAPPINGS_OKTA[0].group_name}` }),
    );

    expect(deletedPath).toBe("/api/settings/auth/providers/okta/mappings/network-admins");
  });

  it("encodes the group name in the path of the delete", async () => {
    const user = userEvent.setup();
    let deleted = false;
    renderPage(ME_ADMIN, {
      "GET /api/settings/auth/providers/okta/mappings": () => ({
        status: 200,
        body: [{ group_name: "net/admins 1", role: "admin" }],
      }),
      "DELETE /api/settings/auth/providers/okta/mappings/net%2Fadmins%201": () => {
        deleted = true;
        return { status: 204 };
      },
    });

    await user.click(await screen.findByRole("button", { name: "Remove mapping net/admins 1" }));

    await waitFor(() => expect(deleted).toBe(true));
  });
});

describe("AuthSettingsPage: local login toggle", () => {
  it("PUTs the toggle body on change", async () => {
    const user = userEvent.setup();
    let putBody: unknown = null;
    renderPage(ME_ADMIN, {
      "PUT /api/settings/auth": (req) => {
        putBody = req.body;
        return { status: 200, body: { local_login_enabled: false } };
      },
    });

    const toggle = await screen.findByRole("checkbox", { name: /local username and password/i });
    await user.click(toggle);

    expect(putBody).toEqual({ local_login_enabled: false });
  });

  it("surfaces a 409 refusal from the break-glass guard", async () => {
    const user = userEvent.setup();
    renderPage(ME_ADMIN, {
      "PUT /api/settings/auth": () => ({
        status: 409,
        body: { error: "refusing: no other enabled login path would remain" },
      }),
    });

    const toggle = await screen.findByRole("checkbox", { name: /local username and password/i });
    await user.click(toggle);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "refusing: no other enabled login path would remain",
    );
  });
});

describe("AuthSettingsPage: delete provider", () => {
  it("does nothing when the confirm is declined", async () => {
    const user = userEvent.setup();
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    let deleteCalled = false;
    renderPage(ME_ADMIN, {
      "DELETE /api/settings/auth/providers/okta": () => {
        deleteCalled = true;
        return { status: 204 };
      },
    });

    await user.click(await screen.findByRole("button", { name: `Delete ${AUTH_PROVIDER_OIDC.name}` }));
    expect(confirmSpy).toHaveBeenCalled();
    expect(deleteCalled).toBe(false);
    confirmSpy.mockRestore();
  });
});

describe("AuthSettingsPage: test action", () => {
  it("shows ok/detail inline", async () => {
    const user = userEvent.setup();
    renderPage(ME_ADMIN, {
      "POST /api/settings/auth/providers/okta/test": () => ({
        status: 200,
        body: { ok: true, detail: "discovery + JWKS reachable" },
      }),
    });

    await user.click(await screen.findByRole("button", { name: `Test ${AUTH_PROVIDER_OIDC.name}` }));
    expect(await screen.findByText("discovery + JWKS reachable")).toBeInTheDocument();
  });
});
