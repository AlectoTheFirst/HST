import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import SourcesPage from "./SourcesPage";
import { AuthProvider } from "../auth";
import { mockApi, type MockHandler } from "../test/fetchMock";
import { ME_ADMIN, SOURCE_TYPES, SOURCE_UNIFI, SOURCES_RESPONSE } from "../test/fixtures";

// the text src/hst/app/sources.py shared_routing_scope_warnings returns
const SCOPE_WARNING = "routing scope 'home' is also the routing scope of office-unifi: prefixes and addresses these sources report for one subnet are one node";

function renderSources(routes: Record<string, MockHandler>) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_ADMIN }),
    "GET /api/source-types": () => ({ status: 200, body: SOURCE_TYPES }),
    "GET /api/sources": () => ({ status: 200, body: SOURCES_RESPONSE }),
    ...routes,
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AuthProvider>
          <SourcesPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("SourcesPage: save warnings", () => {
  it("shows the routing scope warning a create returns, after the form closes", async () => {
    const user = userEvent.setup();
    renderSources({
      "POST /api/sources": () => ({ status: 201, body: { ...SOURCE_UNIFI, name: "new-unifi", warnings: [SCOPE_WARNING] } }),
    });

    await user.click(await screen.findByRole("button", { name: /add source/i }));
    await user.type(screen.getByLabelText("Name"), "new-unifi");
    await user.selectOptions(screen.getByLabelText("Type"), "unifi");
    await user.type(screen.getByLabelText("Url", { exact: false }), "https://192.168.1.1");
    await user.type(screen.getByLabelText("User", { exact: false }), "admin");
    await user.type(screen.getByLabelText("Password", { exact: false }), "hunter2");
    await user.click(screen.getByRole("button", { name: "Create" }));

    const banner = await screen.findByRole("status", { name: "Save warnings for new-unifi" });
    expect(within(banner).getByText(SCOPE_WARNING)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create" })).not.toBeInTheDocument();

    await user.click(within(banner).getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByRole("status", { name: "Save warnings for new-unifi" })).not.toBeInTheDocument();
  });

  it("shows the routing scope warning an edit returns", async () => {
    const user = userEvent.setup();
    renderSources({
      "PATCH /api/sources/home-unifi": () => ({ status: 200, body: { ...SOURCE_UNIFI, warnings: [SCOPE_WARNING] } }),
    });

    await user.click(await screen.findByRole("button", { name: "Edit home-unifi" }));
    await user.click(screen.getByRole("button", { name: "Save connection" }));

    const banner = await screen.findByRole("status", { name: "Save warnings for home-unifi" });
    expect(within(banner).getByText(SCOPE_WARNING)).toBeInTheDocument();
  });

  it("shows no banner when the save returns no warnings", async () => {
    const user = userEvent.setup();
    renderSources({
      "PATCH /api/sources/home-unifi": () => ({ status: 200, body: SOURCE_UNIFI }),
    });

    await user.click(await screen.findByRole("button", { name: "Edit home-unifi" }));
    await user.click(screen.getByRole("button", { name: "Save connection" }));

    await screen.findByRole("button", { name: "Edit home-unifi" });
    expect(screen.queryByRole("button", { name: "Save connection" })).not.toBeInTheDocument();
    expect(screen.queryByRole("status", { name: /Save warnings/ })).not.toBeInTheDocument();
  });
});
