import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, Route, RouterProvider, Routes, useLocation } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../../auth";
import { mockApi, type MockHandler } from "../../test/fetchMock";
import { ME_OPERATOR } from "../../test/fixtures";
import type { ApplicationRevision, BusinessApplicationDefinition } from "../types";
import { ApplicationsLayout } from "./ApplicationsLayout";
import { ApplicationDetailPage, ApplicationsListPage } from "./pages";

vi.mock("./ComponentGraph", () => ({ default: () => <div role="img" aria-label="Component graph" /> }));

const DEFINITION: BusinessApplicationDefinition = {
  schema_version: 1,
  kind: "BusinessApplication",
  id: "webshop",
  name: "Webshop production",
  state: "ready",
  services: [],
  groups: [{ id: "frontend", name: "Frontend", members: [{ id: "vip", name: "webshop-vip", address: "10.1.10.5" }] }],
  connections: [],
};

function revision(definition: BusinessApplicationDefinition): ApplicationRevision {
  return {
    id: definition.id,
    revision: 1,
    name: definition.name,
    digest: "1".repeat(64),
    created_by: 1,
    created_at: "2026-11-20T14:02:00Z",
    definition,
  };
}

function detailRoutes(application: ApplicationRevision): Record<string, MockHandler> {
  const url = `/api/business-applications/${application.id}`;
  return {
    [`GET ${url}`]: () => ({ body: { application } }),
    [`GET ${url}/analyses`]: () => ({ body: { analyses: [] } }),
    [`GET ${url}/review`]: () => ({ body: { current: null, history: [] } }),
    [`GET ${url}/history`]: () => ({ body: { revisions: [application] } }),
  };
}

function routes(extra: Record<string, MockHandler> = {}): Record<string, MockHandler> {
  return {
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/business-applications": () => ({ body: { applications: [revision(DEFINITION)] } }),
    "GET /api/snapshots": () => ({ body: { snapshots: [], current: null, truncated: false } }),
    ...detailRoutes(revision(DEFINITION)),
    ...extra,
  };
}

function Where() {
  const location = useLocation();
  return <output aria-label="Location">{location.pathname + location.search}</output>;
}

/** The router of main.tsx: one splat route whose element holds the routes. */
function mount(path: string) {
  const router = createMemoryRouter(
    [
      {
        path: "*",
        element: (
          <AuthProvider>
            <Where />
            <Routes>
              <Route path="/applications" element={<ApplicationsLayout />}>
                <Route index element={<ApplicationsListPage />} />
                <Route path=":id" element={<ApplicationDetailPage />} />
              </Route>
            </Routes>
          </AuthProvider>
        ),
      },
    ],
    { initialEntries: [path] },
  );
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

const location = () => screen.getByRole("status", { name: "Location" });

async function editName(user: ReturnType<typeof userEvent.setup>) {
  const name = await screen.findByRole("textbox", { name: "Name" });
  await user.type(name, " 2");
  expect(screen.getByText("Revision 1, draft changes")).toBeInTheDocument();
}

describe("Unsaved changes", () => {
  it("asks before a link leaves an application with unsaved changes, and Stay keeps the draft", async () => {
    mockApi(routes());
    mount("/applications/webshop");
    const user = userEvent.setup();
    await editName(user);

    await user.click(screen.getByRole("link", { name: "Applications", current: false }));
    const dialog = await screen.findByRole("dialog", { name: "Unsaved changes" });
    expect(location()).toHaveTextContent("/applications/webshop");
    await user.click(within(dialog).getByRole("button", { name: "Stay" }));

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(location()).toHaveTextContent("/applications/webshop");
    expect(screen.getByRole("textbox", { name: "Name" })).toHaveValue("Webshop production 2");
  });

  it("leaves the application after Leave", async () => {
    mockApi(routes());
    mount("/applications/webshop");
    const user = userEvent.setup();
    await editName(user);

    await user.click(screen.getByRole("link", { name: "Applications", current: false }));
    await user.click(within(await screen.findByRole("dialog", { name: "Unsaved changes" })).getByRole("button", { name: "Leave" }));
    await waitFor(() => expect(location()).toHaveTextContent(/^\/applications$/));
  });

  it("switches tabs without asking", async () => {
    mockApi(routes());
    mount("/applications/webshop");
    const user = userEvent.setup();
    await editName(user);

    await user.click(screen.getByRole("tab", { name: "Components" }));
    expect(location()).toHaveTextContent("/applications/webshop?tab=components");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByText("Revision 1, draft changes")).toBeInTheDocument();
  });

  it("leaves an application without unsaved changes without asking", async () => {
    mockApi(routes());
    mount("/applications/webshop");
    const user = userEvent.setup();
    await screen.findByRole("textbox", { name: "Name" });
    await user.click(screen.getByRole("link", { name: "Applications", current: false }));
    await waitFor(() => expect(location()).toHaveTextContent(/^\/applications$/));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("asks the browser before it unloads a page with unsaved changes", async () => {
    mockApi(routes());
    mount("/applications/webshop");
    const user = userEvent.setup();
    const clean = new Event("beforeunload", { cancelable: true });
    await screen.findByRole("textbox", { name: "Name" });
    act(() => void window.dispatchEvent(clean));
    expect(clean.defaultPrevented).toBe(false);

    await editName(user);
    const dirty = new Event("beforeunload", { cancelable: true });
    act(() => void window.dispatchEvent(dirty));
    expect(dirty.defaultPrevented).toBe(true);
  });

  it("opens a saved new application without asking", async () => {
    const saved = revision({ ...DEFINITION, id: "intranet", name: "Intranet production" });
    mockApi(
      routes({
        "POST /api/business-applications": () => ({ status: 201, body: saved }),
        ...detailRoutes(saved),
      }),
    );
    mount("/applications/new");
    const user = userEvent.setup();
    await user.type(await screen.findByRole("textbox", { name: "Name" }), "Intranet production");
    await user.type(screen.getByRole("textbox", { name: "Stable ID" }), "intranet");
    await user.tab();
    await user.click(screen.getByRole("button", { name: "Save revision" }));

    await waitFor(() => expect(location()).toHaveTextContent("/applications/intranet"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Intranet production" })).toBeInTheDocument();
  });

  it("asks before a link leaves a new application with unsaved changes", async () => {
    mockApi(routes());
    mount("/applications/new");
    const user = userEvent.setup();
    await user.type(await screen.findByRole("textbox", { name: "Name" }), "Intranet production");
    await user.click(screen.getByRole("link", { name: "Applications", current: false }));
    expect(await screen.findByRole("dialog", { name: "Unsaved changes" })).toBeInTheDocument();
    expect(location()).toHaveTextContent("/applications/new");
  });
});
