/**
 * Release scenario "Import update/conflict",
 * web part: preview one changed connection and an explicit removal; a
 * concurrent revision makes the commit conflict, and the page keeps the YAML
 * and states the conflict and applies nothing.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth";
import ApplicationsPage from "../applications/ApplicationsPage";
import type { ApplicationRevision } from "../applications/types";
import { mockApi, type MockRequest } from "../test/fetchMock";
import { ME_OPERATOR } from "../test/fixtures";

const CURRENT: ApplicationRevision = {
  id: "checkout", revision: 2, name: "Checkout", digest: "2".repeat(64), created_by: 1, created_at: "2026-01-01T00:00:00Z",
  definition: { schema_version: 1, kind: "BusinessApplication", id: "checkout", name: "Checkout", state: "draft", services: [], groups: [], connections: [] },
};

const YAML = [
  "schema_version: 1",
  "kind: BusinessApplication",
  "id: checkout",
  "name: Checkout",
  "connections:",
  "  - id: web-to-api",
  "    name: Frontend to API",
  "    source: frontend",
  "    destination: api",
  "    protocol: tcp",
  "    destination_ports: [8443]",
  "",
].join("\n");

const PREVIEW = {
  application_id: "checkout", base_revision: 2, base_digest: "2".repeat(64), result_digest: "3".repeat(64), preview_digest: "4".repeat(64), definition: {},
  changes: { connections_updated: ["web-to-api"], connections_removed: ["api-to-db"] },
  mapping_issues: [], no_op: false,
};

describe("Import update/conflict", () => {
  it("keeps the YAML and states the conflict when the application changed after the preview", async () => {
    const previews: MockRequest[] = [];
    const commits: MockRequest[] = [];
    const writes: MockRequest[] = [];
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [CURRENT] } }),
      "GET /api/snapshots": () => ({ body: { snapshots: [{ id: "4000", ts_ms: 4000, kind: "full" }], current: 4000, truncated: false } }),
      "POST /api/business-applications/import/preview": (req) => { previews.push(req); return { body: PREVIEW }; },
      "POST /api/business-applications/import/commit": (req) => { commits.push(req); return { status: 409, body: { detail: "application checkout is at revision 3, not 2", code: "revision-conflict", current_revision: 3 } }; },
      "PUT /api/business-applications/checkout": (req) => { writes.push(req); return { body: CURRENT }; },
      "POST /api/business-applications": (req) => { writes.push(req); return { body: CURRENT }; },
    });
    const navigated = vi.fn();
    const user = userEvent.setup();
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><AuthProvider><ApplicationsPage onNavigate={navigated} onOpenAnalysis={() => undefined} /></AuthProvider></MemoryRouter></QueryClientProvider>);

    await waitFor(() => expect(screen.getByText("Import YAML").closest("details")).not.toHaveAttribute("open"));
    await user.click(screen.getByText("Import YAML"));
    const editor = await screen.findByRole("textbox", { name: "Definition YAML" });
    await user.click(editor);
    await user.paste(YAML);
    await user.selectOptions(screen.getByLabelText("Import mode"), "replace");
    await user.click(screen.getByRole("button", { name: "Preview import" }));

    // the preview names the changed connection and the explicit removal
    const preview = await screen.findByRole("region", { name: "Import preview" });
    expect(within(preview).getByText("connections updated:").parentElement).toHaveTextContent("web-to-api");
    expect(within(preview).getByText("connections removed:").parentElement).toHaveTextContent("api-to-db");

    await user.click(within(preview).getByRole("button", { name: "Commit revision" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Application changed after this preview");
    // the YAML is kept, nothing navigates to a saved revision, nothing else is written
    expect(screen.getByRole("textbox", { name: "Definition YAML" })).toHaveValue(YAML);
    expect(commits).toHaveLength(1);
    expect(commits[0].body).toEqual({ yaml: YAML, mode: "replace", base_revision: 2, base_digest: "2".repeat(64), preview_digest: "4".repeat(64) });
    expect(writes).toHaveLength(0);
    expect(navigated).not.toHaveBeenCalled();

    // the retained YAML previews again as it was
    await user.click(screen.getByRole("button", { name: "Preview import" }));
    await waitFor(() => expect(previews).toHaveLength(2));
    expect(previews[1].body).toEqual({ yaml: YAML, mode: "replace" });
  });
});
