/**
 * WP-06 "Done when" criterion of the Business Applications plan: the
 * protections of a saved simulation session show in Scope and in Results,
 * each one and in full, up to the bound of 50.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { AuthProvider } from "../auth";
import AnalysisWorkspace from "../analysis/AnalysisWorkspace";
import { mockApi } from "../test/fetchMock";
import { ME_VIEWER } from "../test/fixtures";

const SNAPSHOT = { snapshot: "4000", manifest_sha256: "b".repeat(64), estate: "test" };
const FLOW = { src: "10.9.0.5", dst: "10.30.0.10", proto: "tcp", port: 443 };

const APPLICATION_PROTECTION = {
  kind: "application_connection",
  reference: {
    application: { id: "checkout", revision: 3, digest: "a".repeat(64) },
    service_id: "storefront",
    connection_id: "frontend-to-api",
  },
  resolved_scope_digest: "c".repeat(64),
  desired: "holds",
};

function inline(name: string, desired = "isolated") {
  return {
    kind: "inline",
    name,
    request: { name, destination: "API", sources: ["10.9.0.0/24"], members: [{ name: "api", addresses: ["10.30.0.10"] }], condition: { kind: "member", member: "api" } },
    desired,
  };
}

/** A completed simulation session whose run evaluated each protection, in the shape `_simulate` saves. */
function session(protections: Record<string, unknown>[]) {
  return {
    id: "sim-p", revision: 2, title: "Protected change", created_by: 1, created_at: "2026-01-01T00:00:00Z", input_digest: "e".repeat(64),
    definition: {
      schema_version: 1, id: "sim-p", revision: 2, title: "Protected change",
      input: { kind: "simulation", snapshot: SNAPSHOT, changes: [{ kind: "fw_rule.remove", params: { rulebase: "rb:r1", rule: "deny-8443" } }], scope: { flows: [FLOW], sites: [] }, bounds: { max_flows: 50, max_seconds: 30 }, protected: protections },
      runs: [{ id: "run-p", item_id: "simulation", execution: "completed", result: null, coverage: "partial", result_ref: "analysis-run:run-p" }],
    },
    results: {
      simulation: { flows: [{ flow: FLOW, before: { result: "denied" }, after: { result: "permitted" } }] },
      protected: protections.map((protection, index) => ({
        desired: protection.desired,
        reference: protection,
        result: { outcomes: { after: { result: { answer: index === 0 ? "true" : "open" } } }, missing_evidence: index === 0 ? [] : [`evidence ${index} missing`] },
      })),
    },
  };
}

function open(record: ReturnType<typeof session>) {
  mockApi({
    "GET /api/me": () => ({ body: ME_VIEWER }),
    "GET /api/analysis-sessions": () => ({ body: { sessions: [record] } }),
    "GET /api/analysis-sessions/sim-p": () => ({ body: record }),
  });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter><AuthProvider><AnalysisWorkspace sessionId="sim-p" onNavigate={() => undefined} /></AuthProvider></MemoryRouter>
    </QueryClientProvider>,
  );
  return userEvent.setup();
}

describe("Protections of a saved simulation session", () => {
  it("shows each protection with its desired state and outcome in Results and its selection in Scope", async () => {
    const user = open(session([APPLICATION_PROTECTION, inline("Admin isolation")]));

    const results = (await screen.findByRole("heading", { name: "Protected requirements" })).parentElement!;
    expect(results).toHaveTextContent(/"connection_id": "frontend-to-api"/);
    expect(results).toHaveTextContent(/"id": "checkout",\s*"revision": 3/);
    expect(results).toHaveTextContent(/"name": "Admin isolation"/);
    expect(results).toHaveTextContent(/"desired": "holds"/);
    expect(results).toHaveTextContent(/"desired": "isolated"/);
    expect(results).toHaveTextContent("evidence 1 missing");

    await user.click(screen.getByRole("tab", { name: "Scope" }));
    const scope = screen.getByRole("heading", { name: "Scope" }).parentElement!;
    expect(scope).toHaveTextContent(/"protected": \[/);
    expect(scope).toHaveTextContent(/"connection_id": "frontend-to-api"/);
    expect(scope).toHaveTextContent(/"resolved_scope_digest": "c{64}"/);
    expect(scope).toHaveTextContent(/"name": "Admin isolation"/);
  });

  it("shows all 50 protections of a session at the bound in Results and in Scope", async () => {
    const names = Array.from({ length: 50 }, (_, index) => `Protection ${index + 1}`);
    const user = open(session(names.map((name) => inline(name))));

    const results = (await screen.findByRole("heading", { name: "Protected requirements" })).parentElement!;
    const shown = (text: string | null) => [...(text ?? "").matchAll(/"name": "(Protection \d+)"/g)].map((match) => match[1]);
    // a name appears in the reference and in the request of its protection
    expect(new Set(shown(results.textContent))).toEqual(new Set(names));

    await user.click(screen.getByRole("tab", { name: "Scope" }));
    const scope = screen.getByRole("heading", { name: "Scope" }).parentElement!;
    expect(new Set(shown(scope.textContent))).toEqual(new Set(names));
  });
});
