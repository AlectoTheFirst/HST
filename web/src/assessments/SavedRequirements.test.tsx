import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router";
import { AuthProvider } from "../auth";
import { ME_OPERATOR } from "../test/fixtures";
import { mockApi, type MockRequest } from "../test/fetchMock";
import AssessmentsPage from "./AssessmentsPage";
import type { Assessment, SavedRequirement } from "./types";

const assessment: Assessment = {
  id: "a1",
  title: "Application change",
  revision: 1,
  created_at: "2026-09-08T00:00:00Z",
  updated_at: "2026-09-08T00:00:00Z",
  definition: {
    snapshot: "1000",
    mode: "possible",
    freshness_s: 3600,
    request: {
      name: "Application",
      destination: "Backend",
      sources: ["10.0.0.1"],
      members: [
        {
          name: "backend",
          addresses: ["192.0.2.1"],
          proto: "tcp",
          port: "443",
          source_port: "1024-65535",
        },
      ],
      condition: { kind: "member", member: "backend" },
      success: "session",
    },
    intents: [{ kind: "fw_rule.remove", params: { rulebase: "rb1", rule: "deny1" } }],
  },
};
const saved: SavedRequirement = {
  id: "req1",
  revision: 3,
  title: "Reusable service",
  created_at: assessment.created_at,
  definition: {
    ...assessment.definition,
    request: {
      ...assessment.definition.request!,
      name: "Reusable service",
      sources: ["10.1.0.0/24", "10.2.0.0/24"],
    },
    intents: [],
  },
};

function Wrapper() {
  const [client] = useState(
    () => new QueryClient({ defaultOptions: { queries: { retry: false } } }),
  );
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AuthProvider>
          <AssessmentsPage assessmentId="a1" onNavigate={() => {}} />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

function setup() {
  const revise = vi.fn((_request: MockRequest) => ({ body: assessment }));
  const create = vi.fn((_request: MockRequest) => ({ body: saved }));
  mockApi({
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/assessments": () => ({ body: { assessments: [assessment] } }),
    "GET /api/assessments/a1": () => ({ body: { assessment, runs: [] } }),
    "GET /api/snapshots": () => ({
      body: { snapshots: [{ id: "1000", ts_ms: 1000, kind: "full" }] },
    }),
    "GET /api/assessment-options": () => ({
      body: { snapshot: "1000", items: [], truncated: false },
    }),
    "GET /api/requirements": () => ({ body: { requirements: [saved] } }),
    "POST /api/requirements": create,
    "PATCH /api/assessments/a1": revise,
  });
  render(<Wrapper />);
  return { create, revise };
}

describe("Reusable authored requirements", () => {
  it("copies the selected immutable request and records its revision", async () => {
    const { revise } = setup();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Edit assessment" }));
    await user.click(await screen.findByRole("button", { name: /Reusable service Saved service/ }));
    await user.click(screen.getByRole("button", { name: "Edit selected service" }));
    expect(screen.getByLabelText("Requirement name")).toHaveValue("Reusable service");
    expect(screen.getByLabelText("Client addresses or prefixes")).toHaveValue(
      "10.1.0.0/24, 10.2.0.0/24",
    );
    expect(screen.getByLabelText("Member 1 source port")).toHaveValue("1024-65535");
    await user.click(screen.getByRole("button", { name: "Save new revision" }));
    await waitFor(() => expect(revise).toHaveBeenCalledOnce());
    expect(revise.mock.calls[0][0].body).toMatchObject({
      expected_revision: 1,
      definition: {
        requirement_id: "req1",
        requirement_revision: 3,
        request: saved.definition.request,
        intents: assessment.definition.intents,
      },
    });
  });

  it("saves a reusable requirement without carrying proposed firewall changes", async () => {
    const { create } = setup();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Edit assessment" }));
    await user.click(screen.getByText("Assumptions, freshness and proposed changes"));
    await user.click(screen.getByRole("button", { name: "Save requirement" }));
    expect(await screen.findByText("Service saved as requirement revision 3")).toBeInTheDocument();
    expect(create.mock.calls[0][0].body).toMatchObject({
      title: "Application",
      definition: { request: assessment.definition.request, snapshot: "1000", intents: [] },
    });
    await user.click(screen.getByRole("button", { name: "Edit selected service" }));
    expect(screen.getByLabelText("Requirement name")).toHaveValue("Reusable service");
  });

  it("detaches the saved revision when its copied request is edited", async () => {
    const { revise } = setup();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Edit assessment" }));
    await user.click(await screen.findByRole("button", { name: /Reusable service Saved service/ }));
    await user.click(screen.getByRole("button", { name: "Edit selected service" }));
    await user.type(screen.getByLabelText("Requirement name"), " customized");
    expect(screen.getByLabelText("Requirement name")).toHaveValue("Reusable service customized");
    await user.click(screen.getByRole("button", { name: "Save new revision" }));
    await waitFor(() => expect(revise).toHaveBeenCalledOnce());
    const body = revise.mock.calls[0][0].body as { definition: Record<string, unknown> };
    expect(body.definition).not.toHaveProperty("requirement_id");
    expect(body.definition).not.toHaveProperty("requirement_revision");
    expect(body.definition.request).toMatchObject({ name: "Reusable service customized" });
  });
});
