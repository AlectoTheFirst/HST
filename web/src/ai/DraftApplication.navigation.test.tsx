import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { it, vi } from "vitest";
import type { AnswerEnvelope } from "../api/types";
import { AuthProvider } from "../auth";
import { ME_OPERATOR } from "../test/fixtures";
import { mockApi } from "../test/fetchMock";
import { Workspace } from "../workspace/Workspace";
import { WorkspaceProvider } from "../workspace/WorkspaceContext";
import { DraftApplication } from "./DraftApplication";

// The initial pane's pages are stubs.
vi.mock("../flowdesk/TracePage", () => ({ default: () => <p>Trace pane</p> }));
vi.mock("../explore/ExplorePage", () => ({ default: () => <p>Explore pane</p> }));

it.each(["running", "done", "error"])("opens the real draft page for a %s generation", async (status) => {
  const reference = { snapshot: "4000", manifest_sha256: "a".repeat(64), estate: "test", observation_floor_ms: null };
  const envelope: AnswerEnvelope = {
    version: 2, message_id: "m1", conversation_id: "c1", kind: "answer",
    snapshot: { id: "4000", origin: "pointer", others_used: [] },
    model: { provider: "bedrock", requested: "eu.anthropic.claude-opus-5-5" },
    prompt_hash: "test", tools_used: [], answer_markdown: "Application found.", claims: [],
    grounding: { status: "no-evidence", cited: 0, uncited: 0, invalid: 0, cross_snapshot: 0 }, links: [],
  };
  const definition = { schema_version: 2, kind: "BusinessApplication", id: "webshop", name: "Webshop", state: "draft", groups: [], connections: [], services: [] };
  mockApi({
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/ai/conversations/c1": () => ({ body: { messages: [
      { id: "q1", seq: 0, role: "user", content: "Describe webshop" },
      { id: "m1", seq: 1, role: "assistant", content: "Application found." },
    ] } }),
    "POST /api/ai/service-drafts": () => ({ status: 202, body: { generation_id: "g1" } }),
    "GET /api/business-applications": () => ({ body: { applications: [] } }),
    "GET /api/business-applications/generations/g1": () => ({ body: status === "done" ? {
      status, generation_id: "g1", snapshot: reference, yaml: "name: Webshop", errors: [],
      report: { snapshot: reference, references: [], related: [] },
      validation: { definition, errors: [], warnings: [], blocking: [], preview: null, resolution: null, flows: null },
    } : { status, detail: status === "error" ? "The generation failed." : undefined } }),
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const user = userEvent.setup();
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/"]}>
    <AuthProvider><WorkspaceProvider><DraftApplication envelope={envelope} /><Workspace /></WorkspaceProvider></AuthProvider>
  </MemoryRouter></QueryClientProvider>);
  await user.click(await screen.findByRole("button", { name: "Draft Business Application" }));
  if (status === "running") expect(await screen.findByText("Generating the definition")).toBeInTheDocument();
  if (status === "error") expect(await screen.findByRole("alert")).toHaveTextContent("The generation failed.");
  if (status === "done") expect(await screen.findByLabelText("Draft YAML")).toHaveValue("name: Webshop");
  expect(screen.getByRole("region", { name: "Application draft" })).toBeInTheDocument();
  view.unmount();
  client.clear();
});
