import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { mockApi } from "../test/fetchMock";
import { AssistantDraftPanel } from "./AssistantDraftPanel";

const suggestion = {
  status: "done",
  title: "Frankfurt continuity",
  kind: "resilience",
  snapshot: "1000",
  plan: { title: "Continuity", kind: "resilience" },
  candidates: [
    { uid: "service-1", name: "Checkout", kind: "service", selectable: true },
    { uid: "link-1", name: "Frankfurt uplink", kind: "link", selectable: true },
  ],
  selections: [],
  questions: ["Choose exactly one recorded service."],
  assumptions: ["No evaluation has run."],
  ready: false,
  truncated: false,
};

describe("Assistant draft review", () => {
  it("requires explicit named selections before handing a draft to the guided form", async () => {
    const bodies: any[] = [];
    const onDraft = vi.fn();
    mockApi({
      "POST /api/assessment-assistant/drafts": ({ body }: any) => {
        bodies.push(body);
        return { body: { job_id: String(bodies.length) }, status: 202 };
      },
      "GET /api/assessment-assistant/drafts/1": () => ({ body: suggestion }),
      "GET /api/assessment-assistant/drafts/2": () => ({
        body: {
          ...suggestion,
          ready: true,
          questions: [],
          definition: {
            snapshot: "1000",
            intents: [],
            mode: "possible",
            freshness_s: 3600,
            requirement: "service-1",
          },
          analysis: {
            kind: "resilience",
            snapshot: "1000",
            targets: [{ id: "failure-1", uid: "link-1", kind: "link", interfaces: ["a", "b"] }],
          },
        },
      }),
    });
    render(<AssistantDraftPanel snapshot="1000" onDraft={onDraft} />);
    const user = userEvent.setup();
    await user.type(
      screen.getByLabelText("Question for AI"),
      "Can checkout survive Frankfurt uplink loss?",
    );
    await user.click(screen.getByRole("button", { name: "Prepare with AI" }));
    const service = await screen.findByRole("checkbox", { name: /Checkout/ });
    expect(service).not.toBeChecked();
    expect(
      screen.queryByRole("button", { name: "Review draft in guided form" }),
    ).not.toBeInTheDocument();
    await user.click(service);
    await user.click(screen.getByRole("checkbox", { name: /Frankfurt uplink/ }));
    await user.click(screen.getByRole("button", { name: "Use selected objects" }));
    await user.click(await screen.findByRole("button", { name: "Review draft in guided form" }));
    expect(bodies[1].selections).toEqual([
      { uid: "service-1", kind: "service" },
      { uid: "link-1", kind: "link" },
    ]);
    expect(onDraft).toHaveBeenCalledWith(
      expect.objectContaining({
        kind: "resilience",
        definition: expect.objectContaining({ snapshot: "1000" }),
        analysis: expect.objectContaining({ targets: expect.any(Array) }),
      }),
    );
    expect(bodies.every((b) => b.snapshot === "1000")).toBe(true);
    expect(screen.queryByText("service-1")).not.toBeInTheDocument();
  });

  it("keeps the manual path available when AI is disabled", async () => {
    mockApi({
      "POST /api/assessment-assistant/drafts": () => ({
        status: 503,
        body: { error: "AI assistance is unavailable." },
      }),
    });
    render(<AssistantDraftPanel snapshot="1000" onDraft={vi.fn()} />);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Question for AI"), "Help");
    await user.click(screen.getByRole("button", { name: "Prepare with AI" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("AI assistance is unavailable.");
  });

  it("never displays a delayed response after the question changes", async () => {
    let resolve: ((value: any) => void) | undefined;
    mockApi({
      "POST /api/assessment-assistant/drafts": () => ({ body: { job_id: "late" }, status: 202 }),
      "GET /api/assessment-assistant/drafts/late": () =>
        new Promise((r) => {
          resolve = r;
        }),
    });
    render(<AssistantDraftPanel snapshot="1000" onDraft={vi.fn()} />);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Question for AI"), "Old question");
    await user.click(screen.getByRole("button", { name: "Prepare with AI" }));
    await waitFor(() => expect(resolve).toBeDefined());
    await user.type(screen.getByLabelText("Question for AI"), " changed");
    resolve!({ body: suggestion });
    await waitFor(() => expect(screen.queryByText("Frankfurt continuity")).not.toBeInTheDocument());
  });

  it("keeps the symptom while using a follow-up answer to discover the traffic", async () => {
    const bodies: any[] = [];
    mockApi({
      "POST /api/assessment-assistant/drafts": ({ body }) => {
        bodies.push(body);
        return { status: 202, body: { job_id: String(bodies.length) } };
      },
      "GET /api/assessment-assistant/drafts/1": () => ({
        body: {
          ...suggestion,
          candidates: [],
          questions: ["What destination are you trying to reach?"],
        },
      }),
      "GET /api/assessment-assistant/drafts/2": () => ({
        body: {
          ...suggestion,
          clues: [{ kind: "service", destination: "https://shop.example", location: "Berlin" }],
        },
      }),
    });
    const onDraft = vi.fn();
    render(<AssistantDraftPanel snapshot="1000" onDraft={onDraft} />);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Question for AI"), "A page fails from Berlin");
    await user.click(screen.getByRole("button", { name: "Prepare with AI" }));
    await screen.findByText("What destination are you trying to reach?");
    await user.type(screen.getByLabelText("Additional clues or answer"), "https://shop.example");
    await user.click(screen.getByRole("button", { name: "Find matches with this information" }));
    expect(await screen.findByRole("checkbox", { name: /Checkout/ })).not.toBeChecked();
    expect(bodies[1].question).toBe(
      "A page fails from Berlin\nAdditional information: https://shop.example",
    );
    expect(bodies[1]).not.toHaveProperty("plan");
    expect(bodies[1].selections).toEqual([]);
    expect(onDraft).not.toHaveBeenCalled();
  });

  it("carries unconfirmed clues into manual discovery without inventing a service", async () => {
    const onDraft = vi.fn();
    mockApi({
      "POST /api/assessment-assistant/drafts": () => ({ status: 202, body: { job_id: "none" } }),
      "GET /api/assessment-assistant/drafts/none": () => ({
        body: {
          ...suggestion,
          candidates: [],
          clues: [{ kind: "service", destination: "192.0.2.10", client: "10.0.0.8" }],
        },
      }),
    });
    render(
      <AssistantDraftPanel snapshot="1000" onDraft={onDraft} initialQuestion="This IP fails" />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Prepare with AI" }));
    await user.click(await screen.findByRole("button", { name: "Continue with known traffic" }));
    expect(onDraft).toHaveBeenCalledWith(
      expect.objectContaining({
        definition: expect.objectContaining({
          snapshot: "1000",
          request: expect.objectContaining({ sources: [] }),
        }),
        analysis: {
          service_clues: { kind: "service", destination: "192.0.2.10", client: "10.0.0.8" },
        },
      }),
    );
  });

  it("allows a fresh question when the snapshot changes during admission", async () => {
    let resolve: ((value: any) => void) | undefined;
    mockApi({
      "POST /api/assessment-assistant/drafts": () =>
        new Promise((done) => {
          resolve = done;
        }),
    });
    const props = { onDraft: vi.fn(), initialQuestion: "A page fails" };
    const { rerender } = render(<AssistantDraftPanel snapshot="1000" {...props} />);
    await userEvent.click(screen.getByRole("button", { name: "Prepare with AI" }));
    await waitFor(() => expect(resolve).toBeDefined());
    rerender(<AssistantDraftPanel snapshot="2000" {...props} />);
    expect(screen.getByRole("button", { name: "Prepare with AI" })).toBeEnabled();
    resolve!({ status: 202, body: { job_id: "old-snapshot" } });
    expect(screen.queryByText(/Preparing a draft/)).not.toBeInTheDocument();
  });

  it("submits a saved match with its explicit origin and immutable revision", async () => {
    const bodies: any[] = [];
    mockApi({
      "POST /api/assessment-assistant/drafts": ({ body }) => {
        bodies.push(body);
        return { status: 202, body: { job_id: "saved" } };
      },
      "GET /api/assessment-assistant/drafts/saved": () => ({
        body: {
          ...suggestion,
          candidates: [
            {
              uid: "s1",
              kind: "service",
              origin: "saved",
              name: "Saved checkout",
              requirement_revision: 3,
              selectable: true,
            },
          ],
        },
      }),
    });
    render(
      <AssistantDraftPanel
        snapshot="1000"
        onDraft={vi.fn()}
        initialQuestion="The checkout page fails"
      />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Prepare with AI" }));
    await user.click(await screen.findByRole("checkbox", { name: /Saved checkout/ }));
    await user.click(screen.getByRole("button", { name: "Use selected objects" }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1].selections).toEqual([
      { uid: "s1", kind: "service", origin: "saved", requirement_revision: 3 },
    ]);
  });
});
