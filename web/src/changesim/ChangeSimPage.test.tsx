/** The tests cover each tool result in the pane that it fills. */

import { afterEach, describe, it, expect } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import ChangeSimPage from "./ChangeSimPage";
import { AiContextProvider } from "../ai/context";
import { AiDrawerProvider, CONVERSATION_KEY, useAiDrawer } from "../ai/drawer";
import { AuthProvider } from "../auth";
import { mockApi, type MockRequest } from "../test/fetchMock";
import {
  FIXTURE_ASSESS_IMPACT,
  FIXTURE_ASSESS_IMPACT_JSON,
  FIXTURE_CHANGE_SIMULATE_JSON,
  FIXTURE_IMPACT_ASSESS_JSON,
  FIXTURE_INVENTORY_RESOLVE_ENVELOPE,
  FIXTURE_PREDICT_ROUTES_JSON,
  FIXTURE_RESOLVE_ADDRESS,
  FIXTURE_RESOLVE_ADDRESS_JSON,
  FIXTURE_ROUTING_PREDICT_ROUTES_JSON,
  FIXTURE_SIMULATE_POLICY_CHANGE_JSON,
  ME_OPERATOR,
  ME_VIEWER,
  catalogueEnvelope,
} from "../test/fixtures";
import { WorkspaceProvider, useWorkspace } from "../workspace/WorkspaceContext";
import { panes } from "../workspace/layout";

// The language rules forbid these labels in the rendered text.
const BANNED_WORDS = /\b(reached|delivered|reachability|live|intended)\b/i;

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <ChangeSimPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

// The first question creates the conversation; a question starts a turn whose
// answer comes from polling the assistant message.
const CREATED = { status: 201, body: { id: "c1", surface: "changesim", message_count: 0 } };
const STARTED = { status: 202, body: { message_id: "m1" } };

describe("ChangeSimPage: mount", () => {
  it("mounts with both panes and the chat input, no assessment yet", () => {
    const { container } = renderPage();

    expect(screen.getByRole("heading", { name: "Baseline" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Predicted" })).toBeInTheDocument();
    expect(screen.getByLabelText("Planned change")).toBeInTheDocument();

    expect(container.textContent).not.toMatch(BANNED_WORDS);
  });
});

describe("ChangeSimPage: assess_impact result", () => {
  it("renders the tool result in both panes under the binding labels", async () => {
    mockApi({
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => ({
        status: 200,
        body: {
          status: "done",
          answer: "Reloading leaf101 would isolate one prefix and one endpoint.",
          declined: false,
          steps: [
            {
              name: "assess_impact",
              arguments: { device: "leaf101" },
              result: FIXTURE_ASSESS_IMPACT_JSON,
              is_error: false,
            },
          ],
        },
      }),
    });
    const user = userEvent.setup();
    const { container } = renderPage();

    await user.type(screen.getByLabelText("Planned change"), "what if leaf101 reloads?");
    await user.click(screen.getByRole("button", { name: /Send/ }));

    const baseline = screen.getByRole("region", { name: "Baseline pane" });
    const predicted = screen.getByRole("region", { name: "Predicted pane" });

    expect(await within(baseline).findByText("leaf101")).toBeInTheDocument();
    expect(within(baseline).getByText(/10\.0\.1\.0\/24/)).toBeInTheDocument();
    expect(within(baseline).getByText("host9")).toBeInTheDocument();
    expect(within(baseline).getByText(/rg1/)).toBeInTheDocument();
    expect(within(baseline).queryByText("1724236800000")).not.toBeInTheDocument();

    expect(within(predicted).getByText("leaf101")).toBeInTheDocument();
    expect(within(predicted).getByText(/10\.0\.1\.0\/24/)).toBeInTheDocument();
    expect(within(predicted).getByText("host9")).toBeInTheDocument();
    expect(within(predicted).getByText(/surviving members leaf102/)).toBeInTheDocument();
    expect(within(predicted).getByText("Gi1/0/1")).toBeInTheDocument();
    expect(within(predicted).getByText(/10\.0\.0\.1.*10\.0\.0\.2/)).toBeInTheDocument();
    expect(within(predicted).getByText(/10\.0\.1\.1/)).toBeInTheDocument();
    expect(within(predicted).getByText(/^Snapshot /)).toBeInTheDocument();

    // and the panes carry no banned word anywhere in their rendered text
    expect(container.textContent).not.toMatch(BANNED_WORDS);
  });

  it("shows the tool call in the chat transcript alongside the answer", async () => {
    mockApi({
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => ({
        status: 200,
        body: {
          status: "done",
          answer: "Reloading leaf101 would isolate one prefix and one endpoint.",
          declined: false,
          steps: [
            {
              name: "assess_impact",
              arguments: { device: "leaf101" },
              result: FIXTURE_ASSESS_IMPACT_JSON,
              is_error: false,
            },
          ],
        },
      }),
    });
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("Planned change"), "what if leaf101 reloads?");
    await user.click(screen.getByRole("button", { name: /Send/ }));

    expect(
      await screen.findByText("Reloading leaf101 would isolate one prefix and one endpoint."),
    ).toBeInTheDocument();
    expect(screen.getByText("1 tool call")).toBeInTheDocument();
  });
});

/** One finished ask whose answer carries a single successful tool call. */
function answerWith(name: string, result: string, answer: string) {
  return {
    status: 200,
    body: {
      status: "done",
      answer,
      declined: false,
      steps: [{ name, arguments: {}, result, is_error: false }],
    },
  };
}

async function ask(question: string) {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText("Planned change"), question);
  await user.click(screen.getByRole("button", { name: /Send/ }));
}

describe("ChangeSimPage: resolve_address result", () => {
  it("renders the address and its sections in the Baseline pane", async () => {
    mockApi({
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () =>
        answerWith(
          "resolve_address",
          FIXTURE_RESOLVE_ADDRESS_JSON,
          "192.168.2.35 is a server on vlan20 behind leaf101.",
        ),
    });
    const { container } = renderPage();
    await ask("can I block 192.168.2.35 with an ACL?");

    const baseline = screen.getByRole("region", { name: "Baseline pane" });
    expect(await within(baseline).findByText("192.168.2.35")).toBeInTheDocument();
    expect(within(baseline).getByText(/ip:bd:vlan20:192\.168\.2\.35/)).toBeInTheDocument();
    expect(within(baseline).getByText(/host9 \(server\)/)).toBeInTheDocument();
    expect(within(baseline).getByText(/attached to Gi1\/0\/1/)).toBeInTheDocument();
    expect(within(baseline).getByText(/leaf101 Vlan20/)).toBeInTheDocument();
    expect(within(baseline).getByText(/peer 192\.168\.2\.35 \(AS65001\)/)).toBeInTheDocument();

    expect(within(baseline).queryByText("Next-hop routes")).not.toBeInTheDocument();

    // the tool fills no prediction, so the Predicted pane keeps its placeholder
    const predicted = screen.getByRole("region", { name: "Predicted pane" });
    expect(within(predicted).getByText("no prediction")).toBeInTheDocument();

    expect(container.textContent).not.toMatch(BANNED_WORDS);
  });
});

describe("ChangeSimPage: predict_routes result", () => {
  it("renders the predicted rows per VRF with the model errors always shown", async () => {
    mockApi({
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () =>
        answerWith(
          "predict_routes",
          FIXTURE_PREDICT_ROUTES_JSON,
          "leaf101 is predicted to hold two prefixes.",
        ),
    });
    const { container } = renderPage();
    await ask("what does leaf101 learn over BGP?");

    const predicted = screen.getByRole("region", { name: "Predicted pane" });
    expect(await within(predicted).findByText("dev:leaf101")).toBeInTheDocument();
    expect(within(predicted).getByRole("heading", { name: "vrf:leaf101:default" })).toBeInTheDocument();
    expect(within(predicted).getByText(/10\.0\.1\.0\/24 via 10\.0\.0\.2/)).toBeInTheDocument();
    expect(within(predicted).getByText(/AS path 65002 65003/)).toBeInTheDocument();
    // both rows carry it, so both rows rendered
    expect(within(predicted).getAllByText(/local pref 100/)).toHaveLength(2);

    const gap = within(predicted).getByText(/unpaired-bgp-session/);
    expect(gap).toBeInTheDocument();
    expect(gap.textContent).toMatch(/bgp:leaf101:10\.0\.0\.10/);
    expect(predicted.querySelector("details")).toBeNull();
    expect(within(predicted).getByText(/^Snapshot /)).toBeInTheDocument();

    const baseline = screen.getByRole("region", { name: "Baseline pane" });
    expect(within(baseline).getByText("no assessment")).toBeInTheDocument();

    expect(container.textContent).not.toMatch(BANNED_WORDS);
  });
});

describe("ChangeSimPage: a question that fills neither pane", () => {
  it("leaves both placeholders standing after an answer with no pane tool", async () => {
    mockApi({
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => answerWith("find_device", "[]", "No device by that name."),
    });
    renderPage();
    await ask("is there a device called leaf999?");

    expect(await screen.findByText("No device by that name.")).toBeInTheDocument();
    const baseline = screen.getByRole("region", { name: "Baseline pane" });
    const predicted = screen.getByRole("region", { name: "Predicted pane" });
    expect(within(baseline).getByText("no assessment")).toBeInTheDocument();
    expect(within(predicted).getByText("no prediction")).toBeInTheDocument();
  });
});


describe("ChangeSimPage: the context the server read", () => {
  it("fills the Baseline pane from a question the model answered with other tools", async () => {
    mockApi({
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => ({
        status: 200,
        body: {
          status: "done",
          answer: "192.168.2.35 is a server on vlan20 behind leaf101.",
          declined: false,
          // the model answered through the tools it chose, neither of which
          // fills a pane
          steps: [
            { name: "run_cypher", arguments: {}, result: "{}", is_error: false },
            { name: "trace_path", arguments: {}, result: "{}", is_error: false },
          ],
          context_entries: [
            {
              kind: "address",
              subject: "192.168.2.35",
              tool: "resolve_address",
              result: FIXTURE_RESOLVE_ADDRESS,
            },
          ],
        },
      }),
    });
    const { container } = renderPage();
    await ask("what is 192.168.2.35 and what talks to it?");

    const baseline = screen.getByRole("region", { name: "Baseline pane" });
    expect(await within(baseline).findByText("192.168.2.35")).toBeInTheDocument();
    expect(within(baseline).getByText(/host9 \(server\)/)).toBeInTheDocument();
    expect(within(baseline).getByText(/leaf101 Vlan20/)).toBeInTheDocument();

    // a prediction is computed, never read: nothing the server read fills it
    const predicted = screen.getByRole("region", { name: "Predicted pane" });
    expect(within(predicted).getByText("no prediction")).toBeInTheDocument();

    expect(container.textContent).not.toMatch(BANNED_WORDS);
  });

  it("asks for the context with every question", async () => {
    const asks: unknown[] = [];
    mockApi({
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": (req) => {
        asks.push(req.body);
        return STARTED;
      },
      "GET /api/ai/messages/m1": () => answerWith("find_device", "[]", "No device by that name."),
    });
    renderPage();
    await ask("is there a device called leaf999?");

    expect(await screen.findByText("No device by that name.")).toBeInTheDocument();
    expect(asks).toEqual([
      { question: "is there a device called leaf999?", include_context: true },
    ]);
  });

  it("falls back to the tool step when the question named no entity to read", async () => {
    mockApi({
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => ({
        status: 200,
        body: {
          status: "done",
          answer: "Reloading it would isolate one prefix and one endpoint.",
          declined: false,
          steps: [
            {
              name: "assess_impact",
              arguments: { device: "leaf101" },
              result: FIXTURE_ASSESS_IMPACT_JSON,
              is_error: false,
            },
          ],
          context_entries: [],
        },
      }),
    });
    renderPage();
    await ask("what if the one we discussed reloads?");

    const baseline = screen.getByRole("region", { name: "Baseline pane" });
    expect(await within(baseline).findByText("leaf101")).toBeInTheDocument();
    expect(within(baseline).getByText(/10\.0\.1\.0\/24/)).toBeInTheDocument();
  });
});

describe("ChangeSimPage: a result the Predicted pane cannot read", () => {
  it("names the unreadable result in a line", async () => {
    mockApi({
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () =>
        answerWith(
          "simulate_policy_change",
          // JSON that ends mid-object, which is what a result cut at the
          // response's own cap arrives as
          FIXTURE_SIMULATE_POLICY_CHANGE_JSON.slice(0, 400),
          "Blocking 192.168.2.35 would change the verdict on four of the six flows.",
        ),
    });
    const { container } = renderPage();
    await ask("what happens if I block 192.168.2.35 on core1?");

    const predicted = screen.getByRole("region", { name: "Predicted pane" });
    expect(
      await within(predicted).findByText(/simulate_policy_change result could not be read/),
    ).toBeInTheDocument();
    expect(
      within(predicted).queryByText("no prediction"),
    ).not.toBeInTheDocument();
    expect(container.textContent).not.toMatch(BANNED_WORDS);
  });

  it("draws a result it can read and says nothing about one it could not", async () => {
    mockApi({
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () =>
        answerWith(
          "simulate_policy_change",
          FIXTURE_SIMULATE_POLICY_CHANGE_JSON,
          "Blocking 192.168.2.35 changes the verdict on one flow.",
        ),
    });
    renderPage();
    await ask("what happens if I block 192.168.2.35 on core1?");

    const predicted = screen.getByRole("region", { name: "Predicted pane" });
    expect(await within(predicted).findByText("Proposed policy change")).toBeInTheDocument();
    expect(within(predicted).queryByText(/could not be read/)).not.toBeInTheDocument();
  });
});

describe("ChangeSimPage: the Predicted pane draws paths as rows", () => {
  it("draws a row per outcome with its next hops, counts and deciding rule", async () => {
    mockApi({
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () =>
        answerWith(
          "simulate_policy_change",
          FIXTURE_SIMULATE_POLICY_CHANGE_JSON,
          "Blocking 192.168.2.35 changes the verdict on one flow.",
        ),
    });
    const { container } = renderPage();
    await ask("what happens if I block 192.168.2.35 on core1?");

    const predicted = screen.getByRole("region", { name: "Predicted pane" });
    // the equal-cost pair is one row, and its two next hops are what tell the
    // two paths apart
    expect(await within(predicted).findByText("10.0.0.1, 10.0.0.2")).toBeInTheDocument();
    expect(within(predicted).getByText("LAN policy (LAN>WAN) drop by rule 10")).toBeInTheDocument();
    // a path the change does not decide says which rulebase did
    expect(
      within(predicted).getByText("decided by fw:core1:INTRA, which this change does not alter"),
    ).toBeInTheDocument();
    expect(within(predicted).getByText(/2 of 4 paths blocked/)).toBeInTheDocument();
    expect(container.textContent).not.toMatch(BANNED_WORDS);
  });
});

describe("ChangeSimPage: the page context", () => {
  it("sends the page context with include_context, and the newest result's run as the page default", async () => {
    const asks: any[] = [];
    mockApi({
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": (req) => {
        asks.push(req.body);
        return STARTED;
      },
      "GET /api/ai/messages/m1": () =>
        answerWith("assess_impact", FIXTURE_ASSESS_IMPACT_JSON, "Reloading leaf101 isolates one prefix."),
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <AiContextProvider>
            <ChangeSimPage />
          </AiContextProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await ask("what if leaf101 reloads?");
    expect(await screen.findByText("Reloading leaf101 isolates one prefix.")).toBeInTheDocument();
    await ask("and if leaf102 reloads too?");
    await waitFor(() => expect(asks).toHaveLength(2));

    expect(asks[0]).toMatchObject({ include_context: true, context: { version: 1, route: { pathname: "/" } } });
    expect(asks[0].context.snapshot).toBeUndefined();
    expect(asks[1]).toMatchObject({
      include_context: true,
      context: { version: 1, snapshot: { id: FIXTURE_ASSESS_IMPACT.snapshot, origin: "page-default" } },
    });
  });
});

describe("ChangeSimPage: the pane's conversation", () => {
  function renderStored(props: { conversationId?: string; onConversation?: (id: string | undefined) => void }) {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <ChangeSimPage {...props} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
  }

  it("restores the transcript and the panes from the stored conversation", async () => {
    const base = { context: null, error: null, created_at: null, finished_at: null };
    mockApi({
      "GET /api/ai/conversations/c1": () => ({
        status: 200,
        body: {
          id: "c1",
          surface: "changesim",
          message_count: 2,
          messages: [
            { ...base, id: "q1", seq: 1, role: "user", status: "done", content: "what if leaf101 reloads?",
              envelope: null, snapshot: null, steps: [] },
            { ...base, id: "m1", seq: 2, role: "assistant", status: "done",
              content: "Reloading leaf101 would isolate one prefix.",
              envelope: { payload: { declined: false, context_entries: [] } }, snapshot: "1724236800000",
              steps: [{ id: "st1", step: "s1", tool: "assess_impact", arguments: { device: "leaf101" },
                is_error: false, result_summary: "ok", compacted: false }] },
          ],
        },
      }),
      // the conversation read carries no step results; the message read does
      "GET /api/ai/messages/m1": () =>
        answerWith("assess_impact", FIXTURE_ASSESS_IMPACT_JSON, "Reloading leaf101 would isolate one prefix."),
    });
    renderStored({ conversationId: "c1" });

    expect(await screen.findByText("Reloading leaf101 would isolate one prefix.")).toBeInTheDocument();
    expect(screen.getByText("what if leaf101 reloads?")).toBeInTheDocument();
    const baseline = screen.getByRole("region", { name: "Baseline pane" });
    expect(within(baseline).getByText("leaf101")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "New chat" })).toBeInTheDocument();
  });

  it("New chat cancels the running turn and clears the pane's conversation", async () => {
    let polls = 0;
    let cancels = 0;
    const stored: (string | undefined)[] = [];
    mockApi({
      "POST /api/ai/conversations": (req) => {
        expect(req.body).toEqual({ surface: "changesim" });
        return CREATED;
      },
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => {
        polls += 1;
        return { status: 200, body: { status: "running", state: "running", answer: "", declined: false, steps: [] } };
      },
      "POST /api/ai/messages/m1/cancel": () => {
        cancels += 1;
        return { status: 200, body: { cancel_requested: true } };
      },
    });
    renderStored({ onConversation: (id) => stored.push(id) });

    await ask("what if leaf101 reloads?");
    await waitFor(() => expect(polls).toBeGreaterThan(0));
    await userEvent.setup().click(screen.getByRole("button", { name: "New chat" }));

    await waitFor(() => expect(cancels).toBe(1));
    expect(stored).toEqual(["c1", undefined]);
    expect(screen.queryByText("what if leaf101 reloads?")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Planned change")).not.toBeDisabled();
  });
});

describe("ChangeSimPage: the catalogue tools the agent calls", () => {
  function answerFrom(name: string, result: string, answer: string) {
    mockApi({
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => answerWith(name, result, answer),
    });
  }

  it("renders an impact_assess step in both panes", async () => {
    answerFrom("impact_assess", FIXTURE_IMPACT_ASSESS_JSON, "Reloading leaf101 would isolate one prefix.");
    const { container } = renderPage();
    await ask("what if leaf101 reloads?");

    const baseline = screen.getByRole("region", { name: "Baseline pane" });
    const predicted = screen.getByRole("region", { name: "Predicted pane" });
    expect(await within(baseline).findByText("leaf101")).toBeInTheDocument();
    expect(within(baseline).getByText(/rg1/)).toBeInTheDocument();
    expect(within(predicted).getByText("leaf101")).toBeInTheDocument();
    expect(within(predicted).getByText(/surviving members leaf102/)).toBeInTheDocument();
    expect(within(predicted).getByText(/^Snapshot /)).toBeInTheDocument();
    expect(container.textContent).not.toMatch(BANNED_WORDS);
  });

  it("renders a routing_predict_routes step in the Predicted pane with its model errors", async () => {
    answerFrom("routing_predict_routes", FIXTURE_ROUTING_PREDICT_ROUTES_JSON, "leaf101 is predicted to hold two prefixes.");
    const { container } = renderPage();
    await ask("what does leaf101 learn over BGP?");

    const predicted = screen.getByRole("region", { name: "Predicted pane" });
    expect(await within(predicted).findByText("dev:leaf101")).toBeInTheDocument();
    expect(within(predicted).getByRole("heading", { name: "vrf:leaf101:default" })).toBeInTheDocument();
    expect(within(predicted).getByText(/10\.0\.1\.0\/24 via 10\.0\.0\.2/)).toBeInTheDocument();
    expect(within(predicted).getByText(/unpaired-bgp-session/)).toBeInTheDocument();
    const baseline = screen.getByRole("region", { name: "Baseline pane" });
    expect(within(baseline).getByText("no assessment")).toBeInTheDocument();
    expect(container.textContent).not.toMatch(BANNED_WORDS);
  });

  it("renders a change_simulate step in the Predicted pane as rows and counts", async () => {
    answerFrom("change_simulate", FIXTURE_CHANGE_SIMULATE_JSON, "Blocking 192.168.2.35 changes the verdict on one flow.");
    const { container } = renderPage();
    await ask("what happens if I block 192.168.2.35 on core1?");

    const predicted = screen.getByRole("region", { name: "Predicted pane" });
    expect(await within(predicted).findByText("Proposed policy change")).toBeInTheDocument();
    expect(within(predicted).getByText("10.0.0.1, 10.0.0.2")).toBeInTheDocument();
    expect(within(predicted).getByText(/2 of 4 paths blocked/)).toBeInTheDocument();
    expect(within(predicted).queryByText(/could not be read/)).not.toBeInTheDocument();
    expect(container.textContent).not.toMatch(BANNED_WORDS);
  });

  it("names a change_simulate result it cannot read", async () => {
    answerFrom("change_simulate", FIXTURE_CHANGE_SIMULATE_JSON.slice(0, 400), "The simulation changed one verdict.");
    renderPage();
    await ask("what happens if I block 192.168.2.35 on core1?");

    const predicted = screen.getByRole("region", { name: "Predicted pane" });
    expect(await within(predicted).findByText(/change_simulate result could not be read/)).toBeInTheDocument();
  });

  it("fills the Baseline pane from an inventory_resolve context entry", async () => {
    mockApi({
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => ({
        status: 200,
        body: {
          status: "done",
          answer: "192.168.2.35 is a server on vlan20 behind leaf101.",
          declined: false,
          steps: [{ name: "query_cypher", arguments: {}, result: "{}", is_error: false }],
          context_entries: [
            {
              kind: "address",
              subject: "192.168.2.35",
              tool: "inventory_resolve",
              result: FIXTURE_INVENTORY_RESOLVE_ENVELOPE,
            },
          ],
        },
      }),
    });
    renderPage();
    await ask("what is 192.168.2.35?");

    const baseline = screen.getByRole("region", { name: "Baseline pane" });
    expect(await within(baseline).findByText("192.168.2.35")).toBeInTheDocument();
    expect(within(baseline).getByText(/host9 \(server\)/)).toBeInTheDocument();
  });
});

describe("ChangeSimPage: handoffs from a stored step", () => {
  afterEach(() => {
    window.history.replaceState({}, "", "/");
  });

  /** The focused pane's view, with the analysis session or the draft it opened. */
  function FocusedPane() {
    const workspace = useWorkspace()!;
    const pane = panes(workspace.state.root).find((item) => item.id === workspace.state.focus)!;
    return (
      <output aria-label="Focused pane">
        {pane.view}:{pane.analysisSessionId ?? pane.assessmentDraft?.title ?? ""}
      </output>
    );
  }

  function renderInWorkspace(signedIn: boolean) {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const page = (
      <WorkspaceProvider>
        <ChangeSimPage />
        <FocusedPane />
      </WorkspaceProvider>
    );
    return render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>{signedIn ? <AuthProvider>{page}</AuthProvider> : page}</MemoryRouter>
      </QueryClientProvider>,
    );
  }

  function bucket(items: string[]) {
    return { count: items.length, items, truncated: false };
  }

  const SERVICE_JSON = JSON.stringify(
    catalogueEnvelope("impact_evaluate_service", {
      mode: "possible",
      intents: [{ kind: "fw_rule.add", params: {} }],
      request: {
        name: "web",
        destination: "10.0.0.10",
        sources: bucket(["10.1.0.0/24"]),
        members: [{ name: "web", addresses: ["10.0.0.10"] }],
        condition: { kind: "member", member: "web" },
        requirement: null,
      },
      decided_change: { loss: bucket(["10.1.0.0/24"]), gain: bucket([]) },
      open_change: { loss: bucket(["10.1.0.0/24"]), gain: bucket([]) },
      open: { before: bucket([]), after: bucket([]) },
      passes: { before: bucket(["10.1.0.0/24"]), after: bucket([]) },
      triage: {
        decided_loss: bucket(["10.1.0.0/24"]), passes_then_open: bucket([]), open_then_fails: bucket([]),
        open_throughout: bucket([]), decided_gain: bucket([]), open_then_passes: bucket([]), fails_then_open: bucket([]),
      },
      members: [],
      evidence: { count: 0, items: [], truncated: false },
      missing_evidence: [],
      gaps: [],
      model_errors: [],
    }),
  );

  it("opens the assessment draft the server built from the stored service step", async () => {
    window.history.replaceState({}, "", "/");
    const reads: string[] = [];
    mockApi({
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => ({
        status: 200,
        body: {
          status: "done",
          answer: "The change costs web one client prefix.",
          declined: false,
          steps: [
            {
              id: "st1",
              step: "s1",
              name: "impact_evaluate_service",
              arguments: { form: "request", request: { name: "web" } },
              result: SERVICE_JSON,
              is_error: false,
            },
          ],
        },
      }),
      "GET /api/ai/steps/st1/assessment-draft": (req) => {
        reads.push(req.path);
        return {
          status: 200,
          body: {
            title: "web from the stored step",
            kind: "troubleshoot",
            definition: { intents: [], snapshot: "1724236800000", mode: "possible", freshness_s: 86400 },
          },
        };
      },
    });
    renderInWorkspace(false);
    await ask("what does the change do to web?");

    await userEvent.setup().click(await screen.findByRole("button", { name: "Investigate evidence" }));
    expect(screen.getByRole("status", { name: "Focused pane" })).toHaveTextContent(
      "assessments:web from the stored step",
    );
    expect(reads).toEqual(["/api/ai/steps/st1/assessment-draft"]);
  });

  it("saves a change_simulate step from the chat as a simulation for an operator", async () => {
    window.history.replaceState({}, "", "/");
    const posts: MockRequest[] = [];
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_OPERATOR }),
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => ({
        status: 200,
        body: {
          status: "done",
          answer: "Blocking 192.168.2.35 changes the verdict on one flow.",
          declined: false,
          steps: [
            {
              id: "st1",
              step: "s1",
              name: "change_simulate",
              arguments: { intents: [] },
              result: FIXTURE_CHANGE_SIMULATE_JSON,
              is_error: false,
            },
          ],
        },
      }),
      "POST /api/ai/steps/st1/analysis-session": (req) => {
        posts.push(req);
        return { status: 201, body: { id: "sess-1", revision: 1, title: "Simulation from chat step s1" } };
      },
    });
    const { container } = renderInWorkspace(true);
    await ask("what happens if I block 192.168.2.35 on core1?");

    const user = userEvent.setup();
    await user.click(await screen.findByText("1 tool call"));
    await user.click(await screen.findByRole("button", { name: "Save as simulation" }));
    expect(await screen.findByText("Saved as analysis session Simulation from chat step s1")).toBeInTheDocument();
    expect(posts.map((req) => req.body)).toEqual([undefined]);
    expect(screen.getByRole("status", { name: "Focused pane" })).toHaveTextContent("analysis:sess-1");
    // the compact card leaves the assessment draft to the service pane
    expect(screen.queryByRole("button", { name: "Investigate evidence" })).not.toBeInTheDocument();
    expect(container.textContent).not.toMatch(BANNED_WORDS);
  });
});

describe("ChangeSimPage: Open in drawer", () => {
  afterEach(() => {
    try {
      window.localStorage.removeItem(CONVERSATION_KEY);
    } catch {
      // this origin keeps no storage
    }
  });

  /** Whether the drawer is open and on which conversation. */
  function DrawerState() {
    const drawer = useAiDrawer();
    return <output aria-label="HST AI drawer">{drawer?.open ? `open on ${drawer.conversationId ?? "none"}` : "closed"}</output>;
  }

  it("opens the pane's conversation in the HST AI drawer from a change simulation card", async () => {
    const base = { context: null, error: null, created_at: null, finished_at: null };
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/health": () => ({ status: 200, body: { path: true, neo4j: true, postgres: true, agent: true } }),
      "GET /api/ai/conversations/c-sim": () => ({
        status: 200,
        body: {
          id: "c-sim",
          surface: "changesim",
          message_count: 2,
          messages: [
            { ...base, id: "q1", seq: 1, role: "user", status: "done", content: "what happens if I block 192.168.2.35 on core1?",
              envelope: null, snapshot: null, steps: [] },
            { ...base, id: "m1", seq: 2, role: "assistant", status: "done",
              content: "Blocking 192.168.2.35 changes the verdict on one flow.",
              envelope: { payload: { declined: false, context_entries: [] } }, snapshot: "1724236800000",
              steps: [{ id: "st1", step: "s1", tool: "change_simulate", arguments: {}, is_error: false,
                result_summary: "ok", compacted: false }] },
          ],
        },
      }),
      "GET /api/ai/messages/m1": () =>
        answerWith("change_simulate", FIXTURE_CHANGE_SIMULATE_JSON, "Blocking 192.168.2.35 changes the verdict on one flow."),
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <AuthProvider>
            <AiDrawerProvider>
              <ChangeSimPage conversationId="c-sim" />
              <DrawerState />
            </AiDrawerProvider>
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const user = userEvent.setup();

    await user.click(await screen.findByText("1 tool call"));
    await user.click(await screen.findByRole("button", { name: "Open in drawer" }));

    expect(screen.getByRole("status", { name: "HST AI drawer" })).toHaveTextContent("open on c-sim");
  });
});
