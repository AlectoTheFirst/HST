/**
 * The HST AI button exists only when the agent can answer.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { TopBar } from "./TopBar";
import { AuthProvider } from "../auth";
import { api } from "../api/client";
import { mockApi, type MockHandler, type MockRequest } from "../test/fetchMock";
import { FIXTURE_CHANGE_SIMULATE_JSON, ME_OPERATOR, ME_VIEWER, catalogueEnvelope } from "../test/fixtures";
import { ASK_MAX_ATTEMPTS, ASK_POLL_MS } from "./AgentDrawer";
import { AiContextProvider, useAiContext } from "../ai/context";
import type { AnswerClaim, AnswerEnvelope, ConversationLink, Me, PageContext } from "../api/types";
import { WorkspaceProvider, useWorkspace } from "../workspace/WorkspaceContext";
import { panes } from "../workspace/layout";
import { AiDrawerProvider } from "../ai/drawer";

function renderBar() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <AuthProvider>
          <AiDrawerProvider><TopBar /></AiDrawerProvider>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function mockBase(agent: boolean, extra: Record<string, unknown> = {}) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
    "GET /api/health": () => ({
      status: 200,
      body: { path: true, neo4j: true, postgres: true, agent },
    }),
    ...extra,
  });
}

// The first question creates the conversation; a question starts a turn whose
// answer comes from polling the assistant message.
const CREATED = { status: 201, body: { id: "c1", surface: "drawer", message_count: 0 } };
const STARTED = { status: 202, body: { message_id: "m1" } };

const DONE = (text: string) => ({
  status: 200,
  body: { status: "done", answer: text, declined: false, steps: [] },
});

describe("HST AI", () => {
  it("offers no button while the agent cannot answer", async () => {
    mockBase(false);
    renderBar();
    expect(await screen.findByRole("status", { name: "connected" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "HST AI" })).not.toBeInTheDocument();
  });

  it("opens from the top bar and answers in the transcript", async () => {
    mockBase(true, {
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => DONE("Yes, via wg0."),
    });
    const user = userEvent.setup();
    renderBar();

    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });

    await user.type(within(drawer).getByLabelText("Ask HST AI"), "can A reach B?");
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));

    expect(await within(drawer).findByText("Yes, via wg0.")).toBeInTheDocument();
    expect(within(within(drawer).getByRole("region", { name: "Chat" })).getByText("can A reach B?")).toBeInTheDocument();
  });

  it("asks the follow-up in the same conversation and sends no history", async () => {
    const bodies: unknown[] = [];
    let created = 0;
    let n = 0;
    mockBase(true, {
      "POST /api/ai/conversations": (req: MockRequest) => {
        created += 1;
        expect(req.body).toEqual({ surface: "drawer" });
        return CREATED;
      },
      "POST /api/ai/conversations/c1/messages": (req: MockRequest) => {
        bodies.push(req.body);
        n += 1;
        return STARTED;
      },
      "GET /api/ai/messages/m1": () => DONE(n === 1 ? "Yes, via wg0." : "Over udp too."),
    });
    const user = userEvent.setup();
    renderBar();

    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    const input = within(drawer).getByLabelText("Ask HST AI");

    await user.type(input, "can A reach B?");
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));
    await within(drawer).findByText("Yes, via wg0.");

    await user.type(input, "and over udp?");
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));
    await within(drawer).findByText("Over udp too.");

    // the server builds the history window from the stored conversation
    expect(created).toBe(1);
    expect(bodies).toEqual([{ question: "can A reach B?" }, { question: "and over udp?" }]);
  });

  it("keeps the transcript across close and reopen; New chat discards it", async () => {
    mockBase(true, {
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => DONE("Yes, via wg0."),
    });
    const user = userEvent.setup();
    renderBar();

    const toggle = await screen.findByRole("button", { name: "HST AI" });
    await user.click(toggle);
    const drawer = screen.getByRole("complementary", { name: "HST AI", hidden: true });

    await user.type(within(drawer).getByLabelText("Ask HST AI"), "can A reach B?");
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));
    await within(drawer).findByText("Yes, via wg0.");

    await user.keyboard("{Escape}");
    expect(drawer).toHaveAttribute("aria-hidden", "true");
    await user.click(toggle);
    expect(drawer).toHaveAttribute("aria-hidden", "false");
    expect(within(drawer).getByText("Yes, via wg0.")).toBeInTheDocument();

    await user.click(within(drawer).getByRole("button", { name: "New chat" }));
    expect(within(drawer).queryByText("Yes, via wg0.")).not.toBeInTheDocument();
  });

  it("shows the tool calls behind an answer on demand", async () => {
    mockBase(true, {
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => ({
        status: 200,
        body: {
          status: "done",
          answer: "Yes.",
          declined: false,
          steps: [
            {
              name: "trace_path",
              arguments: { src: "10.0.0.1", dst: "8.8.8.8" },
              result: "PERMITTED via wg0",
              is_error: false,
            },
          ],
        },
      }),
    });
    const user = userEvent.setup();
    renderBar();

    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    await user.type(within(drawer).getByLabelText("Ask HST AI"), "reachable?");
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));

    await user.click(await within(drawer).findByText("1 tool call"));
    expect(within(drawer).getByText("trace_path")).toBeInTheDocument();
    expect(within(drawer).getByText(/PERMITTED via wg0/)).toBeInTheDocument();
  });

  it("holds the input while a question is in flight", async () => {
    let release: (v: { status: number; body: unknown }) => void;
    mockBase(true, {
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () =>
        new Promise<{ status: number; body: unknown }>((resolve) => {
          release = resolve;
        }),
    });
    const user = userEvent.setup();
    renderBar();

    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    const input = within(drawer).getByLabelText("Ask HST AI");
    await user.type(input, "slow one");
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));

    expect(input).toBeDisabled();
    release!(DONE("done"));
    expect(await within(drawer).findByText("done")).toBeInTheDocument();
    expect(input).not.toBeDisabled();
  });

  it("surfaces a job that failed server-side as the error it reported", async () => {
    mockBase(true, {
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => ({
        status: 200,
        body: { status: "error", detail: "provider unreachable" },
      }),
    });
    const user = userEvent.setup();
    renderBar();

    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    await user.type(within(drawer).getByLabelText("Ask HST AI"), "hello?");
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));

    expect(await within(drawer).findByText("provider unreachable")).toBeInTheDocument();
  });

  it("surfaces the server's own error and keeps the question in view", async () => {
    mockBase(true, {
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => ({
        status: 503,
        body: { error: "the agent is turned off" },
      }),
    });
    const user = userEvent.setup();
    renderBar();

    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    await user.type(within(drawer).getByLabelText("Ask HST AI"), "hello?");
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));

    expect(await within(drawer).findByText("the agent is turned off")).toBeInTheDocument();
    // the user's turn is not lost to the failure
    expect(within(within(drawer).getByRole("region", { name: "Chat" })).getByText("hello?")).toBeInTheDocument();
  });

  it("resizes by the left-edge handle down to a minimum width", async () => {
    mockBase(true, {});
    const user = userEvent.setup();
    renderBar();

    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    const handle = within(drawer).getByRole("separator", { name: "Resize HST AI" });

    fireEvent.pointerDown(handle, { button: 0, clientX: 600, pointerId: 1 });
    fireEvent.pointerMove(handle, { clientX: 300, pointerId: 1 });
    fireEvent.pointerUp(handle, { pointerId: 1 });
    // jsdom's window.innerWidth is 1024.
    expect(drawer.style.width).toBe("724px");

    fireEvent.pointerDown(handle, { button: 0, clientX: 700, pointerId: 2 });
    fireEvent.pointerMove(handle, { clientX: 1020, pointerId: 2 });
    fireEvent.pointerUp(handle, { pointerId: 2 });
    expect(drawer.style.width).toBe("380px");
  });
});

async function flush(stepMs = 50, rounds = 10) {
  for (let i = 0; i < rounds; i++) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(stepMs);
    });
  }
}

describe("HST AI: New chat discards the in-flight ask", () => {
  it("drops an answer that resolves after New chat, and does not repoll the old job", async () => {
    let pollCalls = 0;
    let cancels = 0;
    let release: (v: { status: number; body: unknown }) => void;
    mockBase(true, {
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "POST /api/ai/messages/m1/cancel": () => {
        cancels += 1;
        return { status: 200, body: { cancel_requested: true } };
      },
      "GET /api/ai/messages/m1": () => {
        pollCalls += 1;
        return new Promise<{ status: number; body: unknown }>((resolve) => {
          release = resolve;
        });
      },
    });
    const user = userEvent.setup();
    renderBar();

    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    await user.type(within(drawer).getByLabelText("Ask HST AI"), "can A reach B?");
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));
    expect(pollCalls).toBe(1);

    // discard the ask before its poll resolves
    await user.click(within(drawer).getByRole("button", { name: "New chat" }));
    expect(within(drawer).queryByText("can A reach B?")).not.toBeInTheDocument();

    // the stale request now settles with what would have been the answer
    await act(async () => {
      release!(DONE("Yes, via wg0."));
      // let the resolved poll's promise chain (onSuccess) run
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(within(drawer).queryByText("Yes, via wg0.")).not.toBeInTheDocument();
    // the discarded job is never polled again
    expect(pollCalls).toBe(1);
    // and the server is asked to stop the turn
    expect(cancels).toBe(1);
  });

  it("stops polling a discarded job even when it never resolves at all", async () => {
    let pollCalls = 0;
    vi.useFakeTimers();
    mockBase(true, {
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => {
        pollCalls += 1;
        return { status: 200, body: { status: "running" } };
      },
    });
    renderBar();

    await flush(); // resolve the health check that gates the toggle button
    fireEvent.click(screen.getByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    fireEvent.change(within(drawer).getByLabelText("Ask HST AI"), {
      target: { value: "still there?" },
    });
    fireEvent.click(within(drawer).getByRole("button", { name: /Send/ }));

    await flush(); // the POST resolves and the first poll goes out
    expect(pollCalls).toBe(1);

    fireEvent.click(within(drawer).getByRole("button", { name: "New chat" }));

    await flush(ASK_POLL_MS, 5);
    expect(pollCalls).toBe(1);

    vi.useRealTimers();
  });
});

/** A page outside the workspace that publishes a device and the run it shows. */
function DevicePage() {
  useAiContext(null, {
    snapshot: { id: "1724236800000", origin: "pinned" },
    selection: [
      { kind: "device", uid: "dev:leaf101", inventory_id: "inv-1", label: "leaf101", source: "url" },
    ],
  });
  return null;
}

describe("HST AI: page context", () => {
  it("shows the page context as removable chips and leaves a removed chip out of the ask", async () => {
    const bodies: any[] = [];
    const created: any[] = [];
    mockBase(true, {
      "POST /api/ai/conversations": (req: MockRequest) => {
        created.push(req.body);
        return CREATED;
      },
      "POST /api/ai/conversations/c1/messages": (req: MockRequest) => {
        bodies.push(req.body);
        return STARTED;
      },
      "GET /api/ai/messages/m1": () => DONE("It is a leaf."),
    });
    const user = userEvent.setup();
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/"]}>
          <AuthProvider>
            <AiContextProvider>
              <AiDrawerProvider><TopBar /></AiDrawerProvider>
              <DevicePage />
            </AiContextProvider>
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    const chips = within(drawer).getByRole("group", { name: "Context" });
    expect(await within(chips).findByRole("button", { name: /^Remove Snapshot / })).toBeInTheDocument();

    await user.click(within(chips).getByRole("button", { name: "Remove Device leaf101" }));
    expect(within(chips).queryByRole("button", { name: "Remove Device leaf101" })).not.toBeInTheDocument();

    await user.type(within(drawer).getByLabelText("Ask HST AI"), "what is this device?");
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));
    await within(drawer).findByText("It is a leaf.");

    const context = { version: 1, route: { pathname: "/" }, snapshot: { id: "1724236800000", origin: "pinned" } };
    expect(created).toEqual([{ surface: "drawer", context }]);
    expect(bodies).toEqual([{ question: "what is this device?", context }]);
  });
});

/** A page in one pane that registers a device named after the pane. */
function PaneDevice({ paneId }: { paneId: string }) {
  useAiContext(paneId, { selection: [{ kind: "device", uid: `dev:${paneId}` }] });
  return null;
}

/** One registering page per pane, and a control that splits the focused pane. */
function PaneDevices() {
  const workspace = useWorkspace()!;
  const ids = panes(workspace.state.root).map((pane) => pane.id);
  return (
    <>
      {ids.map((id) => (
        <PaneDevice key={id} paneId={id} />
      ))}
      <output aria-label="Pane count">{ids.length}</output>
      <button type="button" onClick={() => workspace.dispatch({ type: "split", id: workspace.state.focus, dir: "row" })}>
        Split
      </button>
    </>
  );
}

describe("HST AI: page context in a split workspace", () => {
  afterEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("sends only the focused pane's registrations", async () => {
    // the workspace restores from the URL
    window.history.replaceState({}, "", "/");
    const created: PageContext[] = [];
    const asked: PageContext[] = [];
    mockBase(true, {
      "POST /api/ai/conversations": (req: MockRequest) => {
        created.push((req.body as { context: PageContext }).context);
        return CREATED;
      },
      "POST /api/ai/conversations/c1/messages": (req: MockRequest) => {
        asked.push((req.body as { context: PageContext }).context);
        return STARTED;
      },
      "GET /api/ai/messages/m1": () => DONE("It is a leaf."),
    });
    const user = userEvent.setup();
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/"]}>
          <AuthProvider>
            <WorkspaceProvider>
              <AiContextProvider>
                <AiDrawerProvider><TopBar /></AiDrawerProvider>
                <PaneDevices />
              </AiContextProvider>
            </WorkspaceProvider>
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await user.click(await screen.findByRole("button", { name: "Split" }));
    expect(screen.getByRole("status", { name: "Pane count" })).toHaveTextContent("2");
    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    await user.type(within(drawer).getByLabelText("Ask HST AI"), "what is this device?");
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));
    await within(drawer).findByText("It is a leaf.");

    expect(created).toHaveLength(1);
    const focused = created[0].route.pane_id;
    expect(focused).toEqual(expect.any(String));
    expect(created[0].selection).toEqual([{ kind: "device", uid: `dev:${focused}` }]);
    expect(asked).toEqual([created[0]]);
  });
});

describe("HST AI: bounded polling", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("gives up after ASK_MAX_ATTEMPTS polls and appends a timeout turn", async () => {
    let pollCalls = 0;
    vi.useFakeTimers();
    mockBase(true, {
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => {
        pollCalls += 1;
        return { status: 200, body: { status: "running" } };
      },
    });
    renderBar();

    await flush();
    fireEvent.click(screen.getByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    fireEvent.change(within(drawer).getByLabelText("Ask HST AI"), {
      target: { value: "still there?" },
    });
    fireEvent.click(within(drawer).getByRole("button", { name: /Send/ }));

    await flush(ASK_POLL_MS, ASK_MAX_ATTEMPTS + 5);

    expect(within(drawer).getByText("Agent timeout")).toBeInTheDocument();
    // the loop stopped at the bound rather than continuing forever
    expect(pollCalls).toBeLessThanOrEqual(ASK_MAX_ATTEMPTS);
    expect(within(drawer).getByLabelText("Ask HST AI")).not.toBeDisabled();
  });
});

function installStorage(): Map<string, string> {
  const data = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: {
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
      removeItem: (k: string) => void data.delete(k),
      clear: () => data.clear(),
    },
  });
  return data;
}

/** One message of GET /api/ai/conversations/{id}. */
function message(id: string, role: "user" | "assistant", content: string, status = "done") {
  return {
    id, seq: 0, role, status, content, context: null, envelope: null, error: null,
    snapshot: null, created_at: null, finished_at: null, steps: [],
  };
}

describe("HST AI: the server-held conversation", () => {
  const original = Object.getOwnPropertyDescriptor(window, "localStorage");
  afterEach(() => {
    // the other tests run on an origin without storage
    if (original) Object.defineProperty(window, "localStorage", original);
    else Reflect.deleteProperty(window, "localStorage");
  });

  it("restores the transcript after a reload", async () => {
    const storage = installStorage();
    mockBase(true, {
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => DONE("Yes, via wg0."),
      "GET /api/ai/conversations/c1": () => ({
        status: 200,
        body: {
          id: "c1",
          surface: "drawer",
          message_count: 2,
          messages: [message("q1", "user", "can A reach B?"), message("m1", "assistant", "Yes, via wg0.")],
        },
      }),
    });
    const user = userEvent.setup();
    const first = renderBar();
    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    let drawer = screen.getByRole("complementary", { name: "HST AI" });
    await user.type(within(drawer).getByLabelText("Ask HST AI"), "can A reach B?");
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));
    await within(drawer).findByText("Yes, via wg0.");
    expect(storage.get("hst.agent.conversation")).toBe(JSON.stringify("c1"));
    first.unmount();

    renderBar();
    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    drawer = screen.getByRole("complementary", { name: "HST AI" });
    expect(await within(drawer).findByText("Yes, via wg0.")).toBeInTheDocument();
    expect(within(within(drawer).getByRole("region", { name: "Chat" })).getByText("can A reach B?")).toBeInTheDocument();

    // New chat forgets the stored conversation
    await user.click(within(drawer).getByRole("button", { name: "New chat" }));
    expect(storage.get("hst.agent.conversation")).toBe("null");
  });

  it("shows the steps of a running turn, and New chat cancels the turn", async () => {
    let cancels = 0;
    mockBase(true, {
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => ({
        status: 200,
        body: {
          status: "running",
          state: "running",
          answer: "",
          declined: false,
          steps: [
            { id: "st1", step: "s1", name: "trace_path", arguments: {}, result: "PERMITTED via wg0", is_error: false },
          ],
        },
      }),
      "POST /api/ai/messages/m1/cancel": () => {
        cancels += 1;
        return { status: 200, body: { cancel_requested: true } };
      },
    });
    const user = userEvent.setup();
    renderBar();

    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    await user.type(within(drawer).getByLabelText("Ask HST AI"), "can A reach B?");
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));

    // the step arrives while the turn runs
    expect(await within(drawer).findByText("trace_path")).toBeInTheDocument();
    expect(within(drawer).getByText("Working")).toBeInTheDocument();

    await user.click(within(drawer).getByRole("button", { name: "New chat" }));
    await waitFor(() => expect(cancels).toBe(1));
    expect(within(drawer).queryByText("trace_path")).not.toBeInTheDocument();
    expect(within(drawer).queryByText("can A reach B?")).not.toBeInTheDocument();
    expect(within(drawer).getByLabelText("Ask HST AI")).not.toBeDisabled();
  });
});

/** The answer envelope of `answer` (src/hst/app/ai/envelope.py): `claims`
 *  with the spans the server computes, and a step link per cited step. */
function answerEnvelope(
  answer: string,
  claims: AnswerClaim[],
  links: Record<string, string>,
  othersUsed: string[] = [],
): AnswerEnvelope {
  return {
    version: 2,
    message_id: "m1",
    conversation_id: "c1",
    kind: "answer",
    snapshot: { id: "1759", origin: "pointer", others_used: othersUsed },
    model: { provider: "anthropic", requested: "claude-opus-5" },
    prompt_hash: "h",
    tools_used: [],
    answer_markdown: answer,
    claims,
    grounding: { status: "partially-grounded", cited: 1, uncited: 1, invalid: 0, cross_snapshot: 0 },
    links: Object.entries(links).map(([step, id]) => ({ kind: "step", ref_id: id, step })),
  };
}

const TRACE_STEP = {
  id: "st1",
  step: "s1",
  name: "reach_trace",
  arguments: { mode: "path" },
  result: '{"result": {"verdict": "deny"}}',
  is_error: false,
};

async function askWith(body: Record<string, unknown>) {
  mockBase(true, {
    "POST /api/ai/conversations": () => CREATED,
    "POST /api/ai/conversations/c1/messages": () => STARTED,
    "GET /api/ai/messages/m1": () => ({ status: 200, body: { status: "done", declined: false, ...body } }),
  });
  const user = userEvent.setup();
  renderBar();
  await user.click(await screen.findByRole("button", { name: "HST AI" }));
  const drawer = screen.getByRole("complementary", { name: "HST AI" });
  await user.type(within(drawer).getByLabelText("Ask HST AI"), "is it denied?");
  await user.click(within(drawer).getByRole("button", { name: /Send/ }));
  return { user, drawer };
}

describe("HST AI: citations", () => {
  it("renders the markers as chips that open the evidence of the step, and counts an uncited statement", async () => {
    const answer = "Rule 10 on fw1 denies the flow [s1]. The graph holds two rulebases.";
    const { user, drawer } = await askWith({
      answer,
      steps: [TRACE_STEP],
      envelope: answerEnvelope(
        answer,
        [
          { id: "c1", span: [0, 36], citations: ["s1"], citation_status: "cited", evidence_status: null },
          { id: "c2", span: [37, 67], citations: [], citation_status: "uncited", evidence_status: null },
        ],
        { s1: "st1" },
      ),
    });

    const chip = await within(drawer).findByRole("button", { name: "Show evidence of s1" });
    expect(within(drawer).queryByText(/\[s1\]/)).not.toBeInTheDocument();
    // no marker after the statement; one line under the answer counts it
    expect(within(drawer).queryByText("uncited")).not.toBeInTheDocument();
    expect(within(drawer).getByText("1 statement without tool source")).toBeInTheDocument();

    await user.click(chip);
    const evidence = within(drawer).getByRole("region", { name: "Evidence of s1" });
    expect(within(evidence).getByText("Path trace")).toBeInTheDocument();
    // the step's result, readable, and its raw form behind Details
    expect(within(evidence).getByText("verdict")).toBeInTheDocument();
    const details = within(evidence).getByText("Details").closest("details");
    expect(details).not.toHaveAttribute("open");

    // Details moves to the step in the tool call list
    const step = drawer.querySelector("#ai-step-st1");
    expect(step?.closest("details")).not.toHaveAttribute("open");
    await user.click(within(evidence).getByText("Details"));
    await user.click(within(evidence).getByRole("button", { name: "Show in tool calls" }));
    expect(step?.closest("details")).toHaveAttribute("open");
    expect(step).toHaveFocus();

    // the chip closes the evidence again
    await user.click(chip);
    expect(within(drawer).queryByRole("region", { name: "Evidence of s1" })).not.toBeInTheDocument();
  });

  it("gives a matched statement a chip whose evidence highlights the row that holds it", async () => {
    const answer = "What the rule says\n\nLAN-WAN rule 10 on core1 is a drop rule.";
    const query =
      "MATCH (rb:Rulebase {name: 'LAN-WAN'})-[r:HAS_RULE]->(rule:Rule) " +
      "WHERE coalesce(rb.collection_ts, $snap) = $snap RETURN rb.uid, rb.name, type(r), rule.uid, rule.position, rule.action";
    const rows = {
      id: "st2",
      step: "s2",
      name: "query_cypher",
      arguments: { query },
      result: JSON.stringify({
        snapshot: { id: "1759" },
        provenance: { tool: "query_cypher" },
        result: {
          columns: ["rb.uid", "rb.name", "type(r)", "rule.uid", "rule.position", "rule.action"],
          data: [
            { row: ["vyos:core1:fw:LAN-WAN", "LAN-WAN", "HAS_RULE", "vyos:core1:fw:LAN-WAN:10", 10, "drop"] },
            { row: ["vyos:core1:fw:LAN-WAN", "LAN-WAN", "HAS_RULE", "vyos:core1:fw:LAN-WAN:20", 20, "accept"] },
          ],
          truncated: false,
        },
      }),
      is_error: false,
    };
    const envelope = {
      ...answerEnvelope(
        answer,
        [
          {
            id: "c1",
            span: [20, 60],
            citations: [],
            citation_status: "matched",
            evidence_status: null,
            support: [{ step: "s2", pointer: "/result/data/0" }],
          },
        ],
        { s2: "st2" },
      ),
      version: 2 as const,
      tools_used: [
        { step: "s2", step_id: "st2", tool: "query_cypher", version: 1, is_error: false, snapshot: "1759" },
      ],
    };
    const { user, drawer } = await askWith({ answer, steps: [rows], envelope });

    const chip = await within(drawer).findByRole("button", { name: "Show evidence of s2" });
    expect(chip.previousSibling?.textContent).toMatch(/drop rule\.$/);
    expect(within(drawer).queryByText(/no tool source/)).not.toBeInTheDocument();

    await user.click(chip);
    const evidence = within(drawer).getByRole("region", { name: "Evidence of s2" });
    expect(
      within(evidence).getByText(
        "Graph query on Rulebase, Rule records for LAN-WAN, returning rb.uid, rb.name, type(r), rule.uid, " +
          "rule.position, rule.action at run 1759",
      ),
    ).toBeInTheDocument();
    expect(within(evidence).getByText("Matched step")).toBeInTheDocument();
    // only the supporting row, highlighted, by its column names
    const records = evidence.querySelectorAll(".evidence-record");
    expect(records).toHaveLength(1);
    expect(records[0]).toHaveClass("supporting");
    expect(within(records[0] as HTMLElement).getByText("rule.action").nextSibling?.textContent).toBe("drop");
    expect(within(evidence).queryByText("accept")).not.toBeInTheDocument();
    // the query sits behind the collapsed Details
    const details = within(evidence).getByText("Details").closest("details");
    expect(details).not.toHaveAttribute("open");
    expect(within(details as HTMLElement).getByText(query)).toBeInTheDocument();
  });

  it("lists the unsupported statements under the answer and highlights them when opened", async () => {
    const answer = "fw1 denies it [s1]. The graph holds two rulebases. I traced one flow.";
    const { user, drawer } = await askWith({
      answer,
      steps: [TRACE_STEP],
      envelope: answerEnvelope(
        answer,
        [
          { id: "c1", span: [0, 19], citations: ["s1"], citation_status: "cited", evidence_status: null },
          { id: "c2", span: [20, 50], citations: [], citation_status: "uncited", evidence_status: null },
          { id: "c3", span: [51, 69], citations: [], citation_status: "process", evidence_status: null },
        ],
        { s1: "st1" },
      ),
    });

    const summary = await within(drawer).findByText("1 statement without tool source");
    expect(drawer.querySelector("mark")).toBeNull();
    await user.click(summary);
    const list = summary.closest("details") as HTMLElement;
    expect(within(list).getByRole("listitem")).toHaveTextContent("The graph holds two rulebases.");
    // the statement is highlighted in the answer; the process statement is not
    const marks = Array.from(drawer.querySelectorAll("mark.citation-highlight"), (mark) => mark.textContent).join("");
    expect(marks).toBe("The graph holds two rulebases.");
  });

  it("says so when the answer used more than one run, and marks a marker that names no step", async () => {
    const answer = "fw1 denies it [s1]. The route exists [s7].";
    const { drawer } = await askWith({
      answer,
      steps: [TRACE_STEP],
      envelope: answerEnvelope(
        answer,
        [
          { id: "c1", span: [0, 19], citations: ["s1"], citation_status: "cited", evidence_status: "deny" },
          { id: "c2", span: [20, 42], citations: ["s7"], citation_status: "citation-invalid" },
        ],
        { s1: "st1" },
        ["1760"],
      ),
    });

    expect(await within(drawer).findByText("Runs: 1759, 1760")).toBeInTheDocument();
    expect(within(drawer).getByText("s7")).toHaveClass("citation-chip", "invalid");
    expect(within(drawer).queryByRole("button", { name: "Show evidence of s7" })).not.toBeInTheDocument();
    expect(within(drawer).queryByText("uncited")).not.toBeInTheDocument();
  });

  it("renders a marker that no statement carries as a neutral chip", async () => {
    const answer = "# Trace [s1]\n\nThe graph holds two rulebases.";
    const { drawer } = await askWith({
      answer,
      steps: [TRACE_STEP],
      envelope: answerEnvelope(
        answer,
        [{ id: "c1", span: [14, 44], citations: [], citation_status: "uncited", evidence_status: null }],
        {},
      ),
    });

    // a heading is no statement, so its marker is neither cited nor invalid
    const chip = await within(drawer).findByText("s1", { selector: ".citation-chip" });
    expect(chip).toHaveClass("neutral");
    expect(chip).not.toHaveClass("invalid");
    expect(within(drawer).getByText("1 statement without tool source")).toBeInTheDocument();
  });

  it("shows the markers of an answer without an envelope as the text they are", async () => {
    const { drawer } = await askWith({ answer: "fw1 denies it [s1].", steps: [TRACE_STEP] });

    expect(await within(drawer).findByText("fw1 denies it [s1].")).toBeInTheDocument();
    expect(within(drawer).queryByRole("button", { name: "Show evidence of s1" })).not.toBeInTheDocument();
  });

  it("counts the uncited statements of a stored answer after a reload", async () => {
    const original = Object.getOwnPropertyDescriptor(window, "localStorage");
    const storage = installStorage();
    storage.set("hst.agent.conversation", JSON.stringify("c1"));
    const answer = "fw1 denies the flow.";
    const stored = {
      ...message("m1", "assistant", answer),
      envelope: {
        ...answerEnvelope(answer, [{ id: "c1", span: [0, 20], citations: [], citation_status: "uncited" }], {}),
        payload: { declined: false, context_entries: [] },
      },
    };
    try {
      mockBase(true, {
        "GET /api/ai/conversations/c1": () => ({
          status: 200,
          body: {
            id: "c1",
            surface: "drawer",
            message_count: 2,
            messages: [message("q1", "user", "is it denied?"), stored],
          },
        }),
      });
      const user = userEvent.setup();
      renderBar();
      await user.click(await screen.findByRole("button", { name: "HST AI" }));
      const drawer = screen.getByRole("complementary", { name: "HST AI" });

      expect(await within(drawer).findByText("1 statement without tool source")).toBeInTheDocument();
      expect(within(drawer).queryByText("uncited")).not.toBeInTheDocument();
      expect(within(within(drawer).getByRole("region", { name: "Chat" })).getByText("is it denied?")).toBeInTheDocument();
    } finally {
      if (original) Object.defineProperty(window, "localStorage", original);
      else Reflect.deleteProperty(window, "localStorage");
    }
  });
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

function renderInWorkspace() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <AuthProvider>
          <WorkspaceProvider>
            <AiDrawerProvider><TopBar /></AiDrawerProvider>
            <FocusedPane />
          </WorkspaceProvider>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const SIMULATE_STEP = {
  id: "st1",
  step: "s1",
  name: "change_simulate",
  arguments: { intents: [{ kind: "fw_rule.add", params: { rulebase: "fw:core1:LAN" } }] },
  result: FIXTURE_CHANGE_SIMULATE_JSON,
  is_error: false,
};

// A service evaluation as impact_evaluate_service returns it.
const SERVICE_STEP = {
  id: "st2",
  step: "s2",
  name: "impact_evaluate_service",
  arguments: { form: "requirement", requirement: "req:web" },
  result: JSON.stringify(
    catalogueEnvelope("impact_evaluate_service", {
      mode: "possible",
      request: {
        name: "web",
        destination: "10.0.0.10",
        sources: { count: 1, items: ["10.1.0.0/24"], truncated: false },
        members: [{ name: "web", addresses: ["10.0.0.10"] }],
        condition: { kind: "member", member: "web" },
        requirement: "req:web",
      },
      decided_change: {
        loss: { count: 1, items: ["10.1.0.0/24"], truncated: false },
        gain: { count: 0, items: [], truncated: false },
      },
      open_change: {
        loss: { count: 1, items: ["10.1.0.0/24"], truncated: false },
        gain: { count: 0, items: [], truncated: false },
      },
      open: {
        before: { count: 0, items: [], truncated: false },
        after: { count: 0, items: [], truncated: false },
      },
      passes: {
        before: { count: 1, items: ["10.1.0.0/24"], truncated: false },
        after: { count: 0, items: [], truncated: false },
      },
      members: [],
      evidence: { count: 0, items: [], truncated: false },
      missing_evidence: [],
      gaps: [],
      model_errors: [],
    }),
  ),
  is_error: false,
};

/** Ask once as `me` in a workspace; the answer carries `steps`, and the step
 *  list is opened in the evidence pane. `extra` adds routes. */
async function askForCards(me: Me, steps: unknown[], extra: Record<string, MockHandler> = {}) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: me }),
    "GET /api/health": () => ({ status: 200, body: { path: true, neo4j: true, postgres: true, agent: true } }),
    "POST /api/ai/conversations": () => CREATED,
    "POST /api/ai/conversations/c1/messages": () => STARTED,
    "GET /api/ai/messages/m1": () => ({
      status: 200,
      body: { status: "done", declined: false, answer: "Blocking it changes one verdict.", steps },
    }),
    ...extra,
  });
  const user = userEvent.setup();
  renderInWorkspace();
  await user.click(await screen.findByRole("button", { name: "HST AI" }));
  const drawer = screen.getByRole("complementary", { name: "HST AI" });
  await user.type(within(drawer).getByLabelText("Ask HST AI"), "what if I block it?");
  await user.click(within(drawer).getByRole("button", { name: /Send/ }));
  await user.click(
    await within(drawer).findByRole("button", { name: `${steps.length} step${steps.length === 1 ? "" : "s"}` }),
  );
  return { user, drawer };
}

function card(drawer: HTMLElement, stepId: string): HTMLElement {
  const element = drawer.querySelector<HTMLElement>(`#ai-step-${stepId}`);
  if (!element) throw new Error(`no card for step ${stepId}`);
  return element;
}

describe("HST AI: result cards", () => {
  afterEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("renders a change simulation as a card, and an operator saves it as an analysis session", async () => {
    window.history.replaceState({}, "", "/");
    const posts: MockRequest[] = [];
    const { user, drawer } = await askForCards(ME_OPERATOR, [SIMULATE_STEP], {
      "POST /api/ai/steps/st1/analysis-session": (req) => {
        posts.push(req);
        return { status: 201, body: { id: "sess-1", revision: 1, title: "Simulation from chat step s1" } };
      },
    });

    const simulation = card(drawer, "st1");
    expect(within(simulation).getByText("s1", { selector: ".agentpanel-steplabel" })).toBeInTheDocument();
    expect(within(simulation).getByText(/2 of 4 paths blocked after the change/)).toBeInTheDocument();

    await user.click(within(simulation).getByRole("button", { name: "Save as simulation" }));
    expect(
      await within(simulation).findByText("Saved as analysis session Simulation from chat step s1"),
    ).toBeInTheDocument();
    // the request names the step and carries no copy of its arguments or result
    expect(posts).toHaveLength(1);
    expect(posts[0].body).toBeUndefined();
    await waitFor(() =>
      expect(screen.getByRole("status", { name: "Focused pane" })).toHaveTextContent("analysis:sess-1"),
    );
    expect(window.location.search).toBe("?analysis=sess-1");
    expect(within(simulation).queryByRole("button", { name: "Save as simulation" })).not.toBeInTheDocument();
    expect(within(simulation).getByRole("button", { name: "Open analysis session" })).toBeInTheDocument();
  });

  it("offers a viewer no Save as simulation", async () => {
    const { drawer } = await askForCards(ME_VIEWER, [SIMULATE_STEP]);

    const simulation = card(drawer, "st1");
    expect(within(simulation).getByText(/2 of 4 paths blocked after the change/)).toBeInTheDocument();
    expect(within(simulation).queryByRole("button", { name: "Save as simulation" })).not.toBeInTheDocument();
  });

  it("says why the server refused to save the simulation", async () => {
    const { user, drawer } = await askForCards(ME_OPERATOR, [SIMULATE_STEP], {
      "POST /api/ai/steps/st1/analysis-session": () => ({
        status: 422,
        body: { error: "A published snapshot with an evidence manifest is required." },
      }),
    });

    const simulation = card(drawer, "st1");
    await user.click(within(simulation).getByRole("button", { name: "Save as simulation" }));
    expect(await within(simulation).findByRole("alert")).toHaveTextContent(
      "A published snapshot with an evidence manifest is required.",
    );
    expect(within(simulation).getByRole("button", { name: "Save as simulation" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Focused pane" })).not.toHaveTextContent("analysis");
  });

  it("opens the assessment draft the server built for a service evaluation", async () => {
    const reads: string[] = [];
    const { user, drawer } = await askForCards(ME_VIEWER, [SIMULATE_STEP, SERVICE_STEP], {
      "GET /api/ai/steps/st2/assessment-draft": (req) => {
        reads.push(req.path);
        return {
          status: 200,
          body: {
            title: "web from the stored step",
            kind: "troubleshoot",
            definition: {
              intents: [],
              snapshot: "1724236800000",
              mode: "possible",
              freshness_s: 86400,
              requirement: "req:web",
            },
          },
        };
      },
    });

    const service = card(drawer, "st2");
    expect(within(service).getByText(/fails after the change 1/)).toBeInTheDocument();
    expect(
      within(card(drawer, "st1")).queryByRole("button", { name: "Investigate evidence" }),
    ).not.toBeInTheDocument();
    await user.click(within(service).getByRole("button", { name: "Investigate evidence" }));

    await waitFor(() =>
      expect(screen.getByRole("status", { name: "Focused pane" })).toHaveTextContent(
        "assessments:web from the stored step",
      ),
    );
    expect(reads).toEqual(["/api/ai/steps/st2/assessment-draft"]);
  });

  it("offers the analysis session that the conversation's links name for the step", async () => {
    const posts: MockRequest[] = [];
    const links: ConversationLink[] = [
      { kind: "analysis_session", ref_id: "sess-1", ref_revision: 1, direction: "to", message_id: "m1", step_id: "st1", created_at: null },
    ];
    const { user, drawer } = await askForCards(ME_OPERATOR, [SIMULATE_STEP], {
      "GET /api/ai/conversations/c1": () => ({
        status: 200,
        body: { id: "c1", surface: "drawer", message_count: 2, messages: [], links },
      }),
      "POST /api/ai/steps/st1/analysis-session": (req) => {
        posts.push(req);
        return { status: 201, body: { id: "sess-2", revision: 1, title: "Simulation from chat step s1" } };
      },
    });

    const simulation = card(drawer, "st1");
    await user.click(await within(simulation).findByRole("button", { name: "Open analysis session" }));
    expect(within(simulation).queryByRole("button", { name: "Save as simulation" })).not.toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByRole("status", { name: "Focused pane" })).toHaveTextContent("analysis:sess-1"),
    );
    expect(posts).toEqual([]);
  });

  it("reads the saved analysis sessions again after a save", async () => {
    let reads = 0;
    function SavedSessions() {
      const sessions = useQuery({
        queryKey: ["analysis-sessions"],
        queryFn: () => api<{ sessions: unknown[] }>("/analysis-sessions"),
      });
      return <output aria-label="Saved sessions">{sessions.data?.sessions.length ?? 0}</output>;
    }
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_OPERATOR }),
      "GET /api/health": () => ({ status: 200, body: { path: true, neo4j: true, postgres: true, agent: true } }),
      "GET /api/analysis-sessions": () => {
        reads += 1;
        return { status: 200, body: { sessions: [] } };
      },
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => ({
        status: 200,
        body: { status: "done", declined: false, answer: "Blocking it changes one verdict.", steps: [SIMULATE_STEP] },
      }),
      "POST /api/ai/steps/st1/analysis-session": () => ({
        status: 201,
        body: { id: "sess-1", revision: 1, title: "Simulation from chat step s1" },
      }),
    });
    const user = userEvent.setup();
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/"]}>
          <AuthProvider>
            <WorkspaceProvider>
              <AiDrawerProvider><TopBar /></AiDrawerProvider>
              <SavedSessions />
            </WorkspaceProvider>
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await waitFor(() => expect(reads).toBe(1));

    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    await user.type(within(drawer).getByLabelText("Ask HST AI"), "what if I block it?");
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));
    await user.click(await within(drawer).findByRole("button", { name: "1 step" }));
    await user.click(within(card(drawer, "st1")).getByRole("button", { name: "Save as simulation" }));

    await waitFor(() => expect(reads).toBe(2));
  });
});

/** The path of the current route. */
function RouteProbe() {
  const { pathname } = useLocation();
  return <output aria-label="Route">{pathname}</output>;
}

describe("HST AI: link chips on another route", () => {
  afterEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("goes to the workspace before it opens the linked object in the focused pane", async () => {
    window.history.replaceState({}, "", "/");
    const answer = "The saved session holds the change.";
    const envelope: AnswerEnvelope = {
      ...answerEnvelope(answer, [], {}),
      links: [{ kind: "analysis_session", ref_id: "sess-1", ref_revision: 1, step: "s1" }],
    };
    mockBase(true, {
      "POST /api/ai/conversations": () => CREATED,
      "POST /api/ai/conversations/c1/messages": () => STARTED,
      "GET /api/ai/messages/m1": () => ({
        status: 200,
        body: { status: "done", declined: false, answer, steps: [], envelope },
      }),
    });
    const user = userEvent.setup();
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/settings"]}>
          <AuthProvider>
            <WorkspaceProvider>
              <AiDrawerProvider><TopBar /></AiDrawerProvider>
              <FocusedPane />
              <RouteProbe />
            </WorkspaceProvider>
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    await user.type(within(drawer).getByLabelText("Ask HST AI"), "which session holds it?");
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));
    expect(screen.getByRole("status", { name: "Route" })).toHaveTextContent(/^\/settings$/);
    await user.click(await within(drawer).findByRole("button", { name: "Analysis session sess-1 revision 1" }));

    await waitFor(() => expect(screen.getByRole("status", { name: "Route" })).toHaveTextContent(/^\/$/));
    await waitFor(() =>
      expect(screen.getByRole("status", { name: "Focused pane" })).toHaveTextContent("analysis:sess-1"),
    );
  });
});

describe("AgentDrawer prompt", () => {
  it("labels the question field and names no reachability", async () => {
    mockBase(true);
    const user = userEvent.setup();
    renderBar();
    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    expect(within(drawer).getByLabelText("Ask HST AI")).toHaveAttribute(
      "placeholder",
      "Question",
    );
    expect(drawer.textContent?.toLowerCase()).not.toContain("reachab");
  });
});
