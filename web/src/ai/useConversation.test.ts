/**
 * The conversation hook against the routes of
 * src/hst/app/routes/ai_conversations.py: the first question creates the
 * conversation, a stored conversation loads with its step results, a running
 * turn shows its steps, and a reset cancels the running turn. jsdom has no
 * EventSource, so the hook polls unless a test installs FakeEventSource.
 */

import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";
import { mockApi } from "../test/fetchMock";
import type { PageContext } from "../api/types";
import { ASK_MAX_ATTEMPTS, ASK_POLL_MS, useConversation } from "./useConversation";

const STEP = { id: "st1", step: "s1", name: "assess_impact", arguments: { device: "leaf101" }, result: "{}", is_error: false };
const STEP2 = { ...STEP, id: "st2", step: "s2", name: "trace_path" };
const ENTRY = { kind: "device", subject: "dev:leaf101", tool: "assess_impact", result: {} };

function poll(status: "running" | "done" | "error", extra: Record<string, unknown> = {}) {
  return {
    status: 200,
    body: {
      status,
      state: status === "done" ? "done" : status === "running" ? "running" : "error",
      message_id: "m1",
      conversation_id: "c1",
      answer: "",
      declined: false,
      steps: [],
      context: null,
      snapshot: null,
      context_entries: [],
      page_context: null,
      prompt_hash: null,
      ...extra,
    },
  };
}

function message(id: string, role: "user" | "assistant", content: string, status = "done", steps: unknown[] = []) {
  return {
    id, seq: 0, role, status, content, context: null, envelope: null, error: null,
    snapshot: null, created_at: null, finished_at: null, steps,
  };
}

describe("useConversation", () => {
  it("creates the conversation on the first question and asks in it", async () => {
    const created: unknown[] = [];
    const asked: unknown[] = [];
    mockApi({
      "POST /api/ai/conversations": (req) => {
        created.push(req.body);
        return { status: 201, body: { id: "c1" } };
      },
      "POST /api/ai/conversations/c1/messages": (req) => {
        asked.push(req.body);
        return { status: 202, body: { message_id: "m1" } };
      },
      "GET /api/ai/messages/m1": () =>
        poll("done", { answer: "It isolates one prefix.", steps: [STEP], context_entries: [ENTRY] }),
    });
    const onConversation = vi.fn();
    const { result } = renderHook(() =>
      useConversation({ surface: "changesim", includeContext: true, onConversation }),
    );
    const context: PageContext = { version: 1, route: { pathname: "/" } };

    act(() => result.current.send("what if leaf101 reloads?", context));
    await waitFor(() => expect(result.current.turns).toHaveLength(2));

    expect(created).toEqual([{ surface: "changesim", context }]);
    expect(asked).toEqual([{ question: "what if leaf101 reloads?", include_context: true, context }]);
    expect(onConversation).toHaveBeenCalledWith("c1");
    expect(result.current.turns[1]).toMatchObject({
      role: "assistant",
      content: "It isolates one prefix.",
      steps: [STEP],
      context: [ENTRY],
    });
    expect(result.current.isPending).toBe(false);
  });

  it("keeps the stored envelope of an answer without steps in version 2, and no other", async () => {
    const stored = (version: number) => ({
      version,
      claims: [],
      payload: { declined: false },
    });
    mockApi({
      "GET /api/ai/conversations/c1": () => ({
        status: 200,
        body: {
          id: "c1",
          messages: [1, 2, 3].map((version) => ({
            ...message(`m${version}`, "assistant", `answer ${version}`),
            envelope: stored(version),
          })),
        },
      }),
    });
    const { result } = renderHook(() => useConversation({ surface: "drawer", conversationId: "c1" }));

    await waitFor(() => expect(result.current.turns).toHaveLength(3));
    expect(result.current.turns.map((turn) => turn.envelope?.version)).toEqual([undefined, 2, undefined]);
  });

  it("loads a stored conversation with its step results and follows a running turn", async () => {
    const meta = { id: "st1", step: "s1", tool: "assess_impact", arguments: {}, is_error: false, result_summary: "ok", compacted: false };
    mockApi({
      "GET /api/ai/conversations/c1": () => ({
        status: 200,
        body: {
          id: "c1",
          messages: [
            message("q1", "user", "what if leaf101 reloads?"),
            message("m1", "assistant", "It isolates one prefix.", "done", [meta]),
            message("q2", "user", "and leaf102?"),
            message("m2", "assistant", "", "running"),
          ],
        },
      }),
      "GET /api/ai/messages/m1": () => poll("done", { answer: "It isolates one prefix.", steps: [STEP] }),
      "GET /api/ai/messages/m2": () => poll("done", { answer: "Nothing changes.", message_id: "m2" }),
    });
    const { result } = renderHook(() => useConversation({ surface: "drawer", conversationId: "c1" }));
    expect(result.current.isLoading).toBe(true);

    await waitFor(() => expect(result.current.turns).toHaveLength(4));
    expect(result.current.turns.map((t) => t.content)).toEqual([
      "what if leaf101 reloads?",
      "It isolates one prefix.",
      "and leaf102?",
      "Nothing changes.",
    ]);
    // the conversation read has no step results; the message read supplied them
    expect(result.current.turns[1].steps).toEqual([STEP]);
    expect(result.current.isLoading).toBe(false);
    await waitFor(() => expect(result.current.isPending).toBe(false));
  });

  it("shows the steps of a running turn, and reset cancels it", async () => {
    let cancels = 0;
    mockApi({
      "POST /api/ai/conversations": () => ({ status: 201, body: { id: "c1" } }),
      "POST /api/ai/conversations/c1/messages": () => ({ status: 202, body: { message_id: "m1" } }),
      "GET /api/ai/messages/m1": () => poll("running", { steps: [STEP] }),
      "POST /api/ai/messages/m1/cancel": () => {
        cancels += 1;
        return { status: 200, body: { cancel_requested: true } };
      },
    });
    const onConversation = vi.fn();
    const { result } = renderHook(() => useConversation({ surface: "drawer", onConversation }));

    act(() => result.current.send("can A reach B?"));
    await waitFor(() => expect(result.current.runningSteps).toEqual([STEP]));
    expect(result.current.isPending).toBe(true);

    act(() => result.current.reset());
    await waitFor(() => expect(cancels).toBe(1));
    expect(result.current.turns).toEqual([]);
    expect(result.current.runningSteps).toEqual([]);
    expect(result.current.isPending).toBe(false);
    expect(onConversation).toHaveBeenLastCalledWith(undefined);
  });

  it("appends a turn that ended without an answer with its detail", async () => {
    mockApi({
      "POST /api/ai/conversations": () => ({ status: 201, body: { id: "c1" } }),
      "POST /api/ai/conversations/c1/messages": () => ({ status: 202, body: { message_id: "m1" } }),
      "GET /api/ai/messages/m1": () => poll("error", { detail: "provider unreachable" }),
    });
    const { result } = renderHook(() => useConversation({ surface: "drawer" }));

    act(() => result.current.send("hello?"));
    await waitFor(() => expect(result.current.turns).toHaveLength(2));
    expect(result.current.turns[1]).toMatchObject({ content: "provider unreachable", failed: true });
    expect(result.current.error).toBeNull();
  });

  it("posts a question sent before an unmount and reports the conversation it created", async () => {
    let releaseCreate: () => void = () => undefined;
    const createHeld = new Promise<void>((resolve) => {
      releaseCreate = resolve;
    });
    const asked: unknown[] = [];
    let cancels = 0;
    mockApi({
      "POST /api/ai/conversations": async () => {
        await createHeld;
        return { status: 201, body: { id: "c1" } };
      },
      "POST /api/ai/conversations/c1/messages": (req) => {
        asked.push(req.body);
        return { status: 202, body: { message_id: "m1" } };
      },
      "POST /api/ai/messages/m1/cancel": () => {
        cancels += 1;
        return { status: 200, body: { cancel_requested: true } };
      },
    });
    const onConversation = vi.fn();
    const { result, unmount } = renderHook(() => useConversation({ surface: "changesim", onConversation }));

    act(() => result.current.send("what if leaf101 reloads?"));
    // the pane switches its view while the create request is in flight
    unmount();
    releaseCreate();

    await waitFor(() => expect(onConversation).toHaveBeenCalledWith("c1"));
    expect(asked).toEqual([{ question: "what if leaf101 reloads?" }]);
    expect(cancels).toBe(0);
  });

  it("cancels a turn that a reset discards while its question is posted", async () => {
    let releaseAsk: () => void = () => undefined;
    const askHeld = new Promise<void>((resolve) => {
      releaseAsk = resolve;
    });
    let cancels = 0;
    mockApi({
      "POST /api/ai/conversations": () => ({ status: 201, body: { id: "c1" } }),
      "POST /api/ai/conversations/c1/messages": async () => {
        await askHeld;
        return { status: 202, body: { message_id: "m1" } };
      },
      "POST /api/ai/messages/m1/cancel": () => {
        cancels += 1;
        return { status: 200, body: { cancel_requested: true } };
      },
    });
    const onConversation = vi.fn();
    const { result } = renderHook(() => useConversation({ surface: "drawer", onConversation }));

    act(() => result.current.send("can A reach B?"));
    await waitFor(() => expect(onConversation).toHaveBeenCalledWith("c1"));
    act(() => result.current.reset());
    releaseAsk();

    await waitFor(() => expect(cancels).toBe(1));
    expect(result.current.turns).toEqual([]);
    expect(onConversation).toHaveBeenLastCalledWith(undefined);
  });

  it("clears the transcript and the running turn when the conversation id is removed", async () => {
    mockApi({
      "GET /api/ai/conversations/c1": () => ({
        status: 200,
        body: {
          id: "c1",
          messages: [message("q1", "user", "what if leaf101 reloads?"), message("m1", "assistant", "", "running")],
        },
      }),
      "GET /api/ai/messages/m1": () => poll("running"),
    });
    const { result, rerender } = renderHook(
      ({ id }: { id: string | undefined }) => useConversation({ surface: "changesim", conversationId: id }),
      { initialProps: { id: "c1" as string | undefined } },
    );
    await waitFor(() => expect(result.current.turns).toHaveLength(1));
    expect(result.current.isPending).toBe(true);

    rerender({ id: undefined });

    await waitFor(() => expect(result.current.turns).toEqual([]));
    expect(result.current.isPending).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it("forgets a stored conversation that no longer exists", async () => {
    mockApi({
      "GET /api/ai/conversations/gone": () => ({ status: 404, body: { error: "no such conversation" } }),
    });
    const onConversation = vi.fn();
    const { result } = renderHook(() =>
      useConversation({ surface: "drawer", conversationId: "gone", onConversation }),
    );

    await waitFor(() => expect(onConversation).toHaveBeenCalledWith(undefined));
    expect(result.current.turns).toEqual([]);
    expect(result.current.error).toBeNull();
    expect(result.current.isLoading).toBe(false);
  });
});

/** An EventSource the test drives: `emit` sends a named event, and `fail`
 *  reports an error with the state the browser would leave the source in. */
class FakeEventSource extends EventTarget {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSED = 2;
  static instances: FakeEventSource[] = [];
  readyState: number = FakeEventSource.CONNECTING;
  onerror: ((event: Event) => void) | null = null;

  constructor(readonly url: string) {
    super();
    FakeEventSource.instances.push(this);
  }

  close(): void {
    this.readyState = FakeEventSource.CLOSED;
  }

  emit(type: string, data: unknown): void {
    this.readyState = FakeEventSource.OPEN;
    this.dispatchEvent(new MessageEvent(type, { data: JSON.stringify(data) }));
  }

  fail(readyState: number): void {
    this.readyState = readyState;
    this.onerror?.(new Event("error"));
  }
}

describe("useConversation with an event stream", () => {
  beforeEach(() => {
    FakeEventSource.instances = [];
    vi.stubGlobal("EventSource", FakeEventSource);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /** Starts a turn in a new conversation and returns its event source and a
   *  counter of the polls the hook made. */
  async function startTurn(answer: () => ReturnType<typeof poll> = () => poll("running")) {
    const polls = { count: 0 };
    mockApi({
      "POST /api/ai/conversations": () => ({ status: 201, body: { id: "c1" } }),
      "POST /api/ai/conversations/c1/messages": () => ({ status: 202, body: { message_id: "m1" } }),
      "GET /api/ai/messages/m1": () => {
        polls.count += 1;
        return answer();
      },
    });
    const hook = renderHook(() => useConversation({ surface: "drawer" }));
    act(() => hook.result.current.send("can A reach B?"));
    await waitFor(() => expect(FakeEventSource.instances).toHaveLength(1));
    const source = FakeEventSource.instances[0];
    expect(source.url).toBe("/api/ai/messages/m1/events");
    return { result: hook.result, source, polls };
  }

  it("shows each step as its event arrives and ends the turn on the turn event", async () => {
    const { result, source, polls } = await startTurn();

    act(() => source.emit("step", STEP));
    expect(result.current.runningSteps).toEqual([STEP]);
    expect(result.current.isPending).toBe(true);

    act(() => source.emit("turn", poll("done", { answer: "Yes.", steps: [STEP] }).body));
    await waitFor(() => expect(result.current.turns).toHaveLength(2));
    expect(result.current.turns[1]).toMatchObject({ role: "assistant", content: "Yes.", steps: [STEP] });
    expect(result.current.isPending).toBe(false);
    expect(result.current.runningSteps).toEqual([]);
    expect(source.readyState).toBe(FakeEventSource.CLOSED);
    expect(polls.count).toBe(0);
  });

  it("keeps the steps received before a reconnect and adds the ones after it", async () => {
    const { result, source, polls } = await startTurn();

    act(() => source.emit("step", STEP));
    // the browser reconnects with the id of the last event; the server sends
    // only the steps after it
    act(() => source.fail(FakeEventSource.CONNECTING));
    act(() => source.emit("step", STEP2));
    expect(result.current.runningSteps).toEqual([STEP, STEP2]);

    act(() => source.emit("turn", poll("done", { answer: "Yes.", steps: [STEP, STEP2] }).body));
    await waitFor(() => expect(result.current.turns).toHaveLength(2));
    expect(result.current.turns[1].steps).toEqual([STEP, STEP2]);
    expect(polls.count).toBe(0);
  });

  it("gives the poll after a closed stream only the time the stream left", async () => {
    let now = 1_000_000;
    const clock = vi.spyOn(Date, "now").mockImplementation(() => now);
    try {
      const { result, source, polls } = await startTurn(() => poll("running"));

      // the stream used all but one poll interval of the shared bound
      now += (ASK_MAX_ATTEMPTS - 1) * ASK_POLL_MS;
      act(() => source.fail(FakeEventSource.CLOSED));

      await waitFor(() => expect(result.current.turns).toHaveLength(2));
      expect(result.current.turns[1]).toMatchObject({ content: "Agent timeout", failed: true });
      expect(polls.count).toBe(1);
    } finally {
      clock.mockRestore();
    }
  });

  it("polls the turn when the stream closes before the turn ends", async () => {
    const { result, source, polls } = await startTurn(() =>
      poll("done", { answer: "Polled.", steps: [STEP] }),
    );

    act(() => source.fail(FakeEventSource.CLOSED));
    await waitFor(() => expect(result.current.turns).toHaveLength(2));
    expect(result.current.turns[1]).toMatchObject({ content: "Polled.", steps: [STEP] });
    expect(polls.count).toBe(1);
    expect(result.current.error).toBeNull();
  });
});
