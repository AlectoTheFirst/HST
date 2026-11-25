/** The hook follows one HST AI conversation held on the server (src/hst/app/routes/ai_conversations.py). */

import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import type {
  AgentContextEntry,
  AgentStep,
  AiConversation,
  AnswerEnvelope,
  ChatMessage,
  ConversationMessage,
  ConversationSurface,
  PageContext,
  TurnPoll,
  TurnStarted,
  TurnStep,
} from "../api/types";

/** How often a running turn polls for its result. */
export const ASK_POLL_MS = 1500;

/** The bound of 330 seconds exceeds the server turn deadline of 300 seconds. */
export const ASK_MAX_ATTEMPTS = 220;

/** The message states of a turn in progress (TURN_ACTIVE_STATES). */
const ACTIVE_STATES: ReadonlySet<string> = new Set(["pending", "running"]);

const UNREACHABLE = "Agent not reachable";

export interface ConversationTurn extends ChatMessage {
  steps?: AgentStep[];
  /** What the server read about the entities the question named, for a
   *  question sent with `include_context` (src/hst/app/agent/context.py). */
  context?: AgentContextEntry[];
  declined?: boolean;
  /** A turn that ended without an answer, or a poll that timed out. */
  failed?: boolean;
  /** The answer envelope: the claims of the answer and the steps they cite.
   *  Absent for an answer stored without one. */
  envelope?: AnswerEnvelope;
}

export interface ConversationOptions {
  surface: ConversationSurface;
  /** The conversation to show. Absent until the first question creates one. */
  conversationId?: string;
  /** Receives the id of a conversation the hook created, and undefined after
   *  a reset or when the stored conversation no longer exists. */
  onConversation?: (id: string | undefined) => void;
  /** Ask the server for the entity context beside every answer. */
  includeContext?: boolean;
}

export interface ConversationChat {
  turns: ConversationTurn[];
  /** The steps of the running turn recorded so far. */
  runningSteps: AgentStep[];
  send: (question: string, context?: PageContext) => void;
  reset: () => void;
  isPending: boolean;
  /** The transcript of `conversationId` has not loaded yet. */
  isLoading: boolean;
  /** A failure to show beside the transcript. A poll timeout appends its own
   *  turn and sets no error. */
  error: string | null;
}

/** Unwinds the poll of a turn a reset discarded or whose hook unmounted. */
class DiscardedTurn extends Error {}

/** The event stream of a turn closed for good before the turn ended. */
class StreamUnavailable extends Error {}

/** A turn that outlived ASK_MAX_ATTEMPTS polls. */
class TurnTimeoutError extends ApiError {
  constructor() {
    super(504, "Agent timeout");
  }
}

function messagePath(id: string): string {
  return `/ai/messages/${encodeURIComponent(id)}`;
}

function answerTurn(poll: TurnPoll): ConversationTurn {
  if (poll.status === "done") {
    return {
      role: "assistant",
      content: poll.answer,
      steps: poll.steps,
      declined: poll.declined,
      context: poll.context_entries,
      ...(poll.envelope ? { envelope: poll.envelope } : {}),
    };
  }
  return {
    role: "assistant",
    content: poll.detail ?? `the turn ended as ${poll.state}`,
    steps: poll.steps,
    failed: true,
  };
}

/** An answer with no steps, from the conversation read alone. */
function storedAnswer(message: ConversationMessage): ConversationTurn {
  const payload = message.envelope?.payload ?? undefined;
  // the stored row holds the poll fields beside the answer envelope
  const version = message.envelope?.version;
  const envelope = version === 2 ? (message.envelope as AnswerEnvelope) : undefined;
  return {
    role: "assistant",
    content: message.content,
    steps: [],
    declined: payload?.declined ?? false,
    context: payload?.context_entries,
    ...(envelope ? { envelope } : {}),
  };
}

/** The transcript of a stored conversation, and the assistant message of a
 *  turn still in progress. The conversation read carries no step results, so
 *  every finished turn with steps, and every turn that ended without an
 *  answer, is read through its message. */
async function loadTranscript(id: string): Promise<{ turns: ConversationTurn[]; running?: string }> {
  const conversation = await api<AiConversation>(`/ai/conversations/${encodeURIComponent(id)}`);
  const messages = conversation.messages ?? [];
  const polls = await Promise.all(
    messages.map((message) =>
      message.role === "assistant" &&
      !ACTIVE_STATES.has(message.status) &&
      (message.status !== "done" || message.steps.length > 0)
        ? api<TurnPoll>(messagePath(message.id))
        : Promise.resolve(null),
    ),
  );
  const turns: ConversationTurn[] = [];
  let running: string | undefined;
  messages.forEach((message, i) => {
    if (message.role === "user") {
      turns.push({ role: "user", content: message.content });
    } else if (ACTIVE_STATES.has(message.status)) {
      running = message.id;
    } else {
      const poll = polls[i];
      turns.push(poll ? answerTurn(poll) : storedAnswer(message));
    }
  });
  return { turns, running };
}

/** Poll a turn until it ends, at most `attempts` times. `current` turns false
 *  once the turn is discarded; `onRunning` receives the steps of every poll
 *  that finds the turn still running. */
async function pollTurn(
  messageId: string,
  attempts: number,
  current: () => boolean,
  onRunning: (steps: AgentStep[]) => void,
): Promise<TurnPoll> {
  for (let attempt = 0; ; attempt++) {
    if (!current()) throw new DiscardedTurn();
    if (attempt >= attempts) throw new TurnTimeoutError();
    const poll = await api<TurnPoll>(messagePath(messageId));
    if (!current()) throw new DiscardedTurn();
    if (poll.status !== "running") return poll;
    onRunning(poll.steps ?? []);
    await new Promise((r) => setTimeout(r, ASK_POLL_MS));
  }
}

/** Follow a turn through its event stream until it ends. Each `step` event
 *  adds one step, and the `turn` event carries the poll answer. After a
 *  dropped connection the browser reconnects with the id of the last event,
 *  and the server sends only the steps after it. Rejects with
 *  StreamUnavailable when the stream closes for good, and with
 *  TurnTimeoutError at `deadline`. */
function streamTurn(
  messageId: string,
  deadline: number,
  current: () => boolean,
  onRunning: (steps: AgentStep[]) => void,
): Promise<TurnPoll> {
  return new Promise((resolve, reject) => {
    const source = new EventSource(`/api${messagePath(messageId)}/events`);
    const steps: TurnStep[] = [];
    let settled = false;
    const settle = (done: () => void) => {
      if (settled) return;
      settled = true;
      window.clearInterval(watch);
      source.close();
      done();
    };
    const watch = window.setInterval(() => {
      if (!current()) settle(() => reject(new DiscardedTurn()));
      else if (Date.now() >= deadline) settle(() => reject(new TurnTimeoutError()));
    }, ASK_POLL_MS);
    function read<T>(event: Event): T | undefined {
      if (!current()) {
        settle(() => reject(new DiscardedTurn()));
        return undefined;
      }
      try {
        return JSON.parse((event as MessageEvent<string>).data) as T;
      } catch {
        settle(() => reject(new StreamUnavailable()));
        return undefined;
      }
    }
    source.addEventListener("step", (event) => {
      const step = read<TurnStep>(event);
      if (step === undefined || settled) return;
      steps.push(step);
      onRunning([...steps]);
    });
    source.addEventListener("turn", (event) => {
      const poll = read<TurnPoll>(event);
      if (poll !== undefined) settle(() => resolve(poll));
    });
    source.onerror = () => {
      // a dropped connection reconnects on its own; a closed one does not
      if (source.readyState === EventSource.CLOSED) settle(() => reject(new StreamUnavailable()));
    };
  });
}

/** Follow a turn through its event stream, or poll it when the browser has
 *  no EventSource or the stream closes before the turn ends. The stream and
 *  the poll share one bound of ASK_MAX_ATTEMPTS * ASK_POLL_MS: a poll after a
 *  closed stream gets the attempts the stream left, and at least one. */
async function followTurn(
  messageId: string,
  current: () => boolean,
  onRunning: (steps: AgentStep[]) => void,
): Promise<TurnPoll> {
  let attempts = ASK_MAX_ATTEMPTS;
  if (typeof EventSource !== "undefined") {
    const deadline = Date.now() + ASK_MAX_ATTEMPTS * ASK_POLL_MS;
    try {
      return await streamTurn(messageId, deadline, current, onRunning);
    } catch (err) {
      if (!(err instanceof StreamUnavailable)) throw err;
    }
    attempts = Math.max(1, Math.ceil((deadline - Date.now()) / ASK_POLL_MS));
  }
  return pollTurn(messageId, attempts, current, onRunning);
}

function requestCancel(messageId: string): void {
  api(`${messagePath(messageId)}/cancel`, { method: "POST" }).catch(() => undefined);
}

export function useConversation({
  surface,
  conversationId,
  onConversation,
  includeContext = false,
}: ConversationOptions): ConversationChat {
  const [turns, setTurns] = useState<ConversationTurn[]>([]);
  const [runningSteps, setRunningSteps] = useState<AgentStep[]>([]);
  const [isPending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // the conversation whose transcript is settled: loaded, found missing, or
  // created here. `conversationId` differs from it while a load runs.
  const [settledId, setSettledId] = useState<string | undefined>(undefined);
  const isLoading = conversationId !== undefined && conversationId !== settledId;

  // the conversation the next question goes to; it is ahead of the
  // `conversationId` prop between a create and the caller storing the id
  const idRef = useRef<string | undefined>(undefined);
  // the assistant message of the running turn, for the cancel request
  const runningRef = useRef<string | undefined>(undefined);
  const pendingRef = useRef(false);
  const generationRef = useRef(0);
  const unmountedRef = useRef(false);
  useEffect(() => {
    unmountedRef.current = false;
    return () => {
      unmountedRef.current = true;
    };
  }, []);

  /** Follow the turn of `messageId` and append its answer. */
  const follow = useCallback(async (messageId: string, generation: number) => {
    const current = () => !unmountedRef.current && generationRef.current === generation;
    try {
      const poll = await followTurn(messageId, current, setRunningSteps);
      setTurns((prev) => [...prev, answerTurn(poll)]);
    } catch (err) {
      if (err instanceof DiscardedTurn || !current()) return;
      if (err instanceof TurnTimeoutError) {
        setTurns((prev) => [...prev, { role: "assistant", content: err.message, failed: true }]);
      } else {
        setError(err instanceof ApiError ? err.message : UNREACHABLE);
      }
    } finally {
      if (current()) {
        runningRef.current = undefined;
        pendingRef.current = false;
        setPending(false);
        setRunningSteps([]);
      }
    }
  }, []);

  useEffect(() => {
    if (conversationId === idRef.current) return;
    idRef.current = conversationId;
    generationRef.current += 1;
    runningRef.current = undefined;
    pendingRef.current = false;
    if (conversationId === undefined) {
      setTurns([]);
      setRunningSteps([]);
      setPending(false);
      setError(null);
      setSettledId(undefined);
      return;
    }
    const generation = generationRef.current;
    const current = () => !unmountedRef.current && generationRef.current === generation;
    void loadTranscript(conversationId).then(
      ({ turns: loaded, running }) => {
        if (!current()) return;
        setTurns(loaded);
        setError(null);
        setRunningSteps([]);
        setSettledId(conversationId);
        pendingRef.current = running !== undefined;
        runningRef.current = running;
        setPending(running !== undefined);
        if (running !== undefined) void follow(running, generation);
      },
      (err: unknown) => {
        if (!current()) return;
        setTurns([]);
        setRunningSteps([]);
        setPending(false);
        setSettledId(conversationId);
        if (err instanceof ApiError && err.status === 404) {
          // deleted or purged: the next question starts a new conversation
          idRef.current = undefined;
          setError(null);
          onConversation?.(undefined);
        } else {
          setError(err instanceof ApiError ? err.message : UNREACHABLE);
        }
      },
    );
  }, [conversationId, onConversation, follow]);

  const send = useCallback(
    (question: string, context?: PageContext) => {
      const trimmed = question.trim();
      if (!trimmed || pendingRef.current || isLoading) return;
      const generation = generationRef.current;
      const wasReset = () => generationRef.current !== generation;
      const current = () => !unmountedRef.current && !wasReset();
      pendingRef.current = true;
      setPending(true);
      setError(null);
      setRunningSteps([]);
      setTurns((prev) => [...prev, { role: "user", content: trimmed }]);

      const start = async (): Promise<string> => {
        let id = idRef.current;
        // a conversation created after an unmount, reported once its question is posted
        let unreported: string | undefined;
        if (id === undefined) {
          const created = await api<AiConversation>("/ai/conversations", {
            method: "POST",
            body: context ? { surface, context } : { surface },
          });
          if (wasReset()) throw new DiscardedTurn();
          id = created.id;
          idRef.current = id;
          if (unmountedRef.current) {
            unreported = id;
          } else {
            setSettledId(id);
            onConversation?.(id);
          }
        }
        const { message_id } = await api<TurnStarted>(
          `/ai/conversations/${encodeURIComponent(id)}/messages`,
          {
            method: "POST",
            body: {
              question: trimmed,
              ...(includeContext ? { include_context: true } : {}),
              ...(context ? { context } : {}),
            },
          },
        );
        if (wasReset()) {
          // a reset came while the turn was starting
          requestCancel(message_id);
          throw new DiscardedTurn();
        }
        if (unmountedRef.current) {
          // the turn runs on; the surface that shows the conversation next
          // loads it and follows the running turn
          if (unreported !== undefined) onConversation?.(unreported);
          throw new DiscardedTurn();
        }
        runningRef.current = message_id;
        return message_id;
      };

      void start().then(
        (messageId) => follow(messageId, generation),
        (err: unknown) => {
          if (err instanceof DiscardedTurn || !current()) return;
          pendingRef.current = false;
          setPending(false);
          setError(err instanceof ApiError ? err.message : UNREACHABLE);
        },
      );
    },
    [surface, includeContext, onConversation, isLoading, follow],
  );

  const reset = useCallback(() => {
    if (runningRef.current !== undefined) requestCancel(runningRef.current);
    generationRef.current += 1;
    runningRef.current = undefined;
    pendingRef.current = false;
    idRef.current = undefined;
    setTurns([]);
    setRunningSteps([]);
    setPending(false);
    setError(null);
    setSettledId(undefined);
    onConversation?.(undefined);
  }, [onConversation]);

  return {
    turns: isLoading ? [] : turns,
    runningSteps,
    send,
    reset,
    isPending,
    isLoading,
    error,
  };
}
