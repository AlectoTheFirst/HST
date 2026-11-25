export const EVENTS_URL = "/api/hst/events";

export interface EventStream {
  /** 2 (`EventSource.CLOSED`) for a stream that the browser does not reconnect */
  readonly readyState?: number;
  addEventListener(type: string, listener: (event: MessageEvent) => void): void;
  close(): void;
}

export type Open = (url: string) => EventStream;

const openEventSource: Open = (url) => new EventSource(url, { withCredentials: true });

const CLOSED = 2;
const FIRST_RETRY_MS = 1_000;
const MAX_RETRY_MS = 30_000;

/**
 * Calls `onReady` with the run key of each `run.tiers_ready` event until the returned function runs.
 * A closed stream is opened again after a wait that doubles from 1 s to 30 s. `onReopen` runs when
 * such a stream is open.
 */
export function subscribe(
  onReady: (runKey: number) => void,
  open: Open = openEventSource,
  onReopen?: () => void,
): () => void {
  let stream: EventStream;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let wait = FIRST_RETRY_MS;
  let stopped = false;

  const connect = (reopened: boolean) => {
    const current = open(EVENTS_URL);
    stream = current;
    current.addEventListener("open", () => {
      wait = FIRST_RETRY_MS;
      if (reopened) onReopen?.();
    });
    current.addEventListener("error", () => {
      if (stopped || current.readyState !== CLOSED) return;
      current.close();
      timer = setTimeout(() => connect(true), wait);
      wait = Math.min(wait * 2, MAX_RETRY_MS);
    });
    current.addEventListener("run.tiers_ready", (event) => {
      try {
        const body = JSON.parse(String(event.data)) as { run_key?: unknown };
        if (typeof body.run_key === "number") onReady(body.run_key);
      } catch {
        // A malformed message is skipped.
      }
    });
  };

  connect(false);
  return () => {
    stopped = true;
    clearTimeout(timer);
    stream.close();
  };
}
