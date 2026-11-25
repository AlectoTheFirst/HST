export interface LayoutSaver {
  /** Sends after `delay` ms without another call. */
  schedule(): void;
  /** Drops a scheduled send. */
  cancel(): void;
  /** Sends a scheduled send at once. `onSettled` gets no later result. */
  close(): void;
}

/**
 * One send is in flight at a time. A send asked for during a flight runs
 * once after it, so `send` reads the state of that moment.
 */
export function layoutSaver<T>({
  send,
  onSaved,
  onSettled,
  delay,
}: {
  send: () => Promise<T>;
  onSaved: (saved: T) => void;
  /** `null` after a saved send, the error after a failed one */
  onSettled: (error: unknown) => void;
  delay: number;
}): LayoutSaver {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let busy = false;
  let again = false;
  let open = true;

  const run = async () => {
    if (busy) {
      again = true;
      return;
    }
    busy = true;
    try {
      do {
        again = false;
        onSaved(await send());
      } while (again);
      if (open) onSettled(null);
    } catch (err) {
      again = false;
      if (open) onSettled(err);
    } finally {
      busy = false;
    }
  };

  const drop = () => {
    const pending = timer !== undefined;
    clearTimeout(timer);
    timer = undefined;
    return pending;
  };

  return {
    schedule() {
      drop();
      timer = setTimeout(() => {
        timer = undefined;
        void run();
      }, delay);
    },
    cancel() {
      drop();
    },
    close() {
      open = false;
      if (drop()) void run();
    },
  };
}
