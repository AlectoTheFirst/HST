/**
 * The keys of the SPA in localStorage, in sessionStorage and in `history.state`.
 * test/storageKeys.test.ts fails for a storage key in no list.
 */

/** The keys that hold data of the user or of the network. */
export const USER_KEYS: readonly string[] = [
  "hst-workspace",
  "hst.agent.conversation",
  "hst.agent.evidence",
  "hst.trace.mtu",
  "hst:route",
];

/** The prefixes of the keys that hold data of the user or of the network. */
export const USER_KEY_PREFIXES: readonly string[] = ["hst.inventory.draft:"];

/** The keys that hold a display preference. */
export const PREFERENCE_KEYS: readonly string[] = [
  "hst-theme",
  "hst-rail-collapsed",
  "hst-rail-mini",
  "hst.agent.width",
  "hst-explore-result-view",
  "hst-explore-picture",
  "hst-explore-picture-dir",
  "hst-graph-height",
  "hst.trace.panes",
  "hst.trace.bottom",
  "hst.trace.info.open",
  "hst.trace.inspector.open",
  "hst.trace.view",
  "hst.trace.direction",
];

/** The key of localStorage that holds the username of the owner of the stored data. */
const OWNER_KEY = "hst.user";

function isUserKey(key: string): boolean {
  return USER_KEYS.includes(key) || USER_KEY_PREFIXES.some((prefix) => key.startsWith(prefix));
}

function clear(storage: () => Storage): void {
  try {
    const store = storage();
    const keys = Array.from({ length: store.length }, (_, i) => store.key(i));
    for (const key of keys) {
      if (key !== null && isUserKey(key)) store.removeItem(key);
    }
  } catch {
    // storage unavailable
  }
}

/** The keys of `history.state` that hold data of the user (workspace/WorkspaceContext.tsx). */
export const USER_HISTORY_KEYS: readonly string[] = ["hstWorkspace", "hstWorkspaceUser"];

/** A copy of a history state without the keys of USER_HISTORY_KEYS. */
export function withoutUserHistory(state: unknown): Record<string, unknown> {
  const rest: Record<string, unknown> = {};
  if (state === null || typeof state !== "object") return rest;
  for (const [key, value] of Object.entries(state)) {
    if (!USER_HISTORY_KEYS.includes(key)) rest[key] = value;
  }
  return rest;
}

function clearHistoryState(): void {
  const state: unknown = window.history.state;
  if (state === null || typeof state !== "object") return;
  if (!USER_HISTORY_KEYS.some((key) => key in state)) return;
  window.history.replaceState(withoutUserHistory(state), "");
}

/**
 * Removes the keys of USER_KEYS and USER_KEY_PREFIXES from localStorage and
 * sessionStorage, the owner key, and the keys of USER_HISTORY_KEYS from the
 * current history entry.
 */
export function clearUserStorage(): void {
  clear(() => window.localStorage);
  clear(() => window.sessionStorage);
  try {
    window.localStorage.removeItem(OWNER_KEY);
  } catch {
    // storage unavailable
  }
  clearHistoryState();
}

/**
 * Records `username` as the owner of the stored data. Runs `clearUserStorage`
 * first when the recorded owner is another user.
 */
export function claimUserStorage(username: string): void {
  try {
    const owner = window.localStorage.getItem(OWNER_KEY);
    if (owner !== null && owner !== username) clearUserStorage();
    window.localStorage.setItem(OWNER_KEY, username);
  } catch {
    // storage unavailable
  }
}
