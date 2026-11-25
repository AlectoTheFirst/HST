import type { PathResponse } from "../../api/types";

/** The trace the Trace pane hands to the map through the session, until the map takes it. */
export interface Handoff {
  result: PathResponse;
  snapshot: number | null;
}

const KEY = "hst:route";

export function handOff(result: PathResponse, snapshot: number | string | null | undefined): void {
  const key = snapshot === null || snapshot === undefined || snapshot === "" ? null : Number(snapshot);
  try {
    sessionStorage.setItem(KEY, JSON.stringify({ result, snapshot: Number.isFinite(key) ? key : null }));
  } catch {
    // Storage refused: the map opens without the route.
  }
}

export function takeHandoff(): Handoff | null {
  try {
    const raw = sessionStorage.getItem(KEY);
    if (!raw) return null;
    sessionStorage.removeItem(KEY);
    const parsed = JSON.parse(raw) as Handoff;
    return parsed && Array.isArray(parsed.result?.hops) ? parsed : null;
  } catch {
    return null;
  }
}
