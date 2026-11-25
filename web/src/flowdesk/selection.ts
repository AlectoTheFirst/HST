import type { Hop, Leg, PathResponse } from "../api/types";
import { isGate } from "./gate";

/** What the Inspector shows: a clicked station or a clicked lane cap. */
export type Selection = { type: "hop"; data: Hop } | { type: "leg"; data: Leg };

/** The graph's selection highlight does not use the default selection. */
export function defaultSelection(result: PathResponse | null): Selection | null {
  if (!result || result.hops.length === 0) return null;
  const gate = result.hops.find((h) => isGate(h));
  return { type: "hop", data: gate ?? result.hops[0] };
}
