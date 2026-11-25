import type { Leg } from "../api/types";

/** A gate's decision, as the ribbon, serpentine, ledger and Strata views show it. */
export type GateVerdict = "ok" | "bad" | "warn";

export const VERDICT_WORD: Readonly<Record<GateVerdict, string>> = {
  ok: "permitted",
  bad: "blocked",
  warn: "not decided",
};

/** The outcome of a whole leg. A leg the tracer could not forward (no route,
 *  answer "false") reads as bad and one it could not decide reads as warn,
 *  even when no rulebase blocked it. */
export function legOutcome(leg: Leg): GateVerdict {
  if (leg.blocked || leg.result?.answer === "false") return "bad";
  if (leg.indeterminate || leg.result?.answer === "open") return "warn";
  return "ok";
}

/** True when a rulebase blocked every leg of a trace. A shared gate then
 *  carries the deny. A leg with no route does not count as blocked. */
export function allLegsBlocked(legs: readonly Leg[]): boolean {
  return legs.length > 0 && legs.every((l) => l.blocked);
}

/** The word a lane that is not forwarded or not decided ends in: the walk's
 *  own word for the leg, such as "no route found", else the outcome's word. */
export function legWord(leg: Leg): string {
  return leg.result?.word || VERDICT_WORD[legOutcome(leg)];
}
