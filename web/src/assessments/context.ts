import type { AgentStep } from "../api/types";
import { SERVICE_IMPACT_PARSERS } from "../changesim/assessImpact";
import type { TraceParams } from "../flowdesk/Composer";
import { emptyRequirement, requirementError } from "./types";
import type { AssessmentDraft, Condition, Intent, Requirement } from "./types";

export function traceDraft(input: TraceParams & { reply: boolean }, snapshot: string | undefined): AssessmentDraft | null {
  if (!snapshot) return null;
  const request: Requirement = {
    ...emptyRequirement(), name: `${input.src} to ${input.dst}`, destination: input.dst,
    sources: [input.src], members: [{ name: "destination", addresses: [input.dst] }],
    condition: { kind: "member", member: "destination" }, proto: input.proto,
    port: input.port || null, success: input.reply ? "session" : "forward",
    ...(input.mtu && input.mtu.mode !== "off" ? { mtu: structuredClone(input.mtu) } : {}),
  };
  return { title: request.name, kind: "troubleshoot", definition: { request, intents: [], snapshot, mode: "possible", freshness_s: 86400 } };
}

function conditionForEditor(value: Condition): Condition {
  const aliases: Record<string, Condition["kind"]> = { every: "and", "any-one": "or", "n-of-m": "threshold" };
  return { ...value, kind: aliases[value.kind] ?? value.kind, ...(value.parts ? { parts: value.parts.map(conditionForEditor) } : {}) };
}

/** Pair a readable service answer with its exact tool arguments. Summary
 * buckets omit service dimensions and cannot serve as a reusable request. */
export function serviceDraft(turns: readonly { steps?: AgentStep[] }[]): AssessmentDraft | null {
  for (let i = turns.length - 1; i >= 0; i--) {
    const steps = turns[i].steps ?? [];
    for (let j = steps.length - 1; j >= 0; j--) {
      const step = steps[j];
      const parse = SERVICE_IMPACT_PARSERS[step.name];
      if (step.is_error || !parse) continue;
      const result = parse(step.result);
      if (!result) continue;
      if (!result.snapshot) return null;
      const args = step.arguments;
      const definition = { intents: Array.isArray(args.intents) ? structuredClone(args.intents) as Intent[] : [], snapshot: result.snapshot, mode: result.mode, freshness_s: 86400 };
      if (typeof args.requirement === "string" && args.requirement) return { title: result.request.name, kind: "troubleshoot", definition: { ...definition, requirement: args.requirement } };
      if (!args.request || typeof args.request !== "object") return null;
      const request = { ...emptyRequirement(), ...structuredClone(args.request) } as Requirement;
      try { request.condition = conditionForEditor(request.condition); if (requirementError(request)) return null; } catch { return null; }
      return { title: request.name, kind: "troubleshoot", definition: { ...definition, request } };
    }
  }
  return null;
}
