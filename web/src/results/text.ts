// The result vocabulary as the pages write it. The words come from the
// generated table (words.ts, from src/hst/results/words.py); this module
// turns a server `result` into the 3 lines every page shows.

import { RESULT_WORDS, type ResultCondition, type ResultQuantifier } from "./words";

export interface ResultMissing {
  code: string;
  subject?: string | null;
  detail?: string | null;
}

/** The server's `result`: an item's answer in the words of the statement it tests. */
export interface ResultValue {
  kind?: "result" | "record" | "declared";
  statement?: string | null;
  answer?: string | null;
  word: string;
  quantifier?: ResultQuantifier | null;
  condition?: ResultCondition | null;
  missing?: ResultMissing[];
}

/** The result's word, or a note that the record states none. */
export function resultText(result: ResultValue | null | undefined): string {
  return result?.word ?? "no result recorded";
}

/** The result's word with a capital, for a label or a heading. */
export function resultLabel(result: ResultValue): string {
  return result.word.charAt(0).toUpperCase() + result.word.slice(1);
}

/** "Tested: the forward flow, counts as passing only if every path and member works." or null. */
export function testedText(result: ResultValue | null | undefined): string | null {
  if (!result) return null;
  const parts: string[] = [];
  if (result.condition) parts.push(RESULT_WORDS.condition[result.condition]);
  if (result.quantifier) parts.push(RESULT_WORDS.quantifier[result.quantifier]);
  return parts.length ? `Tested: ${parts.join(", ")}.` : null;
}

/** "Not decided: dev:leaf101: the fabric policy was not collected; ..." or null for a decided answer. */
export function missingText(result: ResultValue | null | undefined): string | null {
  if (!result?.missing?.length) return null;
  const reasons = result.missing.map((item) => {
    const fixed: Record<string, string> = RESULT_WORDS.fixedReasons;
    const text = item.detail || fixed[item.code] || item.code;
    return item.subject ? `${item.subject}: ${text}` : text;
  });
  return `Not decided: ${reasons.join("; ")}.`;
}

/** The mode's word as a question's strictness. */
export function modeText(mode: string | null | undefined): string {
  const quantifier = mode ? RESULT_WORDS.quantifierOfMode[mode as keyof typeof RESULT_WORDS.quantifierOfMode] : undefined;
  return quantifier ? RESULT_WORDS.quantifier[quantifier] : String(mode ?? "");
}
