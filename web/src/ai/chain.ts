/**
 * The evidence chain of an answer or of one of its statements, as the
 * evidence pane (ai/EvidencePane.tsx) draws it from left to right: statement,
 * tool steps, the records of their results that support the statement, and
 * the objects those records and steps name (graph objects by uid, stored
 * objects from the envelope's links, and the runs the steps read).
 *
 * A step builds on an earlier one when one of its arguments holds a value
 * that the earlier step returned and was not given: a uid, an address or
 * another identifier. Such pairs get an edge between the two steps. The scope
 * of one statement also holds the steps its steps build on.
 *
 * Pure: no React and no DOM.
 */

import type { AnswerClaim, AnswerEnvelope } from "../api/types";
import { endLabels, statementText } from "./citations";
import { fields, isUid, lookup, parseResult, resolvePointer, resultBody, short, tableColumns } from "./evidence";
import { linkChips } from "./links";
import type { CardStep } from "./ResultCards";

export type ChainNodeKind = "statement" | "step" | "record" | "object";

/** What opening a node selects in the evidence pane. */
export type ChainTarget =
  | { claim: string }
  | { step: string; pointer?: string | null }
  | { object: string };

export interface ChainNode {
  id: string;
  kind: ChainNodeKind;
  label: string;
  target: ChainTarget;
}

export type ChainEdgeKind = "cites" | "returned" | "names" | "builds-on";

export interface ChainEdge {
  id: string;
  source: string;
  target: string;
  kind: ChainEdgeKind;
  /** The value a step took from the step before it. */
  value?: string;
}

export interface EvidenceChain {
  nodes: ChainNode[];
  edges: ChainEdge[];
}

/** An object node: what it is and, for a stored object, how it opens. */
export interface ChainObject {
  key: string;
  label: string;
  /** A graph object's uid, opened in Explore's search. */
  uid?: string;
  /** A run id. */
  run?: string;
  /** The link chip of a stored object (ai/links.tsx). */
  link?: ReturnType<typeof linkChips>[number];
}

const LABEL_CHARS = 56;
/** The shortest returned value an argument is matched against. */
const MIN_VALUE_CHARS = 4;
/** Result keys that hold no value a later step can take: the run and the
 *  provenance every result carries, and the column names of a table. */
const SKIP_KEYS = new Set(["snapshot", "provenance", "columns", "query"]);
const MAX_VALUES = 2000;

function cut(text: string, chars = LABEL_CHARS): string {
  return text.length > chars ? text.slice(0, chars - 3) + "..." : text;
}

/** The label number of `s12`. */
function labelNumber(label: string): number {
  return Number(label.slice(1)) || 0;
}

/** A value that can identify something: it holds a digit or one of `:./`.
 *  A plain word such as "drop" or a relation type is no identifier. */
function identifies(value: string): boolean {
  return value.length >= MIN_VALUE_CHARS && /[\d:./]/.test(value);
}

/** The string values in `node`, outside the keys in SKIP_KEYS. */
function strings(node: unknown, out: Set<string>, skip = true): Set<string> {
  if (out.size >= MAX_VALUES) return out;
  if (typeof node === "string") out.add(node);
  else if (Array.isArray(node)) node.forEach((item) => strings(item, out, skip));
  else if (typeof node === "object" && node !== null) {
    for (const [key, value] of Object.entries(node)) {
      if (!(skip && SKIP_KEYS.has(key))) strings(value, out, skip);
    }
  }
  return out;
}

/** Whether `text` holds `value` as a whole token. */
function holds(text: string, value: string): boolean {
  if (text === value) return true;
  const at = text.indexOf(value);
  if (at < 0) return false;
  const edge = /[\w.:-]/;
  const before = at === 0 ? "" : text[at - 1];
  const after = text[at + value.length] ?? "";
  return !(before && edge.test(before)) && !(after && edge.test(after));
}

/** The value of `later`'s arguments that `earlier` returned and was not
 *  given, or undefined. */
export function buildsOn(earlier: CardStep, later: CardStep): string | undefined {
  const given = strings(earlier.arguments, new Set(), false);
  const returned = [...strings(parseResult(earlier.result), new Set())].filter(
    (value) => identifies(value) && !given.has(value),
  );
  if (returned.length === 0) return undefined;
  const args = [...strings(later.arguments, new Set(), false)];
  for (const value of returned) {
    if (args.some((arg) => holds(arg, value))) return value;
  }
  return undefined;
}

/** The label of a step, such as `s3`. */
function stepLabel(step: CardStep, envelope: AnswerEnvelope | undefined): string | undefined {
  if (step.step) return step.step;
  return (envelope?.links ?? []).find((link) => link.kind === "step" && link.ref_id === step.id)?.step ?? undefined;
}

/** The step labels a statement rests on: the valid labels its markers cite,
 *  and the steps it is matched to. */
export function claimSteps(claim: AnswerClaim, known: ReadonlySet<string>): string[] {
  const labels = [...claim.citations, ...(claim.support ?? []).map((item) => item.step), ...endLabels(claim)];
  return [...new Set(labels)].filter((label) => known.has(label));
}

/** A short title of what a step looked up, such as "Path trace". */
export function stepTitle(step: CardStep | undefined, tool: string | undefined): string {
  if (!tool) return "tool not known";
  return cut(lookup(tool, step?.arguments ?? {}, resultBody(parseResult(step?.result))), 40);
}

/**
 * The chain of `envelope`'s answer, or of its statement `claim`. `steps` are
 * the steps of the whole conversation, in order; `turnSteps` the labels of
 * the answer's own steps, which the chain of the whole answer shows even when
 * no statement cites them. A running turn has no envelope yet: its chain is
 * its steps so far and the steps they build on, with no statement.
 */
export function evidenceChain({
  content,
  envelope,
  steps,
  turnSteps = [],
  claim,
}: {
  content: string;
  envelope?: AnswerEnvelope;
  steps: CardStep[];
  turnSteps?: string[];
  claim?: string;
}): { chain: EvidenceChain; objects: Map<string, ChainObject> } {
  const byLabel = new Map<string, CardStep>();
  for (const step of steps) {
    const label = stepLabel(step, envelope);
    if (label) byLabel.set(label, step);
  }
  const toolOf = new Map((envelope?.tools_used ?? []).map((used) => [used.step, used] as const));
  const known = new Set([...byLabel.keys(), ...toolOf.keys()]);
  for (const link of envelope?.links ?? []) if (link.kind === "step" && link.step) known.add(link.step);

  const nodes = new Map<string, ChainNode>();
  const edges = new Map<string, ChainEdge>();
  const objects = new Map<string, ChainObject>();
  const addEdge = (source: string, target: string, kind: ChainEdgeKind, value?: string) => {
    const id = `${source}->${target}`;
    if (!edges.has(id)) edges.set(id, { id, source, target, kind, ...(value ? { value } : {}) });
  };
  const addObject = (object: ChainObject, from: string) => {
    const id = `object:${object.key}`;
    if (!objects.has(object.key)) objects.set(object.key, object);
    if (!nodes.has(id)) nodes.set(id, { id, kind: "object", label: cut(object.label), target: { object: object.key } });
    addEdge(from, id, "names");
  };

  const all = envelope?.claims ?? [];
  const claims = claim ? all.filter((item) => item.id === claim) : all;
  const scope = new Set<string>(claim ? [] : turnSteps.filter((label) => known.has(label)));
  const statementSteps: [AnswerClaim, string[]][] = [];
  for (const item of claims) {
    const labels = claimSteps(item, known);
    if (labels.length === 0 && !claim) continue;
    statementSteps.push([item, labels]);
    labels.forEach((label) => scope.add(label));
  }

  // the steps the scope builds on, back to the first step of the conversation
  const ordered = [...byLabel.keys()].sort((a, b) => labelNumber(a) - labelNumber(b));
  const builds: [string, string, string][] = [];
  const pending = [...scope].sort((a, b) => labelNumber(b) - labelNumber(a));
  const seen = new Set(pending);
  while (pending.length > 0) {
    const label = pending.shift()!;
    const later = byLabel.get(label);
    if (!later) continue;
    for (const earlier of ordered) {
      if (labelNumber(earlier) >= labelNumber(label)) break;
      const value = buildsOn(byLabel.get(earlier)!, later);
      if (value === undefined) continue;
      builds.push([earlier, label, value]);
      if (!seen.has(earlier)) {
        seen.add(earlier);
        scope.add(earlier);
        pending.push(earlier);
      }
    }
  }

  for (const [item, labels] of statementSteps) {
    const id = `statement:${item.id}`;
    nodes.set(id, { id, kind: "statement", label: cut(statementText(content, item)), target: { claim: item.id } });
    for (const label of labels) addEdge(id, `step:${label}`, "cites");
  }
  for (const label of [...scope].sort((a, b) => labelNumber(a) - labelNumber(b))) {
    const step = byLabel.get(label);
    const tool = step?.name ?? toolOf.get(label)?.tool;
    nodes.set(`step:${label}`, {
      id: `step:${label}`,
      kind: "step",
      label: `${label} ${stepTitle(step, tool)}`,
      target: { step: label },
    });
  }
  for (const [earlier, later, value] of builds) addEdge(`step:${earlier}`, `step:${later}`, "builds-on", value);

  // the records that support the statements, and the objects they name
  for (const [item] of statementSteps) {
    for (const support of item.support ?? []) {
      if (!scope.has(support.step)) continue;
      const step = byLabel.get(support.step);
      const id = `record:${support.step}:${support.pointer ?? "summary"}`;
      const from = `step:${support.step}`;
      if (support.pointer === null) {
        if (!nodes.has(id)) {
          nodes.set(id, { id, kind: "record", label: `${support.step} summary`, target: { step: support.step, pointer: null } });
        }
        addEdge(from, id, "returned");
        continue;
      }
      const root = parseResult(step?.result);
      const record = root === undefined ? undefined : resolvePointer(root, support.pointer);
      if (record === undefined) continue;
      if (!nodes.has(id)) {
        nodes.set(id, {
          id,
          kind: "record",
          label: cut(short(record)),
          target: { step: support.step, pointer: support.pointer },
        });
      }
      addEdge(from, id, "returned");
      for (const [field, value] of fields(record, tableColumns(root, support.pointer))) {
        if (isUid(field, value)) addObject({ key: `uid:${value}`, label: value, uid: value }, id);
      }
    }
  }

  // the stored objects and the runs the steps read
  for (const label of scope) {
    const from = `step:${label}`;
    const links = (envelope?.links ?? []).filter((link) => link.step === label && link.kind !== "step");
    for (const chip of linkChips(links)) addObject({ key: chip.key, label: chip.label, link: chip }, from);
    const run = toolOf.get(label)?.snapshot;
    if (run) addObject({ key: `run:${run}`, label: `Run ${run}`, run }, from);
  }

  // statements first, then steps, records and objects: the reading order
  const rank: Record<ChainNodeKind, number> = { statement: 0, step: 1, record: 2, object: 3 };
  const sorted = [...nodes.values()].sort((a, b) => rank[a.kind] - rank[b.kind]);
  return { chain: { nodes: sorted, edges: [...edges.values()] }, objects };
}
