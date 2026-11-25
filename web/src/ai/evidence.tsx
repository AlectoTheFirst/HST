/** The evidence view of a citation chip shows the records that support the statement. */

import type { ReactNode } from "react";
import type { AnswerClaim, AnswerEnvelope } from "../api/types";
import { useOpenInWorkspace } from "../workspace/WorkspaceContext";
import { nearestStep } from "./stepElement";
import { linkChips } from "./links";
import type { CardStep } from "./ResultCards";

/** Records shown when no record is named as support. */
const FIRST_RECORDS = 10;
const VALUE_CHARS = 60;

type Json = unknown;

function isObject(value: Json): value is Record<string, Json> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isScalar(value: Json): value is string | number | boolean | null {
  return value === null || ["string", "number", "boolean"].includes(typeof value);
}

/** The stored result as JSON, or undefined when it is text or cut short. */
export function parseResult(text: string | undefined): Json {
  if (!text) return undefined;
  try {
    return JSON.parse(text) as Json;
  } catch {
    return undefined;
  }
}

/** The `result` of a catalogue envelope or of another object that wraps
 *  one, or the whole body. */
export function resultBody(body: Json): Json {
  return isObject(body) && (isObject(body.result) || Array.isArray(body.result)) ? body.result : body;
}

/** The value at an RFC 6901 JSON pointer. */
export function resolvePointer(root: Json, pointer: string): Json {
  if (pointer === "") return root;
  let node: Json = root;
  for (const raw of pointer.slice(1).split("/")) {
    const key = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(node)) node = node[Number(key)];
    else if (isObject(node)) node = node[key];
    else return undefined;
  }
  return node;
}

/** A value as one short line of text. */
export function short(value: Json): string {
  let text: string;
  if (Array.isArray(value)) text = value.map(short).join(", ");
  else if (isObject(value)) text = Object.values(value).filter(isScalar).map(short).join(" ");
  else text = String(value);
  return text.length > VALUE_CHARS ? text.slice(0, VALUE_CHARS - 3) + "..." : text;
}

/** The arguments named in `keys` that hold a value, as short text. */
function named(args: Record<string, Json>, keys: string[]): string[] {
  return keys.flatMap((key) => {
    const value = args[key];
    return value === undefined || value === null || value === "" ? [] : [short(value)];
  });
}

function pick(args: Record<string, Json>, key: string): string | undefined {
  return named(args, [key])[0];
}

/** The node labels a Cypher query matches and the string literals it
 *  compares, at most four of each. */
function cypherSubject(query: string): string {
  const labels = [...new Set(Array.from(query.matchAll(/\(\s*\w*\s*:\s*`?(\w+)/g), (m) => m[1]))].slice(0, 4);
  const values = [...new Set(Array.from(query.matchAll(/'([^'\n]{1,60})'|"([^"\n]{1,60})"/g), (m) => m[1] ?? m[2]))]
    .filter((value) => !value.includes("$"))
    .slice(0, 4);
  const what = labels.length > 0 ? `${labels.join(", ")} records` : "records";
  return values.length > 0 ? `${what} for ${values.join(", ")}` : what;
}

function columnsOf(body: Json): string[] {
  return isObject(body) && Array.isArray(body.columns) ? body.columns.map(String) : [];
}

/** What a step looked up, from its tool and arguments, without the run. */
export function lookup(tool: string, args: Record<string, Json>, body: Json): string {
  const mode = pick(args, "mode") ?? pick(args, "kind");
  const device = pick(args, "device") ?? pick(args, "firewall");
  const on = device ? ` on ${device}` : "";
  switch (tool) {
    case "query_cypher": {
      const columns = columnsOf(body);
      const query = typeof args.query === "string" ? args.query : "";
      return `Graph query on ${cypherSubject(query)}` + (columns.length ? `, returning ${columns.join(", ")}` : "");
    }
    case "query_run_named":
      return `Named query ${pick(args, "key") ?? ""}`.trim();
    case "query_catalog":
      return mode === "list" ? "Named queries" : "Graph schema";
    case "policy_evaluate":
      if (mode === "explain_rule") {
        const rule = pick(args, "rule");
        const rulebase = pick(args, "rulebase");
        return `Rule ${rule ?? ""}${rulebase ? ` of rulebase ${rulebase}` : ""}${on}`.replace(/\s+/g, " ");
      }
      return `Rules${on} matching flow ${named(args, ["flow"]).join(" ")}`.trim();
    case "policy_lookup_nat":
      return `NAT rules for ${pick(args, "address") ?? "the address"}${on}`;
    case "lb_lookup_vip":
      return `Load balancer virtual servers for ${pick(args, "address") ?? "the address"}`;
    case "inventory_get":
      return mode === "site" ? `Site ${pick(args, "code") ?? ""}`.trim() : `Device ${device ?? ""}`.trim();
    case "inventory_list":
      return `${mode === "zones" ? "Zones" : "Interfaces"}${on}`;
    case "inventory_search":
      return `Inventory search for "${pick(args, "q") ?? ""}"`;
    case "inventory_resolve":
      return mode === "context"
        ? `Routing context ${pick(args, "name") ?? ""}`.trim()
        : `Records for address ${pick(args, "address") ?? ""}`.trim();
    case "routing_routes":
      if (mode === "table") return `Route table${on}`;
      if (mode === "search_prefix") return `Routes for prefix ${pick(args, "prefix") ?? pick(args, "prefix_contains") ?? ""}`.trim();
      return `Route lookup for ${pick(args, "address") ?? ""}${on}`.replace(/\s+/g, " ");
    case "routing_bgp":
      return mode === "paths" ? `BGP paths${on}` : `BGP sessions${on}`;
    case "routing_evaluate_policy":
      return `Route policy ${pick(args, "policy_name") ?? ""}${on}`.replace(/\s+/g, " ");
    case "routing_predict_routes":
      return "Predicted BGP routes";
    case "reach_trace": {
      if (mode === "groups") {
        return `Traffic allowed from ${pick(args, "source") ?? "the source"} to ${pick(args, "destination") ?? "the destination"}`;
      }
      const flow = isObject(args.flow) ? args.flow : {};
      const from = pick(flow, "src") ?? pick(flow, "source") ?? pick(args, "source");
      const to = pick(flow, "dst") ?? pick(flow, "destination") ?? pick(args, "destination");
      return from || to ? `Path trace from ${from ?? "the source"} to ${to ?? "the destination"}` : "Path trace";
    }
    case "reach_audit_mtu":
      return "MTU audit";
    case "impact_evaluate_service":
      return "Service impact evaluation";
    case "impact_assess":
      return `Impact of losing ${pick(args, "device") ?? pick(args, "link") ?? "the object"}`;
    case "change_simulate":
      return "Change simulation";
    case "change_get_simulation":
      return `Stored simulation ${pick(args, "session_id") ?? ""}`.trim();
    case "app_applications":
      return mode === "get" ? `Business application ${pick(args, "application_id") ?? ""}`.trim() : "Business applications";
    case "app_find_affected":
      return "Affected business applications";
    case "assessment_read": {
      const assessment = pick(args, "assessment_id");
      const run = pick(args, "run_id");
      if (mode === "analysis_session") return `Analysis session ${pick(args, "session_id") ?? ""}`.trim();
      if (mode === "list") return "Assessments";
      return `Assessment ${assessment ?? ""}${run ? ` run ${run}` : ""}`.trim();
    }
    case "evidence_get_gaps":
      return "Evidence gaps";
    case "ops_list_collection_runs":
      return "Collection runs";
    case "snapshot_list":
      return "Recorded runs";
    case "snapshot_resolve":
      return "Run in force";
    case "snapshot_diff":
      return `Differences from run ${pick(args, "base") ?? ""}`.trim();
    default:
      return `Tool ${tool}`;
  }
}

export function lookupSentence(tool: string, args: Record<string, Json>, run: string | null | undefined, body: Json): string {
  return `${lookup(tool, args, body)}${run ? ` at run ${run}` : ""}`;
}

/** The fields of one record as label and value: a table row by its columns,
 *  an object by its scalar fields, nested objects by dotted names. */
export function fields(record: Json, columns: string[]): [string, Json][] {
  if (isObject(record) && Array.isArray(record.row)) {
    return record.row.map((value, i) => [columns[i] ?? String(i + 1), value]);
  }
  if (!isObject(record)) return [["value", record]];
  const out: [string, Json][] = [];
  const walk = (node: Record<string, Json>, prefix: string, depth: number) => {
    for (const [key, value] of Object.entries(node)) {
      if (isScalar(value)) out.push([prefix + key, value]);
      else if (Array.isArray(value) && value.every(isScalar)) out.push([prefix + key, value]);
      else if (Array.isArray(value)) out.push([prefix + key, `${value.length} items`]);
      else if (isObject(value) && depth < 2) walk(value, `${prefix}${key}.`, depth + 1);
    }
  };
  walk(record, "", 0);
  return out;
}

/** A record field whose value names a graph object by its uid. */
export function isUid(label: string, value: Json): value is string {
  return typeof value === "string" && value !== "" && /(^|[._])uid$/i.test(label);
}

function RecordView({ record, columns, supporting }: { record: Json; columns: string[]; supporting: boolean }) {
  const openIn = useOpenInWorkspace();
  return (
    <dl className={"evidence-record" + (supporting ? " supporting" : "")}>
      {fields(record, columns).map(([label, value], i) => (
        <div key={i} className="evidence-field">
          <dt>{label}</dt>
          <dd>
            {isUid(label, value) && openIn ? (
              <button
                type="button"
                className="linkish"
                onClick={() => openIn((workspace) => workspace.openSearch(undefined, value))}
              >
                {value}
              </button>
            ) : Array.isArray(value) ? (
              value.map(String).join(", ")
            ) : (
              String(value)
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** The records of a result shown when none is named as support. */
function firstRecords(body: Json): { records: Json[]; total: number } {
  if (isObject(body) && Array.isArray(body.data) && Array.isArray(body.columns)) {
    return { records: body.data.slice(0, FIRST_RECORDS), total: body.data.length };
  }
  const list = Array.isArray(body)
    ? body
    : isObject(body)
      ? Object.values(body).find((value) => Array.isArray(value) && value.some(isObject))
      : undefined;
  if (Array.isArray(list)) return { records: list.slice(0, FIRST_RECORDS), total: list.length };
  return body === undefined ? { records: [], total: 0 } : { records: [body], total: 1 };
}

/** The columns of the table that holds the row at `pointer`. */
export function tableColumns(root: Json, pointer: string): string[] {
  const at = pointer.lastIndexOf("/data/");
  return at < 0 ? [] : columnsOf(resolvePointer(root, pointer.slice(0, at)));
}

function Records({ step, label, claim }: { step: CardStep; label: string; claim?: AnswerClaim }) {
  const root = parseResult(step.result);
  const body = resultBody(root);
  const support = (claim?.support ?? []).filter((item) => item.step === label);
  if (support.some((item) => item.pointer === null)) {
    // a compacted step keeps its summary, which is the record
    return (
      <>
        <p className="evidence-caption">Result summary</p>
        <p className="evidence-record supporting">{step.result}</p>
      </>
    );
  }
  if (root === undefined) {
    return step.result ? <p className="evidence-caption">Text result</p> : null;
  }
  const named = support
    .map((item) => ({ pointer: item.pointer!, record: resolvePointer(root, item.pointer!) }))
    .filter((item) => item.record !== undefined);
  if (named.length > 0) {
    return (
      <>
        <p className="evidence-caption">
          {named.length === 1 ? "Supporting record" : "Supporting records"}
        </p>
        {named.map((item) => (
          <RecordView key={item.pointer} record={item.record} columns={tableColumns(root, item.pointer)} supporting />
        ))}
      </>
    );
  }
  const { records, total } = firstRecords(body);
  if (records.length === 0) return <p className="evidence-caption">No records</p>;
  return (
    <>
      <p className="evidence-caption">
        {total > records.length ? `First ${records.length} of ${total} records` : "Result"}
      </p>
      {records.map((record, i) => (
        <RecordView key={i} record={record} columns={columnsOf(body)} supporting={false} />
      ))}
    </>
  );
}

function StepLinks({ envelope, label }: { envelope: AnswerEnvelope; label: string }) {
  const openIn = useOpenInWorkspace();
  const chips = linkChips((envelope.links ?? []).filter((link) => link.step === label));
  if (!openIn || chips.length === 0) return null;
  return (
    <div className="answer-links" role="group" aria-label={`Objects ${label} read`}>
      {chips.map((chip) => (
        <button key={chip.key} type="button" className="context-chip answer-link" onClick={() => openIn(chip.open)}>
          {chip.label}
        </button>
      ))}
    </div>
  );
}

/** Open the step list that holds a step and move to the step. */
function showInList(from: HTMLElement, stepId: string): void {
  const element = nearestStep(from, stepId);
  if (!element) return;
  const list = element.closest("details");
  if (list) list.open = true;
  if (typeof element.scrollIntoView === "function") element.scrollIntoView({ block: "nearest" });
  element.focus();
}

function Details({ step, stepId }: { step: CardStep; stepId: string }) {
  const query = typeof step.arguments.query === "string" ? step.arguments.query : null;
  return (
    <details className="evidence-details">
      <summary>Details</summary>
      <p className="evidence-caption">Tool {step.name}</p>
      {query && <pre className="rawpre">{query}</pre>}
      <pre className="rawpre">{JSON.stringify(step.arguments, null, 1)}</pre>
      <pre className="rawpre">{step.result}</pre>
      <button type="button" className="linkish" onClick={(e) => showInList(e.currentTarget, stepId)}>
        Show in tool calls
      </button>
    </details>
  );
}

/** The evidence of one chip: step `label` (`stepId`) for statement `claim`.
 *  A step of a running turn has no envelope yet, and no object links. */
export function EvidenceView({
  label,
  stepId,
  claim,
  step,
  envelope,
  onClose,
}: {
  label: string;
  stepId: string;
  claim?: AnswerClaim;
  step?: CardStep;
  envelope?: AnswerEnvelope;
  onClose: () => void;
}): ReactNode {
  const used = envelope?.tools_used.find((tool) => tool.step === label);
  const tool = step?.name ?? used?.tool;
  const root = parseResult(step?.result);
  const run =
    used?.snapshot ?? (isObject(root) && isObject(root.snapshot) ? (root.snapshot.id as string | null) : null);
  return (
    <section className="evidence" aria-label={`Evidence of ${label}`}>
      <div className="evidence-head">
        <span className="agentpanel-steplabel">{label}</span>
        <span className="evidence-lookup">
          {tool ? lookupSentence(tool, step?.arguments ?? {}, run, resultBody(root)) : "Tool not known"}
        </span>
        <button type="button" className="linkish" onClick={onClose} aria-label="Close evidence">
          Close
        </button>
      </div>
      {claim?.citation_status === "matched" && (
        <p className="evidence-caption">Matched step</p>
      )}
      {step ? (
        <>
          <Records step={step} label={label} claim={claim} />
          {envelope && <StepLinks envelope={envelope} label={label} />}
          <Details step={step} stepId={stepId} />
        </>
      ) : (
        <p className="evidence-caption">Result not loaded</p>
      )}
    </section>
  );
}
