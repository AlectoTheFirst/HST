/** The pane shows what a change set does to an application's declared success condition. */

import { ResultLines } from "../results/ResultLines";
import { resultLabel } from "../results/text";
import { resultWord } from "../results/words";
import { useNamer } from "../shell/deviceNames";
import type {
  EvaluateServiceImpactResult,
  ServiceImpactCondition,
  ServiceImpactEvidence,
  ServiceImpactMember,
  ServiceImpactOutcome,
} from "./assessImpact";
import { BucketSection, ListSection } from "./Buckets";
import { PagedServiceBucket, type LoadBucket } from "./PagedServiceBucket";
import "./changesim.css";

// One member's movement, in parts that do not overlap.
const TRIAGE_LABELS: [keyof ServiceImpactMember["triage"], string][] = [
  ["decided_loss", "passes before, fails after"],
  ["passes_then_open", "passes before, not decided after"],
  ["open_then_fails", "not decided before, fails after"],
  ["open_throughout", "not decided before or after"],
  ["decided_gain", "fails before, passes after"],
  ["open_then_passes", "not decided before, passes after"],
  ["fails_then_open", "fails before, not decided after"],
];

/** The disjoint request parts present within a member. */
export function memberParts(m: ServiceImpactMember): string[] {
  return TRIAGE_LABELS.filter(([key]) => m.triage[key]).map(([, label]) => label);
}

/** The condition as one line of plain text, in the shape it was evaluated. */
export function conditionText(condition: ServiceImpactCondition): string {
  if (condition.kind === "member") return condition.member ?? "an unnamed member";
  const parts = (condition.parts ?? []).map(conditionText);
  if (parts.length === 0) return condition.kind;
  if (condition.kind === "every") return `every one of (${parts.join(", ")})`;
  if (condition.kind === "any-one") return `any one of (${parts.join(", ")})`;
  if (condition.kind === "n-of-m") return `at least ${condition.n ?? "an unrecorded number"} of (${parts.join(", ")})`;
  if (condition.kind === "capacity") return `capacity over (${parts.join(", ")})`;
  return `${condition.kind} (${parts.join(", ")})`;
}

function decidedBy(entry: ServiceImpactEvidence): string {
  const last = entry.steps[entry.steps.length - 1];
  const where = last?.device_uid ? `${last.device_uid} ` : "";
  return last ? `${where}${last.stage}: ${last.detail}` : "no step recorded";
}

/** The part's answer: its result word. */
function evidenceAnswer(entry: ServiceImpactEvidence): string {
  return entry.result.word;
}

function evidenceLine(entry: ServiceImpactEvidence): string {
  return `${entry.side}: ${entry.member} ${evidenceAnswer(entry)}, ${decidedBy(entry)}`;
}

/** A decision without its side. */
function decisionLine(entry: ServiceImpactEvidence): string {
  return `${entry.member} ${evidenceAnswer(entry)}, ${decidedBy(entry)}`;
}

/** A gap field as text. */
function gapValue(value: unknown): string {
  if (Array.isArray(value)) return value.map(gapValue).join(", ");
  if (value !== null && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .filter(([, inner]) => inner !== null && inner !== undefined && inner !== "")
      .map(([key, inner]) => `${key} ${gapValue(inner)}`)
      .join(" ");
  }
  return String(value);
}

function gapLine(gap: Record<string, unknown>): string {
  const rest = Object.entries(gap)
    .filter(([key, value]) => key !== "kind" && value !== null && value !== undefined && value !== "")
    .map(([key, value]) => `${key} ${gapValue(value)}`)
    .join(", ");
  return rest ? `${String(gap.kind)}: ${rest}` : String(gap.kind);
}

function bucketEmpty(bucket: { count: number | null; count_decimal?: string }): boolean {
  return bucket.count === 0 || (bucket.count === null && bucket.count_decimal === "0");
}

/** A failing part decides the word of the whole population, then an open part. */
function wordFromParts(fails: { count: number | null; count_decimal?: string }, open: { count: number | null; count_decimal?: string }): string {
  const answer = !bucketEmpty(fails) ? "false" : !bucketEmpty(open) ? "open" : "true";
  const word = resultWord("condition-holds", answer);
  return word.charAt(0).toUpperCase() + word.slice(1);
}

/** One member's answer on one side, from its counted parts. */
function memberState(counts: ServiceImpactMember["after"] | undefined): string {
  if (!counts) return "no answer recorded";
  const passes = counts.passes ?? 0;
  const fails = counts.fails ?? 0;
  const open = counts.open ?? 0;
  if (open > 0) return passes > 0 || fails > 0 ? "not decided for part of the clients" : "not decided";
  if (passes > 0 && fails > 0) return "passes for part of the clients, fails for the rest";
  if (fails > 0) return "fails";
  return "passes";
}

function list(items: string[]) {
  return { count: items.length, items, truncated: false };
}

/** The answer over one recorded state. */
function SingleStateOutcome({ result }: { result: EvaluateServiceImpactResult }) {
  // A saved run holds `outcomes`, and a tool result holds the three capped buckets.
  const outcome: ServiceImpactOutcome | undefined = result.outcomes?.after;
  const passes = outcome ? list(outcome.passes) : result.passes.after;
  const fails = outcome ? list(outcome.fails) : result.fails.after;
  const open = outcome ? list(outcome.open) : result.open.after;
  const label = outcome ? resultLabel(outcome.result) : wordFromParts(fails, open);
  return (
    <section aria-label="Answer">
      <h3>Answer: {label}</h3>
      {outcome && <ResultLines className="chgsim-devicemeta" subject={result.request.name} result={outcome.result} run={result.snapshot} />}
      <BucketSection title="Passes" bucket={passes} render={(cidr) => cidr} />
      <BucketSection title="Fails" bucket={fails} render={(cidr) => cidr} />
      <BucketSection title="Not decided" bucket={open} render={(cidr) => cidr} />
    </section>
  );
}

export function ServiceImpactPane({ result, loadBucket }: {
  result: EvaluateServiceImpactResult | null; loadBucket?: LoadBucket;
}) {
  const name = useNamer();
  if (!result) return null;
  const request = result.request;
  // An empty evaluated change set is one recorded state.
  const singleState = Array.isArray(result.intents) && result.intents.length === 0;
  const afterEvidence = result.evidence.items.filter((entry) => entry.side === "after");
  const decisions = singleState && afterEvidence.length > 0 ? afterEvidence : result.evidence.items;
  const meta = [
    request.requirement ?? "stated with the question",
    `destination ${request.destination}`,
    `${result.mode} mode`,
    singleState ? "one recorded state" : "before and after the change",
  ].join(", ");

  return (
    <section className="chgsim-pane" aria-label="Application condition pane">
      <header className="chgsim-panehead">
        <h2>Application condition</h2>
        <span className="chgsim-panets">
          {result.snapshot ? `run ${result.snapshot}` : "no run pinned"}
        </span>
      </header>
      <div className="chgsim-panebody">
        {result.complete === false && <p role="status">Analysis incomplete</p>}
        <div className="chgsim-device">
          <div className="chgsim-devicename">{request.name}</div>
          <div className="chgsim-devicemeta">{meta}</div>
          <div className="chgsim-devicemeta">{conditionText(request.condition)}</div>
        </div>

        {singleState ? (
          <SingleStateOutcome result={result} />
        ) : (
          TRIAGE_LABELS.map(([key, label]) => {
            const bucket = result.triage[key];
            return bucket ? (
              <PagedServiceBucket key={`${result.symbolic?.artifact_sha256 ?? result.snapshot}:${key}`}
                title={label.charAt(0).toUpperCase() + label.slice(1)} name={`triage.${key}`} bucket={bucket} load={loadBucket} />
            ) : null;
          })
        )}

        <ListSection
          title="Assumptions"
          items={result.assumptions ?? []}
          render={name}
        />
        <ListSection
          title="Missing evidence"
          items={result.missing_evidence}
          render={name}
        />
        <ListSection
          title="Members"
          items={result.members}
          render={(m) => {
            if (singleState) return `${m.name}: ${memberState(m.after)}`;
            const moved = memberParts(m);
            return `${m.name}: ${moved.length > 0 ? moved.join(", ") : "unchanged"}`;
          }}
        />
        <ListSection
          title="Decisions"
          items={decisions}
          count={singleState && afterEvidence.length > 0 ? undefined : result.evidence.count}
          truncated={result.evidence.truncated}
          render={(entry) => name(singleState ? decisionLine(entry) : evidenceLine(entry))}
        />
        <ListSection title="Routing gaps" items={result.gaps} render={(gap) => name(gapLine(gap))} />
        <ListSection
          title="Model errors"
          items={result.model_errors}
          render={(e) =>
            name(`${e.kind}: ${e.detail || e.kind}${e.subject ? ` (${e.subject})` : ""}`)
          }
        />
      </div>
    </section>
  );
}
