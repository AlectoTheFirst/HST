import { resultLabel, type ResultValue } from "../results/text";
import { DeviceText, useNamer } from "../shell/deviceNames";
import { useMemo, useState, type KeyboardEvent, type ReactNode } from "react";
import type { LoadBucket } from "../changesim/PagedServiceBucket";
import { ServiceImpactPane } from "../changesim/ServiceImpactPane";
import type { EvaluateServiceImpactResult } from "../changesim/assessImpact";

export function label(key: string): string {
  return key.replaceAll("_", " ");
}
export function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
function text(value: unknown): string {
  if (value === null || value === undefined || value === "") return "Not recorded";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

/** The exact record of a value. */
export function EvidenceValue({ value, depth = 0 }: { value: unknown; depth?: number }) {
  if (value === null || typeof value !== "object")
    return (
      <span>
        <DeviceText text={text(value)} />
      </span>
    );
  if (depth > 8)
    return (
      <details>
        <summary>Nested evidence</summary>
        <pre>{JSON.stringify(value, null, 2)}</pre>
      </details>
    );
  if (Array.isArray(value)) {
    if (!value.length) return <span>None recorded</span>;
    return (
      <ol className="assessment-evidence-list">
        {value.slice(0, 100).map((entry, i) => (
          <li key={i}>
            <EvidenceValue value={entry} depth={depth + 1} />
          </li>
        ))}
        {value.length > 100 && <li>{value.length - 100} more entries in the exact export</li>}
      </ol>
    );
  }
  return (
    <dl className="assessment-evidence">
      {Object.entries(value).map(([key, entry]) => (
        <div key={key}>
          <dt>{label(key)}</dt>
          <dd>
            <EvidenceValue value={entry} depth={depth + 1} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** A stored result, or null for anything else. */
function asResult(value: unknown): ResultValue | null {
  const row = record(value);
  return typeof row.word === "string" ? (row as unknown as ResultValue) : null;
}
/** A stored answer as a label: the word of its result. */
function answerText(value: unknown): string {
  const result = asResult(value);
  return result ? resultLabel(result) : text(value);
}
/** The answer of a stored result, or null. */
function answerOf(value: unknown): string | null {
  return asResult(value)?.answer ?? null;
}

function ScrollTable({ children }: { children: ReactNode }) {
  return (
    // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
    <div className="assessment-tablewrap" tabIndex={0} role="region" aria-label="Analysis table">
      {children}
    </div>
  );
}

/** The result of a requirement's state: the state itself, or the result an outcome record carries. */
function state(value: unknown): unknown {
  return asResult(value) ?? record(value).result;
}
function primitive(value: unknown): boolean {
  return (
    value === null || value === undefined || ["string", "number", "boolean"].includes(typeof value)
  );
}
function stableValue(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableValue).join(",")}]`;
  if (value !== null && typeof value === "object")
    return `{${Object.entries(record(value))
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableValue(entry)}`)
      .join(",")}}`;
  return JSON.stringify(value) ?? String(value);
}
function EvidenceSummary({ value }: { value: unknown }) {
  if (primitive(value))
    return (
      <span>
        <DeviceText text={text(value)} />
      </span>
    );
  if (Array.isArray(value)) {
    if (!value.length) return <span>None recorded</span>;
    return (
      <ul className="assessment-summary-list">
        {value.slice(0, 20).map((entry, index) => (
          <li key={index}>{primitive(entry) ? text(entry) : <EvidenceSummary value={entry} />}</li>
        ))}
        {value.length > 20 && <li>{value.length - 20} more entries in the exact record</li>}
      </ul>
    );
  }
  const entries = Object.entries(record(value));
  if (!entries.length) return <span>None recorded</span>;
  return (
    <dl className="assessment-summary">
      {entries.slice(0, 20).map(([key, entry]) => (
        <div key={key}>
          <dt>{label(key)}</dt>
          <dd>
            {primitive(entry) ? (
              text(entry)
            ) : Array.isArray(entry) && entry.every(primitive) ? (
              entry.map(text).join(", ") || "None recorded"
            ) : (
              <code>{stableValue(entry)}</code>
            )}
          </dd>
        </div>
      ))}
      {entries.length > 20 && (
        <div>
          <dt>Further fields</dt>
          <dd>{entries.length - 20} more fields in the exact record</dd>
        </div>
      )}
    </dl>
  );
}
function ExactRecord({ summary, value }: { summary: string; value: unknown }) {
  const [open, setOpen] = useState(false);
  return (
    <details
      className="assessment-raw"
      open={open}
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary>{summary}</summary>
      {open && <EvidenceValue value={value} />}
    </details>
  );
}

function ConstraintMatrix({ constraints }: { constraints: Record<string, unknown> }) {
  return (
    <section>
      <h3>
        Requirement constraints
        {constraints.result !== undefined ? `: ${answerText(constraints.result)}` : ""}
      </h3>
      {constraints.reason !== undefined && constraints.reason !== null && (
        <p>{text(constraints.reason)}</p>
      )}
      <ScrollTable>
        <table>
          <thead>
            <tr>
              <th>Requirement</th>
              <th>Outcome</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <th scope="row">Desired requirement</th>
              <td>{answerText(state(constraints.desired))}</td>
              <td>
                <EvidenceSummary value={constraints.desired} />
              </td>
            </tr>
            {Object.entries(record(constraints.protected)).map(([name, value]) => (
              <tr key={name}>
                <th scope="row">{name}</th>
                <td>{answerText(state(value))}</td>
                <td>
                  <EvidenceSummary value={value} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </ScrollTable>
    </section>
  );
}
function Changes({ changes }: { changes: unknown[] }) {
  return (
    <ScrollTable>
      <table>
        <thead>
          <tr>
            <th>Object</th>
            <th>Before</th>
            <th>After</th>
          </tr>
        </thead>
        <tbody>
          {changes.map((change, i) => {
            const row = record(change);
            return (
              <tr key={String(row.id ?? row.uid ?? i)}>
                <th scope="row">
                  {text(row.rule ?? row.uid ?? row.id)}
                  <br />
                  {row.rulebase ? text(row.rulebase) : ""}
                </th>
                <td>
                  <EvidenceSummary value={row.before} />
                </td>
                <td>
                  <EvidenceSummary value={row.after} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </ScrollTable>
  );
}
function Proposal({ finding, order }: { finding: Record<string, unknown>; order: unknown }) {
  const names = Array.isArray(order) ? order : ["devices", "newly_permitted_scope", "rule_edits"];
  const costs = Array.isArray(finding.cost_decimal)
    ? finding.cost_decimal
    : Array.isArray(finding.cost)
      ? finding.cost
      : [];
  const lower = Array.isArray(finding.cost_lower_decimal)
    ? finding.cost_lower_decimal
    : Array.isArray(finding.cost_lower)
      ? finding.cost_lower
      : [];
  const upper = Array.isArray(finding.cost_upper_decimal)
    ? finding.cost_upper_decimal
    : Array.isArray(finding.cost_upper)
      ? finding.cost_upper
      : [];
  return (
    <>
      <h4>Proposal cost</h4>
      <ol>
        {names.map((name, i) => (
          <li key={String(name)}>
            {label(String(name))}:{" "}
            {costs[i] !== undefined && costs[i] !== null
              ? text(costs[i])
              : `${text(lower[i])} to ${text(upper[i])}`}
          </li>
        ))}
      </ol>
      <p>{finding.minimum_cost === true ? "Minimum cost decided" : "Minimum cost not decided"}</p>
      <ConstraintMatrix constraints={finding} />
      {Array.isArray(finding.diff) && (
        <>
          <h4>Proposed changes</h4>
          <Changes changes={finding.diff} />
        </>
      )}
      {finding.diff_truncated === true && (
        <p>Diff of {text(finding.diff_count)} recorded edits incomplete</p>
      )}
      {finding.diff_sha256 !== undefined && (
        <p>
          Diff identity: <code>{text(finding.diff_sha256)}</code>
        </p>
      )}
      {Array.isArray(finding.intents) && (
        <>
          <h4>Ordered proposal operations</h4>
          <EvidenceSummary value={finding.intents} />
        </>
      )}
      {finding.cost_bounds !== undefined && (
        <>
          <h4>Permitted scope measurement</h4>
          <EvidenceSummary value={finding.cost_bounds} />
        </>
      )}
    </>
  );
}

function ownId(value: Record<string, unknown>): string | undefined {
  const explicit = value.finding_id ?? value.id ?? value.uid ?? value.digest ?? value.diff_sha256;
  return typeof explicit === "string" && explicit ? explicit : undefined;
}
function stableId(prefix: string, value: Record<string, unknown>): string {
  const explicit = ownId(value);
  if (explicit) return `${prefix}:${explicit}`;
  let hash = 2166136261;
  for (const character of stableValue(value)) {
    hash ^= character.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return `${prefix}:legacy-${(hash >>> 0).toString(36)}`;
}

type FindingKind = "finding" | "gap" | "domain" | "outcome" | "verification";
interface PresentedFinding {
  id: string;
  index: number;
  kind: FindingKind;
  title: string;
  outcome: string;
  value: Record<string, unknown>;
}
/** The reference the server resolves against the stored run
 *  (src/hst/assessment/findings.py): the entry's own id when it has one, a
 *  domain's name, and its position otherwise. A stored result never changes,
 *  so the position names the same entry for good. */
function findingRef(item: PresentedFinding): string {
  const explicit = ownId(item.value);
  if (explicit) return `${item.kind}:${explicit}`;
  if (item.kind === "domain" && typeof item.value.name === "string")
    return `domain:${item.value.name}`;
  return `${item.kind}:@${item.index}`;
}
interface ResultPresentation {
  summary: string;
  items: PresentedFinding[];
}

function resultFindings(result: Record<string, unknown>): PresentedFinding[] {
  const findings = Array.isArray(result.findings) ? result.findings.map(record) : [];
  return findings.map((value, index) => ({
    id: stableId("finding", value),
    index,
    kind: "finding",
    title: Array.isArray(value.candidates)
      ? value.candidates.join(", ") || "Baseline"
      : String(value.title ?? `Finding ${index + 1}`),
    outcome: answerText(value.result),
    value,
  }));
}
function gapFindings(result: Record<string, unknown>): PresentedFinding[] {
  const gaps = Array.isArray(result.gaps) ? result.gaps.map(record) : [];
  return gaps.map((value, index) => ({
    id: stableId("gap", value),
    index,
    kind: "gap",
    title: text(value.code ?? value.kind),
    outcome: "Evidence missing",
    value,
  }));
}
function domainFindings(result: Record<string, unknown>): PresentedFinding[] {
  return Object.entries(record(result.expanded_domains)).map(([name, entry], index) => {
    const value: Record<string, unknown> = { name, ...record(entry) };
    return {
      id: stableId("domain", value),
      index,
      kind: "domain",
      title: name,
      outcome: value.evidence_complete === true ? "Evidence validated" : "Evidence incomplete",
      value,
    };
  });
}
function outcome(result: Record<string, unknown>): string {
  return answerText(
    result.result ??
      record(result.constraints).result ??
      record(record(result.outcomes).after).result ??
      record(result.evaluation).result,
  );
}
function oneOutcome(result: Record<string, unknown>): PresentedFinding[] {
  return [
    {
      id: stableId("outcome", result),
      index: 0,
      kind: "outcome",
      title: "Analysis outcome",
      outcome: outcome(result),
      value: result,
    },
  ];
}
function allOrOutcome(
  result: Record<string, unknown>,
  ...groups: PresentedFinding[][]
): PresentedFinding[] {
  const items = groups.flat();
  return items.length > 0 ? items : oneOutcome(result);
}
const presentationAdapters: Record<
  string,
  (result: Record<string, unknown>) => ResultPresentation
> = {
  evaluate: (result) => ({
    summary: outcome(result),
    items: allOrOutcome(result, resultFindings(result), gapFindings(result)),
  }),
  troubleshoot: (result) => ({
    summary: outcome(result),
    items: allOrOutcome(result, resultFindings(result), gapFindings(result)),
  }),
  regression: (result) => ({
    summary: outcome(result),
    items: allOrOutcome(result, resultFindings(result), gapFindings(result)),
  }),
  repair: (result) => ({
    summary: outcome(result),
    items: allOrOutcome(result, resultFindings(result), gapFindings(result)),
  }),
  resilience: (result) => ({
    summary: outcome(result),
    items: allOrOutcome(
      result,
      resultFindings(result),
      domainFindings(result),
      gapFindings(result),
    ),
  }),
  verify: (result) => {
    const summary =
      result.state === "agreement"
        ? "Prediction matches collected model"
        : result.state === "deviation"
          ? "Prediction differs from collected model"
          : "Insufficient evidence for verification";
    const comparison: PresentedFinding = {
      id: stableId("verification", result),
      index: 0,
      kind: "verification",
      title: "Post-deployment comparison",
      outcome:
        result.state === "agreement"
          ? "Agreement"
          : result.state === "deviation"
            ? "Deviation"
            : "Unknown",
      value: result,
    };
    return { summary, items: [comparison, ...gapFindings(result)] };
  },
};
function present(result: Record<string, unknown>): ResultPresentation {
  return (presentationAdapters[String(result.kind)] ?? presentationAdapters.evaluate)(result);
}

function GapSummary({ gap, index }: { gap: Record<string, unknown>; index: number }) {
  const qualifiers = [
    gap.kind !== undefined && gap.kind !== gap.code ? text(gap.kind) : "",
    gap.dimension !== undefined ? text(gap.dimension) : "",
  ]
    .filter(Boolean)
    .join(", ");
  return (
    <>
      <p>
        <strong>{text(gap.code ?? gap.kind)}</strong>
        {qualifiers ? ` (${qualifiers})` : ""}:{" "}
        <span>
          <DeviceText text={text(gap.detail)} />
        </span>
        {gap.subject ? (
          <>
            , subject: <DeviceText text={text(gap.subject)} />
          </>
        ) : (
          ""
        )}
      </p>
      <span className="assessment-note">Gap record {index + 1}</span>
    </>
  );
}

function FindingInspector({
  item,
  result,
  onSaveProposal,
  onAskAi,
}: {
  item: PresentedFinding;
  result: Record<string, unknown>;
  onSaveProposal?: (findingIndex: number) => void;
  onAskAi?: (findingRef: string) => void;
}) {
  const name = useNamer();
  const row = item.value;
  const forward = record(row.forward_replay);
  const valid =
    row.verified === true &&
    answerOf(row.result) === "true" &&
    answerOf(state(row.desired)) === "true" &&
    Object.values(record(row.protected)).every((value) => answerOf(state(value)) === "true");
  return (
    <section className="assessment-inspector" aria-label="Finding evidence inspector">
      <p className="assessment-note">Finding ID: {findingRef(item)}</p>
      <h3>{item.title}</h3>
      <p className="assessment-finding-outcome">{item.outcome}</p>
      {item.kind === "gap" && <GapSummary gap={row} index={item.index} />}
      {item.kind === "domain" && (
        <>
          <p>
            {row.evidence_complete === true
              ? "Domain membership validated"
              : "Domain coverage not decided"}
          </p>
          <p>
            {result.independent_diversity_established === true
              ? "Independent diversity established"
              : "Independent physical diversity not known"}
          </p>
          <h4>Dependent objects</h4>
          <ul>
            {(Array.isArray(row.effects) ? row.effects : []).map((effect, i) => {
              const value = record(effect);
              return (
                <li key={String(value.uid ?? i)}>
                  {text(value.kind)}: {name(text(value.uid))}
                  {Array.isArray(value.interfaces) && value.interfaces.length > 0
                    ? `, interfaces ${value.interfaces.join(", ")}`
                    : ""}
                </li>
              );
            })}
          </ul>
          {Array.isArray(row.domains) && row.domains.length > 0 && (
            <p>Shared or nested domains: {row.domains.join(", ")}</p>
          )}
          <p>Source provenance: {row.provenance_validated === true ? "Validated" : "Unverified"}</p>
          {Array.isArray(record(row.evidence).missing) && (
            <>
              <h4>Missing observations</h4>
              <EvidenceSummary value={record(row.evidence).missing} />
            </>
          )}
          <h4>Recorded observation references</h4>
          <EvidenceSummary value={record(row.evidence).evidence_refs} />
        </>
      )}
      {result.kind === "repair" && item.kind === "finding" && (
        <Proposal finding={row} order={result.cost_order} />
      )}
      {result.kind === "regression" && item.kind === "finding" && (
        <>
          <h4>Reverse recovery on snapshot B</h4>
          <p>{answerText(row.result)}</p>
          <h4>Forward replay on snapshot A</h4>
          <p>
            {forward.reproduces_failure === true
              ? "Failure reproduced"
              : answerOf(forward.result) === "true"
                ? "Failure not reproduced"
                : "Reproduction not decided"}
          </p>
          <EvidenceSummary value={forward.evaluation} />
        </>
      )}
      {item.kind === "verification" && (
        <>
          <p>
            Configuration realization:{" "}
            {label(String(result.configuration_realization ?? "not-decided"))}
          </p>
          <EvidenceSummary value={record(result.configuration_realization_detail).reason} />
          {record(result.observation_coverage).qualifies !== true && (
            <section className="assessment-gaps">
              <h4>Required post-deployment observations</h4>
              <EvidenceSummary value={record(result.observation_coverage).missing} />
            </section>
          )}
          <h4>Predicted requirements</h4>
          <EvidenceSummary value={record(result.protected_comparison).predicted} />
          <h4>Collected protected requirements</h4>
          <EvidenceSummary value={record(result.protected_comparison).observed} />
        </>
      )}
      {item.kind === "outcome" && (
        <EvidenceSummary
          value={{
            reason: result.reason,
            constraints: result.constraints,
            outcomes: result.outcomes,
            evaluation: result.evaluation,
          }}
        />
      )}
      {item.kind === "finding" && result.kind !== "repair" && result.kind !== "regression" && (
        <EvidenceSummary value={row} />
      )}
      {onSaveProposal && item.kind === "finding" && Array.isArray(row.intents) && valid && (
        <button type="button" onClick={() => onSaveProposal(item.index)}>
          Save proposal {item.index + 1}
        </button>
      )}
      {onAskAi && (
        <button type="button" onClick={() => onAskAi(findingRef(item))}>
          Ask HST AI about this finding
        </button>
      )}
      <ExactRecord summary="Exact finding record" value={row} />
    </section>
  );
}

export function AnalysisResult({
  result,
  analysisKind,
  onSaveProposal,
  loadBucket,
  selectedFindingId,
  onSelectFinding,
  onAskAi,
}: {
  result: Record<string, unknown>;
  analysisKind?: string;
  onSaveProposal?: (findingIndex: number) => void;
  loadBucket?: LoadBucket;
  selectedFindingId?: string | null;
  /** Receives the selected finding's stable id and the reference the server
   *  resolves for it, or null when the selection is cleared. */
  onSelectFinding?: (findingId: string | null, findingRef?: string) => void;
  /** Opens a HST AI conversation about the finding its reference names. */
  onAskAi?: (findingRef: string) => void;
}) {
  const typedResult = useMemo(
    () => (result.kind === undefined && analysisKind ? { kind: analysisKind, ...result } : result),
    [analysisKind, result],
  );
  const presentation = useMemo(() => present(typedResult), [typedResult]);
  const items = presentation.items;
  const [localSelection, setLocalSelection] = useState<string | null>(null);
  const selection = selectedFindingId === undefined ? localSelection : selectedFindingId;
  const selected = items.find((item) => item.id === selection) ?? null;
  const select = (id: string | null) => {
    if (selectedFindingId === undefined) setLocalSelection(id);
    const item = items.find((entry) => entry.id === id);
    onSelectFinding?.(id, item ? findingRef(item) : undefined);
  };
  const outcomes = record(typedResult.outcomes);
  const evaluation = record(typedResult.evaluation);
  const service =
    typedResult.request &&
    typedResult.decided_change &&
    typedResult.open_change &&
    typedResult.open;
  const mtu = record(record(typedResult.request).mtu ?? record(evaluation.request).mtu);
  function move(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const key = event.key;
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(key)) return;
    event.preventDefault();
    const next =
      key === "Home"
        ? 0
        : key === "End"
          ? items.length - 1
          : key === "ArrowDown"
            ? Math.min(items.length - 1, index + 1)
            : Math.max(0, index - 1);
    const buttons = event.currentTarget
      .closest(".assessment-finding-list")
      ?.querySelectorAll<HTMLButtonElement>("button[data-finding-button]");
    buttons?.[next]?.focus();
  }
  return (
    <div className="assessment-result">
      <section className="assessment-outcome" aria-label="Outcome summary">
        <h3>{presentation.summary}</h3>
      </section>
      {mtu.mode === "inventory" ? (
        <section aria-label="MTU evidence">
          <h3>MTU evidence</h3>
          <p>No packet size requirement</p>
        </section>
      ) : mtu.mode && mtu.mode !== "off" ? (
        <section aria-label="MTU requirement">
          <h3>Packet size requirement</h3>
          <p>
            {label(String(mtu.mode))}
            {mtu.ip_packet_bytes != null ? `: ${text(mtu.ip_packet_bytes)} complete IP bytes` : ""}
            {mtu.reply_ip_packet_bytes != null
              ? `, reply: ${text(mtu.reply_ip_packet_bytes)} bytes`
              : ""}
            {mtu.ipv4_df != null ? `, IPv4 DF: ${mtu.ipv4_df ? "set" : "clear"}` : ""}
          </p>
        </section>
      ) : null}
      {Object.keys(record(typedResult.constraints)).length > 0 && (
        <ConstraintMatrix constraints={record(typedResult.constraints)} />
      )}
      {Object.keys(outcomes).length > 0 && (
        <div className="assessment-fields">
          {["before", "after"].map((side) => (
            <section key={side}>
              <h3>
                {side === "before" ? "Baseline" : "Predicted"}:{" "}
                {answerText(record(outcomes[side]).result)}
              </h3>
              <EvidenceSummary value={outcomes[side]} />
            </section>
          ))}
        </div>
      )}
      {typedResult.stop_reason !== undefined && (
        <p role="status">
          Search stopped: {label(String(typedResult.stop_reason))},{" "}
          {typedResult.search_complete === true ? "search complete" : "search bounded"}
        </p>
      )}
      {typedResult.kind === "regression" && (
        <section>
          <h3>Observed semantic changes</h3>
          {Array.isArray(typedResult.edits) && <Changes changes={typedResult.edits} />}
          {Array.isArray(typedResult.excluded) && typedResult.excluded.length > 0 && (
            <details>
              <summary>Changes excluded from counterfactual search</summary>
              <EvidenceValue value={typedResult.excluded} />
            </details>
          )}
        </section>
      )}
      <section className={`assessment-finding-workspace${selected ? " has-selection" : ""}`}>
        <div className="assessment-finding-list" aria-label="Findings">
          <h3>Findings</h3>
          <ul>
            {items.map((item, index) => {
              const reason = text(item.value.reason ?? item.value.detail ?? item.value.subject);
              const accessibleName =
                item.kind === "finding"
                  ? `Inspect finding ${item.index + 1}: ${item.title}, ${reason !== "Not recorded" ? `${reason}, ` : ""}${item.outcome}`
                  : `${item.title}: ${item.outcome}`;
              return (
                <li key={item.id}>
                  {item.kind === "gap" && <GapSummary gap={item.value} index={item.index} />}
                  <button
                    data-finding-button
                    type="button"
                    aria-label={accessibleName}
                    aria-pressed={item.id === selection}
                    onKeyDown={(event) => move(event, index)}
                    onClick={() => select(item.id)}
                  >
                    {item.kind === "finding" ? (
                      <>
                        <span className="assessment-sr-only">{`Inspect finding ${item.index + 1}`}</span>
                        <strong>{item.title}</strong>
                        {reason !== "Not recorded" && (
                          <span>
                            <DeviceText text={reason} />
                          </span>
                        )}
                        <small>{item.outcome}</small>
                      </>
                    ) : (
                      <span>
                        {item.title}: {item.outcome}
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
        <div className="assessment-finding-detail">
          {selected ? (
            <>
              <button
                type="button"
                className="assessment-finding-back"
                onClick={() => select(null)}
              >
                Back to findings
              </button>
              <FindingInspector
                item={selected}
                result={typedResult}
                onSaveProposal={onSaveProposal}
                onAskAi={onAskAi}
              />
            </>
          ) : (
            <p className="assessment-note">No finding selected</p>
          )}
        </div>
      </section>
      {service ? (
        <ServiceImpactPane
          result={typedResult as unknown as EvaluateServiceImpactResult}
          loadBucket={loadBucket}
        />
      ) : evaluation.request &&
        evaluation.decided_change &&
        evaluation.open_change &&
        evaluation.open ? (
        <ServiceImpactPane result={evaluation as unknown as EvaluateServiceImpactResult} />
      ) : null}
      <ExactRecord summary="Exact analysis record" value={result} />
    </div>
  );
}
