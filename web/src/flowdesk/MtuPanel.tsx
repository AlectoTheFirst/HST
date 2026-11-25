/** Every number comes from the backend result. */

import { DeviceName } from "../shell/deviceNames";
import type { Hop, MtuConstraint, MtuObservation, MtuResult, MtuStage } from "../api/types";
import "./mtu.css";

const words = (value: string) => value.replaceAll("_", " ");
const bytes = (value: number | null | undefined) => value == null ? "unknown" : `${value.toLocaleString()} B`;
const uncoveredWords: Record<string, string> = {
  "source-endpoint": "source endpoint",
  "destination-endpoint": "destination endpoint",
  "path-beyond-twin": "path beyond the twin",
};
const metrics: Record<MtuConstraint["metric"], string> = {
  l2_max_frame_bytes: "L2 frame without FCS", l2_payload_mtu_bytes: "Ethernet payload", ipv4_mtu_bytes: "IPv4 packet", ipv6_mtu_bytes: "IPv6 packet", path_pmtu_bytes: "IP path", unknown: "Unknown size basis",
};

type HopRef = Pick<Hop, "uid" | "lane" | "shared">;

/** The stages of a result and of its connections, lanes and candidates, once each. */
export function mtuStages(result: MtuResult): MtuStage[] {
  const stages = new Map<string, MtuStage>();
  function visit(value: MtuResult) {
    for (const stage of value.stages ?? []) stages.set(stage.stage_id, stage);
    for (const child of [...value.connections ?? [], ...value.lanes ?? [], ...value.candidates ?? []]) visit(child);
  }
  visit(result);
  return [...stages.values()];
}

/** The result that answers for one lane: the lane entry when the connection
 *  was split by lane, the connection itself otherwise. Null when the response
 *  carries no enabled result. */
export function mtuForLane(result: MtuResult | undefined, lane: number | string): MtuResult | null {
  if (!result || result.mode === "off") return null;
  const wanted = String(lane);
  function find(value: MtuResult): MtuResult | null {
    if (value.lane === wanted) return value;
    for (const child of [...value.lanes ?? [], ...value.connections ?? []]) {
      const hit = find(child);
      if (hit) return hit;
    }
    return null;
  }
  const exact = find(result);
  if (exact) return exact;
  // One lane only: the connection result carries the lane's stages itself.
  if ((result.lanes?.length ?? 0) === 0 && (result.connections?.length ?? 0) === 0) return result;
  return null;
}

function matchingStages(result: MtuResult, subjectUid?: string, lane?: string): MtuStage[] {
  return mtuStages(result).filter((stage) =>
    (!subjectUid || [stage.ingress_subject_uid, stage.egress_subject_uid, stage.peer_subject_uid].includes(subjectUid)) &&
    (lane == null || stage.lane === lane || stage.lane === "shared"),
  );
}

function constraintText(value: MtuConstraint): string {
  const bound = value.bound_kind === "acceptance_lower_bound" ? "accepts at least" : value.bound_kind === "ceiling" ? "ceiling" : "bound unknown";
  return `${metrics[value.metric]} ${value.direction} ${bound} ${bytes(value.value_bytes)}`;
}

function bottlenecks(result: MtuResult): Set<string> {
  return new Set([
    ...(result.bottleneck_stage_ids ?? []),
    ...[...result.connections ?? [], ...result.lanes ?? [], ...result.candidates ?? []].flatMap((r) => [...bottlenecks(r)]),
  ]);
}

export interface MtuMark {
  /** Short text for the hop chip, for example "MTU 1,500 B". */
  text: string;
  /** The full constraint list for a tooltip. */
  title: string;
}

/** Only a hop with a resolved limit gets a mark. */
export function hopMtuMark(result: MtuResult | undefined, hop: HopRef): MtuMark | null {
  if (!result || result.mode === "off") return null;
  const stages = matchingStages(result, hop.uid, hop.shared ? undefined : String(hop.lane));
  const constraints = stages.flatMap((s) => s.constraints ?? []);
  const known = constraints.filter((c) => c.value_bytes != null);
  if (!known.length) return null;
  const smallest = Math.min(...known.map((c) => c.value_bytes as number));
  return { text: `MTU ${bytes(smallest)}`, title: [...new Set(constraints.map(constraintText))].join(", ") };
}

/** The ledger row line. Only a hop with a resolved limit gets one. */
export function MtuHopSummary({ result, hop }: { result?: MtuResult; hop: Hop }) {
  if (!result || result.mode === "off") return null;
  const stages = matchingStages(result, hop.uid, hop.shared ? undefined : String(hop.lane));
  const constraints = stages.flatMap((s) => s.constraints ?? []);
  if (!constraints.some((c) => c.value_bytes != null)) return null;
  return <span className="mtu-hop">{[...new Set(constraints.map(constraintText))].join(", ")}</span>;
}

/** One line for a leg: outcome, known ceiling, guarantee and coverage. */
export function MtuLegSummary({ result, lane }: { result?: MtuResult; lane: number | string }) {
  const value = mtuForLane(result, lane);
  if (!value) return null;
  const outcome = value.mode === "inventory" ? "inventory" : words(value.outcome ?? "unknown");
  const coverage = `${value.coverage?.complete ? "complete" : "incomplete"}${value.coverage?.truncated ? ", truncated" : ""}`;
  return <span className={`mtu-leg mtu-${value.outcome ?? "unknown"}`} aria-label={`MTU leg ${lane}`}>
    <span className="mtu-leg-outcome">MTU {outcome}</span>
    {value.requested_bytes != null && <span>target {bytes(value.requested_bytes)}</span>}
    <span>known ceiling {bytes(value.known_ceiling_bytes)}</span>
    <span>guaranteed {bytes(value.guaranteed_bytes)}</span>
    <span>coverage {coverage}</span>
    {(value.coverage?.uncovered?.length ?? 0) > 0 &&
      <span>not covered: {value.coverage!.uncovered!.map((code) => uncoveredWords[code] ?? words(code)).join(", ")}</span>}
    {(value.candidates?.length ?? 0) > 0 && <span>{value.candidates!.length} candidates</span>}
    {(value.findings?.length ?? 0) > 0 && <span>{value.findings!.length} findings</span>}
  </span>;
}

function Observation({ value }: { value: MtuObservation }) {
  return <details className="mtu-observation">
    <summary>{value.source_field}: {value.raw_value_json} ({words(value.raw_basis ?? "unknown")}) <span className="mtu-help">{words(value.assertion_kind)}, {words(value.resolution_state ?? "unknown")}</span></summary>
    <dl className="mtu-evidence">
      <dt>Normalized</dt><dd>{bytes(value.normalized_value)}, {metrics[value.metric ?? "unknown"]}, {words(value.bound_kind ?? "unknown")}</dd>
      <dt>Subject</dt><dd><DeviceName uid={value.subject_uid} /></dd><dt>Source</dt><dd>{value.source} / {value.source_target}</dd>
      <dt>Profile</dt><dd>{value.profile_id ?? "unknown"} / {value.profile_version ?? "unknown"}</dd>
      <dt>Original observation</dt><dd>{value.observed_at_ms == null ? "Not recorded" : new Date(value.observed_at_ms).toLocaleString()}</dd>
      <dt>Tags</dt><dd>{value.metric === "l2_payload_mtu_bytes" ? "Ethernet/VLAN headers excluded" : <>{words(value.tag_accounting ?? "unknown")}, depth {value.tag_depth ?? "unknown"}, allowance {bytes(value.tag_allowance_bytes)}</>}</dd>
      <dt>Inheritance</dt><dd>{value.policy_ref ?? "None recorded"}, dependencies {(value.dependency_uids ?? []).length ? (value.dependency_uids ?? []).map((uid, i) => <span key={uid}>{i > 0 && ", "}<DeviceName uid={uid} /></span>) : "none recorded"}</dd>
      <dt>Raw evidence</dt><dd>{value.raw_evidence_ref || "No reference recorded"}</dd>
    </dl>
    <details><summary>Full MTU observation</summary><pre className="rawpre">{JSON.stringify(value, null, 2)}</pre></details>
  </details>;
}

function Findings({ result }: { result: MtuResult }) {
  const findings = result.findings ?? [];
  const feedback = result.feedback ?? [];
  if (!findings.length && !feedback.length) return null;
  return <>
    {findings.length > 0 && <details><summary>Findings</summary><ul>{findings.map((finding, i) => <li key={i}><strong>{words(finding.severity ?? "gap")}: </strong>{finding.detail} <code>{finding.code}</code></li>)}</ul></details>}
    {feedback.length > 0 && <details><summary>PMTUD feedback</summary><ul>{feedback.map((item, i) => <li key={i}>{words(item.outcome ?? "not_assessed")}{item.packet ? `: IPv${item.packet.af} ICMP type ${item.packet.icmp_type}, code ${item.packet.icmp_code}` : ": feedback packet not established"}{item.gaps?.length ? `, gaps ${item.gaps.join(", ")}` : ""}</li>)}</ul></details>}
  </>;
}

export function MtuDetails({ result, subjectUid, lane }: { result?: MtuResult; subjectUid?: string; lane?: string }) {
  if (!result || result.mode === "off") return null;
  const stages = matchingStages(result, subjectUid, lane);
  const ids = new Set(stages.flatMap((s) => (s.constraints ?? []).flatMap((c) => [...c.evidence_uids ?? [], ...c.inherited_from ?? []])));
  const observations = (result.observations ?? []).filter((o) => !subjectUid && lane == null || o.subject_uid === subjectUid || ids.has(o.uid));
  const limiting = bottlenecks(result);
  const scoped = lane != null ? mtuForLane(result, lane) : result;
  return <section className="mtu-details" aria-label="MTU enforcement and evidence">
    <h4>MTU enforcement and evidence</h4>
    {scoped && !subjectUid && <Findings result={scoped} />}
    {!stages.length && <p>No enforcement stages</p>}
    <ol className="mtu-stages">{stages.map((stage) => <li key={stage.stage_id} className={limiting.has(stage.stage_id) ? "mtu-limiting" : undefined}>
      <div className="mtu-heading"><strong>{words(stage.enforcement ?? "unknown")} / {stage.context.direction ?? "tx"}</strong><span>{limiting.has(stage.stage_id) ? "Bottleneck" : words(stage.applicability ?? "unknown")}</span></div>
      <p className="mtu-help">{stage.direction ?? "forward"}, connection {stage.connection_id ?? "original"}, lane {stage.lane ?? "unknown"}, {stage.selection ?? "unknown"} path, IPv{stage.context.af}, tags {stage.context.tag_depth ?? "unknown"}, class {stage.context.traffic_class ?? "unknown"}</p>
      <p className="mtu-subject">{stage.ingress_subject_uid ?? stage.egress_subject_uid ? <DeviceName uid={(stage.ingress_subject_uid ?? stage.egress_subject_uid)!} /> : "Unresolved endpoint or transit stretch"}{stage.peer_subject_uid ? <>, peer <DeviceName uid={stage.peer_subject_uid} /></> : ""}</p>
      {(stage.constraints?.length ?? 0) ? <ul>{stage.constraints!.map((constraint, i) => <li key={i}>{constraintText(constraint)}<span className="mtu-help">, evidence {(constraint.evidence_quality ?? []).map(words).join(", ") || "unknown"}{constraint.inherited_from?.length ? `, inherited from ${constraint.inherited_from.join(", ")}` : ""}</span></li>)}</ul> : <p>{stage.applicability === "not_applicable" ? "No MTU enforcement" : "No resolved limit"}</p>}
      {(stage.encapsulation?.length ?? 0) > 0 && <p>Encapsulation: {stage.encapsulation!.map((e) => `${e.kind} (${e.operation ?? "encapsulate"}, profile ${e.profile_id ?? "unknown"})`).join(", ")}</p>}
      {(stage.coverage?.gaps?.length ?? 0) > 0 && <p className="mtu-help">Gaps: {stage.coverage!.gaps!.join(", ")}</p>}
    </li>)}</ol>
    <details><summary>Raw and normalized evidence</summary>{observations.length ? observations.map((observation) => <Observation key={observation.uid} value={observation} />) : <p>No observations</p>}</details>
  </section>;
}
