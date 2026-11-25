import type { MtuRequest } from "../api/types";

export interface Condition {
  kind: "member" | "and" | "or" | "threshold";
  member?: string;
  n?: number;
  parts?: Condition[];
}

export interface Member {
  name: string;
  addresses: string[];
  proto?: string | null;
  port?: string | null;
  source_port?: string | null;
}

export interface Requirement {
  mtu?: MtuRequest | null;
  name: string;
  destination: string;
  sources: string[];
  members: Member[];
  condition: Condition;
  proto?: string | null;
  port?: string | null;
  source_port?: string | null;
  success: string;
  source_context?: string | null;
  source_device_uid?: string | null;
  identity_uid?: string | null;
  segment_uid?: string | null;
}

export interface Intent { kind: string; params: Record<string, unknown> }
export interface Definition {
  request?: Requirement;
  requirement?: string;
  intents: Intent[];
  mode: string;
  snapshot: string;
  freshness_s: number;
  deployments?: Record<string, unknown>[];
  collection_actions?: Record<string, unknown>[];
  origin_requirement?: string | null;
  origin_snapshot?: string | null;
  requirement_id?: string | null;
  requirement_revision?: number | null;
  change_id?: string;
  change_revision?: number;
  priority?: number;
}
export interface AssessmentDraft { title: string; definition: Definition; kind?: AnalysisKind; analysis?: Record<string, unknown> }
export interface SavedRequirement {
  id: string;
  revision: number;
  title: string;
  definition: Definition;
  created_at: string;
}
export interface Assessment {
  id: string;
  title: string;
  revision: number;
  definition: Definition;
  created_at: string;
  updated_at: string;
  freshness?: { state: string; reason?: string };
}
export type AnalysisKind = "evaluate" | "troubleshoot" | "regression" | "repair" | "resilience" | "verify";
export interface AnalysisRun {
  id: string;
  kind: AnalysisKind;
  state: string;
  inputs: Record<string, unknown>;
  result: Record<string, unknown> | null;
  error?: unknown;
  created_at: string;
  progress?: Record<string, unknown>;
  assessment_revision?: number;
  engine_version?: string;
}
export interface AssessmentDetail {
  assessment: Assessment;
  runs: AnalysisRun[];
  deployments?: Record<string, unknown>[];
  revisions?: Assessment[];
  proposals?: import("./ProposalPanel").Proposal[];
  freshness?: { state: string; reasons?: string[]; causes?: string[] };
}

export function emptyRequirement(): Requirement {
  return {
    name: "", destination: "", sources: [],
    members: [{ name: "member-1", addresses: [] }],
    condition: { kind: "member", member: "member-1" },
    success: "forward",
  };
}
export function list(value: string): string[] {
  return value.split(/[\s,]+/).map((part) => part.trim()).filter(Boolean);
}
export function conditionSentence(condition: Condition): string {
  if (condition.kind === "member") return condition.member || "Select a member";
  const parts = (condition.parts ?? []).map(conditionSentence).join(", ");
  return `${condition.kind === "and" ? "All" : condition.kind === "or" ? "Any" : `At least ${condition.n ?? 1}`} of (${parts})`;
}
export function requirementError(request: Requirement): string | null {
  const mtu = request.mtu;
  if (mtu && mtu.mode !== "off") {
    const ipv6 = request.sources.some((source) => source.includes(":"));
    const low = ipv6 ? 40 : 20, high = ipv6 ? 65575 : 65535;
    const validLength = (n: number | null | undefined) => n == null || (Number.isInteger(n) && n >= low && n <= high);
    if ((mtu.mode === "unfragmented" || mtu.mode === "packet") && mtu.ip_packet_bytes == null) return "MTU requirement without a complete IP packet size";
    if (!validLength(mtu.ip_packet_bytes) || !validLength(mtu.reply_ip_packet_bytes)) return `MTU packet sizes in whole bytes from ${low} to ${high}`;
    if (ipv6 && mtu.ipv4_df != null) return "IPv4 Don't Fragment set on an IPv6 requirement";
  }
  if (!request.name.trim() || !request.destination.trim()) return "Requirement name or logical destination missing";
  if (!request.sources.length) return "No client address or prefix";
  if (!request.members.length || request.members.some((m) => !m.name.trim() || !m.addresses.length)) return "Destination member without a name or an address";
  const names = new Set(request.members.map((m) => m.name));
  if (names.size !== request.members.length) return "Destination member names not unique";
  const valid = (c: Condition): boolean => c.kind === "member" ? names.has(c.member ?? "")
    : !!c.parts?.length && c.parts.every(valid) && (c.kind !== "threshold" || (Number.isInteger(c.n) && c.n! > 0 && c.n! <= c.parts.length));
  return valid(request.condition) ? null : "Success condition incomplete or threshold above the number of parts";
}
export function isRunning(state: string): boolean { return ["queued", "pending", "running", "cancelling"].includes(state); }
