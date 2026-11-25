import type { ResultValue } from "../results/text";
/** The parsers read the tool results of the comparison panes out of a chat transcript. */

import type { AgentContextEntry, AgentStep, MtuRequest } from "../api/types";

export interface ImpactDevice {
  uid: string;
  hostname: string | null;
  role: string | null;
  software_version: string | null;
  platform: string | null;
  vendor: string | null;
  model: string | null;
}

export interface ImpactBucket<T> {
  count: number;
  items: T[];
  truncated: boolean;
}

interface GatewayPrefixItem {
  uid: string;
  cidr: string | null;
  kind: string | null;
  l3dom: string | null;
  other_devices?: string[];
}

interface SingleHomedPrefixItem {
  uid: string;
  cidr: string | null;
  kind: string | null;
  l3dom: string | null;
}

interface AttachedEndpointItem {
  uid: string;
  name: string | null;
  kind: string | null;
  other_devices?: string[];
}

interface SingleHomedEndpointItem {
  uid: string;
  name: string | null;
  kind: string | null;
}

interface RedundancyMemberRef {
  uid: string;
  hostname: string | null;
}

interface RedundancyGroupItem {
  uid: string;
  kind: string | null;
  name: string | null;
  role: string | null;
  other_members: RedundancyMemberRef[];
  has_other_members: boolean;
}

interface InterfaceItem {
  uid: string;
  name: string | null;
  kind: string | null;
}

interface TunnelItem {
  uid: string;
  encap: string | null;
  state: string | null;
}

interface BgpSessionItem {
  uid: string;
  local_ip: string | null;
  peer_ip: string | null;
  peer_asn: number | string | null;
  kind: string | null;
  state: string | null;
}

interface FhrpGroupItem {
  uid: string;
  kind: string | null;
  group_id: string | number | null;
  vip: string | null;
  interfaces: string[];
  other_devices: string[];
}

export interface AssessImpactResult {
  /** The run id (`ts_ms` as a string) this prediction is pinned to, or null
   *  when the graph carries no run pointer at all. */
  snapshot: string | null;
  device: ImpactDevice;
  single_homed_prefixes: ImpactBucket<SingleHomedPrefixItem>;
  single_homed_endpoints: ImpactBucket<SingleHomedEndpointItem>;
  gateway_prefixes: ImpactBucket<GatewayPrefixItem>;
  attached_endpoints: ImpactBucket<AttachedEndpointItem>;
  redundancy_groups: ImpactBucket<RedundancyGroupItem>;
  interfaces: ImpactBucket<InterfaceItem>;
  tunnels: ImpactBucket<TunnelItem>;
  bgp_sessions: ImpactBucket<BgpSessionItem>;
  fhrp_groups: ImpactBucket<FhrpGroupItem>;
  /** `assess_impact` emits no model errors. */
  model_errors?: string[];
}

const BUCKET_KEYS = [
  "single_homed_prefixes",
  "single_homed_endpoints",
  "gateway_prefixes",
  "attached_endpoints",
  "redundancy_groups",
  "interfaces",
  "tunnels",
  "bgp_sessions",
  "fhrp_groups",
] as const;

function isBucket(value: unknown): value is ImpactBucket<unknown> {
  return (
    !!value &&
    typeof value === "object" &&
    Array.isArray((value as { items?: unknown }).items) &&
    typeof (value as { count?: unknown }).count === "number"
  );
}

/** An already-parsed value as an `assess_impact` payload, or null when it is
 *  not shaped like one. The same check both a tool step's JSON text and the
 *  server's `context` entry go through. */
function asAssessImpact(parsed: unknown): AssessImpactResult | null {
  if (!parsed || typeof parsed !== "object") return null;
  const obj = parsed as Record<string, unknown>;
  if (!obj.device || typeof obj.device !== "object") return null;
  for (const key of BUCKET_KEYS) {
    if (!isBucket(obj[key])) return null;
  }
  return obj as unknown as AssessImpactResult;
}

/** Returns null for a raw `result` that is not JSON shaped like an `assess_impact` payload. */
export function parseAssessImpact(raw: string): AssessImpactResult | null {
  try {
    return asAssessImpact(JSON.parse(raw));
  } catch {
    return null;
  }
}

/** An `impact_assess` envelope with subject device, as the payload above.
 *  A link subject lists no device buckets and is null here. */
function assessFromEnvelope(parsed: unknown): AssessImpactResult | null {
  const envelope = asEnvelope(parsed);
  if (!envelope) return null;
  const { subject, device, buckets } = envelope.result;
  if (subject !== "device" || !buckets || typeof buckets !== "object") return null;
  return asAssessImpact({ ...(buckets as Record<string, unknown>), device, snapshot: envelope.snapshot.id });
}

/** Parse one `impact_assess` step's raw `result` string. Returns null for
 *  anything that is not a device envelope, a truncated result included. */
export function parseImpactAssess(raw: string): AssessImpactResult | null {
  try {
    return assessFromEnvelope(JSON.parse(raw));
  } catch {
    return null;
  }
}

/* --- resolve_address ------------------------------------------------------ */

interface AddressAttachment {
  uid: string;
  name: string | null;
  ssid: string | null;
  kind: string | null;
}

interface AddressBridgeDomain {
  uid: string;
  name: string | null;
}

interface AddressIpNode {
  uid: string;
  anchor: string | null;
  l3dom: string | null;
  af: string | number | null;
}

interface AddressEndpoint {
  uid: string;
  mac: string | null;
  kind: string | null;
  name: string | null;
  ip_uid: string | null;
  anchor: string | null;
  attached: AddressAttachment[];
  bridge_domains: AddressBridgeDomain[];
}

interface AddressInterface {
  uid: string;
  name: string | null;
  kind: string | null;
  ip_uid: string | null;
  anchor: string | null;
  device_uid: string | null;
  device_hostname: string | null;
}

interface AddressBgpSession {
  uid: string;
  peer_ip: string | null;
  local_asn: number | string | null;
  peer_asn: number | string | null;
  import_policy_name: string | null;
  import_policy_kind: string | null;
  export_policy_name: string | null;
  export_policy_kind: string | null;
  process_uid: string | null;
  process_proto: string | null;
  process_asn: number | string | null;
  vrf_uid: string | null;
  vrf_name: string | null;
}

interface AddressNextHopRoute {
  kind: string | null;
  prefix: string | null;
  prefix_uid: string | null;
  protocol: string | null;
  metric: number | string | null;
  interface: string | null;
  vrf_uid: string | null;
  vrf_name: string | null;
}

export interface ResolveAddressResult {
  address: string;
  /** The run id this lookup was pinned to, or null when the graph carries no
   *  run pointer at all. */
  snapshot: string | null;
  limit_per_section: number;
  ip_nodes: AddressIpNode[];
  endpoints: AddressEndpoint[];
  interfaces: AddressInterface[];
  bgp_sessions: AddressBgpSession[];
  next_hop_routes: AddressNextHopRoute[];
}

const ADDRESS_SECTION_KEYS = [
  "ip_nodes",
  "endpoints",
  "interfaces",
  "bgp_sessions",
  "next_hop_routes",
] as const;

/** An already-parsed value as a `resolve_address` payload, or null when it is
 *  not shaped like one. */
function asResolveAddress(parsed: unknown): ResolveAddressResult | null {
  if (!parsed || typeof parsed !== "object") return null;
  const obj = parsed as Record<string, unknown>;
  if (typeof obj.address !== "string") return null;
  for (const key of ADDRESS_SECTION_KEYS) {
    if (!Array.isArray(obj[key])) return null;
  }
  return obj as unknown as ResolveAddressResult;
}

/** Returns null for a raw `result` that is not JSON shaped like a `resolve_address` payload. */
export function parseResolveAddress(raw: string): ResolveAddressResult | null {
  try {
    return asResolveAddress(JSON.parse(raw));
  } catch {
    return null;
  }
}

/** The rows `inventory_resolve` lists per section
 *  (src/hst/twin_tools/inventory.py: ADDRESS_SECTION_ROWS). */
const ADDRESS_SECTION_ROWS = 10;

/** An `inventory_resolve` envelope with kind address, as the payload above:
 *  each section's rows at the top level. */
function addressFromEnvelope(parsed: unknown): ResolveAddressResult | null {
  const envelope = asEnvelope(parsed);
  if (!envelope) return null;
  const { kind, address, sections } = envelope.result;
  if (kind !== "address" || !sections || typeof sections !== "object") return null;
  const flat: Record<string, unknown> = {
    address,
    snapshot: envelope.snapshot.id,
    limit_per_section: ADDRESS_SECTION_ROWS,
  };
  for (const key of ADDRESS_SECTION_KEYS) {
    const section = (sections as Record<string, unknown>)[key];
    flat[key] = section && typeof section === "object" ? (section as { rows?: unknown }).rows : undefined;
  }
  return asResolveAddress(flat);
}

/** Parse one `inventory_resolve` step's raw `result` string. Returns null for
 *  anything that is not an address envelope, a truncated result included. */
export function parseInventoryResolve(raw: string): ResolveAddressResult | null {
  try {
    return addressFromEnvelope(JSON.parse(raw));
  } catch {
    return null;
  }
}

/* --- predict_routes ------------------------------------------------------- */

interface PredictedRoute {
  context_uid: string;
  prefix: string | null;
  next_hop: string | null;
  protocol: string | null;
  metric: number | string | null;
  local_pref: number | string | null;
  med: number | string | null;
  weight: number | string | null;
  as_path: (number | string)[];
  origin: string | null;
  origin_mechanism: string | null;
  session_protocol: string | null;
  admin: number | string | null;
  communities: string[];
  originator_ip: string | null;
  cluster_list: string[];
  tag: number | string | null;
}

interface PredictedVrf {
  context_uid: string;
  row_count: number;
  truncated: boolean;
  rows: PredictedRoute[];
}

/** One named model error: `kind` groups, `detail` is prose, `subject` names the
 *  config object (src/hst/simul/errors.py). */
export interface ModelError {
  kind: string;
  detail: string;
  subject: string | null;
}

export interface PredictRoutesResult {
  scope: string;
  scope_kind: string;
  snapshot: string | null;
  /** The row cap per VRF of a `predict_routes` result. A `routing_predict_routes`
   *  result has no cap here. The `truncated` of each VRF states whether its rows were cut. */
  row_limit_per_vrf?: number;
  row_count: number;
  truncated: boolean;
  vrfs: PredictedVrf[];
  model_errors: ModelError[];
  /** Present only when at least one VRF was capped; the tool's own wording. */
  truncation?: string;
}

function isPredictedVrf(value: unknown): value is PredictedVrf {
  return (
    !!value &&
    typeof value === "object" &&
    typeof (value as { context_uid?: unknown }).context_uid === "string" &&
    Array.isArray((value as { rows?: unknown }).rows)
  );
}

/** Returns null for a raw `result` that is not JSON shaped like a `predict_routes` payload. */
export function parsePredictRoutes(raw: string): PredictRoutesResult | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const obj = parsed as Record<string, unknown>;
  if (!Array.isArray(obj.vrfs) || !Array.isArray(obj.model_errors)) return null;
  if (!obj.vrfs.every(isPredictedVrf)) return null;
  return obj as unknown as PredictRoutesResult;
}

/** Parse one `routing_predict_routes` step's raw `result` string. Each VRF of
 *  the envelope's page becomes one VRF of the payload above, its
 *  `rows_truncated` as `truncated`; `row_count` sums the VRFs of the page.
 *  Returns null for anything that is not such an envelope. */
export function parseRoutingPredictRoutes(raw: string): PredictRoutesResult | null {
  const envelope = parseEnvelope(raw);
  if (!envelope) return null;
  const { scope, scope_kind, vrfs, model_errors } = envelope.result;
  if (typeof scope !== "string" || !Array.isArray(vrfs) || !Array.isArray(model_errors)) return null;
  const mapped: PredictedVrf[] = [];
  for (const entry of vrfs) {
    if (!entry || typeof entry !== "object") return null;
    const vrf = entry as Record<string, unknown>;
    if (typeof vrf.context_uid !== "string" || !Array.isArray(vrf.rows)) return null;
    mapped.push({
      context_uid: vrf.context_uid,
      row_count: typeof vrf.row_count === "number" ? vrf.row_count : vrf.rows.length,
      truncated: vrf.rows_truncated === true,
      rows: vrf.rows as PredictedRoute[],
    });
  }
  return {
    scope,
    scope_kind: typeof scope_kind === "string" ? scope_kind : "",
    snapshot: envelope.snapshot.id,
    row_count: mapped.reduce((sum, vrf) => sum + vrf.row_count, 0),
    truncated: mapped.some((vrf) => vrf.truncated) || envelope.page?.truncated === true,
    vrfs: mapped,
    model_errors: model_errors as ModelError[],
  };
}

/* --- simulate_policy_change ----------------------------------------------- */

interface FlowSummary {
  /** the tracer's prose on the walk */
  detail: string | null;
  /** whether the rule set permits the flow */
  result: ResultValue;
  indeterminate: boolean;
  blocked: boolean;
  decided_by: string[];
  dnat: string[];
  snat: string[];
  warnings: string[];
}

/** One side of a compared path: what the trace on that side decided, and the
 *  rule it decided by. Null where only the other side records the path. */
export interface PathSide {
  blocked: boolean;
  indeterminate: boolean;
  decided_by: string | null;
  rulebase: string | null;
  /** the tracer's prose on the path */
  detail: string | null;
  /** whether the device forwards the flow at this hop */
  result: ResultValue | null;
}

/** The MTU view of one side of a compared path group: the outcome, the known
 *  ceiling, and which subjects the bottleneck stage(s) sit on. Present only
 *  when the flow carried an `mtu` request; a flow that did not carries
 *  neither `mtu_before` nor `mtu_after` on any of its groups. */
export interface MtuPathSide {
  outcome: "not_assessed" | "pass" | "fail" | "unknown" | "fragmentation_required" | "conditional" | null;
  known_ceiling_bytes: number | null;
  bottleneck: string[];
  uncovered: string[];
}

/** The paths that share an outcome before, an outcome after, an egress interface and an explanation. */
export interface PathGroup {
  path_count: number;
  destinations: string[];
  destination_count: number;
  next_hops: string[];
  next_hop_count: number;
  egress: string | null;
  before: PathSide | null;
  after: PathSide | null;
  changed: boolean;
  sample_truncated: boolean;
  note?: string;
  /** Present only when the flow carried an `mtu` request: the MTU outcome on
   *  this group's lead path, before and after. An outcome change here makes
   *  `changed` true even where the firewall result (`before`/`after` above)
   *  never moves. */
  mtu_before?: MtuPathSide;
  mtu_after?: MtuPathSide;
}

/** One flow's paths, before beside after. */
export interface FlowPaths {
  groups: PathGroup[];
  group_count: number;
  truncated: boolean;
  path_count_before: number;
  path_count_after: number;
  blocked_before: number;
  blocked_after: number;
  indeterminate_after: number;
  changed: number;
}

export interface SimulatedFlowSpec {
  src?: string | null;
  dst?: string | null;
  port?: number | string | null;
  proto?: string | null;
  /** {mode, ip_packet_bytes, ipv4_df, traffic_class} -- the same request
   *  trace_path and GET /api/path take. `reply_ip_packet_bytes` is never set
   *  here: a change simulation traces the forward direction only. */
  mtu?: Omit<MtuRequest, "reply_ip_packet_bytes"> | null;
}

export interface SimulatedFlow {
  flow: SimulatedFlowSpec;
  before: FlowSummary;
  after: FlowSummary;
  result_changed: boolean;
  blocked_changed: boolean;
  /** The structure behind the detail line. */
  paths?: FlowPaths;
  /** null when the check could not run. */
  crosses_a_changed_device?: boolean | null;
  /** Set by the API when the basis of the before-and-after comparison is not established. */
  basis_uncertain?: boolean;
  /** Why the basis is not established, one statement each; present only with
   *  `basis_uncertain`. */
  basis_uncertain_reasons?: string[];
  /** Present when the flow crosses none of the changed devices (its result says
   *  nothing about the change), or when its comparison is not established. The
   *  `kind` tells the two apart. */
  model_error?: ModelError;
}

/** The `ModelError.kind` of a flow that crosses none of the devices the change
 *  set alters. */
export const FLOW_OUTSIDE_CHANGE = "flow-does-not-cross-the-changed-device";

/** Whether the API did not establish the comparison of this flow. A flow is
 *  never read as changed or unchanged on a basis that is not established. */
export function flowNotEstablished(flow: SimulatedFlow): boolean {
  return flow.basis_uncertain === true;
}

/** The reasons the API gives for a flow whose comparison is not established;
 *  empty for a flow whose comparison is. */
export function flowBasisReasons(flow: SimulatedFlow): string[] {
  const reasons = flow.basis_uncertain_reasons;
  return Array.isArray(reasons) ? reasons.filter((r): r is string => typeof r === "string" && r !== "") : [];
}

/** How many flows have a comparison that is not established: the API's own
 *  count, else the flows that carry the flag. */
export function resultsNotEstablished(policy: SimulatePolicyChangeResult): number {
  const stated = policy.results_not_established;
  if (typeof stated === "number" && Number.isFinite(stated)) return stated;
  return (policy.flows ?? []).filter(flowNotEstablished).length;
}

/** One recorded next hop of one prefix, in one VRF. `withdrawn_because` is
 *  present only on a next hop the change set removes. */
export interface NextHopRecord {
  next_hop: string;
  kind: string;
  protocol: string | null;
  interface: string | null;
  metric: number | string | null;
  withdrawn_because?: string;
}

interface WithdrawnPrefix {
  prefix: string;
  next_hops_before: NextHopRecord[];
  next_hops_after: NextHopRecord[];
  withdrawn_next_hops: NextHopRecord[];
  no_next_hop_left: boolean;
  /** The levels of the dependency walk for this prefix. */
  level?: number;
  no_next_hop_left_at_level?: number | null;
}

/** One level of the next-hop dependency walk, as counts. */
interface WithdrawalLevel {
  level: number;
  prefix_count: number;
  prefixes_with_no_next_hop_left: number;
  withdrawn_route_edge_count: number;
  vrf_count: number;
  sample: string[];
  sample_truncated: boolean;
}

/** `complete` false means that a limit cut the answer short. */
export interface WithdrawalWalk {
  depth_requested?: number;
  depth?: number;
  depth_cap?: number;
  depth_clamped?: boolean;
  levels_walked?: number;
  levels?: WithdrawalLevel[];
  level_count?: number;
  complete?: boolean;
  limits?: string[];
  prefixes_not_followed_at_the_depth_limit?: number;
  prefixes_not_followed_at_the_site_boundary?: number;
  definition?: string;
  note?: string;
}

/** Present only when the caller named sites. */
export interface WithdrawalSiteScope {
  sites_requested?: string[];
  sites_resolved?: string[];
  sites_not_found?: string[];
  vrfs_in_scope?: number;
  vrfs_outside_the_selected_sites?: number;
  vrfs_with_no_recorded_site?: number;
  stopped_the_walk?: boolean;
  prefixes_not_followed?: number;
  withdrawn_route_edges_not_followed?: number;
  vrfs_not_followed?: string[];
  vrfs_not_followed_count?: number;
  vrfs_not_followed_truncated?: boolean;
  basis?: string;
  note?: string;
}

interface WithdrawalVrf {
  context_uid: string;
  prefix_count: number;
  prefixes_with_no_next_hop_left: number;
  truncated: boolean;
  prefixes: WithdrawnPrefix[];
}

interface NextHopWithdrawal {
  vrfs: WithdrawalVrf[];
  prefix_count: number;
  prefixes_with_no_next_hop_left: number;
  withdrawn_route_edge_count: number;
  truncated: boolean;
  truncation?: string;
}

/** A BGP session the change set's denied addresses name, as an address
 *  dependency: the session peers through a denied address, which is a fact
 *  about the address, not a prediction that the session goes down. */
export interface RoutingBgpSessionDependency {
  uid: string;
  peer_ip?: string;
  peer_asn?: number;
  local_asn?: number;
  process_uid?: string;
  context_uid?: string;
}

export interface RoutingConsequence {
  /** The follow-on in one sentence, at the prefix level, in counts. */
  headline?: string;
  /** Always "address-dependency": this result names which recorded routes and
   *  sessions depend on a denied address, not an evaluation of effective
   *  policy or a control-plane prediction. */
  evaluation?: string;
  basis?: string;
  direction_rule?: string;
  denied_addresses?: { traffic_to: string[]; traffic_from: string[] };
  /** null when the change denies an address a peering uses but no recorded
   *  route names as a next hop. */
  next_hop_withdrawal?: NextHopWithdrawal | null;
  /** The depth the walk ran at, the per-level counts, and whether a limit stopped it. */
  walk?: WithdrawalWalk;
  /** Present only when the call named sites. */
  site_scope?: WithdrawalSiteScope;
  static_routes_kept_under_a_source_side_deny?: unknown[];
  /** The BGP sessions that peer through a denied address. */
  bgp_sessions_to_a_denied_address?: RoutingBgpSessionDependency[];
  /** The tool's own wording: a session listed above needs a context-scoped
   *  control-plane evaluation before a shutdown can be predicted for it. */
  bgp_sessions_to_a_denied_address_note?: string;
  /** Always empty from an address match: an address dependency does not by
   *  itself propose a `bgp_session.shut` intent. */
  implied_intents?: { kind: string; params: Record<string, unknown> }[];
  /** The route engine's own rows, computed only for an explicit `bgp_session.shut` intent. */
  predicted_prefixes_withdrawn?: PredictedBgpRow[];
  predicted_withdrawn_count?: number;
  predicted_prefixes_added?: PredictedBgpRow[];
  predicted_added_count?: number;
  predicted_rows_changed?: PredictedRowChange[];
  predicted_changed_count?: number;
  scopes_predicted?: string[];
  /** The tool's own wording naming which keys are the protocol-specific
   *  prediction and which the recorded next-hop dependency. */
  bgp_prediction?: string;
}

/** One predicted RIB row as the route engine produced it. */
export type PredictedBgpRow = Partial<PredictedRoute> & { context_uid: string; prefix: string };

interface PredictedRowChange {
  context_uid: string;
  prefix: string;
  before: PredictedBgpRow;
  after: PredictedBgpRow;
}

export interface SimulatePolicyChangeResult {
  /** The run id this simulation is pinned to, or null when the graph carries no
   *  run pointer at all. */
  snapshot: string | null;
  intents: { kind: string; params: Record<string, unknown> }[];
  flow_count: number;
  /** The flows whose result changed and whose basis is established. */
  results_changed: number;
  /** The flows whose comparison is not established. */
  results_not_established?: number;
  /** "7 of 13 paths blocked" is `paths_blocked_after` of `path_count_after`. */
  path_count_before?: number;
  path_count_after?: number;
  paths_blocked_before?: number;
  paths_blocked_after?: number;
  paths_changed?: number;
  flows: SimulatedFlow[];
  changed_devices: string[];
  /** uid -> hostname for the changed devices that record one. */
  changed_device_hostnames?: Record<string, string>;
  /** Every subject an `interface.set_mtu` intent in this change set touched:
   *  the changed interface itself, plus its own physical Port where the
   *  catalog knows one. Empty for a change set with no MTU intent. */
  mtu_subjects?: string[];
  /** The tool's own wording, present only when it chose the flows itself. */
  flows_derived?: string;
  /** How many flows the derivation traced, and how many candidates its cap left out. */
  flows_derived_count?: number;
  flows_derived_not_traced?: number;
  flows_derived_truncated?: boolean;
  routing_consequence?: RoutingConsequence;
  model_errors: ModelError[];
}

/** Returns null for a raw `result` that is not JSON shaped like a `simulate_policy_change` payload. */
export function parseSimulatePolicyChange(raw: string): SimulatePolicyChangeResult | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const obj = parsed as Record<string, unknown>;
  if (!Array.isArray(obj.flows) || !Array.isArray(obj.model_errors)) return null;
  if (typeof obj.flow_count !== "number") return null;
  return obj as unknown as SimulatePolicyChangeResult;
}

/** Parse one `change_simulate` step's raw `result` string: the envelope's
 *  result, with the run its `snapshot.id` names, as the payload above.
 *  Returns null for anything that is not such an envelope. */
export function parseChangeSimulate(raw: string): SimulatePolicyChangeResult | null {
  const envelope = parseEnvelope(raw);
  return envelope ? parseSimulatePolicyChange(JSON.stringify(flatten(envelope))) : null;
}

/* --- catalogue envelopes ---------------------------------------------------
 *
 * The envelope every catalogue tool answers with
 * (src/hst/twin_tools/envelope.py). Only the fields the panes read are
 * typed here.
 */

interface Envelope {
  snapshot: { id: string | null };
  result: Record<string, unknown>;
  page?: { truncated?: boolean };
}

function asEnvelope(parsed: unknown): Envelope | null {
  if (!parsed || typeof parsed !== "object") return null;
  const obj = parsed as Record<string, unknown>;
  const snapshot = obj.snapshot as Record<string, unknown> | null | undefined;
  const result = obj.result;
  if (!snapshot || typeof snapshot !== "object") return null;
  if (!obj.provenance || typeof obj.provenance !== "object") return null;
  if (!result || typeof result !== "object" || Array.isArray(result)) return null;
  const id = snapshot.id;
  return {
    snapshot: { id: typeof id === "string" ? id : null },
    result: result as Record<string, unknown>,
    page: (obj.page ?? undefined) as Envelope["page"],
  };
}

function parseEnvelope(raw: string): Envelope | null {
  try {
    return asEnvelope(JSON.parse(raw));
  } catch {
    return null;
  }
}

function flatten(envelope: Envelope): Record<string, unknown> {
  return { ...envelope.result, snapshot: envelope.snapshot.id };
}

/* --- finding a pane's result in the transcript ---------------------------- */

/** The most recent successful call to any of `parsers`' tools, most recent turn first. */
function latestToolResult<T>(
  turns: readonly { steps?: AgentStep[] }[],
  parsers: Readonly<Record<string, (raw: string) => T | null>>,
): T | null {
  return latestToolStep(turns, parsers)?.value ?? null;
}

/** The step behind `latestToolResult`, with its parsed result. */
function latestToolStep<T>(
  turns: readonly { steps?: AgentStep[] }[],
  parsers: Readonly<Record<string, (raw: string) => T | null>>,
): { step: AgentStep; value: T } | null {
  for (let i = turns.length - 1; i >= 0; i--) {
    const steps = turns[i].steps;
    if (!steps) continue;
    for (let j = steps.length - 1; j >= 0; j--) {
      const step = steps[j];
      if (step.is_error) continue;
      const parse = parsers[step.name];
      if (!parse) continue;
      const parsed = parse(step.result);
      if (parsed) return { step, value: parsed };
    }
  }
  return null;
}

/** What the Baseline pane draws: what the pinned snapshot records, from either
 *  kind of result that records it. */
export type BaselineResult =
  | { tool: "assess_impact"; impact: AssessImpactResult }
  | { tool: "resolve_address"; address: ResolveAddressResult };

/** What the Predicted pane draws: what an engine computes over the pinned
 *  snapshot, from any kind of result that computes it. */
export type PredictedResult =
  | { tool: "assess_impact"; impact: AssessImpactResult }
  | { tool: "predict_routes"; routes: PredictRoutesResult }
  | { tool: "simulate_policy_change"; policy: SimulatePolicyChangeResult };

/** The Baseline result that the server read for the question (src/hst/app/agent/context.py). */
export function baselineFromContext(
  turns: readonly { context?: AgentContextEntry[] }[],
): BaselineResult | null {
  for (let i = turns.length - 1; i >= 0; i--) {
    for (const entry of turns[i].context ?? []) {
      if (entry.tool === "impact_assess" || entry.tool === "assess_impact") {
        const impact =
          entry.tool === "impact_assess" ? assessFromEnvelope(entry.result) : asAssessImpact(entry.result);
        if (impact) return { tool: "assess_impact", impact };
      } else if (entry.tool === "inventory_resolve" || entry.tool === "resolve_address") {
        const address =
          entry.tool === "inventory_resolve" ? addressFromEnvelope(entry.result) : asResolveAddress(entry.result);
        if (address) return { tool: "resolve_address", address };
      }
    }
  }
  return null;
}

function asBaselineImpact(parse: (raw: string) => AssessImpactResult | null) {
  return (raw: string): BaselineResult | null => {
    const impact = parse(raw);
    return impact ? { tool: "assess_impact", impact } : null;
  };
}

function asBaselineAddress(parse: (raw: string) => ResolveAddressResult | null) {
  return (raw: string): BaselineResult | null => {
    const address = parse(raw);
    return address ? { tool: "resolve_address", address } : null;
  };
}

function asPredicted<T>(parse: (raw: string) => T | null, wrap: (value: T) => PredictedResult) {
  return (raw: string): PredictedResult | null => {
    const value = parse(raw);
    return value ? wrap(value) : null;
  };
}

/** The Baseline pane's parsers, by step name. */
const BASELINE_PARSERS: Readonly<Record<string, (raw: string) => BaselineResult | null>> = {
  impact_assess: asBaselineImpact(parseImpactAssess),
  inventory_resolve: asBaselineAddress(parseInventoryResolve),
  assess_impact: asBaselineImpact(parseAssessImpact),
  resolve_address: asBaselineAddress(parseResolveAddress),
};

/** The Predicted pane's parsers, by step name. */
const PREDICTED_PARSERS: Readonly<Record<string, (raw: string) => PredictedResult | null>> = {
  impact_assess: asPredicted(parseImpactAssess, (impact) => ({ tool: "assess_impact", impact })),
  routing_predict_routes: asPredicted(parseRoutingPredictRoutes, (routes) => ({ tool: "predict_routes", routes })),
  change_simulate: asPredicted(parseChangeSimulate, (policy) => ({ tool: "simulate_policy_change", policy })),
  assess_impact: asPredicted(parseAssessImpact, (impact) => ({ tool: "assess_impact", impact })),
  predict_routes: asPredicted(parsePredictRoutes, (routes) => ({ tool: "predict_routes", routes })),
  simulate_policy_change: asPredicted(parseSimulatePolicyChange, (policy) => ({
    tool: "simulate_policy_change",
    policy,
  })),
};

export function latestBaseline(turns: readonly { steps?: AgentStep[] }[]): BaselineResult | null {
  return latestToolResult<BaselineResult>(turns, BASELINE_PARSERS);
}

export function latestPredicted(turns: readonly { steps?: AgentStep[] }[]): PredictedResult | null {
  return latestToolResult<PredictedResult>(turns, PREDICTED_PARSERS);
}

/** The name of the newest predicted-pane tool call whose result could not be read. */
export function unreadablePredicted(turns: readonly { steps?: AgentStep[] }[]): string | null {
  for (let i = turns.length - 1; i >= 0; i--) {
    const steps = turns[i].steps;
    if (!steps) continue;
    for (let j = steps.length - 1; j >= 0; j--) {
      const step = steps[j];
      if (step.is_error) continue;
      const parse = PREDICTED_PARSERS[step.name];
      if (!parse) continue;
      return parse(step.result) ? null : step.name;
    }
  }
  return null;
}

/** The run id a pane result is pinned to, whichever tool produced it. */
export function resultSnapshot(result: BaselineResult | PredictedResult | null): string | null {
  if (!result) return null;
  if (result.tool === "assess_impact") return result.impact.snapshot;
  if (result.tool === "resolve_address") return result.address.snapshot;
  if (result.tool === "simulate_policy_change") return result.policy.snapshot;
  return result.routes.snapshot;
}

/* --- impact_evaluate_service: the declared success condition ------------- */

/** One address set that the answer names, capped with the whole count beside it. */
export interface ServiceImpactBucket {
  count: number | null;
  count_decimal?: string;
  address_count_decimal?: string;
  items: string[];
  truncated: boolean;
}

/** The success condition as it was evaluated: a member by name, or a group
 *  (`every`, `any-one`, `n-of-m`, `capacity`) over further conditions. */
export interface ServiceImpactCondition {
  kind: string;
  member?: string | null;
  n?: number | null;
  parts?: ServiceImpactCondition[];
}

// The parts of one comparison that do not overlap.
interface ServiceImpactTriage<T> {
  decided_loss: T;
  passes_then_open: T;
  open_then_fails: T;
  open_throughout: T;
  decided_gain: T;
  open_then_passes: T;
  fails_then_open: T;
}

/** A member's parts on one side: the clients for which the condition passes,
 *  fails or is not decided. */
export interface ServiceImpactCounts {
  passes?: number | null;
  fails?: number | null;
  open?: number | null;
}

export interface ServiceImpactMember {
  name: string;
  triage: Partial<ServiceImpactTriage<boolean>>;
  before: ServiceImpactCounts;
  after: ServiceImpactCounts;
  count_unit?: "client-addresses";
  counts_decimal?: Record<string, Record<string, string>>;
}

interface ServiceImpactStep {
  device_uid: string | null;
  stage: string;
  kind: string;
  detail: string;
  unknown: string[];
}

/** One evidence pointer: the steps behind one part of one member's answer on
 *  one side, and what a part the evidence does not settle would need. */
export interface ServiceImpactEvidence {
  side: string;
  member: string;
  /** the part's answer */
  result: ResultValue;
  steps: ServiceImpactStep[];
  missing: string[];
}

interface ServiceImpactGap {
  kind: string;
  [key: string]: unknown;
}

/** One side's answer over the whole source population. */
export interface ServiceImpactOutcome {
  result: ResultValue;
  passes: string[];
  fails: string[];
  open: string[];
  isolated?: boolean;
}

export interface EvaluateServiceImpactResult {
  /** The change set under test. An empty list means one recorded state was
   *  evaluated and there is no before/after comparison to draw. */
  intents?: unknown[];
  outcomes?: { before?: ServiceImpactOutcome; after?: ServiceImpactOutcome };
  symbolic?: { artifact_sha256?: string; artifact_ref?: Record<string, unknown> };
  complete?: boolean;
  completion_status?: "complete" | "incomplete";
  snapshot: string | null;
  mode: string;
  assumptions?: string[];
  request: {
    name: string;
    destination: string;
    sources: ServiceImpactBucket;
    members: { name: string; addresses: string[] }[];
    condition: ServiceImpactCondition;
    requirement: string | null;
  };
  /** the clients the change decidedly costs or adds the condition */
  decided_change: { loss: ServiceImpactBucket; gain: ServiceImpactBucket };
  /** the clients the change may cost or add the condition; contains `decided_change` */
  open_change: { loss: ServiceImpactBucket; gain: ServiceImpactBucket };
  /** the clients for which the condition is not decided */
  open: { before: ServiceImpactBucket; after: ServiceImpactBucket };
  triage: Partial<ServiceImpactTriage<ServiceImpactBucket>>;
  /** the clients for which the condition passes */
  passes: { before: ServiceImpactBucket; after: ServiceImpactBucket };
  /** the clients for which the condition fails: with `passes` and `open` it
   *  partitions the source population */
  fails: { before: ServiceImpactBucket; after: ServiceImpactBucket };
  members: ServiceImpactMember[];
  evidence: { count: number; items: ServiceImpactEvidence[]; truncated: boolean };
  missing_evidence: string[];
  gaps: ServiceImpactGap[];
  model_errors: ModelError[];
}

function isServiceBucket(value: unknown): value is ServiceImpactBucket {
  if (!value || typeof value !== "object") return false;
  const b = value as Record<string, unknown>;
  const countValid = typeof b.count === "number" || (
    b.count === null && typeof b.count_decimal === "string" && /^(0|[1-9]\d*)$/.test(b.count_decimal)
  );
  return countValid && Array.isArray(b.items) && typeof b.truncated === "boolean";
}

/** The `evaluate_service_impact` result, or null when the step is not shaped like one. */
export function parseEvaluateServiceImpact(raw: string): EvaluateServiceImpactResult | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const obj = parsed as Record<string, unknown>;
  const decided = obj.decided_change as Record<string, unknown> | undefined;
  const change = obj.open_change as Record<string, unknown> | undefined;
  const open = obj.open as Record<string, unknown> | undefined;
  if (!decided || !change || !open) return null;
  if (!isServiceBucket(decided.loss) || !isServiceBucket(change.loss)) return null;
  if (!isServiceBucket(open.before) || !isServiceBucket(open.after)) return null;
  if (!obj.request || typeof obj.request !== "object") return null;
  if (!Array.isArray(obj.missing_evidence) || !Array.isArray(obj.members)) return null;
  return obj as unknown as EvaluateServiceImpactResult;
}

/** Parse one `impact_evaluate_service` step's raw `result` string: the
 *  envelope's result, with the run its `snapshot.id` names, as the payload
 *  above. An unresolved application connection carries no evaluation and is
 *  null here, as is anything that is not such an envelope. */
export function parseImpactEvaluateService(raw: string): EvaluateServiceImpactResult | null {
  const envelope = parseEnvelope(raw);
  if (!envelope) return null;
  return parseEvaluateServiceImpact(JSON.stringify(flatten(envelope)));
}

/** The parsers of the steps whose result is a service evaluation, by step name. */
export const SERVICE_IMPACT_PARSERS: Readonly<
  Record<string, (raw: string) => EvaluateServiceImpactResult | null>
> = {
  impact_evaluate_service: parseImpactEvaluateService,
  evaluate_service_impact: parseEvaluateServiceImpact,
};

/** The newest readable service evaluation in the transcript. */
export function latestServiceImpact(
  turns: readonly { steps?: AgentStep[] }[],
): EvaluateServiceImpactResult | null {
  return latestToolResult<EvaluateServiceImpactResult>(turns, SERVICE_IMPACT_PARSERS);
}

/** The step of the newest readable service evaluation, the one
 *  `latestServiceImpact` reads, or null. A step the server stored carries
 *  its id. */
export function latestServiceImpactStep(
  turns: readonly { steps?: AgentStep[] }[],
): (AgentStep & { id?: string }) | null {
  return latestToolStep<EvaluateServiceImpactResult>(turns, SERVICE_IMPACT_PARSERS)?.step ?? null;
}
